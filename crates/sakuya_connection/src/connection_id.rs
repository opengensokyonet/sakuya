//! The connection IDs the peer issued and this side sends with: the
//! destination connection ID strategy ([RFC 9000 §5.1]).
//!
//! A [`DestinationConnectionIdStrategy`] decides, for a link path, which of
//! the peer's connection IDs this side is willing to send with at this
//! moment: the order of its offer is its preference, and what it leaves out
//! it is not willing to use there. The sending call asks once per datagram,
//! because one datagram carries one destination connection ID
//! ([RFC 9000 §12.2]), and picks the first offered connection ID that fits
//! what the datagram leads with ([`DatagramConnectionId::choose_first`](datagram::DatagramConnectionId::choose_first)).
//! Every offered connection ID carries its sequence number, which the
//! protocol keeps unique ([RFC 9000 §5.1.1]); retirement, Retire Prior To
//! and reset tokens are all keyed by it.
//!
//! The protocol's requirements on the peer's connection IDs are the
//! contract of every strategy, not something the sending call enforces
//! around it:
//!
//! - After a NEW_CONNECTION_ID frame is processed, more active connection IDs
//!   than this side's `active_connection_id_limit` is a
//!   CONNECTION_ID_LIMIT_ERROR ([RFC 9000 §5.1.1]).
//! - When Retire Prior To increases, the connection IDs below it stop being
//!   used and are retired before the new connection ID is added; none is
//!   forgotten without being retired ([RFC 9000 §5.1.2]).
//! - A connection ID used on another network path is never offered for a
//!   link path, except as [RFC 9000 §9.5] permits after a change of the
//!   peer's address alone; a connection ID that is to stop being used
//!   leaves every offer at once. A packet carrying a RETIRE_CONNECTION_ID
//!   frame therefore never uses the connection ID it retires
//!   ([RFC 9000 §19.16]).
//! - A connection ID's stateless reset token is registered for detection
//!   only once the connection ID was used, and the registration is dropped
//!   when the connection ID is retired or the link path is removed,
//!   whichever comes first ([RFC 9000 §10.3.1]).
//!
//! [`ResetTokenRegistrar`] is the capability that registers a token; the
//! sending call lends it to [`DestinationConnectionIdStrategy::on_used`].
//! [`PeerGroupedResetTokenRegistrar`](reset_token::PeerGroupedResetTokenRegistrar)
//! registers with routing's
//! [`StatelessResetTokens`](sakuya_datagram_routing::route::reset::StatelessResetTokens).
//!
//! [`SequenceMapDestinationConnectionIdStrategy`](sequence_map::SequenceMapDestinationConnectionIdStrategy)
//! is the strategy sakuya provides. With the `connection_id_strategy_checks` feature,
//! `strategy_checks` holds functions that check any strategy against the
//! contract above.
//!
//! [RFC 9000 §5.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1
//! [RFC 9000 §5.1.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1.1
//! [RFC 9000 §5.1.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1.2
//! [RFC 9000 §9.5]: https://www.rfc-editor.org/rfc/rfc9000.html#section-9.5
//! [RFC 9000 §10.3.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-10.3.1
//! [RFC 9000 §12.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.2
//! [RFC 9000 §19.16]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.16

use sakuya_wire::{
    connection_id::ConnectionId,
    v1::{
        frame::new_connection_id::NewConnectionIdFrame,
        transport_parameters::integer::ActiveConnectionIdLimit,
    },
};

pub mod datagram;
pub mod reset_token;
pub mod sequence_map;
#[cfg(feature = "connection_id_strategy_checks")]
pub mod strategy_checks;
pub mod violation;

use reset_token::ResetTokenRegistrar;
use violation::NewConnectionIdViolationError;

/// A connection ID the peer issued, offered for sending, with its sequence
/// number ([RFC 9000 §5.1.1]).
///
/// [RFC 9000 §5.1.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1.1
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OfferedConnectionId {
    /// The sequence number the peer assigned: 0 for the connection ID of
    /// the handshake.
    pub sequence: u64,
    /// The connection ID.
    pub id: ConnectionId,
}

/// Decides which of the peer's connection IDs this side sends with on each
/// link path, and keeps what the protocol requires of them.
///
/// `Id` identifies a link path and is only compared for identity; QUIC
/// version 1 uses the link's [`LinkId`](sakuya_link::LinkId). `I` is an
/// instant of the connection's clock. `R` registers the stateless reset
/// tokens of used connection IDs; the composition provides it, filled in
/// with the peer and target of the link path it is lent for.
///
/// The [module documentation](self) lists the contract every implementation
/// keeps.
pub trait DestinationConnectionIdStrategy<Id, I, R: ResetTokenRegistrar>: Sized {
    /// The configuration each connection's strategy is made from.
    type Config: Clone;

    /// The connection IDs offered for one datagram.
    type Offer<'a>: Iterator<Item = OfferedConnectionId>
    where
        Self: 'a;

    /// The strategy of a new logical path, made before the connection ID
    /// the peer chose for the handshake is known: it offers nothing until
    /// [`on_handshake_connection_id`](Self::on_handshake_connection_id).
    /// `active_limit` is the `active_connection_id_limit` this side sends.
    fn new(config: &Self::Config, active_limit: ActiveConnectionIdLimit) -> Self;

    /// The connection ID to send the handshake with is now `id`, numbered
    /// 0: a server's is the Source Connection ID of the first Initial
    /// packet it processed from the client ([RFC 9000 §7.2]); a zero-length
    /// one means the peer issues no other connection ID
    /// ([RFC 9000 §5.1.1]).
    ///
    /// It comes before any NEW_CONNECTION_ID frame. It replaces the
    /// connection ID numbered 0 and what was bound to it.
    ///
    /// [RFC 9000 §5.1.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1.1
    /// [RFC 9000 §7.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-7.2
    fn on_handshake_connection_id(&mut self, id: ConnectionId);

    /// The connection IDs this side is willing to send with on
    /// `link_path` at this moment, most preferred first.
    ///
    /// The offer holds for one datagram only: the sending call asks again
    /// for the next.
    fn offer(&mut self, link_path: &Id) -> Self::Offer<'_>;

    /// A datagram of `datagram_len` bytes with content was sealed on
    /// `link_path` with the connection ID numbered `sequence`.
    ///
    /// The strategy records that the connection ID is bound to the link
    /// path's network path ([RFC 9000 §9.5]). The first time the connection
    /// ID is used on the link path, it registers the connection ID's reset
    /// token through `registrar` and keeps the registration
    /// ([RFC 9000 §10.3.1]).
    ///
    /// [RFC 9000 §9.5]: https://www.rfc-editor.org/rfc/rfc9000.html#section-9.5
    /// [RFC 9000 §10.3.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-10.3.1
    fn on_used(&mut self, registrar: &mut R, sequence: u64, link_path: &Id, datagram_len: usize);

    /// The peer sent `frame`.
    ///
    /// # Errors
    ///
    /// [`NewConnectionIdViolationError`] if the frame violates a rule the
    /// strategy checks; the caller closes the connection with its
    /// [`transport_error_code`](NewConnectionIdViolationError::transport_error_code).
    fn on_new_connection_id(
        &mut self,
        frame: &NewConnectionIdFrame,
    ) -> Result<(), NewConnectionIdViolationError>;

    /// `link_path` was added. `peer_switched_local_id` tells whether the
    /// peer, on it, uses another of this side's connection IDs than on the
    /// link path it came from; when it does not, [RFC 9000 §9.5] lets this
    /// side keep its current connection ID towards the new remote address.
    ///
    /// [RFC 9000 §9.5]: https://www.rfc-editor.org/rfc/rfc9000.html#section-9.5
    fn on_link_path_added(&mut self, link_path: &Id, peer_switched_local_id: bool);

    /// `link_path` ended: its bindings and the registrations kept for it go.
    fn on_link_path_ended(&mut self, link_path: &Id);

    /// The earliest instant the strategy wants [`on_deadline`](Self::on_deadline)
    /// called at; `None` when it has nothing to do in time.
    fn next_deadline(&self) -> Option<I> {
        None
    }

    /// Does everything due at or before `now`.
    fn on_deadline(&mut self, _now: I) {}
}
