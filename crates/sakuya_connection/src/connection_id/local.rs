//! The connection IDs this side issues and the peer sends with: the local
//! connection ID strategy ([RFC 9000 §5.1]).
//!
//! A [`LocalConnectionIdStrategy`] decides how many of this side's
//! connection IDs the peer holds and when they are issued and dropped. It
//! issues them with a [`ConnectionIdIssuer`], lent to the events that may
//! issue: the issuer generates a connection ID and its stateless reset
//! token and registers it with routing before it is disclosed, and the
//! strategy keeps the registration by sequence number. Dropping a
//! registration stops routing the connection ID to the connection.
//!
//! The protocol's requirements are the contract of every strategy:
//!
//! - Sequence numbers go up by one, from 0 for the connection ID of the
//!   handshake ([RFC 9000 §5.1.1]).
//! - A connection ID issued is accepted until the peer retires it; no more
//!   are issued than the peer's `active_connection_id_limit`, the one of
//!   the handshake included ([RFC 9000 §5.1.1]).
//! - A connection with a zero-length local connection ID issues none
//!   ([RFC 9000 §5.1.1, §18.2]).
//! - A RETIRE_CONNECTION_ID frame with a sequence number never issued, or
//!   one received with a zero-length local connection ID, is a
//!   PROTOCOL_VIOLATION ([RFC 9000 §19.16]).
//! - The NEW_CONNECTION_ID frame of a connection ID is published to send,
//!   and published again while it is declared lost and the connection ID
//!   is not retired ([RFC 9000 §13.3]).
//!
//! [`SequenceMapLocalConnectionIdStrategy`] is the strategy sakuya
//! provides.
//!
//! [RFC 9000 §5.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1
//! [RFC 9000 §5.1.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1.1
//! [RFC 9000 §13.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-13.3
//! [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
//! [RFC 9000 §19.16]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.16

use core::{ops::Add, time::Duration};
use std::collections::BTreeMap;

use sakuya_recovery::packet_number_space::PacketNumberSpaceKind;
use sakuya_wire::{
    connection_id::{ConnectionId, NonEmptyCid, StatelessResetToken},
    v1::{frame::new_connection_id::NewConnectionIdFrame, transport_error::TransportErrorCode},
    var_int::{VarInt, VarIntField},
};
use snafu::Snafu;

use sakuya_stream::send_options::destination::Unfulfilled;

use crate::{
    feedback::InjectSummary,
    frame_source::{FrameSource, PublishIntent},
    write::{InFlightClass, OpenPacket, PacketPosition, PacketWriting, SummaryOf, Supplied},
};

/// A connection ID this side issued: the value, its stateless reset token,
/// and its registration with routing, which routes the connection ID to
/// the connection until it is dropped.
#[derive(Debug)]
pub struct IssuedConnectionId<R> {
    /// The connection ID.
    pub id: NonEmptyCid,
    /// Its stateless reset token.
    pub token: StatelessResetToken,
    /// Its registration.
    pub registration: R,
}

/// What issues this side's connection IDs: it generates a connection ID
/// and its stateless reset token, and registers the connection ID before
/// it is disclosed.
pub trait ConnectionIdIssuer {
    /// Keeps a connection ID registered until it is dropped.
    type Registration;

    /// Issue a connection ID. It cannot fail: a generated value already
    /// taken is generated again.
    fn issue(&mut self) -> IssuedConnectionId<Self::Registration>;
}

/// The NEW_CONNECTION_ID frame of the connection ID numbered `sequence` is
/// to be sent, and sent again with the same values while it is lost
/// (RFC 9000 §13.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NewConnectionIdIntent {
    sequence: u64,
}

impl NewConnectionIdIntent {
    /// The connection ID numbered `sequence` is to be disclosed.
    pub const fn new(sequence: u64) -> Self {
        Self { sequence }
    }

    /// The sequence number of the connection ID.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// What a NEW_CONNECTION_ID frame written is remembered by: its sequence
/// number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewConnectionIdSummary {
    /// The sequence number of the connection ID it discloses.
    pub sequence: u64,
}

/// How a RETIRE_CONNECTION_ID frame breaks the protocol (RFC 9000 §19.16);
/// each is a PROTOCOL_VIOLATION.
#[derive(Debug, Snafu, Clone, Copy, PartialEq, Eq)]
pub enum RetiredByPeerViolationError {
    /// It retires a sequence number this side never issued.
    #[snafu(display("RETIRE_CONNECTION_ID retires sequence number {sequence}, never issued"))]
    NotIssued {
        /// The sequence number.
        sequence: u64,
    },
    /// This side's connection ID is zero-length, so it issued none.
    #[snafu(display("RETIRE_CONNECTION_ID with a zero-length local connection ID"))]
    ZeroLength,
    /// It retires the connection ID of the packet that carries it, which a
    /// strategy may treat as a violation (MAY).
    #[snafu(display("RETIRE_CONNECTION_ID retires sequence number {sequence}, which carries it"))]
    RetiresItsPacketsDestination {
        /// The sequence number.
        sequence: u64,
    },
}

impl RetiredByPeerViolationError {
    /// The transport error code the connection closes with.
    pub const fn transport_error_code(&self) -> TransportErrorCode {
        TransportErrorCode::PROTOCOL_VIOLATION
    }
}

/// The local connection ID strategy: the connection IDs this side issues,
/// for link paths identified by `Id`, with instants `I`. The issuer lent
/// to each event registers with `R`.
///
/// The value is also the frame source of the NEW_CONNECTION_ID frames
/// (`Self: FrameSource<Intent = NewConnectionIdIntent>`); the events that
/// issue publish them to `publish`.
pub trait LocalConnectionIdStrategy<Id, I, R> {
    /// This side may issue up to `peer_limit` connection IDs, the one of
    /// the handshake included: first with the protocol's minimum of 2, then
    /// with the peer's `active_connection_id_limit` once 1-RTT packets can
    /// be sent (RFC 9000 §5.1.1, §18.2). It only grows.
    fn on_issuable<C, Pb, Idx>(&mut self, issuer: &mut C, publish: &mut Pb, peer_limit: u64)
    where
        C: ConnectionIdIssuer<Registration = R>,
        Pb: PublishIntent<NewConnectionIdIntent, Idx>;

    /// The handshake is confirmed.
    fn on_handshake_confirmed<C, Pb, Idx>(&mut self, issuer: &mut C, publish: &mut Pb)
    where
        C: ConnectionIdIssuer<Registration = R>,
        Pb: PublishIntent<NewConnectionIdIntent, Idx>;

    /// The peer retired `sequence` in a packet sent to `packet_destination`
    /// at `now`, on a link path whose probe timeout is `pto` then.
    ///
    /// # Errors
    ///
    /// The [`RetiredByPeerViolationError`] the frame breaks the protocol
    /// with.
    #[allow(clippy::too_many_arguments)]
    fn on_retired_by_peer<C, Pb, Idx>(
        &mut self,
        issuer: &mut C,
        publish: &mut Pb,
        sequence: u64,
        packet_destination: &ConnectionId,
        now: I,
        pto: Duration,
    ) -> Result<(), RetiredByPeerViolationError>
    where
        C: ConnectionIdIssuer<Registration = R>,
        Pb: PublishIntent<NewConnectionIdIntent, Idx>;

    /// The peer switched to `id` on `link_path`, the link path's first
    /// packet included.
    fn on_used_by_peer<C, Pb, Idx>(
        &mut self,
        _issuer: &mut C,
        _publish: &mut Pb,
        _id: &ConnectionId,
        _link_path: &Id,
    ) where
        C: ConnectionIdIssuer<Registration = R>,
        Pb: PublishIntent<NewConnectionIdIntent, Idx>,
    {
    }

    /// The next instant the strategy acts at by itself.
    fn next_deadline(&self) -> Option<I> {
        None
    }

    /// The deadline came at `now`: act on everything due by then.
    fn on_deadline<C, Pb, Idx>(&mut self, _issuer: &mut C, _publish: &mut Pb, _now: I)
    where
        C: ConnectionIdIssuer<Registration = R>,
        Pb: PublishIntent<NewConnectionIdIntent, Idx>,
    {
    }
}

/// One connection ID the strategy issued.
#[derive(Debug)]
struct Issued<R, I> {
    id: NonEmptyCid,
    token: StatelessResetToken,
    /// `None` for the handshake's while it is held elsewhere.
    registration: Option<R>,
    /// When the peer retired it: the registration is dropped at this
    /// instant.
    deregister_at: Option<I>,
    acknowledged: bool,
}

/// The local connection ID strategy sakuya provides.
///
/// It issues only once the handshake is confirmed, up to the smaller of the
/// peer's limit and [`DEFAULT_ACTIVE_LIMIT`](Self::DEFAULT_ACTIVE_LIMIT),
/// and issues one more whenever the peer retires one. A connection ID the
/// peer retired stays registered for three probe timeouts, so that packets
/// already sent with it still reach the connection, then its registration
/// is dropped. It never sends Retire Prior To and does not rotate. With a
/// zero-length local connection ID it issues nothing.
#[derive(Debug)]
pub struct SequenceMapLocalConnectionIdStrategy<R, I> {
    /// `None` with a zero-length local connection ID.
    issued: Option<BTreeMap<u64, Issued<R, I>>>,
    next_sequence: u64,
    peer_limit: u64,
    confirmed: bool,
}

impl<R, I: Ord + Copy + Add<Duration, Output = I>> SequenceMapLocalConnectionIdStrategy<R, I> {
    /// The most connection IDs it keeps issued: 4.
    pub const DEFAULT_ACTIVE_LIMIT: u64 = 4;

    /// The strategy of a connection whose handshake connection ID is
    /// `first`, sequence number 0, registered with `registration` when it
    /// holds it; `None` for a zero-length local connection ID.
    pub fn new(first: Option<(NonEmptyCid, StatelessResetToken)>, registration: Option<R>) -> Self {
        let issued = first.map(|(id, token)| {
            BTreeMap::from([(
                0,
                Issued {
                    id,
                    token,
                    registration,
                    deregister_at: None,
                    acknowledged: true,
                },
            )])
        });
        Self {
            issued,
            next_sequence: 1,
            peer_limit: 2,
            confirmed: false,
        }
    }

    /// The connection IDs issued and not retired by the peer, in order.
    pub fn active(&self) -> impl Iterator<Item = (u64, NonEmptyCid)> + '_ {
        self.issued
            .iter()
            .flatten()
            .filter(|(_, issued)| issued.deregister_at.is_none())
            .map(|(sequence, issued)| (*sequence, issued.id))
    }

    /// Whether the connection ID numbered `sequence` is still registered.
    pub fn is_registered(&self, sequence: u64) -> bool {
        self.issued
            .iter()
            .flatten()
            .any(|(each, issued)| *each == sequence && issued.registration.is_some())
    }

    fn top_up<C, Pb, Idx>(&mut self, issuer: &mut C, publish: &mut Pb)
    where
        C: ConnectionIdIssuer<Registration = R>,
        Pb: PublishIntent<NewConnectionIdIntent, Idx>,
    {
        if !self.confirmed {
            return;
        }
        let target = self.peer_limit.min(Self::DEFAULT_ACTIVE_LIMIT);
        let Some(issued) = self.issued.as_mut() else {
            return;
        };
        let mut active = issued
            .values()
            .filter(|each| each.deregister_at.is_none())
            .count() as u64;
        while active < target {
            let new = issuer.issue();
            let sequence = self.next_sequence;
            self.next_sequence += 1;
            issued.insert(
                sequence,
                Issued {
                    id: new.id,
                    token: new.token,
                    registration: Some(new.registration),
                    deregister_at: None,
                    acknowledged: false,
                },
            );
            publish.publish(NewConnectionIdIntent::new(sequence));
            active += 1;
        }
    }
}

impl<Id, R, I> LocalConnectionIdStrategy<Id, I, R> for SequenceMapLocalConnectionIdStrategy<R, I>
where
    I: Ord + Copy + Add<Duration, Output = I>,
{
    fn on_issuable<C, Pb, Idx>(&mut self, issuer: &mut C, publish: &mut Pb, peer_limit: u64)
    where
        C: ConnectionIdIssuer<Registration = R>,
        Pb: PublishIntent<NewConnectionIdIntent, Idx>,
    {
        self.peer_limit = self.peer_limit.max(peer_limit);
        self.top_up(issuer, publish);
    }

    fn on_handshake_confirmed<C, Pb, Idx>(&mut self, issuer: &mut C, publish: &mut Pb)
    where
        C: ConnectionIdIssuer<Registration = R>,
        Pb: PublishIntent<NewConnectionIdIntent, Idx>,
    {
        self.confirmed = true;
        self.top_up(issuer, publish);
    }

    fn on_retired_by_peer<C, Pb, Idx>(
        &mut self,
        issuer: &mut C,
        publish: &mut Pb,
        sequence: u64,
        packet_destination: &ConnectionId,
        now: I,
        pto: Duration,
    ) -> Result<(), RetiredByPeerViolationError>
    where
        C: ConnectionIdIssuer<Registration = R>,
        Pb: PublishIntent<NewConnectionIdIntent, Idx>,
    {
        let Some(issued) = self.issued.as_mut() else {
            return Err(RetiredByPeerViolationError::ZeroLength);
        };
        if sequence >= self.next_sequence {
            return Err(RetiredByPeerViolationError::NotIssued { sequence });
        }
        // a sequence number no longer in the map was retired before and
        // its registration dropped: a repeated frame
        let Some(entry) = issued.get_mut(&sequence) else {
            return Ok(());
        };
        if entry.id.as_bytes() == packet_destination.as_bytes() {
            return Err(RetiredByPeerViolationError::RetiresItsPacketsDestination { sequence });
        }
        if entry.deregister_at.is_none() {
            entry.deregister_at = Some(now + pto.saturating_mul(3));
            self.top_up(issuer, publish);
        }
        Ok(())
    }

    fn next_deadline(&self) -> Option<I> {
        self.issued
            .iter()
            .flatten()
            .filter_map(|(_, issued)| issued.deregister_at)
            .min()
    }

    fn on_deadline<C, Pb, Idx>(&mut self, _: &mut C, _: &mut Pb, now: I)
    where
        C: ConnectionIdIssuer<Registration = R>,
        Pb: PublishIntent<NewConnectionIdIntent, Idx>,
    {
        if let Some(issued) = self.issued.as_mut() {
            issued.retain(|_, each| each.deregister_at.is_none_or(|at| at > now));
        }
    }
}

/// The strategy writes the NEW_CONNECTION_ID frames of version 1, with
/// Retire Prior To 0.
impl<R, I> FrameSource for SequenceMapLocalConnectionIdStrategy<R, I> {
    type Summary = NewConnectionIdSummary;
    type Class = InFlightClass;
    type Item<'a> = u64;
    type Intent = NewConnectionIdIntent;

    /// A connection ID the peer retired in the meantime is not disclosed
    /// again.
    fn supply<W, P, Idx>(
        &mut self,
        sequence: u64,
        mut packet: OpenPacket<W, InFlightClass, P>,
    ) -> Supplied<W, InFlightClass, P>
    where
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<NewConnectionIdSummary, Idx>,
        P: PacketPosition,
    {
        let Some(issued) = self
            .issued
            .as_ref()
            .and_then(|issued| issued.get(&sequence))
            .filter(|issued| issued.deregister_at.is_none())
        else {
            return Supplied::Open(packet);
        };
        let frame = new_connection_id_frame(sequence, issued.id, issued.token);
        let written = packet.write_frame(
            frame,
            <SummaryOf<W>>::inject_summary(NewConnectionIdSummary { sequence }),
        );
        debug_assert!(written.is_ok(), "the intent asks room for the whole frame");
        Supplied::Open(packet)
    }

    fn delivered<Pb, Idx>(
        &mut self,
        _: &mut Pb,
        _: PacketNumberSpaceKind,
        summary: NewConnectionIdSummary,
    ) where
        Pb: PublishIntent<NewConnectionIdIntent, Idx>,
    {
        if let Some(issued) = self
            .issued
            .as_mut()
            .and_then(|issued| issued.get_mut(&summary.sequence))
        {
            issued.acknowledged = true;
        }
    }

    fn lost<Pb, Idx>(
        &mut self,
        publish: &mut Pb,
        _: PacketNumberSpaceKind,
        summary: &NewConnectionIdSummary,
    ) where
        Pb: PublishIntent<NewConnectionIdIntent, Idx>,
    {
        let again = self
            .issued
            .as_ref()
            .and_then(|issued| issued.get(&summary.sequence))
            .is_some_and(|issued| !issued.acknowledged && issued.deregister_at.is_none());
        if again {
            publish.publish(NewConnectionIdIntent::new(summary.sequence));
        }
    }

    /// A connection ID is disclosed on any active link path; one left
    /// unsent when none will be active again goes with the connection.
    fn unfulfilled(&mut self, _: u64, _: Unfulfilled) {}
}

/// The NEW_CONNECTION_ID frame of the connection ID numbered `sequence`,
/// with Retire Prior To 0.
pub fn new_connection_id_frame(
    sequence: u64,
    id: NonEmptyCid,
    token: StatelessResetToken,
) -> NewConnectionIdFrame {
    let field = |value: u64| {
        // invariant: sequence numbers stay far below 2^62
        VarIntField::shortest(VarInt::try_from(value).expect("a sequence number below 2^62"))
    };
    // invariant: Retire Prior To 0 is never above the sequence number
    NewConnectionIdFrame::new(field(sequence), field(0), id, token)
        .expect("Retire Prior To 0 is at most any sequence number")
}

#[cfg(test)]
mod tests;
