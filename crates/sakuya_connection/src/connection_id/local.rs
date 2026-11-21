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
//! - The NEW_CONNECTION_ID frame of a connection ID waits to be sent, and
//!   waits again when it is declared lost while the connection ID is not
//!   retired ([RFC 9000 §13.3]).
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
use sakuya_wire_v1::frame::write::InFlightClass;
use std::collections::BTreeMap;

use sakuya_recovery_v1::packet_number_space::PacketNumberSpaceKind;
use sakuya_wire_v1::{
    connection_id::{ConnectionId, NonEmptyCid, StatelessResetToken},
    var_int::{VarInt, VarIntField},
};
use sakuya_wire_v1::{
    frame::new_connection_id::NewConnectionIdFrame, transport_error::TransportErrorCode,
};
use snafu::Snafu;

use sakuya_stream_v1::send_options::destination::Unfulfilled;

use crate::{
    feedback::InjectSummary,
    frame_source::FrameSource,
    write::{OpenPacket, PacketPosition, PacketWriting, SummaryOf, Supplied},
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
/// (`Self: FrameSource`); the events that issue leave their frames waiting
/// to be sent, which [`waiting_disclosures`](Self::waiting_disclosures)
/// tells; writing a frame takes it out of waiting, and a frame declared lost
/// waits again while the connection ID is neither acknowledged nor retired.
///
/// The methods that change the strategy return whether the answer of
/// [`waiting_disclosures`](Self::waiting_disclosures) or
/// [`next_deadline`](Self::next_deadline) may have changed. An
/// implementation may return `true` when neither did, but never `false`
/// when one did.
pub trait LocalConnectionIdStrategy<Id, I, R> {
    /// The strategy of a new logical path whose handshake connection ID,
    /// sequence number 0, is `first`, with its registration, which the
    /// strategy keeps; `None` for a zero-length local connection ID, which
    /// issues none (RFC 9000 §5.1.1).
    ///
    /// `preferred` is the connection ID of a server's `preferred_address`
    /// transport parameter, sequence number 1, with its registration: the
    /// handshake discloses it as it does the first, so no NEW_CONNECTION_ID
    /// frame carries it, and it counts among the connection IDs issued
    /// towards the peer's `active_connection_id_limit` (RFC 9000 §5.1.1,
    /// §18.2). Every connection ID the strategy issues comes after it. It is
    /// `None` without a preferred address, and dropped with a zero-length
    /// `first`.
    fn new(first: Option<IssuedConnectionId<R>>, preferred: Option<IssuedConnectionId<R>>) -> Self
    where
        Self: Sized;

    /// This side may issue up to `peer_limit` connection IDs, the one of
    /// the handshake included: the protocol's minimum of 2 holds from the
    /// start, when the strategy is made, and this is called with the
    /// peer's `active_connection_id_limit` once 1-RTT packets can be sent
    /// (RFC 9000 §5.1.1, §18.2); a client that sends 0-RTT is told the
    /// remembered limit before, which 0-RTT keeps to (§7.4.1). It only
    /// grows, but through [`on_zero_rtt_rejected`](Self::on_zero_rtt_rejected).
    fn on_issuable<C>(&mut self, issuer: &mut C, peer_limit: u64) -> bool
    where
        C: ConnectionIdIssuer<Registration = R>;

    /// The server rejected this client's 0-RTT (RFC 9001 §4.6.2): this
    /// side may issue up to `peer_limit` connection IDs, this connection's
    /// `active_connection_id_limit`, in place of the remembered one it was
    /// told, and it may be smaller.
    ///
    /// The server processed none of the 0-RTT packets, so it knows of no
    /// connection ID their NEW_CONNECTION_ID frames carried: those frames
    /// come back as lost. The strategy withdraws the connection IDs beyond
    /// `peer_limit` that the peer cannot have acknowledged, the last ones
    /// issued first, so that what it discloses stays within the limit
    /// (§5.1.1); the sequence numbers it issues next go on from the last
    /// one it keeps, as each one is one more than the one before.
    fn on_zero_rtt_rejected<C>(&mut self, issuer: &mut C, peer_limit: u64) -> bool
    where
        C: ConnectionIdIssuer<Registration = R>;

    /// The handshake is confirmed.
    fn on_handshake_confirmed<C>(&mut self, issuer: &mut C) -> bool
    where
        C: ConnectionIdIssuer<Registration = R>;

    /// The peer retired `sequence` in a packet sent to `packet_destination`
    /// at `now`, on a link path whose probe timeout is `pto` then.
    ///
    /// # Errors
    ///
    /// The [`RetiredByPeerViolationError`] the frame breaks the protocol
    /// with.
    fn on_retired_by_peer<C>(
        &mut self,
        issuer: &mut C,
        sequence: u64,
        packet_destination: &ConnectionId,
        now: I,
        pto: Duration,
    ) -> Result<bool, RetiredByPeerViolationError>
    where
        C: ConnectionIdIssuer<Registration = R>;

    /// The peer switched to `id` on `link_path`, the link path's first
    /// packet included.
    fn on_used_by_peer<C>(&mut self, _issuer: &mut C, _id: &ConnectionId, _link_path: &Id) -> bool
    where
        C: ConnectionIdIssuer<Registration = R>,
    {
        false
    }

    /// The next instant the strategy acts at by itself.
    fn next_deadline(&self) -> Option<I> {
        None
    }

    /// The deadline came at `now`: act on everything due by then.
    fn on_deadline<C>(&mut self, _issuer: &mut C, _now: I) -> bool
    where
        C: ConnectionIdIssuer<Registration = R>,
    {
        false
    }

    /// The connection IDs whose NEW_CONNECTION_ID frame waits to be sent
    /// now, each once: those issued and not yet written, and those whose
    /// frame was declared lost while they are neither acknowledged nor
    /// retired. Asking does not change the strategy.
    fn waiting_disclosures(&self) -> impl Iterator<Item = NewConnectionIdIntent> + '_;
}

/// One connection ID the strategy issued.
#[derive(Debug)]
struct Issued<R, I> {
    id: NonEmptyCid,
    token: StatelessResetToken,
    #[expect(dead_code, reason = "held for the entry to stay registered")]
    registration: R,
    /// When the peer retired it: the registration is dropped at this
    /// instant.
    deregister_at: Option<I>,
    disclosure: Disclosure,
}

/// Where the NEW_CONNECTION_ID frame of a connection ID issued stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disclosure {
    /// It waits to be sent.
    Waiting,
    /// It was written into a packet whose fate is not known yet.
    InFlight,
    /// A packet with it was acknowledged, or the handshake disclosed the
    /// connection ID.
    Acknowledged,
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
            .as_ref()
            .is_some_and(|issued| issued.contains_key(&sequence))
    }

    /// Issues up to the target; whether it issued any.
    fn top_up<C>(&mut self, issuer: &mut C) -> bool
    where
        C: ConnectionIdIssuer<Registration = R>,
    {
        if !self.confirmed {
            return false;
        }
        let target = self.peer_limit.min(Self::DEFAULT_ACTIVE_LIMIT);
        let Some(issued) = self.issued.as_mut() else {
            return false;
        };
        let mut active = issued
            .values()
            .filter(|each| each.deregister_at.is_none())
            .count() as u64;
        let before = active;
        while active < target {
            let new = issuer.issue();
            let sequence = self.next_sequence;
            self.next_sequence += 1;
            issued.insert(
                sequence,
                Issued {
                    id: new.id,
                    token: new.token,
                    registration: new.registration,
                    deregister_at: None,
                    disclosure: Disclosure::Waiting,
                },
            );
            active += 1;
        }
        active != before
    }
}

impl<Id, R, I> LocalConnectionIdStrategy<Id, I, R> for SequenceMapLocalConnectionIdStrategy<R, I>
where
    I: Ord + Copy + Add<Duration, Output = I>,
{
    /// The handshake connection ID, and the one of the preferred address,
    /// count as acknowledged: the handshake disclosed them, not a
    /// NEW_CONNECTION_ID frame.
    fn new(first: Option<IssuedConnectionId<R>>, preferred: Option<IssuedConnectionId<R>>) -> Self {
        let disclosed = |issued: IssuedConnectionId<R>| Issued {
            id: issued.id,
            token: issued.token,
            registration: issued.registration,
            deregister_at: None,
            disclosure: Disclosure::Acknowledged,
        };
        let issued = first.map(|first| {
            let mut issued = BTreeMap::from([(0, disclosed(first))]);
            if let Some(preferred) = preferred {
                issued.insert(1, disclosed(preferred));
            }
            issued
        });
        let next_sequence = match &issued {
            Some(issued) => issued.len() as u64,
            None => 1,
        };
        Self {
            issued,
            next_sequence,
            peer_limit: 2,
            confirmed: false,
        }
    }

    fn on_issuable<C>(&mut self, issuer: &mut C, peer_limit: u64) -> bool
    where
        C: ConnectionIdIssuer<Registration = R>,
    {
        self.peer_limit = self.peer_limit.max(peer_limit);
        self.top_up(issuer)
    }

    fn on_handshake_confirmed<C>(&mut self, issuer: &mut C) -> bool
    where
        C: ConnectionIdIssuer<Registration = R>,
    {
        self.confirmed = true;
        self.top_up(issuer)
    }

    /// It withdraws the connection IDs issued last, while more are active
    /// than `peer_limit` and the last is not acknowledged; a withdrawn one
    /// leaves the map, and its registration drops with it.
    fn on_zero_rtt_rejected<C>(&mut self, issuer: &mut C, peer_limit: u64) -> bool
    where
        C: ConnectionIdIssuer<Registration = R>,
    {
        self.peer_limit = peer_limit;
        let mut changed = false;
        if let Some(issued) = self.issued.as_mut() {
            loop {
                let active = issued
                    .values()
                    .filter(|each| each.deregister_at.is_none())
                    .count() as u64;
                if active <= peer_limit {
                    break;
                }
                // only the last issued goes, so that the numbers stay one
                // after the other
                let last = issued.last_key_value().filter(|&(&sequence, each)| {
                    sequence + 1 == self.next_sequence
                        && each.disclosure != Disclosure::Acknowledged
                        && each.deregister_at.is_none()
                });
                let Some((&sequence, _)) = last else {
                    break;
                };
                issued.remove(&sequence);
                self.next_sequence = sequence;
                changed = true;
            }
        }
        self.top_up(issuer) || changed
    }

    fn on_retired_by_peer<C>(
        &mut self,
        issuer: &mut C,
        sequence: u64,
        packet_destination: &ConnectionId,
        now: I,
        pto: Duration,
    ) -> Result<bool, RetiredByPeerViolationError>
    where
        C: ConnectionIdIssuer<Registration = R>,
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
            return Ok(false);
        };
        if entry.id.as_bytes() == packet_destination.as_bytes() {
            return Err(RetiredByPeerViolationError::RetiresItsPacketsDestination { sequence });
        }
        if entry.deregister_at.is_none() {
            entry.deregister_at = Some(now + pto.saturating_mul(3));
            self.top_up(issuer);
            return Ok(true);
        }
        Ok(false)
    }

    fn next_deadline(&self) -> Option<I> {
        self.issued
            .iter()
            .flatten()
            .filter_map(|(_, issued)| issued.deregister_at)
            .min()
    }

    fn on_deadline<C>(&mut self, _: &mut C, now: I) -> bool
    where
        C: ConnectionIdIssuer<Registration = R>,
    {
        let Some(issued) = self.issued.as_mut() else {
            return false;
        };
        let before = issued.len();
        issued.retain(|_, each| each.deregister_at.is_none_or(|at| at > now));
        issued.len() != before
    }

    /// A connection ID the peer retired is not disclosed again.
    fn waiting_disclosures(&self) -> impl Iterator<Item = NewConnectionIdIntent> + '_ {
        self.issued
            .iter()
            .flatten()
            .filter(|(_, issued)| {
                issued.disclosure == Disclosure::Waiting && issued.deregister_at.is_none()
            })
            .map(|(&sequence, _)| NewConnectionIdIntent::new(sequence))
    }
}

/// The strategy writes the NEW_CONNECTION_ID frames of version 1, with
/// Retire Prior To 0.
impl<R, I> FrameSource for SequenceMapLocalConnectionIdStrategy<R, I> {
    type Summary = NewConnectionIdSummary;
    type Class = InFlightClass;
    type Item<'a> = u64;

    /// The frame is written only while it waits to be sent and the peer did
    /// not retire the connection ID; once written, it is in flight.
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
            .as_mut()
            .and_then(|issued| issued.get_mut(&sequence))
            .filter(|issued| {
                issued.disclosure == Disclosure::Waiting && issued.deregister_at.is_none()
            })
        else {
            return Supplied::Open(packet);
        };
        let frame = new_connection_id_frame(sequence, issued.id, issued.token);
        let written = packet.write_frame(
            frame,
            <SummaryOf<W>>::inject_summary(NewConnectionIdSummary { sequence }),
        );
        if written.is_ok() {
            issued.disclosure = Disclosure::InFlight;
        }
        Supplied::Open(packet)
    }

    fn delivered(&mut self, _: PacketNumberSpaceKind, summary: NewConnectionIdSummary) {
        if let Some(issued) = self
            .issued
            .as_mut()
            .and_then(|issued| issued.get_mut(&summary.sequence))
        {
            issued.disclosure = Disclosure::Acknowledged;
        }
    }

    /// A frame lost while its connection ID is neither acknowledged nor
    /// retired waits to be sent again.
    fn lost(&mut self, _: PacketNumberSpaceKind, summary: &NewConnectionIdSummary) {
        if let Some(issued) = self
            .issued
            .as_mut()
            .and_then(|issued| issued.get_mut(&summary.sequence))
            .filter(|issued| {
                issued.disclosure == Disclosure::InFlight && issued.deregister_at.is_none()
            })
        {
            issued.disclosure = Disclosure::Waiting;
        }
    }

    /// A disclosure is the driver's content, which no strategy ends.
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
