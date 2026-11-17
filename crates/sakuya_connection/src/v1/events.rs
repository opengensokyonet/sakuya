//! The events of a connection, for whoever records them, such as a qlog
//! writer.
//!
//! The host chooses what receives them
//! ([`HostChoices::Events`](super::HostChoices::Events)); by default it is
//! [`NoEvents`], which records nothing, and with it every place that would
//! give an event compiles to nothing: each is guarded by the constant
//! [`ConnectionEvents::ENABLED`], and the component is not even taken. A
//! receiver that records still decides for each connection whether it does
//! ([`ConnectionEvents::enabled`]).
//!
//! The events are in two traits by what they depend on. Those of
//! [`ConnectionEvents`] depend on nothing of the composition's list of
//! parts. Those of [`PacketEvents`] carry the plaintext of packets, whose
//! frames a receiver reads with the list's frame set, so a receiver may
//! implement them only for the lists whose parts it can describe: the
//! places that give them require it, and a composition proves it where it
//! is composed. [`NoEvents`] implements both for every list, so no part has
//! to do anything for a host that records nothing.
//!
//! The application's threads give events of their own, those of streams
//! and datagrams, through a handle the receiver shares
//! ([`ConnectionEvents::Shared`], [`SharedEvents`]).
//!
//! The connection node keeps the receiver in a [`ConnectionEventSink`].

use core::time::Duration;

use sakuya_stream::connection::ImmediateClose;
use sakuya_wire::{
    connection_id::ConnectionId,
    v1::{encryption_level::EncryptionLevel, role::Role},
};

use super::receive::DropReason;
use sakuya_recovery::packet_number_space::PacketNumberSpaceKind;

/// What receives the events of one connection that do not depend on the
/// composition's list of parts, at instants `I`.
pub trait ConnectionEvents<I>: Sized {
    /// Whether the receiver records anything at all; `false` makes every
    /// place that gives an event compile to nothing.
    const ENABLED: bool;

    /// What the receiver of each connection is made from, which the
    /// connection is made with.
    type Config: Clone + Default + 'static;

    /// The handle the application's threads give their events through.
    type Shared: SharedEvents + Clone;

    /// The receiver of a connection that starts as `start` says, made from
    /// `config`. It is made with the connection and cannot fail: a receiver
    /// that cannot record this connection records nothing for it.
    fn new(config: &Self::Config, start: &EventsStart) -> Self;

    /// Whether this connection's events are recorded.
    fn enabled(&self) -> bool;

    /// A handle for the application's threads.
    fn shared(&self) -> Self::Shared;

    /// The connection's first poll began at `at`.
    fn connection_started(&mut self, at: I);

    /// A packet of `level`, where it is known, was dropped for `reason`.
    fn packet_dropped(&mut self, at: I, level: Option<EncryptionLevel>, reason: &DropReason);

    /// A packet sent was declared lost.
    fn packet_lost(&mut self, at: I, lost: &LostPacket);

    /// The recovery state of a link path is as `metrics` says.
    fn recovery_metrics(&mut self, at: I, metrics: &RecoveryMetrics);

    /// The record of why the connection closed was written.
    fn connection_closed(&mut self, at: I, closed: &ConnectionClosed);
}

/// What receives the events of one connection that carry packets, whose
/// frames are read with the frame set of the list of parts `L`, at instants
/// `I`.
pub trait PacketEvents<I, L> {
    /// A packet was received and opened, and is not a duplicate; its frames
    /// are not processed yet.
    fn packet_received(&mut self, at: I, packet: &PlainPacket<'_>);
}

/// What the application's threads give their events through.
pub trait SharedEvents {
    /// Whether the events are recorded.
    fn enabled(&self) -> bool;
}

/// What a connection's event receiver is made with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventsStart {
    /// The side of the connection.
    pub role: Role,
    /// The Destination Connection ID of the client's very first Initial
    /// packet, which names the connection in a log (qlog's group ID).
    pub original_destination_connection_id: ConnectionId,
}

/// A packet in plaintext: its header with header protection removed,
/// followed by its payload, without the AEAD tag.
#[derive(Debug, Clone, Copy)]
pub struct PlainPacket<'a> {
    /// The encryption level of the packet.
    pub level: EncryptionLevel,
    /// Its full packet number.
    pub number: u64,
    /// The header and the payload.
    pub bytes: &'a [u8],
    /// Where the payload starts in `bytes`.
    pub header_len: usize,
    /// The size of the packet as it went over the link, with its AEAD tag.
    pub wire_len: usize,
}

impl<'a> PlainPacket<'a> {
    /// The header.
    pub fn header(&self) -> &'a [u8] {
        &self.bytes[..self.header_len]
    }
    /// The payload: the frames.
    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[self.header_len..]
    }
}

/// A packet declared lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LostPacket {
    /// The packet number space it was sent in.
    pub space: PacketNumberSpaceKind,
    /// Its packet number.
    pub number: u64,
    /// What declared it lost, where it is known.
    pub trigger: Option<LossTrigger>,
}

/// What declared a packet lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossTrigger {
    /// The time threshold of the packet passed (RFC 9002 §6.1.2).
    TimeThreshold,
    /// The probe timeout expired and the link path declared what it had in
    /// flight lost.
    ProbeTimeout,
}

/// The recovery state of a link path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryMetrics {
    /// The minimum RTT.
    pub min_rtt: Duration,
    /// The smoothed RTT.
    pub smoothed_rtt: Duration,
    /// The latest RTT sample.
    pub latest_rtt: Duration,
    /// The RTT variation.
    pub rtt_variance: Duration,
    /// The congestion window, in bytes.
    pub congestion_window: usize,
    /// The bytes in flight.
    pub bytes_in_flight: usize,
}

/// Why the connection closed, as its record holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionClosed {
    /// Which side closed it.
    pub initiator: Initiator,
    /// The close sent or received; `None` when none was.
    pub close: Option<ImmediateClose>,
    /// What closed it.
    pub trigger: CloseTrigger,
}

/// Which side something came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Initiator {
    /// This side.
    Local,
    /// The peer.
    Remote,
}

/// What closed a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseTrigger {
    /// An error this side found, or the handshake failed.
    Error,
    /// The application closed it.
    Application,
    /// A link ended and no link path was left.
    LinkEnded,
    /// The peer sent a CONNECTION_CLOSE frame.
    PeerClose,
    /// This side's idle timer expired.
    IdleTimeout,
    /// A stateless reset was received.
    StatelessReset,
    /// The client had no version in common with the server.
    VersionMismatch,
    /// The client gave up after a Retry.
    RetryAbandoned,
    /// The connection ended without a close.
    Aborted,
}

/// The default: records nothing, for every list of parts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoEvents;

impl<I> ConnectionEvents<I> for NoEvents {
    const ENABLED: bool = false;
    type Config = ();
    type Shared = NoEvents;
    #[inline(always)]
    fn new(_: &(), _: &EventsStart) -> Self {
        NoEvents
    }
    #[inline(always)]
    fn enabled(&self) -> bool {
        false
    }
    #[inline(always)]
    fn shared(&self) -> NoEvents {
        NoEvents
    }
    #[inline(always)]
    fn connection_started(&mut self, _: I) {}
    #[inline(always)]
    fn packet_dropped(&mut self, _: I, _: Option<EncryptionLevel>, _: &DropReason) {}
    #[inline(always)]
    fn packet_lost(&mut self, _: I, _: &LostPacket) {}
    #[inline(always)]
    fn recovery_metrics(&mut self, _: I, _: &RecoveryMetrics) {}
    #[inline(always)]
    fn connection_closed(&mut self, _: I, _: &ConnectionClosed) {}
}

impl<I, L> PacketEvents<I, L> for NoEvents {
    #[inline(always)]
    fn packet_received(&mut self, _: I, _: &PlainPacket<'_>) {}
}

impl SharedEvents for NoEvents {
    #[inline(always)]
    fn enabled(&self) -> bool {
        false
    }
}

/// The connection node's component that keeps the event receiver `X`.
#[derive(Debug)]
pub struct ConnectionEventSink<X> {
    events: X,
    started: bool,
    closed: bool,
}

impl<X> ConnectionEventSink<X> {
    /// The sink of `events`, before the connection's first poll.
    pub fn new(events: X) -> Self {
        Self {
            events,
            started: false,
            closed: false,
        }
    }

    /// The receiver, when it records this connection's events.
    #[inline(always)]
    pub fn active<I>(&mut self) -> Option<&mut X>
    where
        X: ConnectionEvents<I>,
    {
        (X::ENABLED && self.events.enabled()).then_some(&mut self.events)
    }

    /// The receiver, whether it records or not.
    pub fn events(&self) -> &X {
        &self.events
    }

    /// A poll began at `now`: the first one starts the connection.
    pub(super) fn poll_began<I>(&mut self, now: I)
    where
        X: ConnectionEvents<I>,
    {
        if !self.started {
            self.started = true;
            if let Some(events) = self.active::<I>() {
                events.connection_started(now);
            }
        }
    }

    /// The record of why the connection closed was written, as `closed`
    /// makes it: the first time only.
    pub(super) fn record_written<I>(&mut self, at: I, closed: impl FnOnce() -> ConnectionClosed)
    where
        X: ConnectionEvents<I>,
    {
        if !self.closed {
            self.closed = true;
            if let Some(events) = self.active::<I>() {
                events.connection_closed(at, &closed());
            }
        }
    }
}
