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
//! and those of the parts, such as DATAGRAM's, through a handle the
//! receiver shares ([`ConnectionEvents::Shared`], [`SharedEvents`]). Each
//! part gives the type of its own events ([`SharedEventsPart`]); the
//! handle takes the sum of them ([`SharedEvents::PartEvents`]), into which
//! a part puts its event at a place the compiler infers
//! ([`PartEventSum`]), as the parts' summaries of frames are.
//!
//! The connection node keeps the receiver in a [`ConnectionEventSink`].

use core::{fmt, net::SocketAddr, time::Duration};

use sakuya_packet_protection_v1::{
    header_protection::HeaderProtectionError, packet_key::OpenPacketError,
};
use sakuya_stream_v1::{
    connection::ImmediateClose, receive::ReceiveStreamState, send::SendStreamState,
};
use sakuya_wire::{
    parts::{CNil, Coproduct, HCons, HNil},
    version::Version,
};
use sakuya_wire_v1::header::VERSION;
use sakuya_wire_v1::packet_number::PacketNumber;
use sakuya_wire_v1::{connection_id::ConnectionId, parameters::ParametersOf};
use sakuya_wire_v1::{
    encryption_level::EncryptionLevel,
    role::Role,
    stream_id::StreamId,
    transport_parameters::{TransportParameterSlots, TransportParameterSpace},
};

use crate::take::{Here, There};
use sakuya_recovery_v1::packet_number_space::PacketNumberSpaceKind;

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
    type Shared: SharedEvents + Clone + 'static;

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

    /// The connection reached `state`.
    fn connection_state(&mut self, at: I, state: ConnectionState);

    /// The keys of one level and direction were installed, by the
    /// handshake or by a 1-RTT key update.
    fn key_updated(&mut self, at: I, key: KeyChange);

    /// The keys of one level and direction were discarded.
    fn key_discarded(&mut self, at: I, key: KeyChange);

    /// The QUIC version the connection uses is `chosen`, of those this side
    /// offers or accepts, `local`.
    fn version_information(&mut self, at: I, local: &[Version], chosen: Version);

    /// The handshake chose the application protocol `chosen`; `None` when
    /// none was negotiated.
    fn alpn_information(&mut self, at: I, chosen: Option<&[u8]>);

    /// A client took no link to `address`, of the server's preferred
    /// address, for `reason`: it does not migrate there (RFC 9000 §9.6.1).
    fn preferred_address_connect_failed(
        &mut self,
        at: I,
        address: SocketAddr,
        reason: &dyn fmt::Display,
    );
}

/// What receives the events of one connection that carry packets, whose
/// frames are read with the frame set of the list of parts `L`, at instants
/// `I`.
pub trait PacketEvents<I, L> {
    /// A packet was sealed, to go out in the datagram being written.
    fn packet_sent(&mut self, at: I, packet: &PlainPacket<'_>);

    /// The transport parameters of `initiator`, every part's, are
    /// `parameters`: this side's as it sends them, or the peer's once they
    /// passed their checks.
    fn parameters_set(
        &mut self,
        at: I,
        initiator: EventInitiator,
        parameters: &TransportParameterSlots<L>,
    ) where
        L: ParametersOf<TransportParameterSpace>;

    /// A packet was received and opened, and is not a duplicate; its frames
    /// are not processed yet. A closing connection records no packet, so a
    /// packet it receives is known only not to be one it processed before
    /// it closed. The Initial packets a server read before its connection
    /// was made ([`FirstFlight::Read`](super::first_flight::FirstFlight::Read))
    /// are given once the connection started, with the instants they
    /// arrived at.
    fn packet_received(&mut self, at: I, packet: &PlainPacket<'_>);
}

/// What sees each packet a datagram writer seals, in plaintext, just before
/// it is sealed.
///
/// `()` sees nothing: with it, nothing of this is compiled in.
pub trait SealObserver {
    /// Whether it sees anything; `false` compiles the call away.
    const ENABLED: bool;

    /// The packet `packet` is about to be sealed.
    fn sealing(&mut self, packet: &PlainPacket<'_>);
}

impl SealObserver for () {
    const ENABLED: bool = false;
    #[inline(always)]
    fn sealing(&mut self, _: &PlainPacket<'_>) {}
}

/// What the application's threads, and the driver where it changes what
/// they share, give the events of streams and of the parts through.
///
/// Its methods take `&self`: the handle is cloned into the stream set and
/// the datagram queues, and called under their locks. It reads the time of
/// each event itself.
pub trait SharedEvents {
    /// Whether the handle records anything at all; `false` makes every
    /// place that gives an event through it compile to nothing.
    const ENABLED: bool;

    /// Whether the events are recorded.
    fn enabled(&self) -> bool;

    /// A part of the stream `stream_id` changed its state as `change` says,
    /// on the action of `trigger`.
    fn stream_state(&self, stream_id: StreamId, change: StreamStateChange, trigger: EventInitiator);

    /// Data of a stream moved between the application and the transport.
    fn stream_data_moved(&self, moved: &StreamDataMoved);

    /// The sum of the parts' own events this handle takes
    /// ([`SharedEventsPart`]); one that records none takes
    /// [`NoPartEvents`].
    type PartEvents;

    /// A part gave `event`, its own event in the sum.
    fn part_event(&self, event: Self::PartEvents);
}

/// The type of a part's own events, given through the handle of the
/// connection's event receiver ([`SharedEvents::part_event`]): an enum of
/// them, or [`Infallible`](core::convert::Infallible) for a part that has
/// none.
///
/// It is implemented by the marker type of each part.
pub trait SharedEventsPart {
    /// The part's events.
    type SharedEvent;
}

/// The sum of the events of a list of parts: a [`Coproduct`] of each
/// part's [`SharedEventsPart::SharedEvent`], in the order of the list.
pub trait SharedEventsOfParts {
    /// The sum.
    type PartEvents;
}

impl SharedEventsOfParts for HNil {
    type PartEvents = CNil;
}

impl<P: SharedEventsPart, Ps: SharedEventsOfParts> SharedEventsOfParts for HCons<P, Ps> {
    type PartEvents = Coproduct<P::SharedEvent, Ps::PartEvents>;
}

/// The sum of the events of the list of parts `L`.
pub type PartEventsOf<L> = <L as SharedEventsOfParts>::PartEvents;

/// `S: PartEventSum<V, Idx>`: the event `V` of one part goes into the sum
/// `S` at the place `Idx`, which the compiler infers; `None` for a sum that
/// keeps none of the parts' events ([`NoPartEvents`]).
pub trait PartEventSum<V, Idx>: Sized {
    /// The sum that holds `event`, if it keeps it.
    fn inject(event: V) -> Option<Self>;
}

impl<V, Tail> PartEventSum<V, Here> for Coproduct<V, Tail> {
    fn inject(event: V) -> Option<Self> {
        Some(Coproduct::Inl(event))
    }
}

impl<V, Head, Tail, Idx> PartEventSum<V, There<Idx>> for Coproduct<Head, Tail>
where
    Tail: PartEventSum<V, Idx>,
{
    fn inject(event: V) -> Option<Self> {
        Tail::inject(event).map(Coproduct::Inr)
    }
}

/// The sum of a handle that keeps none of the parts' events: every event
/// goes into it as nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoPartEvents {}

impl<V> PartEventSum<V, Here> for NoPartEvents {
    fn inject(_: V) -> Option<Self> {
        None
    }
}

/// Give `event`, the event of one part, through `events`, at the place
/// `Idx` in the sum.
pub fn give_part_event<E, V, Idx>(events: &E, event: V)
where
    E: SharedEvents,
    E::PartEvents: PartEventSum<V, Idx>,
{
    if let Some(event) = E::PartEvents::inject(event) {
        events.part_event(event);
    }
}

/// How a part of a stream changed its state ([`SharedEvents::stream_state`]).
///
/// `old` is `None` for a part just made, which was idle; `new` is `None` for
/// a part whose state was reclaimed (qlog's `destroyed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamStateChange {
    /// The sending part.
    Sending {
        /// The state before.
        old: Option<SendStreamState>,
        /// The state after.
        new: Option<SendStreamState>,
    },
    /// The receiving part.
    Receiving {
        /// The state before.
        old: Option<ReceiveStreamState>,
        /// The state after.
        new: Option<ReceiveStreamState>,
    },
}

/// Data of a stream that moved between the application and the transport
/// ([`SharedEvents::stream_data_moved`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamDataMoved {
    /// The stream.
    pub stream_id: StreamId,
    /// Where in the stream the data starts.
    pub offset: u64,
    /// How many bytes moved; zero for an end alone.
    pub length: u64,
    /// Where they were.
    pub from: DataLocation,
    /// Where they went.
    pub to: DataLocation,
    /// What ended with the move, if anything.
    pub additional_info: Option<DataMovedAdditionalInfo>,
}

/// Where data of a stream or a datagram is (qlog's `DataLocation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataLocation {
    /// The application, above the connection.
    Application,
    /// The connection: its buffers and queues.
    Transport,
    /// The network: in packets sent or received.
    Network,
}

/// What ended together with a move of stream data (qlog's
/// `DataMovedAdditionalInfo`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataMovedAdditionalInfo {
    /// The application ended the stream: its end moved to the transport.
    FinSet,
    /// The transport gave the application the peer's reset.
    StreamReset,
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
    /// The size of the packet as it goes over the link, with its AEAD tag.
    pub wire_len: usize,
    /// Whether it is a probe of a larger datagram size; never for a packet
    /// received.
    pub pmtu_probe: bool,
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
    pub initiator: EventInitiator,
    /// The close sent or received; `None` when none was.
    pub close: Option<ImmediateClose>,
    /// What closed it.
    pub trigger: CloseTrigger,
}

/// A state the connection reached, of those qlog logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// An Initial packet was sent or received: the connection started.
    Attempted,
    /// The first Handshake packet was sent or received.
    HandshakeStarted,
    /// The handshake completed (RFC 9001 §4.1.1).
    HandshakeComplete,
    /// The handshake was confirmed (RFC 9001 §4.1.2).
    HandshakeConfirmed,
    /// The record of why the connection closed was written: it closes,
    /// drains or ended.
    Closed,
}

/// The keys of one encryption level and one direction: those `sender`
/// protects packets with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyChange {
    /// The encryption level.
    pub level: EncryptionLevel,
    /// The side that protects packets with them.
    pub sender: Role,
    /// The generation of 1-RTT keys a key update made, counted from 0, the
    /// keys the handshake gave (RFC 9001 §6); `None` for keys the handshake
    /// gave or that the connection drops otherwise.
    pub key_phase: Option<u64>,
    /// Which side initiated the key update that made these keys: this side,
    /// or the peer, whose packet with the flipped Key Phase bit this side
    /// followed (RFC 9001 §6.2); `None` when no key update made them.
    pub trigger: Option<EventInitiator>,
}

impl KeyChange {
    /// The keys of `level` that `sender` protects packets with, not made by
    /// a key update.
    pub(crate) const fn new(level: EncryptionLevel, sender: Role) -> Self {
        Self {
            level,
            sender,
            key_phase: None,
            trigger: None,
        }
    }

    /// The 1-RTT keys of generation `key_phase` that `sender` protects
    /// packets with, with no word of who initiated the update that made
    /// them.
    pub(crate) const fn generation(sender: Role, key_phase: u64) -> Self {
        Self {
            level: EncryptionLevel::OneRtt,
            sender,
            key_phase: Some(key_phase),
            trigger: None,
        }
    }

    /// The 1-RTT keys of generation `key_phase` that `sender` protects
    /// packets with, made by a key update `trigger` initiated.
    pub(crate) const fn updated(sender: Role, key_phase: u64, trigger: EventInitiator) -> Self {
        Self {
            level: EncryptionLevel::OneRtt,
            sender,
            key_phase: Some(key_phase),
            trigger: Some(trigger),
        }
    }
}

/// Which side something came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventInitiator {
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
    #[inline(always)]
    fn connection_state(&mut self, _: I, _: ConnectionState) {}
    #[inline(always)]
    fn key_updated(&mut self, _: I, _: KeyChange) {}
    #[inline(always)]
    fn key_discarded(&mut self, _: I, _: KeyChange) {}
    #[inline(always)]
    fn version_information(&mut self, _: I, _: &[Version], _: Version) {}
    #[inline(always)]
    fn alpn_information(&mut self, _: I, _: Option<&[u8]>) {}
    #[inline(always)]
    fn preferred_address_connect_failed(&mut self, _: I, _: SocketAddr, _: &dyn fmt::Display) {}
}

impl<I, L> PacketEvents<I, L> for NoEvents {
    #[inline(always)]
    fn packet_sent(&mut self, _: I, _: &PlainPacket<'_>) {}
    #[inline(always)]
    fn parameters_set(&mut self, _: I, _: EventInitiator, _: &TransportParameterSlots<L>)
    where
        L: ParametersOf<TransportParameterSpace>,
    {
    }
    #[inline(always)]
    fn packet_received(&mut self, _: I, _: &PlainPacket<'_>) {}
}

impl SharedEvents for NoEvents {
    const ENABLED: bool = false;
    #[inline(always)]
    fn enabled(&self) -> bool {
        false
    }
    #[inline(always)]
    fn stream_state(&self, _: StreamId, _: StreamStateChange, _: EventInitiator) {}
    #[inline(always)]
    fn stream_data_moved(&self, _: &StreamDataMoved) {}
    type PartEvents = NoPartEvents;
    #[inline(always)]
    fn part_event(&self, event: NoPartEvents) {
        match event {}
    }
}

/// The connection node's component that keeps the event receiver `X`.
#[derive(Debug)]
pub struct ConnectionEventSink<X> {
    events: X,
    started: bool,
    handshake_started: bool,
    closed: bool,
    /// The record of why the connection closed as the connection's future
    /// was dropped, given to the receiver when the connection node ends,
    /// which has the instant; `None` when the receiver heard of it already.
    dropped_with: Option<ConnectionClosed>,
}

impl<X> ConnectionEventSink<X> {
    /// The sink of `events`, before the connection's first poll.
    pub fn new(events: X) -> Self {
        Self {
            events,
            started: false,
            handshake_started: false,
            closed: false,
            dropped_with: None,
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
    pub(super) fn poll_began<I: Copy>(&mut self, now: I)
    where
        X: ConnectionEvents<I>,
    {
        if !self.started {
            self.started = true;
            if let Some(events) = self.active::<I>() {
                events.connection_started(now);
                events.connection_state(now, ConnectionState::Attempted);
                // this version speaks QUIC version 1 alone
                events.version_information(now, &[VERSION], VERSION);
                // the Initial keys are there from the start
                for sender in [Role::Client, Role::Server] {
                    let level = EncryptionLevel::Initial;
                    events.key_updated(now, KeyChange::new(level, sender));
                }
            }
        }
    }

    /// The record of why the connection closed was written, as `closed`
    /// makes it: the first time only.
    pub(super) fn record_written<I: Copy>(
        &mut self,
        at: I,
        closed: impl FnOnce() -> ConnectionClosed,
    ) where
        X: ConnectionEvents<I>,
    {
        if !self.closed {
            self.closed = true;
            if let Some(events) = self.active::<I>() {
                events.connection_closed(at, &closed());
                events.connection_state(at, ConnectionState::Closed);
            }
        }
    }

    /// The connection's future is dropped with `closed` as the record of
    /// why it closed: the receiver hears of it when the connection node
    /// ends ([`node_ended`](Self::node_ended)), unless it did already, or
    /// the connection never started: a future dropped before its first
    /// poll gives nothing.
    pub(super) fn future_dropped<I>(&mut self, closed: ConnectionClosed)
    where
        X: ConnectionEvents<I>,
    {
        if self.started && !self.closed && self.active::<I>().is_some() {
            self.dropped_with = Some(closed);
        }
    }

    /// The connection node ended at `at`: a record of why it closed kept as
    /// its future was dropped is written.
    pub(super) fn node_ended<I: Copy>(&mut self, at: I)
    where
        X: ConnectionEvents<I>,
    {
        if let Some(closed) = self.dropped_with.take() {
            self.record_written(at, || closed);
        }
    }

    /// A packet of `level` was sent or received at `at`: the first of the
    /// Handshake level starts the handshake, unless the connection closed
    /// already.
    pub(super) fn packet_of_level<I: Copy>(&mut self, at: I, level: EncryptionLevel)
    where
        X: ConnectionEvents<I>,
    {
        if level == EncryptionLevel::Handshake && !self.handshake_started && !self.closed {
            self.handshake_started = true;
            if let Some(events) = self.active::<I>() {
                events.connection_state(at, ConnectionState::HandshakeStarted);
            }
        }
    }
}

/// Why a packet was dropped without a trace.
#[derive(Debug)]
pub enum DropReason {
    /// The logical link the packet arrived on has no link path in this
    /// logical path.
    NoLinkPath,
    /// The logical link the packet arrived on has no link path in this
    /// logical path, and the migration policy admitted none for it: every
    /// packet of the datagram is dropped, and no stateless reset is sent
    /// (RFC 9000 §9).
    LinkPathNotAdmitted,
    /// The link path the packet arrived on is draining: nothing it receives
    /// is read (RFC 9000 §10.2.2).
    Draining,
    /// A client received an Initial packet whose Token Length is not zero,
    /// which a server never sends (RFC 9000 §17.2.2).
    TokenFromServer,
    /// A long header packet whose Source Connection ID is not the one of
    /// the first Initial packet that opened from the peer: a client must
    /// discard it (RFC 9000 §7.2), and a server's is from another
    /// connection attempt, which routing gives the connection when it was
    /// sent to one of this side's connection IDs.
    OtherSourceConnectionId {
        /// The packet's Source Connection ID.
        scid: ConnectionId,
    },
    /// The packet's level has no keys to read it with, and none are to come:
    /// they were discarded, the link path is closing, or, for 0-RTT, this
    /// side is a client or rejected 0-RTT.
    NoReceiveKeys {
        /// The level of the packet.
        level: EncryptionLevel,
    },
    /// The packet is held as protected, but its header is that of a Retry
    /// packet, which has no packet protection.
    NotProtected,
    /// Header protection could not be removed: the packet is too short for
    /// the sample (RFC 9001 §5.4.2).
    HeaderProtectionNotRemoved {
        /// The failure.
        source: HeaderProtectionError,
    },
    /// The payload did not open, such as when it fails authentication (RFC
    /// 9001 §5.5).
    PayloadNotOpened {
        /// The failure.
        source: OpenPacketError,
    },
    /// The packet number was already processed in its space, or lies below
    /// what the space still tells apart (RFC 9000 §12.3).
    Duplicate {
        /// The packet number.
        number: PacketNumber,
    },
    /// The packet arrived at a local end the active link path moved away
    /// from, and the migration policy dropped it, as a server drops the
    /// newer packets at its original address once it moved to its
    /// preferred one (RFC 9000 §9.6.2).
    OldLocalAddress,
}
