//! A receiver of the connection's events that keeps them in order for each
//! side, on the test's thread.

use core::{fmt, marker::PhantomData};
use std::cell::RefCell;

use sakuya_connection::v1::events::NoPartEvents;
use sakuya_connection::v1::{
    events::{
        CloseTrigger, ConnectionClosed, ConnectionEvents, ConnectionState, EventInitiator,
        EventsStart, KeyChange, LossTrigger, LostPacket, PacketEvents, PlainPacket,
        RecoveryMetrics, SharedEvents, StreamDataMoved, StreamStateChange,
    },
    receive::DropReason,
};
use sakuya_recovery::packet_number_space::PacketNumberSpaceKind;
use sakuya_wire::{parameters::ParametersOf, version::Version};
use sakuya_wire_v1::{
    encryption_level::EncryptionLevel,
    role::Role,
    stream_id::StreamId,
    transport_parameters::{TransportParameterSlots, TransportParameterSpace},
};

/// One event, with what the tests look at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recorded {
    Started,
    Sent {
        level: EncryptionLevel,
        number: u64,
        /// Whether the header and the payload were both there.
        whole: bool,
    },
    Received {
        level: EncryptionLevel,
        number: u64,
        /// Whether the header and the payload were both there.
        whole: bool,
    },
    Dropped {
        level: Option<EncryptionLevel>,
        reason: String,
    },
    Lost {
        space: PacketNumberSpaceKind,
        number: u64,
        trigger: Option<LossTrigger>,
    },
    Metrics {
        congestion_window: usize,
        bytes_in_flight: usize,
    },
    Closed {
        initiator: EventInitiator,
        trigger: CloseTrigger,
    },
    State(ConnectionState),
    KeyUpdated(KeyChange),
    KeyDiscarded(KeyChange),
    Version(Version),
    Alpn(Option<Vec<u8>>),
    Parameters(EventInitiator),
    PreferredAddressConnectFailed {
        address: std::net::SocketAddr,
        reason: String,
    },
}

/// One event of the streams and of the parts, which the application's
/// threads and the driver give through the shared handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharedRecorded {
    StreamState {
        stream_id: StreamId,
        change: StreamStateChange,
        trigger: EventInitiator,
    },
    StreamDataMoved(StreamDataMoved),
    /// One of the parts' own events, as its `Debug` writes it.
    Part(String),
}

thread_local! {
    /// What each side recorded: the server's first.
    static RECORDED: RefCell<[Vec<Recorded>; 2]> = const { RefCell::new([Vec::new(), Vec::new()]) };
    /// What each side's shared handle recorded, apart: the server's first.
    static SHARED: RefCell<[Vec<SharedRecorded>; 2]> =
        const { RefCell::new([Vec::new(), Vec::new()]) };
}

fn index(role: Role) -> usize {
    match role {
        Role::Server => 0,
        Role::Client => 1,
    }
}

/// Forget what both sides recorded.
pub fn reset() {
    RECORDED.with(|r| *r.borrow_mut() = [Vec::new(), Vec::new()]);
    SHARED.with(|r| *r.borrow_mut() = [Vec::new(), Vec::new()]);
}

/// What the side `role` recorded so far.
pub fn recorded(role: Role) -> Vec<Recorded> {
    RECORDED.with(|r| r.borrow()[index(role)].clone())
}

/// What the shared handle of the side `role` recorded so far, on the test's
/// thread.
pub fn shared_recorded(role: Role) -> Vec<SharedRecorded> {
    SHARED.with(|r| r.borrow()[index(role)].clone())
}

/// Records every connection's events, for every list of parts whose own
/// events go into `P` ([`SharedEvents::PartEvents`]).
pub struct RecordingEvents<P = NoPartEvents> {
    role: Role,
    part_events: PhantomData<fn(P)>,
}

impl<P> fmt::Debug for RecordingEvents<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordingEvents")
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

impl<P> RecordingEvents<P> {
    fn push(&self, event: Recorded) {
        RECORDED.with(|r| r.borrow_mut()[index(self.role)].push(event));
    }
}

/// The handle of the application's threads: records what is given through
/// it on the thread it is given on, apart from the connection's events;
/// the parts' own events go into `P`.
pub struct RecordingShared<P = NoPartEvents> {
    role: Role,
    part_events: PhantomData<fn(P)>,
}

impl<P> fmt::Debug for RecordingShared<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordingShared")
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

impl<P> Clone for RecordingShared<P> {
    fn clone(&self) -> Self {
        Self {
            role: self.role,
            part_events: PhantomData,
        }
    }
}

impl<P> RecordingShared<P> {
    fn push(&self, event: SharedRecorded) {
        SHARED.with(|r| r.borrow_mut()[index(self.role)].push(event));
    }
}

impl<P: fmt::Debug> SharedEvents for RecordingShared<P> {
    const ENABLED: bool = true;
    fn enabled(&self) -> bool {
        true
    }
    fn stream_state(
        &self,
        stream_id: StreamId,
        change: StreamStateChange,
        trigger: EventInitiator,
    ) {
        self.push(SharedRecorded::StreamState {
            stream_id,
            change,
            trigger,
        });
    }
    fn stream_data_moved(&self, moved: &StreamDataMoved) {
        self.push(SharedRecorded::StreamDataMoved(*moved));
    }
    type PartEvents = P;
    fn part_event(&self, event: P) {
        self.push(SharedRecorded::Part(format!("{event:?}")));
    }
}

impl<I, P: fmt::Debug + 'static> ConnectionEvents<I> for RecordingEvents<P> {
    const ENABLED: bool = true;
    type Config = ();
    type Shared = RecordingShared<P>;
    fn new(_: &(), start: &EventsStart) -> Self {
        Self {
            role: start.role,
            part_events: PhantomData,
        }
    }
    fn enabled(&self) -> bool {
        true
    }
    fn shared(&self) -> RecordingShared<P> {
        RecordingShared {
            role: self.role,
            part_events: PhantomData,
        }
    }
    fn connection_started(&mut self, _: I) {
        self.push(Recorded::Started);
    }
    fn packet_dropped(&mut self, _: I, level: Option<EncryptionLevel>, reason: &DropReason) {
        let reason = format!("{reason:?}");
        let reason = reason
            .split([' ', '{', '('])
            .next()
            .unwrap_or_default()
            .to_owned();
        self.push(Recorded::Dropped { level, reason });
    }
    fn packet_lost(&mut self, _: I, lost: &LostPacket) {
        self.push(Recorded::Lost {
            space: lost.space,
            number: lost.number,
            trigger: lost.trigger,
        });
    }
    fn recovery_metrics(&mut self, _: I, metrics: &RecoveryMetrics) {
        self.push(Recorded::Metrics {
            congestion_window: metrics.congestion_window,
            bytes_in_flight: metrics.bytes_in_flight,
        });
    }
    fn connection_closed(&mut self, _: I, closed: &ConnectionClosed) {
        self.push(Recorded::Closed {
            initiator: closed.initiator,
            trigger: closed.trigger,
        });
    }
    fn connection_state(&mut self, _: I, state: ConnectionState) {
        self.push(Recorded::State(state));
    }
    fn key_updated(&mut self, _: I, key: KeyChange) {
        self.push(Recorded::KeyUpdated(key));
    }
    fn key_discarded(&mut self, _: I, key: KeyChange) {
        self.push(Recorded::KeyDiscarded(key));
    }
    fn version_information(&mut self, _: I, _: &[Version], chosen: Version) {
        self.push(Recorded::Version(chosen));
    }
    fn alpn_information(&mut self, _: I, chosen: Option<&[u8]>) {
        self.push(Recorded::Alpn(chosen.map(<[u8]>::to_vec)));
    }
    fn preferred_address_connect_failed(
        &mut self,
        _: I,
        address: std::net::SocketAddr,
        reason: &dyn core::fmt::Display,
    ) {
        self.push(Recorded::PreferredAddressConnectFailed {
            address,
            reason: reason.to_string(),
        });
    }
}

impl<I, L, P: fmt::Debug + 'static> PacketEvents<I, L> for RecordingEvents<P> {
    fn packet_sent(&mut self, _: I, packet: &PlainPacket<'_>) {
        self.push(Recorded::Sent {
            level: packet.level,
            number: packet.number,
            whole: packet.header_len > 0 && !packet.payload().is_empty(),
        });
    }
    fn parameters_set(&mut self, _: I, initiator: EventInitiator, _: &TransportParameterSlots<L>)
    where
        L: ParametersOf<TransportParameterSpace>,
    {
        self.push(Recorded::Parameters(initiator));
    }
    fn packet_received(&mut self, _: I, packet: &PlainPacket<'_>) {
        self.push(Recorded::Received {
            level: packet.level,
            number: packet.number,
            whole: packet.header_len > 0 && !packet.payload().is_empty(),
        });
    }
}
