//! A receiver of the connection's events that keeps them in order for each
//! side, on the test's thread.

use std::cell::RefCell;

use sakuya_connection::v1::{
    events::{
        CloseTrigger, ConnectionClosed, ConnectionEvents, ConnectionState, EventsStart, Initiator,
        KeyChange, LossTrigger, LostPacket, PacketEvents, PlainPacket, RecoveryMetrics,
        SharedEvents,
    },
    receive::DropReason,
};
use sakuya_recovery::packet_number_space::PacketNumberSpaceKind;
use sakuya_wire::{
    parameters::ParametersOf,
    v1::{
        encryption_level::EncryptionLevel,
        role::Role,
        transport_parameters::{TransportParameterSlots, TransportParameterSpace},
    },
    version::Version,
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
        initiator: Initiator,
        trigger: CloseTrigger,
    },
    State(ConnectionState),
    KeyUpdated(KeyChange),
    KeyDiscarded(KeyChange),
    Version(Version),
    Alpn(Option<Vec<u8>>),
    Parameters(Initiator),
}

thread_local! {
    /// What each side recorded: the server's first.
    static RECORDED: RefCell<[Vec<Recorded>; 2]> = const { RefCell::new([Vec::new(), Vec::new()]) };
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
}

/// What the side `role` recorded so far.
pub fn recorded(role: Role) -> Vec<Recorded> {
    RECORDED.with(|r| r.borrow()[index(role)].clone())
}

/// Records every connection's events, for every list of parts.
#[derive(Debug)]
pub struct RecordingEvents {
    role: Role,
}

impl RecordingEvents {
    fn push(&self, event: Recorded) {
        RECORDED.with(|r| r.borrow_mut()[index(self.role)].push(event));
    }
}

/// The handle of the application's threads records nothing yet.
#[derive(Debug, Clone)]
pub struct RecordingShared;

impl SharedEvents for RecordingShared {
    fn enabled(&self) -> bool {
        true
    }
}

impl<I> ConnectionEvents<I> for RecordingEvents {
    const ENABLED: bool = true;
    type Config = ();
    type Shared = RecordingShared;
    fn new(_: &(), start: &EventsStart) -> Self {
        Self { role: start.role }
    }
    fn enabled(&self) -> bool {
        true
    }
    fn shared(&self) -> RecordingShared {
        RecordingShared
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
}

impl<I, L> PacketEvents<I, L> for RecordingEvents {
    fn packet_sent(&mut self, _: I, packet: &PlainPacket<'_>) {
        self.push(Recorded::Sent {
            level: packet.level,
            number: packet.number,
            whole: packet.header_len > 0 && !packet.payload().is_empty(),
        });
    }
    fn parameters_set(&mut self, _: I, initiator: Initiator, _: &TransportParameterSlots<L>)
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
