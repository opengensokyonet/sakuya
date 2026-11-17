//! A receiver of the connection's events that keeps them in order for each
//! side, on the test's thread.

use std::cell::RefCell;

use sakuya_connection::v1::{
    events::{
        CloseTrigger, ConnectionClosed, ConnectionEvents, EventsStart, Initiator, LossTrigger,
        LostPacket, PacketEvents, PlainPacket, RecoveryMetrics, SharedEvents,
    },
    receive::DropReason,
};
use sakuya_recovery::packet_number_space::PacketNumberSpaceKind;
use sakuya_wire::v1::{encryption_level::EncryptionLevel, role::Role};

/// One event, with what the tests look at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recorded {
    Started,
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
}

impl<I, L> PacketEvents<I, L> for RecordingEvents {
    fn packet_received(&mut self, _: I, packet: &PlainPacket<'_>) {
        self.push(Recorded::Received {
            level: packet.level,
            number: packet.number,
            whole: packet.header_len > 0 && !packet.payload().is_empty(),
        });
    }
}
