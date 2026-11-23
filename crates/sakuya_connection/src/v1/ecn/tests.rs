//! The fixed part of ECN, driven by hand with a policy and a controller
//! that record what they are asked.

use core::time::Duration;

use sakuya_link::EcnMarking;
use sakuya_recovery_v1::{
    congestion::{
        CongestionContext, CongestionController, InFlightPacket, RemovedPacket, SealedPacket,
        SpuriouslyLostPacket,
    },
    ecn::{EcnContext, EcnPolicy, EcnValidationOutcome, ect0_testing_marking},
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaceState},
    receive_journals::ReceivedEcnCounts,
    rtt::RttEstimate,
};
use sakuya_wire_v1::packet_number::PacketNumber;

use super::{EcnAck, EcnAckCounts, LinkPathEcnState, ack_counts};

const APP: PacketNumberSpaceKind = PacketNumberSpaceKind::ApplicationData;
const PTO: Duration = Duration::from_millis(100);

fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}

fn pn(value: u64) -> PacketNumber {
    PacketNumber::new(value).unwrap()
}

fn counts(ect0: u64, ect1: u64, ce: u64) -> ReceivedEcnCounts {
    ReceivedEcnCounts { ect0, ect1, ce }
}

fn rtt() -> RttEstimate {
    RttEstimate::initial(ms(333))
}

/// The default test of RFC 9000 §13.4.2, recording what it is asked.
#[derive(Debug, Default)]
struct Policy {
    contexts: Vec<EcnContext<Duration>>,
    revalidations: Vec<EcnContext<Duration>>,
    revalidate: bool,
}

impl EcnPolicy<Duration> for Policy {
    fn marking(&mut self, context: &EcnContext<Duration>) -> EcnMarking {
        self.contexts.push(*context);
        ect0_testing_marking(context)
    }

    fn wants_revalidation(&mut self, context: &EcnContext<Duration>) -> bool {
        self.revalidations.push(*context);
        self.revalidate
    }
}

/// A controller that records only its congestion events of ECN-CE.
#[derive(Debug, Default)]
struct CeEvents(Vec<(u64, Duration)>);

impl CongestionController<Duration> for CeEvents {
    type SentState = ();
    type LossState = ();
    fn window(&self) -> usize {
        usize::MAX
    }
    fn on_packet_sealed(&mut self, _: &SealedPacket<Duration>) {}
    fn on_spurious_loss(
        &mut self,
        (): (),
        _: impl Iterator<Item = SpuriouslyLostPacket<Duration>>,
        _: &CongestionContext<Duration>,
    ) {
    }
    fn on_ce(
        &mut self,
        increase: u64,
        reference_sent_at: Duration,
        _: &CongestionContext<Duration>,
    ) {
        self.0.push((increase, reference_sent_at));
    }
    fn on_lost(
        &mut self,
        _: impl Iterator<Item = InFlightPacket<Duration, ()>>,
        _: &CongestionContext<Duration>,
    ) {
    }
    fn on_persistent_congestion(&mut self, _: &CongestionContext<Duration>) {}
    fn wants_recovery_send(&mut self) -> bool {
        false
    }
    fn on_acked(
        &mut self,
        _: impl Iterator<Item = InFlightPacket<Duration, ()>>,
        _: &CongestionContext<Duration>,
    ) {
    }
    fn on_removed(
        &mut self,
        _: impl Iterator<Item = RemovedPacket<()>>,
        _: &CongestionContext<Duration>,
    ) {
    }
    fn on_max_datagram_size_changed(&mut self, _: usize, _: bool, _: &CongestionContext<Duration>) {
    }
}

fn context() -> CongestionContext<Duration> {
    CongestionContext {
        now: ms(50),
        bytes_in_flight: 0,
        rtt: rtt(),
        rtt_sampled: false,
        max_datagram_size: 1200,
    }
}

/// A link path that marked and the link accepted `sent` packets of the
/// Application Data space, at 10 ms.
fn marked(sent: u64) -> (LinkPathEcnState<Duration>, Policy) {
    let mut state = LinkPathEcnState::new();
    let mut policy = Policy::default();
    let marking = state.marking(&mut policy, true, false, ms(10), rtt(), PTO);
    assert_eq!(marking, EcnMarking::Ect0);
    state.on_datagram_sealed(marking, sent);
    for _ in 0..sent {
        state.on_accepted(APP, marking);
    }
    (state, policy)
}

/// An ACK frame with these counts newly acknowledging `ect0` packets sent
/// with ECT(0).
fn ack(increase: Option<ReceivedEcnCounts>, ect0: u64) -> EcnAck {
    EcnAck {
        counts: EcnAckCounts {
            increase,
            exceeds_sent: false,
        },
        newly_ect0: ect0,
        newly_ect1: 0,
    }
}

/// `state` gets `ack`, the largest acknowledged packet sent at 12 ms: the
/// congestion events it gave.
fn receive(state: &mut LinkPathEcnState<Duration>, ack: &EcnAck) -> Vec<(u64, Duration)> {
    let mut events = CeEvents::default();
    state.on_ack(ack, &mut events, Some(ms(12)), &context());
    events.0
}

// ---- marking ----

#[test]
fn an_active_link_path_starts_its_test_at_its_first_marking() {
    let mut state = LinkPathEcnState::new();
    let mut policy = Policy::default();
    assert_eq!(
        state.marking(&mut policy, true, false, ms(10), rtt(), PTO),
        EcnMarking::Ect0
    );
    state.on_datagram_sealed(EcnMarking::Ect0, 3);
    assert_eq!(
        state.marking(&mut policy, true, false, ms(20), rtt(), PTO),
        EcnMarking::Ect0
    );
    let second = policy.contexts[1];
    assert_eq!(second.started_at, ms(10));
    assert_eq!(second.marked_since_start, 3);
    assert_eq!(second.outcome, EcnValidationOutcome::Unvalidated);
    assert_eq!(second.pto, PTO);
    // ten packets end the default test
    state.on_datagram_sealed(EcnMarking::Ect0, 7);
    assert_eq!(
        state.marking(&mut policy, true, false, ms(30), rtt(), PTO),
        EcnMarking::NotEct
    );
}

#[test]
fn a_link_path_that_may_not_mark_or_holds_is_not_ect_and_asks_nothing() {
    let mut state = LinkPathEcnState::new();
    let mut policy = Policy::default();
    // a candidate, a settling link path, or a link that cannot mark
    assert_eq!(
        state.marking(&mut policy, false, false, ms(10), rtt(), PTO),
        EcnMarking::NotEct
    );
    assert_eq!(
        state.marking(&mut policy, true, true, ms(10), rtt(), PTO),
        EcnMarking::NotEct
    );
    assert!(state.hold());
    assert!(policy.contexts.is_empty());
    // the test starts once it no longer holds
    assert_eq!(
        state.marking(&mut policy, true, false, ms(40), rtt(), PTO),
        EcnMarking::Ect0
    );
    assert!(!state.hold());
    assert_eq!(policy.contexts[0].started_at, ms(40));
}

#[test]
fn a_failed_validation_asks_whether_to_validate_again() {
    let (mut state, mut policy) = marked(2);
    let _ = receive(&mut state, &ack(None, 2));
    assert_eq!(state.outcome(), EcnValidationOutcome::Failed);
    let asked = policy.contexts.len();
    assert_eq!(
        state.marking(&mut policy, true, false, ms(60), rtt(), PTO),
        EcnMarking::NotEct
    );
    assert_eq!(policy.revalidations.len(), 1);
    assert_eq!(
        policy.revalidations[0].outcome,
        EcnValidationOutcome::Failed
    );
    assert_eq!(policy.contexts.len(), asked, "the marking is not asked");
    // validating again starts a new test
    policy.revalidate = true;
    assert_eq!(
        state.marking(&mut policy, true, false, ms(70), rtt(), PTO),
        EcnMarking::Ect0
    );
    assert_eq!(state.outcome(), EcnValidationOutcome::Unvalidated);
    let last = policy.contexts.last().unwrap();
    assert_eq!((last.started_at, last.marked_since_start), (ms(70), 0));
}

// ---- validation ----

#[test]
fn counts_that_cover_the_newly_acknowledged_marked_packets_make_it_capable() {
    let (mut state, _) = marked(3);
    assert!(state.marks_for(APP));
    assert!(receive(&mut state, &ack(Some(counts(2, 0, 0)), 2)).is_empty());
    state.on_acknowledged(APP, 2);
    assert_eq!(state.outcome(), EcnValidationOutcome::Capable);
    assert_eq!(state.marked_outstanding(), 1);
}

#[test]
fn a_frame_without_marked_packets_newly_acknowledged_leaves_it_unvalidated() {
    let (mut state, _) = marked(3);
    let _ = receive(&mut state, &ack(Some(counts(0, 0, 0)), 0));
    assert_eq!(state.outcome(), EcnValidationOutcome::Unvalidated);
}

#[test]
fn missing_counts_fail_it() {
    let (mut state, _) = marked(3);
    let _ = receive(&mut state, &ack(None, 1));
    assert_eq!(state.outcome(), EcnValidationOutcome::Failed);
}

#[test]
fn an_increase_short_of_the_newly_acknowledged_marked_packets_fails_it() {
    let (mut state, _) = marked(3);
    // a path that clears the marking: two acknowledged, one counted
    let _ = receive(&mut state, &ack(Some(counts(1, 0, 0)), 2));
    assert_eq!(state.outcome(), EcnValidationOutcome::Failed);
    // ECT(1) is checked the same way, CE counting for both
    let (mut state, _) = marked(3);
    let frame = EcnAck {
        counts: EcnAckCounts {
            increase: Some(counts(0, 1, 1)),
            exceeds_sent: false,
        },
        newly_ect0: 0,
        newly_ect1: 3,
    };
    let _ = receive(&mut state, &frame);
    assert_eq!(state.outcome(), EcnValidationOutcome::Failed);
}

#[test]
fn more_counted_than_newly_acknowledged_passes() {
    // an ACK frame was lost: this one counts packets it does not newly
    // acknowledge (RFC 9000 §13.4.2.1)
    let (mut state, _) = marked(3);
    let _ = receive(&mut state, &ack(Some(counts(3, 0, 0)), 1));
    assert_eq!(state.outcome(), EcnValidationOutcome::Capable);
}

#[test]
fn a_count_beyond_the_packets_sent_fails_it() {
    let (mut state, _) = marked(3);
    let frame = EcnAck {
        counts: EcnAckCounts {
            increase: Some(counts(2, 0, 0)),
            exceeds_sent: true,
        },
        newly_ect0: 2,
        newly_ect1: 0,
    };
    let _ = receive(&mut state, &frame);
    assert_eq!(state.outcome(), EcnValidationOutcome::Failed);
}

#[test]
fn every_newly_acknowledged_marked_packet_reported_ce_fails_it_while_unvalidated() {
    let (mut state, _) = marked(3);
    let events = receive(&mut state, &ack(Some(counts(0, 0, 2)), 2));
    assert_eq!(state.outcome(), EcnValidationOutcome::Failed);
    assert!(events.is_empty(), "no congestion event once it failed");
}

#[test]
fn a_capable_link_path_takes_ce_as_a_congestion_event() {
    let (mut state, _) = marked(4);
    let _ = receive(&mut state, &ack(Some(counts(1, 0, 0)), 1));
    assert_eq!(state.outcome(), EcnValidationOutcome::Capable);
    // every packet reported CE is congestion once capable, not a failure
    let events = receive(&mut state, &ack(Some(counts(0, 0, 2)), 2));
    assert_eq!(state.outcome(), EcnValidationOutcome::Capable);
    assert_eq!(events, [(2, ms(12))]);
}

#[test]
fn ce_with_some_marked_packets_counted_ect_is_a_congestion_event_while_unvalidated() {
    let (mut state, _) = marked(3);
    let events = receive(&mut state, &ack(Some(counts(1, 0, 1)), 2));
    assert_eq!(state.outcome(), EcnValidationOutcome::Capable);
    assert_eq!(events, [(1, ms(12))]);
}

#[test]
fn a_failed_link_path_takes_no_congestion_event_and_stays_failed() {
    let (mut state, _) = marked(3);
    let _ = receive(&mut state, &ack(None, 1));
    let events = receive(&mut state, &ack(Some(counts(2, 0, 3)), 2));
    assert_eq!(state.outcome(), EcnValidationOutcome::Failed);
    assert!(events.is_empty());
}

#[test]
fn a_frame_that_does_not_increase_the_largest_acknowledged_is_not_validated() {
    let mut numbers = PacketNumberSpaceState::new();
    for _ in 0..4 {
        numbers.marked_sent(EcnMarking::Ect0);
    }
    let first = ack_counts(&mut numbers, pn(5), Some(counts(2, 0, 0)));
    assert_eq!(
        first,
        Some(EcnAckCounts {
            increase: Some(counts(2, 0, 0)),
            exceeds_sent: false
        })
    );
    numbers.on_ack(pn(0), pn(5));
    // reordered: no counts at all, and counts beyond what was sent, are
    // not looked at, and leave the base
    assert_eq!(ack_counts(&mut numbers, pn(5), None), None);
    assert_eq!(ack_counts(&mut numbers, pn(3), Some(counts(9, 0, 0))), None);
    assert_eq!(numbers.ecn_counts_reported(), counts(2, 0, 0));
    // the next frame that does increase it counts from the base
    let next = ack_counts(&mut numbers, pn(6), Some(counts(4, 0, 0)));
    assert_eq!(
        next,
        Some(EcnAckCounts {
            increase: Some(counts(2, 0, 0)),
            exceeds_sent: false
        })
    );
    // and its counts are checked against what the space sent
    numbers.on_ack(pn(0), pn(6));
    let beyond = ack_counts(&mut numbers, pn(7), Some(counts(5, 0, 0)));
    assert!(beyond.unwrap().exceeds_sent);
    let ect1 = ack_counts(&mut numbers, pn(8), Some(counts(5, 1, 0)));
    assert!(ect1.unwrap().exceeds_sent, "no ECT(1) was ever sent");
}

/// A CE mark falls only on a packet sent marked: a CE count beyond the
/// packets the space sent marked fails the validation, and a huge one
/// reaches no congestion controller.
#[test]
fn a_ce_count_beyond_the_marked_packets_sent_fails_it() {
    let mut numbers = PacketNumberSpaceState::new();
    for _ in 0..4 {
        numbers.marked_sent(EcnMarking::Ect0);
    }
    let within = ack_counts(&mut numbers, pn(3), Some(counts(1, 0, 4)));
    assert!(!within.unwrap().exceeds_sent, "CE on each of the 4 sent");
    numbers.on_ack(pn(0), pn(3));
    let beyond = ack_counts(&mut numbers, pn(4), Some(counts(1, 0, 1 << 60)));
    let beyond = beyond.unwrap();
    assert!(beyond.exceeds_sent);
    let (mut state, _) = marked(4);
    let ack = EcnAck {
        counts: beyond,
        newly_ect0: 1,
        newly_ect1: 0,
    };
    assert!(receive(&mut state, &ack).is_empty(), "no congestion event");
    assert_eq!(state.outcome(), EcnValidationOutcome::Failed);
}

// ---- losses ----

#[test]
fn every_marked_packet_declared_lost_fails_it() {
    let (mut state, _) = marked(3);
    state.on_lost(APP, 2);
    assert_eq!(state.outcome(), EcnValidationOutcome::Unvalidated);
    state.on_lost(APP, 1);
    assert_eq!(state.outcome(), EcnValidationOutcome::Failed);
    assert_eq!(state.marked_outstanding(), 0);
}

#[test]
fn a_marked_packet_acknowledged_keeps_the_losses_from_failing_it() {
    let (mut state, _) = marked(3);
    state.on_acknowledged(APP, 1);
    state.on_lost(APP, 2);
    assert_eq!(state.outcome(), EcnValidationOutcome::Unvalidated);
}

#[test]
fn a_retired_space_has_nothing_outstanding() {
    let mut state = LinkPathEcnState::<Duration>::new();
    let mut policy = Policy::default();
    let marking = state.marking(&mut policy, true, false, ms(1), rtt(), PTO);
    state.on_accepted(PacketNumberSpaceKind::Initial, marking);
    state.on_accepted(APP, marking);
    assert!(state.marks_for(PacketNumberSpaceKind::Initial));
    state.on_space_retired(PacketNumberSpaceKind::Initial);
    assert!(!state.marks_for(PacketNumberSpaceKind::Initial));
    assert_eq!(state.marked_outstanding(), 1);
    // a Not-ECT packet is never outstanding
    state.on_accepted(APP, EcnMarking::NotEct);
    assert_eq!(state.marked_outstanding(), 1);
}
