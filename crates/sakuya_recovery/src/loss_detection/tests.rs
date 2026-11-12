use super::*;
use core::time::Duration;

type State = LossDetectionState<Duration, (), u32>;

fn pn(value: u64) -> PacketNumber {
    PacketNumber::new(value).unwrap()
}

fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}

fn threshold() -> PacketThreshold {
    PacketThreshold::RECOMMENDED
}

fn charge(bytes: usize) -> Option<InFlightCharge<()>> {
    Some(InFlightCharge {
        bytes,
        app_limited: false,
        sent_state: (),
    })
}

/// Packets 0.. sent at 0, 10, 20 ... ms, all ack-eliciting.
fn state_with(count: u64) -> State {
    let mut state = State::new();
    for n in 0..count {
        state.accept(pn(n), ms(n * 10), true, charge(1200));
    }
    state
}

fn numbers<'a>(iter: impl Iterator<Item = &'a Outstanding<Duration, ()>>) -> Vec<u64> {
    iter.map(|p| p.number.get()).collect()
}

fn drained(batch: impl Iterator<Item = Outstanding<Duration, ()>>) -> Vec<u64> {
    batch.map(|p| p.number.get()).collect()
}

/// Send the packets `numbers` at their number in ms, declare them all lost
/// as one batch, keep every one and finish the batch with `loss`.
fn lose(state: &mut State, numbers: &[u64], loss: u32, retain_until: u64) {
    for &n in numbers {
        state.accept(pn(n), ms(n), true, charge(1200));
    }
    let mut batch = state.take_all();
    while let Some(packet) = batch.next() {
        batch.keep(packet.number, packet.sent_at, 1200);
    }
    batch.finish(loss, ms(retain_until));
}

fn kept(state: &State) -> Vec<(u64, u64, u32)> {
    state
        .declared_lost()
        .map(|p| {
            let retain_until = u64::try_from(p.retain_until.as_millis()).unwrap();
            (p.number.get(), retain_until, *p.loss)
        })
        .collect()
}

#[test]
fn accepted_packets_get_consecutive_sequence_numbers() {
    let mut state = State::new();
    // the packet numbers skip, the sequence numbers do not
    state.accept(pn(2), ms(0), true, charge(1200));
    state.accept(pn(5), ms(1), false, None);
    state.accept(pn(9), ms(2), true, charge(1200));
    let seqs: Vec<_> = state.outstanding().map(|p| p.seq).collect();
    assert_eq!(seqs, [0, 1, 2]);
    assert_eq!(numbers(state.outstanding()), [2, 5, 9]);
    assert_eq!(state.outstanding().len(), 3);
}

#[test]
fn ack_eliciting_packets_are_counted_and_the_last_send_time_kept() {
    let mut state = State::new();
    assert!(!state.has_ack_eliciting_outstanding());
    assert_eq!(state.last_ack_eliciting_sent_at(), None);
    state.accept(pn(0), ms(5), false, None);
    assert!(!state.has_ack_eliciting_outstanding());
    assert_eq!(state.last_ack_eliciting_sent_at(), None);
    state.accept(pn(1), ms(6), true, charge(100));
    state.accept(pn(2), ms(7), false, None);
    assert!(state.has_ack_eliciting_outstanding());
    assert_eq!(state.last_ack_eliciting_sent_at(), Some(ms(6)));
}

#[test]
fn the_last_ack_eliciting_send_time_outlives_the_packet() {
    let mut state = state_with(1);
    drained(state.take_acknowledged(&(pn(0)..=pn(0))));
    assert!(!state.has_ack_eliciting_outstanding());
    assert_eq!(state.last_ack_eliciting_sent_at(), Some(ms(0)));
}

#[test]
fn acknowledging_a_range_takes_those_packets_oldest_first() {
    let mut state = state_with(6);
    let taken = drained(state.take_acknowledged(&(pn(1)..=pn(3))));
    assert_eq!(taken, [1, 2, 3]);
    assert_eq!(numbers(state.outstanding()), [0, 4, 5]);
}

#[test]
fn acknowledging_a_range_without_packets_takes_nothing() {
    let mut state = state_with(3);
    assert!(drained(state.take_acknowledged(&(pn(10)..=pn(12)))).is_empty());
    assert!(drained(state.take_acknowledged(&(pn(5)..=pn(4)))).is_empty());
    assert_eq!(state.largest_acked_seq(), None);
    assert_eq!(state.outstanding().len(), 3);
}

#[test]
fn acknowledging_records_the_largest_acknowledged_sequence_number() {
    let mut state = state_with(6);
    assert_eq!(state.largest_acked_seq(), None);
    drained(state.take_acknowledged(&(pn(3)..=pn(4))));
    assert_eq!(state.largest_acked_seq(), Some(4));
    // a lower acknowledgment does not lower it
    drained(state.take_acknowledged(&(pn(0)..=pn(1))));
    assert_eq!(state.largest_acked_seq(), Some(4));
}

#[test]
fn acknowledging_lowers_the_ack_eliciting_count() {
    let mut state = State::new();
    state.accept(pn(0), ms(0), true, charge(1));
    state.accept(pn(1), ms(1), false, None);
    state.accept(pn(2), ms(2), true, charge(1));
    drained(state.take_acknowledged(&(pn(0)..=pn(1))));
    assert!(state.has_ack_eliciting_outstanding());
    drained(state.take_acknowledged(&(pn(2)..=pn(2))));
    assert!(!state.has_ack_eliciting_outstanding());
}

#[test]
fn a_packet_is_lost_after_a_packet_three_later_was_acknowledged() {
    let mut state = state_with(5);
    drained(state.take_acknowledged(&(pn(3)..=pn(3))));
    // sequence 3 acknowledged: sequence 0 is three behind, 1 is two behind
    let lost = drained(state.detect_lost(ms(40), pn(3), ms(1000), threshold()));
    assert_eq!(lost, [0]);
    assert_eq!(numbers(state.outstanding()), [1, 2, 4]);
}

#[test]
fn the_packet_threshold_counts_sequence_numbers_not_packet_numbers() {
    let mut state = State::new();
    // packet numbers 0, 10, 11, 12: the gap of numbers does not count
    for (n, at) in [(0, 0), (10, 1), (11, 2), (12, 3)] {
        state.accept(pn(n), ms(at), true, charge(1));
    }
    drained(state.take_acknowledged(&(pn(12)..=pn(12))));
    // seq 3 acknowledged; seq 0 is lost, seq 1 is only two behind
    let lost = drained(state.detect_lost(ms(4), pn(12), ms(1000), threshold()));
    assert_eq!(lost, [0]);
}

#[test]
fn a_packet_is_lost_after_the_loss_delay() {
    let mut state = state_with(3);
    drained(state.take_acknowledged(&(pn(2)..=pn(2))));
    // packet 0 was sent at 0, packet 1 at 10; delay 30 at now = 30
    let lost = drained(state.detect_lost(ms(30), pn(2), ms(30), threshold()));
    assert_eq!(lost, [0]);
    assert_eq!(numbers(state.outstanding()), [1]);
}

#[test]
fn a_packet_is_not_lost_before_the_loss_delay_ends() {
    let mut state = state_with(3);
    drained(state.take_acknowledged(&(pn(2)..=pn(2))));
    let lost = drained(state.detect_lost(ms(29), pn(2), ms(30), threshold()));
    assert!(lost.is_empty());
    assert_eq!(numbers(state.outstanding()), [0, 1]);
}

#[test]
fn only_packets_below_the_largest_acknowledged_number_can_be_lost() {
    let mut state = state_with(4);
    // packets 2 and 3 are old enough but not below the largest acknowledged 2
    let lost = drained(state.detect_lost(ms(1000), pn(2), ms(1), threshold()));
    assert_eq!(lost, [0, 1]);
    assert_eq!(numbers(state.outstanding()), [2, 3]);
}

#[test]
fn the_loss_time_is_the_first_remaining_eligible_packets_deadline() {
    let mut state = state_with(4);
    // eligible: packets below 3, i.e. 0, 1, 2; delay 25 at now 25 loses only 0
    let lost = drained(state.detect_lost(ms(25), pn(3), ms(25), threshold()));
    assert_eq!(lost, [0]);
    assert_eq!(state.loss_time(), Some(ms(35)));
}

#[test]
fn no_remaining_eligible_packet_leaves_no_loss_time() {
    let mut state = state_with(4);
    let lost = drained(state.detect_lost(ms(0), pn(0), ms(25), threshold()));
    assert!(lost.is_empty());
    assert_eq!(state.loss_time(), None);
}

#[test]
fn detecting_again_recomputes_the_loss_time_from_nothing() {
    let mut state = state_with(3);
    drained(state.detect_lost(ms(0), pn(2), ms(25), threshold()));
    assert_eq!(state.loss_time(), Some(ms(25)));
    // nothing eligible any more
    drained(state.detect_lost(ms(0), pn(0), ms(25), threshold()));
    assert_eq!(state.loss_time(), None);
}

#[test]
fn losses_lower_the_ack_eliciting_count() {
    let mut state = State::new();
    state.accept(pn(0), ms(0), true, charge(1));
    state.accept(pn(1), ms(1), false, None);
    state.accept(pn(2), ms(2), false, None);
    let lost = drained(state.detect_lost(ms(100), pn(2), ms(10), threshold()));
    assert_eq!(lost, [0, 1]);
    assert!(!state.has_ack_eliciting_outstanding());
}

#[test]
fn taking_all_empties_the_state_and_clears_the_loss_time() {
    let mut state = state_with(3);
    drained(state.detect_lost(ms(0), pn(2), ms(25), threshold()));
    assert!(state.loss_time().is_some());
    let all = drained(state.take_all());
    assert_eq!(all, [0, 1, 2]);
    assert_eq!(state.outstanding().len(), 0);
    assert_eq!(state.loss_time(), None);
    assert!(!state.has_ack_eliciting_outstanding());
}

#[test]
fn sequence_numbers_continue_after_packets_were_taken() {
    let mut state = state_with(2);
    drained(state.take_all());
    state.accept(pn(2), ms(50), true, charge(1));
    assert_eq!(state.outstanding().next().unwrap().seq, 2);
}

#[test]
fn a_kept_lost_packet_is_handed_back_by_a_late_acknowledgment() {
    let mut state = State::new();
    lose(&mut state, &[1, 2], 7, 100);
    lose(&mut state, &[5], 8, 100);
    let back: Vec<_> = state
        .take_spuriously_lost(&(pn(2)..=pn(5)))
        .map(|p| (p.number.get(), p.loss))
        .collect();
    assert_eq!(back, [(2, 7), (5, 8)]);
    // taken once only
    assert_eq!(state.take_spuriously_lost(&(pn(0)..=pn(9))).count(), 1);
}

#[test]
fn a_range_without_kept_packets_hands_back_nothing() {
    let mut state = State::new();
    lose(&mut state, &[1], 7, 100);
    assert_eq!(state.take_spuriously_lost(&(pn(3)..=pn(4))).count(), 0);
    assert_eq!(state.take_spuriously_lost(&(pn(5)..=pn(4))).count(), 0);
}

#[test]
fn kept_lost_packets_are_discarded_when_their_batchs_retention_ends() {
    let mut state = State::new();
    lose(&mut state, &[1], 7, 50);
    lose(&mut state, &[2], 8, 100);
    state.discard_expired(ms(49));
    assert_eq!(kept(&state), [(1, 50, 7), (2, 100, 8)]);
    state.discard_expired(ms(50));
    assert_eq!(kept(&state), [(2, 100, 8)]);
}

#[test]
fn packets_are_kept_as_they_are_handed_out() {
    let mut state = state_with(4);
    let mut batch = state.take_all();
    let first = batch.next().unwrap();
    batch.keep(first.number, first.sent_at, 1200);
    // the second leaves without being kept
    batch.next().unwrap();
    let third = batch.next().unwrap();
    batch.keep(third.number, third.sent_at, 1200);
    batch.finish(9, ms(100));
    assert_eq!(kept(&state), [(0, 100, 9), (2, 100, 9)]);
}

#[test]
fn the_packets_of_a_batch_can_be_looked_at_before_they_are_handed_out() {
    let mut state = state_with(3);
    let mut batch = state.detect_lost(ms(100), pn(2), ms(10), threshold());
    assert_eq!(numbers(batch.packets()), [0, 1]);
    assert_eq!(batch.next().unwrap().number.get(), 0);
    assert_eq!(numbers(batch.packets()), [1]);
}

#[test]
fn next_if_hands_out_while_the_test_holds() {
    let mut state = state_with(3);
    let mut batch = state.take_all();
    let below_two = |p: &Outstanding<Duration, ()>| p.number < pn(2);
    assert_eq!(batch.next_if(below_two).unwrap().number.get(), 0);
    assert_eq!(batch.next_if(below_two).unwrap().number.get(), 1);
    assert!(batch.next_if(below_two).is_none());
    assert_eq!(drained(batch), [2]);
}

#[test]
fn packets_not_handed_out_leave_with_the_batch() {
    let mut state = state_with(3);
    {
        let mut batch = state.detect_lost(ms(100), pn(2), ms(10), threshold());
        batch.next().unwrap();
    }
    assert_eq!(numbers(state.outstanding()), [2]);
}

#[test]
fn a_batch_dropped_without_finishing_keeps_nothing() {
    let mut state = state_with(2);
    {
        let mut batch = state.take_all();
        let packet = batch.next().unwrap();
        batch.keep(packet.number, packet.sent_at, 1200);
    }
    assert!(kept(&state).is_empty());
}

#[test]
fn a_batch_without_kept_packets_stores_no_value() {
    let mut state = state_with(2);
    drained(state.take_all());
    lose(&mut state, &[5], 7, 100);
    assert_eq!(kept(&state), [(5, 100, 7)]);
}
