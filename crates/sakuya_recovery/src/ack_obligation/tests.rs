use super::*;
use core::time::Duration;

type Obligation = Rfc9000AckObligation<Duration>;

fn pn(value: u64) -> PacketNumber {
    PacketNumber::new(value).unwrap()
}

fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}

/// A packet that arrived with no gap below it.
fn record(o: &mut Obligation, number: u64, at: u64, eliciting: bool) {
    let run_below = number.checked_sub(1).map(|_| pn(0));
    o.record(pn(number), ms(at), eliciting, false, run_below);
}

#[test]
fn the_tighter_of_two_dues_follows_the_order() {
    use AckDue::{By, NotDue, Now};
    assert_eq!(Now.tighter(By(ms(1))), Now);
    assert_eq!(By(ms(1)).tighter(Now), Now);
    assert_eq!(NotDue::<Duration>.tighter(Now), Now);
    assert_eq!(By(ms(5)).tighter(By(ms(3))), By(ms(3)));
    assert_eq!(By(ms(3)).tighter(By(ms(5))), By(ms(3)));
    assert_eq!(By(ms(3)).tighter(NotDue), By(ms(3)));
    assert_eq!(NotDue.tighter(By(ms(3))), By(ms(3)));
    assert_eq!(NotDue::<Duration>.tighter(NotDue), NotDue);
}

#[test]
fn only_an_instant_has_a_deadline() {
    assert_eq!(AckDue::By(ms(4)).deadline(), Some(ms(4)));
    assert_eq!(AckDue::<Duration>::Now.deadline(), None);
    assert_eq!(AckDue::<Duration>::NotDue.deadline(), None);
}

#[test]
fn nothing_is_due_at_first() {
    let o = Obligation::new(Some(ms(25)));
    assert_eq!(o.due(), AckDue::NotDue);
    assert!(!o.wants_piggyback());
}

#[test]
fn without_a_delay_an_ack_eliciting_packet_is_acknowledged_at_once() {
    let mut o = Obligation::new(None);
    record(&mut o, 0, 10, true);
    assert_eq!(o.due(), AckDue::Now);
}

#[test]
fn the_first_ack_eliciting_packet_is_acknowledged_by_the_delay() {
    let mut o = Obligation::new(Some(ms(25)));
    record(&mut o, 0, 10, true);
    assert_eq!(o.due(), AckDue::By(ms(35)));
}

#[test]
fn the_second_ack_eliciting_packet_is_acknowledged_at_once() {
    let mut o = Obligation::new(Some(ms(25)));
    record(&mut o, 0, 10, true);
    record(&mut o, 1, 12, true);
    assert_eq!(o.due(), AckDue::Now);
}

#[test]
fn a_packet_with_ce_is_acknowledged_at_once() {
    let mut o = Obligation::new(Some(ms(25)));
    o.record(pn(0), ms(10), true, true, None);
    assert_eq!(o.due(), AckDue::Now);
}

#[test]
fn a_packet_below_the_largest_ack_eliciting_one_is_acknowledged_at_once() {
    let mut o = Obligation::new(Some(ms(25)));
    record(&mut o, 5, 10, true);
    o.ack_written(pn(5));
    o.record(pn(3), ms(20), true, false, None);
    assert_eq!(o.due(), AckDue::Now);
}

#[test]
fn a_gap_below_an_ack_eliciting_packet_is_acknowledged_at_once() {
    let mut o = Obligation::new(Some(ms(25)));
    record(&mut o, 1, 10, true);
    o.ack_written(pn(1));
    // 3 does not elicit, 4 does, 2 did not arrive
    o.record(pn(3), ms(11), false, false, None);
    o.record(pn(4), ms(12), true, false, Some(pn(3)));
    assert_eq!(o.due(), AckDue::Now);
}

#[test]
fn a_run_that_reaches_the_next_number_is_not_a_gap() {
    let mut o = Obligation::new(Some(ms(25)));
    record(&mut o, 1, 10, true);
    o.ack_written(pn(1));
    // 2 arrived without eliciting, then 3 eliciting: the run below 3 starts at 2
    o.record(pn(2), ms(11), false, false, Some(pn(0)));
    o.record(pn(3), ms(12), true, false, Some(pn(0)));
    assert_eq!(o.due(), AckDue::By(ms(37)));
}

#[test]
fn a_non_ack_eliciting_packet_creates_no_obligation_but_wants_a_piggyback() {
    let mut o = Obligation::new(Some(ms(25)));
    record(&mut o, 0, 10, false);
    assert_eq!(o.due(), AckDue::NotDue);
    assert!(o.wants_piggyback());
}

#[test]
fn an_ack_eliciting_packet_wants_a_piggyback() {
    let mut o = Obligation::new(Some(ms(25)));
    record(&mut o, 0, 10, true);
    assert!(o.wants_piggyback());
}

#[test]
fn writing_an_ack_returns_what_was_due_and_clears_it() {
    let mut o = Obligation::new(Some(ms(25)));
    record(&mut o, 0, 10, true);
    assert_eq!(o.ack_written(pn(0)), AckDue::By(ms(35)));
    assert_eq!(o.due(), AckDue::NotDue);
    assert!(!o.wants_piggyback());
}

#[test]
fn the_count_of_ack_eliciting_packets_restarts_after_an_ack_is_written() {
    let mut o = Obligation::new(Some(ms(25)));
    record(&mut o, 0, 10, true);
    o.ack_written(pn(0));
    record(&mut o, 1, 20, true);
    assert_eq!(o.due(), AckDue::By(ms(45)));
}

#[test]
fn a_lost_ack_makes_the_tighter_of_the_two_due() {
    let mut o = Obligation::new(Some(ms(25)));
    record(&mut o, 0, 10, true);
    let before = o.ack_written(pn(0));
    assert_eq!(before, AckDue::By(ms(35)));
    o.ack_lost(before);
    assert_eq!(o.due(), AckDue::By(ms(35)));
}

#[test]
fn a_lost_ack_keeps_a_tighter_due_that_arose_since() {
    let mut o = Obligation::new(Some(ms(25)));
    record(&mut o, 0, 10, true);
    let before = o.ack_written(pn(0));
    record(&mut o, 1, 12, true);
    assert_eq!(o.due(), AckDue::By(ms(37)));
    o.ack_lost(before);
    assert_eq!(o.due(), AckDue::By(ms(35)));
    let mut o = Obligation::new(Some(ms(25)));
    record(&mut o, 0, 10, true);
    o.ack_lost(AckDue::By(ms(99)));
    assert_eq!(o.due(), AckDue::By(ms(35)));
}

#[test]
fn a_lost_ack_that_was_due_now_is_due_now() {
    let mut o = Obligation::new(None);
    o.ack_lost(AckDue::Now);
    assert_eq!(o.due(), AckDue::Now);
}

#[test]
fn the_deadline_turns_the_due_into_now() {
    let mut o = Obligation::new(Some(ms(25)));
    record(&mut o, 0, 10, true);
    o.on_deadline(ms(35));
    assert_eq!(o.due(), AckDue::Now);
}

#[test]
fn a_deadline_that_has_not_come_changes_nothing() {
    let mut o = Obligation::new(Some(ms(25)));
    record(&mut o, 0, 10, true);
    o.on_deadline(ms(34));
    assert_eq!(o.due(), AckDue::By(ms(35)));
}

#[test]
fn a_deadline_without_an_instant_changes_nothing() {
    let mut o = Obligation::new(Some(ms(25)));
    o.on_deadline(ms(100));
    assert_eq!(o.due(), AckDue::NotDue);
}

#[test]
fn a_later_packet_does_not_push_the_deadline_back() {
    let mut o = Obligation::new(Some(ms(25)));
    record(&mut o, 0, 10, true);
    let before = o.ack_written(pn(0));
    // the ACK was lost: By(35) is due again, and one more packet arrives
    o.ack_lost(before);
    record(&mut o, 1, 20, true);
    assert_eq!(o.due(), AckDue::By(ms(35)));
}
