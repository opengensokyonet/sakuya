//! The two finish policies

use super::support::{Judging, Probe, TestDatagram, UnclaimedSink, drops, ready, route};
use crate::claim::DatagramClaimAttempt;
use crate::claim::shared::DatagramFinishPolicy;

#[test]
fn last_takes_releases_the_datagram_when_all_exit() {
    let first = Probe::new(Judging::Reject);
    let second = Probe::new(Judging::Reject);
    let (datagram, datagram_drops) = TestDatagram::new(b"released");
    route(
        datagram,
        DatagramFinishPolicy::LastTakes,
        &[&first, &second],
    );
    let DatagramClaimAttempt::Unclaimed(candidate) = ready(first.take_candidate().try_exclusive())
    else {
        panic!("two participants still compete");
    };
    drop(second.take_candidate());
    assert_eq!(drops(&datagram_drops), 0);
    drop(candidate);
    assert_eq!(drops(&datagram_drops), 1);
}

#[test]
fn on_unclaimed_hands_off_once_from_the_last_exit() {
    let first = Probe::new(Judging::Reject);
    let second = Probe::new(Judging::Reject);
    let sink = UnclaimedSink::default();
    let (datagram, datagram_drops) = TestDatagram::new(b"unclaimed");
    route(datagram, sink.policy(), &[&first, &second]);

    let DatagramClaimAttempt::Unclaimed(first_candidate) =
        ready(first.take_candidate().try_exclusive())
    else {
        panic!("the judgment rejects");
    };
    let DatagramClaimAttempt::Unclaimed(second_candidate) =
        ready(second.take_candidate().try_exclusive())
    else {
        panic!("the sole participant still judges under on-unclaimed");
    };
    drop(first_candidate);
    assert_eq!(sink.len(), 0);
    drop(second_candidate);
    // Handed off synchronously by the last exit.
    let work = sink.take();
    assert_eq!(work.len(), 1);
    assert_eq!(drops(&datagram_drops), 0);
    let work = work.into_iter().next().unwrap();
    assert_eq!(work.datagram().as_ref(), b"unclaimed");
    // Routing resumes from the datagram, its history and the continuation.
    let (datagram, _offered, _continuation) = work.into_parts();
    drop(datagram);
    assert_eq!(drops(&datagram_drops), 1);
}

#[test]
fn single_on_unclaimed_entry_competes_and_judges() {
    let only = Probe::new(Judging::Reject);
    let sink = UnclaimedSink::default();
    let (datagram, _) = TestDatagram::new(b"single");
    route(datagram, sink.policy(), &[&only]);

    let DatagramClaimAttempt::Unclaimed(candidate) = ready(only.take_candidate().try_exclusive())
    else {
        panic!("a single on-unclaimed participant is judged");
    };
    assert_eq!(only.claim_calls(), 1);
    drop(candidate);
    assert_eq!(sink.len(), 1);
}

#[test]
fn on_unclaimed_without_entries_hands_off_at_dispatch() {
    let sink = UnclaimedSink::default();
    let (datagram, datagram_drops) = TestDatagram::new(b"nobody");
    route(datagram, sink.policy(), &[]);
    assert_eq!(sink.len(), 1);
    let datagram = sink.take().pop().unwrap().into_datagram();
    assert_eq!(drops(&datagram_drops), 0);
    drop(datagram);
    assert_eq!(drops(&datagram_drops), 1);
}

#[test]
fn last_takes_without_entries_releases_at_dispatch() {
    let (datagram, datagram_drops) = TestDatagram::new(b"nobody");
    route(datagram, DatagramFinishPolicy::LastTakes, &[]);
    assert_eq!(drops(&datagram_drops), 1);
}

#[test]
fn winner_dropping_its_datagram_neither_refills_nor_hands_off() {
    let winner = Probe::new(Judging::Accept);
    let other = Probe::new(Judging::Accept);
    let sink = UnclaimedSink::default();
    let (datagram, datagram_drops) = TestDatagram::new(b"won");
    route(datagram, sink.policy(), &[&winner, &other]);
    let losing = other.take_candidate();

    let DatagramClaimAttempt::Claimed(delivery) = ready(winner.take_candidate().try_exclusive())
    else {
        panic!("the judgment accepts");
    };
    // The receiver rejects the claimed datagram.
    drop(delivery);
    assert_eq!(drops(&datagram_drops), 1);
    assert!(matches!(
        ready(losing.try_exclusive()),
        DatagramClaimAttempt::ClaimedElsewhere
    ));
    assert_eq!(sink.len(), 0);
}

#[test]
fn losers_exiting_after_a_win_do_not_hand_off() {
    let winner = Probe::new(Judging::Accept);
    let other = Probe::new(Judging::Reject);
    let sink = UnclaimedSink::default();
    let (datagram, _) = TestDatagram::new(b"won");
    route(datagram, sink.policy(), &[&winner, &other]);
    let losing = other.take_candidate();
    let DatagramClaimAttempt::Claimed(_delivery) = ready(winner.take_candidate().try_exclusive())
    else {
        panic!("the judgment accepts");
    };
    drop(losing);
    assert_eq!(sink.len(), 0);
}
