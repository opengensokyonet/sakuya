//! Attempts, factory calls and participation

use std::pin::pin;
use std::sync::Arc;

use super::support::{
    Judging, Probe, TestDatagram, UnclaimedSink, WakeCount, drops, poll_with, ready, route,
};
use crate::claim::group::prepare_claim;
use crate::claim::shared::DatagramFinishPolicy;
use crate::claim::{
    DatagramClaimAttempt, DatagramClaimPrecheck, DatagramDelivery, DatagramRouteMatchInfo,
    ErasedDatagramDeliverer,
};

#[test]
fn preparation_without_dispatch_runs_no_author_code() {
    let first = Probe::new(Judging::Accept);
    let second = Probe::new(Judging::Accept);
    let sink = UnclaimedSink::default();
    let erased = |probe: &Arc<Probe>| -> (Arc<dyn ErasedDatagramDeliverer<TestDatagram>>, _) {
        (Arc::clone(probe) as _, DatagramRouteMatchInfo::new())
    };

    let (datagram, competing_drops) = TestDatagram::new(b"competing");
    drop(prepare_claim(
        datagram,
        sink.policy(),
        vec![erased(&first), erased(&second)],
    ));
    let (datagram, single_drops) = TestDatagram::new(b"single");
    drop(prepare_claim(
        datagram,
        DatagramFinishPolicy::LastTakes,
        vec![erased(&first)],
    ));
    let (datagram, empty_drops) = TestDatagram::new(b"empty");
    drop(
        prepare_claim::<_, dyn ErasedDatagramDeliverer<TestDatagram>>(
            datagram,
            sink.policy(),
            Vec::new(),
        ),
    );

    for probe in [&first, &second] {
        assert_eq!(probe.factory_calls(), 0);
        assert_eq!(probe.claim_calls(), 0);
        assert_eq!(probe.delivery_count(), 0);
    }
    assert_eq!(drops(&competing_drops), 1);
    assert_eq!(drops(&single_drops), 1);
    assert_eq!(drops(&empty_drops), 1);
    assert_eq!(sink.len(), 0, "an uncommitted set never hands off");
}

#[test]
fn single_last_takes_entry_initializes_state_only_on_consume() {
    let probe = Probe::new(Judging::Reject);
    let (datagram, datagram_drops) = TestDatagram::new(b"only");
    route(datagram, DatagramFinishPolicy::LastTakes, &[&probe]);

    let delivery = probe.take_exclusive();
    assert!(delivery.initialized_state().is_none());
    assert_eq!(probe.factory_calls(), 0);

    let (datagram, state) = delivery.consume();
    assert_eq!(probe.factory_calls(), 1);
    assert_eq!(probe.claim_calls(), 0);
    assert_eq!(datagram.bytes(), b"only");
    assert_eq!(state.state().judgments, 0);
    drop(datagram);
    assert_eq!(drops(&datagram_drops), 1);
}

#[test]
fn unconsumed_single_delivery_never_runs_the_factory() {
    let probe = Probe::new(Judging::Reject);
    let (datagram, datagram_drops) = TestDatagram::new(b"only");
    route(datagram, DatagramFinishPolicy::LastTakes, &[&probe]);
    let delivery = probe.take_delivery();
    // Matching and rewrapping are not consumption.
    let delivery = match delivery {
        DatagramDelivery::Exclusive(exclusive) => DatagramDelivery::Exclusive(exclusive),
        DatagramDelivery::Competing(_) => panic!("expected an exclusive delivery"),
    };
    drop(delivery);
    assert_eq!(probe.factory_calls(), 0);
    assert_eq!(drops(&datagram_drops), 1);
}

#[test]
fn unpolled_attempt_calls_nothing_and_exits_on_drop() {
    let first = Probe::new(Judging::Reject);
    let second = Probe::new(Judging::Reject);
    let (datagram, _) = TestDatagram::new(b"lazy");
    route(
        datagram,
        DatagramFinishPolicy::LastTakes,
        &[&first, &second],
    );
    let candidate = first.take_candidate();
    let other = second.take_candidate();
    assert_eq!(other.core().participants(), 2);

    let attempt = candidate.try_exclusive();
    assert_eq!(other.core().participants(), 2);
    drop(attempt);
    assert_eq!(other.core().participants(), 1);
    assert_eq!(first.factory_calls(), 0);
    assert_eq!(first.claim_calls(), 0);
}

#[test]
fn candidate_of_a_taken_datagram_skips_the_factory() {
    let winner = Probe::new(Judging::Accept);
    let late = Probe::new(Judging::Accept);
    let (datagram, datagram_drops) = TestDatagram::new(b"taken");
    route(datagram, DatagramFinishPolicy::LastTakes, &[&winner, &late]);
    let winning = winner.take_candidate();
    let losing = late.take_candidate();

    let DatagramClaimAttempt::Claimed(delivery) = ready(winning.try_exclusive()) else {
        panic!("the first judgment accepts");
    };
    assert!(matches!(
        ready(losing.try_exclusive()),
        DatagramClaimAttempt::ClaimedElsewhere
    ));
    assert_eq!(late.factory_calls(), 0);
    assert_eq!(late.claim_calls(), 0);

    // Consuming a won competition hands over the existing state.
    let (datagram, state) = delivery.consume();
    assert_eq!(winner.factory_calls(), 1);
    assert_eq!(state.state().judgments, 1);
    assert_eq!(datagram.bytes(), b"taken");
    assert_eq!(drops(&datagram_drops), 0);
}

#[test]
fn unclaimed_retries_reuse_the_state_initialized_once() {
    let retrying = Probe::new(Judging::Reject);
    let other = Probe::new(Judging::Reject);
    let (datagram, _) = TestDatagram::new(b"retry");
    route(
        datagram,
        DatagramFinishPolicy::LastTakes,
        &[&retrying, &other],
    );
    let mut candidate = retrying.take_candidate();
    let _other = other.take_candidate();
    assert!(candidate.initialized_state().is_none());

    for judgments in 1..=3 {
        let DatagramClaimAttempt::Unclaimed(next) = ready(candidate.try_exclusive()) else {
            panic!("the judgment rejects");
        };
        candidate = next;
        assert_eq!(candidate.initialized_state().unwrap().judgments, judgments);
    }
    assert_eq!(retrying.factory_calls(), 1);
    assert_eq!(retrying.claim_calls(), 3);
    assert_eq!(drops(&retrying.state_drops), 0);

    retrying.judge_with(Judging::Accept);
    let DatagramClaimAttempt::Claimed(delivery) = ready(candidate.try_exclusive()) else {
        panic!("the judgment accepts");
    };
    let (_, state) = delivery.consume();
    assert_eq!(state.state().judgments, 4);
    assert_eq!(retrying.factory_calls(), 1);
}

#[test]
fn sole_last_takes_participant_takes_without_judging() {
    let remaining = Probe::new(Judging::Reject);
    let leaving = Probe::new(Judging::Reject);
    let (datagram, _) = TestDatagram::new(b"last");
    route(
        datagram,
        DatagramFinishPolicy::LastTakes,
        &[&remaining, &leaving],
    );
    let candidate = remaining.take_candidate();
    let DatagramClaimAttempt::Unclaimed(candidate) = ready(candidate.try_exclusive()) else {
        panic!("two participants still compete");
    };
    assert_eq!(remaining.claim_calls(), 1);

    drop(leaving.take_candidate());
    let DatagramClaimAttempt::Claimed(delivery) = ready(candidate.try_exclusive()) else {
        panic!("the sole participant takes the datagram");
    };
    assert_eq!(
        remaining.claim_calls(),
        1,
        "no judgment for the sole participant"
    );
    assert_eq!(remaining.factory_calls(), 1);
    let (datagram, _) = delivery.consume();
    assert_eq!(remaining.factory_calls(), 1);
    assert_eq!(datagram.bytes(), b"last");
}

#[test]
fn participation_count_excludes_waits_and_counts_undelivered_candidates() {
    let waiting = Probe::new(Judging::Reject);
    let holder = Probe::new(Judging::Reject);
    let leaving = Probe::new(Judging::Reject);
    let (datagram, _) = TestDatagram::new(b"count");
    route(
        datagram,
        DatagramFinishPolicy::LastTakes,
        &[&waiting, &holder, &leaving],
    );
    let candidate = waiting.take_candidate();
    let holding = holder.take_candidate();
    let leaver = leaving.take_candidate();
    assert_eq!(holding.core().participants(), 3);

    let guard = holding.core().input.try_lock().unwrap();
    let (wakes, waker) = WakeCount::waker();
    let mut attempt = pin!(candidate.try_exclusive());
    assert!(poll_with(attempt.as_mut(), &waker).is_pending());
    assert_eq!(
        holding.core().participants(),
        3,
        "a wait adds no participant"
    );

    drop(leaver);
    assert_eq!(holding.core().participants(), 2);
    drop(guard);
    assert_eq!(wakes.get(), 1);
    drop(holding);

    let std::task::Poll::Ready(DatagramClaimAttempt::Claimed(_)) =
        poll_with(attempt.as_mut(), &waker)
    else {
        panic!("the sole participant takes the datagram");
    };
    assert_eq!(waiting.claim_calls(), 0);
}

#[test]
fn immediate_attempt_runs_when_free_and_defers_when_busy() {
    let checking = Probe::new(Judging::Reject);
    let holder = Probe::new(Judging::Reject);
    let (datagram, _) = TestDatagram::new(b"now");
    route(
        datagram,
        DatagramFinishPolicy::LastTakes,
        &[&checking, &holder],
    );
    let candidate = checking.take_candidate();
    let holding = holder.take_candidate();

    let DatagramClaimPrecheck::Completed(DatagramClaimAttempt::Unclaimed(candidate)) =
        candidate.try_exclusive_now()
    else {
        panic!("the free access completes the attempt");
    };
    assert_eq!(checking.factory_calls(), 1);
    assert_eq!(checking.claim_calls(), 1);

    let guard = holding.core().input.try_lock().unwrap();
    let DatagramClaimPrecheck::Deferred(candidate) = candidate.try_exclusive_now() else {
        panic!("the busy access defers");
    };
    assert_eq!(checking.factory_calls(), 1);
    assert_eq!(checking.claim_calls(), 1);
    assert_eq!(candidate.initialized_state().unwrap().judgments, 1);
    assert_eq!(holding.core().participants(), 2);
    drop(guard);

    checking.judge_with(Judging::Accept);
    assert!(matches!(
        candidate.try_exclusive_now(),
        DatagramClaimPrecheck::Completed(DatagramClaimAttempt::Claimed(_))
    ));
}

#[test]
fn immediate_attempt_on_an_untouched_candidate_initializes_on_access() {
    let checking = Probe::new(Judging::Reject);
    let holder = Probe::new(Judging::Reject);
    let (datagram, _) = TestDatagram::new(b"busy");
    route(
        datagram,
        DatagramFinishPolicy::LastTakes,
        &[&checking, &holder],
    );
    let candidate = checking.take_candidate();
    let holding = holder.take_candidate();

    let guard = holding.core().input.try_lock().unwrap();
    let DatagramClaimPrecheck::Deferred(candidate) = candidate.try_exclusive_now() else {
        panic!("the busy access defers");
    };
    assert!(candidate.initialized_state().is_none());
    assert_eq!(checking.factory_calls(), 0);
    drop(guard);
}

#[test]
fn rewrapped_candidate_keeps_its_participation() {
    let first = Probe::new(Judging::Reject);
    let second = Probe::new(Judging::Reject);
    let (datagram, _) = TestDatagram::new(b"wrap");
    route(
        datagram,
        DatagramFinishPolicy::LastTakes,
        &[&first, &second],
    );
    let candidate = first.take_candidate();
    let other = second.take_candidate();

    let DatagramClaimAttempt::Unclaimed(candidate) = ready(candidate.try_exclusive()) else {
        panic!("the judgment rejects");
    };
    let stored = DatagramDelivery::Competing(candidate);
    assert_eq!(other.core().participants(), 2);
    let DatagramDelivery::Competing(candidate) = stored else {
        panic!("the stored delivery competes");
    };
    assert_eq!(other.core().participants(), 2);
    assert_eq!(candidate.initialized_state().unwrap().judgments, 1);
    assert_eq!(first.factory_calls(), 1);
}

#[test]
fn deliverers_of_one_type_and_repeated_entries_are_distinct_targets() {
    let first = Probe::new(Judging::Reject);
    let second = Probe::new(Judging::Reject);
    let (datagram, _) = TestDatagram::new(b"targets");
    // The second probe appears twice, as under two interpretations.
    route(
        datagram,
        DatagramFinishPolicy::LastTakes,
        &[&first, &second, &second],
    );
    assert_eq!(first.delivery_count(), 1);
    assert_eq!(second.delivery_count(), 2);

    let only = first.take_candidate();
    assert_eq!(only.core().participants(), 3);
    let DatagramClaimAttempt::Unclaimed(_kept) = ready(only.try_exclusive()) else {
        panic!("the judgment rejects");
    };
    assert_eq!(first.factory_calls(), 1);
    assert_eq!(second.factory_calls(), 0, "states are never shared");
}
