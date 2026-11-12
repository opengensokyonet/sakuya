//! Attempts, judgment calls and participation

use std::pin::pin;
use std::sync::Arc;

use super::support::{
    Delivery, Judging, Local, Probe, TestDatagram, UnclaimedSink, WakeCount, drops, poll_with,
    ready, route, route_info,
};
use crate::claim::candidate::{DatagramClaimAttempt, DatagramClaimOutcome, DatagramClaimPrecheck};
use crate::claim::delivery::DatagramDelivery;
use crate::claim::erased::ErasedDatagramDeliverer;
use crate::claim::group::prepare_claim;
use crate::claim::shared::DatagramFinishPolicy;

#[test]
fn preparation_without_dispatch_runs_no_author_code() {
    let first = Probe::new(Judging::Accept);
    let second = Probe::new(Judging::Accept);
    let sink = UnclaimedSink::default();
    type Target = dyn ErasedDatagramDeliverer<TestDatagram, Local, UnclaimedSink>;
    let erased =
        |probe: &Arc<Probe>| -> (Arc<Target>, _) { (Arc::clone(probe) as _, route_info()) };

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
    drop(prepare_claim::<_, Local, _, Target, Vec<_>>(
        datagram,
        sink.policy(),
        Vec::new(),
    ));

    for probe in [&first, &second] {
        assert_eq!(probe.delivery_count(), 0);
    }
    assert_eq!(drops(&competing_drops), 1);
    assert_eq!(drops(&single_drops), 1);
    assert_eq!(drops(&empty_drops), 1);
    assert_eq!(sink.len(), 0, "an uncommitted set never hands off");
}

#[test]
fn single_last_takes_entry_is_delivered_exclusively() {
    let probe = Probe::new(Judging::Reject);
    let (datagram, datagram_drops) = TestDatagram::new(b"only");
    route(datagram, DatagramFinishPolicy::LastTakes, &[&probe]);

    let delivery = probe.take_exclusive();
    assert_eq!(
        delivery.route_match().interpretation(),
        route_info().interpretation()
    );
    let (datagram, route) = delivery.consume();
    assert_eq!(datagram.bytes(), b"only");
    assert_eq!(route.interpretation(), route_info().interpretation());
    drop(datagram);
    assert_eq!(drops(&datagram_drops), 1);
}

#[test]
fn unconsumed_single_delivery_releases_the_datagram() {
    let probe = Probe::new(Judging::Reject);
    let (datagram, datagram_drops) = TestDatagram::new(b"only");
    route(datagram, DatagramFinishPolicy::LastTakes, &[&probe]);
    let delivery = probe.take_delivery();
    // Matching and rewrapping are not consumption.
    let delivery: Delivery = match delivery {
        DatagramDelivery::Exclusive(exclusive) => DatagramDelivery::Exclusive(exclusive),
        DatagramDelivery::Competing(_) => panic!("expected an exclusive delivery"),
    };
    assert_eq!(drops(&datagram_drops), 0);
    drop(delivery);
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

    let attempt = candidate.try_exclusive(first.judgment());
    assert_eq!(other.core().participants(), 2);
    drop(attempt);
    assert_eq!(other.core().participants(), 1);
    assert_eq!(first.claim_calls(), 0);
}

#[test]
fn claimed_attempt_carries_the_delivery_and_the_judgment_value() {
    let winner = Probe::new(Judging::Accept);
    let late = Probe::new(Judging::Accept);
    let (datagram, datagram_drops) = TestDatagram::new(b"taken");
    route(datagram, DatagramFinishPolicy::LastTakes, &[&winner, &late]);
    let winning = winner.take_candidate();
    let losing = late.take_candidate();

    let DatagramClaimAttempt::Claimed(delivery, call) =
        ready(winning.try_exclusive(winner.judgment()))
    else {
        panic!("the first judgment accepts");
    };
    assert_eq!(call, 1);
    assert!(matches!(
        ready(losing.try_exclusive(late.judgment())),
        DatagramClaimAttempt::ClaimedElsewhere
    ));
    assert_eq!(late.claim_calls(), 0, "a taken datagram is not judged");

    let (datagram, route) = delivery.consume();
    assert_eq!(route.interpretation(), route_info().interpretation());
    assert_eq!(datagram.bytes(), b"taken");
    assert_eq!(drops(&datagram_drops), 0);
}

#[test]
fn unclaimed_hands_the_candidate_back_for_another_attempt() {
    let retrying = Probe::new(Judging::Reject);
    let other = Probe::new(Judging::Reject);
    let (datagram, _) = TestDatagram::new(b"retry");
    route(
        datagram,
        DatagramFinishPolicy::LastTakes,
        &[&retrying, &other],
    );
    let mut candidate = retrying.take_candidate();
    let observer = other.take_candidate();

    for calls in 1..=3 {
        let DatagramClaimAttempt::Unclaimed(next) =
            ready(candidate.try_exclusive(retrying.judgment()))
        else {
            panic!("the judgment rejects");
        };
        candidate = next;
        assert_eq!(retrying.claim_calls(), calls);
        assert_eq!(observer.core().participants(), 2);
        assert!(
            observer.core().input.try_lock().is_ok(),
            "the access is released"
        );
    }

    retrying.judge_with(Judging::Accept);
    let DatagramClaimAttempt::Claimed(_, call) =
        ready(candidate.try_exclusive(retrying.judgment()))
    else {
        panic!("the judgment accepts");
    };
    assert_eq!(call, 4);
}

#[test]
fn abandoned_judgment_exits_the_candidate_with_its_value() {
    let abandoning = Probe::new(Judging::Abandon);
    let remaining = Probe::new(Judging::Reject);
    let (datagram, datagram_drops) = TestDatagram::new(b"abandon");
    route(
        datagram,
        DatagramFinishPolicy::LastTakes,
        &[&abandoning, &remaining],
    );
    let candidate = remaining.take_candidate();
    assert_eq!(candidate.core().participants(), 2);

    let DatagramClaimAttempt::Abandoned(call) = ready(
        abandoning
            .take_candidate()
            .try_exclusive(abandoning.judgment()),
    ) else {
        panic!("the judgment abandons");
    };
    assert_eq!(call, 1);
    assert_eq!(candidate.core().participants(), 1);
    assert_eq!(drops(&datagram_drops), 0, "abandoning leaves the datagram");

    // The other candidate is the only participant left and takes it.
    let DatagramClaimAttempt::Exclusive(delivery) =
        ready(candidate.try_exclusive(remaining.judgment()))
    else {
        panic!("the sole participant takes the datagram");
    };
    assert_eq!(remaining.claim_calls(), 0);
    assert_eq!(delivery.consume().0.bytes(), b"abandon");
}

#[test]
fn last_abandoned_judgment_hands_off_under_on_unclaimed() {
    let first = Probe::new(Judging::Abandon);
    let second = Probe::new(Judging::Abandon);
    let sink = UnclaimedSink::default();
    let (datagram, _) = TestDatagram::new(b"nobody");
    route(datagram, sink.policy(), &[&first, &second]);

    let DatagramClaimAttempt::Abandoned(_) =
        ready(first.take_candidate().try_exclusive(first.judgment()))
    else {
        panic!("the judgment abandons");
    };
    assert_eq!(sink.len(), 0);
    let DatagramClaimAttempt::Abandoned(_) =
        ready(second.take_candidate().try_exclusive(second.judgment()))
    else {
        panic!("the sole participant still judges under on-unclaimed");
    };
    assert_eq!(sink.len(), 1, "the last exit handed the datagram off");
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
    let DatagramClaimAttempt::Unclaimed(candidate) =
        ready(candidate.try_exclusive(remaining.judgment()))
    else {
        panic!("two participants still compete");
    };
    assert_eq!(remaining.claim_calls(), 1);

    drop(leaving.take_candidate());
    let DatagramClaimAttempt::Exclusive(delivery) =
        ready(candidate.try_exclusive(remaining.judgment()))
    else {
        panic!("the sole participant takes the datagram");
    };
    assert_eq!(
        remaining.claim_calls(),
        1,
        "no judgment for the sole participant"
    );
    let (datagram, _) = delivery.consume();
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
    let mut attempt = pin!(candidate.try_exclusive(waiting.judgment()));
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

    let std::task::Poll::Ready(DatagramClaimAttempt::Exclusive(_)) =
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
        candidate.try_exclusive_now(checking.judgment())
    else {
        panic!("the free access completes the attempt");
    };
    assert_eq!(checking.claim_calls(), 1);

    let guard = holding.core().input.try_lock().unwrap();
    let DatagramClaimPrecheck::Deferred(candidate, judgment) =
        candidate.try_exclusive_now(checking.judgment())
    else {
        panic!("the busy access defers");
    };
    assert_eq!(
        checking.claim_calls(),
        1,
        "a deferred judgment is not called"
    );
    assert_eq!(holding.core().participants(), 2);
    drop(guard);

    // The judgment comes back unused and runs on the next attempt.
    checking.judge_with(Judging::Accept);
    assert!(matches!(
        candidate.try_exclusive_now(judgment),
        DatagramClaimPrecheck::Completed(DatagramClaimAttempt::Claimed(_, 2))
    ));
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

    let DatagramClaimAttempt::Unclaimed(candidate) =
        ready(candidate.try_exclusive(first.judgment()))
    else {
        panic!("the judgment rejects");
    };
    let stored = DatagramDelivery::Competing(candidate);
    assert_eq!(other.core().participants(), 2);
    let DatagramDelivery::Competing(candidate) = stored else {
        panic!("the stored delivery competes");
    };
    assert_eq!(other.core().participants(), 2);
    assert_eq!(
        candidate.route_match().interpretation(),
        route_info().interpretation()
    );
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
}

#[test]
fn judgment_reads_and_updates_state_it_captures() {
    /// The caller's state, as a path receiver's view of its levels.
    struct Levels {
        accepted_first_byte: Option<u8>,
        judged: Vec<u8>,
    }

    let first = Probe::new(Judging::Reject);
    let second = Probe::new(Judging::Reject);
    let (datagram, _) = TestDatagram::new(b"captured");
    route(
        datagram,
        DatagramFinishPolicy::LastTakes,
        &[&first, &second],
    );
    let mut candidate = first.take_candidate();
    let _other = second.take_candidate();
    let mut levels = Levels {
        accepted_first_byte: None,
        judged: Vec::new(),
    };

    for expected in [false, true] {
        let levels = &mut levels;
        let attempt = candidate.try_exclusive(|access, _route| {
            let first_byte = access.bytes()[0];
            levels.judged.push(first_byte);
            if levels.accepted_first_byte == Some(first_byte) {
                DatagramClaimOutcome::<_, (), _>::Claimed(access.into_exclusive(), first_byte)
            } else {
                DatagramClaimOutcome::Unclaimed(access)
            }
        });
        match ready(attempt) {
            DatagramClaimAttempt::Unclaimed(next) => {
                assert!(!expected);
                candidate = next;
                // The state the caller keeps changes between attempts.
                levels.accepted_first_byte = Some(b'c');
            }
            DatagramClaimAttempt::Claimed(delivery, first_byte) => {
                assert!(expected);
                assert_eq!(first_byte, b'c');
                assert_eq!(delivery.consume().0.bytes(), b"captured");
                break;
            }
            other => panic!("unexpected attempt {other:?}"),
        }
    }
    assert_eq!(levels.judged, b"cc");
}
