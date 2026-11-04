//! Cancelling and pausing attempts

use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Poll, Wake, Waker};

use super::support::{
    Judging, Probe, TestDatagram, UnclaimedSink, WakeCount, poll_with, ready, route,
};
use crate::claim::candidate::DatagramClaimAttempt;
use crate::claim::shared::{ClaimCore, DatagramFinishPolicy};

/// Records the participation count when the next waiter is woken.
struct ObservingWaker {
    core: Arc<ClaimCore<TestDatagram, UnclaimedSink>>,
    participants_at_wake: AtomicUsize,
}

impl Wake for ObservingWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.participants_at_wake
            .store(self.core.participants(), Ordering::SeqCst);
    }
}

#[test]
fn cancelling_a_woken_attempt_withdraws_the_wait_then_releases_the_credential() {
    let cancelled = Probe::new(Judging::Reject);
    let next = Probe::new(Judging::Accept);
    let holder = Probe::new(Judging::Reject);
    let (datagram, _) = TestDatagram::new(b"handoff");
    route(
        datagram,
        DatagramFinishPolicy::LastTakes,
        &[&cancelled, &next, &holder],
    );
    let waiting = next.take_candidate();
    let holding = holder.take_candidate();
    // The next waiter observes the exit order when the withdrawn wait hands
    // the access on: the cancelled credential is still alive then.
    let observer = Arc::new(ObservingWaker {
        core: holding.core_handle(),
        participants_at_wake: AtomicUsize::new(usize::MAX),
    });
    let next_waker = Waker::from(observer.clone());
    let DatagramClaimAttempt::Unclaimed(candidate) = ready(
        cancelled
            .take_candidate()
            .try_exclusive(cancelled.judgment()),
    ) else {
        panic!("the judgment rejects");
    };
    let guard = holding.core().input.try_lock().unwrap();

    let (cancelled_wakes, cancelled_waker) = WakeCount::waker();
    let mut next_attempt = pin!(waiting.try_exclusive(next.judgment()));
    {
        let mut cancelled_attempt = pin!(candidate.try_exclusive(cancelled.judgment()));
        assert!(poll_with(cancelled_attempt.as_mut(), &cancelled_waker).is_pending());
        assert!(poll_with(next_attempt.as_mut(), &next_waker).is_pending());
        drop(guard);
        assert_eq!(cancelled_wakes.get(), 1);
        assert_eq!(
            observer.participants_at_wake.load(Ordering::SeqCst),
            usize::MAX
        );
        assert_eq!(holding.core().participants(), 3);
    }
    assert_eq!(
        observer.participants_at_wake.load(Ordering::SeqCst),
        3,
        "the wait was withdrawn before the credential was released"
    );
    assert_eq!(holding.core().participants(), 2);
    assert_eq!(cancelled.claim_calls(), 1);

    let Poll::Ready(DatagramClaimAttempt::Claimed(..)) =
        poll_with(next_attempt.as_mut(), &next_waker)
    else {
        panic!("the next waiter takes the datagram");
    };
}

#[test]
fn cancelling_an_unwoken_attempt_leaves_other_waiters_queued() {
    let cancelled = Probe::new(Judging::Reject);
    let next = Probe::new(Judging::Accept);
    let holder = Probe::new(Judging::Reject);
    let (datagram, _) = TestDatagram::new(b"queued");
    route(
        datagram,
        DatagramFinishPolicy::LastTakes,
        &[&cancelled, &next, &holder],
    );
    let candidate = cancelled.take_candidate();
    let waiting = next.take_candidate();
    let holding = holder.take_candidate();
    let guard = holding.core().input.try_lock().unwrap();

    let (next_wakes, next_waker) = WakeCount::waker();
    let mut next_attempt = pin!(waiting.try_exclusive(next.judgment()));
    {
        let mut cancelled_attempt = pin!(candidate.try_exclusive(cancelled.judgment()));
        assert!(poll_with(cancelled_attempt.as_mut(), &WakeCount::waker().1).is_pending());
        assert!(poll_with(next_attempt.as_mut(), &next_waker).is_pending());
    }
    assert_eq!(holding.core().participants(), 2);
    assert_eq!(cancelled.claim_calls(), 0);
    assert_eq!(next_wakes.get(), 0);
    drop(guard);
    assert_eq!(next_wakes.get(), 1);
    assert!(matches!(
        poll_with(next_attempt.as_mut(), &next_waker),
        Poll::Ready(DatagramClaimAttempt::Claimed(..))
    ));
}

#[test]
fn pausing_keeps_the_same_attempt_and_its_place() {
    let paused = Probe::new(Judging::Accept);
    let holder = Probe::new(Judging::Reject);
    let (datagram, _) = TestDatagram::new(b"pause");
    route(
        datagram,
        DatagramFinishPolicy::LastTakes,
        &[&paused, &holder],
    );
    let candidate = paused.take_candidate();
    let holding = holder.take_candidate();
    let guard = holding.core().input.try_lock().unwrap();

    let (wakes, waker) = WakeCount::waker();
    let mut attempt = pin!(candidate.try_exclusive(paused.judgment()));
    assert!(poll_with(attempt.as_mut(), &waker).is_pending());
    drop(guard);
    assert_eq!(wakes.get(), 1);
    // Not polled for a while: nothing runs, the participation stays.
    assert_eq!(paused.claim_calls(), 0);
    assert_eq!(holding.core().participants(), 2);
    assert!(matches!(
        poll_with(attempt.as_mut(), &waker),
        Poll::Ready(DatagramClaimAttempt::Claimed(..))
    ));
    assert_eq!(paused.claim_calls(), 1);
}

#[test]
fn cancelled_attempts_count_as_exits_for_the_handoff() {
    let cancelled = Probe::new(Judging::Reject);
    let holder = Probe::new(Judging::Reject);
    let sink = UnclaimedSink::default();
    let (datagram, _) = TestDatagram::new(b"cancelled");
    route(datagram, sink.policy(), &[&cancelled, &holder]);
    let candidate = cancelled.take_candidate();
    let holding = holder.take_candidate();
    let guard = holding.core().input.try_lock().unwrap();

    {
        let mut attempt = pin!(candidate.try_exclusive(cancelled.judgment()));
        assert!(poll_with(attempt.as_mut(), &WakeCount::waker().1).is_pending());
    }
    drop(guard);
    assert_eq!(sink.len(), 0);
    drop(holding);
    assert_eq!(sink.len(), 1);
}
