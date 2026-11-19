//! Interleavings of routing over the tables shared between threads, explored
//! by Shuttle.
//!
//! The route index is `DashMapRouteIndex` of `sakuya_sync_std`, compiled
//! against a `dashmap` built on Shuttle's lock, so that every access to a
//! bucket is a scheduling point; the reflow work goes through the queue of
//! `sakuya_sync_std`, and the candidates of a datagram compete under its
//! claim lock, the mutex of `tokio`. `check_dfs` enumerates every schedule of
//! a scenario. The mutex of `tokio`, the mutexes of std and the atomics run
//! without a scheduling point inside, so interleavings within them and weak
//! memory orderings are not explored here.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use routing_shuttle::*;
use sakuya_datagram_routing::route::association::MatchAssociation;
use sakuya_datagram_routing::route::recognizer::ConnectionIdOccupancy;
use shuttle::thread;

/// A bound on the schedules of one scenario; the search must end below it.
const SCHEDULES: usize = 2_000_000;

/// Shuttle's default coroutine stacks are too small for unoptimized code
/// that keeps inline vectors on the stack.
fn config() -> shuttle::Config {
    let mut config = shuttle::Config::new();
    config.stack_size = 1 << 20;
    config
}

/// Runs `scenario` under every schedule, and fails if the bound cut the
/// search short.
fn check_dfs(name: &str, scenario: impl Fn() + Send + Sync + 'static) {
    let scheduler = shuttle::scheduler::DfsScheduler::new(Some(SCHEDULES), false);
    let started = Instant::now();
    let schedules = shuttle::Runner::new(scheduler, config()).run(scenario);
    println!(
        "{name}: explored all {schedules} schedules in {:.2?}",
        started.elapsed()
    );
    assert!(schedules < SCHEDULES, "the bound cut the search short");
}

/// The `N` items of `items`, which must have exactly `N`.
fn exactly<const N: usize, T>(items: Vec<T>, what: &str) -> [T; N] {
    let found = items.len();
    items
        .try_into()
        .unwrap_or_else(|_| panic!("expected {N} items, found {found}; {what}"))
}

/// A key is handed from its Initial association to its local association:
/// the local entry is published before the Initial one is revoked. At every
/// instant one entry applies, so the lookup of a 0-RTT packet, which reads
/// both associations within one access, finds one or both.
#[test]
fn a_handover_is_never_missed() {
    check_dfs("a_handover_is_never_missed", || {
        let domain = Domain::new(Judging::Accept);
        let (first, second) = (
            Recorder::new(Judging::Accept),
            Recorder::new(Judging::Accept),
        );
        let held = register(
            domain.index(),
            MatchAssociation::InitialDcid(key(1)),
            &first,
        );
        let writer = {
            let index = domain.index().clone();
            let second = Arc::clone(&second);
            thread::spawn(move || {
                let next = register(&index, MatchAssociation::LocalCid(key(1)), &second);
                drop(held);
                next
            })
        };
        domain.route(zero_rtt(1));
        let next = writer.join().unwrap();
        let found = first.delivered() + second.delivered();
        assert!(
            (1..=2).contains(&found),
            "a lookup found {found} of the two associations"
        );
        drop(next);
        assert_eq!(domain.index().occupancy(&key(1)), 0);
    });
}

/// Two unclaimed Initials of one key are resumed concurrently; the receiver
/// published first accepts everything. One receiver is published, and the
/// other datagram is offered to it.
#[test]
fn concurrent_rechecks_publish_once_and_offer_to_the_other() {
    check_dfs(
        "concurrent_rechecks_publish_once_and_offer_to_the_other",
        || {
            let mut domain = Domain::new(Judging::Accept);
            domain.route(initial(2));
            domain.route(initial(2));
            let [one, two] = exactly(domain.reflow(), "both Initials reflow");
            let other = {
                let router = Arc::clone(&domain.router);
                thread::spawn(move || router.resume(one))
            };
            domain.router.resume(two);
            other.join().unwrap();
            let published = domain.published();
            assert_eq!(published.len(), 1, "a second receiver was created blindly");
            let deliverer = &published[0].deliverer;
            assert_eq!(deliverer.delivered(), 1, "the other datagram is offered");
            assert_eq!(deliverer.settle_all(), 1);
            assert!(domain.reflow().is_empty(), "a claimed datagram reflows");
            assert_eq!(domain.index().occupancy(&key(2)), 1);
        },
    );
}

/// When the first published receiver leaves the other datagram, that
/// datagram reflows once and creates its own receiver: creation is not
/// suppressed, it only comes after the chance.
#[test]
fn a_receiver_that_exits_lets_the_other_datagram_create() {
    check_dfs(
        "a_receiver_that_exits_lets_the_other_datagram_create",
        || {
            let mut domain = Domain::new(Judging::Reject);
            domain.route(initial(3));
            domain.route(initial(3));
            let [one, two] = exactly(domain.reflow(), "both Initials reflow");
            let other = {
                let router = Arc::clone(&domain.router);
                thread::spawn(move || router.resume(one))
            };
            domain.router.resume(two);
            other.join().unwrap();
            let [first] = exactly(domain.published(), "one receiver is published");
            assert_eq!(first.deliverer.settle_all(), 0);
            let [work] = exactly(domain.reflow(), "the exit hands the datagram off once");
            domain.router.resume(work);
            let second = domain.published();
            assert_eq!(second.len(), 1);
            assert_eq!(first.deliverer.delivered(), 1, "one chance per datagram");
            assert_eq!(domain.index().occupancy(&key(3)), 2);
        },
    );
}

/// A local entry registered while a recheck runs is either offered the
/// datagram, when it came first, or a legal later registration beside the
/// published receiver. The datagram is never lost and never given to both.
#[test]
fn a_local_entry_races_the_recheck() {
    check_dfs("a_local_entry_races_the_recheck", || {
        let mut domain = Domain::new(Judging::Accept);
        domain.route(initial(4));
        let [work] = exactly(domain.reflow(), "the Initial reflows");
        let local = Recorder::new(Judging::Accept);
        let registering = {
            let index = domain.index().clone();
            let local = Arc::clone(&local);
            thread::spawn(move || register(&index, MatchAssociation::LocalCid(key(4)), &local))
        };
        domain.router.resume(work);
        let registration = registering.join().unwrap();
        let published = domain.published();
        assert_eq!(local.delivered() + published.len(), 1);
        assert_eq!(local.settle_all(), local.delivered());
        assert!(domain.reflow().is_empty(), "a claimed datagram reflows");
        drop(published);
        drop(registration);
        assert_eq!(domain.index().occupancy(&key(4)), 0);
    });
}

/// Revoking one entry and registering another under the same key, while a
/// lookup runs: exactly the revoked instance goes, the bucket survives for the
/// other, and the lookup sees a consistent subset of the two.
#[test]
fn revocation_removes_exactly_its_instance() {
    check_dfs("revocation_removes_exactly_its_instance", || {
        let domain = Domain::new(Judging::Accept);
        let (old, new) = (
            Recorder::new(Judging::Accept),
            Recorder::new(Judging::Accept),
        );
        let held = register(domain.index(), MatchAssociation::LocalCid(key(5)), &old);
        let revoking = thread::spawn(move || drop(held));
        let registering = {
            let index = domain.index().clone();
            let new = Arc::clone(&new);
            thread::spawn(move || register(&index, MatchAssociation::LocalCid(key(5)), &new))
        };
        domain.route(zero_rtt(5));
        revoking.join().unwrap();
        let registration = registering.join().unwrap();
        assert!(old.delivered() <= 1 && new.delivered() <= 1);
        assert_eq!(domain.index().occupancy(&key(5)), 1);
        drop(registration);
        assert_eq!(domain.index().occupancy(&key(5)), 0);
    });
}

/// A receiver that closes while another Initial of its key arrives: the
/// datagram reaches the old deliverer, which stays callable, or reflows at
/// once. Either way it reflows exactly once and is not lost.
#[test]
fn a_closing_receiver_races_a_new_datagram() {
    check_dfs("a_closing_receiver_races_a_new_datagram", || {
        let mut domain = Domain::new(Judging::Reject);
        domain.route(initial(6));
        let [work] = exactly(domain.reflow(), "the Initial reflows");
        domain.router.resume(work);
        let [first] = exactly(domain.published(), "the receiver is published");
        let old = Arc::clone(&first.deliverer);
        let closing = thread::spawn(move || drop(first));
        domain.route(initial(6));
        closing.join().unwrap();
        assert!(old.delivered() <= 1);
        assert_eq!(old.settle_all(), 0);
        assert_eq!(
            domain.reflow().len(),
            1,
            "the datagram reflows exactly once"
        );
        assert_eq!(domain.index().occupancy(&key(6)), 0);
    });
}

/// Competing candidates on separate threads: one winner, the others see the
/// datagram gone or exit, and nothing is handed off.
#[test]
fn one_candidate_of_several_wins() {
    check_dfs("one_candidate_of_several_wins", || {
        let mut domain = Domain::new(Judging::Accept);
        let recorders = [
            Recorder::new(Judging::Accept),
            Recorder::new(Judging::Accept),
            Recorder::new(Judging::Reject),
        ];
        let registrations: Vec<_> = recorders
            .iter()
            .map(|recorder| {
                register(
                    domain.index(),
                    MatchAssociation::InitialDcid(key(7)),
                    recorder,
                )
            })
            .collect();
        domain.route(initial(7));
        let winners = Arc::new(AtomicUsize::new(0));
        let attempts: Vec<_> = recorders
            .iter()
            .map(|recorder| {
                let [delivery] = exactly(recorder.take(), "one delivery per entry");
                let judging = recorder.judging();
                let winners = Arc::clone(&winners);
                thread::spawn(move || {
                    if settle(delivery, judging) {
                        winners.fetch_add(1, Ordering::SeqCst);
                    }
                })
            })
            .collect();
        for attempt in attempts {
            attempt.join().unwrap();
        }
        assert_eq!(winners.load(Ordering::SeqCst), 1, "exactly one winner");
        assert!(
            domain.reflow().is_empty(),
            "a taken datagram is not handed off"
        );
        drop(registrations);
    });
}

/// Every candidate exits, concurrently: the datagram is handed off exactly
/// once, with the complete history, so the next round offers it to no
/// existing entry and publishes a receiver.
#[test]
fn concurrent_exits_hand_off_once() {
    check_dfs("concurrent_exits_hand_off_once", || {
        let mut domain = Domain::new(Judging::Accept);
        let recorders = [
            Recorder::new(Judging::Reject),
            Recorder::new(Judging::Reject),
        ];
        let registrations: Vec<_> = recorders
            .iter()
            .map(|recorder| {
                register(
                    domain.index(),
                    MatchAssociation::InitialDcid(key(8)),
                    recorder,
                )
            })
            .collect();
        domain.route(initial(8));
        let exits: Vec<_> = recorders
            .iter()
            .map(|recorder| {
                let [delivery] = exactly(recorder.take(), "one delivery per entry");
                let judging = recorder.judging();
                thread::spawn(move || assert!(!settle(delivery, judging)))
            })
            .collect();
        for exit in exits {
            exit.join().unwrap();
        }
        let [work] = exactly(domain.reflow(), "handed off once");
        domain.router.resume(work);
        assert_eq!(domain.published().len(), 1, "both entries had their chance");
        for recorder in &recorders {
            assert_eq!(recorder.delivered(), 1);
        }
        drop(registrations);
    });
}
