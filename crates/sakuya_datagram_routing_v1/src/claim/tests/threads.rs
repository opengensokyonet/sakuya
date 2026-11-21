//! Candidates moved to and competing on other threads

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::support::{Judging, Probe, TestDatagram, UnclaimedSink, block_on, drops, route};
use crate::claim::candidate::DatagramClaimAttempt;
use crate::claim::shared::DatagramFinishPolicy;

const THREADS: usize = 8;

fn probes(judging: Judging) -> Vec<Arc<Probe>> {
    (0..THREADS).map(|_| Probe::new(judging)).collect()
}

#[test]
fn concurrent_exits_hand_off_exactly_once() {
    let probes = probes(Judging::Reject);
    let sink = UnclaimedSink::default();
    let (datagram, _) = TestDatagram::new(b"threads");
    route(datagram, sink.policy(), &probes.iter().collect::<Vec<_>>());

    std::thread::scope(|scope| {
        for probe in &probes {
            let candidate = probe.take_candidate();
            let judgment = probe.judgment();
            scope.spawn(move || match block_on(candidate.try_exclusive(judgment)) {
                DatagramClaimAttempt::Unclaimed(candidate) => drop(candidate),
                _ => panic!("every judgment rejects"),
            });
        }
    });
    assert_eq!(sink.len(), 1);
}

#[test]
fn concurrent_attempts_have_exactly_one_winner() {
    let probes = probes(Judging::Accept);
    let (datagram, datagram_drops) = TestDatagram::new(b"threads");
    route(
        datagram,
        DatagramFinishPolicy::LastTakes,
        &probes.iter().collect::<Vec<_>>(),
    );

    let claimed = AtomicUsize::new(0);
    let elsewhere = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for probe in &probes {
            let candidate = probe.take_candidate();
            let judgment = probe.judgment();
            let (claimed, elsewhere) = (&claimed, &elsewhere);
            scope.spawn(move || match block_on(candidate.try_exclusive(judgment)) {
                DatagramClaimAttempt::Claimed(delivery, _)
                | DatagramClaimAttempt::Exclusive(delivery) => {
                    claimed.fetch_add(1, Ordering::SeqCst);
                    drop(delivery.consume());
                }
                DatagramClaimAttempt::ClaimedElsewhere => {
                    elsewhere.fetch_add(1, Ordering::SeqCst);
                }
                DatagramClaimAttempt::Unclaimed(_) | DatagramClaimAttempt::Abandoned(_) => {
                    panic!("every judgment accepts")
                }
            });
        }
    });
    assert_eq!(claimed.load(Ordering::SeqCst), 1);
    assert_eq!(elsewhere.load(Ordering::SeqCst), THREADS - 1);
    assert_eq!(drops(&datagram_drops), 1);
    // Only the attempt that found the datagram ran its judgment.
    let claim_calls: usize = probes.iter().map(|probe| probe.claim_calls()).sum();
    assert!(claim_calls <= 1);
}
