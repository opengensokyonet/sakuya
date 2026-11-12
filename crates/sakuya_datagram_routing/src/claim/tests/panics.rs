//! Panics in author code, per the impact table of the mechanism

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::pin;
use std::task::Waker;

use super::support::{
    Delivery, Judging, Local, Probe, TestDatagram, UnclaimedSink, drops, poll_with, ready, route,
};
use crate::claim::candidate::DatagramClaimAttempt;
use crate::claim::deliverer::DatagramDeliverer;

#[test]
fn judgment_panic_before_the_take_keeps_the_datagram_for_others() {
    let panicking = Probe::new(Judging::PanicBeforeTake);
    let other = Probe::new(Judging::Accept);
    let sink = UnclaimedSink::default();
    let (datagram, datagram_drops) = TestDatagram::new(b"kept");
    route(datagram, sink.policy(), &[&panicking, &other]);
    let surviving = other.take_candidate();

    let mut attempt = pin!(
        panicking
            .take_candidate()
            .try_exclusive(panicking.judgment())
    );
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        poll_with(attempt.as_mut(), Waker::noop())
    }));
    assert!(unwound.is_err());
    // The candidate went with the unwinding; the access is free again.
    assert_eq!(surviving.core().participants(), 1);
    assert!(surviving.core().input.try_lock().is_ok());
    assert_eq!(drops(&datagram_drops), 0);
    assert_eq!(sink.len(), 0, "the panic is not an unclaimed outcome");

    // The failed attempt cannot be advanced again, and does not rerun the
    // judgment.
    let again = catch_unwind(AssertUnwindSafe(|| {
        poll_with(attempt.as_mut(), Waker::noop())
    }));
    assert!(again.is_err());
    assert_eq!(panicking.claim_calls(), 1);

    let DatagramClaimAttempt::Claimed(delivery, _) =
        ready(surviving.try_exclusive(other.judgment()))
    else {
        panic!("the datagram is still available");
    };
    assert_eq!(delivery.consume().0.bytes(), b"kept");
}

#[test]
fn panic_after_the_take_leaves_the_slot_empty() {
    let panicking = Probe::new(Judging::PanicAfterTake);
    let other = Probe::new(Judging::Accept);
    let sink = UnclaimedSink::default();
    let (datagram, datagram_drops) = TestDatagram::new(b"gone");
    route(datagram, sink.policy(), &[&panicking, &other]);
    let surviving = other.take_candidate();

    let unwound = catch_unwind(AssertUnwindSafe(|| {
        ready(
            panicking
                .take_candidate()
                .try_exclusive(panicking.judgment()),
        )
    }));
    assert!(unwound.is_err());
    assert_eq!(drops(&datagram_drops), 1, "the exclusive owner dropped it");
    assert!(matches!(
        ready(surviving.try_exclusive(other.judgment())),
        DatagramClaimAttempt::ClaimedElsewhere
    ));
    assert_eq!(other.claim_calls(), 0);
    assert_eq!(sink.len(), 0);
    assert_eq!(drops(&datagram_drops), 1);
}

/// Panics in `deliver`, as when a deliverer consumes on the spot and fails.
struct PanickingDeliverer;

impl DatagramDeliverer<TestDatagram, Local> for PanickingDeliverer {
    type Handoff = UnclaimedSink;

    fn deliver(&self, _delivery: Delivery) {
        panic!("simulated deliver panic");
    }
}

#[test]
fn deliver_panic_releases_the_candidates_not_yet_delivered() {
    use std::sync::Arc;

    use crate::claim::erased::SendDatagramDeliverer;
    use crate::claim::group::prepare_claim;

    let later = Probe::new(Judging::Accept);
    let sink = UnclaimedSink::default();
    let (datagram, datagram_drops) = TestDatagram::new(b"dispatch");
    type Target = dyn SendDatagramDeliverer<TestDatagram, Local, UnclaimedSink>;
    let entries: Vec<(Arc<Target>, _)> = vec![
        (Arc::new(PanickingDeliverer), super::support::route_info()),
        (later.clone(), super::support::route_info()),
    ];
    let prepared = prepare_claim(datagram, sink.policy(), entries);
    let unwound = catch_unwind(AssertUnwindSafe(|| prepared.dispatch()));
    assert!(unwound.is_err());
    assert_eq!(later.delivery_count(), 0);
    // Every participant exited after the set was committed.
    assert_eq!(sink.len(), 1);
    drop(sink.take());
    assert_eq!(drops(&datagram_drops), 1);
}
