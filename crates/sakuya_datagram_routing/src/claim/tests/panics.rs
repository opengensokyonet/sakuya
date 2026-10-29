//! Panics in author code, per the impact table of the mechanism

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::pin;
use std::task::Waker;

use super::support::{Judging, Probe, TestDatagram, UnclaimedSink, drops, poll_with, ready, route};
use crate::claim::candidate::DatagramClaimAttempt;
use crate::claim::deliverer::DatagramDeliverer;
use crate::claim::delivery::DatagramDelivery;
use crate::claim::shared::DatagramFinishPolicy;

#[test]
fn factory_panic_before_the_take_keeps_the_datagram_for_others() {
    let panicking = Probe::new(Judging::Accept);
    let other = Probe::new(Judging::Accept);
    panicking.panic_in_factory();
    let (datagram, datagram_drops) = TestDatagram::new(b"kept");
    route(
        datagram,
        DatagramFinishPolicy::LastTakes,
        &[&panicking, &other],
    );
    let surviving = other.take_candidate();

    let mut attempt = pin!(panicking.take_candidate().try_exclusive());
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        poll_with(attempt.as_mut(), Waker::noop())
    }));
    assert!(unwound.is_err());
    // The candidate went with the unwinding; the access is free again.
    assert_eq!(surviving.core().participants(), 1);
    assert!(surviving.core().input.try_lock().is_ok());
    assert_eq!(drops(&datagram_drops), 0);

    // The failed attempt cannot be advanced again, and does not rerun the
    // factory.
    let again = catch_unwind(AssertUnwindSafe(|| {
        poll_with(attempt.as_mut(), Waker::noop())
    }));
    assert!(again.is_err());
    assert_eq!(panicking.factory_calls(), 1);

    let DatagramClaimAttempt::Claimed(delivery) = ready(surviving.try_exclusive()) else {
        panic!("the datagram is still available");
    };
    assert_eq!(delivery.consume().0.bytes(), b"kept");
}

#[test]
fn judgment_panic_before_the_take_keeps_the_datagram_for_others() {
    let panicking = Probe::new(Judging::PanicBeforeTake);
    let other = Probe::new(Judging::Accept);
    let sink = UnclaimedSink::default();
    let (datagram, _) = TestDatagram::new(b"kept");
    route(datagram, sink.policy(), &[&panicking, &other]);
    let surviving = other.take_candidate();

    let mut attempt = pin!(panicking.take_candidate().try_exclusive());
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        poll_with(attempt.as_mut(), Waker::noop())
    }));
    assert!(unwound.is_err());
    assert_eq!(drops(&panicking.state_drops), 1);
    assert_eq!(sink.len(), 0, "the panic is not an unclaimed outcome");
    assert!(matches!(
        ready(surviving.try_exclusive()),
        DatagramClaimAttempt::Claimed(_)
    ));
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
        ready(panicking.take_candidate().try_exclusive())
    }));
    assert!(unwound.is_err());
    assert_eq!(drops(&datagram_drops), 1, "the exclusive owner dropped it");
    assert!(matches!(
        ready(surviving.try_exclusive()),
        DatagramClaimAttempt::ClaimedElsewhere
    ));
    assert_eq!(other.factory_calls(), 0);
    assert_eq!(sink.len(), 0);
    assert_eq!(drops(&datagram_drops), 1);
}

#[test]
fn factory_panic_while_consuming_a_single_delivery_releases_the_datagram() {
    let only = Probe::new(Judging::Accept);
    only.panic_in_factory();
    let (datagram, datagram_drops) = TestDatagram::new(b"single");
    route(datagram, DatagramFinishPolicy::LastTakes, &[&only]);
    let delivery = only.take_exclusive();

    let unwound = catch_unwind(AssertUnwindSafe(|| delivery.consume()));
    assert!(unwound.is_err());
    assert_eq!(drops(&datagram_drops), 1);
}

/// Panics in `deliver`, as when a deliverer consumes on the spot and fails.
struct PanickingDeliverer;

impl DatagramDeliverer<TestDatagram> for PanickingDeliverer {
    type Handoff = UnclaimedSink;
    type DelivererDatagramState = ();

    fn new_datagram_state(
        &self,
        _datagram: crate::claim::deliverer::DatagramView<'_>,
        _route: &crate::claim::route_match::DatagramRouteMatchInfo,
    ) {
    }

    fn try_claim<'access>(
        &self,
        access: crate::claim::deliverer::DatagramClaimAccess<'access, TestDatagram>,
        _route: &crate::claim::route_match::DatagramRouteMatchInfo,
        state: (),
    ) -> crate::claim::deliverer::DatagramClaimOutcome<'access, TestDatagram, ()> {
        crate::claim::deliverer::DatagramClaimOutcome::Unclaimed { access, state }
    }

    fn deliver(&self, _delivery: DatagramDelivery<TestDatagram, Self>) {
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
    let entries: Vec<(
        Arc<dyn SendDatagramDeliverer<TestDatagram, UnclaimedSink>>,
        _,
    )> = vec![
        (Arc::new(PanickingDeliverer), super::support::route_info()),
        (later.clone(), super::support::route_info()),
    ];
    let prepared = prepare_claim(datagram, sink.policy(), entries);
    let unwound = catch_unwind(AssertUnwindSafe(|| prepared.dispatch()));
    assert!(unwound.is_err());
    assert_eq!(later.delivery_count(), 0);
    assert_eq!(later.factory_calls(), 0);
    // Every participant exited after the set was committed.
    assert_eq!(sink.len(), 1);
    drop(sink.take());
    assert_eq!(drops(&datagram_drops), 1);
}
