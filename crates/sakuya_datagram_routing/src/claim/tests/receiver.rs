//! A queue-style deliverer and a receiver that closes

use std::num::NonZeroUsize;
use std::sync::Arc;

use super::support::{TestDatagram, drops, ready};
use crate::claim::candidate::DatagramClaimAttempt;
use crate::claim::deliverer::{
    DatagramClaimAccess, DatagramClaimOutcome, DatagramDeliverer, DatagramView,
};
use crate::claim::delivery::DatagramDelivery;
use crate::claim::erased::SendDatagramDeliverer;
use crate::claim::finish::ReleaseUnclaimed;
use crate::claim::group::prepare_claim;
use crate::claim::queue::{DatagramDeliveryPoster, DatagramDeliveryQueue};
use crate::claim::route_match::DatagramRouteMatchInfo;
use crate::claim::shared::DatagramFinishPolicy;

type Delivery = DatagramDelivery<TestDatagram, Queued>;

/// Claims every datagram while its receiver is open.
struct Queued {
    poster: DatagramDeliveryPoster<Delivery>,
}

impl DatagramDeliverer<TestDatagram> for Queued {
    type DelivererDatagramState = ();

    fn new_datagram_state(&self, _datagram: DatagramView<'_>, _route: &DatagramRouteMatchInfo) {}

    fn try_claim<'access>(
        &self,
        access: DatagramClaimAccess<'access, TestDatagram>,
        _route: &DatagramRouteMatchInfo,
        state: (),
    ) -> DatagramClaimOutcome<'access, TestDatagram, ()> {
        if self.poster.is_closed() {
            return DatagramClaimOutcome::Unclaimed { access, state };
        }
        DatagramClaimOutcome::Claimed {
            datagram: access.into_exclusive(),
            state,
        }
    }

    fn deliver(&self, delivery: Delivery) {
        self.poster.post(delivery);
    }
}

fn receiver() -> (DatagramDeliveryQueue<Delivery>, Arc<Queued>) {
    let queue = DatagramDeliveryQueue::new(NonZeroUsize::new(4).unwrap()).unwrap();
    let deliverer = Arc::new(Queued {
        poster: queue.poster(),
    });
    (queue, deliverer)
}

fn route_to(
    datagram: TestDatagram,
    finish: DatagramFinishPolicy<ReleaseUnclaimed>,
    deliverers: &[&Arc<Queued>],
) {
    let entries = deliverers
        .iter()
        .map(|deliverer| {
            let erased: Arc<dyn SendDatagramDeliverer<TestDatagram>> = Arc::clone(deliverer) as _;
            (erased, super::support::route_info())
        })
        .collect::<Vec<_>>();
    prepare_claim(datagram, finish, entries).dispatch();
}

#[test]
fn queued_competing_delivery_is_claimed_and_consumed_by_the_receiver() {
    let (mut queue, first) = receiver();
    let (_other_queue, second) = receiver();
    let (datagram, datagram_drops) = TestDatagram::new(b"queued");
    route_to(
        datagram,
        DatagramFinishPolicy::LastTakes,
        &[&first, &second],
    );

    let Some(DatagramDelivery::Competing(candidate)) = queue.try_recv() else {
        panic!("the delivery waits in the queue");
    };
    let DatagramClaimAttempt::Claimed(delivery) = ready(candidate.try_exclusive()) else {
        panic!("an open receiver claims");
    };
    let (datagram, _) = delivery.consume();
    assert_eq!(datagram.bytes(), b"queued");
    drop(datagram);
    assert_eq!(drops(&datagram_drops), 1);
}

#[test]
fn closed_receiver_drops_deliveries_and_stops_claiming() {
    let (queue, deliverer) = receiver();
    let (mut other_queue, other) = receiver();
    drop(queue);

    // A delivery after the close is taken over and dropped.
    let (datagram, single_drops) = TestDatagram::new(b"late");
    route_to(datagram, DatagramFinishPolicy::LastTakes, &[&deliverer]);
    assert_eq!(drops(&single_drops), 1);

    // A candidate the closed receiver still holds no longer claims.
    let (mut queue, deliverer) = receiver();
    let (datagram, datagram_drops) = TestDatagram::new(b"held");
    route_to(
        datagram,
        DatagramFinishPolicy::LastTakes,
        &[&deliverer, &other],
    );
    let Some(DatagramDelivery::Competing(held)) = queue.try_recv() else {
        panic!("the delivery waits in the queue");
    };
    drop(queue);
    let DatagramClaimAttempt::Unclaimed(held) = ready(held.try_exclusive()) else {
        panic!("a failed deliverer leaves the datagram");
    };
    drop(held);
    let Some(DatagramDelivery::Competing(candidate)) = other_queue.try_recv() else {
        panic!("the other receiver got its delivery");
    };
    assert!(matches!(
        ready(candidate.try_exclusive()),
        DatagramClaimAttempt::Claimed(_)
    ));
    assert_eq!(drops(&datagram_drops), 1);
}

#[test]
fn queued_deliveries_keep_neither_the_receiver_nor_the_deliverer_alive() {
    let (queue, deliverer) = receiver();
    let (_other_queue, other) = receiver();
    let (datagram, datagram_drops) = TestDatagram::new(b"cycle");
    route_to(
        datagram,
        DatagramFinishPolicy::LastTakes,
        &[&deliverer, &other],
    );
    let weak = Arc::downgrade(&deliverer);
    drop(deliverer);
    // The queued candidate holds the deliverer, but not the queue.
    assert!(weak.upgrade().is_some());

    drop(queue);
    assert!(weak.upgrade().is_none());
    assert_eq!(
        drops(&datagram_drops),
        0,
        "the other candidate still holds it"
    );
}
