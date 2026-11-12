//! Reflow, the Initial recheck and the publication of new receivers

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex, Weak, mpsc};
use std::time::Duration;

use super::support::{Local, TestLink};
use sakuya_wire::v1::header::LongPacketType;

use super::support::{
    Datagram, Domain, Handoff, Index, Judging, Recorder, Target, cid, datagram, initial, lengths,
    link, local_end, long, nonempty, register,
};
use crate::claim::candidate::DatagramClaimOutcome;
use crate::claim::deliverer::DatagramDeliverer;
use crate::claim::delivery::DatagramDelivery;
use crate::claim::delivery::ExclusiveDatagram;
use crate::claim::queue::DatagramDeliveryQueue;
use crate::route::acceptance::{
    InitialAcceptance, InitialDatagramReceiver, InitialReceiverFactory, PreparedReceiver,
};
use crate::route::association::{MatchAssociation, PacketForms};
use crate::route::index::{RouteEntryRegistration, RouteIndex};
use crate::route::interpretation::RecognizedInitial;
use crate::route::recognizer::ConnectionIdOccupancy;
use crate::route::router::DatagramRouter;

#[test]
fn unclaimed_initial_is_published_only_after_a_separate_resume() {
    let mut domain = Domain::new(&[8]);
    let end = local_end();
    domain.route(initial(&cid(1), &cid(9)), &link(&end));
    // Nothing ran inline: the work waits in the outer queue.
    assert_eq!(domain.factory.shared().prepared.load(Ordering::SeqCst), 0);
    assert_eq!(domain.factory.accepted_count(), 0);
    assert_eq!(domain.drain(), 1);

    let [accepted] = <[_; 1]>::try_from(domain.factory.take_accepted())
        .ok()
        .unwrap();
    let matcher = accepted.registration.entry().matcher();
    assert_eq!(
        matcher.association(),
        &MatchAssociation::InitialDcid(nonempty(&cid(1)))
    );
    assert_eq!(
        matcher.forms(),
        PacketForms::INITIAL | PacketForms::ZERO_RTT
    );
    assert_eq!(
        accepted.datagram.get().payload(),
        &initial(&cid(1), &cid(9))
    );
    assert_eq!(accepted.initial.scid().as_bytes(), cid(9));
    assert_eq!(
        accepted.deliverer.label, 1000,
        "the first prepared receiver"
    );
    assert_eq!(domain.index().key_counts(), (1, 0));
    drop(accepted);
    assert_eq!(domain.index().key_counts(), (0, 0));
}

#[test]
fn zero_length_initial_is_published_under_its_local_end() {
    let mut domain = Domain::new(&[0]);
    let end = local_end();
    domain.route(initial(&[], &cid(9)), &link(&end));
    assert_eq!(domain.drain(), 1);
    let [accepted] = <[_; 1]>::try_from(domain.factory.take_accepted())
        .ok()
        .unwrap();
    assert_eq!(
        accepted.registration.entry().matcher().association(),
        &MatchAssociation::ZeroCid(end)
    );
    assert_eq!(domain.index().key_counts(), (0, 1));
}

/// Inputs A and B both find nothing in their first round. A's recheck
/// publishes a receiver; B's recheck then offers B to it first.
fn two_empty_snapshots(judging: Judging) -> (Domain, Arc<Recorder>) {
    let mut domain = Domain::new(&[8]);
    *domain.factory.shared().judging.lock().unwrap() = judging;
    let end = local_end();
    domain.route(initial(&cid(1), &cid(10)), &link(&end));
    domain.route(initial(&cid(1), &cid(11)), &link(&end));
    let first = domain.next_work().unwrap();
    let second = domain.next_work().unwrap();
    domain.router.resume(first);
    assert_eq!(domain.factory.accepted_count(), 1);
    let published = Arc::clone(&domain.factory.shared().accepted.lock().unwrap()[0].deliverer);
    domain.router.resume(second);
    assert_eq!(
        domain.factory.accepted_count(),
        1,
        "B did not create blindly"
    );
    assert_eq!(published.delivery_count(), 1);
    (domain, published)
}

#[test]
fn second_empty_snapshot_is_claimed_by_the_first_receiver() {
    let (mut domain, published) = two_empty_snapshots(Judging::Accept);
    let owned = published.settle();
    assert_eq!(owned.len(), 1);
    assert_eq!(&owned[0].payload()[..], &initial(&cid(1), &cid(11))[..]);
    assert_eq!(domain.drain(), 0);
    assert_eq!(domain.factory.accepted_count(), 1);
}

#[test]
fn second_empty_snapshot_creates_after_the_first_receiver_exits() {
    let (mut domain, published) = two_empty_snapshots(Judging::Reject);
    assert!(published.settle().is_empty());
    let work = domain.next_work().expect("B reflows again");
    assert_eq!(work.offered_len(), 1);
    domain.router.resume(work);
    assert_eq!(domain.factory.accepted_count(), 2);
    assert_eq!(
        published.delivery_count(),
        0,
        "the exited receiver is not offered B again"
    );
    // A new datagram is offered to both receivers again.
    domain.route(initial(&cid(1), &cid(12)), &link(&local_end()));
    assert_eq!(published.delivery_count(), 1);
}

#[test]
fn concurrent_rechecks_publish_once_and_offer_to_the_other() {
    let mut domain = Domain::new(&[8]);
    let end = local_end();
    domain.route(initial(&cid(3), &cid(10)), &link(&end));
    domain.route(initial(&cid(3), &cid(11)), &link(&end));
    let works = [domain.next_work().unwrap(), domain.next_work().unwrap()];
    // Both prepare before either rechecks.
    *domain.factory.shared().barrier.lock().unwrap() = Some(Arc::new(Barrier::new(2)));
    std::thread::scope(|scope| {
        for work in works {
            let router = &domain.router;
            scope.spawn(move || router.resume(work));
        }
    });
    assert_eq!(domain.factory.shared().prepared.load(Ordering::SeqCst), 2);
    let accepted = domain.factory.take_accepted();
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted[0].deliverer.delivery_count(), 1);
    assert_eq!(domain.index().occupancy(&nonempty(&cid(3))), 1);
}

#[test]
fn local_entry_registered_while_preparing_becomes_a_candidate() {
    let mut domain = Domain::new(&[8]);
    let end = local_end();
    domain.route(initial(&cid(4), &cid(10)), &link(&end));
    let local = Recorder::new(7, Judging::Accept);
    let registrations = Arc::new(Mutex::new(Vec::new()));
    {
        let index = Arc::clone(domain.index());
        let local = Arc::clone(&local);
        let registrations = Arc::clone(&registrations);
        *domain.factory.shared().during_prepare.lock().unwrap() = Some(Box::new(move || {
            registrations.lock().unwrap().push(register(
                &index,
                MatchAssociation::LocalCid(nonempty(&cid(4))),
                &local,
            ));
        }));
    }
    assert_eq!(domain.drain(), 1);
    assert_eq!(
        domain.factory.accepted_count(),
        0,
        "the prepared receiver was not used"
    );
    assert_eq!(local.settle().len(), 1);
    drop(registrations);
}

#[test]
fn nothing_prepared_releases_without_leaving_a_bucket() {
    let mut domain = Domain::new(&[8]);
    *domain.factory.shared().can_prepare.lock().unwrap() = false;
    domain.route(initial(&cid(5), &cid(10)), &link(&local_end()));
    assert_eq!(domain.drain(), 1);
    assert_eq!(domain.factory.accepted_count(), 0);
    assert_eq!(domain.index().key_counts(), (0, 0));
}

#[test]
fn rejected_entry_is_not_offered_again_and_history_keeps_it_unalive() {
    let mut domain = Domain::new(&[8]);
    let end = local_end();
    let rejecting = Recorder::new(1, Judging::Reject);
    let registration = register(
        domain.index(),
        MatchAssociation::InitialDcid(nonempty(&cid(6))),
        &rejecting,
    );
    domain.route(initial(&cid(6), &cid(10)), &link(&end));
    assert!(rejecting.settle().is_empty());
    let work = domain.next_work().unwrap();
    assert_eq!(work.offered_len(), 1);

    // The entry is still registered: the recheck skips it and publishes.
    domain.router.resume(work);
    assert_eq!(rejecting.delivery_count(), 0);
    assert_eq!(domain.factory.accepted_count(), 1);

    // A new datagram is offered to the old entry again.
    domain.route(initial(&cid(6), &cid(11)), &link(&end));
    assert_eq!(rejecting.delivery_count(), 1);
    drop(rejecting.take());

    // The history holds the entry weakly.
    domain.factory.take_accepted();
    let weak = Arc::downgrade(&rejecting);
    domain.route(initial(&cid(6), &cid(12)), &link(&end));
    rejecting.settle();
    let work = domain.next_work().unwrap();
    drop(registration);
    drop(rejecting);
    assert!(weak.upgrade().is_none());
    drop(work);
}

#[test]
fn published_receiver_can_receive_before_it_handles_the_first_datagram() {
    let mut domain = Domain::new(&[8]);
    let end = local_end();
    let later = link(&end);
    {
        let router = Arc::clone(&domain.router);
        *domain.factory.shared().before_receive.lock().unwrap() =
            Some(Box::new(move |deliverer| {
                // Another datagram reaches the new entry first.
                router.route(datagram(
                    long(LongPacketType::ZeroRtt, &cid(7), &cid(9), 40),
                    &later,
                ));
                assert_eq!(deliverer.delivery_count(), 1);
            }));
    }
    domain.route(initial(&cid(7), &cid(9)), &link(&end));
    assert_eq!(domain.drain(), 1);
    let [accepted] = <[_; 1]>::try_from(domain.factory.take_accepted())
        .ok()
        .unwrap();
    assert_eq!(accepted.deliverer.settle().len(), 1);
}

#[test]
fn closing_receiver_revokes_and_a_later_initial_creates_again() {
    let mut domain = Domain::new(&[8]);
    let end = local_end();
    domain.route(initial(&cid(8), &cid(9)), &link(&end));
    domain.drain();
    let [accepted] = <[_; 1]>::try_from(domain.factory.take_accepted())
        .ok()
        .unwrap();
    // A delivery taken before the close keeps its deliverer.
    domain.route(initial(&cid(8), &cid(9)), &link(&end));
    let held = accepted.deliverer.take();
    assert_eq!(held.len(), 1);

    let old = Arc::clone(&accepted.deliverer);
    drop(accepted);
    assert_eq!(domain.index().key_counts(), (0, 0));
    old.judge_with(Judging::Accept);
    for delivery in held {
        old.deliver(delivery);
    }
    assert_eq!(old.settle().len(), 1);

    domain.route(initial(&cid(8), &cid(9)), &link(&end));
    assert_eq!(domain.drain(), 1);
    assert_eq!(domain.factory.accepted_count(), 1);
}

#[test]
fn closed_or_full_reflow_queue_releases_the_work() {
    let mut domain = Domain::new(&[8]);
    let end = local_end();
    drop(std::mem::replace(
        &mut domain.reflow,
        DatagramDeliveryQueue::new(NonZeroUsize::MIN).unwrap(),
    ));
    domain.route(initial(&cid(9), &cid(9)), &link(&end));
    assert_eq!(domain.drain(), 0);
    assert_eq!(domain.factory.accepted_count(), 0);
}

#[test]
fn next_round_hands_off_again_instead_of_nesting() {
    let mut domain = Domain::new(&[8]);
    let end = local_end();
    domain.route(initial(&cid(10), &cid(9)), &link(&end));
    let work = domain.next_work().unwrap();
    // An entry appears before the recheck; it will exit.
    let late = Recorder::new(1, Judging::Reject);
    let _late = register(
        domain.index(),
        MatchAssociation::InitialDcid(nonempty(&cid(10))),
        &late,
    );
    domain.router.resume(work);
    assert_eq!(late.delivery_count(), 1);
    // Exiting from here, inside no resume, hands the work off once more.
    assert!(late.settle().is_empty());
    assert_eq!(domain.factory.accepted_count(), 0);
    assert_eq!(domain.drain(), 1);
    assert_eq!(domain.factory.accepted_count(), 1);
}

#[test]
fn prepared_material_is_dropped_outside_the_index() {
    /// A deliverer whose drop reads the index; inside an index guard this
    /// would deadlock.
    struct ReadsOnDrop {
        index: Weak<Index>,
        dropped: Arc<AtomicUsize>,
    }

    impl Drop for ReadsOnDrop {
        fn drop(&mut self) {
            if let Some(index) = self.index.upgrade() {
                self.dropped
                    .fetch_add(1 + index.occupancy(&nonempty(&cid(11))), Ordering::SeqCst);
            }
        }
    }

    impl DatagramDeliverer<Datagram, Local> for ReadsOnDrop {
        type Handoff = Handoff;

        fn deliver(&self, _delivery: DatagramDelivery<Datagram, Local, Handoff>) {}
    }

    struct Ignored;

    impl InitialDatagramReceiver<Vec<u8>, TestLink, Target> for Ignored {
        fn receive_first(
            self,
            _: RouteEntryRegistration<Target, Local>,
            _: ExclusiveDatagram<Datagram>,
            _: RecognizedInitial<Local>,
        ) {
        }
    }

    struct Preparing {
        index: Weak<Index>,
        dropped: Arc<AtomicUsize>,
    }

    impl InitialReceiverFactory<Vec<u8>, TestLink, Target> for Preparing {
        type Receiver = Ignored;

        fn admits(&self, _: &RecognizedInitial<Local>, _: &Datagram) -> bool {
            true
        }

        fn prepare(
            &self,
            _: &RecognizedInitial<Local>,
        ) -> Option<PreparedReceiver<Target, Ignored>> {
            let deliverer = Arc::new(ReadsOnDrop {
                index: Weak::clone(&self.index),
                dropped: Arc::clone(&self.dropped),
            });
            Some(PreparedReceiver::new(deliverer as Arc<Target>, Ignored))
        }
    }

    let (done, finished) = mpsc::channel();
    let dropped = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&dropped);
    std::thread::spawn(move || {
        let index = RouteIndex::<Target, Local>::new();
        let mut reflow = DatagramDeliveryQueue::new(NonZeroUsize::new(4).unwrap()).unwrap();
        let router = DatagramRouter::new(Arc::clone(&index), lengths(&[8]))
            .with_initial_acceptance(InitialAcceptance::new(
                Preparing {
                    index: Arc::downgrade(&index),
                    dropped,
                },
                Arc::new(reflow.poster()),
            ));
        let existing = Recorder::new(1, Judging::Reject);
        let end = local_end();
        router.route(datagram(initial(&cid(11), &cid(9)), &link(&end)));
        let work = reflow.try_recv().unwrap();
        let _existing = register(
            &index,
            MatchAssociation::InitialDcid(nonempty(&cid(11))),
            &existing,
        );
        // The recheck offers the new entry; the prepared deliverer goes unused.
        router.resume(work);
        assert_eq!(existing.delivery_count(), 1);
        done.send(()).unwrap();
    });
    finished
        .recv_timeout(Duration::from_secs(10))
        .expect("an unused prepared deliverer was dropped inside the index");
    assert_eq!(observed.load(Ordering::SeqCst), 2);
}

#[test]
fn cancelled_attempts_reflow_and_a_winner_that_drops_its_datagram_does_not() {
    let mut domain = Domain::new(&[8]);
    let end = local_end();
    let first = Recorder::new(1, Judging::Reject);
    let second = Recorder::new(2, Judging::Accept);
    let _first = register(
        domain.index(),
        MatchAssociation::InitialDcid(nonempty(&cid(12))),
        &first,
    );
    let _second = register(
        domain.index(),
        MatchAssociation::LocalCid(nonempty(&cid(12))),
        &second,
    );

    // Every attempt is cancelled before it runs: the last exit hands off.
    domain.route(initial(&cid(12), &cid(9)), &link(&end));
    for delivery in first.take().into_iter().chain(second.take()) {
        let DatagramDelivery::Competing(candidate) = delivery else {
            panic!("two entries compete");
        };
        drop(
            candidate.try_exclusive(|access, _route| {
                DatagramClaimOutcome::<(), (), _>::Unclaimed(access)
            }),
        );
    }
    assert!(domain.next_work().is_some());

    // The winner takes the datagram and then drops it: no handoff, no refill.
    domain.route(initial(&cid(12), &cid(9)), &link(&end));
    let owned = second.settle();
    assert_eq!(owned.len(), 1);
    drop(owned);
    assert!(first.settle().is_empty());
    assert!(domain.next_work().is_none());
}
