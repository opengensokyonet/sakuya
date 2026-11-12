//! The index, registrations, recognition and generation

use std::cell::Cell;
use std::num::NonZeroUsize;
use std::rc::Rc;
use std::sync::Arc;

use super::support::{Local, TestLink, TestLinkId, arrival};
use sakuya_link::{Link as _, ReceivedDatagram};
use sakuya_wire::connection_id::{ConnectionId, StatelessResetToken};
use sakuya_wire::v1::header::LongPacketType;
use sakuya_wire::version::Version;

use super::support::{
    Datagram, Domain, Handoff, Judging, Recorder, cid, dcid_len, lengths, link, local_end, long,
    nonempty, register, short,
};
use crate::claim::candidate::DatagramClaimAttempt;
use crate::claim::deliverer::DatagramDeliverer;
use crate::claim::delivery::DatagramDelivery;
use crate::claim::erased::ErasedDatagramDeliverer;
use crate::claim::finish::ReleaseUnclaimed;
use crate::claim::queue::DatagramDeliveryQueue;
use crate::route::association::{MatchAssociation, PacketForms, RouteMatcher};
use crate::route::index::RouteIndex;
use crate::route::interpretation::FirstPacketInterpretation;
use crate::route::recognizer::{
    ConnectionIdGenerator, ConnectionIdOccupancy, ConnectionIdRecognizer,
    LeastOccupiedConnectionIds,
};
use crate::route::router::DatagramRouter;

#[test]
fn many_zero_and_local_entries_share_one_short_header() {
    let domain = Domain::new(&[8, 0]);
    let end = local_end();
    let recorders: Vec<_> = (0..32)
        .map(|label| Recorder::new(label, Judging::Reject))
        .collect();
    let _registrations: Vec<_> = recorders
        .iter()
        .flat_map(|recorder| {
            [
                register(domain.index(), MatchAssociation::ZeroCid(end), recorder),
                register(
                    domain.index(),
                    MatchAssociation::LocalCid(nonempty(&cid(1))),
                    recorder,
                ),
            ]
        })
        .collect();
    domain.route(short(&cid(1), 30), &link(&end));
    let interpretations: Vec<_> = recorders
        .iter()
        .flat_map(|recorder| recorder.interpretations())
        .collect();
    assert_eq!(interpretations.len(), 64);
    assert_eq!(
        interpretations
            .iter()
            .filter(|interpretation| **interpretation
                == FirstPacketInterpretation::Short {
                    dcid_len: dcid_len(0)
                })
            .count(),
        32
    );
}

#[test]
fn repeated_initial_and_local_keys_are_all_retained() {
    let mut domain = Domain::new(&[8]);
    let end = local_end();
    let recorder = Recorder::new(1, Judging::Reject);
    let _registrations: Vec<_> = (0..20)
        .flat_map(|_| {
            [
                register(
                    domain.index(),
                    MatchAssociation::InitialDcid(nonempty(&cid(2))),
                    &recorder,
                ),
                register(
                    domain.index(),
                    MatchAssociation::LocalCid(nonempty(&cid(2))),
                    &recorder,
                ),
            ]
        })
        .collect();
    for packet_type in [LongPacketType::Initial, LongPacketType::ZeroRtt] {
        domain.route(long(packet_type, &cid(2), &cid(9), 1200), &link(&end));
        assert_eq!(recorder.take().len(), 40);
    }
    drop(domain.next_work());
}

#[test]
fn revoking_removes_only_its_instance_and_keeps_delivered_candidates() {
    let domain = Domain::new(&[8]);
    let end = local_end();
    let old = Recorder::new(1, Judging::Accept);
    let kept = Recorder::new(2, Judging::Reject);
    let first = register(
        domain.index(),
        MatchAssociation::LocalCid(nonempty(&cid(3))),
        &old,
    );
    let _second = register(
        domain.index(),
        MatchAssociation::LocalCid(nonempty(&cid(3))),
        &kept,
    );
    domain.route(
        long(LongPacketType::Handshake, &cid(3), &[], 40),
        &link(&end),
    );
    let delivered = old.take();

    drop(first);
    let successor = Recorder::new(3, Judging::Reject);
    let _successor = register(
        domain.index(),
        MatchAssociation::LocalCid(nonempty(&cid(3))),
        &successor,
    );
    domain.route(
        long(LongPacketType::Handshake, &cid(3), &[], 40),
        &link(&end),
    );
    assert_eq!(
        old.delivery_count(),
        0,
        "a revoked entry is not found again"
    );
    assert_eq!(kept.delivery_count(), 2);
    assert_eq!(successor.delivery_count(), 1);

    // The candidate delivered before the revocation still reaches the old
    // deliverer and can still claim.
    let [DatagramDelivery::Competing(candidate)] = <[_; 1]>::try_from(delivered).ok().unwrap()
    else {
        panic!("two entries compete");
    };
    assert!(matches!(
        super::support::ready(candidate.try_exclusive(|access, _route| old.judge(access))),
        DatagramClaimAttempt::Claimed(..)
    ));
}

#[test]
fn revoking_the_last_entry_removes_the_bucket() {
    let domain = Domain::new(&[8]);
    let end = local_end();
    let recorder = Recorder::new(1, Judging::Reject);
    let local = register(
        domain.index(),
        MatchAssociation::LocalCid(nonempty(&cid(4))),
        &recorder,
    );
    let initial = register(
        domain.index(),
        MatchAssociation::InitialDcid(nonempty(&cid(4))),
        &recorder,
    );
    let zero = register(domain.index(), MatchAssociation::ZeroCid(end), &recorder);
    assert_eq!(domain.index().key_counts(), (1, 1));
    drop(local);
    assert_eq!(domain.index().key_counts(), (1, 1));
    drop(initial);
    drop(zero);
    assert_eq!(domain.index().key_counts(), (0, 0));
}

#[test]
fn revoking_after_the_index_is_gone_does_nothing() {
    let index = RouteIndex::<super::support::Target, Local>::new();
    let recorder = Recorder::new(1, Judging::Reject);
    let registration = register(
        &index,
        MatchAssociation::LocalCid(nonempty(&cid(5))),
        &recorder,
    );
    drop(index);
    drop(registration);
}

#[test]
fn collision_keeps_every_deliverer_even_when_they_share_a_receiver() {
    // Two deliverers feed one receiver queue; they stay separate candidates.
    struct Feeding {
        queue: crate::claim::queue::DatagramDeliveryPoster<(u32, bool)>,
        label: u32,
    }

    impl DatagramDeliverer<Datagram, Local> for Feeding {
        type Handoff = Handoff;

        fn deliver(&self, delivery: DatagramDelivery<Datagram, Local, Handoff>) {
            self.queue.post((
                self.label,
                matches!(delivery, DatagramDelivery::Competing(_)),
            ));
        }
    }

    let domain = Domain::new(&[8]);
    let end = local_end();
    let mut queue = DatagramDeliveryQueue::new(NonZeroUsize::new(4).unwrap()).unwrap();
    let _registrations: Vec<_> = (0..2)
        .map(|label| {
            domain.index().register(
                RouteMatcher::new(
                    MatchAssociation::LocalCid(nonempty(&cid(6))),
                    PacketForms::ALL,
                    Version::V1,
                ),
                Arc::new(Feeding {
                    queue: queue.poster(),
                    label,
                }) as Arc<super::support::Target>,
            )
        })
        .collect();
    domain.route(short(&cid(6), 30), &link(&end));
    assert_eq!(queue.try_recv(), Some((0, true)));
    assert_eq!(queue.try_recv(), Some((1, true)));
    assert_eq!(queue.try_recv(), None);
}

#[test]
#[expect(
    clippy::arc_with_non_send_sync,
    reason = "a routing domain used on one thread is the point"
)]
fn local_routing_domain_does_not_require_send() {
    // A deliverer with a local `Rc` state and a borrowed counter.
    struct Counting<'a> {
        seen: &'a Cell<u32>,
    }

    impl DatagramDeliverer<ReceivedLocal, Local> for Counting<'_> {
        fn deliver(&self, _delivery: DatagramDelivery<ReceivedLocal, Local, ReleaseUnclaimed>) {
            self.seen.set(self.seen.get() + 1);
        }
    }

    // A second deliverer type in the same table.
    struct Other<'a> {
        seen: &'a Cell<u32>,
    }

    impl DatagramDeliverer<ReceivedLocal, Local> for Other<'_> {
        fn deliver(&self, _delivery: DatagramDelivery<ReceivedLocal, Local, ReleaseUnclaimed>) {
            self.seen.set(self.seen.get() + 10);
        }
    }

    type ReceivedLocal = ReceivedDatagram<Rc<[u8]>, TestLink<Rc<TestLinkId>>>;

    let seen = Cell::new(0);
    let index = RouteIndex::<dyn ErasedDatagramDeliverer<ReceivedLocal, Local> + '_, Local>::new();
    let router = DatagramRouter::new(Arc::clone(&index), lengths(&[8]));
    let matcher = || {
        RouteMatcher::new(
            MatchAssociation::LocalCid(nonempty(&cid(7))),
            PacketForms::ALL,
            Version::V1,
        )
    };
    let _local = index.register(matcher(), Arc::new(Counting { seen: &seen }));
    let _other = index.register(matcher(), Arc::new(Other { seen: &seen }));
    let link = link(&local_end()).into_rc();
    router.route(ReceivedDatagram::new(
        Rc::from(short(&cid(7), 30)),
        arrival(&link),
    ));
    assert_eq!(seen.get(), 11);
}

#[test]
fn occupancy_observes_both_kinds_and_generation_prefers_free_values() {
    let domain = Domain::new(&[8]);
    let recorder = Recorder::new(1, Judging::Reject);
    let _initial = register(
        domain.index(),
        MatchAssociation::InitialDcid(nonempty(&cid(1))),
        &recorder,
    );
    let _local = register(
        domain.index(),
        MatchAssociation::LocalCid(nonempty(&cid(2))),
        &recorder,
    );
    let _again = register(
        domain.index(),
        MatchAssociation::LocalCid(nonempty(&cid(1))),
        &recorder,
    );
    assert_eq!(domain.index().occupancy(&nonempty(&cid(1))), 2);
    assert_eq!(domain.index().occupancy(&nonempty(&cid(2))), 1);
    assert_eq!(domain.index().occupancy(&nonempty(&cid(3))), 0);

    // Samples 1, 2, 3 in turn; the free value 3 wins.
    let next = Cell::new(0_u8);
    let mut sampling = LeastOccupiedConnectionIds::new(
        dcid_len(8),
        NonZeroUsize::new(3).unwrap(),
        domain.index().as_ref(),
        |bytes: &mut [u8]| {
            next.set(next.get() + 1);
            bytes.fill(next.get());
        },
    );
    let (generated, token) = sampling.generate();
    assert_eq!(generated.as_bytes(), cid(3));
    // The token is filled after the samples.
    assert_eq!(
        <[u8; StatelessResetToken::LEN]>::from(token),
        [4; StatelessResetToken::LEN]
    );

    // With a single sample, a colliding value is still generated and can be
    // registered.
    let mut single = LeastOccupiedConnectionIds::new(
        dcid_len(8),
        NonZeroUsize::new(1).unwrap(),
        domain.index().as_ref(),
        |bytes: &mut [u8]| bytes.fill(1),
    );
    let (collision, _) = single.generate();
    assert_eq!(collision.as_bytes(), cid(1));
    let _collision = register(
        domain.index(),
        MatchAssociation::LocalCid(collision.try_into().unwrap()),
        &recorder,
    );
    assert_eq!(domain.index().occupancy(&nonempty(&cid(1))), 3);
}

#[test]
fn length_sets_drop_repetitions_and_keep_ambiguity() {
    let lengths = lengths(&[8, 0, 12, 8]);
    let expected = [dcid_len(8), dcid_len(0), dcid_len(12)];
    assert_eq!(lengths.lengths().collect::<Vec<_>>(), expected);
    let link = link(&local_end());
    assert_eq!(
        lengths
            .short_dcid_lengths(&[0x40; 16], link.id())
            .collect::<Vec<_>>(),
        expected
    );
}

#[test]
fn every_generated_length_is_recognized_by_routing() {
    for length in 0..=ConnectionId::MAX_LEN {
        let mut domain = Domain::new(&[length]);
        let end = local_end();
        let mut generator = LeastOccupiedConnectionIds::new(
            dcid_len(length),
            NonZeroUsize::MIN,
            domain.index().as_ref(),
            |bytes: &mut [u8]| bytes.fill(0x5a),
        );
        let (generated, _) = generator.generate();
        assert_eq!(generated.len(), length);
        let association = match generated.try_into() {
            Ok(cid) => MatchAssociation::LocalCid(cid),
            Err(_) => MatchAssociation::ZeroCid(end),
        };
        let recorder = Recorder::new(1, Judging::Reject);
        let _registration = register(domain.index(), association, &recorder);
        domain.route(short(generated.as_bytes(), 20), &link(&end));
        assert_eq!(
            recorder.interpretations(),
            [FirstPacketInterpretation::Short {
                dcid_len: dcid_len(length)
            }]
        );
        assert!(domain.next_work().is_none());
    }
}

#[test]
fn inline_capacity_does_not_limit_buckets_or_candidates() {
    let domain = Domain::new(&[8]);
    let end = local_end();
    let recorder = Recorder::new(1, Judging::Reject);
    let _registrations: Vec<_> = (0..5)
        .map(|_| {
            register(
                domain.index(),
                MatchAssociation::LocalCid(nonempty(&cid(8))),
                &recorder,
            )
        })
        .collect();
    domain.route(short(&cid(8), 30), &link(&end));
    assert_eq!(recorder.delivery_count(), 5);
}

#[test]
fn least_occupied_generators_come_from_their_config_and_recompute_no_token() {
    let index = RouteIndex::<super::support::Target, Local>::new();
    let config = LeastOccupiedConnectionIds::new(
        dcid_len(8),
        NonZeroUsize::MIN,
        Arc::clone(&index),
        |bytes: &mut [u8]| bytes.fill(9),
    );
    let mut generator = <LeastOccupiedConnectionIds<_, _> as ConnectionIdGenerator>::new(&config);
    let (generated, _) = generator.generate();
    assert_eq!(generated.as_bytes(), [9; 8]);
    assert!(
        <LeastOccupiedConnectionIds<_, _> as ConnectionIdGenerator>::stateless_reset_token(
            &config, &generated
        )
        .is_none()
    );
}

/// Counts how often it was woken.
#[derive(Default)]
struct WakeCount(std::sync::atomic::AtomicUsize);

impl std::task::Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl WakeCount {
    fn count(&self) -> usize {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[test]
fn the_last_revoked_registration_wakes_who_waits_for_an_empty_index() {
    use std::task::{Context, Poll, Waker};

    let domain = Domain::new(&[8]);
    let recorder = Recorder::new(1, Judging::Reject);
    let wakes = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&wakes));
    let mut cx = Context::from_waker(&waker);
    assert_eq!(domain.index().poll_empty(&mut cx), Poll::Ready(()));

    let first = register(
        domain.index(),
        MatchAssociation::LocalCid(nonempty(&cid(1))),
        &recorder,
    );
    let second = register(
        domain.index(),
        MatchAssociation::ZeroCid(local_end()),
        &recorder,
    );
    assert_eq!(domain.index().registration_count(), 2);
    assert_eq!(domain.index().poll_empty(&mut cx), Poll::Pending);
    // Polling again with the same waker keeps one waiter.
    assert_eq!(domain.index().poll_empty(&mut cx), Poll::Pending);

    drop(first);
    assert_eq!(domain.index().registration_count(), 1);
    assert_eq!(wakes.count(), 0);
    drop(second);
    assert_eq!(domain.index().registration_count(), 0);
    assert_eq!(wakes.count(), 1);
    assert_eq!(domain.index().poll_empty(&mut cx), Poll::Ready(()));
}

#[test]
fn a_receiver_published_by_reflow_is_counted_until_revoked() {
    let mut domain = Domain::new(&[8]);
    let end = local_end();
    domain.route(super::support::initial(&cid(1), &cid(9)), &link(&end));
    assert_eq!(domain.index().registration_count(), 0);
    assert_eq!(domain.drain(), 1);
    let accepted = domain.factory.take_accepted();
    assert_eq!(accepted.len(), 1);
    assert_eq!(domain.index().registration_count(), 1);
    drop(accepted);
    assert_eq!(domain.index().registration_count(), 0);
}
