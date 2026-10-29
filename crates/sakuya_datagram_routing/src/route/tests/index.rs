//! The index, registrations, recognition and generation

use std::cell::Cell;
use std::num::NonZeroUsize;
use std::rc::Rc;
use std::sync::Arc;

use sakuya_link::LinkId;
use sakuya_wire::connection_id::{ConnectionId, ConnectionIdLengthError};
use sakuya_wire::header::v1::LongPacketType;

use super::support::{
    Datagram, Domain, Handoff, Judging, Recorder, binding, cid, dcid_len, lengths, link, long,
    nonempty, register, short,
};
use crate::claim::candidate::DatagramClaimAttempt;
use crate::claim::deliverer::{
    DatagramClaimAccess, DatagramClaimOutcome, DatagramDeliverer, DatagramView,
};
use crate::claim::delivery::DatagramDelivery;
use crate::claim::erased::ErasedDatagramDeliverer;
use crate::claim::queue::DatagramDeliveryQueue;
use crate::claim::route_match::DatagramRouteMatchInfo;
use crate::route::association::{MatchAssociation, PacketForms, RouteMatcher};
use crate::route::index::RouteIndex;
use crate::route::interpretation::FirstPacketInterpretation;
use crate::route::recognizer::{
    ConnectionIdGenerator, ConnectionIdLength, ConnectionIdOccupancy, ConnectionIdRecognizer,
    LeastOccupiedConnectionIds,
};
use crate::route::router::DatagramRouter;
use crate::version::Version;

#[test]
fn many_zero_and_local_entries_share_one_short_header() {
    let domain = Domain::new(&[8, 0]);
    let binding = binding();
    let recorders: Vec<_> = (0..32)
        .map(|label| Recorder::new(label, Judging::Reject))
        .collect();
    let _registrations: Vec<_> = recorders
        .iter()
        .flat_map(|recorder| {
            [
                register(
                    domain.index(),
                    MatchAssociation::ZeroCid(binding.clone()),
                    recorder,
                ),
                register(
                    domain.index(),
                    MatchAssociation::LocalCid(nonempty(&cid(1))),
                    recorder,
                ),
            ]
        })
        .collect();
    domain.route(short(&cid(1), 30), &link(&binding));
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
    let binding = binding();
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
        domain.route(long(packet_type, &cid(2), &cid(9), 1200), &link(&binding));
        assert_eq!(recorder.take().len(), 40);
    }
    drop(domain.next_work());
}

#[test]
fn revoking_removes_only_its_instance_and_keeps_delivered_candidates() {
    let domain = Domain::new(&[8]);
    let binding = binding();
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
        &link(&binding),
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
        &link(&binding),
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
        super::support::ready(candidate.try_exclusive()),
        DatagramClaimAttempt::Claimed(_)
    ));
}

#[test]
fn revoking_the_last_entry_removes_the_bucket() {
    let domain = Domain::new(&[8]);
    let binding = binding();
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
    let zero = register(
        domain.index(),
        MatchAssociation::ZeroCid(binding.clone()),
        &recorder,
    );
    assert_eq!(domain.index().key_counts(), (1, 1));
    drop(local);
    assert_eq!(domain.index().key_counts(), (1, 1));
    drop(initial);
    drop(zero);
    assert_eq!(domain.index().key_counts(), (0, 0));
}

#[test]
fn revoking_after_the_index_is_gone_does_nothing() {
    let index = RouteIndex::<super::support::Target>::new();
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

    impl DatagramDeliverer<Datagram> for Feeding {
        type Handoff = Handoff;
        type DelivererDatagramState = ();

        fn new_datagram_state(&self, _: DatagramView<'_>, _: &DatagramRouteMatchInfo) {}

        fn try_claim<'access>(
            &self,
            access: DatagramClaimAccess<'access, Datagram>,
            _: &DatagramRouteMatchInfo,
            state: (),
        ) -> DatagramClaimOutcome<'access, Datagram, ()> {
            DatagramClaimOutcome::Unclaimed { access, state }
        }

        fn deliver(&self, delivery: DatagramDelivery<Datagram, Self>) {
            self.queue.post((
                self.label,
                matches!(delivery, DatagramDelivery::Competing(_)),
            ));
        }
    }

    let domain = Domain::new(&[8]);
    let binding = binding();
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
    domain.route(short(&cid(6), 30), &link(&binding));
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
    struct Local<'a> {
        seen: &'a Cell<u32>,
    }

    impl DatagramDeliverer<ReceivedLocal> for Local<'_> {
        type DelivererDatagramState = Rc<Vec<u8>>;

        fn new_datagram_state(
            &self,
            datagram: DatagramView<'_>,
            _: &DatagramRouteMatchInfo,
        ) -> Rc<Vec<u8>> {
            Rc::new(datagram.bytes().to_vec())
        }

        fn try_claim<'access>(
            &self,
            access: DatagramClaimAccess<'access, ReceivedLocal>,
            _: &DatagramRouteMatchInfo,
            state: Rc<Vec<u8>>,
        ) -> DatagramClaimOutcome<'access, ReceivedLocal, Rc<Vec<u8>>> {
            DatagramClaimOutcome::Unclaimed { access, state }
        }

        fn deliver(&self, _delivery: DatagramDelivery<ReceivedLocal, Self>) {
            self.seen.set(self.seen.get() + 1);
        }
    }

    // A second deliverer type in the same table.
    struct Other<'a> {
        seen: &'a Cell<u32>,
    }

    impl DatagramDeliverer<ReceivedLocal> for Other<'_> {
        type DelivererDatagramState = ();

        fn new_datagram_state(&self, _: DatagramView<'_>, _: &DatagramRouteMatchInfo) {}

        fn try_claim<'access>(
            &self,
            access: DatagramClaimAccess<'access, ReceivedLocal>,
            _: &DatagramRouteMatchInfo,
            state: (),
        ) -> DatagramClaimOutcome<'access, ReceivedLocal, ()> {
            DatagramClaimOutcome::Unclaimed { access, state }
        }

        fn deliver(&self, _delivery: DatagramDelivery<ReceivedLocal, Self>) {
            self.seen.set(self.seen.get() + 10);
        }
    }

    type ReceivedLocal = crate::route::datagram::ReceivedDatagram<Rc<[u8]>, Rc<LinkId>>;

    let seen = Cell::new(0);
    let index = RouteIndex::<dyn ErasedDatagramDeliverer<ReceivedLocal> + '_>::new();
    let router = DatagramRouter::new(Arc::clone(&index), lengths(&[8]));
    let matcher = || {
        RouteMatcher::new(
            MatchAssociation::LocalCid(nonempty(&cid(7))),
            PacketForms::ALL,
            Version::V1,
        )
    };
    let _local = index.register(matcher(), Arc::new(Local { seen: &seen }));
    let _other = index.register(matcher(), Arc::new(Other { seen: &seen }));
    let link = Rc::new(link(&binding()));
    router.route(crate::route::datagram::ReceivedDatagram::new(
        Rc::from(short(&cid(7), 30)),
        link,
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
    let sampling = LeastOccupiedConnectionIds::new(
        dcid_len(8),
        NonZeroUsize::new(3).unwrap(),
        |bytes: &mut [u8]| {
            next.set(next.get() + 1);
            bytes.fill(next.get());
        },
    );
    assert_eq!(
        sampling.generate(domain.index().as_ref()).as_bytes(),
        cid(3)
    );

    // With a single sample, a colliding value is still generated and can be
    // registered.
    let single = LeastOccupiedConnectionIds::new(
        dcid_len(8),
        NonZeroUsize::new(1).unwrap(),
        |bytes: &mut [u8]| bytes.fill(1),
    );
    let collision = single.generate(domain.index().as_ref());
    assert_eq!(collision.as_bytes(), cid(1));
    let _collision = register(
        domain.index(),
        MatchAssociation::LocalCid(collision.try_into().unwrap()),
        &recorder,
    );
    assert_eq!(domain.index().occupancy(&nonempty(&cid(1))), 3);
}

#[test]
fn length_sets_validate_and_keep_ambiguity() {
    let lengths = lengths(&[8, 0, 12, 8]);
    let expected = [dcid_len(8), dcid_len(0), dcid_len(12)];
    assert_eq!(lengths.lengths().collect::<Vec<_>>(), expected);
    let link = link(&binding());
    assert_eq!(
        lengths
            .short_dcid_lengths(&[0x40; 16], &link)
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(
        ConnectionIdLength::new(21),
        Err(ConnectionIdLengthError { length: 21 })
    );
    assert_eq!(
        ConnectionIdLength::new(usize::from(u8::MAX) + 1),
        Err(ConnectionIdLengthError { length: 256 })
    );
    assert_eq!(dcid_len(20).get(), 20);
    assert!(ConnectionIdLength::ZERO.is_zero());
}

#[test]
fn every_generated_length_is_recognized_by_routing() {
    for length in 0..=ConnectionId::MAX_LEN {
        let mut domain = Domain::new(&[length]);
        let binding = binding();
        let generator = LeastOccupiedConnectionIds::new(
            dcid_len(length),
            NonZeroUsize::MIN,
            |bytes: &mut [u8]| bytes.fill(0x5a),
        );
        let generated = generator.generate(domain.index().as_ref());
        assert_eq!(generated.len(), length);
        let association = match generated.try_into() {
            Ok(cid) => MatchAssociation::LocalCid(cid),
            Err(_) => MatchAssociation::ZeroCid(binding.clone()),
        };
        let recorder = Recorder::new(1, Judging::Reject);
        let _registration = register(domain.index(), association, &recorder);
        domain.route(short(generated.as_bytes(), 20), &link(&binding));
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
    let binding = binding();
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
    domain.route(short(&cid(8), 30), &link(&binding));
    assert_eq!(recorder.delivery_count(), 5);
}
