//! Multi-thread stress of the shared bucket and of registration revocation.
//!
//! These tests run on real threads and real `DashMap` shards. They can show
//! that a bad interleaving exists; they cannot show that none does.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sakuya_wire::connection_id::StatelessResetToken;
use sakuya_wire::v1::header::LongPacketType;
use sakuya_wire::version::Version;

use super::support::*;
use crate::claim::deliverer::DatagramDeliverer;
use crate::claim::delivery::DatagramDelivery;
use crate::route::association::{MatchAssociation, PacketForms, RouteMatcher};
use crate::route::datagram::ReceivedDatagram;
use crate::route::index::RouteEntryRegistration;
use crate::route::recognizer::ConnectionIdOccupancy;

/// A deliverer that only counts its deliveries.
struct Counter(Arc<AtomicUsize>);

impl DatagramDeliverer<Datagram, Local> for Counter {
    type Handoff = Handoff;

    fn deliver(&self, _delivery: DatagramDelivery<Datagram, Local, Handoff>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// While a 0-RTT datagram's key is handed from its Initial association to its
/// local association and back, at least one entry applies at every instant.
/// Both associations share one bucket so that a reader cannot miss both: the
/// lookup must see one state of the bucket, not two.
#[test]
fn a_lookup_does_not_combine_two_states_of_a_bucket() {
    const DEADLINE: Duration = Duration::from_secs(5);
    let end = local_end();
    let domain = Domain::new(&[8]);
    let router = Arc::clone(&domain.router);
    let key = nonempty(&cid(0x77));
    let delivered = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let counter = || Arc::new(Counter(Arc::clone(&delivered))) as Arc<Target>;
    let matcher = |association| RouteMatcher::new(association, PacketForms::ALL, Version::V1);
    let local = MatchAssociation::LocalCid(key);
    let initial = MatchAssociation::InitialDcid(key);
    let mut held = router.index().register(matcher(initial.clone()), counter());
    let writer = {
        let router = Arc::clone(&router);
        let done = Arc::clone(&done);
        let (local, initial) = (local.clone(), initial.clone());
        let delivered = Arc::clone(&delivered);
        std::thread::spawn(move || {
            let counter = || Arc::new(Counter(Arc::clone(&delivered))) as Arc<Target>;
            while !done.load(Ordering::Relaxed) {
                let next = router.index().register(matcher(local.clone()), counter());
                drop(std::mem::replace(&mut held, next));
                let next = router.index().register(matcher(initial.clone()), counter());
                drop(std::mem::replace(&mut held, next));
            }
            assert!(router.index().occupancy(&key) >= 1);
        })
    };
    let bytes = long(LongPacketType::ZeroRtt, &cid(0x77), &cid(0x10), 20);
    let arrival = link(&end);
    let started = Instant::now();
    let mut routed = 0_u64;
    let mut missed = 0_u64;
    while started.elapsed() < DEADLINE && missed == 0 {
        for _ in 0..4096 {
            let before = delivered.load(Ordering::SeqCst);
            router.route(ReceivedDatagram::new(bytes.clone(), arrival.clone()));
            routed += 1;
            if delivered.load(Ordering::SeqCst) == before {
                missed += 1;
                break;
            }
        }
    }
    done.store(true, Ordering::Relaxed);
    writer.join().unwrap();
    assert_eq!(
        missed, 0,
        "routed {routed} datagrams; a lookup found neither association"
    );
}

/// A deliverer whose drop and delivery read the index. Inside an index guard
/// either would deadlock on the shard.
struct ReadsIndex {
    index: std::sync::Weak<Index>,
    cid: sakuya_wire::connection_id::NonEmptyCid,
    dropped: Arc<AtomicUsize>,
}

impl Drop for ReadsIndex {
    fn drop(&mut self) {
        if let Some(index) = self.index.upgrade() {
            let _ = index.occupancy(&self.cid);
        }
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

impl DatagramDeliverer<Datagram, Local> for ReadsIndex {
    type Handoff = Handoff;

    fn deliver(&self, delivery: DatagramDelivery<Datagram, Local, Handoff>) {
        if let Some(index) = self.index.upgrade() {
            assert!(index.occupancy(&self.cid) >= 1);
        }
        drop(delivery);
    }
}

#[test]
fn revocation_destroys_the_deliverer_outside_the_index() {
    let domain = Domain::new(&[8]);
    let key = nonempty(&cid(0x31));
    let dropped = Arc::new(AtomicUsize::new(0));
    let registration = domain.index().register(
        RouteMatcher::new(
            MatchAssociation::LocalCid(key),
            PacketForms::ALL,
            Version::V1,
        ),
        Arc::new(ReadsIndex {
            index: Arc::downgrade(domain.index()),
            cid: key,
            dropped: Arc::clone(&dropped),
        }) as Arc<Target>,
    );
    domain.route(
        long(LongPacketType::Handshake, &cid(0x31), &cid(0x10), 20),
        &link(&local_end()),
    );
    drop(registration);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert_eq!(domain.index().occupancy(&key), 0);
}

/// Registers another entry while it is being delivered to.
struct RegistersDuringDelivery {
    index: Arc<Index>,
    late: Arc<Recorder>,
    registrations: Mutex<Vec<RouteEntryRegistration<Target, Local>>>,
}

impl DatagramDeliverer<Datagram, Local> for RegistersDuringDelivery {
    type Handoff = Handoff;

    fn deliver(&self, delivery: DatagramDelivery<Datagram, Local, Handoff>) {
        let registration = register(
            &self.index,
            MatchAssociation::InitialDcid(nonempty(&cid(0x32))),
            &self.late,
        );
        self.registrations.lock().unwrap().push(registration);
        drop(delivery);
    }
}

/// The candidate set is frozen before the first delivery: an entry registered
/// meanwhile is not part of the round, and the reflow offers it the datagram.
#[test]
fn an_entry_registered_during_delivery_waits_for_the_next_round() {
    let mut domain = Domain::new(&[8]);
    let late = Recorder::new(1, Judging::Reject);
    let registering = Arc::new(RegistersDuringDelivery {
        index: Arc::clone(domain.index()),
        late: Arc::clone(&late),
        registrations: Mutex::new(Vec::new()),
    });
    let _entry = domain.index().register(
        RouteMatcher::new(
            MatchAssociation::InitialDcid(nonempty(&cid(0x32))),
            PacketForms::ALL,
            Version::V1,
        ),
        Arc::clone(&registering) as Arc<Target>,
    );
    domain.route(initial(&cid(0x32), &cid(0x10)), &link(&local_end()));
    assert_eq!(late.delivery_count(), 0, "the frozen set has no late entry");
    assert_eq!(domain.drain(), 1, "the only candidate exited");
    assert_eq!(
        late.delivery_count(),
        1,
        "the next round offers the late entry"
    );
    assert_eq!(domain.factory.accepted_count(), 0);
}

/// Reflow is not a second arrival: a stateless reset token that appeared after
/// the first round does not end the datagram's next round.
#[test]
fn a_reflow_round_does_not_repeat_reset_detection() {
    let mut domain = Domain::new(&[8]);
    let probe = ResetProbe::default();
    let bytes = initial(&cid(0x33), &cid(0x10));
    let tail = *bytes.last_chunk().unwrap();
    domain.route(bytes, &link(&local_end()));
    let _token = domain
        .resets
        .register(StatelessResetToken::new(tail), probe.clone());
    assert_eq!(domain.drain(), 1);
    assert_eq!(probe.0.load(Ordering::SeqCst), 0);
    assert_eq!(domain.factory.accepted_count(), 1);
}
