//! Multi-thread stress of the shared bucket of the index shared between
//! threads, on real threads and real `dashmap` shards.
//!
//! These tests can show that a bad interleaving exists; they cannot show that
//! none does.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use sakuya_datagram_routing::claim::deliverer::DatagramDeliverer;
use sakuya_datagram_routing::claim::delivery::DatagramDelivery;
use sakuya_datagram_routing::claim::erased::SendDatagramDeliverer;
use sakuya_datagram_routing::claim::finish::ReleaseUnclaimed;
use sakuya_datagram_routing::route::association::{MatchAssociation, PacketForms, RouteMatcher};
use sakuya_datagram_routing::route::index::RouteIndex;
use sakuya_datagram_routing::route::recognizer::{ConnectionIdLengths, ConnectionIdOccupancy};
use sakuya_datagram_routing::route::router::DatagramRouter;
use sakuya_sync_std::claim::TokioMutexDatagramClaimLock;
use sakuya_sync_std::route::DashMapRouteIndex;
use sakuya_wire::connection_id::{ConnectionIdLength, NonEmptyCid};
use sakuya_wire::version::Version;

use support::{Datagram, Local, datagram, link, zero_rtt};

type Target =
    dyn SendDatagramDeliverer<Datagram, Local, ReleaseUnclaimed, TokioMutexDatagramClaimLock>;

/// A deliverer that only counts its deliveries.
struct Counter(Arc<AtomicUsize>);

impl DatagramDeliverer<Datagram, Local> for Counter {
    type ClaimLock = TokioMutexDatagramClaimLock;

    fn deliver(
        &self,
        _delivery: DatagramDelivery<Datagram, Local, ReleaseUnclaimed, TokioMutexDatagramClaimLock>,
    ) {
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
    let index = DashMapRouteIndex::<Target, Local>::new();
    let router = Arc::new(DatagramRouter::new(
        index.clone(),
        ConnectionIdLengths::new([ConnectionIdLength::new(8).unwrap()]),
    ));
    let key = NonEmptyCid::try_from(&[0x77; 8][..]).unwrap();
    let delivered = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let matcher = |association| RouteMatcher::new(association, PacketForms::ALL, Version::V1);
    let local = MatchAssociation::LocalCid(key);
    let initial = MatchAssociation::InitialDcid(key);
    let counter =
        |delivered: &Arc<AtomicUsize>| Arc::new(Counter(Arc::clone(delivered))) as Arc<Target>;
    let mut held = index.register(matcher(initial.clone()), counter(&delivered));
    let writer = {
        let index = index.clone();
        let done = Arc::clone(&done);
        let delivered = Arc::clone(&delivered);
        std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                let next = index.register(matcher(local.clone()), counter(&delivered));
                drop(std::mem::replace(&mut held, next));
                let next = index.register(matcher(initial.clone()), counter(&delivered));
                drop(std::mem::replace(&mut held, next));
            }
            assert!(index.occupancy(&key) >= 1);
        })
    };
    let bytes = zero_rtt([0x77; 8], [0x10; 8], 20);
    let arrival = link(7);
    let started = Instant::now();
    let mut routed = 0_u64;
    let mut missed = 0_u64;
    while started.elapsed() < DEADLINE && missed == 0 {
        for _ in 0..4096 {
            let before = delivered.load(Ordering::SeqCst);
            router.route(datagram(bytes.clone(), &arrival));
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
