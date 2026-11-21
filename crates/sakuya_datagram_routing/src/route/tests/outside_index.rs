//! Deliverer code runs outside the index: revoking, delivering and
//! registering while a round is delivered.
//!
//! The stress of the shared bucket on real threads is the test of the index
//! shared between threads, in `sakuya_sync_std`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use sakuya_link::Link as _;
use sakuya_wire::connection_id::StatelessResetToken;
use sakuya_wire_v1::header::LongPacketType;
use sakuya_wire_v1::header::VERSION;

use super::support::*;
use crate::claim::deliverer::DatagramDeliverer;
use crate::claim::delivery::DatagramDelivery;
use crate::route::association::{MatchAssociation, PacketForms, RouteMatcher};
use crate::route::index::RouteIndex;
use crate::route::recognizer::ConnectionIdOccupancy;
use crate::route::reset::StatelessResetTokens;

/// A deliverer whose drop and delivery read the index. Inside an access of
/// the index either would find the bucket borrowed.
struct ReadsIndex {
    index: Index,
    cid: sakuya_wire::connection_id::NonEmptyCid,
    dropped: Arc<AtomicUsize>,
}

impl Drop for ReadsIndex {
    fn drop(&mut self) {
        let _ = self.index.occupancy(&self.cid);
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

impl DatagramDeliverer<Datagram, Local> for ReadsIndex {
    type Handoff = Handoff;

    fn deliver(&self, delivery: DatagramDelivery<Datagram, Local, Handoff>) {
        assert!(self.index.occupancy(&self.cid) >= 1);
        drop(delivery);
    }
}

#[test]
fn revocation_destroys_the_deliverer_outside_the_index() {
    let domain = Domain::new(&[8]);
    let key = nonempty(&cid(0x31));
    let dropped = Arc::new(AtomicUsize::new(0));
    let registration = domain.index().register(
        RouteMatcher::new(MatchAssociation::LocalCid(key), PacketForms::ALL, VERSION),
        Arc::new(ReadsIndex {
            index: domain.index().clone(),
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
    index: Index,
    late: Arc<Recorder>,
    registrations: Mutex<Vec<Registration>>,
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
        index: domain.index().clone(),
        late: Arc::clone(&late),
        registrations: Mutex::new(Vec::new()),
    });
    let _entry = domain.index().register(
        RouteMatcher::new(
            MatchAssociation::InitialDcid(nonempty(&cid(0x32))),
            PacketForms::ALL,
            VERSION,
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
    let arrival = link(&local_end());
    domain.route(bytes, &arrival);
    let _token = domain.resets.register(
        arrival.id().peer,
        StatelessResetToken::new(tail),
        probe.clone(),
    );
    assert_eq!(domain.drain(), 1);
    assert_eq!(probe.0.load(Ordering::SeqCst), 0);
    assert_eq!(domain.factory.accepted_count(), 1);
}
