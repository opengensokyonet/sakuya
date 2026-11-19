//! What a routing domain and an endpoint shared between threads are made
//! of is `Send` and `Sync`, when what they hold is.

#[expect(dead_code, reason = "these tests use only the types of the support")]
mod support;

use std::future::Future;

use sakuya_datagram_routing::claim::candidate::{DatagramClaimCandidate, DatagramClaimOutcome};
use sakuya_datagram_routing::claim::delivery::DatagramDelivery;
use sakuya_datagram_routing::claim::erased::SendDatagramDeliverer;
use sakuya_datagram_routing::claim::finish::ReleaseUnclaimed;
use sakuya_datagram_routing::route::recognizer::ConnectionIdLengths;
use sakuya_datagram_routing::route::router::DatagramRouter;
use sakuya_endpoint::synchronization::EndpointSynchronization;
use sakuya_endpoint::zero_length::ZeroLengthLocals;
use sakuya_sync_std::claim::TokioMutexDatagramClaimLock;
use sakuya_sync_std::endpoint::{
    DashSetZeroLengthLocals, LockingEndpointSynchronization, MutexSharedEndpointState,
};
use sakuya_sync_std::queue::{MutexDatagramDeliveryPoster, MutexDatagramDeliveryQueue};
use sakuya_sync_std::route::{
    DashMapRouteEntryRegistration, DashMapRouteIndex, DashMapStatelessResetRegistration,
    DashMapStatelessResetTokens,
};

use support::{Datagram, Local, Peer, TestLink};

type Lock = TokioMutexDatagramClaimLock;
type Target = dyn SendDatagramDeliverer<Datagram, Local, ReleaseUnclaimed, Lock>;
type Delivery = DatagramDelivery<Datagram, Local, ReleaseUnclaimed, Lock>;

fn send<T: Send>() {}
fn send_sync<T: ?Sized + Send + Sync>() {}
fn send_value<T: Send>(_: &T) {}

/// The future of an attempt under the lock of `tokio` is `Send` when the
/// candidate and the judgment are.
#[allow(dead_code)]
fn attempt_is_send(candidate: DatagramClaimCandidate<Datagram, Local, ReleaseUnclaimed, Lock>) {
    let attempt =
        candidate.try_exclusive(|access, _| DatagramClaimOutcome::<(), (), _>::Unclaimed(access));
    fn future<F: Future>(_: &F) {}
    future(&attempt);
    send_value(&attempt);
}

#[test]
fn a_routing_domain_shared_between_threads_is_send() {
    type Router = DatagramRouter<
        Vec<u8>,
        TestLink,
        DashMapRouteIndex<Target, Local>,
        ConnectionIdLengths,
        DashMapStatelessResetTokens<Peer, ()>,
    >;
    send_sync::<Router>();
    send_sync::<DashMapRouteIndex<Target, Local>>();
    send::<DashMapRouteEntryRegistration<Target, Local>>();
    send_sync::<DashMapStatelessResetTokens<Peer, ()>>();
    send::<DashMapStatelessResetRegistration<Peer, ()>>();
    send_sync::<MutexDatagramDeliveryQueue<Delivery>>();
    send_sync::<MutexDatagramDeliveryPoster<Delivery>>();
    send::<DatagramClaimCandidate<Datagram, Local, ReleaseUnclaimed, Lock>>();
    send::<Delivery>();
}

#[test]
fn the_endpoint_state_of_the_family_is_send() {
    type Occupancy = <DashSetZeroLengthLocals<Local> as ZeroLengthLocals<Local>>::Occupancy;
    send_sync::<DashSetZeroLengthLocals<Local>>();
    send::<Occupancy>();
    send_sync::<MutexSharedEndpointState<Vec<u8>>>();
    send_sync::<<LockingEndpointSynchronization as EndpointSynchronization>::SharedState<Vec<u8>>>(
    );
}
