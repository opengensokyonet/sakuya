//! The family of an endpoint whose drivers, connections and handles are on
//! several threads ([`LockingEndpointSynchronization`]), with the parts of
//! it that are the endpoint's own: the occupied local ends and the wrapper
//! of the state reached less often than once per datagram.

use std::fmt;
use std::hash::Hash;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use dashmap::DashSet;
use sakuya_endpoint::synchronization::{EndpointSynchronization, SharedEndpointState};
use sakuya_endpoint::zero_length::{ZeroLengthLocalCidInUseError, ZeroLengthLocals};

use crate::claim::TokioMutexDatagramClaimLock;
use crate::queue::MutexDatagramDeliveryQueue;
use crate::route::{DashMapRouteIndex, DashMapStatelessResetTokens};

/// State of an endpoint behind a mutex of std (`MutexSharedEndpointState`),
/// for an endpoint whose drivers, connections and handles are on several
/// threads.
///
/// A clone is the same state. Each operation holds the lock while it runs. A
/// lock poisoned by a panic of a holder is taken as it is: the endpoint
/// borrows its state on the paths that run while a panic unwinds, and every
/// change it makes there leaves the state consistent.
pub struct MutexSharedEndpointState<T>(Arc<Mutex<T>>);

/// A clone is the same state.
impl<T> Clone for MutexSharedEndpointState<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T> SharedEndpointState for MutexSharedEndpointState<T> {
    type State = T;
    fn new(state: T) -> Self {
        Self(Arc::new(Mutex::new(state)))
    }
    fn with<R>(&self, op: impl FnOnce(&mut T) -> R) -> R {
        op(&mut self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

impl<T> fmt::Debug for MutexSharedEndpointState<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MutexSharedEndpointState")
            .finish_non_exhaustive()
    }
}

/// The occupied local ends of an endpoint shared between threads
/// (`DashSetZeroLengthLocals`): a set of `dashmap`, and a count of its
/// members so that the common case of none reads no set.
///
/// It is `Send` and `Sync` when the local ends are.
pub struct DashSetZeroLengthLocals<Local: Eq + Hash> {
    shared: Arc<ZeroLengthLocalsShared<Local>>,
}

struct ZeroLengthLocalsShared<Local: Eq + Hash> {
    occupied: DashSet<Local>,
    count: AtomicUsize,
}

impl<Local: Eq + Hash> Clone for DashSetZeroLengthLocals<Local> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<Local: Clone + Eq + Hash> ZeroLengthLocals<Local> for DashSetZeroLengthLocals<Local> {
    type Occupancy = DashSetZeroLengthLocalOccupancy<Local>;

    fn new() -> Self {
        Self {
            shared: Arc::new(ZeroLengthLocalsShared {
                occupied: DashSet::new(),
                count: AtomicUsize::new(0),
            }),
        }
    }

    fn is_occupied(&self, local: &Local) -> bool {
        self.shared.count.load(Ordering::Acquire) != 0 && self.shared.occupied.contains(local)
    }

    fn occupy(
        &self,
        local: Local,
    ) -> Result<DashSetZeroLengthLocalOccupancy<Local>, ZeroLengthLocalCidInUseError> {
        if !self.shared.occupied.insert(local.clone()) {
            return Err(ZeroLengthLocalCidInUseError);
        }
        self.shared.count.fetch_add(1, Ordering::AcqRel);
        Ok(DashSetZeroLengthLocalOccupancy {
            locals: Arc::clone(&self.shared),
            local,
        })
    }
}

impl<Local: Eq + Hash> fmt::Debug for DashSetZeroLengthLocals<Local> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DashSetZeroLengthLocals")
            .field("occupied", &self.shared.count.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// One connection's hold on a local end of a [`DashSetZeroLengthLocals`];
/// it keeps the table, and dropping it frees the local end.
pub struct DashSetZeroLengthLocalOccupancy<Local: Eq + Hash> {
    locals: Arc<ZeroLengthLocalsShared<Local>>,
    local: Local,
}

impl<Local: Eq + Hash> DashSetZeroLengthLocalOccupancy<Local> {
    /// The occupied local end.
    #[must_use]
    pub fn local(&self) -> &Local {
        &self.local
    }
}

impl<Local: Eq + Hash> Drop for DashSetZeroLengthLocalOccupancy<Local> {
    fn drop(&mut self) {
        if self.locals.occupied.remove(&self.local).is_some() {
            self.locals.count.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

impl<Local: Eq + Hash + fmt::Debug> fmt::Debug for DashSetZeroLengthLocalOccupancy<Local> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DashSetZeroLengthLocalOccupancy")
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

/// The family of an endpoint whose drivers, connections and handles are on
/// several threads (`LockingEndpointSynchronization`): the maps of
/// `dashmap`, the mutex of `tokio` for the claim lock, and mutexes of std
/// for the receive queues and the wrapper of the rest. Its maps hash with
/// the hasher of std, seeded at random and meant to resist collisions an
/// attacker crafts.
///
/// Whether the endpoint's futures are `Send` still follows from its other
/// choices, such as its links and its crypto backend.
#[derive(Debug)]
pub enum LockingEndpointSynchronization {}

impl EndpointSynchronization for LockingEndpointSynchronization {
    type ClaimLock = TokioMutexDatagramClaimLock;
    type RouteIndex<Target: ?Sized, Local: Clone + Eq + Hash> = DashMapRouteIndex<Target, Local>;
    type StatelessResetTokens<Peer: Clone + Eq + Hash, Target> =
        DashMapStatelessResetTokens<Peer, Target>;
    type DatagramDeliveryQueue<T> = MutexDatagramDeliveryQueue<T>;
    type ZeroLengthLocals<Local: Clone + Eq + Hash> = DashSetZeroLengthLocals<Local>;
    type SharedState<T> = MutexSharedEndpointState<T>;
    type HashBuilder = std::hash::RandomState;
}
