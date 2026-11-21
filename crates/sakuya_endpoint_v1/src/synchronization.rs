//! How the state of an endpoint is synchronized: a family of structures the
//! host chooses once ([`EndpointSynchronization`]). Its parent, a family of
//! [`nitori_sync`], gives the wrapper of the state that is not reached for
//! every datagram.
//!
//! The endpoint does not decide whether, nor with what, its state is
//! synchronized; as for a connection, it is a property of the parts it is
//! made of. The three tables every received datagram is looked up in, the
//! route index, the stateless reset tokens and the local ends occupied by
//! zero-length connection IDs, are traits whose handles each reach their own
//! structure, as are the receive queue of each connection and the lock its
//! candidates compete under. The rest of the endpoint's state, reached less
//! often than once per datagram, is kept in wrappers that are borrowed for
//! one operation at a time. The endpoint names no lock: the locks are in the
//! family the host chooses.
//!
//! [`RefCellEndpointSynchronization`] is the family of an endpoint on one
//! thread; a crate with the locks of `std` gives the one whose drivers,
//! connections and handles are on several threads.

use alloc::rc::Rc;
use core::{
    cell::RefCell,
    fmt,
    hash::{BuildHasher, Hash},
    marker::PhantomData,
};

use sakuya_datagram_routing_v1::{
    claim::{
        lock::{DatagramClaimLock, RefCellDatagramClaimLock},
        queue::{DatagramDeliveryQueue, RefCellDatagramDeliveryQueue},
    },
    route::{
        index::{HashMapRouteIndex, RouteIndex},
        reset::{HashMapStatelessResetTokens, StatelessResetTokens},
    },
};

use nitori_sync::{RefCellSynchronization, Synchronization};

use crate::zero_length::{HashSetZeroLengthLocals, ZeroLengthLocals};

/// How the state of an endpoint is synchronized: one family of the
/// structures it is made of (`EndpointSynchronization`), chosen in
/// [`EndpointChoices::Synchronization`](crate::choices::EndpointChoices::Synchronization).
///
/// The family gives all of them at once, so that they agree: an endpoint on
/// one thread, one on each thread with its own sockets, and one whose
/// connections are on the threads of a runtime each choose one family, and
/// do not mix them. Whether the endpoint's drivers, connections and handles
/// are `Send` follows from the family; the endpoint requires nothing of it.
///
/// The state reached less often than once per datagram is in the wrapper of
/// the parent family ([`Synchronization::SharedState`]). The endpoint does
/// not borrow the same state again while an operation on it runs, nor drop
/// or wake anything that may: it takes such values out and drops or wakes
/// them after the borrow. It also borrows on the paths that run while a
/// panic unwinds, so a wrapper whose borrow is a lock takes a lock a panic
/// poisoned as it is, as those of [`nitori_sync`] do.
pub trait EndpointSynchronization: Synchronization {
    /// The lock the candidates of one datagram compete under.
    type ClaimLock: DatagramClaimLock;
    /// The index of the route entries of the endpoint's routing domain.
    type RouteIndex<Target: ?Sized, Local: Clone + Eq + Hash>: RouteIndex<Local, Target = Target, ClaimLock = Self::ClaimLock>;
    /// The table of the peers' stateless reset tokens.
    type StatelessResetTokens<Peer: Clone + Eq + Hash, Target>: StatelessResetTokens<Peer, Target>;
    /// The receive queue of each connection, which its route entries post
    /// to.
    type DatagramDeliveryQueue<T>: DatagramDeliveryQueue<T>;
    /// The local ends on which a connection uses zero-length connection IDs.
    type ZeroLengthLocals<Local: Clone + Eq + Hash>: ZeroLengthLocals<Local>;
    /// What builds the hashers of the endpoint's own maps, among them some
    /// whose keys the peer can choose, such as the links of a binding by
    /// their peers' ends.
    type HashBuilder: BuildHasher + Default;
}

/// The family of an endpoint on one thread
/// (`RefCellEndpointSynchronization`): cells, and hash maps in cells.
///
/// Nothing of it is `Send` or `Sync`. The tables are keyed by values the
/// peer can choose, its addresses and connection IDs; `S` builds the hashers
/// of their maps, and the host chooses it, since the endpoint has no source
/// of randomness to seed one with. A host whose endpoint an attacker can
/// reach chooses one that is seeded at random and resists the collisions an
/// attacker crafts, as the hasher of `std` (`std::hash::RandomState`) does.
pub struct RefCellEndpointSynchronization<S> {
    hasher: PhantomData<fn() -> S>,
}

impl<S> fmt::Debug for RefCellEndpointSynchronization<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefCellEndpointSynchronization")
            .field("hasher", &self.hasher)
            .finish()
    }
}

impl<S: BuildHasher + Default + 'static> EndpointSynchronization
    for RefCellEndpointSynchronization<S>
{
    type ClaimLock = RefCellDatagramClaimLock;
    type RouteIndex<Target: ?Sized, Local: Clone + Eq + Hash> = HashMapRouteIndex<Target, Local, S>;
    type StatelessResetTokens<Peer: Clone + Eq + Hash, Target> =
        HashMapStatelessResetTokens<Peer, Target, S>;
    type DatagramDeliveryQueue<T> = RefCellDatagramDeliveryQueue<T>;
    type ZeroLengthLocals<Local: Clone + Eq + Hash> = HashSetZeroLengthLocals<Local, S>;
    type HashBuilder = S;
}

/// Cells behind an `Rc`, the wrappers of [`RefCellSynchronization`].
impl<S: 'static> Synchronization for RefCellEndpointSynchronization<S> {
    type SharedState<T> = Rc<RefCell<T>>;
    fn share<T>(state: T) -> Rc<RefCell<T>> {
        RefCellSynchronization::share(state)
    }
}
