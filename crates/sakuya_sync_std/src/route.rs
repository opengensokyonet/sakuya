//! The tables every received datagram is looked up in, shared between
//! threads: the route index and the peers' stateless reset tokens, in the
//! maps of `dashmap`.
//!
//! Each map is split into shards behind their own locks; one entry access of
//! a key holds the lock of that key's shard, so that accesses to keys of
//! other shards go on at once. That is how these tables keep the one
//! synchronization boundary of each key that routing requires.

use std::fmt;
use std::hash::Hash;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Poll, Waker};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry as MapEntry;
use sakuya_datagram_routing_v1::route::index::{
    DatagramRouteEntry, NonEmptyCidRouteBucket, RouteIndex, ZeroCidRouteBucket,
};
use sakuya_datagram_routing_v1::route::recognizer::ConnectionIdOccupancy;
use sakuya_datagram_routing_v1::route::reset::{
    PeerStatelessResetTokens, StatelessResetDetector, StatelessResetTarget, StatelessResetTokens,
};
use sakuya_link::LinkId;
use sakuya_wire_v1::connection_id::{NonEmptyCid, StatelessResetToken};

use crate::claim::TokioMutexDatagramClaimLock;

/// Runs `update` on the bucket of `key` in `map`, within the lock of its
/// shard; the bucket starts empty when there is none and is removed when
/// left empty.
fn update_bucket<K: Eq + Hash, B: Default, R>(
    map: &DashMap<K, B>,
    key: K,
    is_empty: impl Fn(&B) -> bool,
    update: impl FnOnce(&mut B) -> R,
) -> R {
    match map.entry(key) {
        MapEntry::Occupied(mut slot) => {
            let updated = update(slot.get_mut());
            if is_empty(slot.get()) {
                drop(slot.remove());
            }
            updated
        }
        MapEntry::Vacant(slot) => {
            let mut bucket = B::default();
            let updated = update(&mut bucket);
            if !is_empty(&bucket) {
                slot.insert(bucket);
            }
            updated
        }
    }
}

/// The index of a routing domain shared between threads
/// (`DashMapRouteIndex`): the buckets in two maps of `dashmap`, which the
/// index's clones share through an `Arc`.
///
/// It is `Send` and `Sync` when its entries are, and its candidates compete
/// under [`TokioMutexDatagramClaimLock`]. The maps hash with the hasher of
/// std, seeded at random and meant to resist collisions an attacker crafts.
pub struct DashMapRouteIndex<Target: ?Sized, Local> {
    shared: Arc<RouteIndexShared<Target, Local>>,
}

struct RouteIndexShared<Target: ?Sized, Local> {
    nonzero: DashMap<NonEmptyCid, NonEmptyCidRouteBucket<Target, Local>>,
    zero: DashMap<Local, ZeroCidRouteBucket<Target, Local>>,
    registrations: AtomicUsize,
    /// Woken when the last registration is revoked. The count is read and
    /// the waker stored under this lock, and the last revocation takes the
    /// wakers under it, so that no wake-up is lost in between.
    empty_waiters: Mutex<Vec<Waker>>,
}

impl<Target: ?Sized, Local> RouteIndexShared<Target, Local> {
    /// The lock is taken on the revocation path, which also runs while a
    /// panic unwinds; a poisoned lock is used as it is.
    fn lock_empty_waiters(&self) -> MutexGuard<'_, Vec<Waker>> {
        self.empty_waiters
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

impl<Target: ?Sized, Local> Clone for DashMapRouteIndex<Target, Local> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<Target: ?Sized, Local: Clone + Eq + Hash> RouteIndex<Local>
    for DashMapRouteIndex<Target, Local>
{
    type Target = Target;
    type Registration = DashMapRouteEntryRegistration<Target, Local>;
    type ClaimLock = TokioMutexDatagramClaimLock;

    fn new() -> Self {
        Self {
            shared: Arc::new(RouteIndexShared {
                nonzero: DashMap::new(),
                zero: DashMap::new(),
                registrations: AtomicUsize::new(0),
                empty_waiters: Mutex::new(Vec::new()),
            }),
        }
    }

    fn registration_count(&self) -> usize {
        self.shared.registrations.load(Ordering::SeqCst)
    }

    fn poll_empty(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut waiters = self.shared.lock_empty_waiters();
        if self.shared.registrations.load(Ordering::SeqCst) == 0 {
            return Poll::Ready(());
        }
        if !waiters.iter().any(|waiter| waiter.will_wake(cx.waker())) {
            waiters.push(cx.waker().clone());
        }
        Poll::Pending
    }

    fn count_published(&self) {
        self.shared.registrations.fetch_add(1, Ordering::SeqCst);
    }

    fn count_revoked(&self) {
        if self.shared.registrations.fetch_sub(1, Ordering::SeqCst) == 1 {
            let waiters = std::mem::take(&mut *self.shared.lock_empty_waiters());
            for waiter in waiters {
                waiter.wake();
            }
        }
    }

    fn read_nonzero<R>(
        &self,
        cid: &NonEmptyCid,
        read: impl FnOnce(&NonEmptyCidRouteBucket<Target, Local>) -> R,
    ) -> Option<R> {
        self.shared.nonzero.get(cid).map(|bucket| read(&bucket))
    }

    fn update_nonzero<R>(
        &self,
        cid: &NonEmptyCid,
        update: impl FnOnce(&mut NonEmptyCidRouteBucket<Target, Local>) -> R,
    ) -> R {
        update_bucket(
            &self.shared.nonzero,
            *cid,
            NonEmptyCidRouteBucket::is_empty,
            update,
        )
    }

    fn read_zero<R>(
        &self,
        local: &Local,
        read: impl FnOnce(&ZeroCidRouteBucket<Target, Local>) -> R,
    ) -> Option<R> {
        self.shared.zero.get(local).map(|bucket| read(&bucket))
    }

    fn update_zero<R>(
        &self,
        local: &Local,
        update: impl FnOnce(&mut ZeroCidRouteBucket<Target, Local>) -> R,
    ) -> R {
        update_bucket(
            &self.shared.zero,
            local.clone(),
            ZeroCidRouteBucket::is_empty,
            update,
        )
    }

    fn hold(
        &self,
        entry: Arc<DatagramRouteEntry<Target, Local>>,
    ) -> DashMapRouteEntryRegistration<Target, Local> {
        DashMapRouteEntryRegistration {
            index: Arc::downgrade(&self.shared),
            entry,
        }
    }
}

impl<Target: ?Sized, Local: Clone + Eq + Hash> ConnectionIdOccupancy
    for DashMapRouteIndex<Target, Local>
{
    fn occupancy(&self, cid: &NonEmptyCid) -> usize {
        self.read_nonzero(cid, NonEmptyCidRouteBucket::len)
            .unwrap_or(0)
    }
}

impl<Target: ?Sized, Local: Eq + Hash> fmt::Debug for DashMapRouteIndex<Target, Local> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DashMapRouteIndex")
            .field("nonzero_keys", &self.shared.nonzero.len())
            .field("zero_keys", &self.shared.zero.len())
            .field(
                "registrations",
                &self.shared.registrations.load(Ordering::SeqCst),
            )
            .finish()
    }
}

/// The registration of an entry of a [`DashMapRouteIndex`]: it finds the
/// index again through a weak reference, and revoking after the index is gone
/// does nothing.
#[must_use = "dropping the registration revokes the route entry"]
pub struct DashMapRouteEntryRegistration<Target: ?Sized, Local: Clone + Eq + Hash> {
    index: Weak<RouteIndexShared<Target, Local>>,
    entry: Arc<DatagramRouteEntry<Target, Local>>,
}

impl<Target: ?Sized, Local: Clone + Eq + Hash> DashMapRouteEntryRegistration<Target, Local> {
    /// The registered entry.
    pub fn entry(&self) -> &DatagramRouteEntry<Target, Local> {
        &self.entry
    }
}

impl<Target: ?Sized, Local: Clone + Eq + Hash> Drop
    for DashMapRouteEntryRegistration<Target, Local>
{
    fn drop(&mut self) {
        if let Some(shared) = self.index.upgrade() {
            DashMapRouteIndex { shared }.revoke(&self.entry);
        }
    }
}

impl<Target: ?Sized, Local: Clone + Eq + Hash + fmt::Debug> fmt::Debug
    for DashMapRouteEntryRegistration<Target, Local>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DashMapRouteEntryRegistration")
            .field("entry", &self.entry)
            .finish_non_exhaustive()
    }
}

/// The token table of a routing domain shared between threads
/// (`DashMapStatelessResetTokens`): the groups in a map of `dashmap`, which
/// the table's clones share through an `Arc`.
///
/// It is `Send` and `Sync` when the peers and the targets are. The map
/// hashes with the hasher of std.
pub struct DashMapStatelessResetTokens<Peer, Target> {
    by_peer: Arc<DashMap<Peer, PeerStatelessResetTokens<Target>>>,
}

impl<Peer, Target> Clone for DashMapStatelessResetTokens<Peer, Target> {
    fn clone(&self) -> Self {
        Self {
            by_peer: Arc::clone(&self.by_peer),
        }
    }
}

impl<Peer: Clone + Eq + Hash, Target> StatelessResetTokens<Peer, Target>
    for DashMapStatelessResetTokens<Peer, Target>
{
    type Registration = DashMapStatelessResetRegistration<Peer, Target>;

    fn new() -> Self {
        Self {
            by_peer: Arc::new(DashMap::new()),
        }
    }

    fn read<R>(
        &self,
        peer: &Peer,
        read: impl FnOnce(&PeerStatelessResetTokens<Target>) -> R,
    ) -> Option<R> {
        self.by_peer.get(peer).map(|group| read(&group))
    }

    fn update<R>(
        &self,
        peer: &Peer,
        update: impl FnOnce(&mut PeerStatelessResetTokens<Target>) -> R,
    ) -> R {
        update_bucket(
            &self.by_peer,
            peer.clone(),
            PeerStatelessResetTokens::is_empty,
            update,
        )
    }

    fn hold(
        &self,
        peer: Peer,
        target: Arc<Target>,
    ) -> DashMapStatelessResetRegistration<Peer, Target> {
        DashMapStatelessResetRegistration {
            tokens: Arc::downgrade(&self.by_peer),
            peer,
            target,
        }
    }
}

impl<Local, Peer: Clone + Eq + Hash, Target: StatelessResetTarget>
    StatelessResetDetector<Local, Peer> for DashMapStatelessResetTokens<Peer, Target>
{
    type Target = Arc<Target>;

    fn detect(
        &self,
        tail: &StatelessResetToken,
        link: &LinkId<Local, Peer>,
    ) -> Option<Arc<Target>> {
        self.detect_from(tail, &link.peer)
    }
}

impl<Peer: Eq + Hash, Target> fmt::Debug for DashMapStatelessResetTokens<Peer, Target> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DashMapStatelessResetTokens")
            .field("peers", &self.by_peer.len())
            .finish()
    }
}

/// The registration of a token in a [`DashMapStatelessResetTokens`]: it
/// finds the table again through a weak reference, and revoking after the
/// table is gone does nothing.
#[must_use = "dropping the registration revokes the token"]
pub struct DashMapStatelessResetRegistration<Peer: Clone + Eq + Hash, Target> {
    tokens: Weak<DashMap<Peer, PeerStatelessResetTokens<Target>>>,
    peer: Peer,
    target: Arc<Target>,
}

impl<Peer: Clone + Eq + Hash, Target> Drop for DashMapStatelessResetRegistration<Peer, Target> {
    fn drop(&mut self) {
        if let Some(by_peer) = self.tokens.upgrade() {
            DashMapStatelessResetTokens { by_peer }.revoke(&self.peer, &self.target);
        }
    }
}

impl<Peer: Clone + Eq + Hash, Target> fmt::Debug
    for DashMapStatelessResetRegistration<Peer, Target>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DashMapStatelessResetRegistration")
            .finish_non_exhaustive()
    }
}
