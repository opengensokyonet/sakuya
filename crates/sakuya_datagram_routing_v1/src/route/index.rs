//! The route index, its entries and their registrations
//!
//! Local connection ID and Initial destination connection ID associations of
//! the same non-empty connection ID share one bucket, and therefore one
//! synchronization boundary: inserting, revoking and the Initial recheck with
//! publication of either kind all pass through the same map entry, so a reader
//! can never combine an empty local list read before a hand-over with an empty
//! Initial list read after it. Zero-length associations are kept per local end
//! of the arrival link.
//!
//! Every operation holds at most one map guard at a time and does only
//! controlled index work under it: no `deliver`, judgment, reflow handoff or
//! receiver construction runs there. Lookups copy the entry references out of
//! the guard; removed references are carried out of the guard before they are
//! dropped, so that no deliverer is destroyed inside the index.
//!
//! The index also counts its published registrations, so that the drivers of
//! a closed endpoint can wait until none is left
//! ([`RouteIndex::poll_empty`]).
//!
//! The index is a trait, [`RouteIndex`], so that how its buckets are stored
//! and synchronized is the implementation's: the contract above is what every
//! implementation keeps, through the entry accesses of the trait.
//! [`HashMapRouteIndex`] is the index of a routing domain on one thread; a
//! crate with the locks of `std` gives one shared between threads. What the
//! index does within each access, and the entries and buckets themselves, are
//! this module's, the same for every implementation.

use alloc::rc::{Rc, Weak};
use alloc::sync::Arc;
use core::cell::{Cell, RefCell};
use core::fmt;
use core::hash::{BuildHasher, Hash};
use core::task::{Context, Poll, Waker};

use hashbrown::{HashMap, hash_map::Entry as MapEntry};
use nitori_id::UniqueId;
use sakuya_wire_v1::connection_id::NonEmptyCid;
use smallvec::SmallVec;

use super::acceptance::PreparedReceiver;
use super::association::{MatchAssociation, PacketForms, RouteMatcher};
use super::interpretation::{FirstPacketInterpretation, InitialKey, RecognizedInitial};
use super::recognizer::ConnectionIdOccupancy;
use crate::claim::lock::{DatagramClaimLock, RefCellDatagramClaimLock};

mod fresh;

pub(crate) use fresh::fresh_initial_entries;
use fresh::gather_fresh;

/// One registration published as a whole: what it matches and the deliverer
/// bound to it.
///
/// Every registration is its own instance with its own identity, even when it
/// shares the deliverer, the association or the receiver with another one; a
/// new registration under the same key never reuses an old identity.
pub struct DatagramRouteEntry<Target: ?Sized, Local> {
    id: UniqueId,
    matcher: RouteMatcher<Local>,
    deliverer: Arc<Target>,
}

impl<Target: ?Sized, Local> DatagramRouteEntry<Target, Local> {
    pub(crate) fn new(matcher: RouteMatcher<Local>, deliverer: Arc<Target>) -> Arc<Self> {
        Arc::new(Self {
            id: UniqueId::allocate(),
            matcher,
            deliverer,
        })
    }

    /// What the entry matches.
    pub fn matcher(&self) -> &RouteMatcher<Local> {
        &self.matcher
    }

    /// The deliverer bound to the entry.
    pub fn deliverer(&self) -> &Arc<Target> {
        &self.deliverer
    }
}

impl<Target: ?Sized, Local: fmt::Debug> fmt::Debug for DatagramRouteEntry<Target, Local> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramRouteEntry")
            .field("matcher", &self.matcher)
            .finish_non_exhaustive()
    }
}

type EntryList<Target, Local> = SmallVec<[Arc<DatagramRouteEntry<Target, Local>>; 2]>;

/// Which list of a non-empty connection ID's bucket an association uses.
#[derive(Clone, Copy)]
enum NonzeroKind {
    Local,
    Initial,
}

/// Where the entries of one association are kept.
enum Location<'a, Local> {
    Nonzero(&'a NonEmptyCid, NonzeroKind),
    Zero(&'a Local),
}

impl<'a, Local> Location<'a, Local> {
    fn of(association: &'a MatchAssociation<Local>) -> Self {
        match association {
            MatchAssociation::LocalCid(cid) => Self::Nonzero(cid, NonzeroKind::Local),
            MatchAssociation::InitialDcid(cid) => Self::Nonzero(cid, NonzeroKind::Initial),
            MatchAssociation::ZeroCid(local) => Self::Zero(local),
        }
    }
}

/// The entries of one non-empty connection ID, both kinds side by side
/// (`NonEmptyCidRouteBucket`): the local connection ID entries and the
/// Initial destination connection ID entries.
///
/// An index keeps one per non-empty connection ID that has an entry; only
/// this crate reads or changes what is in it.
pub struct NonEmptyCidRouteBucket<Target: ?Sized, Local> {
    local: EntryList<Target, Local>,
    initial: EntryList<Target, Local>,
}

impl<Target: ?Sized, Local> NonEmptyCidRouteBucket<Target, Local> {
    /// A bucket without entries.
    pub fn new() -> Self {
        Self {
            local: SmallVec::new(),
            initial: SmallVec::new(),
        }
    }

    fn list_mut(&mut self, kind: NonzeroKind) -> &mut EntryList<Target, Local> {
        match kind {
            NonzeroKind::Local => &mut self.local,
            NonzeroKind::Initial => &mut self.initial,
        }
    }

    /// Whether the bucket has no entry; an index removes such a bucket.
    pub fn is_empty(&self) -> bool {
        self.local.is_empty() && self.initial.is_empty()
    }

    /// How many entries of both kinds the bucket has.
    pub fn len(&self) -> usize {
        self.local.len() + self.initial.len()
    }
}

impl<Target: ?Sized, Local> Default for NonEmptyCidRouteBucket<Target, Local> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Target: ?Sized, Local> fmt::Debug for NonEmptyCidRouteBucket<Target, Local> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NonEmptyCidRouteBucket")
            .field("local", &self.local.len())
            .field("initial", &self.initial.len())
            .finish()
    }
}

/// The zero-length connection ID entries of one local end
/// (`ZeroCidRouteBucket`).
///
/// An index keeps one per local end that has such an entry; only this crate
/// reads or changes what is in it.
pub struct ZeroCidRouteBucket<Target: ?Sized, Local> {
    entries: EntryList<Target, Local>,
}

impl<Target: ?Sized, Local> ZeroCidRouteBucket<Target, Local> {
    /// A bucket without entries.
    pub fn new() -> Self {
        Self {
            entries: SmallVec::new(),
        }
    }

    /// Whether the bucket has no entry; an index removes such a bucket.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many entries the bucket has.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

impl<Target: ?Sized, Local> Default for ZeroCidRouteBucket<Target, Local> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Target: ?Sized, Local> fmt::Debug for ZeroCidRouteBucket<Target, Local> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZeroCidRouteBucket")
            .field("entries", &self.entries.len())
            .finish()
    }
}

/// The index of every route entry of one routing domain (`RouteIndex`): a
/// handle, whose clones are the same index.
///
/// `Local` is this side's end of the domain's links. [`Target`](Self::Target)
/// is the erased deliverer type of the domain, for example
/// `dyn ErasedDatagramDeliverer<Inner, Local, Handoff, Lock>` (see
/// [`erased`](crate::claim::erased)).
///
/// An implementation stores the buckets, one per key, and gives the entry
/// accesses below. Their contract is the one shared synchronization boundary
/// of each key: every read and every update of one key's bucket runs within
/// one access to it, and an update of a key never interleaves with another
/// read or update of the same key. Lookups, inserting, revoking exactly one
/// entry, and the Initial recheck with its publication each run within one
/// access; the closures this crate passes do only controlled index work, hold
/// at most one access at a time, never call the index again and drop no
/// deliverer. Accesses to different keys need not be ordered with each other.
/// An update starts from an empty bucket when the key has none, and a bucket
/// an update leaves empty is removed.
///
/// The index also counts the registrations published and not revoked, and
/// wakes the tasks waiting for none to be left: the count and the waiters are
/// read and changed so that no wake-up is lost between [`poll_empty`]
/// finding registrations and the last revocation.
///
/// Registering, revoking and the lookups of routing are this crate's, on top
/// of the accesses: [`register`](Self::register) publishes an entry, and the
/// [`Registration`](Self::Registration) it returns revokes exactly that entry
/// when dropped, through [`revoke`](Self::revoke).
///
/// The index is `Send` and `Sync` exactly as its implementation makes it.
///
/// [`poll_empty`]: Self::poll_empty
pub trait RouteIndex<Local>: Clone {
    /// The erased deliverer type of the domain.
    type Target: ?Sized;
    /// The handle that revokes one route entry when dropped
    /// (`RouteEntryRegistration`).
    ///
    /// The datagram receiver holds it and is responsible for revoking:
    /// dropping it calls [`revoke`](RouteIndex::revoke) with its entry, so
    /// that new lookups no longer find it, unless the index is gone. It never
    /// removes another instance under the same key, and it does not redirect
    /// lookups already taken: candidates and snapshots keep the original
    /// deliverer, which stays callable. How it finds the index again is the
    /// implementation's.
    type Registration;
    /// The lock of the datagram the candidates of one round compete for, in
    /// this routing domain; its deliverers name the same
    /// ([`DatagramDeliverer::ClaimLock`]).
    ///
    /// [`DatagramDeliverer::ClaimLock`]: crate::claim::deliverer::DatagramDeliverer::ClaimLock
    type ClaimLock: DatagramClaimLock;

    /// Creates an empty index.
    fn new() -> Self;

    /// The number of published registrations that were not revoked yet.
    ///
    /// It is an observation: registrations can be published or revoked right
    /// after it is read.
    fn registration_count(&self) -> usize;

    /// Ready when no registration is published; otherwise arranges for the
    /// task of `cx` to be woken when the last one is revoked.
    ///
    /// Becoming empty is not final: a later registration makes the index
    /// non-empty again. A routing domain that no longer creates connections
    /// stays empty once it is.
    ///
    /// The count it reads is sequentially consistent with
    /// [`count_published`](Self::count_published): an endpoint that reads
    /// its closed flag after registering, and a driver that reads the count
    /// after seeing the flag, cannot both miss the other.
    fn poll_empty(&self, cx: &mut Context<'_>) -> Poll<()>;

    /// Counts a registration about to be published; only this crate calls
    /// it, within the access that publishes the entry. A count shared
    /// across threads is raised in sequentially consistent order, as
    /// [`poll_empty`](Self::poll_empty) says.
    fn count_published(&self);

    /// Counts a revoked registration; only this crate calls it, outside
    /// every access. The last one wakes the tasks
    /// [`poll_empty`](Self::poll_empty) arranged to wake.
    fn count_revoked(&self);

    /// Runs `read` within one access to the bucket of the non-empty
    /// connection ID `cid`, if it has one.
    fn read_nonzero<R>(
        &self,
        cid: &NonEmptyCid,
        read: impl FnOnce(&NonEmptyCidRouteBucket<Self::Target, Local>) -> R,
    ) -> Option<R>;

    /// Runs `update` within one access to the bucket of the non-empty
    /// connection ID `cid`, which starts empty when there is none and is
    /// removed when `update` leaves it empty.
    fn update_nonzero<R>(
        &self,
        cid: &NonEmptyCid,
        update: impl FnOnce(&mut NonEmptyCidRouteBucket<Self::Target, Local>) -> R,
    ) -> R;

    /// Runs `read` within one access to the bucket of the zero-length
    /// entries of the local end `local`, if it has one.
    fn read_zero<R>(
        &self,
        local: &Local,
        read: impl FnOnce(&ZeroCidRouteBucket<Self::Target, Local>) -> R,
    ) -> Option<R>;

    /// Runs `update` within one access to the bucket of the zero-length
    /// entries of the local end `local`, which starts empty when there is
    /// none and is removed when `update` leaves it empty.
    fn update_zero<R>(
        &self,
        local: &Local,
        update: impl FnOnce(&mut ZeroCidRouteBucket<Self::Target, Local>) -> R,
    ) -> R;

    /// The registration of `entry`, which this crate has just published:
    /// the handle that revokes it.
    fn hold(&self, entry: Arc<DatagramRouteEntry<Self::Target, Local>>) -> Self::Registration;

    /// Publishes a route entry for `deliverer`.
    ///
    /// The matcher and the deliverer are published together, as a new
    /// instance; registering the same deliverer or key again is legal and
    /// creates another instance. The returned registration revokes exactly
    /// this instance when dropped; the datagram receiver holds it. A new
    /// local connection ID must be disclosed only after this returns.
    fn register(
        &self,
        matcher: RouteMatcher<Local>,
        deliverer: Arc<Self::Target>,
    ) -> Self::Registration
    where
        Local: Clone,
    {
        let entry = DatagramRouteEntry::new(matcher, deliverer);
        let inserted = Arc::clone(&entry);
        match Location::of(entry.matcher.association()) {
            Location::Zero(local) => self.update_zero(local, |bucket| {
                self.count_published();
                bucket.entries.push(inserted);
            }),
            Location::Nonzero(cid, kind) => self.update_nonzero(cid, |bucket| {
                self.count_published();
                bucket.list_mut(kind).push(inserted);
            }),
        }
        self.hold(entry)
    }

    /// Revokes exactly `entry`, if it is still published: new lookups no
    /// longer find it. The registration of the entry calls it when dropped.
    ///
    /// The index's reference to the entry is dropped outside the access.
    fn revoke(&self, entry: &Arc<DatagramRouteEntry<Self::Target, Local>>) {
        fn take<Target: ?Sized, Local>(
            list: &mut EntryList<Target, Local>,
            entry: &Arc<DatagramRouteEntry<Target, Local>>,
        ) -> Option<Arc<DatagramRouteEntry<Target, Local>>> {
            let position = list
                .iter()
                .position(|current| Arc::ptr_eq(current, entry))?;
            Some(list.remove(position))
        }

        let removed = match Location::of(entry.matcher.association()) {
            Location::Zero(local) => {
                self.update_zero(local, |bucket| take(&mut bucket.entries, entry))
            }
            Location::Nonzero(cid, kind) => {
                self.update_nonzero(cid, |bucket| take(bucket.list_mut(kind), entry))
            }
        };
        if let Some(removed) = removed {
            drop(removed);
            self.count_revoked();
        }
    }
}

/// The entries one lookup found, each with the association and
/// interpretation it was found under.
pub(crate) type FrozenEntries<Target, Local> = SmallVec<
    [(
        Arc<DatagramRouteEntry<Target, Local>>,
        MatchAssociation<Local>,
        FirstPacketInterpretation,
    ); 4],
>;

/// What one first-packet interpretation looks up.
pub(crate) enum Lookup<Local> {
    /// The local association of a non-empty connection ID.
    Local(NonEmptyCid),
    /// The local and the Initial association of a non-empty connection ID.
    LocalAndInitial(NonEmptyCid),
    /// The zero-length association of this side's end of the arrival link.
    Zero(Local),
}

/// The outcome of the Initial recheck.
pub(crate) enum Recheck<Target: ?Sized, Local, Receiver, Registration> {
    /// Entries that apply and had no chance at this datagram yet; the
    /// prepared receiver, if any, was not used.
    Offer {
        fresh: FrozenEntries<Target, Local>,
        unused: Option<PreparedReceiver<Target, Receiver>>,
    },
    /// The prepared deliverer was published; the registration belongs to the
    /// prepared receiver.
    Published {
        registration: Registration,
        receiver: Receiver,
    },
    /// Nothing applies and nothing was prepared.
    Release,
}

/// Appends to `frozen` every entry `lookup` finds in `index` that applies to
/// `interpretation` and is not already there under the same interpretation.
///
/// The lists of one lookup are read within one access, so that a lookup of
/// both associations of a connection ID sees one state of its bucket.
pub(crate) fn collect<Local: Clone, Index: RouteIndex<Local>>(
    index: &Index,
    lookup: &Lookup<Local>,
    interpretation: FirstPacketInterpretation,
    frozen: &mut FrozenEntries<Index::Target, Local>,
) {
    let push = |frozen: &mut FrozenEntries<Index::Target, Local>,
                association: MatchAssociation<Local>,
                list: &EntryList<Index::Target, Local>| {
        for entry in list {
            let seen = frozen.iter().any(|(existing, _, existing_interpretation)| {
                existing.id == entry.id && *existing_interpretation == interpretation
            });
            if !seen && entry.matcher.applies(&interpretation) {
                frozen.push((Arc::clone(entry), association.clone(), interpretation));
            }
        }
    };
    match lookup {
        Lookup::Zero(local) => {
            index.read_zero(local, |bucket| {
                push(
                    frozen,
                    MatchAssociation::ZeroCid(local.clone()),
                    &bucket.entries,
                );
            });
        }
        Lookup::Local(cid) => {
            index.read_nonzero(cid, |bucket| {
                push(frozen, MatchAssociation::LocalCid(*cid), &bucket.local);
            });
        }
        Lookup::LocalAndInitial(cid) => {
            index.read_nonzero(cid, |bucket| {
                push(frozen, MatchAssociation::LocalCid(*cid), &bucket.local);
                push(frozen, MatchAssociation::InitialDcid(*cid), &bucket.initial);
            });
        }
    }
}

/// Rechecks the key of an unclaimed Initial within one entry access of
/// `index`.
///
/// Within the access it collects the entries that apply and have no record
/// in `offered`, recording them there; when there are none it publishes the
/// deliverer of `prepared`, if any, as a new Initial entry. Nothing else runs
/// inside the access; an unused prepared receiver is returned for the caller
/// to drop outside.
pub(crate) fn recheck_initial<Local: Clone, Index: RouteIndex<Local>, Receiver>(
    index: &Index,
    initial: &RecognizedInitial<Local>,
    offered: &mut OfferedRouteHistory,
    prepared: Option<PreparedReceiver<Index::Target, Receiver>>,
) -> Recheck<Index::Target, Local, Receiver, Index::Registration> {
    let interpretation = initial.interpretation();
    let matcher = RouteMatcher::new(
        initial.association(),
        PacketForms::INITIAL | PacketForms::ZERO_RTT,
        initial.version(),
    );
    let mut fresh = FrozenEntries::new();
    let mut prepared = prepared;
    let published = {
        let gather = |fresh: &mut FrozenEntries<Index::Target, Local>,
                      association: MatchAssociation<Local>,
                      list: &EntryList<Index::Target, Local>| {
            gather_fresh(fresh, association, list, interpretation, offered);
        };
        let mut publish = |list: &mut EntryList<Index::Target, Local>| {
            let (deliverer, receiver) = prepared.take()?.into_parts();
            let entry = DatagramRouteEntry::new(matcher.clone(), deliverer);
            index.count_published();
            list.push(Arc::clone(&entry));
            Some((entry, receiver))
        };
        match initial.key() {
            InitialKey::Dcid(cid) => index.update_nonzero(&cid, |bucket| {
                gather(&mut fresh, MatchAssociation::LocalCid(cid), &bucket.local);
                gather(
                    &mut fresh,
                    MatchAssociation::InitialDcid(cid),
                    &bucket.initial,
                );
                if fresh.is_empty() {
                    publish(&mut bucket.initial)
                } else {
                    None
                }
            }),
            InitialKey::Local(local) => index.update_zero(&local, |bucket| {
                gather(
                    &mut fresh,
                    MatchAssociation::ZeroCid(local.clone()),
                    &bucket.entries,
                );
                if fresh.is_empty() {
                    publish(&mut bucket.entries)
                } else {
                    None
                }
            }),
        }
    };
    if !fresh.is_empty() {
        for (entry, _, interpretation) in &fresh {
            offered.record(entry, *interpretation);
        }
        return Recheck::Offer {
            fresh,
            unused: prepared,
        };
    }
    match published {
        Some((entry, receiver)) => Recheck::Published {
            registration: index.hold(entry),
            receiver,
        },
        None => Recheck::Release,
    }
}

/// The index of a routing domain on one thread (`HashMapRouteIndex`): the
/// buckets in hash maps, each in a cell, which the index's clones share
/// through an `Rc`.
///
/// It is neither `Send` nor `Sync`, and its candidates compete under
/// [`RefCellDatagramClaimLock`]. The keys of its maps are values the peer can
/// choose, connection IDs; `S` builds their hashers, and the host chooses it.
/// A host whose endpoint an attacker can reach chooses one that is seeded at
/// random and resists the collisions an attacker crafts.
pub struct HashMapRouteIndex<Target: ?Sized, Local, S> {
    shared: Rc<HashMapRouteIndexShared<Target, Local, S>>,
}

struct HashMapRouteIndexShared<Target: ?Sized, Local, S> {
    nonzero: RefCell<HashMap<NonEmptyCid, NonEmptyCidRouteBucket<Target, Local>, S>>,
    zero: RefCell<HashMap<Local, ZeroCidRouteBucket<Target, Local>, S>>,
    registrations: Cell<usize>,
    /// Woken when the last registration is revoked.
    empty_waiters: RefCell<SmallVec<[Waker; 2]>>,
}

impl<Target: ?Sized, Local, S> Clone for HashMapRouteIndex<Target, Local, S> {
    fn clone(&self) -> Self {
        Self {
            shared: Rc::clone(&self.shared),
        }
    }
}

/// Runs `update` on the bucket of `key` in `map`, which starts empty when
/// there is none and is removed when left empty.
fn update_bucket<K: Eq + Hash, B: Default, R, S: BuildHasher>(
    map: &mut HashMap<K, B, S>,
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

impl<Target: ?Sized, Local, S> RouteIndex<Local> for HashMapRouteIndex<Target, Local, S>
where
    Local: Clone + Eq + Hash,
    S: BuildHasher + Default,
{
    type Target = Target;
    type Registration = HashMapRouteEntryRegistration<Target, Local, S>;
    type ClaimLock = RefCellDatagramClaimLock;

    fn new() -> Self {
        Self {
            shared: Rc::new(HashMapRouteIndexShared {
                nonzero: RefCell::new(HashMap::with_hasher(S::default())),
                zero: RefCell::new(HashMap::with_hasher(S::default())),
                registrations: Cell::new(0),
                empty_waiters: RefCell::new(SmallVec::new()),
            }),
        }
    }

    fn registration_count(&self) -> usize {
        self.shared.registrations.get()
    }

    fn poll_empty(&self, cx: &mut Context<'_>) -> Poll<()> {
        if self.shared.registrations.get() == 0 {
            return Poll::Ready(());
        }
        let mut waiters = self.shared.empty_waiters.borrow_mut();
        if !waiters.iter().any(|waiter| waiter.will_wake(cx.waker())) {
            waiters.push(cx.waker().clone());
        }
        Poll::Pending
    }

    fn count_published(&self) {
        self.shared
            .registrations
            .set(self.shared.registrations.get() + 1);
    }

    fn count_revoked(&self) {
        let left = self.shared.registrations.get() - 1;
        self.shared.registrations.set(left);
        if left == 0 {
            let waiters = core::mem::take(&mut *self.shared.empty_waiters.borrow_mut());
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
        self.shared.nonzero.borrow().get(cid).map(read)
    }

    fn update_nonzero<R>(
        &self,
        cid: &NonEmptyCid,
        update: impl FnOnce(&mut NonEmptyCidRouteBucket<Target, Local>) -> R,
    ) -> R {
        update_bucket(
            &mut self.shared.nonzero.borrow_mut(),
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
        self.shared.zero.borrow().get(local).map(read)
    }

    fn update_zero<R>(
        &self,
        local: &Local,
        update: impl FnOnce(&mut ZeroCidRouteBucket<Target, Local>) -> R,
    ) -> R {
        update_bucket(
            &mut self.shared.zero.borrow_mut(),
            local.clone(),
            ZeroCidRouteBucket::is_empty,
            update,
        )
    }

    fn hold(
        &self,
        entry: Arc<DatagramRouteEntry<Target, Local>>,
    ) -> HashMapRouteEntryRegistration<Target, Local, S> {
        HashMapRouteEntryRegistration {
            index: Rc::downgrade(&self.shared),
            entry,
        }
    }
}

#[cfg(test)]
impl<Target: ?Sized, Local, S> HashMapRouteIndex<Target, Local, S> {
    /// The number of non-empty connection ID keys and of local end keys.
    pub(crate) fn key_counts(&self) -> (usize, usize) {
        (
            self.shared.nonzero.borrow().len(),
            self.shared.zero.borrow().len(),
        )
    }
}

impl<Target: ?Sized, Local, S> ConnectionIdOccupancy for HashMapRouteIndex<Target, Local, S>
where
    Local: Clone + Eq + Hash,
    S: BuildHasher + Default,
{
    fn occupancy(&self, cid: &NonEmptyCid) -> usize {
        self.read_nonzero(cid, NonEmptyCidRouteBucket::len)
            .unwrap_or(0)
    }
}

impl<Target: ?Sized, Local, S> fmt::Debug for HashMapRouteIndex<Target, Local, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HashMapRouteIndex")
            .field("nonzero_keys", &self.shared.nonzero.borrow().len())
            .field("zero_keys", &self.shared.zero.borrow().len())
            .field("registrations", &self.shared.registrations.get())
            .finish()
    }
}

/// The registration of an entry of a [`HashMapRouteIndex`]: it finds the
/// index again through a weak reference, and revoking after the index is gone
/// does nothing.
#[must_use = "dropping the registration revokes the route entry"]
pub struct HashMapRouteEntryRegistration<Target: ?Sized, Local, S>
where
    Local: Clone + Eq + Hash,
    S: BuildHasher + Default,
{
    index: Weak<HashMapRouteIndexShared<Target, Local, S>>,
    entry: Arc<DatagramRouteEntry<Target, Local>>,
}

impl<Target: ?Sized, Local, S> HashMapRouteEntryRegistration<Target, Local, S>
where
    Local: Clone + Eq + Hash,
    S: BuildHasher + Default,
{
    /// The registered entry.
    pub fn entry(&self) -> &DatagramRouteEntry<Target, Local> {
        &self.entry
    }
}

impl<Target: ?Sized, Local, S> Drop for HashMapRouteEntryRegistration<Target, Local, S>
where
    Local: Clone + Eq + Hash,
    S: BuildHasher + Default,
{
    fn drop(&mut self) {
        if let Some(shared) = self.index.upgrade() {
            HashMapRouteIndex { shared }.revoke(&self.entry);
        }
    }
}

impl<Target: ?Sized, Local, S> fmt::Debug for HashMapRouteEntryRegistration<Target, Local, S>
where
    Local: Clone + Eq + Hash + fmt::Debug,
    S: BuildHasher + Default,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HashMapRouteEntryRegistration")
            .field("entry", &self.entry)
            .finish_non_exhaustive()
    }
}

/// The route entries and interpretations that already had a chance at one
/// datagram.
///
/// It travels with the datagram across reflow rounds, so that an entry that
/// exited is not offered the same datagram again under the same
/// interpretation, while new entries are. It identifies entries by their
/// identities, which are never reused and keep neither the entry nor its
/// deliverer alive.
pub(crate) struct OfferedRouteHistory {
    offered: SmallVec<[(UniqueId, FirstPacketInterpretation); 4]>,
}

impl OfferedRouteHistory {
    pub(crate) fn new() -> Self {
        Self {
            offered: SmallVec::new(),
        }
    }

    pub(crate) fn record<Target: ?Sized, Local>(
        &mut self,
        entry: &DatagramRouteEntry<Target, Local>,
        interpretation: FirstPacketInterpretation,
    ) {
        if !self.contains(entry, interpretation) {
            self.offered.push((entry.id.clone(), interpretation));
        }
    }

    pub(crate) fn contains<Target: ?Sized, Local>(
        &self,
        entry: &DatagramRouteEntry<Target, Local>,
        interpretation: FirstPacketInterpretation,
    ) -> bool {
        self.offered.iter().any(|(seen, seen_interpretation)| {
            *seen_interpretation == interpretation && *seen == entry.id
        })
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.offered.len()
    }
}

impl fmt::Debug for OfferedRouteHistory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OfferedRouteHistory")
            .field("offered", &self.offered.len())
            .finish()
    }
}
