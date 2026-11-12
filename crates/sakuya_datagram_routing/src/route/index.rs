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

use std::fmt;
use std::hash::Hash;
use std::sync::{Arc, Weak};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry as MapEntry;
use nitori_id::UniqueId;
use sakuya_wire::connection_id::NonEmptyCid;
use smallvec::SmallVec;

use super::acceptance::PreparedReceiver;
use super::association::{MatchAssociation, PacketForms, RouteMatcher};
use super::interpretation::{FirstPacketInterpretation, InitialKey, RecognizedInitial};
use super::recognizer::ConnectionIdOccupancy;

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
    fn new(matcher: RouteMatcher<Local>, deliverer: Arc<Target>) -> Arc<Self> {
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

/// The entries of one non-empty connection ID, both kinds side by side.
struct NonzeroBucket<Target: ?Sized, Local> {
    local: EntryList<Target, Local>,
    initial: EntryList<Target, Local>,
}

impl<Target: ?Sized, Local> NonzeroBucket<Target, Local> {
    fn new() -> Self {
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

    fn is_empty(&self) -> bool {
        self.local.is_empty() && self.initial.is_empty()
    }
}

/// The index of every route entry of one routing domain.
///
/// `Target` is the erased deliverer type of the domain, for example
/// `dyn ErasedDatagramDeliverer<Inner, Local, Handoff>` for a domain used on one
/// thread or `dyn SendDatagramDeliverer<Inner, Local, Handoff>` for one shared
/// between threads (see [`erased`](crate::claim::erased)); the index is `Send`
/// and `Sync` exactly when its entries are.
pub struct RouteIndex<Target: ?Sized, Local> {
    nonzero: DashMap<NonEmptyCid, NonzeroBucket<Target, Local>>,
    zero: DashMap<Local, EntryList<Target, Local>>,
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
pub(crate) enum Recheck<Target: ?Sized, Local: Clone + Eq + Hash, Receiver> {
    /// Entries that apply and had no chance at this datagram yet; the
    /// prepared receiver, if any, was not used.
    Offer {
        fresh: FrozenEntries<Target, Local>,
        unused: Option<PreparedReceiver<Target, Receiver>>,
    },
    /// The prepared deliverer was published; the registration belongs to the
    /// prepared receiver.
    Published {
        registration: RouteEntryRegistration<Target, Local>,
        receiver: Receiver,
    },
    /// Nothing applies and nothing was prepared.
    Release,
}

impl<Target: ?Sized, Local: Clone + Eq + Hash> RouteIndex<Target, Local> {
    /// Creates an empty index.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            nonzero: DashMap::new(),
            zero: DashMap::new(),
        })
    }

    /// Publishes a route entry for `deliverer`.
    ///
    /// The matcher and the deliverer are published together, as a new
    /// instance; registering the same deliverer or key again is legal and
    /// creates another instance. The returned registration revokes exactly
    /// this instance when dropped; the datagram receiver holds it. A new
    /// local connection ID must be disclosed only after this returns.
    pub fn register(
        self: &Arc<Self>,
        matcher: RouteMatcher<Local>,
        deliverer: Arc<Target>,
    ) -> RouteEntryRegistration<Target, Local> {
        let entry = DatagramRouteEntry::new(matcher, deliverer);
        self.insert(Arc::clone(&entry));
        RouteEntryRegistration {
            index: Arc::downgrade(self),
            entry,
        }
    }

    fn insert(&self, entry: Arc<DatagramRouteEntry<Target, Local>>) {
        match Location::of(entry.matcher.association()) {
            Location::Zero(local) => {
                self.zero.entry(local.clone()).or_default().push(entry);
            }
            Location::Nonzero(cid, kind) => {
                self.nonzero
                    .entry(*cid)
                    .or_insert_with(NonzeroBucket::new)
                    .list_mut(kind)
                    .push(entry);
            }
        }
    }

    /// Removes exactly `entry`, returning the index's reference so that the
    /// caller drops it outside the guard.
    fn remove(
        &self,
        entry: &Arc<DatagramRouteEntry<Target, Local>>,
    ) -> Option<Arc<DatagramRouteEntry<Target, Local>>> {
        fn take<Target: ?Sized, Local>(
            list: &mut EntryList<Target, Local>,
            entry: &Arc<DatagramRouteEntry<Target, Local>>,
        ) -> Option<Arc<DatagramRouteEntry<Target, Local>>> {
            let position = list
                .iter()
                .position(|current| Arc::ptr_eq(current, entry))?;
            Some(list.remove(position))
        }

        match Location::of(entry.matcher.association()) {
            Location::Zero(local) => match self.zero.entry(local.clone()) {
                MapEntry::Occupied(mut slot) => {
                    let removed = take(slot.get_mut(), entry);
                    if slot.get().is_empty() {
                        drop(slot.remove());
                    }
                    removed
                }
                MapEntry::Vacant(_) => None,
            },
            Location::Nonzero(cid, kind) => match self.nonzero.entry(*cid) {
                MapEntry::Occupied(mut slot) => {
                    let removed = take(slot.get_mut().list_mut(kind), entry);
                    if slot.get().is_empty() {
                        drop(slot.remove());
                    }
                    removed
                }
                MapEntry::Vacant(_) => None,
            },
        }
    }

    /// Appends to `frozen` every entry `lookup` finds that applies to
    /// `interpretation` and is not already there under the same
    /// interpretation.
    ///
    /// The lists of one lookup are read under one guard, so that a lookup of
    /// both associations of a connection ID sees one state of its bucket.
    pub(crate) fn collect(
        &self,
        lookup: &Lookup<Local>,
        interpretation: FirstPacketInterpretation,
        frozen: &mut FrozenEntries<Target, Local>,
    ) {
        let mut push = |association: MatchAssociation<Local>, list: &EntryList<Target, Local>| {
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
                if let Some(list) = self.zero.get(local) {
                    push(MatchAssociation::ZeroCid(local.clone()), &list);
                }
            }
            Lookup::Local(cid) => {
                if let Some(bucket) = self.nonzero.get(cid) {
                    push(MatchAssociation::LocalCid(*cid), &bucket.local);
                }
            }
            Lookup::LocalAndInitial(cid) => {
                if let Some(bucket) = self.nonzero.get(cid) {
                    push(MatchAssociation::LocalCid(*cid), &bucket.local);
                    push(MatchAssociation::InitialDcid(*cid), &bucket.initial);
                }
            }
        }
    }

    /// Rechecks the key of an unclaimed Initial within one entry access.
    ///
    /// Within the access it collects the entries that apply and have no
    /// record in `offered`, recording them there; when there are none it
    /// publishes the deliverer of `prepared`, if any, as a new Initial entry.
    /// Nothing else runs inside the access; an unused prepared receiver is
    /// returned for the caller to drop outside.
    pub(crate) fn recheck_initial<Receiver>(
        self: &Arc<Self>,
        initial: &RecognizedInitial<Local>,
        offered: &mut OfferedRouteHistory,
        prepared: Option<PreparedReceiver<Target, Receiver>>,
    ) -> Recheck<Target, Local, Receiver> {
        let interpretation = initial.interpretation();
        let matcher = RouteMatcher::new(
            initial.association(),
            PacketForms::INITIAL | PacketForms::ZERO_RTT,
            initial.version(),
        );
        let mut fresh = FrozenEntries::new();
        let mut gather = |association: MatchAssociation<Local>, list: &EntryList<Target, Local>| {
            for entry in list {
                if entry.matcher.applies(&interpretation)
                    && !offered.contains(entry, interpretation)
                {
                    fresh.push((Arc::clone(entry), association.clone(), interpretation));
                }
            }
        };
        let mut prepared = prepared;
        let mut publish = |list: &mut EntryList<Target, Local>| {
            let (deliverer, receiver) = prepared.take()?.into_parts();
            let entry = DatagramRouteEntry::new(matcher.clone(), deliverer);
            list.push(Arc::clone(&entry));
            Some((entry, receiver))
        };
        let published = match initial.key() {
            InitialKey::Dcid(cid) => match self.nonzero.entry(cid) {
                MapEntry::Occupied(mut slot) => {
                    gather(MatchAssociation::LocalCid(cid), &slot.get().local);
                    gather(MatchAssociation::InitialDcid(cid), &slot.get().initial);
                    if fresh.is_empty() {
                        publish(&mut slot.get_mut().initial)
                    } else {
                        None
                    }
                }
                MapEntry::Vacant(slot) => {
                    let mut bucket = NonzeroBucket::new();
                    let published = publish(&mut bucket.initial);
                    if published.is_some() {
                        slot.insert(bucket);
                    }
                    published
                }
            },
            InitialKey::Local(local) => match self.zero.entry(local.clone()) {
                MapEntry::Occupied(mut slot) => {
                    gather(MatchAssociation::ZeroCid(local), slot.get());
                    if fresh.is_empty() {
                        publish(slot.get_mut())
                    } else {
                        None
                    }
                }
                MapEntry::Vacant(slot) => {
                    let mut list = EntryList::new();
                    let published = publish(&mut list);
                    if published.is_some() {
                        slot.insert(list);
                    }
                    published
                }
            },
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
                registration: RouteEntryRegistration {
                    index: Arc::downgrade(self),
                    entry,
                },
                receiver,
            },
            None => Recheck::Release,
        }
    }
}

#[cfg(test)]
impl<Target: ?Sized, Local: Eq + Hash> RouteIndex<Target, Local> {
    /// The number of non-empty connection ID keys and of local end keys.
    pub(crate) fn key_counts(&self) -> (usize, usize) {
        (self.nonzero.len(), self.zero.len())
    }
}

impl<Target: ?Sized, Local: Eq + Hash> ConnectionIdOccupancy for RouteIndex<Target, Local> {
    fn occupancy(&self, cid: &NonEmptyCid) -> usize {
        self.nonzero
            .get(cid)
            .map_or(0, |bucket| bucket.local.len() + bucket.initial.len())
    }
}

impl<Target: ?Sized, Local: Eq + Hash> fmt::Debug for RouteIndex<Target, Local> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouteIndex")
            .field("nonzero_keys", &self.nonzero.len())
            .field("zero_keys", &self.zero.len())
            .finish()
    }
}

/// The handle that revokes one route entry.
///
/// The datagram receiver holds it and is responsible for revoking: dropping
/// the handle removes exactly its own entry, so that new lookups no longer
/// find it. It never removes another instance under the same key, and it does
/// not redirect lookups already taken: candidates and snapshots keep the
/// original deliverer, which stays callable. Revoking after the index is gone
/// does nothing.
#[must_use = "dropping the registration revokes the route entry"]
pub struct RouteEntryRegistration<Target: ?Sized, Local: Clone + Eq + Hash> {
    index: Weak<RouteIndex<Target, Local>>,
    entry: Arc<DatagramRouteEntry<Target, Local>>,
}

impl<Target: ?Sized, Local: Clone + Eq + Hash> RouteEntryRegistration<Target, Local> {
    /// The registered entry.
    pub fn entry(&self) -> &DatagramRouteEntry<Target, Local> {
        &self.entry
    }
}

impl<Target: ?Sized, Local: Clone + Eq + Hash> Drop for RouteEntryRegistration<Target, Local> {
    fn drop(&mut self) {
        if let Some(index) = self.index.upgrade() {
            // The removed reference outlives the guard and drops here.
            drop(index.remove(&self.entry));
        }
    }
}

impl<Target: ?Sized, Local: Clone + Eq + Hash + fmt::Debug> fmt::Debug
    for RouteEntryRegistration<Target, Local>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouteEntryRegistration")
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
