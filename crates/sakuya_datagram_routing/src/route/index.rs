//! The route index, its entries and their registrations
//!
//! Local connection ID and Initial destination connection ID associations of
//! the same non-empty connection ID share one bucket, and therefore one
//! synchronization boundary: inserting, revoking and the Initial recheck with
//! publication of either kind all pass through the same map entry, so a reader
//! can never combine an empty local list read before a hand-over with an empty
//! Initial list read after it. Zero-length associations are kept per link
//! binding.
//!
//! Every operation holds at most one map guard at a time and does only
//! controlled index work under it: no deliverer method, state factory,
//! `deliver`, reflow handoff or receiver construction runs there. Lookups copy
//! the entry references out of the guard; removed references are carried out
//! of the guard before they are dropped, so that no deliverer or state is
//! destroyed inside the index.

use std::fmt;
use std::sync::{Arc, Weak};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry as MapEntry;
use sakuya_link::BindingId;
use sakuya_wire::connection_id::NonEmptyCid;
use smallvec::SmallVec;

use super::{
    ConnectionIdOccupancy, FirstPacketInterpretation, MatchAssociation, PacketForms,
    RecognizedInitial, RouteMatcher,
};

/// One registration published as a whole: what it matches and the deliverer
/// bound to it.
///
/// Every registration is its own instance with its own identity, even when it
/// shares the deliverer, the association or the receiver with another one; a
/// new registration under the same key never reuses an old identity.
pub struct DatagramRouteEntry<Target: ?Sized> {
    matcher: RouteMatcher,
    deliverer: Arc<Target>,
}

impl<Target: ?Sized> DatagramRouteEntry<Target> {
    /// What the entry matches.
    pub fn matcher(&self) -> &RouteMatcher {
        &self.matcher
    }

    /// The deliverer bound to the entry.
    pub fn deliverer(&self) -> &Arc<Target> {
        &self.deliverer
    }
}

impl<Target: ?Sized> fmt::Debug for DatagramRouteEntry<Target> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramRouteEntry")
            .field("matcher", &self.matcher)
            .finish_non_exhaustive()
    }
}

type EntryList<Target> = SmallVec<[Arc<DatagramRouteEntry<Target>>; 2]>;

/// The entries of one non-empty connection ID, both kinds side by side.
struct NonzeroBucket<Target: ?Sized> {
    local: EntryList<Target>,
    initial: EntryList<Target>,
}

impl<Target: ?Sized> NonzeroBucket<Target> {
    fn new() -> Self {
        Self {
            local: SmallVec::new(),
            initial: SmallVec::new(),
        }
    }

    fn list(&mut self, association: &MatchAssociation) -> &mut EntryList<Target> {
        match association {
            MatchAssociation::LocalCid(_) => &mut self.local,
            MatchAssociation::InitialDcid(_) => &mut self.initial,
            MatchAssociation::ZeroCid(_) => unreachable!("zero-length entries have their own map"),
        }
    }

    fn is_empty(&self) -> bool {
        self.local.is_empty() && self.initial.is_empty()
    }
}

/// The index of every route entry of one routing domain.
///
/// `Target` is the erased deliverer type of the domain, for example
/// `dyn ErasedDatagramDeliverer<Inner>` for a domain used on one thread or
/// `dyn SendDatagramDeliverer<Inner>` for one shared between threads; the
/// index is `Send` and `Sync` exactly when its entries are.
pub struct RouteIndex<Target: ?Sized> {
    nonzero: DashMap<NonEmptyCid, NonzeroBucket<Target>>,
    zero: DashMap<BindingId, EntryList<Target>>,
}

/// The entries one lookup found, each with the association and
/// interpretation it was found under.
pub(crate) type FrozenEntries<Target> = SmallVec<
    [(
        Arc<DatagramRouteEntry<Target>>,
        MatchAssociation,
        FirstPacketInterpretation,
    ); 4],
>;

/// The outcome of the Initial recheck.
pub(crate) enum Recheck<Target: ?Sized> {
    /// Entries that apply and had no chance at this datagram yet.
    Offer(FrozenEntries<Target>),
    /// The prepared deliverer was published.
    Published(RouteEntryRegistration<Target>),
    /// Nothing applies and nothing was published.
    Release,
}

impl<Target: ?Sized> RouteIndex<Target> {
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
        matcher: RouteMatcher,
        deliverer: Arc<Target>,
    ) -> RouteEntryRegistration<Target> {
        let entry = Arc::new(DatagramRouteEntry { matcher, deliverer });
        self.insert(Arc::clone(&entry));
        RouteEntryRegistration {
            index: Arc::downgrade(self),
            entry,
        }
    }

    fn insert(&self, entry: Arc<DatagramRouteEntry<Target>>) {
        match entry.matcher.association() {
            MatchAssociation::ZeroCid(binding) => {
                self.zero.entry(binding.clone()).or_default().push(entry);
            }
            association
            @ (MatchAssociation::LocalCid(cid) | MatchAssociation::InitialDcid(cid)) => {
                self.nonzero
                    .entry(*cid)
                    .or_insert_with(NonzeroBucket::new)
                    .list(association)
                    .push(entry);
            }
        }
    }

    /// Removes exactly `entry`, returning the index's reference so that the
    /// caller drops it outside the guard.
    fn remove(
        &self,
        entry: &Arc<DatagramRouteEntry<Target>>,
    ) -> Option<Arc<DatagramRouteEntry<Target>>> {
        fn take<Target: ?Sized>(
            list: &mut EntryList<Target>,
            entry: &Arc<DatagramRouteEntry<Target>>,
        ) -> Option<Arc<DatagramRouteEntry<Target>>> {
            let position = list
                .iter()
                .position(|current| Arc::ptr_eq(current, entry))?;
            Some(list.remove(position))
        }

        match entry.matcher.association() {
            MatchAssociation::ZeroCid(binding) => match self.zero.entry(binding.clone()) {
                MapEntry::Occupied(mut slot) => {
                    let removed = take(slot.get_mut(), entry);
                    if slot.get().is_empty() {
                        drop(slot.remove());
                    }
                    removed
                }
                MapEntry::Vacant(_) => None,
            },
            association
            @ (MatchAssociation::LocalCid(cid) | MatchAssociation::InitialDcid(cid)) => {
                match self.nonzero.entry(*cid) {
                    MapEntry::Occupied(mut slot) => {
                        let removed = take(slot.get_mut().list(association), entry);
                        if slot.get().is_empty() {
                            drop(slot.remove());
                        }
                        removed
                    }
                    MapEntry::Vacant(_) => None,
                }
            }
        }
    }

    /// Appends to `frozen` every entry under `association` that applies to
    /// `interpretation` and is not already there under the same
    /// interpretation.
    pub(crate) fn collect(
        &self,
        association: &MatchAssociation,
        interpretation: FirstPacketInterpretation,
        frozen: &mut FrozenEntries<Target>,
    ) {
        let mut push = |list: &EntryList<Target>| {
            for entry in list {
                let seen = frozen.iter().any(|(existing, _, existing_interpretation)| {
                    Arc::ptr_eq(existing, entry) && *existing_interpretation == interpretation
                });
                if !seen && entry.matcher.applies(&interpretation) {
                    frozen.push((Arc::clone(entry), association.clone(), interpretation));
                }
            }
        };
        match association {
            MatchAssociation::ZeroCid(binding) => {
                if let Some(list) = self.zero.get(binding) {
                    push(&list);
                }
            }
            MatchAssociation::LocalCid(cid) => {
                if let Some(bucket) = self.nonzero.get(cid) {
                    push(&bucket.local);
                }
            }
            MatchAssociation::InitialDcid(cid) => {
                if let Some(bucket) = self.nonzero.get(cid) {
                    push(&bucket.initial);
                }
            }
        }
    }

    /// Rechecks the key of an unclaimed Initial within one entry access.
    ///
    /// Within the access it collects the entries that apply and have no
    /// record in `offered`, recording them there; when there are none it
    /// publishes the deliverer in `prepared`, if any, as a new Initial entry,
    /// taking it out of `prepared`. Nothing else runs inside the access; an
    /// unused deliverer stays in `prepared` for the caller to drop outside.
    pub(crate) fn recheck_initial(
        self: &Arc<Self>,
        initial: &RecognizedInitial,
        offered: &mut OfferedRouteHistory<Target>,
        prepared: &mut Option<Arc<Target>>,
    ) -> Recheck<Target> {
        let interpretation = initial.interpretation();
        let association = initial.association();
        let mut fresh = FrozenEntries::new();
        let mut gather = |association: MatchAssociation, list: &EntryList<Target>| {
            for entry in list {
                if entry.matcher.applies(&interpretation)
                    && !offered.contains(entry, interpretation)
                {
                    fresh.push((Arc::clone(entry), association.clone(), interpretation));
                }
            }
        };
        let matcher = || {
            RouteMatcher::new(
                association.clone(),
                PacketForms::INITIAL | PacketForms::ZERO_RTT,
                initial.version(),
            )
        };
        let published = match &association {
            MatchAssociation::InitialDcid(cid) => match self.nonzero.entry(*cid) {
                MapEntry::Occupied(mut slot) => {
                    let bucket = slot.get();
                    gather(MatchAssociation::LocalCid(*cid), &bucket.local);
                    gather(MatchAssociation::InitialDcid(*cid), &bucket.initial);
                    match prepared.take_if(|_| fresh.is_empty()) {
                        None => None,
                        Some(deliverer) => {
                            let entry = Arc::new(DatagramRouteEntry {
                                matcher: matcher(),
                                deliverer,
                            });
                            slot.get_mut().initial.push(Arc::clone(&entry));
                            Some(entry)
                        }
                    }
                }
                MapEntry::Vacant(slot) => prepared.take().map(|deliverer| {
                    let entry = Arc::new(DatagramRouteEntry {
                        matcher: matcher(),
                        deliverer,
                    });
                    let mut bucket = NonzeroBucket::new();
                    bucket.initial.push(Arc::clone(&entry));
                    slot.insert(bucket);
                    entry
                }),
            },
            MatchAssociation::ZeroCid(binding) => match self.zero.entry(binding.clone()) {
                MapEntry::Occupied(mut slot) => {
                    gather(association.clone(), slot.get());
                    match prepared.take_if(|_| fresh.is_empty()) {
                        None => None,
                        Some(deliverer) => {
                            let entry = Arc::new(DatagramRouteEntry {
                                matcher: matcher(),
                                deliverer,
                            });
                            slot.get_mut().push(Arc::clone(&entry));
                            Some(entry)
                        }
                    }
                }
                MapEntry::Vacant(slot) => prepared.take().map(|deliverer| {
                    let entry = Arc::new(DatagramRouteEntry {
                        matcher: matcher(),
                        deliverer,
                    });
                    let mut list = EntryList::new();
                    list.push(Arc::clone(&entry));
                    slot.insert(list);
                    entry
                }),
            },
            MatchAssociation::LocalCid(_) => {
                unreachable!("an Initial is published under its Initial association")
            }
        };
        if !fresh.is_empty() {
            for (entry, _, interpretation) in &fresh {
                offered.record(entry, *interpretation);
            }
            return Recheck::Offer(fresh);
        }
        match published {
            Some(entry) => Recheck::Published(RouteEntryRegistration {
                index: Arc::downgrade(self),
                entry,
            }),
            None => Recheck::Release,
        }
    }
}

#[cfg(test)]
impl<Target: ?Sized> RouteIndex<Target> {
    /// The number of non-empty connection ID keys and of link binding keys.
    pub(crate) fn key_counts(&self) -> (usize, usize) {
        (self.nonzero.len(), self.zero.len())
    }
}

impl<Target: ?Sized> ConnectionIdOccupancy for RouteIndex<Target> {
    fn occupancy(&self, cid: &NonEmptyCid) -> usize {
        self.nonzero
            .get(cid)
            .map_or(0, |bucket| bucket.local.len() + bucket.initial.len())
    }
}

impl<Target: ?Sized> fmt::Debug for RouteIndex<Target> {
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
pub struct RouteEntryRegistration<Target: ?Sized> {
    index: Weak<RouteIndex<Target>>,
    entry: Arc<DatagramRouteEntry<Target>>,
}

impl<Target: ?Sized> RouteEntryRegistration<Target> {
    /// The registered entry.
    pub fn entry(&self) -> &DatagramRouteEntry<Target> {
        &self.entry
    }
}

impl<Target: ?Sized> Drop for RouteEntryRegistration<Target> {
    fn drop(&mut self) {
        if let Some(index) = self.index.upgrade() {
            // The removed reference outlives the guard and drops here.
            drop(index.remove(&self.entry));
        }
    }
}

impl<Target: ?Sized> fmt::Debug for RouteEntryRegistration<Target> {
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
/// interpretation, while new entries are. It identifies entries by weak
/// references, which keep the identity from being reused without keeping the
/// entry or its deliverer alive.
pub(crate) struct OfferedRouteHistory<Target: ?Sized> {
    offered: SmallVec<[(Weak<DatagramRouteEntry<Target>>, FirstPacketInterpretation); 4]>,
}

impl<Target: ?Sized> OfferedRouteHistory<Target> {
    pub(crate) fn new() -> Self {
        Self {
            offered: SmallVec::new(),
        }
    }

    pub(crate) fn record(
        &mut self,
        entry: &Arc<DatagramRouteEntry<Target>>,
        interpretation: FirstPacketInterpretation,
    ) {
        if !self.contains(entry, interpretation) {
            self.offered.push((Arc::downgrade(entry), interpretation));
        }
    }

    pub(crate) fn contains(
        &self,
        entry: &Arc<DatagramRouteEntry<Target>>,
        interpretation: FirstPacketInterpretation,
    ) -> bool {
        self.offered.iter().any(|(seen, seen_interpretation)| {
            *seen_interpretation == interpretation
                && std::ptr::eq(seen.as_ptr(), Arc::as_ptr(entry))
        })
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.offered.len()
    }
}

impl<Target: ?Sized> fmt::Debug for OfferedRouteHistory<Target> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OfferedRouteHistory")
            .field("offered", &self.offered.len())
            .finish()
    }
}
