//! The entries an unclaimed Initial has not been offered to yet.

use alloc::sync::Arc;

use super::{EntryList, FrozenEntries, OfferedRouteHistory, RouteIndex};
use crate::route::association::MatchAssociation;
use crate::route::interpretation::{FirstPacketInterpretation, InitialKey, RecognizedInitial};

/// Appends to `fresh` the entries of `list` that apply to `interpretation`
/// and have no record in `offered`.
pub(super) fn gather_fresh<Target: ?Sized, Local: Clone>(
    fresh: &mut FrozenEntries<Target, Local>,
    association: MatchAssociation<Local>,
    list: &EntryList<Target, Local>,
    interpretation: FirstPacketInterpretation,
    offered: &OfferedRouteHistory,
) {
    for entry in list {
        if entry.matcher.applies(&interpretation) && !offered.contains(entry, interpretation) {
            fresh.push((Arc::clone(entry), association.clone(), interpretation));
        }
    }
}

/// The entries under the key of an unclaimed Initial that apply and have no
/// record in `offered`, read within one entry access of `index`; they are
/// recorded in `offered`. Nothing is prepared or published.
pub(crate) fn fresh_initial_entries<Local: Clone, Index: RouteIndex<Local>>(
    index: &Index,
    initial: &RecognizedInitial<Local>,
    offered: &mut OfferedRouteHistory,
) -> FrozenEntries<Index::Target, Local> {
    let interpretation = initial.interpretation();
    let mut fresh = FrozenEntries::new();
    match initial.key() {
        InitialKey::Dcid(cid) => index.read_nonzero(&cid, |bucket| {
            gather_fresh(
                &mut fresh,
                MatchAssociation::LocalCid(cid),
                &bucket.local,
                interpretation,
                offered,
            );
            gather_fresh(
                &mut fresh,
                MatchAssociation::InitialDcid(cid),
                &bucket.initial,
                interpretation,
                offered,
            );
        }),
        InitialKey::Local(local) => index.read_zero(&local, |bucket| {
            gather_fresh(
                &mut fresh,
                MatchAssociation::ZeroCid(local.clone()),
                &bucket.entries,
                interpretation,
                offered,
            );
        }),
    };
    for (entry, _, interpretation) in &fresh {
        offered.record(entry, *interpretation);
    }
    fresh
}
