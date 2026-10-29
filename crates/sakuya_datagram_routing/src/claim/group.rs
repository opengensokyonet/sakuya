//! Preparing and dispatching the candidate set of one datagram
//!
//! Routing completes every lookup that needs the datagram while it still owns
//! it, freezes the matched entries, and then calls [`prepare_claim`] with the
//! datagram, its finish policy and the frozen entries. Preparation builds only
//! light objects: the shared core and one participation credential per entry,
//! never private state, and it calls no author code. Routing then releases its
//! table locks and calls [`PreparedClaim::dispatch`], which commits the set and
//! delivers each candidate to its deliverer in order.
//!
//! | Frozen entries | Last takes | On unclaimed |
//! | --- | --- | --- |
//! | none | the datagram is released at dispatch | the datagram is handed off at dispatch |
//! | one | an exclusive delivery with uninitialized state | one competing candidate |
//! | several | competing candidates | competing candidates |
//!
//! Dropping a prepared set without dispatching it, for example while
//! unwinding, delivers nothing, calls no author code and never hands off: the
//! datagram and the prepared credentials are simply released.

use std::iter;
use std::sync::Arc;

use smallvec::SmallVec;

use super::deliverer::ExclusiveDatagram;
use super::erased::ErasedDatagramDeliverer;
use super::finish::UnclaimedHandoff;
use super::route_match::DatagramRouteMatchInfo;
use super::shared::{ClaimCore, DatagramFinishPolicy, Participation};

/// The complete candidate set of one datagram, ready to be dispatched.
#[must_use = "a prepared claim delivers nothing until dispatched"]
pub(crate) struct PreparedClaim<Inner, Handoff: UnclaimedHandoff<Inner>, Target: ?Sized> {
    prepared: Prepared<Inner, Handoff, Target>,
}

/// Each candidate's deliverer, credential and match information.
type Candidates<Inner, Handoff, Target> = SmallVec<
    [(
        Arc<Target>,
        Participation<Inner, Handoff>,
        DatagramRouteMatchInfo,
    ); 4],
>;

enum Prepared<Inner, Handoff: UnclaimedHandoff<Inner>, Target: ?Sized> {
    Release(Inner),
    Unclaimed {
        datagram: Inner,
        handoff: Handoff,
    },
    Exclusive {
        target: Arc<Target>,
        datagram: ExclusiveDatagram<Inner>,
        route: DatagramRouteMatchInfo,
    },
    Competing {
        core: Arc<ClaimCore<Inner, Handoff>>,
        candidates: Candidates<Inner, Handoff, Target>,
    },
}

/// Builds the candidate set for one datagram and its frozen route entries.
///
/// Each entry pairs the deliverer bound to a route entry with the match
/// information routing recorded for it. The same deliverer may appear more than
/// once, for example under two interpretations; each appearance is its own
/// candidate. No author code runs here, so routing may call this while it still
/// holds its table locks; it must release them before
/// [`dispatch`](PreparedClaim::dispatch).
pub(crate) fn prepare_claim<Inner, Handoff, Target, Entries>(
    datagram: Inner,
    finish: DatagramFinishPolicy<Handoff>,
    entries: Entries,
) -> PreparedClaim<Inner, Handoff, Target>
where
    Handoff: UnclaimedHandoff<Inner>,
    Target: ?Sized + ErasedDatagramDeliverer<Inner, Handoff>,
    Entries: IntoIterator<Item = (Arc<Target>, DatagramRouteMatchInfo)>,
{
    let mut entries = entries.into_iter();
    let prepared = match (finish, entries.next()) {
        (DatagramFinishPolicy::LastTakes, None) => Prepared::Release(datagram),
        (DatagramFinishPolicy::OnUnclaimed(handoff), None) => {
            Prepared::Unclaimed { datagram, handoff }
        }
        (finish, Some(first)) => match (finish, entries.next()) {
            (DatagramFinishPolicy::LastTakes, None) => {
                let (target, route) = first;
                Prepared::Exclusive {
                    target,
                    datagram: ExclusiveDatagram::new(datagram),
                    route,
                }
            }
            (finish, second) => {
                let core = ClaimCore::new(datagram, finish);
                let candidates = iter::once(first)
                    .chain(second)
                    .chain(entries)
                    .map(|(target, route)| (target, Participation::join(&core), route))
                    .collect();
                Prepared::Competing { core, candidates }
            }
        },
    };
    PreparedClaim { prepared }
}

impl<Inner, Handoff, Target> PreparedClaim<Inner, Handoff, Target>
where
    Handoff: UnclaimedHandoff<Inner>,
    Target: ?Sized + ErasedDatagramDeliverer<Inner, Handoff>,
{
    /// Commits the set and delivers every candidate to its deliverer, in
    /// order.
    ///
    /// The preparer's reference to the shared core is released before the
    /// first delivery, so that only participation credentials keep it alive.
    /// A deliverer may consume its delivery on the spot, so author code runs
    /// on this call stack. If a delivery panics, the candidates not yet
    /// delivered exit while unwinding.
    pub(crate) fn dispatch(self) {
        match self.prepared {
            Prepared::Release(datagram) => drop(datagram),
            Prepared::Unclaimed { datagram, handoff } => handoff.hand_off(datagram),
            Prepared::Exclusive {
                target,
                datagram,
                route,
            } => target.deliver_exclusive(datagram, route),
            Prepared::Competing { core, candidates } => {
                core.commit();
                drop(core);
                for (target, participation, route) in candidates {
                    target.deliver_competing(participation, route);
                }
            }
        }
    }
}
