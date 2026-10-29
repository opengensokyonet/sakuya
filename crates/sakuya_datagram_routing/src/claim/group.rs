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
//! | none | the datagram is released at dispatch | the work is handed off at dispatch |
//! | one | an exclusive delivery with uninitialized state | one competing candidate |
//! | several | competing candidates | competing candidates |
//!
//! Dropping a prepared set without dispatching it, for example while
//! unwinding, delivers nothing, calls no author code and never hands off: the
//! datagram and the prepared credentials are simply released.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "used only by datagram routing in this crate")
)]

use std::sync::Arc;

use super::shared::{
    ClaimCore, DatagramFinishPolicy, OfferedRouteHistory, Participation, ReflowContinuation,
    UnclaimedHandoff, hand_off_unclaimed,
};
use super::{DatagramRouteMatchInfo, ErasedDatagramDeliverer, ExclusiveDatagram};

/// The complete candidate set of one datagram, ready to be dispatched.
#[must_use = "a prepared claim delivers nothing until dispatched"]
pub(crate) struct PreparedClaim<Inner, Target: ?Sized> {
    prepared: Prepared<Inner, Target>,
}

enum Prepared<Inner, Target: ?Sized> {
    Release(Inner),
    Unclaimed {
        datagram: Inner,
        handoff: UnclaimedHandoff<Inner>,
        offered: OfferedRouteHistory,
        continuation: ReflowContinuation,
    },
    Exclusive {
        target: Arc<Target>,
        datagram: ExclusiveDatagram<Inner>,
        route: DatagramRouteMatchInfo,
    },
    Competing {
        core: Arc<ClaimCore<Inner>>,
        candidates: Vec<(Arc<Target>, Participation<Inner>, DatagramRouteMatchInfo)>,
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
pub(crate) fn prepare_claim<Inner, Target>(
    datagram: Inner,
    finish: DatagramFinishPolicy<Inner>,
    entries: Vec<(Arc<Target>, DatagramRouteMatchInfo)>,
) -> PreparedClaim<Inner, Target>
where
    Target: ?Sized + ErasedDatagramDeliverer<Inner>,
{
    let prepared = match (finish, entries.len()) {
        (DatagramFinishPolicy::LastTakes, 0) => Prepared::Release(datagram),
        (
            DatagramFinishPolicy::OnUnclaimed {
                handoff,
                offered,
                continuation,
            },
            0,
        ) => Prepared::Unclaimed {
            datagram,
            handoff,
            offered,
            continuation,
        },
        (DatagramFinishPolicy::LastTakes, 1) => {
            let (target, route) = entries
                .into_iter()
                .next()
                .expect("the entry count was checked");
            Prepared::Exclusive {
                target,
                datagram: ExclusiveDatagram::new(datagram),
                route,
            }
        }
        (finish, _) => {
            let core = ClaimCore::new(datagram, finish);
            let candidates = entries
                .into_iter()
                .map(|(target, route)| (target, Participation::join(&core), route))
                .collect();
            Prepared::Competing { core, candidates }
        }
    };
    PreparedClaim { prepared }
}

impl<Inner, Target> PreparedClaim<Inner, Target>
where
    Target: ?Sized + ErasedDatagramDeliverer<Inner>,
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
            Prepared::Unclaimed {
                datagram,
                handoff,
                offered,
                continuation,
            } => hand_off_unclaimed(datagram, handoff, offered, continuation),
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
