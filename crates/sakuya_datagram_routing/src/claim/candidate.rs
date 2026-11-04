//! Claim candidates and their attempts

use std::fmt;
use std::future::Future;
use std::mem;

use super::deliverer::{DatagramClaimAccess, DatagramClaimOutcome, ExclusiveDatagram};
use super::delivery::ExclusiveDatagramDelivery;
use super::finish::UnclaimedHandoff;
use super::route_match::DatagramRouteMatchInfo;
use super::shared::{ClaimCore, DatagramSlot, Participation};

/// One route entry's chance at one datagram.
///
/// A candidate binds the shared core of one datagram to the route match
/// information routing recorded for one entry. It refers to no deliverer and
/// keeps no judgment state: whoever holds it passes a judgment to each
/// attempt. The mechanism builds every candidate of a datagram before
/// delivering any of them; nothing else can create one, and it cannot be
/// cloned.
///
/// Holding a candidate keeps its participation and keeps the datagram alive;
/// holding it indefinitely keeps the datagram indefinitely, so the holder
/// decides how long to wait. Dropping it exits: no deliverer is called,
/// nothing is rerouted and no packet is produced.
pub struct DatagramClaimCandidate<Inner, Handoff: UnclaimedHandoff<Inner>> {
    participation: Participation<Inner, Handoff>,
    route: DatagramRouteMatchInfo,
}

/// The future of one attempt, returned by
/// [`DatagramClaimCandidate::try_exclusive`].
///
/// It owns the candidate and the judgment. It does nothing until first
/// polled, and it is `Send` exactly when the candidate and the judgment are.
/// Keep the same pinned future to pause an attempt; dropping it exits the
/// candidate. After it completes or panics it must not be polled again.
pub type DatagramClaimFuture<Inner, Handoff: UnclaimedHandoff<Inner>, T, U, F>
where
    F: for<'access> FnOnce(
        DatagramClaimAccess<'access, Inner>,
        &DatagramRouteMatchInfo,
    ) -> DatagramClaimOutcome<'access, T, U, Inner>,
= impl Future<Output = DatagramClaimAttempt<T, U, Inner, Handoff>>;

/// The result of one attempt by the mechanism.
///
/// Every variant ends the attempt. [`Claimed`](Self::Claimed) always comes
/// from a judgment that claimed; taking the datagram without a judgment is
/// [`Exclusive`](Self::Exclusive), in line with
/// [`DatagramDelivery::Exclusive`](super::delivery::DatagramDelivery::Exclusive).
#[must_use]
pub enum DatagramClaimAttempt<T, U, Inner, Handoff: UnclaimedHandoff<Inner>> {
    /// The judgment took the datagram; the delivery carries it with the route
    /// match information, next to the judgment's value. It proves sole
    /// ownership, not authentication.
    Claimed(ExclusiveDatagramDelivery<Inner>, T),
    /// The judgment left the datagram; the mechanism released the access and
    /// the same candidate comes back. Retrying is the holder's decision; the
    /// mechanism never retries by itself.
    Unclaimed(DatagramClaimCandidate<Inner, Handoff>),
    /// The judgment gave up; this candidate's participation has ended and the
    /// judgment's value comes back.
    Abandoned(U),
    /// This candidate was the only participant left under the last-takes
    /// policy and took the datagram without a judgment. It does not promise
    /// authentication.
    Exclusive(ExclusiveDatagramDelivery<Inner>),
    /// Another candidate already took the datagram; no judgment ran and this
    /// candidate's participation has ended. This says nothing about
    /// authentication, processing or protocol errors.
    ClaimedElsewhere,
}

/// The result of an immediate attempt, returned by
/// [`DatagramClaimCandidate::try_exclusive_now`].
#[must_use]
pub enum DatagramClaimPrecheck<T, U, Inner, Handoff: UnclaimedHandoff<Inner>, F> {
    /// The access was immediately available and the attempt ran in full.
    Completed(DatagramClaimAttempt<T, U, Inner, Handoff>),
    /// The access was busy; the candidate and the judgment come back
    /// untouched, without a judgment call and without a registered wait.
    Deferred(DatagramClaimCandidate<Inner, Handoff>, F),
}

/// What the synchronous section decided, before the access is released.
enum Judgement<T, U, Inner> {
    Claimed(ExclusiveDatagram<Inner>, T),
    Unclaimed,
    Abandoned(U),
    Exclusive(ExclusiveDatagram<Inner>),
    ClaimedElsewhere,
}

impl<Inner, Handoff: UnclaimedHandoff<Inner>> DatagramClaimCandidate<Inner, Handoff> {
    pub(super) fn new(
        participation: Participation<Inner, Handoff>,
        route: DatagramRouteMatchInfo,
    ) -> Self {
        Self {
            participation,
            route,
        }
    }

    /// What routing recorded about this candidate's match.
    pub fn route_match(&self) -> &DatagramRouteMatchInfo {
        &self.route
    }

    #[cfg(test)]
    pub(super) fn core(&self) -> &ClaimCore<Inner, Handoff> {
        self.participation.core()
    }

    /// An extra strong reference to the core, which the mechanism itself
    /// never creates; tests use it to observe the core from a drop.
    #[cfg(test)]
    pub(super) fn core_handle(&self) -> std::sync::Arc<ClaimCore<Inner, Handoff>> {
        self.participation.core_handle()
    }

    /// Attempts to take the datagram with `try_claim`, waiting for the shared
    /// access.
    ///
    /// The candidate and the judgment move into the returned future, which
    /// does nothing until first polled. Polling waits for the shared access
    /// only; it never waits for keys, configuration or other business
    /// conditions. Once the access is obtained, one synchronous section
    /// decides the result as described in the [module
    /// documentation](super#one-attempt), and the access is released before
    /// the future completes.
    ///
    /// The judgment is synchronous and may capture anything, including
    /// handles to its caller's state. It receives the access and this
    /// candidate's route match information, and must not wait for or re-enter
    /// the shared access of the same datagram, for example by attempting
    /// another candidate of it.
    ///
    /// Dropping the future before its first poll exits the candidate without
    /// a judgment. Dropping it while it waits withdraws the wait first, so
    /// that the next waiter can proceed, and then exits the candidate.
    /// Cancellation does not interrupt a judgment that is already running, and
    /// it does not undo side effects of earlier unclaimed attempts. Woken
    /// futures that are neither polled nor dropped delay the other waiters.
    ///
    /// If the judgment panics, the panic propagates out of `poll`, the access
    /// is released, and the candidate is dropped while unwinding; the future
    /// must not be polled again.
    #[define_opaque(DatagramClaimFuture)]
    pub fn try_exclusive<T, U, F>(
        self,
        try_claim: F,
    ) -> DatagramClaimFuture<Inner, Handoff, T, U, F>
    where
        F: for<'access> FnOnce(
            DatagramClaimAccess<'access, Inner>,
            &DatagramRouteMatchInfo,
        ) -> DatagramClaimOutcome<'access, T, U, Inner>,
    {
        async move {
            let candidate = self;
            let judgement = {
                let mut slot = candidate.participation.core().input.lock().await;
                let judgement = judge(
                    &mut slot,
                    candidate.participation.core(),
                    &candidate.route,
                    try_claim,
                );
                drop(slot);
                judgement
            };
            candidate.conclude(judgement)
        }
    }

    /// Attempts to take the datagram with `try_claim` only if the shared
    /// access is free right now.
    ///
    /// When the access is immediately available, this runs the same
    /// synchronous section as [`try_exclusive`](Self::try_exclusive) and
    /// returns [`DatagramClaimPrecheck::Completed`]. Otherwise it returns the
    /// candidate and the judgment unchanged in
    /// [`DatagramClaimPrecheck::Deferred`] without calling the judgment or
    /// registering a wait. An uncontended access is not free of work: the
    /// judgment still runs on the calling thread.
    pub fn try_exclusive_now<T, U, F>(
        self,
        try_claim: F,
    ) -> DatagramClaimPrecheck<T, U, Inner, Handoff, F>
    where
        F: for<'access> FnOnce(
            DatagramClaimAccess<'access, Inner>,
            &DatagramRouteMatchInfo,
        ) -> DatagramClaimOutcome<'access, T, U, Inner>,
    {
        let judgement = {
            let Ok(mut slot) = self.participation.core().input.try_lock() else {
                return DatagramClaimPrecheck::Deferred(self, try_claim);
            };
            let judgement = judge(&mut slot, self.participation.core(), &self.route, try_claim);
            drop(slot);
            judgement
        };
        DatagramClaimPrecheck::Completed(self.conclude(judgement))
    }

    fn conclude<T, U>(
        self,
        judgement: Judgement<T, U, Inner>,
    ) -> DatagramClaimAttempt<T, U, Inner, Handoff> {
        match judgement {
            Judgement::Claimed(datagram, value) => {
                DatagramClaimAttempt::Claimed(self.into_delivery(datagram), value)
            }
            Judgement::Unclaimed => DatagramClaimAttempt::Unclaimed(self),
            Judgement::Abandoned(value) => {
                drop(self);
                DatagramClaimAttempt::Abandoned(value)
            }
            Judgement::Exclusive(datagram) => {
                DatagramClaimAttempt::Exclusive(self.into_delivery(datagram))
            }
            Judgement::ClaimedElsewhere => {
                drop(self);
                DatagramClaimAttempt::ClaimedElsewhere
            }
        }
    }

    /// Ends the participation and hands the taken datagram over.
    fn into_delivery(self, datagram: ExclusiveDatagram<Inner>) -> ExclusiveDatagramDelivery<Inner> {
        let Self {
            participation,
            route,
        } = self;
        drop(participation);
        ExclusiveDatagramDelivery::new(datagram, route)
    }
}

/// The synchronous section of an attempt, run while holding the access.
fn judge<T, U, Inner, Handoff, F>(
    slot: &mut DatagramSlot<Inner>,
    core: &ClaimCore<Inner, Handoff>,
    route: &DatagramRouteMatchInfo,
    try_claim: F,
) -> Judgement<T, U, Inner>
where
    Handoff: UnclaimedHandoff<Inner>,
    F: for<'access> FnOnce(
        DatagramClaimAccess<'access, Inner>,
        &DatagramRouteMatchInfo,
    ) -> DatagramClaimOutcome<'access, T, U, Inner>,
{
    if core.sole_participant_takes() {
        let DatagramSlot::Present(datagram) = mem::replace(slot, DatagramSlot::Taken) else {
            return Judgement::ClaimedElsewhere;
        };
        return Judgement::Exclusive(ExclusiveDatagram::new(datagram));
    }
    if matches!(slot, DatagramSlot::Taken) {
        return Judgement::ClaimedElsewhere;
    }
    match try_claim(DatagramClaimAccess::new(slot), route) {
        // The claimed datagram can only come from this access, which emptied
        // the slot.
        DatagramClaimOutcome::Claimed(claimed, value) => {
            Judgement::Claimed(claimed.into_datagram(), value)
        }
        // The returned access ends with this arm, before the guard is
        // released.
        DatagramClaimOutcome::Unclaimed(_access) => Judgement::Unclaimed,
        DatagramClaimOutcome::Abandoned(value) => Judgement::Abandoned(value),
    }
}

impl<Inner, Handoff: UnclaimedHandoff<Inner>> fmt::Debug
    for DatagramClaimCandidate<Inner, Handoff>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramClaimCandidate")
            .field("route", &self.route)
            .finish_non_exhaustive()
    }
}

impl<T: fmt::Debug, U: fmt::Debug, Inner, Handoff: UnclaimedHandoff<Inner>> fmt::Debug
    for DatagramClaimAttempt<T, U, Inner, Handoff>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Claimed(delivery, value) => f
                .debug_tuple("Claimed")
                .field(delivery)
                .field(value)
                .finish(),
            Self::Unclaimed(candidate) => f.debug_tuple("Unclaimed").field(candidate).finish(),
            Self::Abandoned(value) => f.debug_tuple("Abandoned").field(value).finish(),
            Self::Exclusive(delivery) => f.debug_tuple("Exclusive").field(delivery).finish(),
            Self::ClaimedElsewhere => f.write_str("ClaimedElsewhere"),
        }
    }
}

impl<T: fmt::Debug, U: fmt::Debug, Inner, Handoff: UnclaimedHandoff<Inner>, F> fmt::Debug
    for DatagramClaimPrecheck<T, U, Inner, Handoff, F>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Completed(attempt) => f.debug_tuple("Completed").field(attempt).finish(),
            Self::Deferred(candidate, _) => f
                .debug_tuple("Deferred")
                .field(candidate)
                .finish_non_exhaustive(),
        }
    }
}
