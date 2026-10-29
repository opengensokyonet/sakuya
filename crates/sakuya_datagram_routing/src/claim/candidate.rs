//! Claim candidates and their attempts

use std::fmt;
use std::future::Future;
use std::mem;
use std::sync::Arc;

use super::deliverer::{
    DatagramClaimAccess, DatagramClaimOutcome, DatagramDeliverer, DatagramView, ExclusiveDatagram,
};
use super::delivery::{ExclusiveDatagramDelivery, PrivateState};
use super::route_match::DatagramRouteMatchInfo;
use super::shared::{ClaimCore, DatagramSlot, Participation};

/// One deliverer's chance at one datagram.
///
/// A candidate binds the shared core of one datagram to one deliverer, the
/// route match information routing recorded for it, and the deliverer's private
/// state, which stays uninitialized until the first access that finds the
/// datagram present. The mechanism builds every candidate of a datagram before
/// delivering any of them; nothing else can create one, and it cannot be
/// cloned.
///
/// Holding a candidate keeps its participation and keeps the datagram alive;
/// holding it indefinitely keeps the datagram indefinitely, so the holder
/// decides how long to wait. Dropping it exits: no other deliverer is called,
/// nothing is rerouted and no packet is produced. Exiting releases the
/// participation credential first and then the private state and the
/// reference to the deliverer.
pub struct DatagramClaimCandidate<Inner, Deliverer: DatagramDeliverer<Inner>> {
    // Field order is drop order: the credential is released before the
    // private state and the deliverer reference.
    participation: Participation<Inner, Deliverer::Handoff>,
    route: DatagramRouteMatchInfo,
    state: PrivateState<Deliverer::DelivererDatagramState>,
    deliverer: Arc<Deliverer>,
}

/// The future of one attempt, returned by
/// [`DatagramClaimCandidate::try_exclusive`].
///
/// It owns the candidate. It does nothing until first polled, and it is `Send`
/// exactly when the candidate is. Keep the same pinned future to pause an
/// attempt; dropping it exits the candidate. After it completes or panics it
/// must not be polled again.
pub type DatagramClaimFuture<Inner: AsRef<[u8]>, Deliverer: DatagramDeliverer<Inner>> =
    impl Future<Output = DatagramClaimAttempt<Inner, Deliverer>>;

/// The result of one attempt by the mechanism.
///
/// Every variant ends the attempt. Unlike the author's
/// [`DatagramClaimOutcome`], a claimed attempt does not imply that
/// [`DatagramDeliverer::try_claim`] ran: a sole last-takes participant takes
/// the datagram directly.
#[must_use]
pub enum DatagramClaimAttempt<Inner, Deliverer: DatagramDeliverer<Inner>> {
    /// This candidate took the datagram; the delivery carries it with the
    /// deliverer, the route match information and the current private state.
    /// It proves sole ownership, not authentication.
    Claimed(ExclusiveDatagramDelivery<Inner, Deliverer>),
    /// The deliverer judged and left the datagram; the same candidate comes
    /// back with its updated state. Retrying is the holder's decision; the
    /// mechanism never retries by itself.
    Unclaimed(DatagramClaimCandidate<Inner, Deliverer>),
    /// Another candidate already took the datagram; this candidate's
    /// participation has ended. This says nothing about authentication,
    /// processing or protocol errors.
    ClaimedElsewhere,
}

/// The result of an immediate attempt, returned by
/// [`DatagramClaimCandidate::try_exclusive_now`].
#[must_use]
pub enum DatagramClaimPrecheck<Inner, Deliverer: DatagramDeliverer<Inner>> {
    /// The access was immediately available and the attempt ran in full.
    Completed(DatagramClaimAttempt<Inner, Deliverer>),
    /// The access was busy; the candidate comes back untouched, without any
    /// author call or state change, and without a registered wait.
    Deferred(DatagramClaimCandidate<Inner, Deliverer>),
}

/// What the synchronous section decided, before the access is released.
enum Judgement<Inner> {
    Claimed(ExclusiveDatagram<Inner>),
    Unclaimed,
    ClaimedElsewhere,
}

impl<Inner, Deliverer: DatagramDeliverer<Inner>> DatagramClaimCandidate<Inner, Deliverer> {
    pub(super) fn new(
        participation: Participation<Inner, Deliverer::Handoff>,
        route: DatagramRouteMatchInfo,
        deliverer: Arc<Deliverer>,
    ) -> Self {
        Self {
            participation,
            route,
            state: PrivateState::Uninitialized,
            deliverer,
        }
    }

    /// Returns the private state if it was already initialized.
    ///
    /// This only borrows: it neither calls the factory nor touches the shared
    /// access. It returns `None` before the first access that found the
    /// datagram present; a candidate returned by an unclaimed attempt always
    /// has its state. Use it between attempts to read what the deliverer
    /// recorded about its last judgment. It does not tell whether the datagram
    /// is still present.
    pub fn initialized_state(&self) -> Option<&Deliverer::DelivererDatagramState> {
        self.state.initialized()
    }

    /// What routing recorded about this candidate's match.
    pub fn route_match(&self) -> &DatagramRouteMatchInfo {
        &self.route
    }

    #[cfg(test)]
    pub(super) fn core(&self) -> &ClaimCore<Inner, Deliverer::Handoff> {
        self.participation.core()
    }

    /// An extra strong reference to the core, which the mechanism itself
    /// never creates; tests use it to observe the core from a drop.
    #[cfg(test)]
    pub(super) fn core_handle(&self) -> Arc<ClaimCore<Inner, Deliverer::Handoff>> {
        self.participation.core_handle()
    }

    fn conclude(self, judgement: Judgement<Inner>) -> DatagramClaimAttempt<Inner, Deliverer> {
        match judgement {
            Judgement::Unclaimed => DatagramClaimAttempt::Unclaimed(self),
            Judgement::Claimed(datagram) => {
                let Self {
                    participation,
                    route,
                    state,
                    deliverer,
                } = self;
                drop(participation);
                DatagramClaimAttempt::Claimed(ExclusiveDatagramDelivery::new(
                    datagram, route, state, deliverer,
                ))
            }
            Judgement::ClaimedElsewhere => {
                drop(self);
                DatagramClaimAttempt::ClaimedElsewhere
            }
        }
    }
}

impl<Inner: AsRef<[u8]>, Deliverer: DatagramDeliverer<Inner>>
    DatagramClaimCandidate<Inner, Deliverer>
{
    /// Attempts to take the datagram, waiting for the shared access.
    ///
    /// The candidate moves into the returned future, which does nothing until
    /// first polled. Polling waits for the shared access only; it never waits
    /// for keys, configuration or other business conditions. Once the access is
    /// obtained, one synchronous section decides the result as described in the
    /// [module documentation](super#one-attempt), and the access is released
    /// before the future completes.
    ///
    /// Dropping the future before its first poll exits the candidate without
    /// any author call. Dropping it while it waits withdraws the wait first, so
    /// that the next waiter can proceed, and then exits the candidate.
    /// Cancellation does not interrupt a judgment that is already running, and
    /// it does not undo side effects of earlier unclaimed attempts. Woken
    /// futures that are neither polled nor dropped delay the other waiters.
    ///
    /// If the factory or [`try_claim`](DatagramDeliverer::try_claim) panics,
    /// the panic propagates out of `poll`, the access is released, and the
    /// candidate is dropped while unwinding; the future must not be polled
    /// again.
    #[define_opaque(DatagramClaimFuture)]
    pub fn try_exclusive(self) -> DatagramClaimFuture<Inner, Deliverer> {
        async move {
            let mut candidate = self;
            let judgement = {
                let mut slot = candidate.participation.core().input.lock().await;
                let judgement = judge(
                    &mut slot,
                    candidate.participation.core(),
                    &*candidate.deliverer,
                    &candidate.route,
                    &mut candidate.state,
                );
                drop(slot);
                judgement
            };
            candidate.conclude(judgement)
        }
    }

    /// Attempts to take the datagram only if the shared access is free right
    /// now.
    ///
    /// When the access is immediately available, this runs the same
    /// synchronous section as [`try_exclusive`](Self::try_exclusive) and
    /// returns [`DatagramClaimPrecheck::Completed`]. Otherwise it returns the
    /// candidate unchanged in [`DatagramClaimPrecheck::Deferred`] without
    /// calling the deliverer or registering a wait. An uncontended access is not
    /// free of work: the factory and the judgment still run on the calling
    /// thread.
    pub fn try_exclusive_now(mut self) -> DatagramClaimPrecheck<Inner, Deliverer> {
        let judgement = {
            let Ok(mut slot) = self.participation.core().input.try_lock() else {
                return DatagramClaimPrecheck::Deferred(self);
            };
            let judgement = judge(
                &mut slot,
                self.participation.core(),
                &*self.deliverer,
                &self.route,
                &mut self.state,
            );
            drop(slot);
            judgement
        };
        DatagramClaimPrecheck::Completed(self.conclude(judgement))
    }
}

/// The synchronous section of an attempt, run while holding the access.
fn judge<Inner: AsRef<[u8]>, Deliverer: DatagramDeliverer<Inner>>(
    slot: &mut DatagramSlot<Inner>,
    core: &ClaimCore<Inner, Deliverer::Handoff>,
    deliverer: &Deliverer,
    route: &DatagramRouteMatchInfo,
    state: &mut PrivateState<Deliverer::DelivererDatagramState>,
) -> Judgement<Inner> {
    let new_state = |datagram: &Inner| {
        deliverer.new_datagram_state(DatagramView::new(datagram.as_ref()), route)
    };
    if core.sole_participant_takes() {
        // No other participant can appear, so taking the datagram before the
        // factory runs is indistinguishable from taking it after.
        let DatagramSlot::Present(datagram) = mem::replace(slot, DatagramSlot::Taken) else {
            return Judgement::ClaimedElsewhere;
        };
        let current = mem::replace(state, PrivateState::Uninitialized);
        *state = PrivateState::Initialized(current.into_initialized(|| new_state(&datagram)));
        return Judgement::Claimed(ExclusiveDatagram::new(datagram));
    }
    let DatagramSlot::Present(datagram) = &*slot else {
        return Judgement::ClaimedElsewhere;
    };
    let current =
        mem::replace(state, PrivateState::Uninitialized).into_initialized(|| new_state(datagram));
    match deliverer.try_claim(DatagramClaimAccess::new(slot), route, current) {
        // The returned access ends here, before the guard is released.
        DatagramClaimOutcome::Unclaimed {
            access: _,
            state: next,
        } => {
            *state = PrivateState::Initialized(next);
            Judgement::Unclaimed
        }
        DatagramClaimOutcome::Claimed {
            datagram,
            state: next,
        } => {
            *state = PrivateState::Initialized(next);
            Judgement::Claimed(datagram)
        }
    }
}

impl<Inner, Deliverer: DatagramDeliverer<Inner>> fmt::Debug
    for DatagramClaimCandidate<Inner, Deliverer>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramClaimCandidate")
            .field("route", &self.route)
            .field("state_initialized", &self.state.initialized().is_some())
            .finish_non_exhaustive()
    }
}

impl<Inner, Deliverer: DatagramDeliverer<Inner>> fmt::Debug
    for DatagramClaimAttempt<Inner, Deliverer>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Claimed(delivery) => f.debug_tuple("Claimed").field(delivery).finish(),
            Self::Unclaimed(candidate) => f.debug_tuple("Unclaimed").field(candidate).finish(),
            Self::ClaimedElsewhere => f.write_str("ClaimedElsewhere"),
        }
    }
}

impl<Inner, Deliverer: DatagramDeliverer<Inner>> fmt::Debug
    for DatagramClaimPrecheck<Inner, Deliverer>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Completed(attempt) => f.debug_tuple("Completed").field(attempt).finish(),
            Self::Deferred(candidate) => f.debug_tuple("Deferred").field(candidate).finish(),
        }
    }
}
