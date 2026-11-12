//! Claim candidates, their attempts, and the access a judgment receives

use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::mem;

use super::delivery::{ExclusiveDatagram, ExclusiveDatagramDelivery};
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
pub struct DatagramClaimCandidate<Inner, Local, Handoff: UnclaimedHandoff<Inner>> {
    participation: Participation<Inner, Handoff>,
    route: DatagramRouteMatchInfo<Local>,
}

/// The future of one attempt, returned by
/// [`DatagramClaimCandidate::try_exclusive`].
///
/// It owns the candidate and the judgment. It does nothing until first
/// polled, and it is `Send` exactly when the candidate and the judgment are.
/// Keep the same pinned future to pause an attempt; dropping it exits the
/// candidate. After it completes or panics it must not be polled again.
pub type DatagramClaimFuture<Inner, Local, Handoff: UnclaimedHandoff<Inner>, T, U, F>
where
    F: for<'access> FnOnce(
        DatagramClaimAccess<'access, Inner>,
        &DatagramRouteMatchInfo<Local>,
    ) -> DatagramClaimOutcome<'access, T, U, Inner>,
= impl Future<Output = DatagramClaimAttempt<T, U, Inner, Local, Handoff>>;

/// The result of one attempt by the mechanism.
///
/// Every variant ends the attempt. [`Claimed`](Self::Claimed) always comes
/// from a judgment that claimed; taking the datagram without a judgment is
/// [`Exclusive`](Self::Exclusive), in line with
/// [`DatagramDelivery::Exclusive`](super::delivery::DatagramDelivery::Exclusive).
#[must_use]
pub enum DatagramClaimAttempt<T, U, Inner, Local, Handoff: UnclaimedHandoff<Inner>> {
    /// The judgment took the datagram; the delivery carries it with the route
    /// match information, next to the judgment's value. It proves sole
    /// ownership, not authentication.
    Claimed(ExclusiveDatagramDelivery<Inner, Local>, T),
    /// The judgment left the datagram; the mechanism released the access and
    /// the same candidate comes back. Retrying is the holder's decision; the
    /// mechanism never retries by itself.
    Unclaimed(DatagramClaimCandidate<Inner, Local, Handoff>),
    /// The judgment gave up; this candidate's participation has ended and the
    /// judgment's value comes back.
    Abandoned(U),
    /// This candidate was the only participant left under the last-takes
    /// policy and took the datagram without a judgment. It does not promise
    /// authentication.
    Exclusive(ExclusiveDatagramDelivery<Inner, Local>),
    /// Another candidate already took the datagram; no judgment ran and this
    /// candidate's participation has ended. This says nothing about
    /// authentication, processing or protocol errors.
    ClaimedElsewhere,
}

/// The result of an immediate attempt, returned by
/// [`DatagramClaimCandidate::try_exclusive_now`].
#[must_use]
pub enum DatagramClaimPrecheck<T, U, Inner, Local, Handoff: UnclaimedHandoff<Inner>, F> {
    /// The access was immediately available and the attempt ran in full.
    Completed(DatagramClaimAttempt<T, U, Inner, Local, Handoff>),
    /// The access was busy; the candidate and the judgment come back
    /// untouched, without a judgment call and without a registered wait.
    Deferred(DatagramClaimCandidate<Inner, Local, Handoff>, F),
}

/// Temporary access to the shared datagram during one judgment.
///
/// The mechanism hands it to the judgment while it holds the shared access,
/// and it is valid only for that call: the judgment must accept it for every
/// lifetime `'access`, and the values the judgment returns are chosen outside
/// it, so the access cannot leave the call. It is neither `Send` nor `Sync`.
/// It offers a read-only look at the datagram and the one-way conversion that
/// takes it. The shared datagram is never mutable: a judgment that needs
/// writable bytes, for example to remove header protection or decrypt in
/// place, copies the range it needs into a buffer of its caller.
///
/// A judgment cannot hand the access out through the values it returns, whose
/// types are chosen outside the judgment, whether claiming:
///
/// ```compile_fail
/// # use sakuya_datagram_routing::claim::candidate::{
/// #     ClaimedDatagram, DatagramClaimCandidate, DatagramClaimOutcome,
/// # };
/// # use sakuya_datagram_routing::claim::finish::ReleaseUnclaimed;
/// // Stands in for a second claimed datagram of the same access, which
/// // cannot exist; only the value is under test.
/// fn second_claim<'access>() -> ClaimedDatagram<'access, Vec<u8>> {
///     unimplemented!()
/// }
///
/// fn attempt(candidate: DatagramClaimCandidate<Vec<u8>, (), ReleaseUnclaimed>) {
///     let _ = candidate.try_exclusive(|access, _route| {
///         DatagramClaimOutcome::<_, (), _>::Claimed(second_claim(), access)
///     });
/// }
/// ```
///
/// or abandoning:
///
/// ```compile_fail
/// # use sakuya_datagram_routing::claim::candidate::{DatagramClaimCandidate, DatagramClaimOutcome};
/// # use sakuya_datagram_routing::claim::finish::ReleaseUnclaimed;
/// fn attempt(candidate: DatagramClaimCandidate<Vec<u8>, (), ReleaseUnclaimed>) {
///     let _ = candidate.try_exclusive(|access, _route| {
///         DatagramClaimOutcome::<(), _, _>::Abandoned(access)
///     });
/// }
/// ```
///
/// nor store it in state it captures:
///
/// ```compile_fail,E0521
/// # use sakuya_datagram_routing::claim::candidate::{
/// #     DatagramClaimAccess, DatagramClaimCandidate, DatagramClaimOutcome,
/// # };
/// # use sakuya_datagram_routing::claim::finish::ReleaseUnclaimed;
/// fn attempt<'kept>(
///     candidate: DatagramClaimCandidate<Vec<u8>, (), ReleaseUnclaimed>,
///     kept: &mut Option<DatagramClaimAccess<'kept, Vec<u8>>>,
/// ) {
///     let _ = candidate.try_exclusive(|access, _route| {
///         *kept = Some(access);
///         DatagramClaimOutcome::<(), (), _>::Abandoned(())
///     });
/// }
/// ```
///
/// It is not `Send`:
///
/// ```compile_fail,E0277
/// # use sakuya_datagram_routing::claim::candidate::DatagramClaimAccess;
/// fn assert_send<T: Send>() {}
/// assert_send::<DatagramClaimAccess<'static, Vec<u8>>>();
/// ```
///
/// and not `Sync`:
///
/// ```compile_fail,E0277
/// # use sakuya_datagram_routing::claim::candidate::DatagramClaimAccess;
/// fn assert_sync<T: Sync>() {}
/// assert_sync::<DatagramClaimAccess<'static, Vec<u8>>>();
/// ```
pub struct DatagramClaimAccess<'access, Inner> {
    // invariant: the slot holds the datagram for as long as the access lives.
    // The mechanism creates an access only for a present datagram, the slot
    // stays borrowed by the access, and only `into_exclusive`, which consumes
    // the access, takes the datagram out.
    slot: &'access mut DatagramSlot<Inner>,
    /// Keeps the access on the thread that holds the shared access.
    local: PhantomData<*const ()>,
}

impl<'access, Inner> DatagramClaimAccess<'access, Inner> {
    /// Wraps a slot that the caller has checked to hold the datagram.
    fn new(slot: &'access mut DatagramSlot<Inner>) -> Self {
        debug_assert!(matches!(slot, DatagramSlot::Present(_)));
        Self {
            slot,
            local: PhantomData,
        }
    }

    fn datagram(&self) -> &Inner {
        match &*self.slot {
            DatagramSlot::Present(datagram) => datagram,
            // invariant: see the field.
            DatagramSlot::Taken => unreachable!("a claim access outlived its datagram"),
        }
    }

    /// Takes the datagram, so that no other candidate can take it.
    ///
    /// This happens within the same synchronous access and cannot fail. It
    /// proves that ownership of the datagram is unique; it does not prove that
    /// the datagram is authenticated, and it does not hand the datagram to a
    /// receiver. Every other candidate of the datagram observes it gone. The
    /// claimed datagram is bound to this access, so the judgment can only
    /// return it in [`DatagramClaimOutcome::Claimed`] of the same call.
    pub fn into_exclusive(self) -> ClaimedDatagram<'access, Inner> {
        match mem::replace(self.slot, DatagramSlot::Taken) {
            DatagramSlot::Present(datagram) => ClaimedDatagram {
                datagram: ExclusiveDatagram::new(datagram),
                access: PhantomData,
            },
            // invariant: see the field.
            DatagramSlot::Taken => unreachable!("a claim access outlived its datagram"),
        }
    }
}

impl<Inner: AsRef<[u8]>> DatagramClaimAccess<'_, Inner> {
    /// Returns the complete datagram bytes for reading.
    pub fn bytes(&self) -> &[u8] {
        self.datagram().as_ref()
    }
}

impl<Inner> fmt::Debug for DatagramClaimAccess<'_, Inner> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramClaimAccess")
            .finish_non_exhaustive()
    }
}

/// The result of one judgment.
///
/// This is the judgment's view. The mechanism's view of a whole attempt is
/// [`DatagramClaimAttempt`], which also covers a datagram already taken and
/// the direct take of a last-takes candidate. Taking and abandoning each carry
/// a value of the caller's choice, and the two types may differ.
#[must_use]
pub enum DatagramClaimOutcome<'access, T, U, Inner> {
    /// The judgment took the datagram, with a value for the caller.
    ///
    /// The claimed datagram comes from this call's
    /// [`access.into_exclusive()`](DatagramClaimAccess::into_exclusive); no
    /// other datagram has its type.
    Claimed(ClaimedDatagram<'access, Inner>, T),
    /// The judgment leaves the datagram this time and hands the unchanged
    /// access back; the candidate stays with its holder.
    Unclaimed(DatagramClaimAccess<'access, Inner>),
    /// The judgment gives up; the access was dropped inside the judgment, the
    /// candidate exits, and the value goes to the caller.
    Abandoned(U),
}

impl<T, U, Inner> fmt::Debug for DatagramClaimOutcome<'_, T, U, Inner> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Claimed(..) => f.write_str("Claimed"),
            Self::Unclaimed(_) => f.write_str("Unclaimed"),
            Self::Abandoned(_) => f.write_str("Abandoned"),
        }
    }
}

/// The datagram a judgment took from its access, on its way to the mechanism.
///
/// Only [`DatagramClaimAccess::into_exclusive`] creates one, and it carries
/// the lifetime of that access: like the access, it is valid only within the
/// judgment that took it, and the judgment can do nothing with it but return
/// it in [`DatagramClaimOutcome::Claimed`]. The mechanism then hands the
/// datagram over as an [`ExclusiveDatagram`] in the exclusive delivery of
/// [`DatagramClaimAttempt::Claimed`]. Dropping it inside the judgment
/// releases the datagram; it is never put back for other candidates.
///
/// A judgment cannot claim with a datagram it did not take from its own
/// access:
///
/// ```compile_fail,E0308
/// # use sakuya_datagram_routing::claim::candidate::{DatagramClaimCandidate, DatagramClaimOutcome};
/// # use sakuya_datagram_routing::claim::delivery::ExclusiveDatagram;
/// # use sakuya_datagram_routing::claim::finish::ReleaseUnclaimed;
/// fn attempt(
///     candidate: DatagramClaimCandidate<Vec<u8>, (), ReleaseUnclaimed>,
///     earlier: ExclusiveDatagram<Vec<u8>>,
/// ) {
///     let _ = candidate.try_exclusive(|_access, _route| {
///         DatagramClaimOutcome::<(), (), _>::Claimed(earlier, ())
///     });
/// }
/// ```
///
/// A judgment cannot hand the claimed datagram out through the values it
/// returns, whose types are chosen outside the judgment, whether claiming:
///
/// ```compile_fail
/// # use sakuya_datagram_routing::claim::candidate::{
/// #     ClaimedDatagram, DatagramClaimCandidate, DatagramClaimOutcome,
/// # };
/// # use sakuya_datagram_routing::claim::finish::ReleaseUnclaimed;
/// // Stands in for a second claimed datagram of the same access, which
/// // cannot exist; only the value is under test.
/// fn second_claim<'access>() -> ClaimedDatagram<'access, Vec<u8>> {
///     unimplemented!()
/// }
///
/// fn attempt(candidate: DatagramClaimCandidate<Vec<u8>, (), ReleaseUnclaimed>) {
///     let _ = candidate.try_exclusive(|access, _route| {
///         DatagramClaimOutcome::<_, (), _>::Claimed(second_claim(), access.into_exclusive())
///     });
/// }
/// ```
///
/// or abandoning:
///
/// ```compile_fail
/// # use sakuya_datagram_routing::claim::candidate::{DatagramClaimCandidate, DatagramClaimOutcome};
/// # use sakuya_datagram_routing::claim::finish::ReleaseUnclaimed;
/// fn attempt(candidate: DatagramClaimCandidate<Vec<u8>, (), ReleaseUnclaimed>) {
///     let _ = candidate.try_exclusive(|access, _route| {
///         DatagramClaimOutcome::<(), _, _>::Abandoned(access.into_exclusive())
///     });
/// }
/// ```
///
/// nor store it in state it captures:
///
/// ```compile_fail,E0521
/// # use sakuya_datagram_routing::claim::candidate::{
/// #     ClaimedDatagram, DatagramClaimCandidate, DatagramClaimOutcome,
/// # };
/// # use sakuya_datagram_routing::claim::finish::ReleaseUnclaimed;
/// fn attempt<'kept>(
///     candidate: DatagramClaimCandidate<Vec<u8>, (), ReleaseUnclaimed>,
///     kept: &mut Option<ClaimedDatagram<'kept, Vec<u8>>>,
/// ) {
///     let _ = candidate.try_exclusive(|access, _route| {
///         *kept = Some(access.into_exclusive());
///         DatagramClaimOutcome::<(), (), _>::Abandoned(())
///     });
/// }
/// ```
pub struct ClaimedDatagram<'access, Inner> {
    datagram: ExclusiveDatagram<Inner>,
    /// Binds the claim to the access it came from. The lifetime is
    /// invariant, so a claim can never pass for one of another access.
    access: PhantomData<fn(&'access ()) -> &'access ()>,
}

impl<Inner> ClaimedDatagram<'_, Inner> {
    /// Unwraps the datagram for the exclusive delivery of a claimed attempt.
    fn into_datagram(self) -> ExclusiveDatagram<Inner> {
        self.datagram
    }
}

impl<Inner> fmt::Debug for ClaimedDatagram<'_, Inner> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClaimedDatagram").finish_non_exhaustive()
    }
}

/// What the synchronous section decided, before the access is released.
enum Judgement<T, U, Inner> {
    Claimed(ExclusiveDatagram<Inner>, T),
    Unclaimed,
    Abandoned(U),
    Exclusive(ExclusiveDatagram<Inner>),
    ClaimedElsewhere,
}

impl<Inner, Local, Handoff: UnclaimedHandoff<Inner>> DatagramClaimCandidate<Inner, Local, Handoff> {
    pub(super) fn new(
        participation: Participation<Inner, Handoff>,
        route: DatagramRouteMatchInfo<Local>,
    ) -> Self {
        Self {
            participation,
            route,
        }
    }

    /// What routing recorded about this candidate's match.
    pub fn route_match(&self) -> &DatagramRouteMatchInfo<Local> {
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
    ) -> DatagramClaimFuture<Inner, Local, Handoff, T, U, F>
    where
        F: for<'access> FnOnce(
            DatagramClaimAccess<'access, Inner>,
            &DatagramRouteMatchInfo<Local>,
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
    ) -> DatagramClaimPrecheck<T, U, Inner, Local, Handoff, F>
    where
        F: for<'access> FnOnce(
            DatagramClaimAccess<'access, Inner>,
            &DatagramRouteMatchInfo<Local>,
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
    ) -> DatagramClaimAttempt<T, U, Inner, Local, Handoff> {
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
    fn into_delivery(
        self,
        datagram: ExclusiveDatagram<Inner>,
    ) -> ExclusiveDatagramDelivery<Inner, Local> {
        let Self {
            participation,
            route,
        } = self;
        drop(participation);
        ExclusiveDatagramDelivery::new(datagram, route)
    }
}

/// The synchronous section of an attempt, run while holding the access.
fn judge<T, U, Inner, Local, Handoff, F>(
    slot: &mut DatagramSlot<Inner>,
    core: &ClaimCore<Inner, Handoff>,
    route: &DatagramRouteMatchInfo<Local>,
    try_claim: F,
) -> Judgement<T, U, Inner>
where
    Handoff: UnclaimedHandoff<Inner>,
    F: for<'access> FnOnce(
        DatagramClaimAccess<'access, Inner>,
        &DatagramRouteMatchInfo<Local>,
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

impl<Inner, Local: fmt::Debug, Handoff: UnclaimedHandoff<Inner>> fmt::Debug
    for DatagramClaimCandidate<Inner, Local, Handoff>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramClaimCandidate")
            .field("route", &self.route)
            .finish_non_exhaustive()
    }
}

impl<T: fmt::Debug, U: fmt::Debug, Inner, Local: fmt::Debug, Handoff: UnclaimedHandoff<Inner>>
    fmt::Debug for DatagramClaimAttempt<T, U, Inner, Local, Handoff>
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

impl<T: fmt::Debug, U: fmt::Debug, Inner, Local: fmt::Debug, Handoff: UnclaimedHandoff<Inner>, F>
    fmt::Debug for DatagramClaimPrecheck<T, U, Inner, Local, Handoff, F>
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
