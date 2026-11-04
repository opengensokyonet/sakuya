//! The author-implemented deliverer, and the access a judgment receives

use std::fmt;
use std::marker::PhantomData;
use std::mem;

use super::delivery::DatagramDelivery;
use super::finish::{ReleaseUnclaimed, UnclaimedHandoff};
use super::shared::DatagramSlot;

/// The capability a route entry offers for every datagram it matches.
///
/// A deliverer is bound to one route entry. For each datagram routed to that
/// entry it receives one delivery and passes it on, typically to its datagram
/// receiver. Several deliverers may feed the same receiver; a receiver shared
/// by deliverers never merges their candidates.
///
/// A deliverer only delivers. It does not judge whether a datagram belongs to
/// it: whoever holds a competing candidate passes its own judgment to
/// [`try_exclusive`](super::candidate::DatagramClaimCandidate::try_exclusive)
/// after delivery, so the judgment can use state the deliverer cannot reach.
/// Candidates and exclusive deliveries do not refer back to the deliverer.
///
/// A deliverer whose backend is no longer available drops its deliveries.
/// There is no error path for this case.
///
/// The trait requires neither `Send`, `Sync` nor `'static`; thread constraints
/// apply where objects actually cross threads (see the [module
/// documentation](super#thread-constraints)).
pub trait DatagramDeliverer<Inner> {
    /// What takes over a datagram that every candidate left, in the routing
    /// domain this deliverer serves.
    ///
    /// Every candidate of a datagram carries the handoff of its routing
    /// domain, so all deliverers registered in one domain share this type.
    /// The default, [`ReleaseUnclaimed`], suits every domain that never hands
    /// datagrams off; candidates are `Send` only if the handoff is.
    type Handoff: UnclaimedHandoff<Inner> = ReleaseUnclaimed;

    /// Takes over one delivery for this deliverer.
    ///
    /// It is synchronous and must not wait. Delivery completes when this
    /// returns; it does not mean the delivery was processed. A competing
    /// delivery is typically attempted later by the receiver with
    /// [`try_exclusive`](super::candidate::DatagramClaimCandidate::try_exclusive);
    /// an exclusive one is
    /// [consumed](super::delivery::ExclusiveDatagramDelivery::consume).
    /// Attempting or consuming on the spot runs that work on the caller's
    /// stack. A deliverer that can no longer accept deliveries drops them.
    fn deliver(&self, delivery: DatagramDelivery<Inner, Self::Handoff>);
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
/// # use sakuya_datagram_routing::claim::candidate::DatagramClaimCandidate;
/// # use sakuya_datagram_routing::claim::deliverer::{DatagramClaimOutcome, ExclusiveDatagram};
/// # use sakuya_datagram_routing::claim::finish::ReleaseUnclaimed;
/// fn attempt(
///     candidate: DatagramClaimCandidate<Vec<u8>, ReleaseUnclaimed>,
///     earlier: ExclusiveDatagram<Vec<u8>>,
/// ) {
///     let _ = candidate.try_exclusive(|access, _route| {
///         DatagramClaimOutcome::<_, (), _>::Claimed(earlier, access)
///     });
/// }
/// ```
///
/// or abandoning:
///
/// ```compile_fail
/// # use sakuya_datagram_routing::claim::candidate::DatagramClaimCandidate;
/// # use sakuya_datagram_routing::claim::deliverer::DatagramClaimOutcome;
/// # use sakuya_datagram_routing::claim::finish::ReleaseUnclaimed;
/// fn attempt(candidate: DatagramClaimCandidate<Vec<u8>, ReleaseUnclaimed>) {
///     let _ = candidate.try_exclusive(|access, _route| {
///         DatagramClaimOutcome::<(), _, _>::Abandoned(access)
///     });
/// }
/// ```
///
/// nor store it in state it captures:
///
/// ```compile_fail,E0521
/// # use sakuya_datagram_routing::claim::candidate::DatagramClaimCandidate;
/// # use sakuya_datagram_routing::claim::deliverer::{DatagramClaimAccess, DatagramClaimOutcome};
/// # use sakuya_datagram_routing::claim::finish::ReleaseUnclaimed;
/// fn attempt<'kept>(
///     candidate: DatagramClaimCandidate<Vec<u8>, ReleaseUnclaimed>,
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
/// # use sakuya_datagram_routing::claim::deliverer::DatagramClaimAccess;
/// fn assert_send<T: Send>() {}
/// assert_send::<DatagramClaimAccess<'static, Vec<u8>>>();
/// ```
///
/// and not `Sync`:
///
/// ```compile_fail,E0277
/// # use sakuya_datagram_routing::claim::deliverer::DatagramClaimAccess;
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
    pub(super) fn new(slot: &'access mut DatagramSlot<Inner>) -> Self {
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
    /// receiver. Every other candidate of the datagram observes it gone.
    pub fn into_exclusive(self) -> ExclusiveDatagram<Inner> {
        match mem::replace(self.slot, DatagramSlot::Taken) {
            DatagramSlot::Present(datagram) => ExclusiveDatagram::new(datagram),
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
/// [`DatagramClaimAttempt`](super::candidate::DatagramClaimAttempt), which also covers a datagram already taken and
/// the direct take of a last-takes candidate. Taking and abandoning each carry
/// a value of the caller's choice, and the two types may differ.
#[must_use]
pub enum DatagramClaimOutcome<'access, T, U, Inner> {
    /// The judgment took the datagram, with a value for the caller.
    ///
    /// The datagram must be the one obtained from this call's
    /// [`access.into_exclusive()`](DatagramClaimAccess::into_exclusive);
    /// returning any other breaks the contract of the mechanism.
    Claimed(ExclusiveDatagram<Inner>, T),
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

/// Sole ownership of one datagram.
///
/// It is obtained only by taking the datagram, either through
/// [`DatagramClaimAccess::into_exclusive`]
/// or when the mechanism takes it for a last-takes candidate. Dropping it
/// releases the datagram; it is never put back for other candidates. It says
/// nothing about authentication.
#[derive(Debug)]
pub struct ExclusiveDatagram<Inner> {
    datagram: Inner,
}

impl<Inner> ExclusiveDatagram<Inner> {
    pub(crate) fn new(datagram: Inner) -> Self {
        Self { datagram }
    }

    /// Returns the datagram.
    pub fn get(&self) -> &Inner {
        &self.datagram
    }

    /// Returns the datagram for modification by its sole owner.
    pub fn get_mut(&mut self) -> &mut Inner {
        &mut self.datagram
    }

    /// Returns the owned datagram.
    pub fn into_inner(self) -> Inner {
        self.datagram
    }
}

impl<Inner: AsRef<[u8]>> ExclusiveDatagram<Inner> {
    /// Returns the complete datagram bytes.
    pub fn bytes(&self) -> &[u8] {
        self.datagram.as_ref()
    }
}
