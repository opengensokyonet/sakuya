//! The author-implemented deliverer and the views it receives

use std::fmt;

use super::{DatagramDelivery, DatagramRouteMatchInfo};

/// The capabilities a route entry offers for every datagram it matches.
///
/// A deliverer is bound to one route entry. For each datagram routed to that
/// entry it receives one claim candidate, decides whether the datagram belongs
/// to it, and passes what it claims on to its datagram receiver. Several
/// deliverers may feed the same receiver; a receiver shared by deliverers never
/// merges their candidates or their private state.
///
/// All three methods are synchronous and must not wait. The mechanism calls
/// [`new_datagram_state`](Self::new_datagram_state) and
/// [`try_claim`](Self::try_claim) while it holds the shared access to the
/// datagram, so they must not wait for or re-enter the access of the same
/// datagram, for example by attempting another candidate of it.
///
/// A deliverer whose backend is no longer available keeps these calls safe
/// and keeps the contract: `try_claim` returns
/// [`DatagramClaimOutcome::Unclaimed`] with the access and the state, and
/// `deliver` drops the delivery. There is no error path for this case.
///
/// The trait requires neither `Send`, `Sync` nor `'static`; thread constraints
/// apply where objects actually cross threads (see the [module
/// documentation](super#thread-constraints)).
pub trait DatagramDeliverer<Inner>: Sized {
    /// The private state the deliverer keeps for one candidate.
    ///
    /// It is created lazily by [`new_datagram_state`](Self::new_datagram_state),
    /// threaded by value through every [`try_claim`](Self::try_claim) of the
    /// same candidate, and handed over with the claimed datagram. It cannot
    /// borrow the datagram or the route match information; it can own data,
    /// offsets, and whatever outside references its own type allows. No
    /// `Clone`, `Default`, `Send`, `Sync`, `Unpin` or `'static` bound is
    /// required.
    type DelivererDatagramState;

    /// Builds the initial private state of one candidate.
    ///
    /// The mechanism calls it at most once per candidate: on the first access
    /// that finds the datagram still present, or at
    /// [`consume`](super::ExclusiveDatagramDelivery::consume) of a delivery
    /// whose state was never initialized. It only builds state: it does not
    /// claim, and it does not advance any protocol processing. Values that must
    /// reflect the moment of reception belong in the route match information or
    /// the datagram, because the factory may run later than the arrival.
    fn new_datagram_state(
        &self,
        datagram: DatagramView<'_>,
        route: &DatagramRouteMatchInfo,
    ) -> Self::DelivererDatagramState;

    /// Decides within one synchronous access whether to take the datagram.
    ///
    /// Return [`DatagramClaimOutcome::Claimed`] with the datagram obtained from
    /// [`access.into_exclusive()`](DatagramClaimAccess::into_exclusive) to take
    /// it, or [`DatagramClaimOutcome::Unclaimed`] with the unchanged access to
    /// leave it for the other candidates. Either way the updated state is
    /// returned. Unclaimed only means "not this time"; it does not exclude the
    /// candidate or ask for an immediate retry.
    ///
    /// Returning a claimed datagram that was not obtained from this access
    /// breaks the contract of the mechanism.
    fn try_claim<'access>(
        &self,
        access: DatagramClaimAccess<'access, Inner>,
        route: &DatagramRouteMatchInfo,
        state: Self::DelivererDatagramState,
    ) -> DatagramClaimOutcome<'access, Inner, Self::DelivererDatagramState>;

    /// Takes over one delivery for this deliverer.
    ///
    /// Delivery completes when this returns; it does not mean the delivery was
    /// processed. A competing delivery is typically attempted later by the
    /// receiver with [`try_exclusive`](super::DatagramClaimCandidate::try_exclusive);
    /// an exclusive one is [consumed](super::ExclusiveDatagramDelivery::consume).
    /// Consuming on the spot runs the factory and judgment on the caller's stack.
    /// A deliverer that can no longer accept deliveries drops them.
    fn deliver(&self, delivery: DatagramDelivery<Inner, Self>);
}

/// A read-only view of the datagram for the state factory.
///
/// The view lives only for one factory call; the state cannot keep it.
#[derive(Clone, Copy)]
pub struct DatagramView<'datagram> {
    bytes: &'datagram [u8],
}

impl<'datagram> DatagramView<'datagram> {
    pub(super) fn new(bytes: &'datagram [u8]) -> Self {
        Self { bytes }
    }

    /// Returns the complete datagram bytes.
    pub fn bytes(&self) -> &'datagram [u8] {
        self.bytes
    }
}

impl fmt::Debug for DatagramView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramView")
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// Temporary access to the shared datagram during one claim judgment.
///
/// It is handed to [`DatagramDeliverer::try_claim`] while the mechanism holds
/// the shared access, and is valid only for that call. It offers a read-only
/// look at the datagram and the one-way conversion that takes it. The shared
/// datagram is never mutable: a judgment that needs writable bytes, for
/// example to remove header protection or decrypt in place, copies the range
/// it needs into its private state.
pub struct DatagramClaimAccess<'access, Inner> {
    slot: &'access mut Option<Inner>,
}

impl<'access, Inner> DatagramClaimAccess<'access, Inner> {
    /// Wraps a slot that the caller has checked to hold the datagram.
    pub(super) fn new(slot: &'access mut Option<Inner>) -> Self {
        debug_assert!(slot.is_some());
        Self { slot }
    }

    fn datagram(&self) -> &Inner {
        self.slot
            .as_ref()
            .expect("a claim access exists only while the datagram is present")
    }

    /// Takes the datagram, so that no other candidate can take it.
    ///
    /// This happens within the same synchronous access and cannot fail. It
    /// proves that ownership of the datagram is unique; it does not prove that
    /// the datagram is authenticated, and it does not hand the datagram to a
    /// receiver. Every other candidate of the datagram observes it gone.
    pub fn into_exclusive(self) -> ExclusiveDatagram<Inner> {
        ExclusiveDatagram::new(
            self.slot
                .take()
                .expect("a claim access exists only while the datagram is present"),
        )
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

/// The result of one [`DatagramDeliverer::try_claim`] call.
///
/// This is the author's view of one judgment. The mechanism's view of a whole
/// attempt is [`DatagramClaimAttempt`](super::DatagramClaimAttempt), which also
/// covers a datagram already taken and the direct take of a last-takes
/// candidate.
#[must_use]
pub enum DatagramClaimOutcome<'access, Inner, State> {
    /// The datagram was not taken; the access goes back to the mechanism.
    Unclaimed {
        /// The unchanged access from this call.
        access: DatagramClaimAccess<'access, Inner>,
        /// The updated private state, stored back into the same candidate.
        state: State,
    },
    /// The datagram was taken by this deliverer.
    Claimed {
        /// The datagram, obtained from this call's access.
        datagram: ExclusiveDatagram<Inner>,
        /// The private state, handed over with the datagram.
        state: State,
    },
}

impl<Inner, State> fmt::Debug for DatagramClaimOutcome<'_, Inner, State> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unclaimed { .. } => f.write_str("Unclaimed"),
            Self::Claimed { .. } => f.write_str("Claimed"),
        }
    }
}

/// Sole ownership of one datagram.
///
/// It is obtained only by taking the datagram, either through
/// [`DatagramClaimAccess::into_exclusive`] or when the mechanism takes it for
/// a last-takes candidate. Dropping it releases the datagram; it is never put
/// back for other candidates. It says nothing about authentication.
#[derive(Debug)]
pub struct ExclusiveDatagram<Inner> {
    datagram: Inner,
}

impl<Inner> ExclusiveDatagram<Inner> {
    pub(super) fn new(datagram: Inner) -> Self {
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
