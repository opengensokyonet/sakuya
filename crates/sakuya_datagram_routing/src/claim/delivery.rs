//! What a deliverer receives, and how the receiver consumes it

use std::fmt;
use std::sync::Arc;

use super::candidate::DatagramClaimCandidate;
use super::deliverer::{DatagramDeliverer, DatagramView, ExclusiveDatagram};
use super::route_match::DatagramRouteMatchInfo;

/// What [`DatagramDeliverer::deliver`] receives for one datagram.
///
/// Matching on it, moving it, storing it and wrapping a candidate back into
/// [`Competing`](Self::Competing) never call the factory, never create a
/// participant and never change the deliverer an object is bound to.
pub enum DatagramDelivery<Inner, Deliverer: DatagramDeliverer<Inner>> {
    /// The datagram has several possible owners; the receiver attempts it with
    /// [`DatagramClaimCandidate::try_exclusive`] and consumes the delivery a
    /// claimed attempt returns. An unclaimed candidate can be kept as it is or
    /// wrapped here again.
    Competing(DatagramClaimCandidate<Inner, Deliverer>),
    /// The datagram already belongs to this deliverer; the receiver
    /// [consumes](ExclusiveDatagramDelivery::consume) it.
    Exclusive(ExclusiveDatagramDelivery<Inner, Deliverer>),
}

/// A datagram owned by one deliverer, with what the deliverer needs to process
/// it.
///
/// It holds the exclusive datagram, the deliverer it is bound to, the route
/// match information and the private state. A single last-takes candidate is
/// delivered as one of these with its state not yet initialized; a won
/// competition produces one with the state already initialized. Nothing else
/// can create one, and it cannot be cloned. Dropping it releases the datagram;
/// it is never put back for other candidates.
pub struct ExclusiveDatagramDelivery<Inner, Deliverer: DatagramDeliverer<Inner>> {
    datagram: ExclusiveDatagram<Inner>,
    route: DatagramRouteMatchInfo,
    state: PrivateState<Deliverer::DelivererDatagramState>,
    deliverer: Arc<Deliverer>,
}

/// The deliverer's private state of one candidate or delivery.
///
/// It starts uninitialized and is initialized at most once: on the first
/// access that finds the datagram present, or when an exclusive delivery
/// that never competed is consumed.
pub(super) enum PrivateState<State> {
    /// The factory has not run for this candidate.
    Uninitialized,
    /// The factory ran; the state is threaded through every judgment.
    Initialized(State),
}

impl<State> PrivateState<State> {
    /// The state, if it was initialized.
    pub(super) fn initialized(&self) -> Option<&State> {
        match self {
            Self::Uninitialized => None,
            Self::Initialized(state) => Some(state),
        }
    }

    /// The state, initialized with `factory` if it was not yet.
    pub(super) fn into_initialized(self, factory: impl FnOnce() -> State) -> State {
        match self {
            Self::Uninitialized => factory(),
            Self::Initialized(state) => state,
        }
    }
}

impl<Inner, Deliverer: DatagramDeliverer<Inner>> ExclusiveDatagramDelivery<Inner, Deliverer> {
    pub(super) fn new(
        datagram: ExclusiveDatagram<Inner>,
        route: DatagramRouteMatchInfo,
        state: PrivateState<Deliverer::DelivererDatagramState>,
        deliverer: Arc<Deliverer>,
    ) -> Self {
        Self {
            datagram,
            route,
            state,
            deliverer,
        }
    }

    /// What routing recorded about this delivery's match.
    pub fn route_match(&self) -> &DatagramRouteMatchInfo {
        &self.route
    }

    /// Returns the private state if it was already initialized.
    ///
    /// This only borrows and never calls the factory.
    pub fn initialized_state(&self) -> Option<&Deliverer::DelivererDatagramState> {
        self.state.initialized()
    }
}

impl<Inner: AsRef<[u8]>, Deliverer: DatagramDeliverer<Inner>>
    ExclusiveDatagramDelivery<Inner, Deliverer>
{
    /// Takes the datagram and its complete associated state.
    ///
    /// If the private state was never initialized, this calls the bound
    /// deliverer's factory once, with a read-only view of the datagram it now
    /// owns; a delivery from a won competition hands over its existing state
    /// without calling the factory. It never calls
    /// [`try_claim`](DatagramDeliverer::try_claim) and never waits. It only
    /// starts the processing of the datagram; it does not mean that any packet
    /// was processed, authenticated or accepted.
    ///
    /// If the factory panics, the datagram is released while unwinding.
    pub fn consume(
        self,
    ) -> (
        ExclusiveDatagram<Inner>,
        DatagramAssociatedState<Deliverer::DelivererDatagramState>,
    ) {
        let Self {
            datagram,
            route,
            state,
            deliverer,
        } = self;
        let state = state.into_initialized(|| {
            deliverer.new_datagram_state(DatagramView::new(datagram.bytes()), &route)
        });
        (datagram, DatagramAssociatedState { route, state })
    }
}

/// The route match information and private state that travel with a
/// consumed datagram.
///
/// It combines what routing recorded for the candidate with the deliverer's
/// private state for it. It is neither the state of a whole route table nor a
/// deliverer's long-lived state.
#[derive(Debug)]
pub struct DatagramAssociatedState<State> {
    route: DatagramRouteMatchInfo,
    state: State,
}

impl<State> DatagramAssociatedState<State> {
    /// Returns the route match information.
    pub fn route(&self) -> &DatagramRouteMatchInfo {
        &self.route
    }

    /// Returns the deliverer's private state.
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Returns the deliverer's private state for modification.
    pub fn state_mut(&mut self) -> &mut State {
        &mut self.state
    }

    /// Returns the route match information and the private state.
    pub fn into_parts(self) -> (DatagramRouteMatchInfo, State) {
        (self.route, self.state)
    }
}

impl<Inner, Deliverer: DatagramDeliverer<Inner>> fmt::Debug for DatagramDelivery<Inner, Deliverer> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Competing(candidate) => f.debug_tuple("Competing").field(candidate).finish(),
            Self::Exclusive(delivery) => f.debug_tuple("Exclusive").field(delivery).finish(),
        }
    }
}

impl<Inner, Deliverer: DatagramDeliverer<Inner>> fmt::Debug
    for ExclusiveDatagramDelivery<Inner, Deliverer>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExclusiveDatagramDelivery")
            .field("route", &self.route)
            .field("state_initialized", &self.state.initialized().is_some())
            .finish_non_exhaustive()
    }
}
