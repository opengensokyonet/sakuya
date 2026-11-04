//! What a deliverer receives, and how the receiver consumes it

use std::fmt;

use super::candidate::DatagramClaimCandidate;
use super::deliverer::ExclusiveDatagram;
use super::finish::UnclaimedHandoff;
use super::route_match::DatagramRouteMatchInfo;

/// What [`DatagramDeliverer::deliver`](super::deliverer::DatagramDeliverer::deliver)
/// receives for one datagram.
///
/// Matching on it, moving it, storing it and wrapping a candidate back into
/// [`Competing`](Self::Competing) never run a judgment and never create a
/// participant. Its type names the datagram and the routing domain's handoff,
/// never the deliverer.
pub enum DatagramDelivery<Inner, Handoff: UnclaimedHandoff<Inner>> {
    /// The datagram has several possible owners; the receiver attempts it with
    /// [`DatagramClaimCandidate::try_exclusive`] and consumes the delivery a
    /// claimed attempt returns. An unclaimed candidate can be kept as it is or
    /// wrapped here again.
    Competing(DatagramClaimCandidate<Inner, Handoff>),
    /// The datagram already belongs to this delivery; the receiver
    /// [consumes](ExclusiveDatagramDelivery::consume) it.
    Exclusive(ExclusiveDatagramDelivery<Inner>),
}

/// A datagram owned by one candidate, with the route match information
/// routing recorded for it.
///
/// A single last-takes candidate is delivered as one of these; an attempt that
/// claimed the datagram or took it as the last participant produces one.
/// Nothing else can create one, and it cannot be cloned. It does not refer to
/// any deliverer. Dropping it releases the datagram; it is never put back for
/// other candidates.
pub struct ExclusiveDatagramDelivery<Inner> {
    datagram: ExclusiveDatagram<Inner>,
    route: DatagramRouteMatchInfo,
}

impl<Inner> ExclusiveDatagramDelivery<Inner> {
    pub(super) fn new(datagram: ExclusiveDatagram<Inner>, route: DatagramRouteMatchInfo) -> Self {
        Self { datagram, route }
    }

    /// What routing recorded about this delivery's match.
    pub fn route_match(&self) -> &DatagramRouteMatchInfo {
        &self.route
    }

    /// Takes the datagram and its route match information.
    ///
    /// It runs no judgment and never waits. It only starts the processing of
    /// the datagram; it does not mean that any packet was processed,
    /// authenticated or accepted.
    pub fn consume(self) -> (ExclusiveDatagram<Inner>, DatagramRouteMatchInfo) {
        (self.datagram, self.route)
    }
}

impl<Inner, Handoff: UnclaimedHandoff<Inner>> fmt::Debug for DatagramDelivery<Inner, Handoff> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Competing(candidate) => f.debug_tuple("Competing").field(candidate).finish(),
            Self::Exclusive(delivery) => f.debug_tuple("Exclusive").field(delivery).finish(),
        }
    }
}

impl<Inner> fmt::Debug for ExclusiveDatagramDelivery<Inner> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExclusiveDatagramDelivery")
            .field("route", &self.route)
            .finish_non_exhaustive()
    }
}
