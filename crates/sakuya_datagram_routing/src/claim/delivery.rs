//! What a deliverer receives, how the receiver consumes it, and the datagram it owns

use std::fmt;

use super::candidate::DatagramClaimCandidate;
use super::finish::UnclaimedHandoff;
use super::route_match::DatagramRouteMatchInfo;

/// What [`DatagramDeliverer::deliver`](super::deliverer::DatagramDeliverer::deliver)
/// receives for one datagram.
///
/// Matching on it, moving it, storing it and wrapping a candidate back into
/// [`Competing`](Self::Competing) never run a judgment and never create a
/// participant. Its type names the datagram and the routing domain's handoff,
/// never the deliverer.
pub enum DatagramDelivery<Inner, Local, Handoff: UnclaimedHandoff<Inner>> {
    /// The datagram has several possible owners; the receiver attempts it with
    /// [`DatagramClaimCandidate::try_exclusive`] and consumes the delivery a
    /// claimed attempt returns. An unclaimed candidate can be kept as it is or
    /// wrapped here again.
    Competing(DatagramClaimCandidate<Inner, Local, Handoff>),
    /// The datagram already belongs to this delivery; the receiver
    /// [consumes](ExclusiveDatagramDelivery::consume) it.
    Exclusive(ExclusiveDatagramDelivery<Inner, Local>),
}

/// A datagram owned by one candidate, with the route match information
/// routing recorded for it.
///
/// A single last-takes candidate is delivered as one of these; an attempt that
/// claimed the datagram or took it as the last participant produces one.
/// Nothing else can create one, and it cannot be cloned. It does not refer to
/// any deliverer. Dropping it releases the datagram; it is never put back for
/// other candidates.
pub struct ExclusiveDatagramDelivery<Inner, Local> {
    datagram: ExclusiveDatagram<Inner>,
    route: DatagramRouteMatchInfo<Local>,
}

impl<Inner, Local> ExclusiveDatagramDelivery<Inner, Local> {
    pub(super) fn new(
        datagram: ExclusiveDatagram<Inner>,
        route: DatagramRouteMatchInfo<Local>,
    ) -> Self {
        Self { datagram, route }
    }

    /// What routing recorded about this delivery's match.
    pub fn route_match(&self) -> &DatagramRouteMatchInfo<Local> {
        &self.route
    }

    /// Takes the datagram and its route match information.
    ///
    /// It runs no judgment and never waits. It only starts the processing of
    /// the datagram; it does not mean that any packet was processed,
    /// authenticated or accepted.
    pub fn consume(self) -> (ExclusiveDatagram<Inner>, DatagramRouteMatchInfo<Local>) {
        (self.datagram, self.route)
    }
}

/// Sole ownership of one datagram.
///
/// It is obtained only by taking the datagram, either through
/// [`DatagramClaimAccess::into_exclusive`](super::candidate::DatagramClaimAccess::into_exclusive)
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

impl<Inner, Local: fmt::Debug, Handoff: UnclaimedHandoff<Inner>> fmt::Debug
    for DatagramDelivery<Inner, Local, Handoff>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Competing(candidate) => f.debug_tuple("Competing").field(candidate).finish(),
            Self::Exclusive(delivery) => f.debug_tuple("Exclusive").field(delivery).finish(),
        }
    }
}

impl<Inner, Local: fmt::Debug> fmt::Debug for ExclusiveDatagramDelivery<Inner, Local> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExclusiveDatagramDelivery")
            .field("route", &self.route)
            .finish_non_exhaustive()
    }
}
