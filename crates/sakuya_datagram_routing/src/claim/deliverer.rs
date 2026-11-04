//! The author-implemented deliverer

use super::delivery::DatagramDelivery;
use super::finish::{ReleaseUnclaimed, UnclaimedHandoff};

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
