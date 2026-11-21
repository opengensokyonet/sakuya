//! What becomes of a datagram that every candidate left
//!
//! Each datagram uses one of two finish policies, chosen by the routing
//! context (see the [module documentation](super#finish-policies)). Under the
//! on-unclaimed policy, the last exit passes the datagram to an
//! [`UnclaimedHandoff`]. The handoff type is fixed per routing domain as
//! [`DatagramDeliverer::Handoff`](super::deliverer::DatagramDeliverer::Handoff),
//! because every candidate of a datagram carries it; a domain that never hands
//! datagrams off uses [`ReleaseUnclaimed`], which cannot be constructed.

/// Takes over a datagram that every candidate left unclaimed.
///
/// The last exit calls it synchronously, and it may be anywhere downstream:
/// in a connection loop, a cancelled future or a dropped delivery. It must
/// only move the datagram, with whatever routing context it carries, to an
/// outside capability; the next lookup, preparation or delivery must not run
/// on the current call stack. The signature cannot prove this; it is the
/// contract of the implementation.
///
/// Every `FnOnce(Inner)` is a handoff. The handoff needs no `Send` bound of its
/// own: candidates of a datagram are `Send` exactly when their handoff is, so
/// a routing domain shared between threads uses a `Send` handoff and a domain
/// used on one thread can use any.
pub trait UnclaimedHandoff<Inner> {
    /// Takes over the unclaimed datagram.
    fn hand_off(self, datagram: Inner);
}

impl<Inner, Handoff: FnOnce(Inner)> UnclaimedHandoff<Inner> for Handoff {
    fn hand_off(self, datagram: Inner) {
        self(datagram);
    }
}

/// The handoff of a routing domain that releases every unclaimed datagram.
///
/// It has no values: datagrams of such a domain always use the last-takes
/// policy, under which a datagram that every candidate left is released.
#[derive(Debug)]
pub enum ReleaseUnclaimed {}

impl<Inner> UnclaimedHandoff<Inner> for ReleaseUnclaimed {
    fn hand_off(self, _datagram: Inner) {
        match self {}
    }
}
