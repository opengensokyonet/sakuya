//! Link, link binding and link driver abstractions for sakuya.
//!
//! A link driver binds a local address and produces a link binding; a link
//! binding produces links, channels that send and receive whole messages
//! between this side and one peer. The three kinds of object have independent
//! lifetimes, and old and new link bindings or links may coexist for the same
//! local address. This crate provides the [`Link`] trait, the identity of a
//! link, and the datagrams a link sends and receives: a received one is a
//! [`ReceivedDatagram`], with the [`ArrivalFacts`] of its arrival. Link
//! bindings and link drivers have no traits yet.
//!
//! Code that refers to a link without holding it, such as a delayed
//! notification, a map key or the routing of a datagram by where it arrived,
//! uses its [`LinkId`]. A `LinkId` names the two ends of the link, which are
//! public fields of types the link chooses ([`Link::Local`] and
//! [`Link::Peer`]), and the link binding the link came from, as its
//! [`BindingId`]; it holds an identity of its own that tells apart two links
//! with the same two ends:
//!
//! ```
//! use sakuya_link::{BindingId, LinkId};
//!
//! struct UdpLink;
//!
//! let binding = BindingId::new();
//! let local = "192.0.2.1:4433";
//! let peer = "198.51.100.7:50000";
//! let first = LinkId::new::<UdpLink>(local, peer, &binding);
//! let second = LinkId::new::<UdpLink>(local, peer, &binding);
//!
//! assert_eq!((first.local, first.peer), (second.local, second.peer));
//! assert_eq!(first.binding, binding);
//! assert_ne!(first, second);
//! assert_eq!(first, first.clone());
//! ```
//!
//! # Identity
//!
//! Each `new` call allocates a [`nitori_id::Identity`]: the `TypeId` of its
//! type parameter, which names the concrete link type, and a value unique
//! within the process and never reused. An identity kept after its link is
//! gone, in a clone, a pending event or a map key, can therefore never be
//! mistaken for a later link.
//!
//! `Eq`, `Hash` and `Ord` compare only that identity, so they agree with one
//! another; the order is total but its meaning is unspecified. The two ends
//! and the binding take no part in it: two `LinkId`s are equal exactly when
//! they come from the same allocation, and equal ends never make them equal. [`LinkId::map`]
//! changes the types of the ends and keeps the binding and the identity,
//! which is how the identity of a link enters a sum of link types.
//!
//! A [`BindingId`] identifies a link binding only: a transport implementation
//! takes one with [`BindingId::new`] when it binds, and gives it to every
//! link of that binding. It does not stand for this side's end, which is
//! `local`.
//!
//! An identity says nothing about whether its link still exists. It neither
//! keeps the link alive nor implies that it still is, and it cannot look the
//! link up.
//!
//! # Within one process only
//!
//! Identities are meaningful only in the process that allocated them. A
//! `LinkId` or a `BindingId` does not expose its numbers, implement
//! serialization, or rebuild an identity from an external value; the ends of
//! a link are values of the link's own types. `Debug` output shows only the identity and is for
//! diagnostics only; its format is not stable.
//!
//! A `LinkId` is `Send` and `Sync` when its ends are, and as cheap to clone as
//! they are. It is not `Copy`, which leaves its representation free to carry
//! more information.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use core::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
};
use nitori_id::{Identity, UniqueId};

mod link;
pub use link::{
    ArrivalFacts, EcnCodepoint, EcnMarking, Link, MIN_DATAGRAM_SIZE, OutgoingDatagram,
    ReceivedDatagram, SendAcceptance,
};

/// The identity of a link binding: unique within the process, opaque.
///
/// A transport implementation takes one when it binds and keeps it for the
/// binding's life; every link of the binding carries it in its [`LinkId`].
/// It identifies the binding only, not this side's end. Equality, hashing
/// and ordering compare the value; the order is total but its meaning is
/// unspecified, and `Debug` output is for diagnostics only.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct BindingId(UniqueId);

impl BindingId {
    /// Allocate the identity of a new link binding, different from every
    /// other one in the process.
    ///
    /// # Panics
    ///
    /// Panics if the process has exhausted its identities, which does not
    /// happen in practice; see [`nitori_id::UniqueId::allocate`].
    #[must_use]
    #[expect(
        clippy::new_without_default,
        reason = "each call allocates a new identity; a default value would hide that"
    )]
    pub fn new() -> Self {
        Self(UniqueId::allocate())
    }
}

/// The identity of a link: its two ends, the binding it came from, and an
/// identity of its own.
///
/// `local` and `peer` say which two ends the link joins, in the types the
/// link chooses ([`Link::Local`], [`Link::Peer`]); `binding` is the link
/// binding that produced the link. The identity, which is
/// not public, tells apart two links with the same two ends: each
/// [`LinkId::new`] call returns a `LinkId` that differs from every other
/// one allocated in the process. Equality, hashing and ordering compare
/// only that identity, not the ends. A `LinkId` does not keep its link alive
/// and cannot be used to find it; it is meaningful only within the process
/// that allocated it.
#[derive(Clone)]
pub struct LinkId<Local, Peer> {
    /// This side's end of the link.
    pub local: Local,
    /// The peer's end of the link.
    pub peer: Peer,
    /// The link binding the link came from.
    pub binding: BindingId,
    identity: Identity,
}

impl<Local, Peer> LinkId<Local, Peer> {
    /// Allocate the identity of a new link of type `L` between `local` and
    /// `peer`, from the link binding `binding`.
    ///
    /// `L` is the concrete link type. It labels the identity and is
    /// otherwise unused; no value of it is needed or kept.
    ///
    /// # Panics
    ///
    /// Panics if the process has exhausted its identities, which does not
    /// happen in practice; see [`nitori_id::UniqueId::allocate`].
    #[must_use]
    pub fn new<L: ?Sized + 'static>(local: Local, peer: Peer, binding: &BindingId) -> Self {
        Self {
            local,
            peer,
            binding: binding.clone(),
            identity: Identity::new::<L>(),
        }
    }

    /// The same identity with its ends turned into other types: `local` and
    /// `peer` are applied to the two ends, and the binding and the identity
    /// are kept.
    ///
    /// The identity of a link enters the identity of a sum of link types this
    /// way, each end injected into the sum of the members' ends; the result
    /// still differs from the identity of every other link.
    #[must_use]
    pub fn map<NewLocal, NewPeer>(
        self,
        local: impl FnOnce(Local) -> NewLocal,
        peer: impl FnOnce(Peer) -> NewPeer,
    ) -> LinkId<NewLocal, NewPeer> {
        LinkId {
            local: local(self.local),
            peer: peer(self.peer),
            binding: self.binding,
            identity: self.identity,
        }
    }
}

impl<Local, Peer> PartialEq for LinkId<Local, Peer> {
    fn eq(&self, other: &Self) -> bool {
        self.identity == other.identity
    }
}

impl<Local, Peer> Eq for LinkId<Local, Peer> {}

impl<Local, Peer> PartialOrd for LinkId<Local, Peer> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<Local, Peer> Ord for LinkId<Local, Peer> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.identity.cmp(&other.identity)
    }
}

impl<Local, Peer> Hash for LinkId<Local, Peer> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.identity.hash(state);
    }
}

impl<Local, Peer> fmt::Debug for LinkId<Local, Peer> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LinkId").field(&self.identity).finish()
    }
}

/// Programs that must not compile.
///
/// The identity is not `Copy`, so that its representation can grow:
///
/// ```compile_fail
/// fn copy<T: Copy>() {}
/// copy::<sakuya_link::LinkId<u16, u16>>();
/// ```
///
/// No identity can be built from its ends alone, from a number or by
/// default:
///
/// ```compile_fail
/// let binding = sakuya_link::BindingId::new();
/// let _ = sakuya_link::LinkId { local: 1u16, peer: 2u16, binding };
/// ```
///
/// Nor the identity of a binding:
///
/// ```compile_fail
/// let _: sakuya_link::BindingId = 0u64.into();
/// ```
///
/// ```compile_fail
/// let _: sakuya_link::BindingId = Default::default();
/// ```
///
/// ```compile_fail
/// let _: sakuya_link::LinkId<u16, u16> = 0u64.into();
/// ```
///
/// ```compile_fail
/// let _: sakuya_link::LinkId<u16, u16> = Default::default();
/// ```
#[cfg(doctest)]
pub struct CompileFail;

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::{BuildHasher, RandomState};

    struct Link;

    #[test]
    fn ends_take_no_part_in_identity() {
        let link = LinkId::new::<Link>(1u16, 2u16, &BindingId::new());
        let mut moved = link.clone();
        moved.local = 3;
        moved.peer = 4;
        assert_eq!(link, moved);
        assert_eq!(link.cmp(&moved), Ordering::Equal);
        let hasher = RandomState::new();
        assert_eq!(hasher.hash_one(&link), hasher.hash_one(&moved));
    }

    #[test]
    fn bindings_differ_and_their_links_keep_them() {
        let binding = BindingId::new();
        assert_ne!(binding, BindingId::new());
        let link = LinkId::new::<Link>(1u16, 2u16, &binding);
        assert_eq!(link.binding, binding);
        assert_eq!(link.map(u32::from, u32::from).binding, binding);
    }

    #[test]
    fn map_keeps_the_identity() {
        let link = LinkId::new::<Link>(1u16, 2u16, &BindingId::new());
        let mapped = link.clone().map(u32::from, Some::<u16>);
        assert_eq!((mapped.local, mapped.peer), (1u32, Some(2u16)));
        assert_eq!(mapped.identity, link.identity);
        let other = LinkId::new::<Link>(1u16, 2u16, &BindingId::new()).map(u32::from, Some::<u16>);
        assert_ne!(mapped, other);
    }
}
