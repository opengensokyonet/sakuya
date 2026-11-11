//! Link, link binding and link driver abstractions for sakuya.
//!
//! A link driver binds a local address and produces a link binding; a link
//! binding produces links, channels that send and receive whole messages
//! between this side and one peer. The three kinds of object have independent
//! lifetimes, and old and new link bindings or links may coexist for the same
//! local address. This crate provides their identities and the [`Link`]
//! trait; link bindings and link drivers have no traits yet.
//!
//! Code that refers to a link binding or a link without holding it, such as a
//! delayed notification, a map key or the routing of a datagram by where it
//! arrived, uses its identity:
//!
//! - [`BindingId`] identifies one link binding. Two link bindings always have
//!   different `BindingId`s, even when they bind the same address.
//! - [`LinkId`] identifies one link. Two links always have different
//!   `LinkId`s, even when both connect the same pair of addresses. A `LinkId`
//!   also records the `BindingId` of the link binding that produced the link,
//!   available through [`LinkId::binding_id`]. A link whose peer address
//!   changes while the local binding stays the same gets a new `LinkId` with
//!   the same source `BindingId`.
//!
//! ```
//! use sakuya_link::{BindingId, LinkId};
//!
//! struct UdpBinding;
//! struct UdpLink;
//!
//! let binding = BindingId::new::<UdpBinding>();
//! let first = LinkId::new::<UdpLink>(binding.clone());
//! let second = LinkId::new::<UdpLink>(binding.clone());
//!
//! assert_ne!(first, second);
//! assert_eq!(first.binding_id(), &binding);
//! assert_eq!(second.binding_id(), &binding);
//! assert_ne!(binding, BindingId::new::<UdpBinding>());
//! ```
//!
//! # Identity
//!
//! Each `new` call allocates a [`nitori_id::Identity`]: the `TypeId` of its
//! type parameter, which names the concrete link binding or link type, and a
//! value unique within the process and never reused. An identity kept after
//! its object is gone, in a clone, a pending event or a map key, can therefore
//! never be mistaken for a later object.
//!
//! `Eq`, `Hash` and `Ord` compare only that identity, so they agree with one
//! another; the order is total but its meaning is unspecified. The source
//! `BindingId` of a `LinkId` takes no part in its identity: two `LinkId`s are
//! equal exactly when they come from the same allocation. Equal addresses, or
//! equal descriptions of what is bound, never make identities equal.
//!
//! An identity says nothing about its object. It neither keeps the object
//! alive nor implies that it still is: a `LinkId` can outlive its link, and
//! its source `BindingId` can outlive the link binding. Neither type can look
//! its object up.
//!
//! # Within one process only
//!
//! Identities are meaningful only in the process that allocated them. Neither
//! type exposes its numbers, implements serialization, or can be rebuilt from
//! an external value. `Debug` output is for diagnostics only; its format is
//! not stable.
//!
//! Both types are `Send` and `Sync` and cheap to clone. They are not `Copy`,
//! which leaves their representation free to carry more information.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use core::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
};
use nitori_id::Identity;

mod link;
pub use link::{EcnMarking, Link, MIN_DATAGRAM_SIZE, OutgoingDatagram, SendAcceptance};

/// The identity of a link binding.
///
/// Each [`BindingId::new`] call returns an identity that differs from every
/// other `BindingId` in the process. Equality, hashing and ordering compare
/// only that identity. A `BindingId` does not keep its link binding alive and
/// cannot be used to find it; it is meaningful only within the process that
/// allocated it.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BindingId {
    identity: Identity,
}

impl BindingId {
    /// Allocate the identity of a new link binding of type `B`.
    ///
    /// `B` is the concrete link binding type. It labels the identity and is
    /// otherwise unused; no value of it is needed or kept.
    ///
    /// # Panics
    ///
    /// Panics if the process has exhausted its identities, which does not
    /// happen in practice; see [`nitori_id::UniqueId::allocate`].
    #[must_use]
    pub fn new<B: ?Sized + 'static>() -> Self {
        Self {
            identity: Identity::new::<B>(),
        }
    }
}

impl fmt::Debug for BindingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BindingId").field(&self.identity).finish()
    }
}

/// The identity of a link, together with the [`BindingId`] of the link
/// binding that produced it.
///
/// Each [`LinkId::new`] call returns an identity that differs from every other
/// `LinkId` in the process. Equality, hashing and ordering compare only that
/// identity, not the source `BindingId`. A `LinkId` does not keep its link or
/// link binding alive and cannot be used to find them; it is meaningful only
/// within the process that allocated it.
#[derive(Clone)]
pub struct LinkId {
    identity: Identity,
    binding: BindingId,
}

impl LinkId {
    /// Allocate the identity of a new link of type `L` produced by the link
    /// binding identified by `binding`.
    ///
    /// `L` is the concrete link type. It labels the identity and is otherwise
    /// unused; no value of it is needed or kept.
    ///
    /// # Panics
    ///
    /// Panics if the process has exhausted its identities, which does not
    /// happen in practice; see [`nitori_id::UniqueId::allocate`].
    #[must_use]
    pub fn new<L: ?Sized + 'static>(binding: BindingId) -> Self {
        Self {
            identity: Identity::new::<L>(),
            binding,
        }
    }

    /// The identity of the link binding that produced this link.
    ///
    /// It remains available after that link binding is gone.
    #[must_use]
    pub fn binding_id(&self) -> &BindingId {
        &self.binding
    }
}

impl PartialEq for LinkId {
    fn eq(&self, other: &Self) -> bool {
        self.identity == other.identity
    }
}

impl Eq for LinkId {}

impl PartialOrd for LinkId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LinkId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.identity.cmp(&other.identity)
    }
}

impl Hash for LinkId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.identity.hash(state);
    }
}

impl fmt::Debug for LinkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkId")
            .field("identity", &self.identity)
            .field("binding", &self.binding)
            .finish()
    }
}

/// Programs that must not compile.
///
/// The identities are not `Copy`, so that their representation can grow:
///
/// ```compile_fail
/// fn copy<T: Copy>() {}
/// copy::<sakuya_link::BindingId>();
/// ```
///
/// ```compile_fail
/// fn copy<T: Copy>() {}
/// copy::<sakuya_link::LinkId>();
/// ```
///
/// No identity can be built from a number or by default:
///
/// ```compile_fail
/// let _: sakuya_link::BindingId = 0u64.into();
/// ```
///
/// ```compile_fail
/// let _: sakuya_link::BindingId = Default::default();
/// ```
#[cfg(doctest)]
pub struct CompileFail;

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::{BuildHasher, RandomState};

    struct Binding;
    struct Link;

    #[test]
    fn source_binding_takes_no_part_in_link_identity() {
        let link = LinkId::new::<Link>(BindingId::new::<Binding>());
        let rebound = LinkId {
            identity: link.identity.clone(),
            binding: BindingId::new::<Binding>(),
        };
        assert_ne!(link.binding_id(), rebound.binding_id());
        assert_eq!(link, rebound);
        assert_eq!(link.cmp(&rebound), Ordering::Equal);
        let hasher = RandomState::new();
        assert_eq!(hasher.hash_one(&link), hasher.hash_one(&rebound));
    }
}
