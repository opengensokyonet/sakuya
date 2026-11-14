//! The layers of a connection's tree and the facts a node is built from.
//!
//! A connection is a tree of nodes. Under the connection node are the nodes
//! of the logical link entries and of the logical paths; under a logical
//! path are its link paths. Two kinds of child nodes come and go with what
//! the connection has reached: the established layer under the connection
//! and the recovery layer under a link path. Every node of one layer holds
//! the same kinds of components and calls: each part of the composition has
//! a share in every layer ([`LayerShare`](crate::share::LayerShare)).
use core::{fmt::Debug, time::Duration};

use crate::{
    clock::{ConnectionChoices, InstantOf, LinkIdOf},
    role::LinkPathRole,
    share::{ConnectionArgsOf, PartList, PathKey},
};

/// The connection: one node.
#[derive(Debug)]
pub struct Connection;
/// A logical link entry: one node for each logical link the connection
/// uses, made with its first link path and ended with its last.
#[derive(Debug)]
pub struct LinkEntry;
/// A logical path.
#[derive(Debug)]
pub struct LogicalPath;
/// A link path: a logical path over one logical link.
#[derive(Debug)]
pub struct LinkPath;
/// The established layer: a child of the connection node, at most one,
/// with what the connection has once the peer's transport parameters
/// are known, until it starts closing.
#[derive(Debug)]
pub struct Established;
/// The recovery layer: a child of a link path node, at most one, with
/// the link path's loss recovery while the link path is in use.
#[derive(Debug)]
pub struct Recovery;

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Connection {}
    impl Sealed for super::LinkEntry {}
    impl Sealed for super::LogicalPath {}
    impl Sealed for super::LinkPath {}
    impl Sealed for super::Established {}
    impl Sealed for super::Recovery {}
}

/// A layer of the tree.
pub trait Layer: sealed::Sealed + 'static {
    /// The facts a node of this layer is built from, for the choices `T`
    /// and the list of parts `L`.
    ///
    /// The connection node is built from what each part declares it needs
    /// ([`LayerShare::Args`](crate::share::LayerShare::Args)); the other
    /// layers are built from structural facts only, and their components
    /// read what else they need from the nodes above.
    type Args<T: ConnectionChoices, L: PartList<T>>;
    /// The index of the layer, for the driver's tables.
    #[doc(hidden)]
    const INDEX: usize;
}
impl Layer for Connection {
    type Args<T: ConnectionChoices, L: PartList<T>> = ConnectionArgsOf<T, L>;
    const INDEX: usize = 0;
}
impl Layer for LinkEntry {
    type Args<T: ConnectionChoices, L: PartList<T>> = LinkEntryArgs<T::Link>;
    const INDEX: usize = 1;
}
impl Layer for LogicalPath {
    type Args<T: ConnectionChoices, L: PartList<T>> = LogicalPathArgs<PathKey<L>>;
    const INDEX: usize = 2;
}
impl Layer for LinkPath {
    type Args<T: ConnectionChoices, L: PartList<T>> =
        LinkPathArgs<PathKey<L>, LinkIdOf<T>, InstantOf<T>>;
    const INDEX: usize = 3;
}
impl Layer for Established {
    type Args<T: ConnectionChoices, L: PartList<T>> = EstablishedArgs;
    const INDEX: usize = 4;
}
impl Layer for Recovery {
    type Args<T: ConnectionChoices, L: PartList<T>> = RecoveryArgs<PathKey<L>, LinkIdOf<T>>;
    const INDEX: usize = 5;
}

/// The facts a logical link entry is built from.
#[derive(Clone, Debug)]
pub struct LinkEntryArgs<Lk> {
    /// The connection's clone of the logical link, moved here from the
    /// request for the first link path over it. The component that keeps
    /// the clone takes it out when it is built; it is `None` afterwards.
    pub link: Option<Lk>,
}

/// The facts a logical path is built from.
#[derive(Clone, Debug)]
pub struct LogicalPathArgs<K> {
    /// The key of the logical path.
    pub path: K,
}

/// A link path: the key of its logical path and its logical link, and the
/// protocol facts it starts with, which whoever asks for it gives.
///
/// A request to build a link path carries the connection's clone of the
/// logical link (`Lk` is the link type): the driver moves it into the
/// entry of the logical link when it builds that entry with this link
/// path, and drops it when the entry is there already. The link path node
/// itself is built from the logical link's identity (`Lk` is
/// [`LinkIdOf`]); its components read the clone from the entry above. `I`
/// is an instant of the connection's clock.
#[derive(Clone, Debug)]
pub struct LinkPathArgs<K, Lk, I> {
    /// The key of the link path's logical path.
    pub path: K,
    /// The link path's logical link.
    pub link: Lk,
    /// The role the link path starts in: [`LinkPathRole::Active`] for the
    /// connection's first link path, which the handshake runs over.
    pub role: LinkPathRole<I>,
    /// Whether the peer, on this link path, uses another of this side's
    /// connection IDs than on the link path it came from; when it does
    /// not, RFC 9000 §9.5 lets this side keep its connection ID towards the
    /// new remote address. `false` for the connection's first link path.
    pub peer_switched_local_id: bool,
}

/// The facts the established layer is built from.
///
/// The fields of this structure are provisional: what the established
/// layer's components are built from is read from the connection node.
#[derive(Clone, Debug, Default)]
pub struct EstablishedArgs {}

/// The facts the recovery layer of a link path is built from.
///
/// `K` is the key of the logical path, `Id` the identity of a link
/// ([`LinkIdOf`]).
#[derive(Clone, Debug)]
pub struct RecoveryArgs<K, Id> {
    /// The key of the link path's logical path.
    pub path: K,
    /// The link path's logical link.
    pub link: Id,
    /// The RTT measured before the layer is built: for a link path whose
    /// new address was validated, the interval between sending a
    /// PATH_CHALLENGE and receiving its PATH_RESPONSE on it (RFC 9002
    /// §6.2.2); `None` for the connection's first link path.
    pub initial_rtt: Option<Duration>,
}

/// The key of a node.
///
/// `K` is the key of a logical path, `Id` the identity of a link
/// ([`LinkIdOf`]).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NodeKey<K, Id> {
    /// The connection node.
    Connection,
    /// The entry of a logical link.
    LinkEntry(Id),
    /// A logical path.
    LogicalPath(K),
    /// A link path: its logical path and its logical link.
    LinkPath(K, Id),
    /// The established layer.
    Established,
    /// The recovery layer of a link path.
    Recovery(K, Id),
}

/// The key of a node of the choices `T` and the list of parts `L`.
pub type NodeKeyOf<T, L> = NodeKey<PathKey<L>, LinkIdOf<T>>;

/// What a key of a logical path must be.
pub trait LogicalPathKey: Clone + Eq + Ord + Debug + 'static {}
impl<K: Clone + Eq + Ord + Debug + 'static> LogicalPathKey for K {}
