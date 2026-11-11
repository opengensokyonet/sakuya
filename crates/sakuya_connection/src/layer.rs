//! The layers of a connection's tree and the facts a node is built from.
//!
//! A connection is a tree of nodes. Under the connection node are the nodes
//! of the logical link entries and of the logical paths; under a logical
//! path are its link paths. Two kinds of child nodes come and go with what
//! the connection has reached: the established layer under the connection
//! and the recovery layer under a link path. Every node of one layer holds
//! the same kinds of components and calls: each part of the composition has
//! a share in every layer ([`LayerShare`](crate::share::LayerShare)).
use core::fmt::Debug;

use sakuya_link::LinkId;

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
    /// The facts a node of this layer is built from; `K` is the key of a
    /// logical path.
    type Args<K>;
    /// The index of the layer, for the driver's tables.
    #[doc(hidden)]
    const INDEX: usize;
}
impl Layer for Connection {
    type Args<K> = ConnectionArgs;
    const INDEX: usize = 0;
}
impl Layer for LinkEntry {
    type Args<K> = LinkEntryArgs;
    const INDEX: usize = 1;
}
impl Layer for LogicalPath {
    type Args<K> = LogicalPathArgs<K>;
    const INDEX: usize = 2;
}
impl Layer for LinkPath {
    type Args<K> = LinkPathArgs<K>;
    const INDEX: usize = 3;
}
impl Layer for Established {
    type Args<K> = EstablishedArgs;
    const INDEX: usize = 4;
}
impl Layer for Recovery {
    type Args<K> = RecoveryArgs<K>;
    const INDEX: usize = 5;
}

/// The facts the connection node is built from.
///
/// The fields of this structure are provisional: it gains the facts that
/// the connection node's components are built from.
#[derive(Debug, Default)]
pub struct ConnectionArgs {}

/// The facts a logical link entry is built from.
#[derive(Clone, Debug)]
pub struct LinkEntryArgs {
    /// The logical link of the entry.
    pub link: LinkId,
}

/// The facts a logical path is built from.
#[derive(Clone, Debug)]
pub struct LogicalPathArgs<K> {
    /// The key of the logical path.
    pub path: K,
}

/// The facts a link path is built from.
#[derive(Clone, Debug)]
pub struct LinkPathArgs<K> {
    /// The key of the link path's logical path.
    pub path: K,
    /// The link path's logical link.
    pub link: LinkId,
}

/// The facts the established layer is built from.
///
/// The fields of this structure are provisional: what the established
/// layer's components are built from is read from the connection node.
#[derive(Clone, Debug, Default)]
pub struct EstablishedArgs {}

/// The facts the recovery layer of a link path is built from.
#[derive(Clone, Debug)]
pub struct RecoveryArgs<K> {
    /// The key of the link path's logical path.
    pub path: K,
    /// The link path's logical link.
    pub link: LinkId,
}

/// The key of a node.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NodeKey<K> {
    /// The connection node.
    Connection,
    /// The entry of a logical link.
    LinkEntry(LinkId),
    /// A logical path.
    LogicalPath(K),
    /// A link path: its logical path and its logical link.
    LinkPath(K, LinkId),
    /// The established layer.
    Established,
    /// The recovery layer of a link path.
    Recovery(K, LinkId),
}

/// What a key of a logical path must be.
pub trait LogicalPathKey: Clone + Eq + Ord + Debug + 'static {}
impl<K: Clone + Eq + Ord + Debug + 'static> LogicalPathKey for K {}
