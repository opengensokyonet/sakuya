//! Requests to change the structure of a connection's tree.
use crate::layer::{EstablishedArgs, LinkPathArgs, LogicalPathArgs, RecoveryArgs};
use core::convert::Infallible;
use sakuya_link::LinkId;

/// A change of the tree's structure: a node made, ended or moved.
///
/// Expiries and rereads return one, calls yield their own type that turns
/// into one. The driver applies it at once: nodes are built or ended before
/// anything else in the poll runs. A request that no longer fits the
/// structure, such as one for a link path whose logical path is gone, is
/// dropped. `K` is the key of a logical path.
///
/// Errors and closing are not requests: whoever finds an error records the
/// reason for closing in the component that keeps it.
#[derive(Clone, Debug)]
pub enum StructureRequest<K> {
    /// Build a logical path.
    AddLogicalPath {
        /// What it is built from, its key among them.
        args: LogicalPathArgs<K>,
    },
    /// Build a link path; the entry of its logical link is built with the
    /// first link path over it.
    AddLinkPath {
        /// What it is built from, its key among them.
        args: LinkPathArgs<K>,
    },
    /// End a link path; the entry of its logical link ends with the last
    /// link path over it.
    EndLinkPath {
        /// Its logical path.
        path: K,
        /// Its logical link.
        link: LinkId,
    },
    /// End a logical path and its link paths.
    EndLogicalPath {
        /// Its key.
        path: K,
    },
    /// End the connection: every node, from the bottom up, at once.
    EndConnection,
    /// Build the established layer.
    AddEstablished {
        /// What it is built from.
        args: EstablishedArgs,
    },
    /// End the established layer.
    EndEstablished,
    /// Build the recovery layer of a link path.
    AddRecovery {
        /// What it is built from, the link path's key among them.
        args: RecoveryArgs<K>,
    },
    /// End the recovery layer of a link path.
    EndRecovery {
        /// The link path's logical path.
        path: K,
        /// The link path's logical link.
        link: LinkId,
    },
    /// Move the recovery layer of a link path, by value, to another link
    /// path of the same logical path that has none.
    MoveRecovery {
        /// The logical path.
        path: K,
        /// The logical link of the link path it is on.
        from: LinkId,
        /// The logical link of the link path it goes to.
        to: LinkId,
    },
}

impl<K> From<Infallible> for StructureRequest<K> {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}
