//! The tree of a connection's nodes.
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::Waker,
};

use crate::{
    call::CallBundle,
    clock::{ConnectionChoices, InstantOf},
    layer::{
        Connection, Established, Layer, LinkEntry, LinkPath, LogicalPath, NodeKeyOf, Recovery,
    },
    others::OtherNodes,
    share::{LineageLists, NodeData, PartList},
    take::{Lineage, TakenPositions},
};

/// The wake marks in a node's head: one bit for each position, and whether
/// the node is in the ready queue.
#[derive(Debug, Default)]
pub struct WakeMarks {
    bits: AtomicU64,
    queued: AtomicBool,
}

impl WakeMarks {
    /// Set the marks `bits`; whether the node was not queued yet, so it is
    /// to be pushed into the ready queue now.
    pub(crate) fn mark(&self, bits: u64) -> bool {
        self.bits.fetch_or(bits, Ordering::SeqCst);
        !self.queued.swap(true, Ordering::SeqCst)
    }
    /// Take the node out of the ready queue: clear "queued", then take the
    /// marks.
    pub(crate) fn take(&self) -> u64 {
        self.queued.store(false, Ordering::SeqCst);
        self.bits.swap(0, Ordering::SeqCst)
    }
}

/// Where a node is: its layer, its slot, and for a link path or a recovery
/// layer the slot among its logical path's link paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct NodeAddr {
    pub(crate) layer: usize,
    pub(crate) slot: usize,
    pub(crate) sub: usize,
}

impl NodeAddr {
    pub(crate) const CONNECTION: Self = Self {
        layer: Connection::INDEX,
        slot: 0,
        sub: 0,
    };
    pub(crate) const ESTABLISHED: Self = Self {
        layer: Established::INDEX,
        slot: 0,
        sub: 0,
    };
    pub(crate) fn entry(slot: usize) -> Self {
        Self {
            layer: LinkEntry::INDEX,
            slot,
            sub: 0,
        }
    }
    pub(crate) fn logical_path(slot: usize) -> Self {
        Self {
            layer: LogicalPath::INDEX,
            slot,
            sub: 0,
        }
    }
    pub(crate) fn link_path(slot: usize, sub: usize) -> Self {
        Self {
            layer: LinkPath::INDEX,
            slot,
            sub,
        }
    }
    pub(crate) fn recovery(slot: usize, sub: usize) -> Self {
        Self {
            layer: Recovery::INDEX,
            slot,
            sub,
        }
    }
}

/// A node: its head (key, wake marks; for a link path the slot of its
/// logical link entry), its data and its calls, and the child node it may
/// have. `Key` is the type of the key ([`NodeKey`](crate::layer::NodeKey)).
pub struct Node<Key, Data, Calls, Child = ()> {
    pub(crate) key: Key,
    pub(crate) marks: Arc<WakeMarks>,
    pub(crate) entry: usize,
    pub(crate) data: Data,
    pub(crate) calls: Calls,
    pub(crate) child: Child,
    pub(crate) wakers: Vec<Waker>,
}

impl<Key, Data, Calls, Child> Node<Key, Data, Calls, Child> {
    /// The node's key.
    pub fn key(&self) -> &Key {
        &self.key
    }
}

/// The node of a logical link entry.
pub(crate) type EntryNode<T, L, B> =
    Node<NodeKeyOf<T, L>, NodeData<T, L, LinkEntry>, <B as CallBundle>::LinkEntry>;
/// The established layer's node.
pub(crate) type EstablishedNode<T, L, B> =
    Node<NodeKeyOf<T, L>, NodeData<T, L, Established>, <B as CallBundle>::Established>;
/// The recovery layer's node.
pub(crate) type RecoveryNode<T, L, B> =
    Node<NodeKeyOf<T, L>, NodeData<T, L, Recovery>, <B as CallBundle>::Recovery>;
/// A link path's node, with its recovery layer when it has one.
pub(crate) type LinkPathNodeOf<T, L, B> = Node<
    NodeKeyOf<T, L>,
    NodeData<T, L, LinkPath>,
    <B as CallBundle>::LinkPath,
    Option<RecoveryNode<T, L, B>>,
>;
/// The connection's node, with its established layer when it has one.
pub(crate) type ConnectionNode<T, L, B> = Node<
    NodeKeyOf<T, L>,
    NodeData<T, L, Connection>,
    <B as CallBundle>::Connection,
    Option<EstablishedNode<T, L, B>>,
>;

/// A logical path's node and its link paths.
pub struct LogicalPathNode<T: ConnectionChoices, L: PartList<T>, B: CallBundle> {
    pub(crate) node: Node<NodeKeyOf<T, L>, NodeData<T, L, LogicalPath>, B::LogicalPath>,
    pub(crate) link_paths: Vec<Option<LinkPathNodeOf<T, L, B>>>,
}

/// The tree of a connection: the connection node, the logical link
/// entries and the logical paths under it, the link paths under their
/// logical paths.
pub struct ConnectionTree<T: ConnectionChoices, L: PartList<T>, B: CallBundle> {
    pub(crate) connection: Option<ConnectionNode<T, L, B>>,
    pub(crate) entries: Vec<Option<EntryNode<T, L, B>>>,
    pub(crate) logical_paths: Vec<Option<LogicalPathNode<T, L, B>>>,
}

/// A slice of slots with one slot taken out of it, and that slot's place.
pub(crate) struct Around<'v, X> {
    before: &'v mut [Option<X>],
    after: &'v mut [Option<X>],
    hole: usize,
}

impl<'v, X> Around<'v, X> {
    pub(crate) fn whole(slots: &'v mut [Option<X>]) -> Self {
        let hole = slots.len();
        Self {
            before: slots,
            after: &mut [],
            hole,
        }
    }
    pub(crate) fn empty() -> Self {
        Self {
            before: &mut [],
            after: &mut [],
            hole: 0,
        }
    }
    /// The slot `at` (which holds a node) and the others around it.
    pub(crate) fn split(slots: &'v mut [Option<X>], at: usize) -> (&'v mut X, Self) {
        let (before, rest) = slots.split_at_mut(at);
        let (this, after) = rest.split_first_mut().expect("a slot inside the slice");
        (
            this.as_mut().expect("a node at the slot"),
            Self {
                before,
                after,
                hole: at,
            },
        )
    }
    /// The nodes with their slots.
    pub(crate) fn indexed(&mut self) -> impl Iterator<Item = (usize, &mut X)> {
        let hole = self.hole;
        let before = self.before.iter_mut().enumerate();
        let after = self
            .after
            .iter_mut()
            .enumerate()
            .map(move |(i, n)| (hole + 1 + i, n));
        before
            .chain(after)
            .filter_map(|(i, n)| n.as_mut().map(|n| (i, n)))
    }
    /// The nodes with their slots, read only.
    pub(crate) fn indexed_ref(&self) -> impl Iterator<Item = (usize, &X)> {
        let hole = self.hole;
        let before = self.before.iter().enumerate();
        let after = self
            .after
            .iter()
            .enumerate()
            .map(move |(i, n)| (hole + 1 + i, n));
        before
            .chain(after)
            .filter_map(|(i, n)| n.as_ref().map(|n| (i, n)))
    }
    /// The first node `found` is true for, with its slot.
    pub(crate) fn find(&mut self, found: impl Fn(&X) -> bool) -> Option<(usize, &mut X)> {
        self.indexed().find(|(_, n)| found(n))
    }
}

/// What a lend hands out besides the lineage: the others, the lent node's
/// calls.
pub(crate) struct Lent<'v, T: ConnectionChoices, L: PartList<T>, B: CallBundle, List, Calls> {
    pub(crate) lineage: Lineage<'v, List>,
    pub(crate) others: OtherNodes<'v, T, L, B>,
    pub(crate) calls: &'v mut Calls,
    pub(crate) wakers: &'v [Waker],
}

/// What a lend records.
pub(crate) struct Records<'v, T: ConnectionChoices> {
    pub(crate) lineage: &'v mut TakenPositions,
    pub(crate) nodes: &'v mut Vec<(NodeAddr, usize)>,
    pub(crate) now: InstantOf<T>,
}

impl<T: ConnectionChoices, L: PartList<T>, B: CallBundle> ConnectionTree<T, L, B> {
    pub(crate) fn connection(&mut self) -> &mut ConnectionNode<T, L, B> {
        self.connection
            .as_mut()
            .expect("the connection node is there until the connection ends")
    }

    pub(crate) fn lend_connection<'v>(
        &'v mut self,
        records: Records<'v, T>,
    ) -> Lent<'v, T, L, B, <L as LineageLists<'v, T>>::Connection, B::Connection>
    where
        L: LineageLists<'v, T>,
    {
        let Self {
            connection,
            entries,
            logical_paths,
        } = self;
        let Node {
            data,
            calls,
            child,
            key,
            wakers,
            ..
        } = connection.as_mut().expect("the connection node");
        let others = OtherNodes::new(
            Around::whole(entries),
            Around::whole(logical_paths),
            Around::empty(),
            None,
            child.as_mut(),
            None,
            records.nodes,
            key.clone(),
            records.now,
        );
        Lent {
            lineage: Lineage::new(L::connection(data), records.lineage),
            others,
            calls,
            wakers,
        }
    }

    pub(crate) fn lend_entry<'v>(
        &'v mut self,
        slot: usize,
        records: Records<'v, T>,
    ) -> Lent<'v, T, L, B, <L as LineageLists<'v, T>>::LinkEntry, B::LinkEntry>
    where
        L: LineageLists<'v, T>,
    {
        let Self {
            connection,
            entries,
            logical_paths,
        } = self;
        let Node {
            data: connection_data,
            child,
            ..
        } = connection.as_mut().expect("the connection node");
        let (entry, entries) = Around::split(entries, slot);
        let others = OtherNodes::new(
            entries,
            Around::whole(logical_paths),
            Around::empty(),
            None,
            child.as_mut(),
            None,
            records.nodes,
            entry.key.clone(),
            records.now,
        );
        Lent {
            lineage: Lineage::new(
                L::link_entry(connection_data, &mut entry.data),
                records.lineage,
            ),
            others,
            calls: &mut entry.calls,
            wakers: &entry.wakers,
        }
    }

    pub(crate) fn lend_logical_path<'v>(
        &'v mut self,
        slot: usize,
        records: Records<'v, T>,
    ) -> Lent<'v, T, L, B, <L as LineageLists<'v, T>>::LogicalPath, B::LogicalPath>
    where
        L: LineageLists<'v, T>,
    {
        let Self {
            connection,
            entries,
            logical_paths,
        } = self;
        let Node {
            data: connection_data,
            child,
            ..
        } = connection.as_mut().expect("the connection node");
        let (path, logical_paths) = Around::split(logical_paths, slot);
        let LogicalPathNode { node, link_paths } = path;
        let others = OtherNodes::new(
            Around::whole(entries),
            logical_paths,
            Around::whole(link_paths),
            Some((slot, None)),
            child.as_mut(),
            None,
            records.nodes,
            node.key.clone(),
            records.now,
        );
        Lent {
            lineage: Lineage::new(
                L::logical_path(connection_data, &mut node.data),
                records.lineage,
            ),
            others,
            calls: &mut node.calls,
            wakers: &node.wakers,
        }
    }

    pub(crate) fn lend_link_path<'v>(
        &'v mut self,
        slot: usize,
        sub: usize,
        records: Records<'v, T>,
    ) -> Lent<'v, T, L, B, <L as LineageLists<'v, T>>::LinkPath, B::LinkPath>
    where
        L: LineageLists<'v, T>,
    {
        let Self {
            connection,
            entries,
            logical_paths,
        } = self;
        let Node {
            data: connection_data,
            child,
            ..
        } = connection.as_mut().expect("the connection node");
        let (path, logical_paths) = Around::split(logical_paths, slot);
        let LogicalPathNode { node, link_paths } = path;
        let (link, siblings) = Around::split(link_paths, sub);
        let (entry, entries) = Around::split(entries, link.entry);
        let Node {
            key,
            data,
            calls,
            child: recovery,
            wakers,
            ..
        } = link;
        let others = OtherNodes::new(
            entries,
            logical_paths,
            siblings,
            Some((slot, Some(sub))),
            child.as_mut(),
            recovery.as_mut(),
            records.nodes,
            key.clone(),
            records.now,
        );
        Lent {
            lineage: Lineage::new(
                L::link_path(connection_data, &mut entry.data, &mut node.data, data),
                records.lineage,
            ),
            others,
            calls,
            wakers,
        }
    }

    pub(crate) fn lend_established<'v>(
        &'v mut self,
        records: Records<'v, T>,
    ) -> Lent<'v, T, L, B, <L as LineageLists<'v, T>>::Established, B::Established>
    where
        L: LineageLists<'v, T>,
    {
        let Self {
            connection,
            entries,
            logical_paths,
        } = self;
        let Node {
            data: connection_data,
            child,
            ..
        } = connection.as_mut().expect("the connection node");
        let Node {
            key,
            data,
            calls,
            wakers,
            ..
        } = child.as_mut().expect("the established layer");
        let others = OtherNodes::new(
            Around::whole(entries),
            Around::whole(logical_paths),
            Around::empty(),
            None,
            None,
            None,
            records.nodes,
            key.clone(),
            records.now,
        );
        Lent {
            lineage: Lineage::new(L::established(connection_data, data), records.lineage),
            others,
            calls,
            wakers,
        }
    }

    pub(crate) fn lend_recovery<'v>(
        &'v mut self,
        slot: usize,
        sub: usize,
        records: Records<'v, T>,
    ) -> Lent<'v, T, L, B, <L as LineageLists<'v, T>>::Recovery, B::Recovery>
    where
        L: LineageLists<'v, T>,
    {
        let Self {
            connection,
            entries,
            logical_paths,
        } = self;
        let Node {
            data: connection_data,
            child,
            ..
        } = connection.as_mut().expect("the connection node");
        let (path, logical_paths) = Around::split(logical_paths, slot);
        let LogicalPathNode { node, link_paths } = path;
        let (link, siblings) = Around::split(link_paths, sub);
        let (entry, entries) = Around::split(entries, link.entry);
        let Node {
            data: link_data,
            child: recovery,
            ..
        } = link;
        let Node {
            key,
            data,
            calls,
            wakers,
            ..
        } = recovery.as_mut().expect("a recovery layer");
        let others = OtherNodes::new(
            entries,
            logical_paths,
            siblings,
            Some((slot, Some(sub))),
            child.as_mut(),
            None,
            records.nodes,
            key.clone(),
            records.now,
        );
        Lent {
            lineage: Lineage::new(
                L::recovery(
                    connection_data,
                    &mut entry.data,
                    &mut node.data,
                    link_data,
                    data,
                ),
                records.lineage,
            ),
            others,
            calls,
            wakers,
        }
    }
}
