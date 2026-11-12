//! The nodes a lend reaches besides the lent node and the nodes above it.
use crate::{
    call::CallBundle,
    clock::{ConnectionChoices, InstantOf, LinkIdOf},
    layer::{Established, LinkEntry, LinkPath, LogicalPath, NodeKey, NodeKeyOf, Recovery},
    share::{FlatMut, NodeData, PartList, PathKey},
    take::{GetAt, RefsOf, TakeEach},
    tree::{
        Around, EntryNode, EstablishedNode, LinkPathNodeOf, LogicalPathNode, NodeAddr, RecoveryNode,
    },
};

/// The nodes other than the lent node and the nodes above it, by key: other
/// logical link entries, other logical paths with their link paths, the
/// lent logical path's link paths (other than the lent one), the child
/// nodes. Only their data is reached, not their calls; mutable takes are
/// recorded, as in a [`Lineage`](crate::take::Lineage). It also carries the
/// lent node's key and the instant of this poll.
pub struct OtherNodes<'v, T: ConnectionChoices, L: PartList<T>, B: CallBundle> {
    entries: Around<'v, EntryNode<T, L, B>>,
    logical_paths: Around<'v, LogicalPathNode<T, L, B>>,
    here_link_paths: Around<'v, LinkPathNodeOf<T, L, B>>,
    here_path: Option<(usize, Option<usize>)>,
    established: Option<&'v mut EstablishedNode<T, L, B>>,
    here_recovery: Option<&'v mut RecoveryNode<T, L, B>>,
    taken: &'v mut Vec<(NodeAddr, usize)>,
    here: NodeKeyOf<T, L>,
    now: InstantOf<T>,
}

impl<'v, T: ConnectionChoices, L: PartList<T>, B: CallBundle> OtherNodes<'v, T, L, B> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        entries: Around<'v, EntryNode<T, L, B>>,
        logical_paths: Around<'v, LogicalPathNode<T, L, B>>,
        here_link_paths: Around<'v, LinkPathNodeOf<T, L, B>>,
        here_path: Option<(usize, Option<usize>)>,
        established: Option<&'v mut EstablishedNode<T, L, B>>,
        here_recovery: Option<&'v mut RecoveryNode<T, L, B>>,
        taken: &'v mut Vec<(NodeAddr, usize)>,
        here: NodeKeyOf<T, L>,
        now: InstantOf<T>,
    ) -> Self {
        Self {
            entries,
            logical_paths,
            here_link_paths,
            here_path,
            established,
            here_recovery,
            taken,
            here,
            now,
        }
    }

    /// The same nodes, for the node of the key `here`: a node being ended,
    /// which is out of the tree.
    pub(crate) fn ending(mut self, here: NodeKeyOf<T, L>) -> Self {
        self.here = here;
        self
    }

    /// The lent node's key; for an end action, the key of the node being
    /// ended.
    pub fn here(&self) -> &NodeKeyOf<T, L> {
        &self.here
    }

    /// The instant of this poll.
    pub fn now(&self) -> InstantOf<T> {
        self.now
    }

    fn record(taken: &mut Vec<(NodeAddr, usize)>, addr: NodeAddr) -> impl FnMut(usize) + '_ {
        move |at| taken.push((addr, at))
    }

    /// Whether the connection has its established layer (when the lent node
    /// is not in it).
    pub fn has_established(&self) -> bool {
        self.established.is_some()
    }

    /// Take components `U` of the established layer, once in a lend; `None`
    /// when there is none, or when it is the lent node or taken already.
    pub fn established<U, Is>(&mut self) -> Option<<U as RefsOf<'v>>::Out>
    where
        NodeData<T, L, Established>: FlatMut<'v>,
        <NodeData<T, L, Established> as FlatMut<'v>>::Out: TakeEach<'v, U, Is>,
        U: RefsOf<'v>,
    {
        let node = self.established.take()?;
        let (items, _) = node
            .data
            .flat_mut()
            .take_each(&mut Self::record(self.taken, NodeAddr::ESTABLISHED));
        Some(items)
    }

    /// Whether the lent link path has its recovery layer.
    pub fn has_recovery(&self) -> bool {
        self.here_recovery.is_some()
    }

    /// Take components `U` of the lent link path's recovery layer, once in a
    /// lend; `None` when it has none.
    pub fn recovery<U, Is>(&mut self) -> Option<<U as RefsOf<'v>>::Out>
    where
        NodeData<T, L, Recovery>: FlatMut<'v>,
        <NodeData<T, L, Recovery> as FlatMut<'v>>::Out: TakeEach<'v, U, Is>,
        U: RefsOf<'v>,
    {
        let node = self.here_recovery.take()?;
        let (slot, sub) = self
            .here_path
            .expect("a recovery layer belongs to a lent link path");
        let addr = NodeAddr::recovery(slot, sub.expect("a lent link path"));
        let (items, _) = node
            .data
            .flat_mut()
            .take_each(&mut Self::record(self.taken, addr));
        Some(items)
    }

    /// Take components `U` of the entry of the logical link `link`; `None`
    /// when there is no such entry among the others.
    pub fn link_entry<'s, U, Is>(&'s mut self, link: &LinkIdOf<T>) -> Option<<U as RefsOf<'s>>::Out>
    where
        NodeData<T, L, LinkEntry>: FlatMut<'s>,
        <NodeData<T, L, LinkEntry> as FlatMut<'s>>::Out: TakeEach<'s, U, Is>,
        U: RefsOf<'s>,
    {
        let Self { entries, taken, .. } = self;
        let (slot, node) =
            entries.find(|n| matches!(&n.key, NodeKey::LinkEntry(l) if l == link))?;
        let (items, _) = node
            .data
            .flat_mut()
            .take_each(&mut Self::record(taken, NodeAddr::entry(slot)));
        Some(items)
    }

    /// Take components `U` of the logical path `path`; `None` when it is not
    /// among the others.
    pub fn logical_path<'s, U, Is>(
        &'s mut self,
        path: &PathKey<L>,
    ) -> Option<<U as RefsOf<'s>>::Out>
    where
        NodeData<T, L, LogicalPath>: FlatMut<'s>,
        <NodeData<T, L, LogicalPath> as FlatMut<'s>>::Out: TakeEach<'s, U, Is>,
        U: RefsOf<'s>,
    {
        let Self {
            logical_paths,
            taken,
            ..
        } = self;
        let (slot, node) =
            logical_paths.find(|n| matches!(&n.node.key, NodeKey::LogicalPath(p) if p == path))?;
        let addr = NodeAddr::logical_path(slot);
        let (items, _) = node
            .node
            .data
            .flat_mut()
            .take_each(&mut Self::record(taken, addr));
        Some(items)
    }

    /// Take components `U` of the link path (`path`, `link`); `None` when it
    /// is not among the others.
    pub fn link_path<'s, U, Is>(
        &'s mut self,
        path: &PathKey<L>,
        link: &LinkIdOf<T>,
    ) -> Option<<U as RefsOf<'s>>::Out>
    where
        NodeData<T, L, LinkPath>: FlatMut<'s>,
        <NodeData<T, L, LinkPath> as FlatMut<'s>>::Out: TakeEach<'s, U, Is>,
        U: RefsOf<'s>,
    {
        let key = NodeKey::LinkPath(path.clone(), link.clone());
        let Self {
            logical_paths,
            here_link_paths,
            here_path,
            taken,
            ..
        } = self;
        let here = here_path.map(|(slot, _)| slot);
        let (addr, node) = match here_link_paths.find(|n| n.key == key) {
            Some((sub, node)) if here.is_some() => {
                (NodeAddr::link_path(here.unwrap_or(0), sub), node)
            }
            _ => {
                let (slot, logical) = logical_paths
                    .find(|n| matches!(&n.node.key, NodeKey::LogicalPath(p) if p == path))?;
                let (sub, node) = logical
                    .link_paths
                    .iter_mut()
                    .enumerate()
                    .find_map(|(sub, n)| n.as_mut().filter(|n| n.key == key).map(|n| (sub, n)))?;
                (NodeAddr::link_path(slot, sub), node)
            }
        };
        let (items, _) = node
            .data
            .flat_mut()
            .take_each(&mut Self::record(taken, addr));
        Some(items)
    }

    /// The node of the link path (`path`, `link`) among the others, with its
    /// address.
    fn find_link_path(
        &mut self,
        path: &PathKey<L>,
        link: &LinkIdOf<T>,
    ) -> Option<(NodeAddr, &mut LinkPathNodeOf<T, L, B>)> {
        let key = NodeKey::LinkPath(path.clone(), link.clone());
        let Self {
            logical_paths,
            here_link_paths,
            here_path,
            ..
        } = self;
        if let Some((slot, _)) = *here_path
            && let Some((sub, node)) = here_link_paths.find(|n| n.key == key)
        {
            return Some((NodeAddr::link_path(slot, sub), node));
        }
        let (slot, logical) =
            logical_paths.find(|n| matches!(&n.node.key, NodeKey::LogicalPath(p) if p == path))?;
        let (sub, node) = logical
            .link_paths
            .iter_mut()
            .enumerate()
            .find_map(|(sub, n)| n.as_mut().filter(|n| n.key == key).map(|n| (sub, n)))?;
        Some((NodeAddr::link_path(slot, sub), node))
    }

    /// Take components `U` of the recovery layer of the link path (`path`,
    /// `link`) among the others, and hand them to `each` together with the
    /// others, read only: the recovery layers still reached from them are
    /// those of every link path but this one ([`each_recovery`](Self::each_recovery)).
    /// `None` when the link path is not among the others or has no
    /// recovery layer.
    ///
    /// The layer is out of its link path while `each` runs and goes back
    /// afterwards.
    pub fn with_recovery_at<U, Is, R>(
        &mut self,
        path: &PathKey<L>,
        link: &LinkIdOf<T>,
        each: impl for<'x> FnOnce(<U as RefsOf<'x>>::Out, &'x Self) -> R,
    ) -> Option<R>
    where
        for<'x> NodeData<T, L, Recovery>: FlatMut<'x>,
        for<'x> <NodeData<T, L, Recovery> as FlatMut<'x>>::Out: TakeEach<'x, U, Is>,
        for<'x> U: RefsOf<'x>,
    {
        let (addr, node) = self.find_link_path(path, link)?;
        let mut layer = node.child.take()?;
        let addr = NodeAddr::recovery(addr.slot, addr.sub);
        let (items, _) = layer
            .data
            .flat_mut()
            .take_each(&mut Self::record(self.taken, addr));
        let result = each(items, &*self);
        let (_, node) = self
            .find_link_path(path, link)
            .expect("the link path is still there");
        node.child = Some(layer);
        Some(result)
    }

    /// Read the recovery layer of every link path among the others that has
    /// one, with the layer's key; and the lent link path's own, unless it
    /// was taken. Nothing is taken.
    pub fn each_recovery<'s>(
        &'s self,
        mut each: impl FnMut(&'s NodeKeyOf<T, L>, &'s NodeData<T, L, Recovery>),
    ) {
        if let Some(own) = self.here_recovery.as_deref() {
            each(&own.key, &own.data);
        }
        let mut visit = |node: &'s LinkPathNodeOf<T, L, B>| {
            if let Some(recovery) = node.child.as_ref() {
                each(&recovery.key, &recovery.data);
            }
        };
        if self.here_path.is_some() {
            for (_, node) in self.here_link_paths.indexed_ref() {
                visit(node);
            }
        }
        for (_, logical) in self.logical_paths.indexed_ref() {
            for node in logical.link_paths.iter().flatten() {
                visit(node);
            }
        }
    }

    /// Take components `U` of every other link path, of every logical path,
    /// and hand them to `each` with the link path's key.
    pub fn each_link_path<'s, U, Is>(
        &'s mut self,
        mut each: impl FnMut(&NodeKeyOf<T, L>, <U as RefsOf<'s>>::Out),
    ) where
        NodeData<T, L, LinkPath>: FlatMut<'s>,
        <NodeData<T, L, LinkPath> as FlatMut<'s>>::Out: TakeEach<'s, U, Is>,
        U: RefsOf<'s>,
    {
        let Self {
            logical_paths,
            here_link_paths,
            here_path,
            taken,
            ..
        } = self;
        if let Some((slot, _)) = *here_path {
            for (sub, node) in here_link_paths.indexed() {
                let (items, _) = node
                    .data
                    .flat_mut()
                    .take_each(&mut Self::record(taken, NodeAddr::link_path(slot, sub)));
                each(&node.key, items);
            }
        }
        for (slot, logical) in logical_paths.indexed() {
            for (sub, node) in logical.link_paths.iter_mut().enumerate() {
                let Some(node) = node else { continue };
                let (items, _) = node
                    .data
                    .flat_mut()
                    .take_each(&mut Self::record(taken, NodeAddr::link_path(slot, sub)));
                each(&node.key, items);
            }
        }
    }

    /// Read the component `X` of every other link path, of every logical
    /// path; nothing is taken.
    pub fn each_link_path_read<'s, X, I>(&'s mut self, mut each: impl FnMut(&NodeKeyOf<T, L>, &X))
    where
        NodeData<T, L, LinkPath>: FlatMut<'s>,
        <NodeData<T, L, LinkPath> as FlatMut<'s>>::Out: GetAt<X, I>,
    {
        let Self {
            logical_paths,
            here_link_paths,
            here_path,
            ..
        } = self;
        if here_path.is_some() {
            for (_, node) in here_link_paths.indexed() {
                let flat = node.data.flat_mut();
                each(&node.key, flat.get_at());
            }
        }
        for (_, logical) in logical_paths.indexed() {
            for node in logical.link_paths.iter_mut().flatten() {
                let flat = node.data.flat_mut();
                each(&node.key, flat.get_at());
            }
        }
    }

    /// Read the component `X` of the recovery layer of every other link
    /// path, of every logical path, with `None` for a link path without one;
    /// and of the lent link path's own, with the key of the layer, unless it
    /// was taken. Nothing is taken.
    pub fn each_recovery_read<'s, X, I>(
        &'s mut self,
        mut each: impl FnMut(&NodeKeyOf<T, L>, Option<&X>),
    ) where
        NodeData<T, L, Recovery>: FlatMut<'s>,
        <NodeData<T, L, Recovery> as FlatMut<'s>>::Out: GetAt<X, I>,
    {
        let Self {
            logical_paths,
            here_link_paths,
            here_path,
            here_recovery,
            ..
        } = self;
        if let Some(own) = here_recovery.as_deref_mut() {
            let flat = own.data.flat_mut();
            each(&own.key, Some(flat.get_at()));
        }
        let mut visit = |node: &'s mut LinkPathNodeOf<T, L, B>| match node.child.as_mut() {
            Some(recovery) => {
                let flat = recovery.data.flat_mut();
                each(&node.key, Some(flat.get_at()));
            }
            None => each(&node.key, None),
        };
        if here_path.is_some() {
            for (_, node) in here_link_paths.indexed() {
                visit(node);
            }
        }
        for (_, logical) in logical_paths.indexed() {
            for node in logical.link_paths.iter_mut().flatten() {
                visit(node);
            }
        }
    }

    /// The keys of the other link paths, of every logical path.
    pub fn link_path_keys(&self) -> impl Iterator<Item = &NodeKeyOf<T, L>> {
        let here = self
            .here_path
            .is_some()
            .then(|| self.here_link_paths.indexed_ref().map(|(_, n)| &n.key))
            .into_iter()
            .flatten();
        let others = self
            .logical_paths
            .indexed_ref()
            .flat_map(|(_, l)| l.link_paths.iter().flatten().map(|n| &n.key));
        here.chain(others)
    }
}
