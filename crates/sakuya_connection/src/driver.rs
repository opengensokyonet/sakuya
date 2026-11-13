//! The connection driver: the future that is the connection.
//!
//! Each call has a waker that only marks the call's position in its node's
//! head; a node enters the ready queue at its first mark, and the outer
//! waker is called at the first wake since the poll began. A poll goes once
//! through the nodes queued before it began, polls each marked call, and
//! after each lend applies the request it handed over and rereads what reads
//! the components it took mutably, round after round; then it runs the
//! expiries that are due, and sleeps until the earliest deadline.
use core::{any::TypeId, future::Future, marker::PhantomData, pin::Pin};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

use futures_util::task::AtomicWaker;
use sakuya_link::Link;
use sakuya_stream::connection::AbortCause;
use sakuya_wire::parts::HNil;

use crate::{
    call::{CallPositions, CallStep, NodeCalls, NodeLoan, PartsCallBundle, TreeCalls},
    clock::{ConnectionChoices, InstantOf, LinkIdOf, MonotonicClock},
    component::{BuildNode, NodePositions, ReadSet, RequestOf},
    layer::{
        Connection, Established, EstablishedArgs, Layer, LinkEntry, LinkEntryArgs, LinkPath,
        LinkPathArgs, LogicalPath, LogicalPathArgs, NodeKey, NodeKeyOf, Recovery, RecoveryArgs,
    },
    others::OtherNodes,
    request::StructureRequest,
    share::{ConnectionArgsOf, LineageLists, NodeData, PathKey},
    take::{Lineage, TakenPositions},
    tree::{Around, ConnectionTree, Lent, LogicalPathNode, Node, NodeAddr, Records, WakeMarks},
};

/// What every waker of a connection shares.
struct Shared {
    /// The nodes with marks, in the order of their first mark.
    ready: Mutex<VecDeque<NodeAddr>>,
    /// Whether the outer waker was called since this poll began.
    notified: AtomicBool,
    /// The waker of whoever polls the connection.
    outer: AtomicWaker,
    /// The connection has ended: wakes do nothing.
    closed: AtomicBool,
}

impl Shared {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            ready: Mutex::new(VecDeque::new()),
            notified: AtomicBool::new(false),
            outer: AtomicWaker::new(),
            closed: AtomicBool::new(false),
        })
    }
    fn queue(&self) -> std::sync::MutexGuard<'_, VecDeque<NodeAddr>> {
        self.ready
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
    /// Mark positions of a node, then call the outer waker if it was not
    /// called since this poll began. Every mark is followed by this check,
    /// so when a poll returns with marks left the outer waker was called.
    fn wake(&self, marks: &WakeMarks, addr: NodeAddr, bits: u64) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        if marks.mark(bits) {
            self.queue().push_back(addr);
        }
        if !self.notified.swap(true, Ordering::SeqCst) {
            self.outer.wake();
        }
    }
}

/// The waker of one call: it marks the call's position in its node.
struct PositionWaker {
    shared: Arc<Shared>,
    marks: Arc<WakeMarks>,
    addr: NodeAddr,
    position: usize,
}

impl Wake for PositionWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.shared.wake(&self.marks, self.addr, 1 << self.position);
    }
}

/// The driver's tables, made once from the list of parts.
struct Tables {
    /// How many data components a node of each layer has.
    data: [usize; 6],
    /// How many calls a node of each layer has.
    calls: [usize; 6],
    /// For each layer and data position: who reads it, as (layer, position).
    readers: [Vec<Vec<(usize, usize)>>; 6],
    /// An upper bound of the rounds of rereads.
    positions: usize,
}

impl Tables {
    fn new(
        types: [Vec<TypeId>; 6],
        data_reads: [Vec<ReadSet>; 6],
        call_reads: [Vec<ReadSet>; 6],
    ) -> Self {
        for l in 0..6 {
            assert!(
                types[l].len() + call_reads[l].len() <= 64,
                "a node has at most 64 positions"
            );
        }
        let readers = core::array::from_fn(|w| {
            types[w]
                .iter()
                .map(|&ty| {
                    let mut out = Vec::new();
                    for r in 0..6 {
                        for (q, reads) in data_reads[r].iter().enumerate() {
                            if reads.contains(ty) {
                                out.push((r, q));
                            }
                        }
                        for (c, reads) in call_reads[r].iter().enumerate() {
                            if reads.contains(ty) {
                                out.push((r, types[r].len() + c));
                            }
                        }
                    }
                    out
                })
                .collect()
        });
        Self {
            data: core::array::from_fn(|l| types[l].len()),
            calls: core::array::from_fn(|l| call_reads[l].len()),
            readers,
            positions: (0..6).map(|l| types[l].len() + call_reads[l].len()).sum(),
        }
    }
}

type Bundle<T, L, P> = PartsCallBundle<T, L, P>;
/// The sleep until the earliest deadline, with that deadline.
type Sleeping<T> = (
    InstantOf<T>,
    Pin<Box<<<T as ConnectionChoices>::Clock as MonotonicClock>::Sleep>>,
);
/// A link path node of a composition whose call positions are given by layer.
type LinkNode<T, L, Pc, Pe, Pl, Pk, Ps, Pr> =
    crate::tree::LinkPathNodeOf<T, L, PartsCallBundle<T, L, (Pc, Pe, Pl, Pk, Ps, Pr)>>;
/// The call positions of the six layers, as one type.
type Six<Pc, Pe, Pl, Pk, Ps, Pr> = (Pc, Pe, Pl, Pk, Ps, Pr);

/// A connection: the tree of its nodes and the driver of their calls, as
/// one future that ends when the connection ends. Dropped before that, it
/// ends its nodes as it is dropped, unless a panic unwound through it.
///
/// `T` is the choices of the composition, `L` the list of parts. `P`, `W`
/// and `Bw` are what the calls, the data components and their builds infer
/// their positions by; they are inferred where the connection is made.
pub struct ConnectionDriver<T: ConnectionChoices, L: TreeCalls<T, P>, P: CallPositions, W, Bw>
where
    for<'v> L: LineageLists<'v, T>,
{
    tree: ConnectionTree<T, L, Bundle<T, L, P>>,
    shared: Arc<Shared>,
    clock: T::Clock,
    sleep: Option<Sleeping<T>>,
    timers: BTreeSet<(InstantOf<T>, NodeAddr, usize)>,
    deadlines: BTreeMap<(NodeAddr, usize), InstantOf<T>>,
    lineage_taken: TakenPositions,
    nodes_taken: Vec<(NodeAddr, usize)>,
    tables: Tables,
    ended: bool,
    /// The driver's own code runs: set where a poll or the making of the
    /// connection begins, cleared where it returns. Still set when the
    /// driver is dropped, a panic unwound through it.
    running: bool,
    /// What a drop before the end runs. `Drop` cannot be implemented with
    /// the bounds the components and their builds need, so the function is
    /// taken where the connection is made, which has them.
    on_drop: fn(&mut Self),
    positions: PhantomData<fn() -> (W, Bw)>,
}

/// A connection dropped before it ended ends here, without a closing
/// period and with nothing sent: every data component is told that the
/// future is dropped
/// ([`DataComponent::future_dropped`](crate::component::DataComponent::future_dropped))
/// with [`AbortCause::DriverDropped`], then every node ends, each component
/// with its end action.
///
/// When a panic unwound through a poll or through the making of the
/// connection, only the data components of the connection node are told,
/// with [`AbortCause::Panicked`], so that the reason is written where the
/// connection keeps it; no end action runs, and what the panic left of the
/// tree is dropped as it is. The driver tells the two apart by itself: it
/// notes that its own code runs where that begins and where it returns, so
/// a driver dropped after its poll panicked has ended by the panic, and one
/// dropped while a panic from elsewhere unwinds was only dropped.
impl<T: ConnectionChoices, L: TreeCalls<T, P>, P: CallPositions, W, Bw> Drop
    for ConnectionDriver<T, L, P, W, Bw>
where
    for<'v> L: LineageLists<'v, T>,
{
    fn drop(&mut self) {
        if !self.ended {
            (self.on_drop)(self);
        }
    }
}

// Nothing in the driver is pinned structurally: the calls and the sleep are
// boxed.
impl<T: ConnectionChoices, L: TreeCalls<T, P>, P: CallPositions, W, Bw> Unpin
    for ConnectionDriver<T, L, P, W, Bw>
where
    for<'v> L: LineageLists<'v, T>,
{
}

/// End the data `$data` of a node of the layer `$lv` (data positions
/// `$b`) whose parent is the connection node, with the key `$key`: its
/// parents are the connection's lend, with the other nodes.
macro_rules! end_under_connection {
    ($self:ident, $lv:ident, $b:ident, $data:expr, $key:expr, $now:expr) => {{
        let Self {
            tree,
            lineage_taken,
            nodes_taken,
            ..
        } = $self;
        let records = Records {
            lineage: lineage_taken,
            nodes: nodes_taken,
            now: $now,
        };
        let Lent {
            mut lineage,
            others,
            ..
        } = tree.lend_connection(records);
        let mut others = others.ending($key);
        <L as BuildNode<T, L, $lv, $b>>::end_node($data, &mut lineage, &mut others);
    }};
}

/// Run `$go!` for the layer of `$addr`, with the name of the tree's lend,
/// its arguments, the layer, its data positions and its call positions.
macro_rules! by_layer {
    ($addr:expr, $go:ident) => {
        match $addr.layer {
            0 => $go!(lend_connection(), Connection, Hw, Connection),
            1 => $go!(lend_entry($addr.slot), LinkEntry, He, LinkEntry),
            2 => $go!(lend_logical_path($addr.slot), LogicalPath, Hl, LogicalPath),
            3 => $go!(
                lend_link_path($addr.slot, $addr.sub),
                LinkPath,
                Hk,
                LinkPath
            ),
            4 => $go!(lend_established(), Established, Hs, Established),
            5 => $go!(lend_recovery($addr.slot, $addr.sub), Recovery, Hr, Recovery),
            _ => unreachable!("six layers"),
        }
    };
}

/// The changes a lend or a structure request made: (node, position).
type Changes = Vec<(NodeAddr, usize)>;

impl<T, L, Pc, Pe, Pl, Pk, Ps, Pr, Hw, He, Hl, Hk, Hs, Hr, Bw, Be, Bl, Bk, Bs, Br>
    ConnectionDriver<
        T,
        L,
        (Pc, Pe, Pl, Pk, Ps, Pr),
        (Hw, He, Hl, Hk, Hs, Hr),
        (Bw, Be, Bl, Bk, Bs, Br),
    >
where
    T: ConnectionChoices,
    for<'v> L: LineageLists<'v, T>,
    L: TreeCalls<T, (Pc, Pe, Pl, Pk, Ps, Pr)>
        + NodeCalls<T, L, Connection, Pc>
        + NodeCalls<T, L, LinkEntry, Pe>
        + NodeCalls<T, L, LogicalPath, Pl>
        + NodeCalls<T, L, LinkPath, Pk>
        + NodeCalls<T, L, Established, Ps>
        + NodeCalls<T, L, Recovery, Pr>
        + BuildNode<T, L, Connection, Bw>
        + BuildNode<T, L, LinkEntry, Be>
        + BuildNode<T, L, LogicalPath, Bl>
        + BuildNode<T, L, LinkPath, Bk>
        + BuildNode<T, L, Established, Bs>
        + BuildNode<T, L, Recovery, Br>,
    Pc: 'static,
    Pe: 'static,
    Pl: 'static,
    Pk: 'static,
    Ps: 'static,
    Pr: 'static,
    NodeData<T, L, Connection>: NodePositions<T, L, Connection, Hw>,
    NodeData<T, L, LinkEntry>: NodePositions<T, L, LinkEntry, He>,
    NodeData<T, L, LogicalPath>: NodePositions<T, L, LogicalPath, Hl>,
    NodeData<T, L, LinkPath>: NodePositions<T, L, LinkPath, Hk>,
    NodeData<T, L, Established>: NodePositions<T, L, Established, Hs>,
    NodeData<T, L, Recovery>: NodePositions<T, L, Recovery, Hr>,
{
    /// Make a connection with its first logical path and its first link
    /// path. Every call starts woken; every deadline is read.
    ///
    /// `connection` is what the parts declare the connection node needs;
    /// `link` carries the clone of the first logical link, which goes into
    /// its entry.
    pub fn new(
        clock: T::Clock,
        mut connection: ConnectionArgsOf<T, L>,
        mut path: LogicalPathArgs<PathKey<L>>,
        link: LinkPathArgs<PathKey<L>, T::Link>,
    ) -> Self {
        let mut types: [Vec<TypeId>; 6] = Default::default();
        let mut data_reads: [Vec<ReadSet>; 6] = Default::default();
        let mut call_reads: [Vec<ReadSet>; 6] = Default::default();
        macro_rules! tables {
            ($lend:ident($($a:expr),*), $lv:ident, $h:ident, $c:ident) => {{
                let l = <$lv as Layer>::INDEX;
                <NodeData<T, L, $lv> as NodePositions<T, L, $lv, $h>>::types(&mut types[l]);
                <NodeData<T, L, $lv> as NodePositions<T, L, $lv, $h>>::reads(&mut data_reads[l]);
                <L as NodeCalls<T, L, $lv, <Six<Pc, Pe, Pl, Pk, Ps, Pr> as CallPositions>::$c>>::reads(&mut call_reads[l]);
            }};
        }
        for layer in 0..6 {
            let addr = NodeAddr {
                layer,
                slot: 0,
                sub: 0,
            };
            by_layer!(addr, tables);
        }
        let tables = Tables::new(types, data_reads, call_reads);
        let now = clock.now();
        let mut driver = Self {
            tree: ConnectionTree {
                connection: None,
                entries: Vec::new(),
                logical_paths: Vec::new(),
            },
            shared: Shared::new(),
            clock,
            sleep: None,
            timers: BTreeSet::new(),
            deadlines: BTreeMap::new(),
            lineage_taken: TakenPositions::default(),
            nodes_taken: Vec::new(),
            tables,
            ended: false,
            running: true,
            on_drop: Self::end_dropped,
            positions: PhantomData,
        };
        let mut changes = Changes::new();
        driver.build_connection(&mut connection, now, &mut changes);
        driver.build_logical_path(&mut path, now, &mut changes);
        driver.build_link_path(link, now, &mut changes);
        let mut todo = Vec::new();
        driver.readers(&changes, None, &mut todo);
        driver.settle(todo, now);
        driver.running = false;
        driver
    }

    // ---- where things are ----

    #[allow(clippy::type_complexity)] // a link path node of the composition
    fn link_node(&self, addr: NodeAddr) -> Option<&LinkNode<T, L, Pc, Pe, Pl, Pk, Ps, Pr>> {
        self.tree
            .logical_paths
            .get(addr.slot)?
            .as_ref()?
            .link_paths
            .get(addr.sub)?
            .as_ref()
    }

    fn marks_at(&self, addr: NodeAddr) -> Option<Arc<WakeMarks>> {
        let tree = &self.tree;
        let connection = tree.connection.as_ref()?;
        Some(match addr.layer {
            0 => connection.marks.clone(),
            1 => tree.entries.get(addr.slot)?.as_ref()?.marks.clone(),
            2 => tree
                .logical_paths
                .get(addr.slot)?
                .as_ref()?
                .node
                .marks
                .clone(),
            3 => self.link_node(addr)?.marks.clone(),
            4 => connection.child.as_ref()?.marks.clone(),
            5 => self.link_node(addr)?.child.as_ref()?.marks.clone(),
            _ => unreachable!("six layers"),
        })
    }

    fn alive(&self, addr: NodeAddr) -> bool {
        self.marks_at(addr).is_some()
    }

    /// The nodes above a node, from the connection down.
    fn ancestors(&self, addr: NodeAddr) -> Vec<NodeAddr> {
        let link = |out: &mut Vec<NodeAddr>| {
            if let Some(node) = self.link_node(addr) {
                out.push(NodeAddr::entry(node.entry));
                out.push(NodeAddr::logical_path(addr.slot));
            }
        };
        let mut out = vec![NodeAddr::CONNECTION];
        match addr.layer {
            0 => out.clear(),
            3 => link(&mut out),
            5 => {
                link(&mut out);
                out.push(NodeAddr::link_path(addr.slot, addr.sub));
            }
            _ => {}
        }
        out
    }

    /// Every node.
    fn live(&self) -> Vec<NodeAddr> {
        let mut out = Vec::new();
        let Some(connection) = self.tree.connection.as_ref() else {
            return out;
        };
        out.push(NodeAddr::CONNECTION);
        if connection.child.is_some() {
            out.push(NodeAddr::ESTABLISHED);
        }
        for (slot, entry) in self.tree.entries.iter().enumerate() {
            if entry.is_some() {
                out.push(NodeAddr::entry(slot));
            }
        }
        for (slot, path) in self.tree.logical_paths.iter().enumerate() {
            let Some(path) = path else { continue };
            out.push(NodeAddr::logical_path(slot));
            for (sub, link) in path.link_paths.iter().enumerate() {
                let Some(link) = link else { continue };
                out.push(NodeAddr::link_path(slot, sub));
                if link.child.is_some() {
                    out.push(NodeAddr::recovery(slot, sub));
                }
            }
        }
        out
    }

    /// The nodes of `layer` that a change in `addr` concerns: the node
    /// itself, the one above it, or those below it.
    fn scope(&self, addr: NodeAddr, layer: usize, out: &mut Vec<NodeAddr>) {
        if layer == addr.layer {
            out.push(addr);
            return;
        }
        if let Some(above) = self.ancestors(addr).into_iter().find(|a| a.layer == layer) {
            out.push(above);
            return;
        }
        let under = |a: &NodeAddr, entry: Option<usize>| match addr.layer {
            0 => true,
            1 => entry == Some(addr.slot),
            2 => a.slot == addr.slot,
            3 => a.slot == addr.slot && a.sub == addr.sub,
            _ => false,
        };
        for a in self.live() {
            if a.layer != layer {
                continue;
            }
            let entry = matches!(a.layer, 3 | 5)
                .then(|| self.link_node(a).map(|n| n.entry))
                .flatten();
            if under(&a, entry) {
                out.push(a);
            }
        }
    }

    /// Who reads the changes, as (node, position); `skip` is a call's own
    /// position, for the changes of its own lend.
    fn readers(
        &self,
        changes: &[(NodeAddr, usize)],
        skip: Option<(NodeAddr, usize)>,
        out: &mut Vec<(NodeAddr, usize)>,
    ) {
        let mut nodes = Vec::new();
        for &(addr, position) in changes {
            for &(layer, reader) in &self.tables.readers[addr.layer][position] {
                nodes.clear();
                self.scope(addr, layer, &mut nodes);
                for &node in &nodes {
                    if skip != Some((node, reader)) {
                        out.push((node, reader));
                    }
                }
            }
        }
    }

    /// The changes recorded by the lend of `addr`: the lineage's takes by
    /// position, the other nodes' takes.
    fn recorded(&mut self, addr: NodeAddr) -> Changes {
        let mut lineage = self.ancestors(addr);
        lineage.push(addr);
        self.recorded_for(&lineage)
    }

    /// The changes recorded by a lend whose lineage is the nodes `lineage`.
    fn recorded_for(&mut self, lineage: &[NodeAddr]) -> Changes {
        let mut out: Changes = std::mem::take(&mut self.nodes_taken);
        for at in self.lineage_taken.drain() {
            let mut at = at;
            for &node in lineage {
                let len = self.tables.data[node.layer];
                if at < len {
                    out.push((node, at));
                    break;
                }
                at -= len;
            }
        }
        out
    }

    // ---- what a lend runs ----

    fn deadline(
        &mut self,
        addr: NodeAddr,
        position: usize,
        now: InstantOf<T>,
    ) -> Option<InstantOf<T>> {
        let r = self.tables.data[addr.layer] - 1 - position;
        let Self {
            tree,
            lineage_taken,
            nodes_taken,
            ..
        } = self;
        macro_rules! go {
            ($lend:ident($($a:expr),*), $lv:ident, $h:ident, $c:ident) => {{
                let lent = tree.$lend($($a,)* Records { lineage: lineage_taken, nodes: nodes_taken, now });
                <NodeData<T, L, $lv> as NodePositions<T, L, $lv, $h>>::deadline_from_end(&lent.lineage, r)
            }};
        }
        let deadline = by_layer!(addr, go);
        self.lineage_taken.clear();
        self.nodes_taken.clear();
        deadline
    }

    fn expire(
        &mut self,
        addr: NodeAddr,
        position: usize,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let r = self.tables.data[addr.layer] - 1 - position;
        let Self {
            tree,
            lineage_taken,
            nodes_taken,
            ..
        } = self;
        macro_rules! go {
            ($lend:ident($($a:expr),*), $lv:ident, $h:ident, $c:ident) => {{
                let mut lent = tree.$lend($($a,)* Records { lineage: lineage_taken, nodes: nodes_taken, now });
                <NodeData<T, L, $lv> as NodePositions<T, L, $lv, $h>>::expire_from_end(lent.lineage, &mut lent.others, r, now)
            }};
        }
        by_layer!(addr, go)
    }

    fn reread_action(
        &mut self,
        addr: NodeAddr,
        position: usize,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let r = self.tables.data[addr.layer] - 1 - position;
        let Self {
            tree,
            lineage_taken,
            nodes_taken,
            ..
        } = self;
        macro_rules! go {
            ($lend:ident($($a:expr),*), $lv:ident, $h:ident, $c:ident) => {{
                let mut lent = tree.$lend($($a,)* Records { lineage: lineage_taken, nodes: nodes_taken, now });
                <NodeData<T, L, $lv> as NodePositions<T, L, $lv, $h>>::reread_from_end(lent.lineage, &mut lent.others, r, now)
            }};
        }
        by_layer!(addr, go)
    }

    fn poll_call(
        &mut self,
        addr: NodeAddr,
        position: usize,
        now: InstantOf<T>,
    ) -> CallStep<RequestOf<T, L>> {
        let data = self.tables.data[addr.layer];
        let index = position - data;
        let r = self.tables.calls[addr.layer] - 1 - index;
        let Self {
            tree,
            lineage_taken,
            nodes_taken,
            ..
        } = self;
        macro_rules! go {
            ($lend:ident($($a:expr),*), $lv:ident, $h:ident, $c:ident) => {{
                let lent = tree.$lend($($a,)* Records { lineage: lineage_taken, nodes: nodes_taken, now });
                let waker = lent.wakers[index].clone();
                let mut cx = Context::from_waker(&waker);
                let loan = NodeLoan { lineage: lent.lineage, others: lent.others };
                <L as NodeCalls<T, L, $lv, <Six<Pc, Pe, Pl, Pk, Ps, Pr> as CallPositions>::$c>>::poll_from_end::<Bundle<T, L, Six<Pc, Pe, Pl, Pk, Ps, Pr>>>(&mut lent.calls.0, r, loan, &mut cx)
            }};
        }
        by_layer!(addr, go)
    }

    // ---- the timer table ----

    fn set_deadline(&mut self, addr: NodeAddr, position: usize, at: Option<InstantOf<T>>) {
        if let Some(old) = self.deadlines.remove(&(addr, position)) {
            self.timers.remove(&(old, addr, position));
        }
        if let Some(at) = at {
            self.deadlines.insert((addr, position), at);
            self.timers.insert((at, addr, position));
        }
    }

    fn drop_deadlines(&mut self, addr: NodeAddr) {
        for position in 0..self.tables.data[addr.layer] {
            self.set_deadline(addr, position, None);
        }
    }

    fn read_deadline(&mut self, addr: NodeAddr, position: usize, now: InstantOf<T>) {
        let at = self.deadline(addr, position, now);
        self.set_deadline(addr, position, at);
    }

    // ---- nodes come and go ----

    fn wakers(&self, addr: NodeAddr, marks: &Arc<WakeMarks>) -> Vec<Waker> {
        let data = self.tables.data[addr.layer];
        (0..self.tables.calls[addr.layer])
            .map(|index| {
                Waker::from(Arc::new(PositionWaker {
                    shared: self.shared.clone(),
                    marks: marks.clone(),
                    addr,
                    position: data + index,
                }))
            })
            .collect()
    }

    fn node<Data, Calls, Child>(
        &self,
        addr: NodeAddr,
        key: NodeKeyOf<T, L>,
        entry: usize,
        data: Data,
        calls: Calls,
        child: Child,
    ) -> Node<NodeKeyOf<T, L>, Data, Calls, Child> {
        let marks = Arc::new(WakeMarks::default());
        let wakers = self.wakers(addr, &marks);
        Node {
            key,
            marks,
            entry,
            data,
            calls,
            child,
            wakers,
        }
    }

    /// A new node: its calls start woken, its deadlines are read, and every
    /// one of its components counts as changed.
    fn started(&mut self, addr: NodeAddr, now: InstantOf<T>, changes: &mut Changes) {
        let (data, calls) = (self.tables.data[addr.layer], self.tables.calls[addr.layer]);
        if calls > 0 {
            let marks = self.marks_at(addr).expect("a node just made");
            self.shared
                .wake(&marks, addr, ((1u64 << calls) - 1) << data);
        }
        for position in 0..data {
            self.read_deadline(addr, position, now);
            changes.push((addr, position));
        }
    }

    /// A node about to end: every one of its components counts as changed
    /// for what reads them, and its deadlines go.
    fn ending(&mut self, addr: NodeAddr, todo: &mut Vec<(NodeAddr, usize)>) {
        let changes: Changes = (0..self.tables.data[addr.layer])
            .map(|p| (addr, p))
            .collect();
        self.readers(&changes, None, todo);
        self.drop_deadlines(addr);
    }

    fn free_slot<X>(slots: &mut Vec<Option<X>>) -> usize {
        match slots.iter().position(Option::is_none) {
            Some(slot) => slot,
            None => {
                slots.push(None);
                slots.len() - 1
            }
        }
    }

    fn build_connection(
        &mut self,
        args: &mut ConnectionArgsOf<T, L>,
        now: InstantOf<T>,
        changes: &mut Changes,
    ) {
        let data = <L as BuildNode<T, L, Connection, Bw>>::build_node(
            &mut Lineage::new(HNil, &mut self.lineage_taken),
            args,
        );
        self.lineage_taken.clear();
        let calls =
            crate::call::ConnectionCalls(<L as NodeCalls<T, L, Connection, Pc>>::start_all::<
                Bundle<T, L, Six<Pc, Pe, Pl, Pk, Ps, Pr>>,
            >(args));
        let node = self.node(
            NodeAddr::CONNECTION,
            NodeKey::Connection,
            0,
            data,
            calls,
            None,
        );
        self.tree.connection = Some(node);
        self.started(NodeAddr::CONNECTION, now, changes);
    }

    fn find_entry(&self, link: &LinkIdOf<T>) -> Option<usize> {
        self.tree.entries.iter().position(|e| {
            e.as_ref()
                .is_some_and(|e| matches!(&e.key, NodeKey::LinkEntry(l) if l == link))
        })
    }

    fn find_logical_path(&self, path: &PathKey<L>) -> Option<usize> {
        self.tree.logical_paths.iter().position(|p| {
            p.as_ref()
                .is_some_and(|p| matches!(&p.node.key, NodeKey::LogicalPath(k) if k == path))
        })
    }

    fn find_link_path(&self, path: &PathKey<L>, link: &LinkIdOf<T>) -> Option<NodeAddr> {
        let slot = self.find_logical_path(path)?;
        let paths = &self.tree.logical_paths[slot].as_ref()?.link_paths;
        let sub = paths.iter().position(|n| {
            n.as_ref()
                .is_some_and(|n| matches!(&n.key, NodeKey::LinkPath(_, l) if l == link))
        })?;
        Some(NodeAddr::link_path(slot, sub))
    }

    fn build_entry(&mut self, link: T::Link, now: InstantOf<T>, changes: &mut Changes) -> usize {
        let id = link.id().clone();
        let mut args = LinkEntryArgs { link: Some(link) };
        let slot = Self::free_slot(&mut self.tree.entries);
        let data = {
            let connection = self.tree.connection.as_mut().expect("the connection node");
            let mut parents =
                Lineage::new(L::connection(&mut connection.data), &mut self.lineage_taken);
            <L as BuildNode<T, L, LinkEntry, Be>>::build_node(&mut parents, &mut args)
        };
        changes.extend(self.recorded_for(&[NodeAddr::CONNECTION]));
        let calls =
            crate::call::LinkEntryCalls(<L as NodeCalls<T, L, LinkEntry, Pe>>::start_all::<
                Bundle<T, L, Six<Pc, Pe, Pl, Pk, Ps, Pr>>,
            >(&mut args));
        let addr = NodeAddr::entry(slot);
        let node = self.node(addr, NodeKey::LinkEntry(id), 0, data, calls, ());
        self.tree.entries[slot] = Some(node);
        self.started(addr, now, changes);
        slot
    }

    fn build_logical_path(
        &mut self,
        args: &mut LogicalPathArgs<PathKey<L>>,
        now: InstantOf<T>,
        changes: &mut Changes,
    ) {
        if self.find_logical_path(&args.path).is_some() {
            return;
        }
        let slot = Self::free_slot(&mut self.tree.logical_paths);
        let data = {
            let connection = self.tree.connection.as_mut().expect("the connection node");
            let mut parents =
                Lineage::new(L::connection(&mut connection.data), &mut self.lineage_taken);
            <L as BuildNode<T, L, LogicalPath, Bl>>::build_node(&mut parents, args)
        };
        changes.extend(self.recorded_for(&[NodeAddr::CONNECTION]));
        let calls =
            crate::call::LogicalPathCalls(<L as NodeCalls<T, L, LogicalPath, Pl>>::start_all::<
                Bundle<T, L, Six<Pc, Pe, Pl, Pk, Ps, Pr>>,
            >(args));
        let addr = NodeAddr::logical_path(slot);
        let node = self.node(
            addr,
            NodeKey::LogicalPath(args.path.clone()),
            0,
            data,
            calls,
            (),
        );
        self.tree.logical_paths[slot] = Some(LogicalPathNode {
            node,
            link_paths: Vec::new(),
        });
        self.started(addr, now, changes);
    }

    /// Build a link path. Without an entry for its logical link, the entry
    /// is built first and takes the clone of the link; otherwise the clone
    /// is dropped here.
    fn build_link_path(
        &mut self,
        request: LinkPathArgs<PathKey<L>, T::Link>,
        now: InstantOf<T>,
        changes: &mut Changes,
    ) {
        let LinkPathArgs { path, link } = request;
        let mut args = LinkPathArgs {
            path,
            link: link.id().clone(),
        };
        let Some(slot) = self.find_logical_path(&args.path) else {
            return;
        };
        if self.find_link_path(&args.path, &args.link).is_some() {
            return;
        }
        let entry = match self.find_entry(&args.link) {
            Some(entry) => entry,
            None => self.build_entry(link, now, changes),
        };
        let sub = Self::free_slot(
            &mut self.tree.logical_paths[slot]
                .as_mut()
                .expect("found")
                .link_paths,
        );
        let data = {
            let ConnectionTree {
                connection,
                entries,
                logical_paths,
            } = &mut self.tree;
            let connection = connection.as_mut().expect("the connection node");
            let entry_node = entries[entry].as_mut().expect("the entry");
            let path = logical_paths[slot].as_mut().expect("found");
            let mut parents = Lineage::new(
                L::link_path_parents(
                    &mut connection.data,
                    &mut entry_node.data,
                    &mut path.node.data,
                ),
                &mut self.lineage_taken,
            );
            <L as BuildNode<T, L, LinkPath, Bk>>::build_node(&mut parents, &mut args)
        };
        changes.extend(self.recorded_for(&[
            NodeAddr::CONNECTION,
            NodeAddr::entry(entry),
            NodeAddr::logical_path(slot),
        ]));
        let calls = crate::call::LinkPathCalls(<L as NodeCalls<T, L, LinkPath, Pk>>::start_all::<
            Bundle<T, L, Six<Pc, Pe, Pl, Pk, Ps, Pr>>,
        >(&mut args));
        let addr = NodeAddr::link_path(slot, sub);
        let node = self.node(
            addr,
            NodeKey::LinkPath(args.path.clone(), args.link.clone()),
            entry,
            data,
            calls,
            None,
        );
        self.tree.logical_paths[slot]
            .as_mut()
            .expect("found")
            .link_paths[sub] = Some(node);
        self.started(addr, now, changes);
    }

    fn build_established(
        &mut self,
        args: &mut EstablishedArgs,
        now: InstantOf<T>,
        changes: &mut Changes,
    ) {
        if self.tree.connection().child.is_some() {
            return;
        }
        let data = {
            let connection = self.tree.connection.as_mut().expect("the connection node");
            let mut parents =
                Lineage::new(L::connection(&mut connection.data), &mut self.lineage_taken);
            <L as BuildNode<T, L, Established, Bs>>::build_node(&mut parents, args)
        };
        changes.extend(self.recorded_for(&[NodeAddr::CONNECTION]));
        let calls =
            crate::call::EstablishedCalls(<L as NodeCalls<T, L, Established, Ps>>::start_all::<
                Bundle<T, L, Six<Pc, Pe, Pl, Pk, Ps, Pr>>,
            >(args));
        let node = self.node(
            NodeAddr::ESTABLISHED,
            NodeKey::Established,
            0,
            data,
            calls,
            (),
        );
        self.tree.connection().child = Some(node);
        self.started(NodeAddr::ESTABLISHED, now, changes);
    }

    fn build_recovery(
        &mut self,
        args: &mut RecoveryArgs<PathKey<L>, LinkIdOf<T>>,
        now: InstantOf<T>,
        changes: &mut Changes,
    ) {
        let Some(link) = self.find_link_path(&args.path, &args.link) else {
            return;
        };
        if self.link_node(link).is_some_and(|n| n.child.is_some()) {
            return;
        }
        let data = {
            let ConnectionTree {
                connection,
                entries,
                logical_paths,
            } = &mut self.tree;
            let connection = connection.as_mut().expect("the connection node");
            let path = logical_paths[link.slot].as_mut().expect("found");
            let link_node = path.link_paths[link.sub].as_mut().expect("found");
            let entry_node = entries[link_node.entry].as_mut().expect("the entry");
            let mut parents = Lineage::new(
                L::link_path(
                    &mut connection.data,
                    &mut entry_node.data,
                    &mut path.node.data,
                    &mut link_node.data,
                ),
                &mut self.lineage_taken,
            );
            <L as BuildNode<T, L, Recovery, Br>>::build_node(&mut parents, args)
        };
        let mut lineage = self.ancestors(link);
        lineage.push(link);
        changes.extend(self.recorded_for(&lineage));
        let calls = crate::call::RecoveryCalls(<L as NodeCalls<T, L, Recovery, Pr>>::start_all::<
            Bundle<T, L, Six<Pc, Pe, Pl, Pk, Ps, Pr>>,
        >(args));
        let addr = NodeAddr::recovery(link.slot, link.sub);
        let key = NodeKey::Recovery(args.path.clone(), args.link.clone());
        let node = self.node(addr, key, 0, data, calls, ());
        self.tree.logical_paths[link.slot]
            .as_mut()
            .expect("found")
            .link_paths[link.sub]
            .as_mut()
            .expect("found")
            .child = Some(node);
        self.started(addr, now, changes);
    }

    fn end_recovery(
        &mut self,
        link: NodeAddr,
        now: InstantOf<T>,
        todo: &mut Vec<(NodeAddr, usize)>,
    ) {
        if !self.link_node(link).is_some_and(|n| n.child.is_some()) {
            return;
        }
        let addr = NodeAddr::recovery(link.slot, link.sub);
        self.ending(addr, todo);
        {
            let node = self.tree.logical_paths[link.slot]
                .as_mut()
                .expect("alive")
                .link_paths[link.sub]
                .as_mut()
                .expect("alive")
                .child
                .take()
                .expect("checked");
            let Self {
                tree,
                lineage_taken,
                nodes_taken,
                ..
            } = self;
            let records = Records {
                lineage: lineage_taken,
                nodes: nodes_taken,
                now,
            };
            let Lent {
                mut lineage,
                others,
                ..
            } = tree.lend_link_path(link.slot, link.sub, records);
            let mut others = others.ending(node.key);
            <L as BuildNode<T, L, Recovery, Br>>::end_node(node.data, &mut lineage, &mut others);
        }
        let mut lineage = self.ancestors(link);
        lineage.push(link);
        let changes = self.recorded_for(&lineage);
        self.readers(&changes, None, todo);
    }

    fn end_link_path(
        &mut self,
        link: NodeAddr,
        now: InstantOf<T>,
        todo: &mut Vec<(NodeAddr, usize)>,
    ) {
        if self.link_node(link).is_none() {
            return;
        }
        self.end_recovery(link, now, todo);
        self.ending(link, todo);
        let entry = self.link_node(link).expect("alive").entry;
        {
            let node = self.tree.logical_paths[link.slot]
                .as_mut()
                .expect("alive")
                .link_paths[link.sub]
                .take()
                .expect("alive");
            let Self {
                tree,
                lineage_taken,
                nodes_taken,
                ..
            } = self;
            let records = Records {
                lineage: lineage_taken,
                nodes: nodes_taken,
                now,
            };
            let (mut parents, mut others) =
                tree.end_link_path_view(link.slot, entry, node.key, records);
            <L as BuildNode<T, L, LinkPath, Bk>>::end_node(node.data, &mut parents, &mut others);
        }
        let changes = self.recorded_for(&[
            NodeAddr::CONNECTION,
            NodeAddr::entry(entry),
            NodeAddr::logical_path(link.slot),
        ]);
        self.readers(&changes, None, todo);
        let still_used = self
            .tree
            .logical_paths
            .iter()
            .flatten()
            .any(|p| p.link_paths.iter().flatten().any(|n| n.entry == entry));
        if !still_used {
            self.end_entry(entry, now, todo);
        }
    }

    fn end_entry(&mut self, slot: usize, now: InstantOf<T>, todo: &mut Vec<(NodeAddr, usize)>) {
        let addr = NodeAddr::entry(slot);
        self.ending(addr, todo);
        let node = self.tree.entries[slot].take().expect("alive");
        end_under_connection!(self, LinkEntry, Be, node.data, node.key, now);
        let changes = self.recorded_for(&[NodeAddr::CONNECTION]);
        self.readers(&changes, None, todo);
    }

    fn end_logical_path(
        &mut self,
        slot: usize,
        now: InstantOf<T>,
        todo: &mut Vec<(NodeAddr, usize)>,
    ) {
        let Some(path) = self.tree.logical_paths.get(slot).and_then(Option::as_ref) else {
            return;
        };
        let subs: Vec<usize> = path
            .link_paths
            .iter()
            .enumerate()
            .filter_map(|(sub, n)| n.as_ref().map(|_| sub))
            .collect();
        for sub in subs {
            self.end_link_path(NodeAddr::link_path(slot, sub), now, todo);
        }
        let addr = NodeAddr::logical_path(slot);
        self.ending(addr, todo);
        let path = self.tree.logical_paths[slot].take().expect("alive");
        end_under_connection!(self, LogicalPath, Bl, path.node.data, path.node.key, now);
        let changes = self.recorded_for(&[NodeAddr::CONNECTION]);
        self.readers(&changes, None, todo);
    }

    fn end_established(&mut self, now: InstantOf<T>, todo: &mut Vec<(NodeAddr, usize)>) {
        if self.tree.connection().child.is_none() {
            return;
        }
        self.ending(NodeAddr::ESTABLISHED, todo);
        let node = self.tree.connection().child.take().expect("checked");
        end_under_connection!(self, Established, Bs, node.data, node.key, now);
        let changes = self.recorded_for(&[NodeAddr::CONNECTION]);
        self.readers(&changes, None, todo);
    }

    fn move_recovery(
        &mut self,
        from: NodeAddr,
        to: NodeAddr,
        now: InstantOf<T>,
        todo: &mut Vec<(NodeAddr, usize)>,
    ) {
        let movable = self.link_node(from).is_some_and(|n| n.child.is_some())
            && self.link_node(to).is_some_and(|n| n.child.is_none());
        if !movable || from.slot != to.slot {
            return;
        }
        let old = NodeAddr::recovery(from.slot, from.sub);
        self.ending(old, todo);
        let paths = &mut self.tree.logical_paths[from.slot]
            .as_mut()
            .expect("alive")
            .link_paths;
        let moved = paths[from.sub]
            .as_mut()
            .expect("alive")
            .child
            .take()
            .expect("checked");
        let NodeKey::LinkPath(path, link) = paths[to.sub].as_ref().expect("alive").key.clone()
        else {
            unreachable!("a link path's key")
        };
        let addr = NodeAddr::recovery(to.slot, to.sub);
        let node = self.node(
            addr,
            NodeKey::Recovery(path, link),
            0,
            moved.data,
            moved.calls,
            (),
        );
        self.tree.logical_paths[to.slot]
            .as_mut()
            .expect("alive")
            .link_paths[to.sub]
            .as_mut()
            .expect("alive")
            .child = Some(node);
        let mut changes = Changes::new();
        self.started(addr, now, &mut changes);
        self.readers(&changes, None, todo);
    }

    /// End every node from the bottom up, each component with its end
    /// action; what is queued or due is not run any more.
    fn end_connection(&mut self, now: InstantOf<T>, todo: &mut Vec<(NodeAddr, usize)>) {
        for slot in 0..self.tree.logical_paths.len() {
            if self.tree.logical_paths[slot].is_some() {
                self.end_logical_path(slot, now, todo);
            }
        }
        for slot in 0..self.tree.entries.len() {
            if self.tree.entries[slot].is_some() {
                self.end_entry(slot, now, todo);
            }
        }
        self.end_established(now, todo);
        self.drop_deadlines(NodeAddr::CONNECTION);
        if let Some(node) = self.tree.connection.take() {
            let mut others = OtherNodes::<T, L, Bundle<T, L, Six<Pc, Pe, Pl, Pk, Ps, Pr>>>::new(
                Around::empty(),
                Around::empty(),
                Around::empty(),
                None,
                None,
                None,
                &mut self.nodes_taken,
                node.key,
                now,
            );
            <L as BuildNode<T, L, Connection, Bw>>::end_node(
                node.data,
                &mut Lineage::new(HNil, &mut self.lineage_taken),
                &mut others,
            );
        }
        self.lineage_taken.clear();
        self.nodes_taken.clear();
        self.shared.closed.store(true, Ordering::SeqCst);
        self.shared.queue().clear();
        self.timers.clear();
        self.deadlines.clear();
        self.sleep = None;
        todo.clear();
        self.ended = true;
    }

    /// The future is dropped before the connection ended: tell every data
    /// component, the nodes above a node first, then end every node. After
    /// a panic unwound through the driver, tell the connection node's only
    /// and end nothing.
    fn end_dropped(&mut self) {
        let panicked = self.running;
        let cause = if panicked {
            AbortCause::Panicked
        } else {
            AbortCause::DriverDropped
        };
        let now = self.clock.now();
        // a panic can have left records of a lend it unwound through
        self.lineage_taken.clear();
        self.nodes_taken.clear();
        let told = if !panicked {
            self.live()
        } else if self.tree.connection.is_some() {
            // lending the connection node needs nothing of the nodes below
            // it, whatever the panic left of them
            vec![NodeAddr::CONNECTION]
        } else {
            Vec::new()
        };
        for addr in told {
            let Self {
                tree,
                lineage_taken,
                nodes_taken,
                ..
            } = self;
            macro_rules! go {
                ($lend:ident($($a:expr),*), $lv:ident, $h:ident, $c:ident) => {{
                    let mut lent = tree.$lend($($a,)* Records { lineage: lineage_taken, nodes: nodes_taken, now });
                    <NodeData<T, L, $lv> as NodePositions<T, L, $lv, $h>>::future_dropped_each(&mut lent.lineage, cause);
                }};
            }
            by_layer!(addr, go);
        }
        // nothing is reread
        self.lineage_taken.clear();
        self.nodes_taken.clear();
        if panicked {
            // the nodes are dropped with the tree; a waker of theirs kept
            // elsewhere does nothing from here on
            self.shared.closed.store(true, Ordering::SeqCst);
        } else {
            self.end_connection(now, &mut Vec::new());
        }
    }

    /// Apply a request at once; one that no longer fits the structure is
    /// dropped. What reads the nodes made or ended goes into `todo`.
    fn apply(
        &mut self,
        request: RequestOf<T, L>,
        now: InstantOf<T>,
        todo: &mut Vec<(NodeAddr, usize)>,
    ) {
        let mut changes = Changes::new();
        match request {
            StructureRequest::AddLogicalPath { mut args } => {
                self.build_logical_path(&mut args, now, &mut changes)
            }
            StructureRequest::AddLinkPath { args } => self.build_link_path(args, now, &mut changes),
            StructureRequest::EndLinkPath { path, link } => {
                if let Some(addr) = self.find_link_path(&path, &link) {
                    self.end_link_path(addr, now, todo);
                }
            }
            StructureRequest::EndLogicalPath { path } => {
                if let Some(slot) = self.find_logical_path(&path) {
                    self.end_logical_path(slot, now, todo);
                }
            }
            StructureRequest::EndConnection => self.end_connection(now, todo),
            StructureRequest::AddEstablished { mut args } => {
                self.build_established(&mut args, now, &mut changes)
            }
            StructureRequest::EndEstablished => self.end_established(now, todo),
            StructureRequest::AddRecovery { mut args } => {
                self.build_recovery(&mut args, now, &mut changes)
            }
            StructureRequest::EndRecovery { path, link } => {
                if let Some(addr) = self.find_link_path(&path, &link) {
                    self.end_recovery(addr, now, todo);
                }
            }
            StructureRequest::MoveRecovery { path, from, to } => {
                if let (Some(from), Some(to)) = (
                    self.find_link_path(&path, &from),
                    self.find_link_path(&path, &to),
                ) {
                    self.move_recovery(from, to, now, todo);
                }
            }
        }
        if !self.ended {
            self.readers(&changes, None, todo);
        }
    }

    /// Reread what reads the changes, round after round, until a round takes
    /// nothing mutably; requests returned on the way are applied at once.
    fn settle(&mut self, mut todo: Vec<(NodeAddr, usize)>, now: InstantOf<T>) {
        let mut round = 0;
        while !todo.is_empty() && !self.ended {
            todo.sort();
            todo.dedup();
            round += 1;
            debug_assert!(
                round <= self.tables.positions * (self.live().len() + 1) + 1,
                "rereads did not settle"
            );
            let mut next = Vec::new();
            for (addr, position) in todo {
                if self.ended {
                    break;
                }
                if !self.alive(addr) {
                    continue;
                }
                if position >= self.tables.data[addr.layer] {
                    let marks = self.marks_at(addr).expect("alive");
                    self.shared.wake(&marks, addr, 1 << position);
                    continue;
                }
                let request = self.reread_action(addr, position, now);
                let changes = self.recorded(addr);
                self.read_deadline(addr, position, now);
                self.readers(&changes, None, &mut next);
                if let Some(request) = request {
                    self.apply(request, now, &mut next);
                }
            }
            todo = next;
        }
    }

    /// After a lend of `addr`: the request it handed over, then the rereads.
    fn after_lend(
        &mut self,
        addr: NodeAddr,
        call: Option<usize>,
        request: Option<RequestOf<T, L>>,
        now: InstantOf<T>,
    ) {
        let changes = self.recorded(addr);
        let mut todo = Vec::new();
        self.readers(&changes, call.map(|position| (addr, position)), &mut todo);
        if let Some(request) = request {
            self.apply(request, now, &mut todo);
        }
        self.settle(todo, now);
    }

    #[cfg(debug_assertions)]
    fn check_deadlines(&mut self, now: InstantOf<T>) {
        for addr in self.live() {
            for position in 0..self.tables.data[addr.layer] {
                let at = self.deadline(addr, position, now);
                debug_assert_eq!(
                    self.deadlines.get(&(addr, position)).copied(),
                    at,
                    "a deadline changed without a reread: a component reads a component it does not declare",
                );
            }
        }
    }

    fn turn(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.ended {
            return Poll::Ready(());
        }
        self.shared.outer.register(cx.waker());
        self.shared.notified.store(false, Ordering::SeqCst);
        let now = self.clock.now();
        let queued = self.shared.queue().len();
        for _ in 0..queued {
            let Some(addr) = self.shared.queue().pop_front() else {
                break;
            };
            let Some(marks) = self.marks_at(addr) else {
                continue;
            };
            let mut bits = marks.take();
            while bits != 0 {
                let position = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                if !self.alive(addr) {
                    break;
                }
                if position < self.tables.data[addr.layer] {
                    continue;
                }
                let request = match self.poll_call(addr, position, now) {
                    CallStep::Requested(request) => {
                        self.shared.wake(&marks, addr, 1 << position);
                        Some(request)
                    }
                    CallStep::Pending | CallStep::Finished => None,
                };
                self.after_lend(addr, Some(position), request, now);
                if self.ended {
                    return Poll::Ready(());
                }
            }
        }
        while let Some(&(at, addr, position)) = self.timers.first() {
            if at > now {
                break;
            }
            self.timers.pop_first();
            self.deadlines.remove(&(addr, position));
            if !self.alive(addr) {
                continue;
            }
            match self.deadline(addr, position, now) {
                Some(current) if current <= now => {
                    let request = self.expire(addr, position, now);
                    let changes = self.recorded(addr);
                    let mut todo = Vec::new();
                    self.readers(&changes, None, &mut todo);
                    // the expiry may have asked to end its own node: its
                    // deadline goes with it
                    if let Some(request) = request {
                        self.apply(request, now, &mut todo);
                    }
                    if self.alive(addr) {
                        self.read_deadline(addr, position, now);
                        debug_assert!(
                            self.deadlines
                                .get(&(addr, position))
                                .is_none_or(|&later| later > now),
                            "after its expiry a deadline is later than the instant it expired at, or gone",
                        );
                    }
                    self.settle(todo, now);
                    if self.ended {
                        return Poll::Ready(());
                    }
                }
                later => self.set_deadline(addr, position, later),
            }
        }
        #[cfg(debug_assertions)]
        self.check_deadlines(now);
        if let Some(&(earliest, _, _)) = self.timers.first() {
            let replace = self.sleep.as_ref().is_none_or(|(at, _)| earliest < *at);
            if replace {
                self.sleep = Some((earliest, Box::pin(self.clock.sleep_until(earliest))));
            }
        }
        if let Some((_, sleep)) = self.sleep.as_mut()
            && sleep.as_mut().poll(cx).is_ready()
        {
            self.sleep = None;
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
}

impl<T, L, Pc, Pe, Pl, Pk, Ps, Pr, Hw, He, Hl, Hk, Hs, Hr, Bw, Be, Bl, Bk, Bs, Br> Future
    for ConnectionDriver<
        T,
        L,
        (Pc, Pe, Pl, Pk, Ps, Pr),
        (Hw, He, Hl, Hk, Hs, Hr),
        (Bw, Be, Bl, Bk, Bs, Br),
    >
where
    T: ConnectionChoices,
    for<'v> L: LineageLists<'v, T>,
    L: TreeCalls<T, (Pc, Pe, Pl, Pk, Ps, Pr)>
        + NodeCalls<T, L, Connection, Pc>
        + NodeCalls<T, L, LinkEntry, Pe>
        + NodeCalls<T, L, LogicalPath, Pl>
        + NodeCalls<T, L, LinkPath, Pk>
        + NodeCalls<T, L, Established, Ps>
        + NodeCalls<T, L, Recovery, Pr>
        + BuildNode<T, L, Connection, Bw>
        + BuildNode<T, L, LinkEntry, Be>
        + BuildNode<T, L, LogicalPath, Bl>
        + BuildNode<T, L, LinkPath, Bk>
        + BuildNode<T, L, Established, Bs>
        + BuildNode<T, L, Recovery, Br>,
    Pc: 'static,
    Pe: 'static,
    Pl: 'static,
    Pk: 'static,
    Ps: 'static,
    Pr: 'static,
    NodeData<T, L, Connection>: NodePositions<T, L, Connection, Hw>,
    NodeData<T, L, LinkEntry>: NodePositions<T, L, LinkEntry, He>,
    NodeData<T, L, LogicalPath>: NodePositions<T, L, LogicalPath, Hl>,
    NodeData<T, L, LinkPath>: NodePositions<T, L, LinkPath, Hk>,
    NodeData<T, L, Established>: NodePositions<T, L, Established, Hs>,
    NodeData<T, L, Recovery>: NodePositions<T, L, Recovery, Hr>,
{
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let driver = self.get_mut();
        driver.running = true;
        let turned = driver.turn(cx);
        driver.running = false;
        turned
    }
}
