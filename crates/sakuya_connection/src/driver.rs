//! The connection driver: the future that is the connection.
//!
//! Each call has a waker that only marks the call's position in its node's
//! head; a node enters the ready queue at its first mark, and the outer
//! waker is called at the first wake since the poll began. A data component
//! that acts before the calls has a waker of its own, which marks its
//! position the same way. A poll first runs the actions before the calls
//! whose positions are marked, then goes once through the nodes queued
//! until then, polls each marked call, and after each lend applies the
//! request it handed over, reads again the deadlines of the components it
//! wrote and hands the component events it published to their
//! subscribers, round after round; then it runs the expiries that are due,
//! and sleeps until the earliest deadline.
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
use sakuya_stream_v1::connection::AbortCause;
use sakuya_wire::parts::HNil;
use smallvec::SmallVec;

use crate::{
    call::{CallBundle, CallPositions, CallStep, NodeCalls, NodeLoan, PartsCallBundle, TreeCalls},
    clock::{ConnectionChoices, InstantOf, LinkIdOf, MonotonicClock},
    component::{BuildNode, LineageOf, NodePositions, RequestOf},
    component_event::{EventSubscriptions, TriggeredEvents, node_ending, node_started},
    layer::{
        Connection, Established, EstablishedArgs, EstablishedEnd, Layer, LinkEntry, LinkEntryArgs,
        LinkPath, LinkPathArgs, LogicalPath, LogicalPathArgs, NodeKey, NodeKeyOf, Recovery,
        RecoveryArgs,
    },
    others::{NodeRecords, OtherNodes},
    request::StructureRequest,
    share::{ConnectionArgsOf, LayerLineage, LineageLists, NodeData, PartList, PathKey, RemainsOf},
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

/// Why [`ConnectionDriver::lend`] lent nothing (`NotLent`).
#[derive(Debug)]
pub enum NotLent<'a, R> {
    /// The connection runs, and has no node of the layer there: the
    /// established layer is not built yet, or ended.
    Absent,
    /// The connection ended; what its parts keep after the end
    /// ([`RemainsOf`]).
    Ended(&'a mut R),
}

/// A connection that lends its nodes to operations from outside its tree
/// (`LendNode`): [`ConnectionDriver::lend`], for whoever has the
/// connection only as the future a composition makes, whose positions are
/// its own.
pub trait LendNode<T: ConnectionChoices, L: PartList<T>>
where
    for<'v> L: LineageLists<'v, T>,
{
    /// Lend the node `at` of the layer `Lv` to `op`; see
    /// [`ConnectionDriver::lend`].
    #[allow(clippy::type_complexity)] // the operation's signature
    fn lend<Lv: LendableLayer, R>(
        &mut self,
        at: Lv::At<T, L>,
        op: impl for<'v> FnOnce(LineageOf<'v, T, L, Lv>, InstantOf<T>) -> (R, Option<RequestOf<T, L>>),
    ) -> Result<R, NotLent<'_, RemainsOf<T, L>>>;
}

/// A layer whose nodes the driver lends to an operation from outside the
/// tree ([`ConnectionDriver::lend`]): the connection and the established
/// layer.
pub trait LendableLayer: LayerLineage + lendable::Sealed {
    /// Which node of the layer: nothing for the layers with at most one
    /// node.
    type At<T: ConnectionChoices, L: PartList<T>>;
}

#[expect(
    private_interfaces,
    reason = "the sealed trait cannot be named outside the crate, so its methods are not reachable"
)]
mod lendable {
    use super::*;

    /// Finding and lending a node of the layer.
    pub trait Sealed: LayerLineage + Sized {
        /// Where the node `at` is, when it is there.
        fn find<T: ConnectionChoices, L: PartList<T>, B: CallBundle>(
            tree: &ConnectionTree<T, L, B>,
            at: &<Self as LendableLayer>::At<T, L>,
        ) -> Option<NodeAddr>
        where
            Self: LendableLayer;
        /// The node's lineage; it is there.
        fn lineage<'v, T: ConnectionChoices, L: LineageLists<'v, T>, B: CallBundle>(
            tree: &'v mut ConnectionTree<T, L, B>,
            records: Records<'v, T, L>,
        ) -> LineageOf<'v, T, L, Self>;
    }

    impl Sealed for Connection {
        fn find<T: ConnectionChoices, L: PartList<T>, B: CallBundle>(
            tree: &ConnectionTree<T, L, B>,
            _: &(),
        ) -> Option<NodeAddr> {
            tree.connection.as_ref().map(|_| NodeAddr::CONNECTION)
        }
        fn lineage<'v, T: ConnectionChoices, L: LineageLists<'v, T>, B: CallBundle>(
            tree: &'v mut ConnectionTree<T, L, B>,
            records: Records<'v, T, L>,
        ) -> LineageOf<'v, T, L, Self> {
            tree.lend_connection(records).lineage
        }
    }

    impl Sealed for Established {
        fn find<T: ConnectionChoices, L: PartList<T>, B: CallBundle>(
            tree: &ConnectionTree<T, L, B>,
            _: &(),
        ) -> Option<NodeAddr> {
            tree.connection
                .as_ref()?
                .child
                .as_ref()
                .map(|_| NodeAddr::ESTABLISHED)
        }
        fn lineage<'v, T: ConnectionChoices, L: LineageLists<'v, T>, B: CallBundle>(
            tree: &'v mut ConnectionTree<T, L, B>,
            records: Records<'v, T, L>,
        ) -> LineageOf<'v, T, L, Self> {
            tree.lend_established(records).lineage
        }
    }
}

/// The connection node.
impl LendableLayer for Connection {
    type At<T: ConnectionChoices, L: PartList<T>> = ();
}

/// The established layer, while it is there.
impl LendableLayer for Established {
    type At<T: ConnectionChoices, L: PartList<T>> = ();
}

/// The waker of one call, or of a data component that acts before the
/// calls: it marks the position in its node.
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
    /// For each layer: the data positions that declare a deadline, as
    /// marks.
    deadline_marks: [u64; 6],
    /// For each layer: the data positions that act before the calls.
    before_calls: [Vec<usize>; 6],
    /// For each layer: those positions as marks.
    before_calls_marks: [u64; 6],
    /// For each layer and position, the data positions first: what it
    /// subscribes to.
    subscriptions: [Vec<EventSubscriptions>; 6],
    /// Who subscribes to each event type, ordered by event type.
    subscribers: Vec<(TypeId, Subscriber)>,
    /// An upper bound of the rounds of events.
    positions: usize,
}

impl Tables {
    /// The tables of a node's layers: for each layer, whether each data
    /// position declares a deadline and acts before the calls, and what
    /// each position, the calls after the data, subscribes to.
    fn new(
        deadlines: [Vec<bool>; 6],
        acts_before_calls: [Vec<bool>; 6],
        subscriptions: [Vec<EventSubscriptions>; 6],
    ) -> Self {
        let data: [usize; 6] = core::array::from_fn(|l| deadlines[l].len());
        let calls: [usize; 6] = core::array::from_fn(|l| subscriptions[l].len() - data[l]);
        let mut subscribers = Vec::new();
        for (layer, positions) in subscriptions.iter().enumerate() {
            for (position, subscribed) in positions.iter().enumerate() {
                assert!(
                    subscribed.handled.len() <= 64,
                    "a position subscribes to at most 64 events for its handler"
                );
                assert!(
                    position < data[layer] || subscribed.for_deadline.is_empty(),
                    "a call subscribes to no event for a deadline"
                );
                for (bit, &event) in subscribed.handled.iter().enumerate() {
                    let bit = Some(bit as u32);
                    subscribers.push((
                        event,
                        Subscriber {
                            layer,
                            position,
                            bit,
                        },
                    ));
                }
                for &event in &subscribed.for_deadline {
                    if !subscribed.handled.contains(&event) {
                        let bit = None;
                        subscribers.push((
                            event,
                            Subscriber {
                                layer,
                                position,
                                bit,
                            },
                        ));
                    }
                }
            }
        }
        subscribers.sort_by_key(|&(event, _)| event);
        for l in 0..6 {
            assert!(data[l] + calls[l] <= 64, "a node has at most 64 positions");
        }
        let marks = |flags: &[bool]| {
            flags
                .iter()
                .enumerate()
                .filter(|&(_, &set)| set)
                .fold(0u64, |marks, (position, _)| marks | 1 << position)
        };
        Self {
            data,
            calls,
            deadline_marks: core::array::from_fn(|l| marks(&deadlines[l])),
            before_calls: core::array::from_fn(|l| {
                acts_before_calls[l]
                    .iter()
                    .enumerate()
                    .filter_map(|(position, &acts)| acts.then_some(position))
                    .collect()
            }),
            before_calls_marks: core::array::from_fn(|l| marks(&acts_before_calls[l])),
            positions: (0..6).map(|l| data[l] + calls[l]).sum(),
            subscriptions,
            subscribers,
        }
    }

    /// Whether the data position `position` of the layer `layer` declares a
    /// deadline.
    fn has_deadline(&self, layer: usize, position: usize) -> bool {
        self.deadline_marks[layer] & 1 << position != 0
    }

    /// Who subscribes to `event`.
    fn subscribers_of(&self, event: TypeId) -> impl Iterator<Item = Subscriber> + '_ {
        let start = self.subscribers.partition_point(|&(e, _)| e < event);
        self.subscribers[start..]
            .iter()
            .take_while(move |&&(e, _)| e == event)
            .map(|&(_, subscriber)| subscriber)
    }
}

/// A position that subscribes to an event.
#[derive(Clone, Copy, Debug)]
struct Subscriber {
    layer: usize,
    position: usize,
    /// The bit of the event among those its handler runs for; `None` when
    /// it subscribes for its deadline only.
    bit: Option<u32>,
}

type Bundle<T, L, P> = PartsCallBundle<T, L, P>;
/// The sleep until the earliest deadline, with that deadline.
type Sleeping<T> = (
    InstantOf<T>,
    Pin<Box<<<T as ConnectionChoices>::Clock as MonotonicClock>::Sleep>>,
);
/// A link path node of a composition whose call positions are given by layer.
type LinkNode<T, L, Q> = crate::tree::LinkPathNodeOf<T, L, PartsCallBundle<T, L, Q>>;

/// Every position the driver takes, as one named type: the call positions
/// of the six layers, and the data positions and the build positions of
/// the six layers, each as a tuple of the six.
pub trait DriverPositions: CallPositions {
    /// The data positions of the six layers.
    type Data: 'static;
    /// The build positions of the six layers.
    type Builds: 'static;
}

/// A tuple of one position for each of the six layers, read by layer: what
/// the driver's impls take [`DriverPositions::Data`] and
/// [`DriverPositions::Builds`] apart by, so that they are generic over the
/// one named type of positions and not over each position, and the names
/// of the functions and closures in them do not list every position.
#[doc(hidden)]
pub trait LayerPositions {
    /// The position at the layer [`Connection`].
    type Connection;
    /// The position at the layer [`LinkEntry`].
    type LinkEntry;
    /// The position at the layer [`LogicalPath`].
    type LogicalPath;
    /// The position at the layer [`LinkPath`].
    type LinkPath;
    /// The position at the layer [`Established`].
    type Established;
    /// The position at the layer [`Recovery`].
    type Recovery;
}

impl<A, B, C, D, E, F> LayerPositions for (A, B, C, D, E, F) {
    type Connection = A;
    type LinkEntry = B;
    type LogicalPath = C;
    type LinkPath = D;
    type Established = E;
    type Recovery = F;
}

/// The call positions of `Q` at each layer.
type PcOf<Q> = <Q as CallPositions>::Connection;
type PeOf<Q> = <Q as CallPositions>::LinkEntry;
type PlOf<Q> = <Q as CallPositions>::LogicalPath;
type PkOf<Q> = <Q as CallPositions>::LinkPath;
type PsOf<Q> = <Q as CallPositions>::Established;
type PrOf<Q> = <Q as CallPositions>::Recovery;
/// The data positions of `Q` at each layer.
type HwOf<Q> = <<Q as DriverPositions>::Data as LayerPositions>::Connection;
type HeOf<Q> = <<Q as DriverPositions>::Data as LayerPositions>::LinkEntry;
type HlOf<Q> = <<Q as DriverPositions>::Data as LayerPositions>::LogicalPath;
type HkOf<Q> = <<Q as DriverPositions>::Data as LayerPositions>::LinkPath;
type HsOf<Q> = <<Q as DriverPositions>::Data as LayerPositions>::Established;
type HrOf<Q> = <<Q as DriverPositions>::Data as LayerPositions>::Recovery;
/// The build positions of `Q` at each layer.
type BwOf<Q> = <<Q as DriverPositions>::Builds as LayerPositions>::Connection;
type BeOf<Q> = <<Q as DriverPositions>::Builds as LayerPositions>::LinkEntry;
type BlOf<Q> = <<Q as DriverPositions>::Builds as LayerPositions>::LogicalPath;
type BkOf<Q> = <<Q as DriverPositions>::Builds as LayerPositions>::LinkPath;
type BsOf<Q> = <<Q as DriverPositions>::Builds as LayerPositions>::Established;
type BrOf<Q> = <<Q as DriverPositions>::Builds as LayerPositions>::Recovery;

/// A connection: the tree of its nodes and the driver of their calls, as
/// one future that ends when the connection ends. Dropped before that, it
/// ends its nodes as it is dropped, unless a panic unwound through it.
///
/// `T` is the choices of the composition, `L` the list of parts. `P`, `W`
/// and `Bw` are what the calls, the data components and their builds infer
/// their positions by; they are inferred where the connection is made.
pub struct ConnectionDriver<T: ConnectionChoices, L: TreeCalls<T, Q>, Q: DriverPositions>
where
    for<'v> L: LineageLists<'v, T>,
{
    tree: ConnectionTree<T, L, Bundle<T, L, Q>>,
    shared: Arc<Shared>,
    clock: T::Clock,
    sleep: Option<Sleeping<T>>,
    timers: BTreeSet<(InstantOf<T>, NodeAddr, usize)>,
    deadlines: BTreeMap<(NodeAddr, usize), InstantOf<T>>,
    lineage_taken: TakenPositions,
    nodes_taken: NodeRecords<NodeKeyOf<T, L>>,
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
    /// What the parts keep after the connection ended, once it did.
    remains: Option<RemainsOf<T, L>>,
    positions: PhantomData<fn() -> Q>,
}

/// A connection dropped before it ended ends here, without a closing
/// period and with nothing sent: every data component is told that the
/// future is dropped
/// ([`DataComponent::future_dropped`](crate::component::DataComponent::future_dropped))
/// with [`AbortCause::DriverDropped`], then every node ends, each component
/// with its end action.
///
/// When a panic unwound through a poll or through the making of the
/// connection, only the data components of the connection node and of its
/// established layer are told, with [`AbortCause::Panicked`], so that the
/// reason is written where the connection keeps it and the waits of the
/// application's handles end; no end action runs, and what the panic left of
/// the tree is dropped as it is. The driver tells the two apart by itself: it
/// notes that its own code runs where that begins and where it returns, so
/// a driver dropped after its poll panicked has ended by the panic, and one
/// dropped while a panic from elsewhere unwinds was only dropped.
impl<T: ConnectionChoices, L: TreeCalls<T, Q>, Q: DriverPositions> Drop
    for ConnectionDriver<T, L, Q>
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
impl<T: ConnectionChoices, L: TreeCalls<T, Q>, Q: DriverPositions> Unpin
    for ConnectionDriver<T, L, Q>
where
    for<'v> L: LineageLists<'v, T>,
{
}

/// End the data `$data` of a node of the layer `$lv` (data positions
/// `$b`) whose parent is the connection node, with the key `$key`: its
/// parents are the connection's lend, with the other nodes.
macro_rules! end_under_connection {
    ($self:ident, $lv:ident, $b:ty, $data:expr, $key:expr, $now:expr) => {
        end_under_connection!(@ $self, $lv, $b, $data, $key, $now, )
    };
    ($self:ident, $lv:ident, $b:ty, $data:expr, $key:expr, $now:expr, because $end:expr) => {
        end_under_connection!(@ $self, $lv, $b, $data, $key, $now, .because($end))
    };
    (@ $self:ident, $lv:ident, $b:ty, $data:expr, $key:expr, $now:expr, $($why:tt)*) => {{
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
        let mut others = others.ending($key)$($why)*;
        <L as BuildNode<T, L, $lv, $b>>::end_node($data, &mut lineage, &mut others);
    }};
}

/// Run `$go!` for the layer of `$addr`, with the name of the tree's lend,
/// its arguments, the layer, its data positions and its call positions.
macro_rules! by_layer {
    ($addr:expr, $go:ident) => {
        match $addr.layer {
            0 => $go!(lend_connection(), Connection, HwOf<Q>, Connection),
            1 => $go!(lend_entry($addr.slot), LinkEntry, HeOf<Q>, LinkEntry),
            2 => $go!(
                lend_logical_path($addr.slot),
                LogicalPath,
                HlOf<Q>,
                LogicalPath
            ),
            3 => $go!(
                lend_link_path($addr.slot, $addr.sub),
                LinkPath,
                HkOf<Q>,
                LinkPath
            ),
            4 => $go!(lend_established(), Established, HsOf<Q>, Established),
            5 => $go!(
                lend_recovery($addr.slot, $addr.sub),
                Recovery,
                HrOf<Q>,
                Recovery
            ),
            _ => unreachable!("six layers"),
        }
    };
}

/// What a lend or a structure request recorded: the positions it took, as
/// (node, position), and the component events published, at their nodes.
#[derive(Default)]
struct Recorded {
    changes: SmallVec<[(NodeAddr, usize); 8]>,
    events: SmallVec<[(NodeAddr, TypeId); 4]>,
}

impl Recorded {
    fn extend(&mut self, other: Recorded) {
        self.changes.extend(other.changes);
        self.events.extend(other.events);
    }
}

/// What a round handles at one position: the events that reached it, by
/// their bits among those its handler runs for. Without any, it is a data
/// position whose deadline is read again: one that was written, or one
/// subscribed to an event for its deadline only.
#[derive(Clone, Copy, Debug)]
struct Hit {
    addr: NodeAddr,
    position: usize,
    events: u64,
}

/// The hits of a round, with room for the usual few without allocating.
type Hits = SmallVec<[Hit; 16]>;

/// Merge the hits of one position into one, ordered by node and position.
fn merge(hits: &mut Hits) {
    hits.sort_unstable_by_key(|hit| (hit.addr, hit.position));
    let mut merged = 0;
    for at in 0..hits.len() {
        let hit = hits[at];
        if merged > 0 {
            let last = &mut hits[merged - 1];
            if (last.addr, last.position) == (hit.addr, hit.position) {
                last.events |= hit.events;
                continue;
            }
        }
        hits[merged] = hit;
        merged += 1;
    }
    hits.truncate(merged);
}

/// A node and the nodes above it, from the connection down, or only the
/// nodes above it: at most five, on the stack.
#[derive(Clone, Copy)]
struct Lineal {
    addrs: [NodeAddr; 5],
    len: usize,
}

impl Default for Lineal {
    fn default() -> Self {
        Self {
            addrs: [NodeAddr::CONNECTION; 5],
            len: 0,
        }
    }
}

impl Lineal {
    fn push(&mut self, addr: NodeAddr) {
        self.addrs[self.len] = addr;
        self.len += 1;
    }
}

impl core::ops::Deref for Lineal {
    type Target = [NodeAddr];
    fn deref(&self) -> &[NodeAddr] {
        &self.addrs[..self.len]
    }
}

impl<T, L, Q> ConnectionDriver<T, L, Q>
where
    Q: DriverPositions<Data: LayerPositions, Builds: LayerPositions>,
    T: ConnectionChoices,
    for<'v> L: LineageLists<'v, T>,
    L: TreeCalls<T, Q>
        + NodeCalls<T, L, Connection, PcOf<Q>>
        + NodeCalls<T, L, LinkEntry, PeOf<Q>>
        + NodeCalls<T, L, LogicalPath, PlOf<Q>>
        + NodeCalls<T, L, LinkPath, PkOf<Q>>
        + NodeCalls<T, L, Established, PsOf<Q>>
        + NodeCalls<T, L, Recovery, PrOf<Q>>
        + BuildNode<T, L, Connection, BwOf<Q>>
        + BuildNode<T, L, LinkEntry, BeOf<Q>>
        + BuildNode<T, L, LogicalPath, BlOf<Q>>
        + BuildNode<T, L, LinkPath, BkOf<Q>>
        + BuildNode<T, L, Established, BsOf<Q>>
        + BuildNode<T, L, Recovery, BrOf<Q>>,
    PcOf<Q>: 'static,
    PeOf<Q>: 'static,
    PlOf<Q>: 'static,
    PkOf<Q>: 'static,
    PsOf<Q>: 'static,
    PrOf<Q>: 'static,
    NodeData<T, L, Connection>: NodePositions<T, L, Connection, HwOf<Q>>,
    NodeData<T, L, LinkEntry>: NodePositions<T, L, LinkEntry, HeOf<Q>>,
    NodeData<T, L, LogicalPath>: NodePositions<T, L, LogicalPath, HlOf<Q>>,
    NodeData<T, L, LinkPath>: NodePositions<T, L, LinkPath, HkOf<Q>>,
    NodeData<T, L, Established>: NodePositions<T, L, Established, HsOf<Q>>,
    NodeData<T, L, Recovery>: NodePositions<T, L, Recovery, HrOf<Q>>,
{
    /// Make a connection with its first logical path and its first link
    /// path. Every call starts woken; every deadline is read.
    ///
    /// `connection` is what the parts declare the connection node needs;
    /// `link` carries the clone of the first logical link, which goes into
    /// its entry, and what the first link path starts with.
    pub fn new(
        clock: T::Clock,
        mut connection: ConnectionArgsOf<T, L>,
        mut path: LogicalPathArgs<PathKey<L>>,
        link: LinkPathArgs<PathKey<L>, T::Link, InstantOf<T>>,
    ) -> Self {
        let mut deadlines: [Vec<bool>; 6] = Default::default();
        let mut acts_before_calls: [Vec<bool>; 6] = Default::default();
        let mut subscriptions: [Vec<EventSubscriptions>; 6] = Default::default();
        macro_rules! tables {
            ($lend:ident($($a:expr),*), $lv:ident, $h:ty, $c:ident) => {{
                let l = <$lv as Layer>::INDEX;
                <NodeData<T, L, $lv> as NodePositions<T, L, $lv, $h>>::deadlines(&mut deadlines[l]);
                <NodeData<T, L, $lv> as NodePositions<T, L, $lv, $h>>::acts_before_calls(
                    &mut acts_before_calls[l],
                );
                <NodeData<T, L, $lv> as NodePositions<T, L, $lv, $h>>::subscribes(
                    &mut subscriptions[l],
                );
                <L as NodeCalls<T, L, $lv, <Q as CallPositions>::$c>>::subscribes(
                    &mut subscriptions[l],
                );
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
        let tables = Tables::new(deadlines, acts_before_calls, subscriptions);
        let now = clock.now();
        let shared = Shared::new();
        let mut driver = Self {
            tree: ConnectionTree {
                connection: None,
                entries: Vec::new(),
                logical_paths: Vec::new(),
            },
            shared,
            clock,
            sleep: None,
            timers: BTreeSet::new(),
            deadlines: BTreeMap::new(),
            lineage_taken: TakenPositions::default(),
            nodes_taken: NodeRecords::default(),
            tables,
            ended: false,
            running: true,
            on_drop: Self::end_dropped,
            remains: None,
            positions: PhantomData,
        };
        let mut recorded = Recorded::default();
        driver.build_connection(&mut connection, now, &mut recorded);
        driver.build_logical_path(&mut path, now, &mut recorded);
        driver.build_link_path(link, now, &mut recorded);
        let mut todo = Hits::new();
        driver.hits(&recorded, None, &mut todo);
        driver.settle(todo, now);
        driver.running = false;
        driver
    }

    // ---- where things are ----

    #[allow(clippy::type_complexity)] // a link path node of the composition
    fn link_node(&self, addr: NodeAddr) -> Option<&LinkNode<T, L, Q>> {
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
    fn ancestors(&self, addr: NodeAddr) -> Lineal {
        let mut out = Lineal::default();
        if addr.layer == Connection::INDEX {
            return out;
        }
        out.push(NodeAddr::CONNECTION);
        if matches!(addr.layer, 3 | 5)
            && let Some(node) = self.link_node(addr)
        {
            out.push(NodeAddr::entry(node.entry));
            out.push(NodeAddr::logical_path(addr.slot));
            if addr.layer == Recovery::INDEX {
                out.push(NodeAddr::link_path(addr.slot, addr.sub));
            }
        }
        out
    }

    /// A node and the nodes above it, from the connection down: the nodes
    /// of its lineage.
    fn lineal(&self, addr: NodeAddr) -> Lineal {
        let mut out = self.ancestors(addr);
        out.push(addr);
        out
    }

    /// Every node, the connection first, then its established layer, the
    /// entries, and each logical path followed by its link paths, each
    /// followed by its recovery layer.
    fn live(&self) -> impl Iterator<Item = NodeAddr> + '_ {
        let connection = self.tree.connection.as_ref();
        let top = connection.into_iter().flat_map(|c| {
            core::iter::once(NodeAddr::CONNECTION)
                .chain(c.child.is_some().then_some(NodeAddr::ESTABLISHED))
        });
        let entries = self
            .tree
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.is_some())
            .map(|(slot, _)| NodeAddr::entry(slot));
        let paths = self
            .tree
            .logical_paths
            .iter()
            .enumerate()
            .flat_map(|(slot, path)| {
                path.iter().flat_map(move |path| {
                    core::iter::once(NodeAddr::logical_path(slot)).chain(
                        path.link_paths
                            .iter()
                            .enumerate()
                            .flat_map(move |(sub, link)| {
                                link.iter().flat_map(move |link| {
                                    core::iter::once(NodeAddr::link_path(slot, sub)).chain(
                                        link.child
                                            .is_some()
                                            .then_some(NodeAddr::recovery(slot, sub)),
                                    )
                                })
                            }),
                    )
                })
            });
        // the nodes below the connection are there only with it
        let with_connection = connection.is_some();
        top.chain(entries.chain(paths).filter(move |_| with_connection))
    }

    /// The nodes of `layer` that a change in `addr` concerns: the node
    /// itself, the one above it, or those below it.
    fn scope(&self, addr: NodeAddr, layer: usize, mut each: impl FnMut(NodeAddr)) {
        if layer == addr.layer {
            each(addr);
            return;
        }
        if let Some(&above) = self.ancestors(addr).iter().find(|a| a.layer == layer) {
            each(above);
            return;
        }
        let under = |a: &NodeAddr, entry: Option<usize>| match addr.layer {
            0 => true,
            1 => entry == Some(addr.slot),
            2 => a.slot == addr.slot,
            3 => a.slot == addr.slot && a.sub == addr.sub,
            _ => false,
        };
        for a in self.live().filter(|a| a.layer == layer) {
            let entry = matches!(a.layer, 3 | 5)
                .then(|| self.link_node(a).map(|n| n.entry))
                .flatten();
            if under(&a, entry) {
                each(a);
            }
        }
    }

    /// What the recorded writes and events reach, as hits: a written
    /// position that declares a deadline, to read it again; who subscribes
    /// to an event in its scope. `skip` is a call's own position, for what
    /// its own lend recorded.
    fn hits(&self, recorded: &Recorded, skip: Option<(NodeAddr, usize)>, out: &mut Hits) {
        for &(addr, position) in &recorded.changes {
            if self.tables.has_deadline(addr.layer, position) {
                out.push(Hit {
                    addr,
                    position,
                    events: 0,
                });
            }
        }
        for &(addr, event) in &recorded.events {
            self.deliver(addr, event, skip, out);
        }
    }

    /// The hits of the event `event` published at `addr`: every subscriber
    /// in its scope, the call at `skip` aside.
    fn deliver(
        &self,
        addr: NodeAddr,
        event: TypeId,
        skip: Option<(NodeAddr, usize)>,
        out: &mut Hits,
    ) {
        for subscriber in self.tables.subscribers_of(event) {
            self.scope(addr, subscriber.layer, |node| {
                if skip != Some((node, subscriber.position)) {
                    out.push(Hit {
                        addr: node,
                        position: subscriber.position,
                        events: subscriber.bit.map_or(0, |bit| 1 << bit),
                    });
                }
            });
        }
    }

    /// What the lend of `addr` recorded.
    fn recorded(&mut self, addr: NodeAddr) -> Recorded {
        let lineage = self.lineal(addr);
        self.recorded_for(&lineage)
    }

    /// What a lend whose lineage is the nodes `lineage` recorded: the
    /// lineage's takes by position and its events at its node of their
    /// layer, the other nodes' takes and their events by key.
    fn recorded_for(&mut self, lineage: &[NodeAddr]) -> Recorded {
        let mut out = Recorded {
            changes: self.nodes_taken.taken.take(),
            events: SmallVec::new(),
        };
        for at in self.lineage_taken.drain() {
            let mut at = at;
            for &node in lineage {
                let len = self.tables.data[node.layer];
                if at < len {
                    out.changes.push((node, at));
                    break;
                }
                at -= len;
            }
        }
        out.changes.sort_unstable();
        out.changes.dedup();
        for (layer, event) in self.lineage_taken.take_events() {
            let node = lineage
                .iter()
                .find(|node| node.layer == layer)
                .expect("an event published through a lineage is of a layer the lineage has");
            out.events.push((*node, event));
        }
        for (key, event) in core::mem::take(&mut self.nodes_taken.events) {
            if let Some(node) = self.addr_of(&key) {
                out.events.push((node, event));
            }
        }
        out.events.sort_unstable();
        out.events.dedup();
        out
    }

    /// Where the node of the key `key` is, when it is there.
    fn addr_of(&self, key: &NodeKeyOf<T, L>) -> Option<NodeAddr> {
        let addr = match key {
            NodeKey::Connection => NodeAddr::CONNECTION,
            NodeKey::LinkEntry(link) => NodeAddr::entry(self.find_entry(link)?),
            NodeKey::LogicalPath(path) => NodeAddr::logical_path(self.find_logical_path(path)?),
            NodeKey::LinkPath(path, link) => self.find_link_path(path, link)?,
            NodeKey::Established => NodeAddr::ESTABLISHED,
            NodeKey::Recovery(path, link) => {
                let link = self.find_link_path(path, link)?;
                NodeAddr::recovery(link.slot, link.sub)
            }
        };
        self.alive(addr).then_some(addr)
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
            ($lend:ident($($a:expr),*), $lv:ident, $h:ty, $c:ident) => {{
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
            ($lend:ident($($a:expr),*), $lv:ident, $h:ty, $c:ident) => {{
                let mut lent = tree.$lend($($a,)* Records { lineage: lineage_taken, nodes: nodes_taken, now });
                <NodeData<T, L, $lv> as NodePositions<T, L, $lv, $h>>::expire_from_end(lent.lineage, &mut lent.others, r, now)
            }};
        }
        by_layer!(addr, go)
    }

    /// The handler of the events `events` (their bits) of the data
    /// component at `position`.
    fn on_events_action(
        &mut self,
        addr: NodeAddr,
        position: usize,
        events: u64,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let r = self.tables.data[addr.layer] - 1 - position;
        let Self {
            tree,
            lineage_taken,
            nodes_taken,
            tables,
            ..
        } = self;
        let events =
            TriggeredEvents::new(events, &tables.subscriptions[addr.layer][position].handled);
        macro_rules! go {
            ($lend:ident($($a:expr),*), $lv:ident, $h:ty, $c:ident) => {{
                let mut lent = tree.$lend($($a,)* Records { lineage: lineage_taken, nodes: nodes_taken, now });
                <NodeData<T, L, $lv> as NodePositions<T, L, $lv, $h>>::on_events_from_end(events, lent.lineage, &mut lent.others, r, now)
            }};
        }
        by_layer!(addr, go)
    }

    /// The action before the calls of the `at`-th position of the layer
    /// that acts before them, at `position`.
    fn before_calls_action(
        &mut self,
        addr: NodeAddr,
        at: usize,
        position: usize,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let r = self.tables.data[addr.layer] - 1 - position;
        // the waker of an action before the calls follows the calls' own
        let waker = self.tables.calls[addr.layer] + at;
        let Self {
            tree,
            lineage_taken,
            nodes_taken,
            ..
        } = self;
        macro_rules! go {
            ($lend:ident($($a:expr),*), $lv:ident, $h:ty, $c:ident) => {{
                let mut lent = tree.$lend($($a,)* Records { lineage: lineage_taken, nodes: nodes_taken, now });
                let waker = &lent.wakers[waker];
                <NodeData<T, L, $lv> as NodePositions<T, L, $lv, $h>>::before_calls_from_end(lent.lineage, &mut lent.others, r, now, waker)
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
            ($lend:ident($($a:expr),*), $lv:ident, $h:ty, $c:ident) => {{
                let lent = tree.$lend($($a,)* Records { lineage: lineage_taken, nodes: nodes_taken, now });
                let waker = lent.wakers[index].clone();
                let mut cx = Context::from_waker(&waker);
                let loan = NodeLoan { lineage: lent.lineage, others: lent.others };
                <L as NodeCalls<T, L, $lv, <Q as CallPositions>::$c>>::poll_from_end::<Bundle<T, L, Q>>(&mut lent.calls.0, r, loan, &mut cx)
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

    /// The wakers of a node: one for each call, then one for each data
    /// position that acts before the calls.
    fn wakers(&self, addr: NodeAddr, marks: &Arc<WakeMarks>) -> Vec<Waker> {
        let data = self.tables.data[addr.layer];
        let calls = (0..self.tables.calls[addr.layer]).map(|index| data + index);
        let actors = self.tables.before_calls[addr.layer].iter().copied();
        calls
            .chain(actors)
            .map(|position| {
                Waker::from(Arc::new(PositionWaker {
                    shared: self.shared.clone(),
                    marks: marks.clone(),
                    addr,
                    position,
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

    /// A new node: its calls and its actions before the calls start woken,
    /// the deadlines it declares are read, and that it started is
    /// published.
    fn started(&mut self, addr: NodeAddr, now: InstantOf<T>, recorded: &mut Recorded) {
        let (data, calls) = (self.tables.data[addr.layer], self.tables.calls[addr.layer]);
        let woken = ((1u64 << calls) - 1) << data | self.tables.before_calls_marks[addr.layer];
        if woken != 0 {
            let marks = self.marks_at(addr).expect("a node just made");
            self.shared.wake(&marks, addr, woken);
        }
        for position in 0..data {
            if self.tables.has_deadline(addr.layer, position) {
                self.read_deadline(addr, position, now);
            }
        }
        recorded.events.push((addr, node_started(addr.layer)));
    }

    /// A node about to end: that it ends is published, and its deadlines
    /// go.
    fn ending(&mut self, addr: NodeAddr, todo: &mut Hits) {
        let recorded = Recorded {
            changes: SmallVec::new(),
            events: [(addr, node_ending(addr.layer))].into_iter().collect(),
        };
        self.hits(&recorded, None, todo);
        self.drop_deadlines(addr);
    }

    fn free_slot<X>(slots: &mut Vec<Option<X>>) -> usize {
        match slots.iter().position(Option::is_none) {
            Some(slot) => slot,
            None => {
                // one slot more at a time: a connection rarely has many
                slots.reserve_exact(1);
                slots.push(None);
                slots.len() - 1
            }
        }
    }

    fn build_connection(
        &mut self,
        args: &mut ConnectionArgsOf<T, L>,
        now: InstantOf<T>,
        recorded: &mut Recorded,
    ) {
        let data = <L as BuildNode<T, L, Connection, BwOf<Q>>>::build_node(
            &mut Lineage::new(HNil, &self.lineage_taken),
            args,
        );
        self.lineage_taken.clear();
        let calls =
            crate::call::ConnectionCalls(<L as NodeCalls<T, L, Connection, PcOf<Q>>>::start_all::<
                Bundle<T, L, Q>,
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
        self.started(NodeAddr::CONNECTION, now, recorded);
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

    fn build_entry(&mut self, link: T::Link, now: InstantOf<T>, recorded: &mut Recorded) -> usize {
        let id = link.id().clone();
        let mut args = LinkEntryArgs { link: Some(link) };
        let slot = Self::free_slot(&mut self.tree.entries);
        let data = {
            let connection = self.tree.connection.as_mut().expect("the connection node");
            let mut parents =
                Lineage::new(L::connection(&mut connection.data), &self.lineage_taken);
            <L as BuildNode<T, L, LinkEntry, BeOf<Q>>>::build_node(&mut parents, &mut args)
        };
        recorded.extend(self.recorded_for(&[NodeAddr::CONNECTION]));
        let calls =
            crate::call::LinkEntryCalls(<L as NodeCalls<T, L, LinkEntry, PeOf<Q>>>::start_all::<
                Bundle<T, L, Q>,
            >(&mut args));
        let addr = NodeAddr::entry(slot);
        let node = self.node(addr, NodeKey::LinkEntry(id), 0, data, calls, ());
        self.tree.entries[slot] = Some(node);
        self.started(addr, now, recorded);
        slot
    }

    fn build_logical_path(
        &mut self,
        args: &mut LogicalPathArgs<PathKey<L>>,
        now: InstantOf<T>,
        recorded: &mut Recorded,
    ) {
        if self.find_logical_path(&args.path).is_some() {
            return;
        }
        let slot = Self::free_slot(&mut self.tree.logical_paths);
        let data = {
            let connection = self.tree.connection.as_mut().expect("the connection node");
            let mut parents =
                Lineage::new(L::connection(&mut connection.data), &self.lineage_taken);
            <L as BuildNode<T, L, LogicalPath, BlOf<Q>>>::build_node(&mut parents, args)
        };
        recorded.extend(self.recorded_for(&[NodeAddr::CONNECTION]));
        let calls = crate::call::LogicalPathCalls(
            <L as NodeCalls<T, L, LogicalPath, PlOf<Q>>>::start_all::<Bundle<T, L, Q>>(args),
        );
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
        self.started(addr, now, recorded);
    }

    /// Build a link path. Without an entry for its logical link, the entry
    /// is built first and takes the clone of the link; otherwise the clone
    /// is dropped here.
    fn build_link_path(
        &mut self,
        request: LinkPathArgs<PathKey<L>, T::Link, InstantOf<T>>,
        now: InstantOf<T>,
        recorded: &mut Recorded,
    ) {
        let LinkPathArgs {
            path,
            link,
            role,
            peer_switched_local_id,
        } = request;
        let mut args = LinkPathArgs {
            path,
            link: link.id().clone(),
            role,
            peer_switched_local_id,
        };
        let Some(slot) = self.find_logical_path(&args.path) else {
            return;
        };
        if self.find_link_path(&args.path, &args.link).is_some() {
            return;
        }
        let entry = match self.find_entry(&args.link) {
            Some(entry) => entry,
            None => self.build_entry(link, now, recorded),
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
                &self.lineage_taken,
            );
            <L as BuildNode<T, L, LinkPath, BkOf<Q>>>::build_node(&mut parents, &mut args)
        };
        recorded.extend(self.recorded_for(&[
            NodeAddr::CONNECTION,
            NodeAddr::entry(entry),
            NodeAddr::logical_path(slot),
        ]));
        let calls =
            crate::call::LinkPathCalls(<L as NodeCalls<T, L, LinkPath, PkOf<Q>>>::start_all::<
                Bundle<T, L, Q>,
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
        self.started(addr, now, recorded);
    }

    fn build_established(
        &mut self,
        args: &mut EstablishedArgs,
        now: InstantOf<T>,
        recorded: &mut Recorded,
    ) {
        if self.tree.connection().child.is_some() {
            return;
        }
        let data = {
            let connection = self.tree.connection.as_mut().expect("the connection node");
            let mut parents =
                Lineage::new(L::connection(&mut connection.data), &self.lineage_taken);
            <L as BuildNode<T, L, Established, BsOf<Q>>>::build_node(&mut parents, args)
        };
        recorded.extend(self.recorded_for(&[NodeAddr::CONNECTION]));
        let calls = crate::call::EstablishedCalls(
            <L as NodeCalls<T, L, Established, PsOf<Q>>>::start_all::<Bundle<T, L, Q>>(args),
        );
        let node = self.node(
            NodeAddr::ESTABLISHED,
            NodeKey::Established,
            0,
            data,
            calls,
            (),
        );
        self.tree.connection().child = Some(node);
        self.started(NodeAddr::ESTABLISHED, now, recorded);
    }

    fn build_recovery(
        &mut self,
        args: &mut RecoveryArgs<PathKey<L>, LinkIdOf<T>>,
        now: InstantOf<T>,
        recorded: &mut Recorded,
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
                &self.lineage_taken,
            );
            <L as BuildNode<T, L, Recovery, BrOf<Q>>>::build_node(&mut parents, args)
        };
        let lineage = self.lineal(link);
        recorded.extend(self.recorded_for(&lineage));
        let calls =
            crate::call::RecoveryCalls(<L as NodeCalls<T, L, Recovery, PrOf<Q>>>::start_all::<
                Bundle<T, L, Q>,
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
        self.started(addr, now, recorded);
    }

    fn end_recovery(&mut self, link: NodeAddr, now: InstantOf<T>, todo: &mut Hits) {
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
            <L as BuildNode<T, L, Recovery, BrOf<Q>>>::end_node(
                node.data,
                &mut lineage,
                &mut others,
            );
        }
        let lineage = self.lineal(link);
        let recorded = self.recorded_for(&lineage);
        self.hits(&recorded, None, todo);
    }

    fn end_link_path(&mut self, link: NodeAddr, now: InstantOf<T>, todo: &mut Hits) {
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
            <L as BuildNode<T, L, LinkPath, BkOf<Q>>>::end_node(
                node.data,
                &mut parents,
                &mut others,
            );
        }
        let recorded = self.recorded_for(&[
            NodeAddr::CONNECTION,
            NodeAddr::entry(entry),
            NodeAddr::logical_path(link.slot),
        ]);
        self.hits(&recorded, None, todo);
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

    fn end_entry(&mut self, slot: usize, now: InstantOf<T>, todo: &mut Hits) {
        let addr = NodeAddr::entry(slot);
        self.ending(addr, todo);
        let node = self.tree.entries[slot].take().expect("alive");
        end_under_connection!(self, LinkEntry, BeOf<Q>, node.data, node.key, now);
        let recorded = self.recorded_for(&[NodeAddr::CONNECTION]);
        self.hits(&recorded, None, todo);
    }

    fn end_logical_path(&mut self, slot: usize, now: InstantOf<T>, todo: &mut Hits) {
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
        end_under_connection!(
            self,
            LogicalPath,
            BlOf<Q>,
            path.node.data,
            path.node.key,
            now
        );
        let recorded = self.recorded_for(&[NodeAddr::CONNECTION]);
        self.hits(&recorded, None, todo);
    }

    fn end_established(&mut self, end: EstablishedEnd, now: InstantOf<T>, todo: &mut Hits) {
        if self.tree.connection().child.is_none() {
            return;
        }
        self.ending(NodeAddr::ESTABLISHED, todo);
        let node = self.tree.connection().child.take().expect("checked");
        end_under_connection!(
            self,
            Established,
            BsOf<Q>,
            node.data,
            node.key,
            now,
            because end
        );
        let recorded = self.recorded_for(&[NodeAddr::CONNECTION]);
        self.hits(&recorded, None, todo);
    }

    fn move_recovery(&mut self, from: NodeAddr, to: NodeAddr, now: InstantOf<T>, todo: &mut Hits) {
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
        let mut recorded = Recorded::default();
        self.started(addr, now, &mut recorded);
        self.hits(&recorded, None, todo);
    }

    /// End every node from the bottom up, each component with its end
    /// action; what is queued or due is not run any more.
    fn end_connection(&mut self, now: InstantOf<T>, todo: &mut Hits) {
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
        self.end_established(EstablishedEnd::ConnectionClosed, now, todo);
        self.drop_deadlines(NodeAddr::CONNECTION);
        self.keep_remains(now);
        if let Some(node) = self.tree.connection.take() {
            let mut others = OtherNodes::<T, L, Bundle<T, L, Q>>::new(
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
            <L as BuildNode<T, L, Connection, BwOf<Q>>>::end_node(
                node.data,
                &mut Lineage::new(HNil, &self.lineage_taken),
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
        let told: Vec<NodeAddr> = if !panicked {
            self.live().collect()
        } else if let Some(connection) = &self.tree.connection {
            // lending the connection node and its established layer needs
            // nothing of the nodes below them, whatever the panic left of
            // them; the established layer's components mark and wake the
            // waits of the application's handles
            let mut told = vec![NodeAddr::CONNECTION];
            if connection.child.is_some() {
                told.push(NodeAddr::ESTABLISHED);
            }
            told
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
                ($lend:ident($($a:expr),*), $lv:ident, $h:ty, $c:ident) => {{
                    let mut lent = tree.$lend($($a,)* Records { lineage: lineage_taken, nodes: nodes_taken, now });
                    <NodeData<T, L, $lv> as NodePositions<T, L, $lv, $h>>::future_dropped_each(&mut lent.lineage, cause);
                }};
            }
            by_layer!(addr, go);
        }
        // nothing written or published is handled
        self.lineage_taken.clear();
        self.nodes_taken.clear();
        if panicked {
            self.keep_remains(now);
            // the nodes are dropped with the tree, and give back what they
            // hold; a waker of theirs kept elsewhere does nothing from here
            // on
            self.shared.closed.store(true, Ordering::SeqCst);
            self.tree.connection = None;
            self.tree.entries.clear();
            self.tree.logical_paths.clear();
            self.shared.queue().clear();
            self.timers.clear();
            self.deadlines.clear();
            self.sleep = None;
            self.ended = true;
            self.running = false;
        } else {
            self.end_connection(now, &mut Hits::new());
        }
    }

    /// Have the connection node's data components write what the parts
    /// keep after the end, and keep it; nothing they write or publish is
    /// handled.
    fn keep_remains(&mut self, now: InstantOf<T>) {
        let mut remains = RemainsOf::<T, L>::default();
        let Self {
            tree,
            lineage_taken,
            nodes_taken,
            ..
        } = self;
        if tree.connection.is_some() {
            let mut lent = tree.lend_connection(Records {
                lineage: lineage_taken,
                nodes: nodes_taken,
                now,
            });
            <NodeData<T, L, Connection> as NodePositions<T, L, Connection, HwOf<Q>>>::remains_each(
                &mut lent.lineage,
                &mut remains,
            );
        }
        self.lineage_taken.clear();
        self.nodes_taken.clear();
        self.remains = Some(remains);
    }

    /// A run of the driver's own code, a poll or a lend, did not return: a
    /// panic unwound through it. End as after a panic, once.
    fn end_unwound(&mut self) {
        if self.running && !self.ended {
            self.end_dropped();
            self.shared.outer.wake();
        }
    }

    /// The future that drives the connection from outside it, such as the
    /// one on a [`SharedConnection`](crate::shared::SharedConnection), is
    /// dropped: as when the driver itself is dropped, a connection that
    /// has not ended ends here, without a closing period, or after a panic
    /// that unwound through the driver only marks; the driver stays, so
    /// that lends see the end.
    pub fn driving_dropped(&mut self) {
        if !self.ended {
            (self.on_drop)(self);
        }
    }

    /// Lend the node `at` of the layer `Lv` to one operation from outside
    /// the tree, such as one of the application's handles.
    ///
    /// `op` is lent the node's data and the data of the nodes above it, as
    /// a handler of events is, with the instant the driver reads from its
    /// clock, and returns what it came to and the request it hands over.
    /// Afterwards the driver handles what it wrote and published and the
    /// request as after any lend: it reads the deadlines it wrote again,
    /// hands its events to their subscribers, applies the request, round
    /// after round, and a call that this wakes is polled at the next poll
    /// of the connection, whose waker it calls.
    ///
    /// When the connection runs and has no node there, nothing is lent;
    /// once it ended, `op` is not run and the error has what the parts keep
    /// after the end. A panic in `op` ends the connection as a panic in a
    /// poll does, at the next poll or lend.
    pub fn lend<Lv: LendableLayer, R>(
        &mut self,
        at: Lv::At<T, L>,
        op: impl for<'v> FnOnce(LineageOf<'v, T, L, Lv>, InstantOf<T>) -> (R, Option<RequestOf<T, L>>),
    ) -> Result<R, NotLent<'_, RemainsOf<T, L>>> {
        self.end_unwound();
        if self.ended {
            return Err(NotLent::Ended(
                self.remains.get_or_insert_with(Default::default),
            ));
        }
        let Some(addr) = Lv::find(&self.tree, &at) else {
            return Err(NotLent::Absent);
        };
        let now = self.clock.now();
        self.running = true;
        let (output, request) = {
            let Self {
                tree,
                lineage_taken,
                nodes_taken,
                ..
            } = self;
            let lineage = Lv::lineage(
                tree,
                Records {
                    lineage: lineage_taken,
                    nodes: nodes_taken,
                    now,
                },
            );
            op(lineage, now)
        };
        self.after_lend(addr, None, request, now);
        self.running = false;
        if self.ended {
            // the lend ended the connection: whoever drives it is done
            self.shared.outer.wake();
        }
        Ok(output)
    }

    /// Apply a request at once; one that no longer fits the structure is
    /// dropped. What the nodes made or ended reach goes into `todo`.
    fn apply(&mut self, request: RequestOf<T, L>, now: InstantOf<T>, todo: &mut Hits) {
        let mut recorded = Recorded::default();
        match request {
            StructureRequest::AddLogicalPath { mut args } => {
                self.build_logical_path(&mut args, now, &mut recorded)
            }
            StructureRequest::AddLinkPath { args } => {
                self.build_link_path(args, now, &mut recorded)
            }
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
                self.build_established(&mut args, now, &mut recorded)
            }
            StructureRequest::EndEstablished => {
                self.end_established(EstablishedEnd::ConnectionClosed, now, todo)
            }
            StructureRequest::RebuildEstablished { mut args } => {
                if self.tree.connection().child.is_some() {
                    self.end_established(EstablishedEnd::ZeroRttRejected, now, todo);
                    self.build_established(&mut args, now, &mut recorded);
                }
            }
            StructureRequest::AddRecovery { mut args } => {
                self.build_recovery(&mut args, now, &mut recorded)
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
            self.hits(&recorded, None, todo);
        }
    }

    /// Handle the hits, round after round, until a round publishes nothing
    /// subscribed to; requests returned on the way are applied at once. A
    /// position is handled once in a round: a call is woken; a data
    /// component's handler runs with the events that reached it, and the
    /// deadline it declares is
    /// read again.
    fn settle(&mut self, mut todo: Hits, now: InstantOf<T>) {
        let mut round = 0;
        while !todo.is_empty() && !self.ended {
            merge(&mut todo);
            round += 1;
            debug_assert!(
                round <= self.tables.positions * (self.live().count() + 1) + 1,
                "events did not settle"
            );
            let mut next = Hits::new();
            for hit in todo {
                let Hit {
                    addr,
                    position,
                    events,
                } = hit;
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
                if events != 0 {
                    let request = self.on_events_action(addr, position, events, now);
                    self.handled(addr, request, now, &mut next);
                }
                if !self.ended && self.alive(addr) && self.tables.has_deadline(addr.layer, position)
                {
                    self.read_deadline(addr, position, now);
                }
            }
            todo = next;
        }
    }

    /// After a handler of `addr`: what it recorded, then the
    /// request it returned.
    fn handled(
        &mut self,
        addr: NodeAddr,
        request: Option<RequestOf<T, L>>,
        now: InstantOf<T>,
        next: &mut Hits,
    ) {
        let recorded = self.recorded(addr);
        self.hits(&recorded, None, next);
        if let Some(request) = request {
            self.apply(request, now, next);
        }
    }

    /// After a lend of `addr`: the request it handed over, then the
    /// deadlines and the events.
    fn after_lend(
        &mut self,
        addr: NodeAddr,
        call: Option<usize>,
        request: Option<RequestOf<T, L>>,
        now: InstantOf<T>,
    ) {
        let recorded = self.recorded(addr);
        let mut todo = Hits::new();
        self.hits(&recorded, call.map(|position| (addr, position)), &mut todo);
        if let Some(request) = request {
            self.apply(request, now, &mut todo);
        }
        self.settle(todo, now);
    }

    /// Run the actions before the calls whose positions are marked: for
    /// each layer with components that act before them, the nodes above a
    /// node first, each node's in order, each followed by what follows a
    /// lend.
    fn run_before_calls(&mut self, now: InstantOf<T>) {
        for layer in 0..6 {
            let mask = self.tables.before_calls_marks[layer];
            if mask == 0 {
                continue;
            }
            // the actions can make and end nodes: go from one node to the
            // next one alive after it
            let mut next = self.live().find(|addr| addr.layer == layer);
            while let Some(addr) = next {
                let marks = self.marks_at(addr).expect("alive");
                // the node stays queued for its calls, if it is
                let woken = marks.take_some(mask);
                for at in 0..self.tables.before_calls[layer].len() {
                    if self.ended || !self.alive(addr) {
                        break;
                    }
                    let position = self.tables.before_calls[layer][at];
                    if woken & 1 << position == 0 {
                        continue;
                    }
                    let request = self.before_calls_action(addr, at, position, now);
                    self.after_lend(addr, None, request, now);
                }
                if self.ended {
                    return;
                }
                next = self.live().find(|a| a.layer == layer && *a > addr);
            }
        }
    }

    #[cfg(debug_assertions)]
    fn check_deadlines(&mut self, now: InstantOf<T>) {
        let live: Vec<NodeAddr> = self.live().collect();
        for addr in live {
            for position in 0..self.tables.data[addr.layer] {
                let at = self.deadline(addr, position, now);
                debug_assert_eq!(
                    self.deadlines.get(&(addr, position)).copied(),
                    at,
                    "a deadline changed and was not read again: a component with a deadline does not declare it, or does not subscribe to an event that moves it",
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
        self.run_before_calls(now);
        if self.ended {
            return Poll::Ready(());
        }
        // what the actions before the calls woke is polled in this poll
        let queued = self.shared.queue().len();
        for _ in 0..queued {
            let Some(addr) = self.shared.queue().pop_front() else {
                break;
            };
            let Some(marks) = self.marks_at(addr) else {
                continue;
            };
            let mut bits = marks.take();
            // an action before the calls woken since they ran runs at the
            // start of the next poll
            let actors = bits & self.tables.before_calls_marks[addr.layer];
            if actors != 0 {
                self.shared.wake(&marks, addr, actors);
                bits &= !actors;
            }
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
                    let recorded = self.recorded(addr);
                    let mut todo = Hits::new();
                    self.hits(&recorded, None, &mut todo);
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

impl<T, L, Q> Future for ConnectionDriver<T, L, Q>
where
    Q: DriverPositions<Data: LayerPositions, Builds: LayerPositions>,
    T: ConnectionChoices,
    for<'v> L: LineageLists<'v, T>,
    L: TreeCalls<T, Q>
        + NodeCalls<T, L, Connection, PcOf<Q>>
        + NodeCalls<T, L, LinkEntry, PeOf<Q>>
        + NodeCalls<T, L, LogicalPath, PlOf<Q>>
        + NodeCalls<T, L, LinkPath, PkOf<Q>>
        + NodeCalls<T, L, Established, PsOf<Q>>
        + NodeCalls<T, L, Recovery, PrOf<Q>>
        + BuildNode<T, L, Connection, BwOf<Q>>
        + BuildNode<T, L, LinkEntry, BeOf<Q>>
        + BuildNode<T, L, LogicalPath, BlOf<Q>>
        + BuildNode<T, L, LinkPath, BkOf<Q>>
        + BuildNode<T, L, Established, BsOf<Q>>
        + BuildNode<T, L, Recovery, BrOf<Q>>,
    PcOf<Q>: 'static,
    PeOf<Q>: 'static,
    PlOf<Q>: 'static,
    PkOf<Q>: 'static,
    PsOf<Q>: 'static,
    PrOf<Q>: 'static,
    NodeData<T, L, Connection>: NodePositions<T, L, Connection, HwOf<Q>>,
    NodeData<T, L, LinkEntry>: NodePositions<T, L, LinkEntry, HeOf<Q>>,
    NodeData<T, L, LogicalPath>: NodePositions<T, L, LogicalPath, HlOf<Q>>,
    NodeData<T, L, LinkPath>: NodePositions<T, L, LinkPath, HkOf<Q>>,
    NodeData<T, L, Established>: NodePositions<T, L, Established, HsOf<Q>>,
    NodeData<T, L, Recovery>: NodePositions<T, L, Recovery, HrOf<Q>>,
{
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let driver = self.get_mut();
        driver.end_unwound();
        driver.running = true;
        let turned = driver.turn(cx);
        driver.running = false;
        turned
    }
}

/// The future that drives it from its wrapper is dropped.
impl<T, L, Q> crate::shared::DrivenFromOutside for ConnectionDriver<T, L, Q>
where
    Q: DriverPositions<Data: LayerPositions, Builds: LayerPositions>,
    T: ConnectionChoices,
    for<'v> L: LineageLists<'v, T>,
    L: TreeCalls<T, Q>
        + NodeCalls<T, L, Connection, PcOf<Q>>
        + NodeCalls<T, L, LinkEntry, PeOf<Q>>
        + NodeCalls<T, L, LogicalPath, PlOf<Q>>
        + NodeCalls<T, L, LinkPath, PkOf<Q>>
        + NodeCalls<T, L, Established, PsOf<Q>>
        + NodeCalls<T, L, Recovery, PrOf<Q>>
        + BuildNode<T, L, Connection, BwOf<Q>>
        + BuildNode<T, L, LinkEntry, BeOf<Q>>
        + BuildNode<T, L, LogicalPath, BlOf<Q>>
        + BuildNode<T, L, LinkPath, BkOf<Q>>
        + BuildNode<T, L, Established, BsOf<Q>>
        + BuildNode<T, L, Recovery, BrOf<Q>>,
    PcOf<Q>: 'static,
    PeOf<Q>: 'static,
    PlOf<Q>: 'static,
    PkOf<Q>: 'static,
    PsOf<Q>: 'static,
    PrOf<Q>: 'static,
    NodeData<T, L, Connection>: NodePositions<T, L, Connection, HwOf<Q>>,
    NodeData<T, L, LinkEntry>: NodePositions<T, L, LinkEntry, HeOf<Q>>,
    NodeData<T, L, LogicalPath>: NodePositions<T, L, LogicalPath, HlOf<Q>>,
    NodeData<T, L, LinkPath>: NodePositions<T, L, LinkPath, HkOf<Q>>,
    NodeData<T, L, Established>: NodePositions<T, L, Established, HsOf<Q>>,
    NodeData<T, L, Recovery>: NodePositions<T, L, Recovery, HrOf<Q>>,
{
    fn driving_dropped(&mut self) {
        ConnectionDriver::driving_dropped(self);
    }
}

/// It lends its nodes as its own [`lend`](ConnectionDriver::lend) does.
impl<T, L, Q> LendNode<T, L> for ConnectionDriver<T, L, Q>
where
    Q: DriverPositions<Data: LayerPositions, Builds: LayerPositions>,
    T: ConnectionChoices,
    for<'v> L: LineageLists<'v, T>,
    L: TreeCalls<T, Q>
        + NodeCalls<T, L, Connection, PcOf<Q>>
        + NodeCalls<T, L, LinkEntry, PeOf<Q>>
        + NodeCalls<T, L, LogicalPath, PlOf<Q>>
        + NodeCalls<T, L, LinkPath, PkOf<Q>>
        + NodeCalls<T, L, Established, PsOf<Q>>
        + NodeCalls<T, L, Recovery, PrOf<Q>>
        + BuildNode<T, L, Connection, BwOf<Q>>
        + BuildNode<T, L, LinkEntry, BeOf<Q>>
        + BuildNode<T, L, LogicalPath, BlOf<Q>>
        + BuildNode<T, L, LinkPath, BkOf<Q>>
        + BuildNode<T, L, Established, BsOf<Q>>
        + BuildNode<T, L, Recovery, BrOf<Q>>,
    PcOf<Q>: 'static,
    PeOf<Q>: 'static,
    PlOf<Q>: 'static,
    PkOf<Q>: 'static,
    PsOf<Q>: 'static,
    PrOf<Q>: 'static,
    NodeData<T, L, Connection>: NodePositions<T, L, Connection, HwOf<Q>>,
    NodeData<T, L, LinkEntry>: NodePositions<T, L, LinkEntry, HeOf<Q>>,
    NodeData<T, L, LogicalPath>: NodePositions<T, L, LogicalPath, HlOf<Q>>,
    NodeData<T, L, LinkPath>: NodePositions<T, L, LinkPath, HkOf<Q>>,
    NodeData<T, L, Established>: NodePositions<T, L, Established, HsOf<Q>>,
    NodeData<T, L, Recovery>: NodePositions<T, L, Recovery, HrOf<Q>>,
{
    fn lend<Lv: LendableLayer, R>(
        &mut self,
        at: Lv::At<T, L>,
        op: impl for<'v> FnOnce(LineageOf<'v, T, L, Lv>, InstantOf<T>) -> (R, Option<RequestOf<T, L>>),
    ) -> Result<R, NotLent<'_, RemainsOf<T, L>>> {
        ConnectionDriver::lend::<Lv, R>(self, at, op)
    }
}
