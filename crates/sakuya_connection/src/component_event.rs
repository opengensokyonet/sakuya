//! Component events: what happened in a node, published by whoever made it
//! happen and handed to the data components and calls that subscribe to it.
//!
//! An event is a type without contents, of the layer of the node it
//! happens in ([`ComponentEvent::Layer`]); a type parameter tells apart
//! events of one kind where that matters, such as the keys of one
//! encryption level. Whoever changes something publishes the event in its
//! lend: through the lineage, at the lineage's node of the event's layer
//! ([`Lineage::publish`](crate::take::Lineage::publish)), or at another node
//! by its key ([`OtherNodes::publish_at`](crate::others::OtherNodes::publish_at)).
//! A method that changes a component returns what happened as a
//! [`Happened`], which must be published. The driver publishes
//! [`NodeStarted`] and [`NodeEnding`] itself.
//!
//! Data components and kinds of calls declare what they subscribe to
//! ([`EventSubscriptions`]); the driver makes one table from event type to
//! subscribers when it makes the connection. After a lend, an event
//! published at a node reaches what subscribes to it in that node, in the
//! node above it of the subscriber's layer, and in the nodes below it;
//! nodes beside it of the same layer do not get it. A position is handled
//! at most once in a round, with every event that reached it: a data
//! component's handler runs with the set of them ([`TriggeredEvents`]), a
//! call is woken. A data component may subscribe to an event only for its
//! deadline, which the driver then reads again without running the
//! handler. What the handlers publish is handled in the next round, until
//! a round publishes nothing.
//!
//! The events of the connection's records, such as qlog's, are another
//! thing: [`v1::events`](crate::v1::events).
use core::{any::TypeId, marker::PhantomData};

use crate::layer::{Connection, Established, Layer, LinkEntry, LinkPath, LogicalPath, Recovery};

/// Something that happened in a node of the layer [`Layer`](Self::Layer).
pub trait ComponentEvent: 'static {
    /// The layer of the node it happens in.
    type Layer: Layer;
}

/// The event `E` happened: what a method that changes a component returns,
/// for whoever called it to publish in its lend.
#[must_use = "what happened is to be published in the lend"]
pub struct Happened<E>(PhantomData<fn() -> E>);

impl<E: ComponentEvent> Happened<E> {
    /// `E` happened.
    #[inline]
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<E: ComponentEvent> Default for Happened<E> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<E> core::fmt::Debug for Happened<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Happened<{}>", core::any::type_name::<E>())
    }
}

/// A node of the layer `Lv` was built. The driver publishes it at the new
/// node, once its deadlines are read and its calls woken.
pub struct NodeStarted<Lv>(PhantomData<fn() -> Lv>);
impl<Lv: Layer> ComponentEvent for NodeStarted<Lv> {
    type Layer = Lv;
}

/// A node of the layer `Lv` is about to end. The driver publishes it at the
/// node while the node is still in the tree; the subscribers run once it
/// is gone, so only those of the nodes above it run.
pub struct NodeEnding<Lv>(PhantomData<fn() -> Lv>);
impl<Lv: Layer> ComponentEvent for NodeEnding<Lv> {
    type Layer = Lv;
}

/// [`NodeStarted`] of the layer at `layer`.
pub(crate) fn node_started(layer: usize) -> TypeId {
    by_layer::<Started>(layer)
}

/// [`NodeEnding`] of the layer at `layer`.
pub(crate) fn node_ending(layer: usize) -> TypeId {
    by_layer::<Ending>(layer)
}

trait ByLayer {
    fn of<Lv: Layer>() -> TypeId;
}
struct Started;
impl ByLayer for Started {
    fn of<Lv: Layer>() -> TypeId {
        TypeId::of::<NodeStarted<Lv>>()
    }
}
struct Ending;
impl ByLayer for Ending {
    fn of<Lv: Layer>() -> TypeId {
        TypeId::of::<NodeEnding<Lv>>()
    }
}

fn by_layer<K: ByLayer>(layer: usize) -> TypeId {
    match layer {
        Connection::INDEX => K::of::<Connection>(),
        LinkEntry::INDEX => K::of::<LinkEntry>(),
        LogicalPath::INDEX => K::of::<LogicalPath>(),
        LinkPath::INDEX => K::of::<LinkPath>(),
        Established::INDEX => K::of::<Established>(),
        Recovery::INDEX => K::of::<Recovery>(),
        _ => unreachable!("six layers"),
    }
}

/// What a data component or a kind of call subscribes to: the events its
/// handler runs for, or that wake the call, and, for a data component, the
/// events it subscribes to only for its deadline.
#[derive(Debug, Default)]
pub struct EventSubscriptions {
    pub(crate) handled: Vec<TypeId>,
    pub(crate) for_deadline: Vec<TypeId>,
}

impl EventSubscriptions {
    /// Subscribe to `E`: a data component's handler runs once it happened,
    /// a call is woken.
    ///
    /// The handler is told which of these events reached it, by the order
    /// they were added in; a position subscribes to at most 64.
    pub fn add<E: ComponentEvent>(&mut self) -> &mut Self {
        let event = TypeId::of::<E>();
        if !self.handled.contains(&event) {
            self.handled.push(event);
        }
        self
    }

    /// Subscribe to `E` for the deadline only: once it happened, the driver
    /// reads the deadline again and does not run the handler. For data
    /// components only; an event also [added](Self::add) runs the handler.
    pub fn for_deadline<E: ComponentEvent>(&mut self) -> &mut Self {
        let event = TypeId::of::<E>();
        if !self.for_deadline.contains(&event) {
            self.for_deadline.push(event);
        }
        self
    }
}

/// The events that reached a data component's handler in one round, of
/// those it subscribed to with [`EventSubscriptions::add`]: one bit for
/// each, without allocating.
#[derive(Clone, Copy)]
pub struct TriggeredEvents<'a> {
    bits: u64,
    subscribed: &'a [TypeId],
}

impl<'a> TriggeredEvents<'a> {
    pub(crate) fn new(bits: u64, subscribed: &'a [TypeId]) -> Self {
        Self { bits, subscribed }
    }

    /// Whether `E` is among them.
    pub fn contains<E: ComponentEvent>(&self) -> bool {
        let event = TypeId::of::<E>();
        self.subscribed
            .iter()
            .position(|&e| e == event)
            .is_some_and(|at| self.bits & 1 << at != 0)
    }

    /// Whether none reached it.
    pub fn is_empty(&self) -> bool {
        self.bits == 0
    }
}

impl core::fmt::Debug for TriggeredEvents<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TriggeredEvents")
            .field("bits", &format_args!("{:#b}", self.bits))
            .finish()
    }
}
