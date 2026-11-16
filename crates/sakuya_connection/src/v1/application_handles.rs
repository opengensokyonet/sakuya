//! The handles of a connection of version 1 in the application's hands:
//! the connection handle ([`connection`]), the handle of an established
//! layer ([`established_layer`]), and the stream writers and readers
//! ([`stream`]).
//!
//! The connection handle is there from the moment the connection is made:
//! it asks for the close, waits for the reason, the handshake's result and
//! the handles of the established layers. It shares a cell with the
//! connection node ([`connection::ConnectionHandleCell`]), which follows
//! the record of why the connection closed and learns from the advancing
//! call and the components of the established layer what happened. An
//! established layer's handle opens and accepts the streams of that one
//! layer; their writers and readers end with it.
//!
//! Each part of the composition gives each level of handle a share of its
//! own ([`HandleShare`]), `HNil` where it gives none, as it holds a share
//! of each layer of the tree; a handle holds the shares of every part, in
//! the order of the list of parts. Only the established layer's handle has
//! shares yet: version 1's is the stream set's handle, the DATAGRAM
//! extension's the handle of its queues.
//!
//! What each handle can do is a trait ([`established_layer::OpenStreams`],
//! [`established_layer::AcceptStreams`], [`stream::StreamWrite`],
//! [`stream::StreamRead`]), implemented on the handle, with the place of
//! the share it uses and of the intent it publishes inferred where it is
//! called; the [prelude](crate::prelude) brings them in. The bytes of a
//! stream are read and written through nitori_io's `Read`, `ReadChunk` and
//! `Write`.

pub mod connection;
pub mod established_layer;
pub mod stream;

use sakuya_stream::connection::LayerEnd;
use sakuya_wire::parts::{HCons, HNil};

use crate::take::{Here, There};

/// The levels of handles a part gives a share to.
pub mod handle {
    /// The handle of an established layer
    /// ([`EstablishedLayerHandle`](super::established_layer::EstablishedLayerHandle)).
    #[derive(Debug)]
    pub struct EstablishedLayer;
}

/// What the part `Self` gives each handle of the level `Hv`
/// (`HandleShare`), as [`LayerShare`](crate::share::LayerShare) is what it
/// holds in each node of a layer.
///
/// `T` is the choices of the composition, `L` the full list of parts. A
/// part that gives the level nothing gives `HNil`; any other share names
/// the part it is of ([`KeyedHandleShare`]), so that a handle's capability
/// finds it among the shares and the component that makes it hands it to
/// the connection handle's cell.
pub trait HandleShare<T, L, Hv> {
    /// The share.
    type Share: HandleShareSlot;
}

/// The shares of a list of parts for the level `Hv` (`HandleShares`):
/// each part's, in the order of the list; `Full` is the whole list.
pub trait HandleShares<T, Full, Hv> {
    /// Each part's share, in the order of the list.
    type Shares: HandleShareSlots;
}

impl<T, Full, Hv> HandleShares<T, Full, Hv> for HNil {
    type Shares = HNil;
}

impl<T, Full, Hv, P, Ps> HandleShares<T, Full, Hv> for HCons<P, Ps>
where
    P: HandleShare<T, Full, Hv>,
    Ps: HandleShares<T, Full, Hv>,
{
    type Shares = HCons<P::Share, Ps::Shares>;
}

/// The shares of the parts `L` of the choices `T` for the level `Hv`.
pub type HandleSharesOf<T, L, Hv> = <L as HandleShares<T, L, Hv>>::Shares;

/// A share of a handle that a part gives (`KeyedHandleShare`): `Part` is
/// the part, which a capability looks the share up by.
pub trait KeyedHandleShare {
    /// The part that gives the share.
    type Part;
}

/// A share as the connection handle's cell waits for it (`HandleShareSlot`):
/// a share of a part, until the component that makes it hands it over;
/// `HNil`, the share of a part that gives none, is there at once.
pub trait HandleShareSlot: Sized + Clone {
    /// The share, when its slot has it.
    fn collected(slot: &Option<Self>) -> Option<Self>;
}

/// The share a part gives is in its slot once it was handed over.
impl<S: KeyedHandleShare + Clone> HandleShareSlot for S {
    fn collected(slot: &Option<S>) -> Option<S> {
        slot.clone()
    }
}

/// A part that gives no share hands nothing over.
impl HandleShareSlot for HNil {
    fn collected(_: &Option<HNil>) -> Option<HNil> {
        Some(HNil)
    }
}

/// What a share of a handle does when the connection's driver panicked
/// (`DriverPanicHandleShare`): the share's part had its node dropped with
/// the tree, and no end action ran, so the waits on the share hear of the
/// end from here. `C` is this endpoint's reason for closing.
///
/// The connection handle's cell calls it on every share of the layer whose
/// handle it gave, in the order of the shares; `HNil`, the share of a part
/// that gives none, does nothing.
pub trait DriverPanicHandleShare<C> {
    /// The driver panicked, and the layer ended as `end`: every wait on the
    /// share ends with it, and every later operation reports it.
    ///
    /// It only marks: it keeps `end` where the operations of the share look
    /// first, and wakes every waker kept, but changes no state machine, as
    /// it may run while the panic unwinds, where a second panic aborts the
    /// process. It takes its locks whatever a holder that panicked left
    /// of them.
    fn driver_panicked(&self, end: LayerEnd<C>);
}

/// A part that gives no share has nothing to end.
impl<C> DriverPanicHandleShare<C> for HNil {
    fn driver_panicked(&self, _: LayerEnd<C>) {}
}

/// Each share in the order of the shares.
impl<C, S, Ss> DriverPanicHandleShare<C> for HCons<S, Ss>
where
    S: DriverPanicHandleShare<C>,
    Ss: DriverPanicHandleShare<C>,
{
    fn driver_panicked(&self, end: LayerEnd<C>) {
        self.head.driver_panicked(end.clone());
        self.tail.driver_panicked(end);
    }
}

/// The shares of a handle as the connection handle's cell collects them
/// (`HandleShareSlots`): a slot for each share.
pub trait HandleShareSlots: Sized + Clone {
    /// A slot for each share, in the order of the shares.
    type Slots;

    /// Slots that have nothing yet.
    fn empty_slots() -> Self::Slots;

    /// Every share, once every slot has its share.
    fn collected(slots: &Self::Slots) -> Option<Self>;
}

impl HandleShareSlots for HNil {
    type Slots = HNil;

    fn empty_slots() -> HNil {
        HNil
    }

    fn collected(_: &HNil) -> Option<HNil> {
        Some(HNil)
    }
}

impl<S: HandleShareSlot, Ss: HandleShareSlots> HandleShareSlots for HCons<S, Ss> {
    type Slots = HCons<Option<S>, Ss::Slots>;

    fn empty_slots() -> Self::Slots {
        HCons {
            head: None,
            tail: Ss::empty_slots(),
        }
    }

    fn collected(slots: &Self::Slots) -> Option<Self> {
        Some(HCons {
            head: S::collected(&slots.head)?,
            tail: Ss::collected(&slots.tail)?,
        })
    }
}

/// The share the part `Key` gives, among the shares of a handle
/// (`FindHandleShare`): `I` is where it is, which the compiler infers.
///
/// A capability implemented on a handle names the share it uses as
/// [`Found`](Self::Found), so that the share's type parameters are those
/// of the implementation.
#[diagnostic::on_unimplemented(
    message = "the composition has no part `{Key}` that gives this handle a share",
    label = "no share of `{Key}` among these shares"
)]
pub trait FindHandleShare<Key, I>: HandleShareSlots {
    /// The share.
    type Found;

    /// The share among `self`.
    fn find(&self) -> &Self::Found;

    /// The slot of the share among `slots`.
    fn slot(slots: &mut Self::Slots) -> &mut Option<Self::Found>;
}

impl<S, Ss, Key> FindHandleShare<Key, Here> for HCons<S, Ss>
where
    S: KeyedHandleShare<Part = Key> + Clone,
    Ss: HandleShareSlots,
{
    type Found = S;

    fn find(&self) -> &S {
        &self.head
    }

    fn slot(slots: &mut Self::Slots) -> &mut Option<S> {
        &mut slots.head
    }
}

impl<S, Ss, Key, I> FindHandleShare<Key, There<I>> for HCons<S, Ss>
where
    S: HandleShareSlot,
    Ss: FindHandleShare<Key, I>,
{
    type Found = Ss::Found;

    fn find(&self) -> &Ss::Found {
        self.tail.find()
    }

    fn slot(slots: &mut Self::Slots) -> &mut Option<Ss::Found> {
        Ss::slot(&mut slots.tail)
    }
}
