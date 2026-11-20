//! Taking components out of a view by type.
//!
//! A view is a list of mutable borrows, one for each component of the
//! nodes it covers: one flat list for a node, and one flat list for each
//! node, in [`NodeCons`] cells, for a lineage of several. Taking components moves their borrows out and leaves a
//! [`TakenOut`] marker in their place, so the rest is a view again and keeps
//! the position of every component: what a lend took is recorded by
//! position, without looking at types at run time. Taking a component twice,
//! or one the view does not have, does not compile.
//!
//! The positions a take goes by (`I`, `Is`, `Hs`) are inferred where the
//! list of parts is concrete; generic code passes them on as type
//! parameters.

use frunk_core::hlist::HList;
pub use frunk_core::indices::{Here, There};
use sakuya_wire::parts::{HCons, HNil};

use core::{
    any::TypeId,
    cell::{Cell, RefCell},
    ops::{Deref, DerefMut},
};

use smallvec::SmallVec;

use crate::{
    component::ComponentTypeList,
    component_event::{ComponentEvent, Happened},
    layer::Layer,
    tree::NodeAddr,
};

/// What is left in a view where a component was taken out.
#[derive(Debug)]
pub struct TakenOut;

/// The value of a position in a list: [`Here`] is 0, [`There`] one more.
pub trait Position {
    /// The position.
    const VALUE: usize;
}
impl Position for Here {
    const VALUE: usize = 0;
}
impl<I: Position> Position for There<I> {
    const VALUE: usize = 1 + I::VALUE;
}

/// How many positions of a lineage are recorded: a node has at most 64,
/// and a lineage at most five nodes. Positions past them lie past the
/// lineage's nodes, which the driver ignores anyway.
const RECORDED_WORDS: usize = 5;

/// What one lend of a lineage records: the positions written, and the
/// component events published, each with the index of its layer.
///
/// It is filled through the borrows a lineage's takes give
/// ([`ComponentMut`]) and by its publications, and read by the driver
/// after the lend.
#[derive(Debug, Default)]
pub struct TakenPositions {
    positions: [Cell<u64>; RECORDED_WORDS],
    events: RefCell<SmallVec<[(usize, TypeId); 4]>>,
}

impl TakenPositions {
    #[inline]
    pub(crate) fn push(&self, position: usize) {
        if let Some(word) = self.positions.get(position / 64) {
            word.set(word.get() | 1 << (position % 64));
        }
    }
    /// The positions written, in order, each once; the record of them is
    /// cleared.
    pub(crate) fn drain(&mut self) -> impl Iterator<Item = usize> + '_ {
        self.positions.iter_mut().enumerate().flat_map(|(w, word)| {
            let mut bits = core::mem::take(word.get_mut());
            core::iter::from_fn(move || {
                (bits != 0).then(|| {
                    let at = bits.trailing_zeros() as usize;
                    bits &= bits - 1;
                    w * 64 + at
                })
            })
        })
    }
    pub(crate) fn publish(&self, layer: usize, event: TypeId) {
        self.events.borrow_mut().push((layer, event));
    }
    /// The events published, with their layers; the record of them is
    /// cleared.
    pub(crate) fn take_events(&mut self) -> SmallVec<[(usize, TypeId); 4]> {
        core::mem::take(self.events.get_mut())
    }
    pub(crate) fn clear(&mut self) {
        *self = Self::default();
    }
}

/// What a lend records of the nodes other than the lineage's: the
/// positions written, as (node, position), each once.
#[derive(Debug, Default)]
pub(crate) struct NodesWritten(RefCell<SmallVec<[(NodeAddr, usize); 8]>>);

impl NodesWritten {
    #[inline]
    fn push(&self, addr: NodeAddr, position: usize) {
        let mut written = self.0.borrow_mut();
        if !written.contains(&(addr, position)) {
            written.push((addr, position));
        }
    }
    /// The positions written; the record of them is cleared.
    pub(crate) fn take(&mut self) -> SmallVec<[(NodeAddr, usize); 8]> {
        core::mem::take(self.0.get_mut())
    }
}

test_util_pub! {
    /// Where the borrows of a take record their writes: the positions of a
    /// lineage, the positions of another node, or nowhere, for a take that
    /// only reads.
    ///
    /// Public only for tests: with the feature `test-util`.
    #[derive(Clone, Copy, Debug)]
    #[cfg_attr(
        feature = "test-util",
        expect(private_interfaces, reason = "only the driver records into another node")
    )]
    pub enum Sink<'a> {
        /// The positions of a lineage.
        Lineage(&'a TakenPositions),
        /// The positions of another node.
        Node(&'a NodesWritten, NodeAddr),
        /// Nowhere: the take only reads.
        Nowhere,
    }
}

impl Sink<'_> {
    #[inline]
    fn record(self, at: usize) {
        match self {
            Sink::Lineage(taken) => taken.push(at),
            Sink::Node(written, addr) => written.push(addr, at),
            Sink::Nowhere => {}
        }
    }
}

/// A component taken to change it: reading it through the borrow records
/// nothing; the first change through [`DerefMut`] records that the
/// component was written, by which the driver reads its deadline again.
/// What every mutable take gives.
pub struct ComponentMut<'a, X: ?Sized> {
    value: &'a mut X,
    sink: Sink<'a>,
    at: usize,
    written: bool,
}

impl<'a, X: ?Sized> ComponentMut<'a, X> {
    test_util_pub! {
        /// The component `value` at the position `at`, whose first change
        /// is recorded into `sink`.
        ///
        /// Public only for tests: with the feature `test-util`.
        #[inline]
        pub fn new(value: &'a mut X, sink: Sink<'a>, at: usize) -> Self {
            Self {
                value,
                sink,
                at,
                written: false,
            }
        }
    }
    #[inline]
    fn write(this: &mut Self) {
        if !this.written {
            this.written = true;
            this.sink.record(this.at);
        }
    }
    /// The borrow for all of `'a`, recorded as written.
    #[inline]
    pub fn into_mut(mut this: Self) -> &'a mut X {
        Self::write(&mut this);
        this.value
    }
    /// The same component for a shorter time; what is written through it is
    /// recorded as through this.
    #[inline]
    pub fn reborrow(this: &mut Self) -> ComponentMut<'_, X> {
        ComponentMut {
            value: &mut *this.value,
            sink: this.sink,
            at: this.at,
            written: this.written,
        }
    }
}

impl<X: ?Sized> Deref for ComponentMut<'_, X> {
    type Target = X;
    #[inline]
    fn deref(&self) -> &X {
        self.value
    }
}

impl<X: ?Sized> DerefMut for ComponentMut<'_, X> {
    #[inline]
    fn deref_mut(&mut self) -> &mut X {
        Self::write(self);
        self.value
    }
}

impl<X: ?Sized + core::fmt::Debug> core::fmt::Debug for ComponentMut<'_, X> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.value.fmt(f)
    }
}

/// The mutable borrows, for `'a`, of a list of component types, each as a
/// [`ComponentMut`].
pub trait RefsOf<'a> {
    /// One `ComponentMut<'a, _>` for each component, in order.
    type Out;
}
impl<'a> RefsOf<'a> for HNil {
    type Out = HNil;
}
impl<'a, X: 'a, Xs: RefsOf<'a>> RefsOf<'a> for HCons<X, Xs> {
    type Out = HCons<ComponentMut<'a, X>, Xs::Out>;
}

/// A list from which the component `X` can be taken for `'a`, at position
/// `I`.
#[diagnostic::on_unimplemented(
    message = "the component `{X}` cannot be taken from this view",
    label = "`{X}` is not in this view, or it is taken already",
    note = "a view holds each component of the lent node and the nodes above it once; another take or another participant of the same capability may have it"
)]
pub trait TakeAt<'a, X: 'a, I> {
    /// The list with [`TakenOut`] in the place of `X`.
    type Rest;
    /// Where `X` is in the list.
    const AT: usize;
    /// Move the borrow of `X` out.
    fn take_at(self) -> (&'a mut X, Self::Rest);
}
impl<'a, X: 'a, T> TakeAt<'a, X, Here> for HCons<&'a mut X, T> {
    type Rest = HCons<TakenOut, T>;
    const AT: usize = 0;
    #[inline]
    fn take_at(self) -> (&'a mut X, HCons<TakenOut, T>) {
        (
            self.head,
            HCons {
                head: TakenOut,
                tail: self.tail,
            },
        )
    }
}
impl<'a, X: 'a, H, T: TakeAt<'a, X, I>, I> TakeAt<'a, X, There<I>> for HCons<H, T> {
    type Rest = HCons<H, T::Rest>;
    const AT: usize = 1 + T::AT;
    #[inline]
    fn take_at(self) -> (&'a mut X, Self::Rest) {
        let (item, tail) = self.tail.take_at();
        (
            item,
            HCons {
                head: self.head,
                tail,
            },
        )
    }
}

/// A list from which the components `U` (a list of component types) can be
/// taken for `'a`, at the positions `Is`.
pub trait TakeEach<'a, U: RefsOf<'a>, Is> {
    /// The list with [`TakenOut`] in their places.
    type Rest;
    /// Move the borrows out, in the order of `U`, each recording its
    /// writes into `sink`.
    #[doc(hidden)]
    #[allow(private_interfaces)]
    fn take_each(self, sink: Sink<'a>) -> (U::Out, Self::Rest);
}
impl<'a, V> TakeEach<'a, HNil, HNil> for V {
    type Rest = V;
    #[inline]
    #[allow(private_interfaces)]
    fn take_each(self, _: Sink<'a>) -> (HNil, V) {
        (HNil, self)
    }
}
impl<'a, V, X: 'a, Us: RefsOf<'a>, I, Is> TakeEach<'a, HCons<X, Us>, HCons<I, Is>> for V
where
    V: TakeAt<'a, X, I>,
    V::Rest: TakeEach<'a, Us, Is>,
{
    type Rest = <V::Rest as TakeEach<'a, Us, Is>>::Rest;
    #[inline]
    #[allow(private_interfaces)]
    fn take_each(self, sink: Sink<'a>) -> (HCons<ComponentMut<'a, X>, Us::Out>, Self::Rest) {
        let (head, rest) = self.take_at();
        let head = ComponentMut::new(head, sink, V::AT);
        let (tail, rest) = rest.take_each(sink);
        (HCons { head, tail }, rest)
    }
}

/// A list from which the components `U` (a list of component types) can be
/// read together, at the positions `Is`.
///
/// It is to [`GetAt`] what [`TakeEach`] is to [`TakeAt`]: generic code
/// names the list once and passes on one type parameter for all of its
/// positions. The borrows' type depends on `U` alone, so generic code can
/// take them apart.
pub trait ReadEach<U: ComponentTypeList, Is> {
    /// Read the components, in the order of `U`.
    fn read_each(&self) -> U::Refs<'_>;
}
impl<V> ReadEach<HNil, HNil> for V {
    #[inline]
    fn read_each(&self) -> HNil {
        HNil
    }
}
impl<V, X: 'static, Xs: ComponentTypeList, I, Is> ReadEach<HCons<X, Xs>, HCons<I, Is>> for V
where
    V: GetAt<X, I> + ReadEach<Xs, Is>,
{
    #[inline]
    fn read_each(&self) -> HCons<&X, Xs::Refs<'_>> {
        HCons {
            head: self.get_at(),
            tail: <V as ReadEach<Xs, Is>>::read_each(self),
        }
    }
}

/// A list that holds a borrow of the component `X`, at position `I`.
#[diagnostic::on_unimplemented(
    message = "the component `{X}` is not in this view",
    label = "`{X}` is not in this view, or it is taken already"
)]
pub trait GetAt<X, I> {
    /// Where `X` is in the list.
    const AT: usize;
    /// Read `X`.
    fn get_at(&self) -> &X;
    /// Change `X`, through a list that already holds it mutably.
    fn get_at_mut(&mut self) -> &mut X;
}
impl<X, T> GetAt<X, Here> for HCons<&mut X, T> {
    const AT: usize = 0;
    #[inline]
    fn get_at(&self) -> &X {
        self.head
    }
    #[inline]
    fn get_at_mut(&mut self) -> &mut X {
        self.head
    }
}
impl<X, H, T: GetAt<X, I>, I> GetAt<X, There<I>> for HCons<H, T> {
    const AT: usize = 1 + T::AT;
    #[inline]
    fn get_at(&self) -> &X {
        self.tail.get_at()
    }
    #[inline]
    fn get_at_mut(&mut self) -> &mut X {
        self.tail.get_at_mut()
    }
}

/// A list that holds, at position `I`, a borrow of the component `X` that
/// may be absent (`GetOptionalAt`): an element a lend appends to a lineage
/// from a node outside it, such as the established layer's stream set,
/// which is `None` while there is no such node.
#[diagnostic::on_unimplemented(
    message = "the component `{X}` is not appended to this view",
    label = "`{X}` is not appended to this view"
)]
pub trait GetOptionalAt<X, I> {
    /// Where `X` is in the list.
    const AT: usize;
    /// Change `X`, if it is there.
    fn get_optional_at_mut(&mut self) -> Option<ComponentMut<'_, X>>;
}
impl<X, T> GetOptionalAt<X, Here> for HCons<Option<ComponentMut<'_, X>>, T> {
    const AT: usize = 0;
    #[inline]
    fn get_optional_at_mut(&mut self) -> Option<ComponentMut<'_, X>> {
        self.head.as_mut().map(ComponentMut::reborrow)
    }
}
impl<X, H, T: GetOptionalAt<X, I>, I> GetOptionalAt<X, There<I>> for HCons<H, T> {
    const AT: usize = 1 + T::AT;
    #[inline]
    fn get_optional_at_mut(&mut self) -> Option<ComponentMut<'_, X>> {
        self.tail.get_optional_at_mut()
    }
}

/// A list with the list `Ys` appended at its end (`AppendEach`).
pub trait AppendEach<Ys> {
    /// The list with the elements of `Ys` last, in their order.
    type Out;
    /// Put the elements of `last` at the end.
    fn append_each(self, last: Ys) -> Self::Out;
}
impl<Ys> AppendEach<Ys> for HNil {
    type Out = Ys;
    #[inline]
    fn append_each(self, last: Ys) -> Ys {
        last
    }
}
impl<Ys, H, T: AppendEach<Ys>> AppendEach<Ys> for HCons<H, T> {
    type Out = HCons<H, T::Out>;
    #[inline]
    fn append_each(self, last: Ys) -> Self::Out {
        HCons {
            head: self.head,
            tail: self.tail.append_each(last),
        }
    }
}

/// A list of component types whose mutable borrows are there together or
/// not at all, each held as one that may be absent (`OptionalRefs`): the
/// components of a node outside a lineage that a lend appends to it, such
/// as those of the established layer, which are `None` while there is no
/// such node.
pub trait OptionalRefs: for<'a> RefsOf<'a> + 'static {
    /// One `Option<ComponentMut<'a, X>>` for each component, in order.
    type Optional<'a>;
    /// Each borrow of `refs`, or `None` for each when there are none.
    fn spread<'a>(refs: Option<<Self as RefsOf<'a>>::Out>) -> Self::Optional<'a>
    where
        Self: 'a;
    /// Every borrow again for the shorter `'s`, positions kept: what a lend
    /// that appends them for one frame after another passes on each time.
    fn reborrow<'s, 'a: 's>(refs: &'s mut Self::Optional<'a>) -> Self::Optional<'s>;
}
impl OptionalRefs for HNil {
    type Optional<'a> = HNil;
    #[inline]
    fn spread<'a>(_: Option<<Self as RefsOf<'a>>::Out>) -> HNil
    where
        Self: 'a,
    {
        HNil
    }
    #[inline]
    fn reborrow<'s, 'a: 's>(_: &'s mut HNil) -> HNil {
        HNil
    }
}
impl<X: 'static, Xs: OptionalRefs> OptionalRefs for HCons<X, Xs> {
    type Optional<'a> = HCons<Option<ComponentMut<'a, X>>, Xs::Optional<'a>>;
    #[inline]
    fn spread<'a>(refs: Option<<Self as RefsOf<'a>>::Out>) -> Self::Optional<'a>
    where
        Self: 'a,
    {
        match refs {
            Some(HCons { head, tail }) => HCons {
                head: Some(head),
                tail: Xs::spread(Some(tail)),
            },
            None => HCons {
                head: None,
                tail: Xs::spread(None),
            },
        }
    }
    #[inline]
    fn reborrow<'s, 'a: 's>(refs: &'s mut Self::Optional<'a>) -> Self::Optional<'s> {
        HCons {
            head: refs.head.as_mut().map(ComponentMut::reborrow),
            tail: Xs::reborrow(&mut refs.tail),
        }
    }
}

/// The lineage list `V` with the borrows of the components `U` (a list of
/// component types), each of which may be absent, appended last for `'s`.
pub type WithOptionals<'s, V, U> = <V as AppendEach<<U as OptionalRefs>::Optional<'s>>>::Out;

/// A list of borrows borrowed again for a shorter time, positions kept.
///
/// It is implemented for every `'s`, not only one the borrows outlive:
/// [`reborrow`](Self::reborrow) takes the list for `'s`, so it can only be
/// called for one they do, and a bound that holds for every pair of
/// lifetimes, such as `for<'v, 's> <L as LineageLists<'v, T>>::LinkPath:
/// Reborrow<'s>`, can be met.
pub trait Reborrow<'s> {
    /// The list with every borrow shortened to `'s`.
    type Out;
    /// Borrow every element again.
    fn reborrow(&'s mut self) -> Self::Out;
}
impl<'s> Reborrow<'s> for HNil {
    type Out = HNil;
    #[inline]
    fn reborrow(&'s mut self) -> HNil {
        HNil
    }
}
impl<'s, X: 's, T: Reborrow<'s>> Reborrow<'s> for HCons<&mut X, T> {
    type Out = HCons<&'s mut X, T::Out>;
    #[inline]
    fn reborrow(&'s mut self) -> Self::Out {
        HCons {
            head: &mut *self.head,
            tail: self.tail.reborrow(),
        }
    }
}
impl<'s, X: 's, T: Reborrow<'s>> Reborrow<'s> for HCons<Option<ComponentMut<'_, X>>, T> {
    type Out = HCons<Option<ComponentMut<'s, X>>, T::Out>;
    #[inline]
    fn reborrow(&'s mut self) -> Self::Out {
        HCons {
            head: self.head.as_mut().map(ComponentMut::reborrow),
            tail: self.tail.reborrow(),
        }
    }
}
impl<'s, T: Reborrow<'s>> Reborrow<'s> for HCons<TakenOut, T> {
    type Out = HCons<TakenOut, T::Out>;
    #[inline]
    fn reborrow(&'s mut self) -> Self::Out {
        HCons {
            head: TakenOut,
            tail: self.tail.reborrow(),
        }
    }
}

/// A node's data and the data of the nodes above it, one list for each
/// node: what a call, an expiry or a handler of events is lent first.
///
/// For a link path it is the data of the connection, of the link path's
/// logical link entry, of its logical path and of the link path itself.
/// Components are taken out by type with [`Take`]; what is left is a
/// lineage again. A component taken mutably is recorded as written at its
/// first change, and the driver reads its deadline again when it declares
/// one.
pub struct Lineage<'r, V> {
    list: V,
    taken: &'r TakenPositions,
}

impl<'r, V> Lineage<'r, V> {
    test_util_pub! {
        /// The lineage of the components `list`, whose changes are
        /// recorded into `taken`.
        ///
        /// Public only for tests: with the feature `test-util`.
        pub fn new(list: V, taken: &'r TakenPositions) -> Self {
            Self { list, taken }
        }
    }

    /// Read the component `X`, without taking it.
    #[inline]
    pub fn get<X, I>(&self) -> &X
    where
        V: GetAt<X, I>,
    {
        self.list.get_at()
    }

    /// Read the components `U` (a list of component types) together, as
    /// shared borrows in the order of `U`, without taking them.
    #[inline]
    pub fn read_each<U: ComponentTypeList, Is>(&self) -> U::Refs<'_>
    where
        V: ReadEach<U, Is>,
    {
        self.list.read_each()
    }

    /// Change the component `X` in place, without taking it out; a change
    /// through the borrow is recorded as through a take.
    #[inline]
    pub fn get_mut<X, I>(&mut self) -> ComponentMut<'_, X>
    where
        V: GetAt<X, I>,
    {
        ComponentMut::new(self.list.get_at_mut(), Sink::Lineage(self.taken), V::AT)
    }

    /// Change the component `X` appended to the lineage, if it is there; a
    /// change is recorded in the node it was taken from.
    #[inline]
    pub fn get_optional_mut<X, I>(&mut self) -> Option<ComponentMut<'_, X>>
    where
        V: GetOptionalAt<X, I>,
    {
        self.list.get_optional_at_mut()
    }

    /// This lineage with `last`, the borrows of the components `U` of a node
    /// outside it, each of which may be absent, appended at its end: frame
    /// sources that are found in another node take them from there
    /// ([`get_optional_mut`](Self::get_optional_mut)).
    #[inline]
    pub(crate) fn append_optionals<'s, U: OptionalRefs>(
        self,
        last: U::Optional<'s>,
    ) -> Lineage<'r, WithOptionals<'s, V, U>>
    where
        V: AppendEach<U::Optional<'s>>,
    {
        Lineage {
            list: self.list.append_each(last),
            taken: self.taken,
        }
    }

    /// Publish what happened at the lineage's node of the event's layer.
    ///
    /// The lineage has to have a node of that layer: an event of another
    /// node is published through the other nodes
    /// ([`OtherNodes::publish_at`](crate::others::OtherNodes::publish_at)).
    #[inline]
    pub fn publish<E: ComponentEvent>(&mut self, happened: Happened<E>) {
        let _ = happened;
        self.taken
            .publish(<E::Layer as Layer>::INDEX, TypeId::of::<E>());
    }

    /// This lineage again for a shorter time, with nothing taken, so that it
    /// can be taken from and still be there afterwards.
    #[inline]
    pub fn reborrow<'s>(&'s mut self) -> Lineage<'s, <V as Reborrow<'s>>::Out>
    where
        V: Reborrow<'s>,
    {
        Lineage {
            list: self.list.reborrow(),
            taken: self.taken,
        }
    }
}

/// A list of mutable borrows made shared: what a take to read only gives.
pub(crate) trait ShareEach {
    /// One shared borrow for each, in order.
    type Out;
    /// Make every borrow shared.
    fn share_each(self) -> Self::Out;
}
impl ShareEach for HNil {
    type Out = HNil;
    #[inline]
    fn share_each(self) -> HNil {
        HNil
    }
}
impl<'a, X, T: ShareEach> ShareEach for HCons<ComponentMut<'a, X>, T> {
    type Out = HCons<&'a X, T::Out>;
    #[inline]
    fn share_each(self) -> Self::Out {
        HCons {
            head: &*self.head.value,
            tail: self.tail.share_each(),
        }
    }
}

impl<'r, V> Lineage<'r, V> {
    /// Take the components `U` out to read them only, as shared borrows in
    /// the order of `U`, with the rest of the view, which can then be taken
    /// from or lent mutably while they are read.
    ///
    /// Nothing can change them through the borrows given, so the take is
    /// not recorded as a write.
    #[inline]
    pub(crate) fn take_read<'a, U, Is>(self) -> (<U::Out as ShareEach>::Out, Lineage<'r, V::Rest>)
    where
        V: TakeEach<'a, U, Is>,
        U: RefsOf<'a>,
        U::Out: ShareEach,
    {
        let Lineage { list, taken } = self;
        let (items, rest) = list.take_each(Sink::Nowhere);
        (items.share_each(), Lineage { list: rest, taken })
    }
}

/// Take named components out of a view.
///
/// `U` is the list of component types, as in
/// `Take::<HList![Pto, Rtt], _>::take(lineage)`; the components come back as
/// mutable borrows in that order, with the rest of the view.
pub trait Take<'a, U: RefsOf<'a>, Is>: Sized {
    /// What is left of the view.
    type Rest;
    /// Take the components.
    fn take(self) -> (U::Out, Self::Rest);
}
impl<'r: 'a, 'a, V: TakeEach<'a, U, Is>, U: RefsOf<'a>, Is> Take<'a, U, Is> for Lineage<'r, V> {
    type Rest = Lineage<'r, V::Rest>;
    #[inline]
    fn take(self) -> (U::Out, Lineage<'r, V::Rest>) {
        let Lineage { list, taken } = self;
        let (items, rest) = list.take_each(Sink::Lineage(taken));
        (items, Lineage { list: rest, taken })
    }
}

/// The borrows of a lineage of several nodes, one flat list for each node,
/// from the connection down: [`NodeCons`] cells ending in [`NodeNil`]. A
/// position in it is the node's place among them ([`InHeadNode`],
/// [`InTailNodes`]), then the component's place in that node's list, so
/// that a position stays short however many components the nodes above
/// hold; [`GetAt::AT`] and [`TakeAt::AT`] still count in the lineage as one
/// flat list.
#[derive(Debug)]
pub struct NodeCons<H, T> {
    /// The list of the first node.
    pub(crate) head: H,
    /// The lists of the nodes after it.
    pub(crate) tail: T,
}
/// No more nodes after a [`NodeCons`].
#[derive(Debug)]
pub struct NodeNil;

/// The position `I` in the first node's list of a [`NodeCons`].
#[derive(Debug)]
pub struct InHeadNode<I>(core::marker::PhantomData<I>);
/// The position `I` among the nodes after the first of a [`NodeCons`].
#[derive(Debug)]
pub struct InTailNodes<I>(core::marker::PhantomData<I>);

impl<'a, X: 'a, S: TakeAt<'a, X, I>, R, I> TakeAt<'a, X, InHeadNode<I>> for NodeCons<S, R> {
    type Rest = NodeCons<S::Rest, R>;
    const AT: usize = S::AT;
    #[inline]
    fn take_at(self) -> (&'a mut X, Self::Rest) {
        let (item, head) = self.head.take_at();
        (
            item,
            NodeCons {
                head,
                tail: self.tail,
            },
        )
    }
}
impl<'a, X: 'a, S: HList, R: TakeAt<'a, X, I>, I> TakeAt<'a, X, InTailNodes<I>> for NodeCons<S, R> {
    type Rest = NodeCons<S, R::Rest>;
    const AT: usize = <S as HList>::LEN + R::AT;
    #[inline]
    fn take_at(self) -> (&'a mut X, Self::Rest) {
        let (item, tail) = self.tail.take_at();
        (
            item,
            NodeCons {
                head: self.head,
                tail,
            },
        )
    }
}
impl<X, S: GetAt<X, I>, R, I> GetAt<X, InHeadNode<I>> for NodeCons<S, R> {
    const AT: usize = S::AT;
    #[inline]
    fn get_at(&self) -> &X {
        self.head.get_at()
    }
    #[inline]
    fn get_at_mut(&mut self) -> &mut X {
        self.head.get_at_mut()
    }
}
impl<X, S: HList, R: GetAt<X, I>, I> GetAt<X, InTailNodes<I>> for NodeCons<S, R> {
    const AT: usize = <S as HList>::LEN + R::AT;
    #[inline]
    fn get_at(&self) -> &X {
        self.tail.get_at()
    }
    #[inline]
    fn get_at_mut(&mut self) -> &mut X {
        self.tail.get_at_mut()
    }
}
impl<X, S: GetOptionalAt<X, I>, R, I> GetOptionalAt<X, InHeadNode<I>> for NodeCons<S, R> {
    const AT: usize = S::AT;
    #[inline]
    fn get_optional_at_mut(&mut self) -> Option<ComponentMut<'_, X>> {
        self.head.get_optional_at_mut()
    }
}
impl<X, S: HList, R: GetOptionalAt<X, I>, I> GetOptionalAt<X, InTailNodes<I>> for NodeCons<S, R> {
    const AT: usize = <S as HList>::LEN + R::AT;
    #[inline]
    fn get_optional_at_mut(&mut self) -> Option<ComponentMut<'_, X>> {
        self.tail.get_optional_at_mut()
    }
}
impl<Ys> AppendEach<Ys> for NodeNil {
    type Out = NodeCons<Ys, NodeNil>;
    #[inline]
    fn append_each(self, last: Ys) -> Self::Out {
        NodeCons {
            head: last,
            tail: NodeNil,
        }
    }
}
impl<Ys, S, R: AppendEach<Ys>> AppendEach<Ys> for NodeCons<S, R> {
    type Out = NodeCons<S, R::Out>;
    #[inline]
    fn append_each(self, last: Ys) -> Self::Out {
        NodeCons {
            head: self.head,
            tail: self.tail.append_each(last),
        }
    }
}
impl<'s> Reborrow<'s> for NodeNil {
    type Out = NodeNil;
    #[inline]
    fn reborrow(&'s mut self) -> NodeNil {
        NodeNil
    }
}
impl<'s, S: Reborrow<'s>, R: Reborrow<'s>> Reborrow<'s> for NodeCons<S, R> {
    type Out = NodeCons<S::Out, R::Out>;
    #[inline]
    fn reborrow(&'s mut self) -> Self::Out {
        NodeCons {
            head: self.head.reborrow(),
            tail: self.tail.reborrow(),
        }
    }
}

#[cfg(test)]
mod tests {
    use frunk_core::{hlist, hlist_pat};
    use sakuya_wire::parts::HList;

    use super::*;

    #[test]
    fn a_reborrowed_lineage_is_there_again_after_a_take() {
        let (mut a, mut b) = (1u8, 2u16);
        let mut taken = TakenPositions::default();
        let mut lineage = Lineage::new(hlist![&mut a, &mut b], &taken);
        {
            let (hlist_pat![mut b], _) = Take::<HList![u16], _>::take(lineage.reborrow());
            *b += 1;
        }
        *lineage.get_mut::<u8, _>() += 1;
        assert_eq!(*lineage.get::<u16, _>(), 3);
        assert_eq!(taken.drain().collect::<Vec<_>>(), [0, 1]);
    }
}
