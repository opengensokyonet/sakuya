//! Data components: how they are built and ended, their deadlines, and how
//! they follow the components they read.
//!
//! A data component is a value in a node. Its deadline is part of its state
//! and the driver reads it after every lend that may have changed it; when
//! the deadline comes, the driver runs the component's expiry. A component
//! states which component types it reads; after a lend took one of them
//! mutably, the driver reads its deadline again and runs its reread.
use core::any::TypeId;
use core::ops::Add;

use sakuya_stream::connection::AbortCause;
use sakuya_wire::parts::{HCons, HNil, Sculptor};

use crate::{
    call::CallBundle,
    clock::{ConnectionChoices, InstantOf},
    layer::Layer,
    others::OtherNodes,
    request::StructureRequest,
    share::{LayerLineage, LayerShare, LayerShares, LineageLists, PathKey},
    take::Lineage,
};

/// The lineage a lend of a node of the layer `Lv` sees.
pub type LineageOf<'v, T, L, Lv> = Lineage<'v, <Lv as LayerLineage>::List<'v, T, L>>;
/// The lineage of the nodes above a node of the layer `Lv`.
pub type ParentsOf<'v, T, L, Lv> = Lineage<'v, <Lv as LayerLineage>::Parents<'v, T, L>>;
/// The facts a node of the layer `Lv` is built from.
pub type ArgsOf<T, L, Lv> = <Lv as Layer>::Args<T, L>;
/// A request of the choices `T` and the list of parts `L`.
pub type RequestOf<T, L> = StructureRequest<PathKey<L>, <T as ConnectionChoices>::Link>;

/// The component types something reads.
#[derive(Debug, Default)]
pub struct ReadSet(Vec<TypeId>);

impl ReadSet {
    /// The component type `X` is read.
    pub fn add<X: 'static>(&mut self) -> &mut Self {
        self.0.push(TypeId::of::<X>());
        self
    }
    /// Each component type of the list `U` is read.
    pub fn add_each<U: ComponentTypeList>(&mut self) -> &mut Self {
        U::add_to(self);
        self
    }
    pub(crate) fn contains(&self, ty: TypeId) -> bool {
        self.0.contains(&ty)
    }
}

/// A list of component types, read or added to a [`ReadSet`] together.
pub trait ComponentTypeList {
    /// One shared borrow for each component, in order.
    type Refs<'s>;
    /// Add each type of the list.
    fn add_to(reads: &mut ReadSet);
}
impl ComponentTypeList for HNil {
    type Refs<'s> = HNil;
    fn add_to(_: &mut ReadSet) {}
}
impl<X: 'static, Xs: ComponentTypeList> ComponentTypeList for HCons<X, Xs> {
    type Refs<'s> = HCons<&'s X, Xs::Refs<'s>>;
    fn add_to(reads: &mut ReadSet) {
        reads.add::<X>();
        Xs::add_to(reads);
    }
}

/// A data component of the layer `Lv`.
///
/// A component without a deadline and without reads keeps the defaults.
/// `T` is the choices, `L` the list of parts; `H` is whatever the
/// implementation infers its takes by.
pub trait DataComponent<T: ConnectionChoices, L, Lv: LayerLineage, H>
where
    for<'v> L: LineageLists<'v, T>,
{
    /// The component types its deadline and its reread read.
    fn reads(_reads: &mut ReadSet) {}
    /// Its earliest deadline, read from the lent node and the nodes above.
    fn deadline<'v>(_lineage: &LineageOf<'v, T, L, Lv>) -> Option<InstantOf<T>> {
        None
    }
    /// Its deadline has come: do what it is for.
    ///
    /// The driver calls it only when the deadline it reads just before is
    /// not later than `now`. Afterwards the deadline must be later than `now`
    /// or gone; debug builds check it. By default nothing.
    fn expire<'v, B: CallBundle>(
        _lineage: LineageOf<'v, T, L, Lv>,
        _others: &mut OtherNodes<'v, T, L, B>,
        _now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        None
    }
    /// A component it reads was taken mutably: look at it again.
    ///
    /// It may take components itself; that counts as a change for what reads
    /// them, round after round until a round takes nothing. A component
    /// first looks and takes only what it changes. By default nothing.
    fn reread<'v, B: CallBundle>(
        _lineage: LineageOf<'v, T, L, Lv>,
        _others: &mut OtherNodes<'v, T, L, B>,
        _now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        None
    }
    /// The connection's future is dropped before the connection ended.
    ///
    /// `cause` tells how: [`AbortCause::DriverDropped`] when the future is
    /// only dropped, [`AbortCause::Panicked`] when a panic unwound through
    /// it; it is never another cause.
    ///
    /// Dropped only, the driver calls it for every data component of every
    /// node, the nodes above a node first, and then ends every node: an end
    /// action sees what the components did here. Nothing is reread
    /// afterwards.
    ///
    /// After a panic the driver calls it for the data components of the
    /// connection node only, and ends no node: what the panic left of the
    /// other nodes is dropped as it is. By default nothing.
    fn future_dropped<'v>(_lineage: &mut LineageOf<'v, T, L, Lv>, _cause: AbortCause) {}
}

/// A data component without a deadline and without reads.
///
/// Its [`DataComponent`] implementation is this marker's; it keeps every
/// default, in every layer.
pub trait PassiveDataComponent {}

/// The position argument of the [`DataComponent`] implementation of every
/// [`PassiveDataComponent`]; it keeps that implementation apart from the
/// others.
#[derive(Debug)]
pub struct Passive;

impl<T: ConnectionChoices, L, Lv: LayerLineage, X: PassiveDataComponent>
    DataComponent<T, L, Lv, Passive> for X
where
    for<'v> L: LineageLists<'v, T>,
{
}

/// How a unit of components of a new node of the layer `Lv` is made, from
/// the facts of the node and the data of the nodes above it.
///
/// `Self` is a component, or a list of components made together. It cannot
/// fail: what could be missing was taken by whoever asked for the node and
/// is in `args`.
pub trait Build<T: ConnectionChoices, L, Lv: LayerLineage, H>: Sized
where
    for<'v> L: LineageLists<'v, T>,
{
    /// Make the unit.
    fn build<'v>(parents: &mut ParentsOf<'v, T, L, Lv>, args: &mut ArgsOf<T, L, Lv>) -> Self;
    /// The node is ended: the unit is handed over with the data of the nodes
    /// above it and the other nodes, as an expiry gets them; the ended
    /// node is out of the tree and the others' key is its key. By default
    /// it is dropped.
    fn end<'v, B: CallBundle>(
        self,
        _parents: &mut ParentsOf<'v, T, L, Lv>,
        _others: &mut OtherNodes<'v, T, L, B>,
    ) {
    }
}

/// How a unit of one component is built: by the component's own
/// [`Build`].
pub struct SingleUnit<H>(core::marker::PhantomData<H>);
impl<T: ConnectionChoices, L, Lv: LayerLineage, X: Build<T, L, Lv, H>, H>
    Build<T, L, Lv, SingleUnit<H>> for HCons<X, HNil>
where
    for<'v> L: LineageLists<'v, T>,
{
    #[inline]
    fn build<'v>(parents: &mut ParentsOf<'v, T, L, Lv>, args: &mut ArgsOf<T, L, Lv>) -> Self {
        HCons {
            head: X::build(parents, args),
            tail: HNil,
        }
    }
    #[inline]
    fn end<'v, B: CallBundle>(
        self,
        parents: &mut ParentsOf<'v, T, L, Lv>,
        others: &mut OtherNodes<'v, T, L, B>,
    ) {
        self.head.end(parents, others);
    }
}

/// Building a part's units one after the other, joined into its data.
pub trait BuildUnits<T: ConnectionChoices, L, Lv: LayerLineage, Hu>: Sized
where
    for<'v> L: LineageLists<'v, T>,
{
    /// The units joined.
    type Flat;
    /// Build every unit.
    fn build_units<'v>(
        parents: &mut ParentsOf<'v, T, L, Lv>,
        args: &mut ArgsOf<T, L, Lv>,
    ) -> Self::Flat;
    /// End every unit.
    fn end_units<'v, B: CallBundle>(
        flat: Self::Flat,
        parents: &mut ParentsOf<'v, T, L, Lv>,
        others: &mut OtherNodes<'v, T, L, B>,
    );
}
impl<T: ConnectionChoices, L, Lv: LayerLineage> BuildUnits<T, L, Lv, HNil> for HNil
where
    for<'v> L: LineageLists<'v, T>,
{
    type Flat = HNil;
    #[inline]
    fn build_units<'v>(_: &mut ParentsOf<'v, T, L, Lv>, _: &mut ArgsOf<T, L, Lv>) -> HNil {
        HNil
    }
    #[inline]
    fn end_units<'v, B: CallBundle>(
        _: HNil,
        _: &mut ParentsOf<'v, T, L, Lv>,
        _: &mut OtherNodes<'v, T, L, B>,
    ) {
    }
}
impl<T: ConnectionChoices, L, Lv: LayerLineage, U, Us, Bh, Iu, Hu>
    BuildUnits<T, L, Lv, HCons<(Bh, Iu), Hu>> for HCons<U, Us>
where
    for<'v> L: LineageLists<'v, T>,
    U: Build<T, L, Lv, Bh> + Add<Us::Flat>,
    Us: BuildUnits<T, L, Lv, Hu>,
    <U as Add<Us::Flat>>::Output: Sculptor<U, Iu, Remainder = Us::Flat>,
{
    type Flat = <U as Add<Us::Flat>>::Output;
    #[inline]
    fn build_units<'v>(
        parents: &mut ParentsOf<'v, T, L, Lv>,
        args: &mut ArgsOf<T, L, Lv>,
    ) -> Self::Flat {
        let unit = U::build(parents, args);
        unit + Us::build_units(parents, args)
    }
    #[inline]
    fn end_units<'v, B: CallBundle>(
        flat: Self::Flat,
        parents: &mut ParentsOf<'v, T, L, Lv>,
        others: &mut OtherNodes<'v, T, L, B>,
    ) {
        let (unit, rest) = flat.sculpt();
        unit.end(parents, others);
        Us::end_units(rest, parents, others);
    }
}

/// Building and ending a node's data: every part's units, in the order of
/// the list. `Full` is the whole list.
pub trait BuildNode<T: ConnectionChoices, Full, Lv: LayerLineage, Hp>:
    LayerShares<T, Full, Lv>
where
    for<'v> Full: LineageLists<'v, T>,
{
    /// Build the data of a node.
    fn build_node<'v>(
        parents: &mut ParentsOf<'v, T, Full, Lv>,
        args: &mut ArgsOf<T, Full, Lv>,
    ) -> <Self as LayerShares<T, Full, Lv>>::Data;
    /// End the data of a node.
    fn end_node<'v, B: CallBundle>(
        data: <Self as LayerShares<T, Full, Lv>>::Data,
        parents: &mut ParentsOf<'v, T, Full, Lv>,
        others: &mut OtherNodes<'v, T, Full, B>,
    );
}
impl<T: ConnectionChoices, Full, Lv: LayerLineage> BuildNode<T, Full, Lv, HNil> for HNil
where
    for<'v> Full: LineageLists<'v, T>,
{
    #[inline]
    fn build_node<'v>(_: &mut ParentsOf<'v, T, Full, Lv>, _: &mut ArgsOf<T, Full, Lv>) -> HNil {
        HNil
    }
    #[inline]
    fn end_node<'v, B: CallBundle>(
        _: HNil,
        _: &mut ParentsOf<'v, T, Full, Lv>,
        _: &mut OtherNodes<'v, T, Full, B>,
    ) {
    }
}
impl<T: ConnectionChoices, Full, Lv: LayerLineage, P, Ps, Hu, Hp>
    BuildNode<T, Full, Lv, HCons<Hu, Hp>> for HCons<P, Ps>
where
    for<'v> Full: LineageLists<'v, T>,
    P: LayerShare<T, Full, Lv>,
    P::Units: BuildUnits<T, Full, Lv, Hu, Flat = P::Data>,
    Ps: BuildNode<T, Full, Lv, Hp>,
{
    #[inline]
    fn build_node<'v>(
        parents: &mut ParentsOf<'v, T, Full, Lv>,
        args: &mut ArgsOf<T, Full, Lv>,
    ) -> <Self as LayerShares<T, Full, Lv>>::Data {
        let head = P::Units::build_units(parents, args);
        HCons {
            head,
            tail: Ps::build_node(parents, args),
        }
    }
    #[inline]
    fn end_node<'v, B: CallBundle>(
        data: <Self as LayerShares<T, Full, Lv>>::Data,
        parents: &mut ParentsOf<'v, T, Full, Lv>,
        others: &mut OtherNodes<'v, T, Full, B>,
    ) {
        P::Units::end_units(data.head, parents, others);
        Ps::end_node(data.tail, parents, others);
    }
}

/// The positions of one part's data components in a node, for the
/// driver's dispatch: a position is counted from the end, and each level
/// compares it with a constant.
pub trait PartPositions<T: ConnectionChoices, L, Lv: LayerLineage, Hs>
where
    for<'v> L: LineageLists<'v, T>,
{
    /// How many components.
    const LEN: usize;
    /// The type of each component, in order.
    fn types(out: &mut Vec<TypeId>);
    /// What each component reads, in order.
    fn reads(out: &mut Vec<ReadSet>);
    /// The deadline of the component at `r` from the end, when it is this
    /// part's; `after` is how many positions follow this part.
    fn try_deadline<'v>(
        lineage: &LineageOf<'v, T, L, Lv>,
        r: usize,
        after: usize,
    ) -> Option<Option<InstantOf<T>>>;
    /// The expiry of the component at `r` from the end, or the lineage back.
    #[allow(clippy::type_complexity)]
    fn try_expire<'v, B: CallBundle>(
        lineage: LineageOf<'v, T, L, Lv>,
        others: &mut OtherNodes<'v, T, L, B>,
        r: usize,
        after: usize,
        now: InstantOf<T>,
    ) -> Result<Option<RequestOf<T, L>>, LineageOf<'v, T, L, Lv>>;
    /// The reread of the component at `r` from the end, or the lineage back.
    #[allow(clippy::type_complexity)]
    fn try_reread<'v, B: CallBundle>(
        lineage: LineageOf<'v, T, L, Lv>,
        others: &mut OtherNodes<'v, T, L, B>,
        r: usize,
        after: usize,
        now: InstantOf<T>,
    ) -> Result<Option<RequestOf<T, L>>, LineageOf<'v, T, L, Lv>>;
    /// Tell each component, in order, that the connection's future is
    /// dropped, and how.
    fn future_dropped_each<'v>(lineage: &mut LineageOf<'v, T, L, Lv>, cause: AbortCause);
}
impl<T: ConnectionChoices, L, Lv: LayerLineage> PartPositions<T, L, Lv, HNil> for HNil
where
    for<'v> L: LineageLists<'v, T>,
{
    const LEN: usize = 0;
    fn types(_: &mut Vec<TypeId>) {}
    fn reads(_: &mut Vec<ReadSet>) {}
    #[inline(always)]
    fn try_deadline<'v>(
        _: &LineageOf<'v, T, L, Lv>,
        _: usize,
        _: usize,
    ) -> Option<Option<InstantOf<T>>> {
        None
    }
    #[inline(always)]
    fn try_expire<'v, B: CallBundle>(
        lineage: LineageOf<'v, T, L, Lv>,
        _: &mut OtherNodes<'v, T, L, B>,
        _: usize,
        _: usize,
        _: InstantOf<T>,
    ) -> Result<Option<RequestOf<T, L>>, LineageOf<'v, T, L, Lv>> {
        Err(lineage)
    }
    #[inline(always)]
    fn try_reread<'v, B: CallBundle>(
        lineage: LineageOf<'v, T, L, Lv>,
        _: &mut OtherNodes<'v, T, L, B>,
        _: usize,
        _: usize,
        _: InstantOf<T>,
    ) -> Result<Option<RequestOf<T, L>>, LineageOf<'v, T, L, Lv>> {
        Err(lineage)
    }
    #[inline(always)]
    fn future_dropped_each<'v>(_: &mut LineageOf<'v, T, L, Lv>, _: AbortCause) {}
}
impl<T: ConnectionChoices, L, Lv: LayerLineage, X, Xs, H, Hs> PartPositions<T, L, Lv, HCons<H, Hs>>
    for HCons<X, Xs>
where
    for<'v> L: LineageLists<'v, T>,
    X: DataComponent<T, L, Lv, H> + 'static,
    Xs: PartPositions<T, L, Lv, Hs>,
{
    const LEN: usize = 1 + Xs::LEN;
    fn types(out: &mut Vec<TypeId>) {
        out.push(TypeId::of::<X>());
        Xs::types(out);
    }
    fn reads(out: &mut Vec<ReadSet>) {
        let mut reads = ReadSet::default();
        X::reads(&mut reads);
        out.push(reads);
        Xs::reads(out);
    }
    #[inline(always)]
    fn try_deadline<'v>(
        lineage: &LineageOf<'v, T, L, Lv>,
        r: usize,
        after: usize,
    ) -> Option<Option<InstantOf<T>>> {
        if r == Xs::LEN + after {
            Some(X::deadline(lineage))
        } else {
            Xs::try_deadline(lineage, r, after)
        }
    }
    #[inline(always)]
    fn try_expire<'v, B: CallBundle>(
        lineage: LineageOf<'v, T, L, Lv>,
        others: &mut OtherNodes<'v, T, L, B>,
        r: usize,
        after: usize,
        now: InstantOf<T>,
    ) -> Result<Option<RequestOf<T, L>>, LineageOf<'v, T, L, Lv>> {
        if r == Xs::LEN + after {
            Ok(X::expire(lineage, others, now))
        } else {
            Xs::try_expire(lineage, others, r, after, now)
        }
    }
    #[inline(always)]
    fn try_reread<'v, B: CallBundle>(
        lineage: LineageOf<'v, T, L, Lv>,
        others: &mut OtherNodes<'v, T, L, B>,
        r: usize,
        after: usize,
        now: InstantOf<T>,
    ) -> Result<Option<RequestOf<T, L>>, LineageOf<'v, T, L, Lv>> {
        if r == Xs::LEN + after {
            Ok(X::reread(lineage, others, now))
        } else {
            Xs::try_reread(lineage, others, r, after, now)
        }
    }
    #[inline(always)]
    fn future_dropped_each<'v>(lineage: &mut LineageOf<'v, T, L, Lv>, cause: AbortCause) {
        X::future_dropped(lineage, cause);
        Xs::future_dropped_each(lineage, cause);
    }
}

/// The positions of a node's data components: every part's, in the order
/// of the list.
pub trait NodePositions<T: ConnectionChoices, L, Lv: LayerLineage, Hss>
where
    for<'v> L: LineageLists<'v, T>,
{
    /// How many data components the node has.
    const LEN: usize;
    /// The type of each component, in order.
    fn types(out: &mut Vec<TypeId>);
    /// What each component reads, in order.
    fn reads(out: &mut Vec<ReadSet>);
    /// The deadline at position `r` from the end.
    fn deadline_from_end<'v>(lineage: &LineageOf<'v, T, L, Lv>, r: usize) -> Option<InstantOf<T>>;
    /// The expiry at position `r` from the end.
    fn expire_from_end<'v, B: CallBundle>(
        lineage: LineageOf<'v, T, L, Lv>,
        others: &mut OtherNodes<'v, T, L, B>,
        r: usize,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>>;
    /// The reread at position `r` from the end.
    fn reread_from_end<'v, B: CallBundle>(
        lineage: LineageOf<'v, T, L, Lv>,
        others: &mut OtherNodes<'v, T, L, B>,
        r: usize,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>>;
    /// Tell each component, in order, that the connection's future is
    /// dropped, and how.
    fn future_dropped_each<'v>(lineage: &mut LineageOf<'v, T, L, Lv>, cause: AbortCause);
}
impl<T: ConnectionChoices, L, Lv: LayerLineage> NodePositions<T, L, Lv, HNil> for HNil
where
    for<'v> L: LineageLists<'v, T>,
{
    const LEN: usize = 0;
    fn types(_: &mut Vec<TypeId>) {}
    fn reads(_: &mut Vec<ReadSet>) {}
    #[inline(always)]
    fn deadline_from_end<'v>(_: &LineageOf<'v, T, L, Lv>, _: usize) -> Option<InstantOf<T>> {
        unreachable!("a position beyond the node's data")
    }
    #[inline(always)]
    fn expire_from_end<'v, B: CallBundle>(
        _: LineageOf<'v, T, L, Lv>,
        _: &mut OtherNodes<'v, T, L, B>,
        _: usize,
        _: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        unreachable!("a position beyond the node's data")
    }
    #[inline(always)]
    fn reread_from_end<'v, B: CallBundle>(
        _: LineageOf<'v, T, L, Lv>,
        _: &mut OtherNodes<'v, T, L, B>,
        _: usize,
        _: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        unreachable!("a position beyond the node's data")
    }
    #[inline(always)]
    fn future_dropped_each<'v>(_: &mut LineageOf<'v, T, L, Lv>, _: AbortCause) {}
}
impl<T: ConnectionChoices, L, Lv: LayerLineage, S, Ss, Hs, Hss>
    NodePositions<T, L, Lv, HCons<Hs, Hss>> for HCons<S, Ss>
where
    for<'v> L: LineageLists<'v, T>,
    S: PartPositions<T, L, Lv, Hs>,
    Ss: NodePositions<T, L, Lv, Hss>,
{
    const LEN: usize = S::LEN + Ss::LEN;
    fn types(out: &mut Vec<TypeId>) {
        S::types(out);
        Ss::types(out);
    }
    fn reads(out: &mut Vec<ReadSet>) {
        S::reads(out);
        Ss::reads(out);
    }
    #[inline(always)]
    fn deadline_from_end<'v>(lineage: &LineageOf<'v, T, L, Lv>, r: usize) -> Option<InstantOf<T>> {
        match S::try_deadline(lineage, r, Ss::LEN) {
            Some(deadline) => deadline,
            None => Ss::deadline_from_end(lineage, r),
        }
    }
    #[inline(always)]
    fn expire_from_end<'v, B: CallBundle>(
        lineage: LineageOf<'v, T, L, Lv>,
        others: &mut OtherNodes<'v, T, L, B>,
        r: usize,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        match S::try_expire(lineage, others, r, Ss::LEN, now) {
            Ok(request) => request,
            Err(lineage) => Ss::expire_from_end(lineage, others, r, now),
        }
    }
    #[inline(always)]
    fn reread_from_end<'v, B: CallBundle>(
        lineage: LineageOf<'v, T, L, Lv>,
        others: &mut OtherNodes<'v, T, L, B>,
        r: usize,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        match S::try_reread(lineage, others, r, Ss::LEN, now) {
            Ok(request) => request,
            Err(lineage) => Ss::reread_from_end(lineage, others, r, now),
        }
    }
    #[inline(always)]
    fn future_dropped_each<'v>(lineage: &mut LineageOf<'v, T, L, Lv>, cause: AbortCause) {
        S::future_dropped_each(lineage, cause);
        Ss::future_dropped_each(lineage, cause);
    }
}
