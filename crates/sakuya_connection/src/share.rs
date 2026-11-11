//! What each part holds in each layer, and the flat views of a node's data.
//!
//! A composition is a list of parts (`HList![v1::Part, datagram::Part]`).
//! Every part writes a [`LayerShare`] for every layer: the data components
//! it keeps in each node of that layer and the kinds of calls it runs there,
//! `HNil` where it has none. A node's data is the list of the parts' data in
//! the order of the list; a lend sees it flat, together with the data of the
//! nodes above ([`LineageLists`]).
use core::ops::Add;

use frunk_core::traits::ToMut;
use sakuya_wire::parts::{HCons, HNil};

use crate::layer::{
    Connection, Established, Layer, LinkEntry, LinkPath, LogicalPath, LogicalPathKey, Recovery,
};

/// What the part `Self` holds in each node of the layer `Lv`.
///
/// `T` is the choices of the composition, `L` the full list of parts.
pub trait LayerShare<T, L, Lv> {
    /// The data components, in the order of their positions in the node.
    type Data: SingleUnits;
    /// The units the data components are built in: a list of lists of
    /// components, joined end to end they are `Data`. By default every
    /// component is a unit of its own; a group of components built together
    /// by one [`Build`](crate::component::Build) is one unit.
    type Units = <Self::Data as SingleUnits>::Units;
    /// The kinds of calls, in the order of their positions after the data.
    type Calls;
    /// What the part needs given when the node is built, as a list; by
    /// default nothing.
    ///
    /// Only the connection layer uses it: the connection node is built from
    /// the parts' lists, in the order of the list of parts
    /// ([`ConnectionArgsOf`]). The other layers are built from structural
    /// facts, and what a part's components there need otherwise they read
    /// from the nodes above. A value only one call or component uses once
    /// is wrapped in an `Option` and taken out when it is built.
    type Args = HNil;
}

/// A list of components, each a unit of its own.
pub trait SingleUnits {
    /// One list of one component for each component.
    type Units;
}
impl SingleUnits for HNil {
    type Units = HNil;
}
impl<X, Xs: SingleUnits> SingleUnits for HCons<X, Xs> {
    type Units = HCons<HCons<X, HNil>, Xs::Units>;
}

/// The shares of a list of parts in the layer `Lv`; `Full` is the whole list.
pub trait LayerShares<T, Full, Lv> {
    /// The data of a node: each part's data, in the order of the list.
    type Data;
    /// What the parts need given when a node is built: each part's list,
    /// in the order of the list.
    type Args;
}
impl<T, Full, Lv> LayerShares<T, Full, Lv> for HNil {
    type Data = HNil;
    type Args = HNil;
}
impl<T, Full, Lv, P: LayerShare<T, Full, Lv>, Ps: LayerShares<T, Full, Lv>> LayerShares<T, Full, Lv>
    for HCons<P, Ps>
{
    type Data = HCons<P::Data, Ps::Data>;
    type Args = HCons<P::Args, Ps::Args>;
}

/// What the connection node is built from: the list the parts declare in
/// the connection layer, one for each part in the order of the list of
/// parts `L`, as a node's data is.
pub type ConnectionArgsOf<T, L> = <L as LayerShares<T, L, Connection>>::Args;

/// The data of a node of the layer `Lv`.
pub type NodeData<T, L, Lv> = <L as LayerShares<T, L, Lv>>::Data;
/// The data of a node of the layer `Lv`, flat: one mutable borrow for each
/// component.
pub type FlatData<'v, T, L, Lv> = <NodeData<T, L, Lv> as FlatMut<'v>>::Out;

/// A node's data borrowed flat: one list of mutable borrows, whatever part
/// owns them.
pub trait FlatMut<'a> {
    /// The flat list of borrows.
    type Out;
    /// Borrow every component.
    fn flat_mut(&'a mut self) -> Self::Out;
}
impl<'a> FlatMut<'a> for HNil {
    type Out = HNil;
    #[inline]
    fn flat_mut(&'a mut self) -> HNil {
        HNil
    }
}
impl<'a, S: ToMut<'a> + 'a, Ss: FlatMut<'a> + 'a> FlatMut<'a> for HCons<S, Ss>
where
    <S as ToMut<'a>>::Output: Add<Ss::Out>,
{
    type Out = <<S as ToMut<'a>>::Output as Add<Ss::Out>>::Output;
    #[inline]
    fn flat_mut(&'a mut self) -> Self::Out {
        let HCons { head, tail } = self;
        head.to_mut() + tail.flat_mut()
    }
}

/// What a part adds to the key of a logical path.
///
/// A part whose logical paths need no key of their own, as QUIC version 1
/// with its one logical path, adds `HNil`.
pub trait LogicalPathKeyShare {
    /// The fields the part adds, as a list.
    type Fields;
}

/// The key of a logical path, from the fields the parts add.
pub trait LogicalPathKeys {
    /// The fields of all parts, joined.
    type Fields;
    /// The key: [`SoleLogicalPath`] when no part adds a field, otherwise the
    /// list of fields.
    type Key: LogicalPathKey;
}
impl LogicalPathKeys for HNil {
    type Fields = HNil;
    type Key = SoleLogicalPath;
}
impl<P: LogicalPathKeyShare, Ps: LogicalPathKeys> LogicalPathKeys for HCons<P, Ps>
where
    P::Fields: Add<Ps::Fields>,
    <P::Fields as Add<Ps::Fields>>::Output: KeyOfFields,
{
    type Fields = <P::Fields as Add<Ps::Fields>>::Output;
    type Key = <<P::Fields as Add<Ps::Fields>>::Output as KeyOfFields>::Key;
}

/// The key of a logical path made of a list of fields.
pub trait KeyOfFields {
    /// The key.
    type Key: LogicalPathKey;
}
impl KeyOfFields for HNil {
    type Key = SoleLogicalPath;
}
impl<H, T> KeyOfFields for HCons<H, T>
where
    HCons<H, T>: LogicalPathKey,
{
    type Key = HCons<H, T>;
}

/// The key of the one logical path of a connection whose parts add no field
/// to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SoleLogicalPath;

/// The key of a logical path of the list of parts `L`.
pub type PathKey<L> = <L as LogicalPathKeys>::Key;

/// A list of parts with a share in every layer.
pub trait PartList<T>:
    LayerShares<T, Self, Connection>
    + LayerShares<T, Self, LinkEntry>
    + LayerShares<T, Self, LogicalPath>
    + LayerShares<T, Self, LinkPath>
    + LayerShares<T, Self, Established>
    + LayerShares<T, Self, Recovery>
    + LogicalPathKeys
    + Sized
    + 'static
{
}
impl<T, L> PartList<T> for L where
    L: LayerShares<T, L, Connection>
        + LayerShares<T, L, LinkEntry>
        + LayerShares<T, L, LogicalPath>
        + LayerShares<T, L, LinkPath>
        + LayerShares<T, L, Established>
        + LayerShares<T, L, Recovery>
        + LogicalPathKeys
        + 'static
{
}

/// The flat lists a lend of each layer sees: a node's data after the data of
/// the nodes above it.
///
/// Implemented for every list of parts whose data can be borrowed flat.
pub trait LineageLists<'v, T>: PartList<T> {
    /// A lend of the connection node.
    type Connection;
    /// A lend of a logical link entry: the connection, the entry.
    type LinkEntry;
    /// A lend of a logical path: the connection, the logical path.
    type LogicalPath;
    /// What a link path is built from: the connection, its entry, its
    /// logical path.
    type LinkPathParents;
    /// A lend of a link path: its parents, the link path.
    type LinkPath;
    /// A lend of the established layer: the connection, the layer.
    type Established;
    /// A lend of a recovery layer: the link path's lineage, the layer.
    type Recovery;
    /// The connection.
    fn connection(c: &'v mut NodeData<T, Self, Connection>) -> Self::Connection;
    /// An entry.
    fn link_entry(
        c: &'v mut NodeData<T, Self, Connection>,
        e: &'v mut NodeData<T, Self, LinkEntry>,
    ) -> Self::LinkEntry;
    /// A logical path.
    fn logical_path(
        c: &'v mut NodeData<T, Self, Connection>,
        l: &'v mut NodeData<T, Self, LogicalPath>,
    ) -> Self::LogicalPath;
    /// A link path's parents.
    fn link_path_parents(
        c: &'v mut NodeData<T, Self, Connection>,
        e: &'v mut NodeData<T, Self, LinkEntry>,
        l: &'v mut NodeData<T, Self, LogicalPath>,
    ) -> Self::LinkPathParents;
    /// A link path.
    fn link_path(
        c: &'v mut NodeData<T, Self, Connection>,
        e: &'v mut NodeData<T, Self, LinkEntry>,
        l: &'v mut NodeData<T, Self, LogicalPath>,
        k: &'v mut NodeData<T, Self, LinkPath>,
    ) -> Self::LinkPath;
    /// The established layer.
    fn established(
        c: &'v mut NodeData<T, Self, Connection>,
        s: &'v mut NodeData<T, Self, Established>,
    ) -> Self::Established;
    /// A recovery layer.
    fn recovery(
        c: &'v mut NodeData<T, Self, Connection>,
        e: &'v mut NodeData<T, Self, LinkEntry>,
        l: &'v mut NodeData<T, Self, LogicalPath>,
        k: &'v mut NodeData<T, Self, LinkPath>,
        r: &'v mut NodeData<T, Self, Recovery>,
    ) -> Self::Recovery;
}

type Join<A, B> = <A as Add<B>>::Output;

impl<'v, T, L: PartList<T>> LineageLists<'v, T> for L
where
    NodeData<T, L, Connection>: FlatMut<'v> + 'v,
    NodeData<T, L, LinkEntry>: FlatMut<'v> + 'v,
    NodeData<T, L, LogicalPath>: FlatMut<'v> + 'v,
    NodeData<T, L, LinkPath>: FlatMut<'v> + 'v,
    NodeData<T, L, Established>: FlatMut<'v> + 'v,
    NodeData<T, L, Recovery>: FlatMut<'v> + 'v,
    FlatData<'v, T, L, Connection>: Add<FlatData<'v, T, L, LinkEntry>>
        + Add<FlatData<'v, T, L, LogicalPath>>
        + Add<FlatData<'v, T, L, Established>>,
    Join<FlatData<'v, T, L, Connection>, FlatData<'v, T, L, LinkEntry>>:
        Add<FlatData<'v, T, L, LogicalPath>>,
    Join<
        Join<FlatData<'v, T, L, Connection>, FlatData<'v, T, L, LinkEntry>>,
        FlatData<'v, T, L, LogicalPath>,
    >: Add<FlatData<'v, T, L, LinkPath>>,
    Join<
        Join<
            Join<FlatData<'v, T, L, Connection>, FlatData<'v, T, L, LinkEntry>>,
            FlatData<'v, T, L, LogicalPath>,
        >,
        FlatData<'v, T, L, LinkPath>,
    >: Add<FlatData<'v, T, L, Recovery>>,
{
    type Connection = FlatData<'v, T, L, Connection>;
    type LinkEntry = Join<FlatData<'v, T, L, Connection>, FlatData<'v, T, L, LinkEntry>>;
    type LogicalPath = Join<FlatData<'v, T, L, Connection>, FlatData<'v, T, L, LogicalPath>>;
    type LinkPathParents = Join<
        Join<FlatData<'v, T, L, Connection>, FlatData<'v, T, L, LinkEntry>>,
        FlatData<'v, T, L, LogicalPath>,
    >;
    type LinkPath = Join<Self::LinkPathParents, FlatData<'v, T, L, LinkPath>>;
    type Established = Join<FlatData<'v, T, L, Connection>, FlatData<'v, T, L, Established>>;
    type Recovery = Join<Self::LinkPath, FlatData<'v, T, L, Recovery>>;
    #[inline]
    fn connection(c: &'v mut NodeData<T, L, Connection>) -> Self::Connection {
        c.flat_mut()
    }
    #[inline]
    fn link_entry(
        c: &'v mut NodeData<T, L, Connection>,
        e: &'v mut NodeData<T, L, LinkEntry>,
    ) -> Self::LinkEntry {
        c.flat_mut() + e.flat_mut()
    }
    #[inline]
    fn logical_path(
        c: &'v mut NodeData<T, L, Connection>,
        l: &'v mut NodeData<T, L, LogicalPath>,
    ) -> Self::LogicalPath {
        c.flat_mut() + l.flat_mut()
    }
    #[inline]
    fn link_path_parents(
        c: &'v mut NodeData<T, L, Connection>,
        e: &'v mut NodeData<T, L, LinkEntry>,
        l: &'v mut NodeData<T, L, LogicalPath>,
    ) -> Self::LinkPathParents {
        c.flat_mut() + e.flat_mut() + l.flat_mut()
    }
    #[inline]
    fn link_path(
        c: &'v mut NodeData<T, L, Connection>,
        e: &'v mut NodeData<T, L, LinkEntry>,
        l: &'v mut NodeData<T, L, LogicalPath>,
        k: &'v mut NodeData<T, L, LinkPath>,
    ) -> Self::LinkPath {
        c.flat_mut() + e.flat_mut() + l.flat_mut() + k.flat_mut()
    }
    #[inline]
    fn established(
        c: &'v mut NodeData<T, L, Connection>,
        s: &'v mut NodeData<T, L, Established>,
    ) -> Self::Established {
        c.flat_mut() + s.flat_mut()
    }
    #[inline]
    fn recovery(
        c: &'v mut NodeData<T, L, Connection>,
        e: &'v mut NodeData<T, L, LinkEntry>,
        l: &'v mut NodeData<T, L, LogicalPath>,
        k: &'v mut NodeData<T, L, LinkPath>,
        r: &'v mut NodeData<T, L, Recovery>,
    ) -> Self::Recovery {
        c.flat_mut() + e.flat_mut() + l.flat_mut() + k.flat_mut() + r.flat_mut()
    }
}

/// The lists a layer's lends and builds see.
pub trait LayerLineage: Layer {
    /// The flat list a lend of a node of this layer sees.
    type List<'v, T, L: LineageLists<'v, T>>;
    /// The flat list a node of this layer is built from and ended with: the
    /// data of the nodes above it.
    type Parents<'v, T, L: LineageLists<'v, T>>;
    /// How many of the layers above, from the connection down, a lend of
    /// this layer sees before its own data, as layer indices.
    #[doc(hidden)]
    const ABOVE: &'static [usize];
}
impl LayerLineage for Connection {
    type List<'v, T, L: LineageLists<'v, T>> = L::Connection;
    type Parents<'v, T, L: LineageLists<'v, T>> = HNil;
    const ABOVE: &'static [usize] = &[];
}
impl LayerLineage for LinkEntry {
    type List<'v, T, L: LineageLists<'v, T>> = L::LinkEntry;
    type Parents<'v, T, L: LineageLists<'v, T>> = L::Connection;
    const ABOVE: &'static [usize] = &[0];
}
impl LayerLineage for LogicalPath {
    type List<'v, T, L: LineageLists<'v, T>> = L::LogicalPath;
    type Parents<'v, T, L: LineageLists<'v, T>> = L::Connection;
    const ABOVE: &'static [usize] = &[0];
}
impl LayerLineage for LinkPath {
    type List<'v, T, L: LineageLists<'v, T>> = L::LinkPath;
    type Parents<'v, T, L: LineageLists<'v, T>> = L::LinkPathParents;
    const ABOVE: &'static [usize] = &[0, 1, 2];
}
impl LayerLineage for Established {
    type List<'v, T, L: LineageLists<'v, T>> = L::Established;
    type Parents<'v, T, L: LineageLists<'v, T>> = L::Connection;
    const ABOVE: &'static [usize] = &[0];
}
impl LayerLineage for Recovery {
    type List<'v, T, L: LineageLists<'v, T>> = L::Recovery;
    type Parents<'v, T, L: LineageLists<'v, T>> = L::LinkPath;
    const ABOVE: &'static [usize] = &[0, 1, 2, 3];
}
