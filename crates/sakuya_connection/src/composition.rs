//! Compositions: where the positions of a connection's calls and
//! components are inferred, once, and named.
//!
//! The compiler infers the positions of what each call and each component
//! takes where the list of parts is concrete. A [`Composition`] is the impl
//! where that happens: its associated types are the positions, opaque
//! (`impl Sized`), defined by its [`connection`](Composition::connection),
//! which makes the connection. The driver and the knot of its calls carry
//! the one named type [`CompositionPositions`] instead of the positions
//! themselves, so that the names of the functions over a connection's tree
//! do not carry every position of the tree. [`composition!`](crate::composition!)
//! writes the impl.
use core::{future::Future, marker::PhantomData};

use crate::{
    call::{CallPositions, NodeCalls, TreeCalls},
    clock::{ConnectionChoices, InstantOf},
    component::{BuildNode, NodePositions},
    driver::DriverPositions,
    layer::{
        Connection, Established, LinkEntry, LinkPath, LinkPathArgs, LogicalPath, LogicalPathArgs,
        Recovery,
    },
    share::{ConnectionArgsOf, LayerShares, LineageLists, LogicalPathKeys, NodeData, PathKey},
};

/// The composition `Self` of the connections of the choices `T` and the
/// list of parts `L`: the positions inferred for them, and the making of a
/// connection. Written by [`composition!`](crate::composition!); `Self` is
/// a type of the crate that writes it.
pub trait Composition<T: ConnectionChoices, L: LayerShares<T, L, Connection> + LogicalPathKeys>:
    'static
{
    /// The positions of the calls of the layer [`Connection`].
    type ConnectionCalls: 'static;
    /// The positions of the calls of the layer [`LinkEntry`].
    type LinkEntryCalls: 'static;
    /// The positions of the calls of the layer [`LogicalPath`].
    type LogicalPathCalls: 'static;
    /// The positions of the calls of the layer [`LinkPath`].
    type LinkPathCalls: 'static;
    /// The positions of the calls of the layer [`Established`].
    type EstablishedCalls: 'static;
    /// The positions of the calls of the layer [`Recovery`].
    type RecoveryCalls: 'static;
    /// The positions of the data components of the six layers.
    type Data: 'static;
    /// The positions of the builds of the six layers.
    type Builds: 'static;
    /// Make a connection, as [`ConnectionDriver::new`](crate::driver::ConnectionDriver::new)
    /// does, as one future; the positions come with it only to define them.
    fn connection(
        clock: T::Clock,
        connection: ConnectionArgsOf<T, L>,
        path: LogicalPathArgs<PathKey<L>>,
        link: LinkPathArgs<PathKey<L>, T::Link, InstantOf<T>>,
    ) -> (
        impl Future<Output = ()> + Unpin + 'static,
        PositionsOf<Self, T, L>,
    );
}

/// The positions of the composition `C`, as the one type that defines them.
pub type PositionsOf<C, T, L> = PhantomData<(
    <C as Composition<T, L>>::ConnectionCalls,
    <C as Composition<T, L>>::LinkEntryCalls,
    <C as Composition<T, L>>::LogicalPathCalls,
    <C as Composition<T, L>>::LinkPathCalls,
    <C as Composition<T, L>>::EstablishedCalls,
    <C as Composition<T, L>>::RecoveryCalls,
    <C as Composition<T, L>>::Data,
    <C as Composition<T, L>>::Builds,
)>;

/// The positions of the composition `C` of the choices `T` and the list
/// `L`, as one named type: what the driver and the knot of its calls carry.
#[allow(clippy::type_complexity)] // a marker of three type parameters
pub struct CompositionPositions<C, T, L>(PhantomData<fn() -> (C, T, L)>);

impl<
    C: Composition<T, L>,
    T: ConnectionChoices,
    L: LayerShares<T, L, Connection> + LogicalPathKeys + 'static,
> CallPositions for CompositionPositions<C, T, L>
{
    type Connection = C::ConnectionCalls;
    type LinkEntry = C::LinkEntryCalls;
    type LogicalPath = C::LogicalPathCalls;
    type LinkPath = C::LinkPathCalls;
    type Established = C::EstablishedCalls;
    type Recovery = C::RecoveryCalls;
}

impl<
    C: Composition<T, L>,
    T: ConnectionChoices,
    L: LayerShares<T, L, Connection> + LogicalPathKeys + 'static,
> DriverPositions for CompositionPositions<C, T, L>
{
    type Data = C::Data;
    type Builds = C::Builds;
}

/// Nothing, at the positions the compiler infers for the choices `T` and
/// the list `L`: what [`composition!`](crate::composition!) defines a
/// composition's positions by.
#[doc(hidden)]
#[allow(clippy::type_complexity)]
pub fn infer<T, L, Pc, Pe, Pl, Pk, Ps, Pr, Hw, He, Hl, Hk, Hs, Hr, Bw, Be, Bl, Bk, Bs, Br>()
-> PhantomData<(
    Pc,
    Pe,
    Pl,
    Pk,
    Ps,
    Pr,
    (Hw, He, Hl, Hk, Hs, Hr),
    (Bw, Be, Bl, Bk, Bs, Br),
)>
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
    PhantomData
}

/// Write the [`Composition`] `$c` of the choices `$t` and the list of parts
/// `$l`: `composition!(impl for Mine: Choices, Parts)`. `$c` is a type of
/// the crate that writes it, often the host's choices.
///
/// `composition!(impl Send for Mine: Choices, Parts)` also checks that the
/// connection's future is `Send`, and says so to whoever makes it through
/// the composition: the opaque positions keep `Send` from being inferred
/// from the composition's types anywhere else.
#[macro_export]
#[allow_internal_unstable(impl_trait_in_assoc_type)]
macro_rules! composition {
    (impl for $c:ty: $t:ty, $l:ty) => {
        impl $crate::composition::Composition<$t, $l> for $c {
            type ConnectionCalls = impl Sized + 'static;
            type LinkEntryCalls = impl Sized + 'static;
            type LogicalPathCalls = impl Sized + 'static;
            type LinkPathCalls = impl Sized + 'static;
            type EstablishedCalls = impl Sized + 'static;
            type RecoveryCalls = impl Sized + 'static;
            type Data = impl Sized + 'static;
            type Builds = impl Sized + 'static;
            fn connection(
                clock: <$t as $crate::clock::ConnectionChoices>::Clock,
                connection: $crate::share::ConnectionArgsOf<$t, $l>,
                path: $crate::layer::LogicalPathArgs<$crate::share::PathKey<$l>>,
                link: $crate::layer::LinkPathArgs<
                    $crate::share::PathKey<$l>,
                    <$t as $crate::clock::ConnectionChoices>::Link,
                    $crate::clock::InstantOf<$t>,
                >,
            ) -> (
                impl ::core::future::Future<Output = ()> + ::core::marker::Unpin + 'static,
                $crate::composition::PositionsOf<Self, $t, $l>,
            ) {
                let positions: $crate::composition::PositionsOf<Self, $t, $l> =
                    $crate::composition::infer::<
                        $t,
                        $l,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                    >();
                let driver = $crate::driver::ConnectionDriver::<
                    $t,
                    $l,
                    $crate::composition::CompositionPositions<Self, $t, $l>,
                >::new(clock, connection, path, link);
                (driver, positions)
            }
        }
    };
    (impl Send for $c:ty: $t:ty, $l:ty) => {
        impl $crate::composition::Composition<$t, $l> for $c {
            type ConnectionCalls = impl Sized + 'static;
            type LinkEntryCalls = impl Sized + 'static;
            type LogicalPathCalls = impl Sized + 'static;
            type LinkPathCalls = impl Sized + 'static;
            type EstablishedCalls = impl Sized + 'static;
            type RecoveryCalls = impl Sized + 'static;
            type Data = impl Sized + 'static;
            type Builds = impl Sized + 'static;
            #[allow(refining_impl_trait)]
            fn connection(
                clock: <$t as $crate::clock::ConnectionChoices>::Clock,
                connection: $crate::share::ConnectionArgsOf<$t, $l>,
                path: $crate::layer::LogicalPathArgs<$crate::share::PathKey<$l>>,
                link: $crate::layer::LinkPathArgs<
                    $crate::share::PathKey<$l>,
                    <$t as $crate::clock::ConnectionChoices>::Link,
                    $crate::clock::InstantOf<$t>,
                >,
            ) -> (
                impl ::core::future::Future<Output = ()>
                + ::core::marker::Unpin
                + ::core::marker::Send
                + 'static,
                $crate::composition::PositionsOf<Self, $t, $l>,
            ) {
                let positions: $crate::composition::PositionsOf<Self, $t, $l> =
                    $crate::composition::infer::<
                        $t,
                        $l,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                        _,
                    >();
                let driver = $crate::driver::ConnectionDriver::<
                    $t,
                    $l,
                    $crate::composition::CompositionPositions<Self, $t, $l>,
                >::new(clock, connection, path, link);
                (driver, positions)
            }
        }
    };
}
