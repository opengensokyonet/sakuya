//! Making a connection's driver, with the positions its calls and
//! components are inferred at.

use sakuya_connection::{
    call::{NodeCalls, TreeCalls},
    clock::{ConnectionChoices, InstantOf},
    component::{BuildNode, NodePositions},
    driver::ConnectionDriver,
    layer::{
        Connection, Established, LinkEntry, LinkPath, LinkPathArgs, LogicalPath, LogicalPathArgs,
        Recovery,
    },
    share::{ConnectionArgsOf, LayerShares, LineageLists, LogicalPathKeys, NodeData, PathKey},
};

/// What makes the future of a connection of the choices `T` and the list of
/// parts `L`: the connection driver, at the positions the compiler infers
/// where the endpoint makes it.
pub trait MakeConnection<T: ConnectionChoices, L>: Future<Output = ()> + Sized
where
    L: LayerShares<T, L, Connection> + LogicalPathKeys,
{
    /// The connection made with its first logical path and link path.
    fn make(
        clock: T::Clock,
        connection: ConnectionArgsOf<T, L>,
        path: LogicalPathArgs<PathKey<L>>,
        link: LinkPathArgs<PathKey<L>, T::Link, InstantOf<T>>,
    ) -> Self;
}

impl<T, L, Pc, Pe, Pl, Pk, Ps, Pr, Hw, He, Hl, Hk, Hs, Hr, Bw, Be, Bl, Bk, Bs, Br>
    MakeConnection<T, L>
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
    fn make(
        clock: T::Clock,
        connection: ConnectionArgsOf<T, L>,
        path: LogicalPathArgs<PathKey<L>>,
        link: LinkPathArgs<PathKey<L>, T::Link, InstantOf<T>>,
    ) -> Self {
        Self::new(clock, connection, path, link)
    }
}
