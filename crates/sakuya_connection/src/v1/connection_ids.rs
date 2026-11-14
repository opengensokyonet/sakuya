//! The connection IDs of a logical path, and what registers the reset
//! tokens of the peer's.
//!
//! Each logical path keeps its [`ConnectionIds`]: this side's connection
//! ID, which the long headers it sends carry as their Source Connection ID,
//! as the connection node keeps it ([`FirstLocalConnectionId`]); and the
//! destination connection ID strategy, made from the configuration the
//! connection node keeps ([`DestinationConnectionIdConfig`]) with the
//! `active_connection_id_limit` this side sends. The strategy learns the
//! connection ID the peer chose for the handshake once: a server's is the
//! Source Connection ID of the first Initial packet it opens from the
//! client (RFC 9000 §7.2), whether the first flight was read before the
//! connection was made or by the receiving call.
//!
//! The connection node keeps the [`ConnectionResetTokenRegistry`]. Each
//! link path makes its [`LinkPathResetTokenRegistrar`] from it when it is
//! built, for its link's peer and its logical path's
//! [`StatelessResetSignal`], and tells the strategy when it is added and
//! when it ends.

use core::fmt;
use std::sync::Arc;

use sakuya_wire::{
    connection_id::ConnectionId,
    parts::Selector,
    v1::transport_parameters::{TransportParameterSlots, integer::ActiveConnectionIdLimit},
};

use super::{
    Choices, ConnectionArgs, first_flight::FirstFlightStart, parameters::LocalTransportParameters,
    stateless_reset::StatelessResetSignal,
};
use crate::{
    call::CallBundle,
    clock::{ConnectionChoices, InstantOf, LinkIdOf},
    component::{
        ArgsOf, Build, DataComponent, LineageOf, ParentsOf, PassiveDataComponent, ReadSet,
        RequestOf,
    },
    connection_id::{
        DestinationConnectionIdStrategy,
        reset_token::{ResetTokenRegistrar, ResetTokenRegistry},
    },
    layer,
    others::OtherNodes,
    share::{ConnectionArgsOf, LineageLists, LineagePartList},
    take::GetAt,
};
use sakuya_link::Link;

/// The peer of a link of the choices `T`.
pub type PeerOf<T> = <<T as ConnectionChoices>::Link as Link>::Peer;

/// The registrar each link path of the choices `T` makes from the
/// connection's registry.
pub type ResetTokenRegistrarOf<T> = <<T as Choices>::ResetTokenRegistry as ResetTokenRegistry<
    PeerOf<T>,
    Arc<StatelessResetSignal>,
>>::Registrar;

/// The configuration the destination connection ID strategy of the
/// choices `T` is made from.
pub type DestinationConnectionIdConfigOf<T> =
    <<T as Choices>::DestinationConnectionIds as DestinationConnectionIdStrategy<
        LinkIdOf<T>,
        InstantOf<T>,
        ResetTokenRegistrarOf<T>,
    >>::Config;

// ---- the connection node ----

/// The configuration each logical path's destination connection ID
/// strategy is made from, kept in the connection node.
#[derive(Debug)]
pub struct DestinationConnectionIdConfig<C>(C);

impl<T: Choices, L, I> Build<T, L, layer::Connection, (I,)>
    for DestinationConnectionIdConfig<DestinationConnectionIdConfigOf<T>>
where
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        Self(
            Selector::<ConnectionArgs<T, L>, I>::get(args)
                .destination_connection_ids
                .clone(),
        )
    }
}
impl<C> PassiveDataComponent for DestinationConnectionIdConfig<C> {}

/// The first of this side's connection IDs, as the connection was made
/// with it, kept in the connection node: the Source Connection ID of the
/// long headers this side sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirstLocalConnectionId(pub ConnectionId);

impl<T: Choices, L, I> Build<T, L, layer::Connection, (I,)> for FirstLocalConnectionId
where
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        Self(Selector::<ConnectionArgs<T, L>, I>::get(args).first_local_connection_id)
    }
}
impl PassiveDataComponent for FirstLocalConnectionId {}

/// What the connection holds to register the reset tokens of the peer's
/// connection IDs, kept in the connection node.
pub struct ConnectionResetTokenRegistry<R>(R);

impl<R> fmt::Debug for ConnectionResetTokenRegistry<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionResetTokenRegistry")
            .finish_non_exhaustive()
    }
}

impl<T: Choices, L, I> Build<T, L, layer::Connection, (I,)>
    for ConnectionResetTokenRegistry<T::ResetTokenRegistry>
where
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        Self(
            Selector::<ConnectionArgs<T, L>, I>::get(args)
                .reset_token_registry
                .clone(),
        )
    }
}
impl<R> PassiveDataComponent for ConnectionResetTokenRegistry<R> {}

// ---- the logical path ----

/// A logical path's mark of a received stateless reset starts unset.
impl<T: Choices, L> Build<T, L, layer::LogicalPath, ()> for Arc<StatelessResetSignal>
where
    L: LineagePartList<T>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::LogicalPath>,
        _: &mut ArgsOf<T, L, layer::LogicalPath>,
    ) -> Self {
        Arc::new(StatelessResetSignal::new())
    }
}
impl PassiveDataComponent for Arc<StatelessResetSignal> {}

/// The connection IDs of a logical path: this side's, and the destination
/// connection ID strategy, with whether it was told the peer's handshake
/// connection ID.
pub struct ConnectionIds<D> {
    local: ConnectionId,
    destination: D,
    handshake_known: bool,
}

impl<D> fmt::Debug for ConnectionIds<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionIds")
            .field("local", &self.local)
            .field("handshake_known", &self.handshake_known)
            .finish_non_exhaustive()
    }
}

impl<D> ConnectionIds<D> {
    /// This side's connection ID: the Source Connection ID of the long
    /// headers it sends.
    pub fn local(&self) -> ConnectionId {
        self.local
    }

    /// The destination connection ID strategy.
    pub fn destination(&self) -> &D {
        &self.destination
    }

    /// The destination connection ID strategy, to tell it of an event or to
    /// choose a datagram's connection ID with.
    pub fn destination_mut(&mut self) -> &mut D {
        &mut self.destination
    }

    /// The peer chose `id` for the handshake; only the first time counts
    /// (RFC 9000 §7.2).
    pub(super) fn handshake_connection_id<Id, I, R>(&mut self, id: ConnectionId)
    where
        D: DestinationConnectionIdStrategy<Id, I, R>,
        R: ResetTokenRegistrar,
    {
        if !self.handshake_known {
            self.handshake_known = true;
            self.destination.on_handshake_connection_id(id);
        }
    }
}

/// The connection IDs of a logical path of the choices `T`.
pub type ConnectionIdsOf<T> = ConnectionIds<<T as Choices>::DestinationConnectionIds>;

/// This side's connection ID is the one the connection was made with. The
/// strategy is made with the `active_connection_id_limit` this side
/// sends, as sent or else as configured (RFC 9000 §18.2: 2 when absent);
/// a first flight read before the connection was made gives the handshake
/// connection ID it opened.
impl<T: Choices, L, Ic, Il, Ia, If, Ix> Build<T, L, layer::LogicalPath, (Ic, Il, Ia, If, Ix)>
    for ConnectionIdsOf<T>
where
    L: LineagePartList<T>,
    TransportParameterSlots: Selector<Option<ActiveConnectionIdLimit>, Ia>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<DestinationConnectionIdConfig<DestinationConnectionIdConfigOf<T>>, Ic>
        + GetAt<LocalTransportParameters<TransportParameterSlots>, Il>
        + GetAt<FirstFlightStart<T>, If>
        + GetAt<FirstLocalConnectionId, Ix>,
{
    fn build<'v>(
        parents: &mut ParentsOf<'v, T, L, layer::LogicalPath>,
        _: &mut ArgsOf<T, L, layer::LogicalPath>,
    ) -> Self {
        let local = parents.get::<LocalTransportParameters<TransportParameterSlots>, Il>();
        let active_limit = local
            .sent()
            .or(local.configured())
            .and_then(|slots| *Selector::<Option<ActiveConnectionIdLimit>, Ia>::get(slots))
            .unwrap_or_default();
        let config = &parents
            .get::<DestinationConnectionIdConfig<DestinationConnectionIdConfigOf<T>>, Ic>()
            .0;
        let mut ids = ConnectionIds {
            local: parents.get::<FirstLocalConnectionId, Ix>().0,
            destination: <T::DestinationConnectionIds as DestinationConnectionIdStrategy<
                LinkIdOf<T>,
                InstantOf<T>,
                ResetTokenRegistrarOf<T>,
            >>::new(config, active_limit),
            handshake_known: false,
        };
        if let Some(id) = parents
            .get_mut::<FirstFlightStart<T>, If>()
            .take_handshake_connection_id()
        {
            ids.handshake_connection_id::<LinkIdOf<T>, InstantOf<T>, ResetTokenRegistrarOf<T>>(id);
        }
        ids
    }
}

/// The strategy's deadline is its own; it reads itself.
impl<T: Choices, L, I> DataComponent<T, L, layer::LogicalPath, I> for ConnectionIdsOf<T>
where
    L: LineagePartList<T>,
    for<'v> <L as LineageLists<'v, T>>::LogicalPath: GetAt<Self, I>,
{
    fn reads(reads: &mut ReadSet) {
        reads.add::<Self>();
    }
    fn deadline<'v>(lineage: &LineageOf<'v, T, L, layer::LogicalPath>) -> Option<InstantOf<T>> {
        DestinationConnectionIdStrategy::<LinkIdOf<T>, InstantOf<T>, ResetTokenRegistrarOf<T>>::next_deadline(
            &lineage.get::<Self, I>().destination,
        )
    }
    fn expire<'v, B: CallBundle>(
        mut lineage: LineageOf<'v, T, L, layer::LogicalPath>,
        _: &mut OtherNodes<'v, T, L, B>,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        DestinationConnectionIdStrategy::<LinkIdOf<T>, InstantOf<T>, ResetTokenRegistrarOf<T>>::on_deadline(
            &mut lineage.get_mut::<Self, I>().destination,
            now,
        );
        None
    }
}

// ---- the link path ----

/// The registrar of a link path's reset tokens: for its link's peer, and
/// for resets of its logical path.
pub struct LinkPathResetTokenRegistrar<R>(R);

impl<R> fmt::Debug for LinkPathResetTokenRegistrar<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkPathResetTokenRegistrar")
            .finish_non_exhaustive()
    }
}

impl<R> LinkPathResetTokenRegistrar<R> {
    /// The registrar, to lend to the destination connection ID strategy.
    pub fn registrar_mut(&mut self) -> &mut R {
        &mut self.0
    }
}

/// A link path makes its registrar and is added to its logical path's
/// strategy when it is built, with whether the peer switched to another of
/// this side's connection IDs on it as its request says, and ends there
/// when it ends.
impl<T: Choices, L, Ir, Is, Ii> Build<T, L, layer::LinkPath, (Ir, Is, Ii)>
    for LinkPathResetTokenRegistrar<ResetTokenRegistrarOf<T>>
where
    L: LineagePartList<T>,
    for<'v> <L as LineageLists<'v, T>>::LinkPathParents: GetAt<ConnectionResetTokenRegistry<T::ResetTokenRegistry>, Ir>
        + GetAt<Arc<StatelessResetSignal>, Is>
        + GetAt<ConnectionIdsOf<T>, Ii>,
{
    fn build<'v>(
        parents: &mut ParentsOf<'v, T, L, layer::LinkPath>,
        args: &mut ArgsOf<T, L, layer::LinkPath>,
    ) -> Self {
        let link = &args.link;
        let signal = Arc::clone(parents.get::<Arc<StatelessResetSignal>, Is>());
        let registrar = parents
            .get::<ConnectionResetTokenRegistry<T::ResetTokenRegistry>, Ir>()
            .0
            .registrar(&link.peer, &signal);
        DestinationConnectionIdStrategy::<LinkIdOf<T>, InstantOf<T>, ResetTokenRegistrarOf<T>>::on_link_path_added(
            &mut parents.get_mut::<ConnectionIdsOf<T>, Ii>().destination,
            link,
            args.peer_switched_local_id,
        );
        Self(registrar)
    }

    fn end<'v, B: CallBundle>(
        self,
        parents: &mut ParentsOf<'v, T, L, layer::LinkPath>,
        others: &mut OtherNodes<'v, T, L, B>,
    ) {
        let crate::layer::NodeKey::LinkPath(_, link) = others.here() else {
            unreachable!("a link path's end carries its key")
        };
        DestinationConnectionIdStrategy::<LinkIdOf<T>, InstantOf<T>, ResetTokenRegistrarOf<T>>::on_link_path_ended(
            &mut parents.get_mut::<ConnectionIdsOf<T>, Ii>().destination,
            link,
        );
    }
}
impl<R> PassiveDataComponent for LinkPathResetTokenRegistrar<R> {}
