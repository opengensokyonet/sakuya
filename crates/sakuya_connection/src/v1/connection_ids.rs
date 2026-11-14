//! The connection IDs of a logical path, and what registers the reset
//! tokens of the peer's.
//!
//! Each logical path keeps its [`ConnectionIds`]: this side's connection
//! ID, which the long headers it sends carry as their Source Connection ID,
//! as the connection node keeps it ([`FirstLocalConnectionId`]); and the
//! destination connection ID strategy, made from the configuration the
//! connection node keeps ([`DestinationConnectionIdConfig`]) with the
//! `active_connection_id_limit` this side sends. A client's strategy starts
//! with the Destination Connection ID the client chose. The strategy learns
//! the connection ID the peer chose for the handshake once: the Source
//! Connection ID of the first Initial packet that opens from the peer (RFC
//! 9000 §7.2), whether a server's first flight was read before the
//! connection was made or by the receiving call. The connection node keeps
//! it too ([`PeerHandshakeConnectionId`]), with the client's first
//! Destination Connection IDs ([`InitialDestinationConnectionIds`]): the
//! handshake checks the peer's transport parameters against them (§7.3).
//!
//! The connection node keeps the [`ConnectionResetTokenRegistry`]. Each
//! link path makes its [`LinkPathResetTokenRegistrar`] from it when it is
//! built, for its link's peer and its logical path's
//! [`StatelessResetSignal`], and tells the strategy when it is added and
//! when it ends.

use core::fmt;
use std::sync::Arc;

use sakuya_wire::{
    connection_id::{ConnectionId, NonEmptyCid, StatelessResetToken},
    parts::Selector,
    v1::transport_parameters::{TransportParameterSlots, integer::ActiveConnectionIdLimit},
};

use frunk_core::{HList, hlist_pat};

use super::{
    Choices, ConnectionArgs, Side,
    first_flight::FirstFlightStart,
    parameters::LocalTransportParameters,
    send::{RetireConnectionIdIntent, SendTypes},
    send_planning::{SendStrategyCore, SendStrategyOf},
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
        DestinationConnectionIdStrategy, NewConnectionId,
        reset_token::{ResetTokenRegistrar, ResetTokenRegistry},
        violation::NewConnectionIdViolationError,
    },
    frame_source::PublishIntent,
    layer,
    others::OtherNodes,
    send_strategy::SendStrategyTypes,
    share::{ConnectionArgsOf, LineageLists, LineagePartList},
    take::{GetAt, Lineage, Reborrow, Take, TakeEach},
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
/// long headers this side sends, and the transport parameters' Initial
/// Source Connection ID (RFC 9000 §7.3).
///
/// A connection that chose a zero-length connection ID for this side has
/// no stateless reset token for it (RFC 9000 §5.1, §10.3); any other has
/// the one it was issued with, which a server sends as its
/// `stateless_reset_token` (§18.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstLocalConnectionId {
    /// This side chose a zero-length connection ID.
    ZeroLength,
    /// A connection ID issued with its stateless reset token.
    Issued {
        /// The connection ID.
        id: NonEmptyCid,
        /// Its stateless reset token.
        reset_token: StatelessResetToken,
    },
}

impl FirstLocalConnectionId {
    /// The connection ID, of zero length when this side chose none.
    pub fn id(&self) -> ConnectionId {
        match self {
            Self::ZeroLength => ConnectionId::EMPTY,
            Self::Issued { id, .. } => id.get(),
        }
    }

    /// Its stateless reset token, if it has one.
    pub fn reset_token(&self) -> Option<StatelessResetToken> {
        match self {
            Self::ZeroLength => None,
            Self::Issued { reset_token, .. } => Some(*reset_token),
        }
    }
}

impl<T: Choices, L, I> Build<T, L, layer::Connection, (I,)> for FirstLocalConnectionId
where
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        Selector::<ConnectionArgs<T, L>, I>::get(args).first_local_connection_id
    }
}
impl PassiveDataComponent for FirstLocalConnectionId {}

/// The Destination Connection IDs of the client's first Initial packets,
/// kept in the connection node: what the transport parameters state of
/// them is checked against, or made from (RFC 9000 §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitialDestinationConnectionIds {
    made_with: ConnectionId,
    before_retry: Option<ConnectionId>,
}

impl InitialDestinationConnectionIds {
    /// The one the connection was made with, which the Initial keys are
    /// derived from: the one a client chose, or the one a server found in
    /// the first datagrams.
    pub fn made_with(&self) -> ConnectionId {
        self.made_with
    }

    /// The client's first one: the one before a Retry, when the server
    /// sent one before the connection was made; the one the connection was
    /// made with otherwise. It is the `original_destination_connection_id`
    /// a server sends.
    pub fn original(&self) -> ConnectionId {
        self.before_retry.unwrap_or(self.made_with)
    }

    /// The Source Connection ID of the Retry a server sent before the
    /// connection was made, which is the one the connection was made with:
    /// the `retry_source_connection_id` it sends. `None` without a Retry.
    pub fn retry_source(&self) -> Option<ConnectionId> {
        self.before_retry.map(|_| self.made_with)
    }
}

impl<T: Choices, L, I> Build<T, L, layer::Connection, (I,)> for InitialDestinationConnectionIds
where
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        let args = Selector::<ConnectionArgs<T, L>, I>::get(args);
        Self {
            made_with: args.client_dcid,
            before_retry: args.original_destination_connection_id,
        }
    }
}
impl PassiveDataComponent for InitialDestinationConnectionIds {}

/// The Source Connection ID of the first Initial packet opened from the
/// peer, kept in the connection node once it is: the connection ID the
/// peer chose for the handshake, which its `initial_source_connection_id`
/// must state (RFC 9000 §7.2, §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PeerHandshakeConnectionId(Option<ConnectionId>);

impl PeerHandshakeConnectionId {
    /// The connection ID, once an Initial packet from the peer opened.
    pub fn get(&self) -> Option<ConnectionId> {
        self.0
    }

    /// An Initial packet from the peer with the Source Connection ID `id`
    /// opened; only the first counts.
    pub(super) fn opened(&mut self, id: ConnectionId) {
        self.0.get_or_insert(id);
    }
}

/// No packet from the peer has opened when the connection is made.
impl<T: Choices, L> Build<T, L, layer::Connection, ()> for PeerHandshakeConnectionId
where
    L: LineagePartList<T>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        _: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        Self(None)
    }
}
/// It has no deadline and reads nothing; the receiving of the first Initial
/// packet from the peer writes it, and the handshake reads it.
impl PassiveDataComponent for PeerHandshakeConnectionId {}

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
/// sends, as sent or else as configured (RFC 9000 §18.2: 2 when absent),
/// and starts with what the side sends with before the peer chose its
/// connection ID: a client, the Destination Connection ID it chose (RFC
/// 9000 §7.2). A first flight read before the connection was made gives
/// the handshake connection ID it opened, which the connection node then
/// keeps too.
impl<T: Choices, L, Ic, Il, Ia, If, Ix, Id, Ip>
    Build<T, L, layer::LogicalPath, ((Ic, Il, Ia, If, Ix), (Id, Ip))> for ConnectionIdsOf<T>
where
    L: LineagePartList<T>,
    TransportParameterSlots: Selector<Option<ActiveConnectionIdLimit>, Ia>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<DestinationConnectionIdConfig<DestinationConnectionIdConfigOf<T>>, Ic>
        + GetAt<LocalTransportParameters<TransportParameterSlots>, Il>
        + GetAt<FirstFlightStart<T>, If>
        + GetAt<FirstLocalConnectionId, Ix>
        + GetAt<InitialDestinationConnectionIds, Id>
        + GetAt<PeerHandshakeConnectionId, Ip>,
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
            local: parents.get::<FirstLocalConnectionId, Ix>().id(),
            destination: <T::DestinationConnectionIds as DestinationConnectionIdStrategy<
                LinkIdOf<T>,
                InstantOf<T>,
                ResetTokenRegistrarOf<T>,
            >>::new(config, active_limit),
            handshake_known: false,
        };
        let made_with = parents
            .get::<InitialDestinationConnectionIds, Id>()
            .made_with();
        if let Some(id) = <T::Side as Side>::initial_destination_connection_id(made_with) {
            DestinationConnectionIdStrategy::<LinkIdOf<T>, InstantOf<T>, ResetTokenRegistrarOf<T>>::on_handshake_connection_id(
                &mut ids.destination,
                id,
            );
        }
        if let Some(id) = parents
            .get_mut::<FirstFlightStart<T>, If>()
            .take_handshake_connection_id()
        {
            parents
                .get_mut::<PeerHandshakeConnectionId, Ip>()
                .opened(id);
            ids.handshake_connection_id::<LinkIdOf<T>, InstantOf<T>, ResetTokenRegistrarOf<T>>(id);
        }
        ids
    }
}

// ---- the strategy's events that retire connection IDs ----

/// The core of the send strategy of the choices `T` and the list of parts
/// `L`, as the connection node holds it.
type CoreOf<T, L> = SendStrategyCore<SendStrategyOf<T, L>>;

/// What an event of the destination connection ID strategy that may
/// retire connection IDs takes out of a lineage: the logical path's
/// connection IDs, and the core the frames are published to.
type RetiringTakes<T, L> = HList![ConnectionIdsOf<T>, CoreOf<T, L>];

/// `V: CoreLentConnectionIdEvents<T, L, H>`: the events of the destination
/// connection ID strategy that may retire connection IDs, in a lineage of
/// `V`, with the core, which the lineage holds, lent to publish the
/// frames of what they retire.
///
/// `H` holds the positions of the connection IDs and of the core, and the
/// place of [`RetireConnectionIdIntent`] among the composition's intents.
pub trait CoreLentConnectionIdEvents<T: Choices, L, H>: Sized {
    /// The peer issued `issued`.
    ///
    /// # Errors
    ///
    /// What [`DestinationConnectionIdStrategy::on_new_connection_id`]
    /// returns.
    fn new_connection_id(
        lineage: &mut Lineage<'_, Self>,
        issued: NewConnectionId,
    ) -> Result<(), NewConnectionIdViolationError>;

    /// `link_path` ended.
    fn link_path_ended(lineage: &mut Lineage<'_, Self>, link_path: &LinkIdOf<T>);

    /// The strategy's deadline came at `now`.
    fn deadline(lineage: &mut Lineage<'_, Self>, now: InstantOf<T>);
}

impl<T, L, V, Is, Idx> CoreLentConnectionIdEvents<T, L, (Is, Idx)> for V
where
    T: Choices,
    SendTypes<T, L>: SendStrategyTypes,
    CoreOf<T, L>: PublishIntent<RetireConnectionIdIntent, Idx> + 'static,
    for<'s> V: Reborrow<'s>,
    for<'s> <V as Reborrow<'s>>::Out: TakeEach<'s, RetiringTakes<T, L>, Is>,
{
    fn new_connection_id(
        lineage: &mut Lineage<'_, V>,
        issued: NewConnectionId,
    ) -> Result<(), NewConnectionIdViolationError> {
        let (hlist_pat![ids, core], _) = Take::<RetiringTakes<T, L>, Is>::take(lineage.reborrow());
        DestinationConnectionIdStrategy::<LinkIdOf<T>, InstantOf<T>, ResetTokenRegistrarOf<T>>::on_new_connection_id::<_, Idx>(
            &mut ids.destination,
            core,
            issued,
        )
    }

    fn link_path_ended(lineage: &mut Lineage<'_, V>, link_path: &LinkIdOf<T>) {
        let (hlist_pat![ids, core], _) = Take::<RetiringTakes<T, L>, Is>::take(lineage.reborrow());
        DestinationConnectionIdStrategy::<LinkIdOf<T>, InstantOf<T>, ResetTokenRegistrarOf<T>>::on_link_path_ended::<_, Idx>(
            &mut ids.destination,
            core,
            link_path,
        );
    }

    fn deadline(lineage: &mut Lineage<'_, V>, now: InstantOf<T>) {
        let (hlist_pat![ids, core], _) = Take::<RetiringTakes<T, L>, Is>::take(lineage.reborrow());
        DestinationConnectionIdStrategy::<LinkIdOf<T>, InstantOf<T>, ResetTokenRegistrarOf<T>>::on_deadline::<_, Idx>(
            &mut ids.destination,
            core,
            now,
        );
    }
}

/// The strategy's deadline is its own; it reads itself. When it comes,
/// what it retires is published to the core.
impl<T: Choices, L, I, H> DataComponent<T, L, layer::LogicalPath, (I, H)> for ConnectionIdsOf<T>
where
    L: LineagePartList<T>,
    for<'v> <L as LineageLists<'v, T>>::LogicalPath:
        GetAt<Self, I> + CoreLentConnectionIdEvents<T, L, H>,
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
        CoreLentConnectionIdEvents::<T, L, H>::deadline(&mut lineage, now);
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
/// when it ends; what its end retires is published to the core.
impl<T: Choices, L, Ir, Is, Ii, H> Build<T, L, layer::LinkPath, (Ir, Is, Ii, H)>
    for LinkPathResetTokenRegistrar<ResetTokenRegistrarOf<T>>
where
    L: LineagePartList<T>,
    for<'v> <L as LineageLists<'v, T>>::LinkPathParents: GetAt<ConnectionResetTokenRegistry<T::ResetTokenRegistry>, Ir>
        + GetAt<Arc<StatelessResetSignal>, Is>
        + GetAt<ConnectionIdsOf<T>, Ii>
        + CoreLentConnectionIdEvents<T, L, H>,
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
        CoreLentConnectionIdEvents::<T, L, H>::link_path_ended(parents, link);
    }
}
impl<R> PassiveDataComponent for LinkPathResetTokenRegistrar<R> {}
