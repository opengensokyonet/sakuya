//! The connection IDs of a logical path, what issues this side's and what
//! registers the reset tokens of the peer's.
//!
//! Each logical path keeps its [`ConnectionIds`]: this side's connection
//! ID, which the long headers it sends carry as their Source Connection ID,
//! as the connection node keeps it ([`FirstLocalConnectionId`]); the
//! destination connection ID strategy, made from the configuration the
//! connection node keeps ([`DestinationConnectionIdConfig`]) with the
//! `active_connection_id_limit` this side sends; and the local connection
//! ID strategy, made with the first local connection ID and its
//! registration, which it takes from the connection node's
//! [`LocalConnectionIdIssuer`]. The issuer there is lent to the local
//! strategy's events: once the peer's transport parameters are known, with
//! the peer's `active_connection_id_limit`, and before that, for a client
//! that sends 0-RTT, with the remembered one; when the server rejected
//! that 0-RTT, with this connection's, which may be smaller; once the
//! handshake is
//! confirmed; when a RETIRE_CONNECTION_ID frame arrives; and when its
//! deadline comes. A client's strategy starts
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

use core::{fmt, time::Duration};
use std::sync::Arc;

use bytes::Bytes;
use sakuya_wire::parts::Selector;
use sakuya_wire_v1::{
    connection_id::{ConnectionId, NonEmptyCid, StatelessResetToken},
    parameters::ParametersOf,
};
use sakuya_wire_v1::{
    role::Role,
    transport_parameters::{
        TransportParameterSlots, TransportParameterSpace, TransportParameters,
        integer::ActiveConnectionIdLimit, preferred_address::PreferredAddress,
        stateless_reset_token::StatelessResetToken as StatelessResetTokenParameter,
    },
};

use frunk_core::{HList, hlist_pat};

use super::{
    Choices, ConnectionArgs, Side,
    component_events::{
        DestinationConnectionIdsChanged, HandshakeConfirmed, LocalConnectionIdsChanged,
        PeerTransportParametersKnown, ZeroRttRejected,
    },
    confirmation::HandshakeConfirmation,
    first_flight::FirstFlightStart,
    parameters::{LocalTransportParameters, PeerTransportParameters},
    stateless_reset::StatelessResetSignal,
};
use crate::v1::{DestinationConnectionIdsOf, LocalConnectionIdsOf};
use crate::{
    call::CallBundle,
    clock::{ConnectionChoices, InstantOf, LinkIdOf},
    component::{
        ArgsOf, Build, DataComponent, LineageOf, ParentsOf, PassiveDataComponent, RequestOf,
    },
    component_event::{EventSubscriptions, Happened, NodeStarted, TriggeredEvents},
    connection_id::{
        DestinationConnectionIdStrategy, NewConnectionId,
        local::{
            ConnectionIdIssuer, IssuedConnectionId, LocalConnectionIdStrategy,
            RetiredByPeerViolationError,
        },
        reset_token::{ResetTokenRegistrar, ResetTokenRegistry},
        violation::NewConnectionIdViolationError,
    },
    layer,
    others::OtherNodes,
    share::{ConnectionArgsOf, LineageLists, LineagePartList},
    take::{GetAt, Lineage, Reborrow, Take, TakeEach},
};
use sakuya_link::Link;

/// The peer of a link of the choices `T`.
pub type PeerOf<T> = <<T as ConnectionChoices>::Link as Link>::Peer;

/// The registrar each link path of the choices `T` makes from the
/// connection's registry.
pub type ResetTokenRegistrarOf<T> =
    <<T as crate::v1::MakerChoices>::ResetTokenRegistry as ResetTokenRegistry<
        PeerOf<T>,
        Arc<StatelessResetSignal>,
    >>::Registrar;

/// What keeps a connection ID the issuer of the choices `T` issued
/// registered with routing, until it is dropped.
pub type LocalConnectionIdRegistrationOf<T> =
    <<T as crate::v1::MakerChoices>::ConnectionIdIssuer as ConnectionIdIssuer>::Registration;

/// The configuration the destination connection ID strategy of the
/// choices `T` is made from.
pub type DestinationConnectionIdConfigOf<T> =
    <DestinationConnectionIdsOf<T> as DestinationConnectionIdStrategy<
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

/// What issues this side's connection IDs after the first, `C`, kept in the
/// connection node and lent to the events of the local connection ID
/// strategy, with the registration of the first local connection ID with
/// routing until the first logical path's strategy takes it.
///
/// The connection is made with one ([`ConnectionArgs::local_connection_id_issuer`]),
/// which the connection node moves out of what it was made with.
///
/// A server whose configured transport parameters have a
/// `preferred_address` issues its connection ID, sequence number 1, as the
/// connection node is built (RFC 9000 §5.1.1): it and its stateless reset
/// token go into the parameter, and the first logical path's strategy takes
/// it with its registration. A connection that issues no other connection
/// ID, with a zero-length one or without the first one's registration,
/// sends no preferred address (§18.2); nor does a client, which never sends
/// one.
pub struct LocalConnectionIdIssuer<C: ConnectionIdIssuer> {
    /// `None` only in what the connection was made with, once the
    /// connection node moved it out.
    issuer: Option<C>,
    first_registration: Option<C::Registration>,
    /// The connection ID of the preferred address, until the first logical
    /// path's strategy takes it.
    preferred: Option<IssuedConnectionId<C::Registration>>,
}

impl<C: ConnectionIdIssuer> LocalConnectionIdIssuer<C> {
    /// `issuer`, with `first_registration`, the registration of the first
    /// local connection ID: `Some` when that connection ID is
    /// [`Issued`](FirstLocalConnectionId::Issued), and then the local
    /// connection ID strategy keeps it; `None` for a zero-length one, whose
    /// registration by its local end whoever made the connection keeps. A
    /// connection whose first local connection ID was issued and is made
    /// without its registration issues no other, as one with a zero-length
    /// connection ID; a registration given with a zero-length one is
    /// dropped.
    pub fn new(issuer: C, first_registration: Option<C::Registration>) -> Self {
        Self {
            issuer: Some(issuer),
            first_registration,
            preferred: None,
        }
    }

    /// Move the issuer and the registration out into a new value, leaving
    /// this one empty.
    fn moved(&mut self) -> Self {
        Self {
            issuer: self.issuer.take(),
            first_registration: self.first_registration.take(),
            preferred: self.preferred.take(),
        }
    }

    /// The issuer, to lend to an event of the local connection ID strategy.
    pub fn issuer_mut(&mut self) -> &mut C {
        // invariant: only what the connection was made with is left
        // without its issuer, once the connection node moved it out; the
        // connection node's keeps it
        self.issuer
            .as_mut()
            .expect("the connection node keeps its connection ID issuer")
    }

    /// The registration of the first local connection ID, the first time
    /// it is asked for; `None` afterwards.
    fn take_first_registration(&mut self) -> Option<C::Registration> {
        self.first_registration.take()
    }

    /// The connection ID of the preferred address, the first time it is
    /// asked for; `None` afterwards, and without one.
    fn take_preferred(&mut self) -> Option<IssuedConnectionId<C::Registration>> {
        self.preferred.take()
    }
}

impl<C: ConnectionIdIssuer> fmt::Debug for LocalConnectionIdIssuer<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalConnectionIdIssuer")
            .field("first_registration", &self.first_registration.is_some())
            .field("preferred", &self.preferred.is_some())
            .finish_non_exhaustive()
    }
}

impl<T: Choices, L, I> Build<T, L, layer::Connection, (I,)>
    for LocalConnectionIdIssuer<T::ConnectionIdIssuer>
where
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        let args = Selector::<ConnectionArgs<T, L>, I>::get_mut(args);
        let mut issuer = args.local_connection_id_issuer.moved();
        let mut parameters = TransportParameters::<Bytes>::new();
        parameters.known = args.transport_parameters;
        let slot = parameters.slot_mut::<PreferredAddress, _>();
        let Some(preferred) = slot.as_mut() else {
            return issuer;
        };
        let issues = <T::Side as Side>::ROLE == Role::Server
            && matches!(
                args.first_local_connection_id,
                FirstLocalConnectionId::Issued { .. }
            )
            && issuer.first_registration.is_some();
        if issues {
            let issued = issuer.issuer_mut().issue();
            preferred.connection_id = issued.id;
            preferred.stateless_reset_token = issued.token;
            issuer.preferred = Some(issued);
        } else {
            *slot = None;
        }
        // the parameters this side sends are settled from these
        args.transport_parameters = parameters.known;
        issuer
    }
}
/// It has no deadline and subscribes to nothing; the first logical path takes the
/// registration from it, and the events of the local connection ID
/// strategy are lent the issuer.
impl<C: ConnectionIdIssuer> PassiveDataComponent for LocalConnectionIdIssuer<C> {}

/// The Destination Connection IDs of the client's first Initial packets,
/// kept in the connection node: what the transport parameters state of
/// them is checked against, or made from (RFC 9000 §7.3). A server knows
/// them when the connection is made; a client learns the Retry's when it
/// goes on after one.
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
    /// sent one before the connection was made or the client went on after
    /// one; the one the connection was made with otherwise. It is the
    /// `original_destination_connection_id` a server sends.
    pub fn original(&self) -> ConnectionId {
        self.before_retry.unwrap_or(self.made_with)
    }

    /// The Source Connection ID of the Retry: the one a server sent before
    /// the connection was made, which is the one the connection was made
    /// with, or the one a client went on after. It is the
    /// `retry_source_connection_id` a server sends. `None` without a Retry.
    pub fn retry_source(&self) -> Option<ConnectionId> {
        self.before_retry.map(|_| self.made_with)
    }

    /// A client went on after a Retry whose Source Connection ID is
    /// `source`: its Initial keys are derived from it now, and its first
    /// one is the original (RFC 9000 §7.3).
    pub(super) fn retried(&mut self, source: ConnectionId) {
        self.before_retry = Some(self.made_with);
        self.made_with = source;
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
/// It has no deadline and subscribes to nothing; the receiving of the first Initial
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

/// The connection IDs of a logical path: this side's, the destination
/// connection ID strategy `D` and the local connection ID strategy `Lo`,
/// with whether the destination strategy was told the peer's handshake
/// connection ID and the local strategy the peer's limit and the
/// confirmation.
pub struct ConnectionIds<D, Lo> {
    local: ConnectionId,
    destination: D,
    local_strategy: Lo,
    handshake_known: bool,
    peer_limit_told: PeerLimitTold,
    confirmation_told: bool,
}

/// Which `active_connection_id_limit` of the peer the local strategy was
/// told.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PeerLimitTold {
    /// None: the strategy holds the protocol's minimum of 2.
    NotYet,
    /// The remembered one, which a client's 0-RTT keeps to (RFC 9000
    /// §7.4.1).
    Remembered,
    /// The one of this connection's handshake.
    Known,
}

impl<D, Lo> fmt::Debug for ConnectionIds<D, Lo> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionIds")
            .field("local", &self.local)
            .field("handshake_known", &self.handshake_known)
            .field("peer_limit_told", &self.peer_limit_told)
            .field("confirmation_told", &self.confirmation_told)
            .finish_non_exhaustive()
    }
}

impl<D, Lo> ConnectionIds<D, Lo> {
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

    /// The local connection ID strategy.
    pub fn local_strategy(&self) -> &Lo {
        &self.local_strategy
    }

    /// The local connection ID strategy, to tell it of an event or to
    /// write its NEW_CONNECTION_ID frames with.
    pub fn local_strategy_mut(&mut self) -> &mut Lo {
        &mut self.local_strategy
    }

    /// The peer chose `id` for the handshake; only the first time counts
    /// (RFC 9000 §7.2). What happened, when the destination strategy
    /// reports that this changed its queries.
    #[must_use = "what happened is to be published in the lend"]
    pub(super) fn handshake_connection_id<Id, I, R>(
        &mut self,
        id: ConnectionId,
    ) -> Option<Happened<DestinationConnectionIdsChanged>>
    where
        D: DestinationConnectionIdStrategy<Id, I, R>,
        R: ResetTokenRegistrar,
    {
        if self.handshake_known {
            return None;
        }
        self.handshake_known = true;
        self.destination
            .on_handshake_connection_id(id)
            .then(Happened::new)
    }
}

/// The connection IDs of a logical path of the choices `T`.
pub type ConnectionIdsOf<T> = ConnectionIds<DestinationConnectionIdsOf<T>, LocalConnectionIdsOf<T>>;

/// This side's connection ID is the one the connection was made with. The
/// destination strategy is made with the `active_connection_id_limit` this
/// side sends, as sent or else as configured (RFC 9000 §18.2: 2 when
/// absent), and starts with what the side sends with before the peer
/// chose its connection ID: a client, the Destination Connection ID it
/// chose (RFC 9000 §7.2). A first flight read before the connection was
/// made gives the handshake connection ID it opened, which the connection
/// node then keeps too.
///
/// The local strategy is made with the first local connection ID, numbered
/// 0, and the registration the connection node keeps for it, which the
/// first logical path takes; a zero-length one has none to take, and the
/// strategy is made with nothing then.
impl<T: Choices, L, Ic, Il, Ia, If, Ix, Id, Ip, Iu>
    Build<T, L, layer::LogicalPath, ((Ic, Il, Ia, If, Ix), (Id, Ip, Iu))> for ConnectionIdsOf<T>
where
    L: LineagePartList<T>,
    TransportParameterSlots: Selector<Option<ActiveConnectionIdLimit>, Ia>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<DestinationConnectionIdConfig<DestinationConnectionIdConfigOf<T>>, Ic>
        + GetAt<LocalTransportParameters<crate::v1::Part>, Il>
        + GetAt<FirstFlightStart<T>, If>
        + GetAt<FirstLocalConnectionId, Ix>
        + GetAt<InitialDestinationConnectionIds, Id>
        + GetAt<PeerHandshakeConnectionId, Ip>
        + GetAt<LocalConnectionIdIssuer<T::ConnectionIdIssuer>, Iu>,
{
    fn build<'v>(
        parents: &mut ParentsOf<'v, T, L, layer::LogicalPath>,
        _: &mut ArgsOf<T, L, layer::LogicalPath>,
    ) -> Self {
        let local = parents.get::<LocalTransportParameters<crate::v1::Part>, Il>();
        let active_limit = local
            .sent()
            .or(local.configured())
            .and_then(|slots| *Selector::<Option<ActiveConnectionIdLimit>, Ia>::get(slots))
            .unwrap_or_default();
        let config = &parents
            .get::<DestinationConnectionIdConfig<DestinationConnectionIdConfigOf<T>>, Ic>()
            .0;
        let destination = <DestinationConnectionIdsOf<T> as DestinationConnectionIdStrategy<
            LinkIdOf<T>,
            InstantOf<T>,
            ResetTokenRegistrarOf<T>,
        >>::new(config, active_limit);
        let first_local = *parents.get::<FirstLocalConnectionId, Ix>();
        let registration = parents
            .get_mut::<LocalConnectionIdIssuer<T::ConnectionIdIssuer>, Iu>()
            .take_first_registration();
        let preferred = parents
            .get_mut::<LocalConnectionIdIssuer<T::ConnectionIdIssuer>, Iu>()
            .take_preferred();
        let first_issued = match (first_local, registration) {
            (FirstLocalConnectionId::Issued { id, reset_token }, Some(registration)) => {
                Some(IssuedConnectionId {
                    id,
                    token: reset_token,
                    registration,
                })
            }
            (FirstLocalConnectionId::Issued { .. }, None)
            | (FirstLocalConnectionId::ZeroLength, _) => None,
        };
        let local_strategy = <LocalConnectionIdsOf<T> as LocalConnectionIdStrategy<
            LinkIdOf<T>,
            InstantOf<T>,
            LocalConnectionIdRegistrationOf<T>,
        >>::new(first_issued, preferred);
        let mut ids = ConnectionIds {
            local: first_local.id(),
            destination,
            local_strategy,
            handshake_known: false,
            peer_limit_told: PeerLimitTold::NotYet,
            confirmation_told: false,
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
            // the logical path is being built: what follows its connection
            // IDs hears of them as the node starts
            drop(
                ids.handshake_connection_id::<LinkIdOf<T>, InstantOf<T>, ResetTokenRegistrarOf<T>>(
                    id,
                ),
            );
        }
        ids
    }
}

// ---- the strategies' events that retire and issue connection IDs ----

/// What an event of the destination connection ID strategy takes out of a
/// lineage: the logical path's connection IDs.
type RetiringTakes<T> = HList![ConnectionIdsOf<T>];

/// What an event of the local connection ID strategy takes out of a
/// lineage: the logical path's connection IDs and the connection's issuer.
type IssuingTakes<T> = HList![
    ConnectionIdsOf<T>,
    LocalConnectionIdIssuer<<T as crate::v1::MakerChoices>::ConnectionIdIssuer>
];

/// `V: LineageConnectionIdEvents<T, L, H>`: the events of the destination
/// connection ID strategy that may retire connection IDs and those of the
/// local connection ID strategy, in a lineage of `V`, the local strategy's
/// with the connection's issuer, which the lineage holds too. What they
/// retire or issue waits in the strategies to be sent. When a strategy
/// reports that its queries changed, that its connection IDs changed is
/// published through the lineage, which holds the logical path.
///
/// `H` holds the positions of what the destination strategy's events take,
/// then those of what the local strategy's events take.
pub trait LineageConnectionIdEvents<T: Choices, L, H>: Sized {
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

    /// This side may issue up to `peer_limit` connection IDs.
    fn issuable(lineage: &mut Lineage<'_, Self>, peer_limit: u64);

    /// The server rejected 0-RTT, and this side may issue up to
    /// `peer_limit` connection IDs, which can be fewer than the remembered
    /// limit it was told.
    fn zero_rtt_rejected(lineage: &mut Lineage<'_, Self>, peer_limit: u64);

    /// The handshake is confirmed.
    fn handshake_confirmed(lineage: &mut Lineage<'_, Self>);

    /// The peer retired `sequence` in a packet sent to
    /// `packet_destination` that arrived at `now`, with the probe timeout
    /// `pto` then.
    ///
    /// # Errors
    ///
    /// What [`LocalConnectionIdStrategy::on_retired_by_peer`] returns.
    fn retired_by_peer(
        lineage: &mut Lineage<'_, Self>,
        sequence: u64,
        packet_destination: &ConnectionId,
        now: InstantOf<T>,
        pto: Duration,
    ) -> Result<(), RetiredByPeerViolationError>;

    /// The deadline of the logical path's connection IDs came at `now`:
    /// each strategy does what is due by then.
    fn deadline(lineage: &mut Lineage<'_, Self>, now: InstantOf<T>);

    /// The peer switched to this side's connection ID `id` on `link_path`,
    /// the link path's first packet included.
    fn used_by_peer(lineage: &mut Lineage<'_, Self>, id: &ConnectionId, link_path: &LinkIdOf<T>);
}

impl<T, L, V, Is, Iu> LineageConnectionIdEvents<T, L, (Is, Iu)> for V
where
    T: Choices,
    for<'s> V: Reborrow<'s>,
    for<'s> <V as Reborrow<'s>>::Out:
        TakeEach<'s, RetiringTakes<T>, Is> + TakeEach<'s, IssuingTakes<T>, Iu>,
{
    fn new_connection_id(
        lineage: &mut Lineage<'_, V>,
        issued: NewConnectionId,
    ) -> Result<(), NewConnectionIdViolationError> {
        let (hlist_pat![mut ids], _) = Take::<RetiringTakes<T>, Is>::take(lineage.reborrow());
        let changed = DestinationConnectionIdStrategy::<
            LinkIdOf<T>,
            InstantOf<T>,
            ResetTokenRegistrarOf<T>,
        >::on_new_connection_id(&mut ids.destination, issued)?;
        destination_changed(lineage, changed);
        Ok(())
    }

    fn link_path_ended(lineage: &mut Lineage<'_, V>, link_path: &LinkIdOf<T>) {
        let (hlist_pat![mut ids], _) = Take::<RetiringTakes<T>, Is>::take(lineage.reborrow());
        let changed = DestinationConnectionIdStrategy::<
            LinkIdOf<T>,
            InstantOf<T>,
            ResetTokenRegistrarOf<T>,
        >::on_link_path_ended(&mut ids.destination, link_path);
        destination_changed(lineage, changed);
    }

    fn issuable(lineage: &mut Lineage<'_, V>, peer_limit: u64) {
        let (hlist_pat![mut ids, mut issuer], _) =
            Take::<IssuingTakes<T>, Iu>::take(lineage.reborrow());
        let changed =
            LocalConnectionIdStrategy::<
                LinkIdOf<T>,
                InstantOf<T>,
                LocalConnectionIdRegistrationOf<T>,
            >::on_issuable(&mut ids.local_strategy, issuer.issuer_mut(), peer_limit);
        local_changed(lineage, changed);
    }

    fn zero_rtt_rejected(lineage: &mut Lineage<'_, V>, peer_limit: u64) {
        let (hlist_pat![mut ids, mut issuer], _) =
            Take::<IssuingTakes<T>, Iu>::take(lineage.reborrow());
        let changed = LocalConnectionIdStrategy::<
            LinkIdOf<T>,
            InstantOf<T>,
            LocalConnectionIdRegistrationOf<T>,
        >::on_zero_rtt_rejected(
            &mut ids.local_strategy, issuer.issuer_mut(), peer_limit
        );
        local_changed(lineage, changed);
    }

    fn handshake_confirmed(lineage: &mut Lineage<'_, V>) {
        let (hlist_pat![mut ids, mut issuer], _) =
            Take::<IssuingTakes<T>, Iu>::take(lineage.reborrow());
        let changed =
            LocalConnectionIdStrategy::<
                LinkIdOf<T>,
                InstantOf<T>,
                LocalConnectionIdRegistrationOf<T>,
            >::on_handshake_confirmed(&mut ids.local_strategy, issuer.issuer_mut());
        local_changed(lineage, changed);
    }

    fn retired_by_peer(
        lineage: &mut Lineage<'_, V>,
        sequence: u64,
        packet_destination: &ConnectionId,
        now: InstantOf<T>,
        pto: Duration,
    ) -> Result<(), RetiredByPeerViolationError> {
        let (hlist_pat![mut ids, mut issuer], _) =
            Take::<IssuingTakes<T>, Iu>::take(lineage.reborrow());
        let changed = LocalConnectionIdStrategy::<
            LinkIdOf<T>,
            InstantOf<T>,
            LocalConnectionIdRegistrationOf<T>,
        >::on_retired_by_peer(
            &mut ids.local_strategy,
            issuer.issuer_mut(),
            sequence,
            packet_destination,
            now,
            pto,
        )?;
        local_changed(lineage, changed);
        Ok(())
    }

    fn deadline(lineage: &mut Lineage<'_, V>, now: InstantOf<T>) {
        let (hlist_pat![mut ids], _) = Take::<RetiringTakes<T>, Is>::take(lineage.reborrow());
        let changed = DestinationConnectionIdStrategy::<
            LinkIdOf<T>,
            InstantOf<T>,
            ResetTokenRegistrarOf<T>,
        >::on_deadline(&mut ids.destination, now);
        destination_changed(lineage, changed);
        let (hlist_pat![mut ids, mut issuer], _) =
            Take::<IssuingTakes<T>, Iu>::take(lineage.reborrow());
        let changed = LocalConnectionIdStrategy::<
            LinkIdOf<T>,
            InstantOf<T>,
            LocalConnectionIdRegistrationOf<T>,
        >::on_deadline(&mut ids.local_strategy, issuer.issuer_mut(), now);
        local_changed(lineage, changed);
    }

    fn used_by_peer(lineage: &mut Lineage<'_, V>, id: &ConnectionId, link_path: &LinkIdOf<T>) {
        let (hlist_pat![mut ids, mut issuer], _) =
            Take::<IssuingTakes<T>, Iu>::take(lineage.reborrow());
        let changed = LocalConnectionIdStrategy::<
            LinkIdOf<T>,
            InstantOf<T>,
            LocalConnectionIdRegistrationOf<T>,
        >::on_used_by_peer(
            &mut ids.local_strategy, issuer.issuer_mut(), id, link_path
        );
        local_changed(lineage, changed);
    }
}

/// When the destination strategy reported that its queries `changed`,
/// publish that the destination connection IDs changed through `lineage`.
fn destination_changed<V>(lineage: &mut Lineage<'_, V>, changed: bool) {
    if changed {
        lineage.publish(Happened::<DestinationConnectionIdsChanged>::new());
    }
}

/// When the local strategy reported that its queries `changed`, publish
/// that the local connection IDs changed through `lineage`.
fn local_changed<V>(lineage: &mut Lineage<'_, V>, changed: bool) {
    if changed {
        lineage.publish(Happened::<LocalConnectionIdsChanged>::new());
    }
}

/// The connection IDs' deadline is the earlier of the two strategies'. When
/// it comes, each strategy does what is due, and what they retire or issue
/// waits in them to be sent.
///
/// They also subscribe to the handshake confirmed, to the peer's transport
/// parameters known and to their logical path built, to tell the local
/// strategy once each: once the peer's parameters are known, 1-RTT packets
/// can be sent (a server's after it processed the ClientHello, a client's
/// as its handshake completes), and this side may issue up to the peer's
/// `active_connection_id_limit` (2 when absent, RFC 9000 §18.2). A client
/// that sends 0-RTT is told the remembered limit first, which 0-RTT keeps
/// to (§7.4.1), and, when the server rejected 0-RTT, this connection's
/// through the strategy's `on_zero_rtt_rejected`, as it may be smaller;
/// once the
/// handshake is confirmed, the strategy is told so. The first call this
/// side may issue at the protocol's minimum of 2 is not made: the strategy
/// starts there. A server's `stateless_reset_token` among the peer's
/// parameters, which only a client receives, is the token of the handshake
/// connection ID the destination strategy is told then; the connection ID
/// of a server's `preferred_address` is told it as the one numbered 1 (RFC
/// 9000 §5.1.1). It comes from the parameters of this connection only, as
/// a preferred address is valid for no other (§9.6.2). A strategy that
/// does not take it, as when it repeats another connection ID, leaves the
/// connection without it (§19.15: closing is a MAY).
impl<T: Choices, L, I, H, If, Ip, Ia, It, Ipa>
    DataComponent<T, L, layer::LogicalPath, (I, H, (If, Ip, Ia, It, Ipa))> for ConnectionIdsOf<T>
where
    L: LineagePartList<T> + ParametersOf<TransportParameterSpace>,
    TransportParameterSlots<L>: Selector<Option<ActiveConnectionIdLimit>, Ia>
        + Selector<Option<StatelessResetTokenParameter>, It>
        + Selector<Option<PreferredAddress>, Ipa>,
    for<'v> <L as LineageLists<'v, T>>::LogicalPath: GetAt<Self, I>
        + GetAt<HandshakeConfirmation, If>
        + GetAt<PeerTransportParameters<TransportParameterSlots<L>>, Ip>
        + LineageConnectionIdEvents<T, L, H>,
{
    const DEADLINE: bool = true;
    fn subscribes(out: &mut EventSubscriptions) {
        out.add::<HandshakeConfirmed>()
            .add::<PeerTransportParametersKnown>()
            .add::<ZeroRttRejected>()
            .add::<NodeStarted<layer::LogicalPath>>();
    }
    fn deadline<'v>(lineage: &LineageOf<'v, T, L, layer::LogicalPath>) -> Option<InstantOf<T>> {
        let ids = lineage.get::<Self, I>();
        let destination = DestinationConnectionIdStrategy::<
            LinkIdOf<T>,
            InstantOf<T>,
            ResetTokenRegistrarOf<T>,
        >::next_deadline(&ids.destination);
        let local = LocalConnectionIdStrategy::<
            LinkIdOf<T>,
            InstantOf<T>,
            LocalConnectionIdRegistrationOf<T>,
        >::next_deadline(&ids.local_strategy);
        match (destination, local) {
            (Some(destination), Some(local)) => Some(destination.min(local)),
            (destination, local) => destination.or(local),
        }
    }
    fn expire<'v, B: CallBundle>(
        mut lineage: LineageOf<'v, T, L, layer::LogicalPath>,
        _: &mut OtherNodes<'v, T, L, B>,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        LineageConnectionIdEvents::<T, L, H>::deadline(&mut lineage, now);
        None
    }
    fn on_events<'v, B: CallBundle>(
        events: TriggeredEvents<'_>,
        mut lineage: LineageOf<'v, T, L, layer::LogicalPath>,
        _: &mut OtherNodes<'v, T, L, B>,
        _: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let ids = lineage.get::<Self, I>();
        let (limit_told, confirmation_told) = (ids.peer_limit_told, ids.confirmation_told);
        let limit_of = |slots: &TransportParameterSlots<L>| {
            u64::from(
                (*Selector::<Option<ActiveConnectionIdLimit>, Ia>::get(slots))
                    .unwrap_or_default()
                    .get(),
            )
        };
        // a client that sends 0-RTT may issue up to the remembered limit
        // (RFC 9000 §7.4.1) until its handshake completes
        let peer = lineage.get::<PeerTransportParameters<TransportParameterSlots<L>>, Ip>();
        let remembered = match (limit_told, peer.known(), peer.slots()) {
            (PeerLimitTold::NotYet, None, Some(slots)) => Some(limit_of(slots)),
            _ => None,
        };
        if let Some(limit) = remembered {
            lineage.get_mut::<Self, I>().peer_limit_told = PeerLimitTold::Remembered;
            LineageConnectionIdEvents::<T, L, H>::issuable(&mut lineage, limit);
        }
        // the rejection is published in the lend that writes the known
        // parameters, so it comes with them
        let rejected =
            limit_told == PeerLimitTold::Remembered && events.contains::<ZeroRttRejected>();
        let known = if limit_told == PeerLimitTold::Known {
            None
        } else {
            lineage
                .get::<PeerTransportParameters<TransportParameterSlots<L>>, Ip>()
                .known()
                .map(|slots| {
                    let limit = (*Selector::<Option<ActiveConnectionIdLimit>, Ia>::get(slots))
                        .unwrap_or_default();
                    let token = (*Selector::<Option<StatelessResetTokenParameter>, It>::get(slots))
                        .map(StatelessResetTokenParameter::get);
                    let preferred = (*Selector::<Option<PreferredAddress>, Ipa>::get(slots))
                        .filter(|_| <T::Side as Side>::ROLE == Role::Client)
                        .map(|preferred| {
                            NewConnectionId::preferred_address(
                                preferred.connection_id,
                                preferred.stateless_reset_token,
                            )
                        });
                    (u64::from(limit.get()), token, preferred)
                })
        };
        debug_assert!(
            known.is_some() || !rejected,
            "0-RTT rejected without the parameters known"
        );
        let confirmed = !confirmation_told
            && *lineage.get::<HandshakeConfirmation, If>() == HandshakeConfirmation::Confirmed;
        if let Some((limit, token, preferred)) = known {
            let mut ids = lineage.get_mut::<Self, I>();
            ids.peer_limit_told = PeerLimitTold::Known;
            let mut changed = token.is_some_and(|token| {
                DestinationConnectionIdStrategy::<
                    LinkIdOf<T>,
                    InstantOf<T>,
                    ResetTokenRegistrarOf<T>,
                >::on_handshake_reset_token(&mut ids.destination, token)
            });
            if let Some(preferred) = preferred {
                let taken = DestinationConnectionIdStrategy::<
                    LinkIdOf<T>,
                    InstantOf<T>,
                    ResetTokenRegistrarOf<T>,
                >::on_new_connection_id(&mut ids.destination, preferred);
                changed |= taken.unwrap_or(false);
            }
            destination_changed(&mut lineage, changed);
            if rejected {
                LineageConnectionIdEvents::<T, L, H>::zero_rtt_rejected(&mut lineage, limit);
            } else {
                LineageConnectionIdEvents::<T, L, H>::issuable(&mut lineage, limit);
            }
        }
        if confirmed {
            lineage.get_mut::<Self, I>().confirmation_told = true;
            LineageConnectionIdEvents::<T, L, H>::handshake_confirmed(&mut lineage);
        }
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
/// when it ends; what its end retires waits in the strategy to be sent.
impl<T: Choices, L, Ir, Is, Ii, H> Build<T, L, layer::LinkPath, (Ir, Is, Ii, H)>
    for LinkPathResetTokenRegistrar<ResetTokenRegistrarOf<T>>
where
    L: LineagePartList<T>,
    for<'v> <L as LineageLists<'v, T>>::LinkPathParents: GetAt<ConnectionResetTokenRegistry<T::ResetTokenRegistry>, Ir>
        + GetAt<Arc<StatelessResetSignal>, Is>
        + GetAt<ConnectionIdsOf<T>, Ii>
        + LineageConnectionIdEvents<T, L, H>,
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
        let changed = DestinationConnectionIdStrategy::<
            LinkIdOf<T>,
            InstantOf<T>,
            ResetTokenRegistrarOf<T>,
        >::on_link_path_added(
            &mut parents.get_mut::<ConnectionIdsOf<T>, Ii>().destination,
            link,
            args.peer_switched_local_id,
        );
        destination_changed(parents, changed);
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
        LineageConnectionIdEvents::<T, L, H>::link_path_ended(parents, link);
    }
}
impl<R> PassiveDataComponent for LinkPathResetTokenRegistrar<R> {}

/// The connection ID of this side's that the peer last sent to on a link
/// path; `None` before the link path processed a packet, and always on a
/// connection whose connection IDs are zero-length, between which the peer
/// never switches.
///
/// The logical path's receiving call compares each processed packet's
/// Destination Connection ID with it, and with the active link path's for a
/// new link path's first packet: a change goes to the local connection ID
/// strategy ([`LocalConnectionIdStrategy::on_used_by_peer`]) and tells the
/// migration policy whether the peer switched (RFC 9000 §9.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LocalConnectionIdUsedByPeer(Option<ConnectionId>);

impl LocalConnectionIdUsedByPeer {
    /// The connection ID, once the peer sent to one on the link path.
    pub fn get(&self) -> Option<ConnectionId> {
        self.0
    }

    /// The peer sent to `id` on the link path.
    pub(super) fn set(&mut self, id: ConnectionId) {
        self.0 = Some(id);
    }
}

/// A link path starts with none.
impl<T: Choices, L> Build<T, L, layer::LinkPath, ()> for LocalConnectionIdUsedByPeer
where
    L: LineagePartList<T>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::LinkPath>,
        _: &mut ArgsOf<T, L, layer::LinkPath>,
    ) -> Self {
        Self::default()
    }
}
impl PassiveDataComponent for LocalConnectionIdUsedByPeer {}
