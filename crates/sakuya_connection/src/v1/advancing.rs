//! The advancing call: the handshake of version 1, run as the one call of
//! the connection node.
//!
//! Each side has its own call, [`server_advancing`] and
//! [`client_advancing`], whose kind the side gives
//! ([`Side::Advancing`](super::Side::Advancing)). The call takes the start
//! state of the side's handshake engine from what the connection was made
//! with ([`HandshakeStart`]) and runs the engine's steps one after the
//! other; after each step it installs what the step returned, in the same
//! lend, through the capability of its side ([`ServerAdvancingCapability`],
//! [`ClientAdvancingCapability`]):
//!
//! - A server first takes the first ClientHello: the one read with the
//!   first flight before the connection was made, or one it reads in the
//!   tree. Once its ServerHello is written it installs the Handshake keys,
//!   and the peer's transport parameters are known, so it yields
//!   [`EstablishedLayerReady`]; once its Finished is written, the 1-RTT
//!   keys to send with; once the client's Finished is verified, the 1-RTT
//!   keys to receive with, and the handshake is complete and confirmed
//!   (RFC 9001 §4.1.1, §4.1.2): the HANDSHAKE_DONE frame is due. It then
//!   writes its session tickets and ends.
//! - A client installs the Handshake keys once the ServerHello is read;
//!   once the server's Finished is verified and its own written, the 1-RTT
//!   keys, and yields [`EstablishedLayerReady`]. It then reads session
//!   tickets until the connection ends.
//!
//! The engine reads and writes CRYPTO data through the connection node's
//! [`CryptoReceiver`] and [`CryptoSender`], and exchanges transport
//! parameters through the connection node: version 1 checks the
//! connection IDs the peer's state (RFC 9000 §7.3) before it keeps them as
//! [`PeerTransportParameters::Known`], and sends its own, as configured
//! with the connection IDs of this connection filled in. The exporter of a
//! completed handshake is kept in [`ConnectionExporter`] until the
//! connection closes.
//!
//! This version neither sends nor receives 0-RTT: a server accepts no
//! early data, and 0-RTT secrets an engine gives are dropped.
//!
//! A step that fails writes its error into the record of why the
//! connection closed, and the call ends. Once the record is written the
//! call is not needed any more: it is dropped with the secrets it holds.
//!
//! [`server_advancing`] and [`client_advancing`] are also the operation
//! structs [`ServerAdvancing`] and [`ClientAdvancing`], with
//! `ServerAdvancingExt` and `ClientAdvancingExt` on receiver accesses.
// `#[call]` generates constructors and extension traits without
// documentation comments; the module documentation above describes them.
#![allow(missing_docs)]

use core::{
    convert::Infallible,
    fmt,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};
use std::sync::Arc;

use bytes::{Buf, BufMut, Bytes};
use nitori_call::{LentAccess, LentCall, call};
use nitori_io::{Read, Write};
use sakuya_link::Link;
use sakuya_packet_protection::backend::AeadAlgorithm;
use sakuya_stream::connection::CloseReason;
use sakuya_tls::{
    client::engine::{
        ClientHandshakeCapability, ClientHandshakeCompleted, ClientHandshakeSteps, ClientTransport,
    },
    engine::{CryptoInput, CryptoLevel, CryptoOutput, HandshakeError},
    extension::OpaqueData,
    message::MessageLimits,
    schedule::{Exporter, HandshakeTrafficSecrets, OneRttSendTrafficSecret},
    server::{
        engine::{
            FirstClientHello, Negotiated, ServerHandshakeCapability, ServerHandshakeCompleted,
            ServerHandshakeSteps, ServerHelloWritten, ServerTransport, read_first_client_hello,
        },
        targets::SelectedTarget,
        ticket::TicketState,
    },
};
use sakuya_wire::{
    parts::{CoprodInjector, Selector},
    v1::{
        role::Role,
        transport_parameters::{
            TransportParameterSlots, TransportParameters,
            codec::{ReadTransportParametersHostExt as _, WriteTransportParametersHostExt as _},
            connection_id::{
                InitialSourceConnectionId, OriginalDestinationConnectionId, RetrySourceConnectionId,
            },
            preferred_address::PreferredAddress,
            stateless_reset_token::StatelessResetToken,
        },
    },
};

use super::{
    Choices, Client, CloseCauseOf, ConnectionArgs, Server,
    close::{CloseReasonRecord, LocalCloseCause},
    confirmation::HandshakeConfirmation,
    connection_ids::{
        FirstLocalConnectionId, InitialDestinationConnectionIds, PeerHandshakeConnectionId,
    },
    crypto::{CryptoReceiver, send::CryptoSender},
    error::ConnectionError,
    handshake_done::HandshakeDoneSource,
    keys::{DirectionKeys, HandshakeKeys, LevelKeys, OneRttKeys, PacketProtectionBackend},
    parameters::{
        LocalTransportParameters, PeerTransportParameters, check_initial_source,
        check_server_destination, read_transport_parameters_error,
    },
    receive::v1_error,
    send::{HandshakeDoneIntent, SendTypes},
    send_planning::{SendStrategyCore, SendStrategyOf},
};
use crate::{
    call::{CallBundle, CallKind, NodeCallFamily, NodeLoan},
    clock::InstantOf,
    component::{ArgsOf, Build, DataComponent, LineageOf, ParentsOf, ReadSet, RequestOf},
    error::{ConnectionErrorOf, ConnectionErrorsOf, TransportParameterValueErrorsOf},
    frame_source::PublishIntent,
    layer::{self, Connection, EstablishedArgs},
    others::OtherNodes,
    request::StructureRequest,
    send_strategy::SendStrategyTypes,
    share::{ConnectionArgsOf, LineageLists, LineagePartList},
    take::GetAt,
};

// ---- what the call starts from ----

/// What a connection's handshake starts from, given once when the
/// connection is made: the start state `E` of the side's handshake engine,
/// and the limits on the first ClientHello a server reads in the tree,
/// which a client does not use. The advancing call takes it when it
/// starts.
pub struct HandshakeStart<E> {
    start: Option<(E, MessageLimits)>,
}

impl<E> HandshakeStart<E> {
    /// The handshake of the engine whose start state is `engine`; a server
    /// reads its first ClientHello within `first_client_hello_limits`,
    /// unless the connection is made with a first flight read before.
    pub fn new(engine: E, first_client_hello_limits: MessageLimits) -> Self {
        Self {
            start: Some((engine, first_client_hello_limits)),
        }
    }

    /// The start state and the limits, the first time they are asked for.
    pub(crate) fn take(&mut self) -> Option<(E, MessageLimits)> {
        self.start.take()
    }
}

impl<E> fmt::Debug for HandshakeStart<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandshakeStart")
            .field("taken", &self.start.is_none())
            .finish_non_exhaustive()
    }
}

/// What the advancing call yields when the established layer can be built:
/// the peer's transport parameters are known, and this side's are sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EstablishedLayerReady;

/// It asks for the established layer.
impl<K, Lk: Link> From<EstablishedLayerReady> for StructureRequest<K, Lk> {
    fn from(EstablishedLayerReady: EstablishedLayerReady) -> Self {
        StructureRequest::AddEstablished {
            args: EstablishedArgs {},
        }
    }
}

// ---- the exporter ----

/// The exporter of the connection's handshake, `X`, as the connection node
/// keeps it: shared, so that whoever lets the application export keeps a
/// clone; the connection's own goes once the connection closes.
pub enum ConnectionExporter<X> {
    /// The handshake has not completed.
    NotYet,
    /// The handshake completed with this exporter.
    Held(Arc<X>),
    /// The connection closed: it let its exporter go.
    Released,
}

impl<X> ConnectionExporter<X> {
    /// The exporter, from the handshake's completion until the connection
    /// closes.
    pub fn exporter(&self) -> Option<&Arc<X>> {
        match self {
            Self::Held(exporter) => Some(exporter),
            Self::NotYet | Self::Released => None,
        }
    }

    /// The handshake completed with `exporter`; a connection that closed
    /// already lets it go at once.
    fn hold(&mut self, exporter: X) {
        if matches!(self, Self::NotYet) {
            *self = Self::Held(Arc::new(exporter));
        }
    }
}

impl<X> fmt::Debug for ConnectionExporter<X> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotYet => "NotYet",
            Self::Held(_) => "Held(..)",
            Self::Released => "Released",
        })
    }
}

/// No handshake has completed when the connection is made.
impl<T: Choices, L, X> Build<T, L, layer::Connection, ()> for ConnectionExporter<X>
where
    L: LineagePartList<T>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        _: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        Self::NotYet
    }
}

/// The exporter reads the record of why the connection closed: once it is
/// written, the connection lets its exporter go, and only the clones given
/// out keep it.
impl<T: Choices, L, X: 'static, I, Ic> DataComponent<T, L, layer::Connection, (I, Ic)>
    for ConnectionExporter<X>
where
    L: LineagePartList<T> + ConnectionErrorsOf,
    for<'v> <L as LineageLists<'v, T>>::Connection:
        GetAt<Self, I> + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>,
{
    fn reads(reads: &mut ReadSet) {
        reads.add::<CloseReasonRecord<CloseCauseOf<T, L>>>();
    }
    fn reread<'v, B: CallBundle>(
        mut lineage: LineageOf<'v, T, L, layer::Connection>,
        _: &mut OtherNodes<'v, T, L, B>,
        _: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let written = lineage
            .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
            .is_written();
        if written && !matches!(lineage.get::<Self, I>(), Self::Released) {
            *lineage.get_mut::<Self, I>() = Self::Released;
        }
        None
    }
}

// ---- the capabilities ----

/// What a server's advancing call does with its view besides what the
/// engine `E` does: install what each step returns, and close.
pub trait ServerAdvancingCapability<E: ServerHandshakeSteps>:
    ServerHandshakeCapability<E::Target>
{
    /// Install the Handshake keys, derived from `secrets` for `aead`.
    fn install_handshake<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        aead: AeadAlgorithm,
        secrets: HandshakeTrafficSecrets,
    ) where
        Self: 'v;

    /// Install the 1-RTT keys to send with, derived from `secret` for
    /// `aead`.
    fn install_one_rtt_send<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        aead: AeadAlgorithm,
        secret: OneRttSendTrafficSecret,
    ) where
        Self: 'v;

    /// The handshake completed: install the 1-RTT keys to receive with,
    /// confirm the handshake, make HANDSHAKE_DONE due and keep the
    /// exporter.
    fn complete<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        completed: ServerHandshakeCompleted<E::Crypto, E::Target>,
    ) where
        Self: 'v;

    /// The handshake failed with `error`: write it into the record of why
    /// the connection closed.
    fn close<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        error: HandshakeError<E::AlertError, <Self as ServerTransport<E::Target>>::Error>,
    ) where
        Self: 'v;
}

/// What a client's advancing call does with its view besides what the
/// engine `E` does: install what each step returns, and close.
pub trait ClientAdvancingCapability<E: ClientHandshakeSteps>: ClientHandshakeCapability {
    /// Install the Handshake keys, derived from `secrets` for `aead`.
    fn install_handshake<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        aead: AeadAlgorithm,
        secrets: HandshakeTrafficSecrets,
    ) where
        Self: 'v;

    /// The handshake completed: install the 1-RTT keys, derived from the
    /// secrets of `completed` for `aead`, and keep the exporter.
    fn complete<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        aead: AeadAlgorithm,
        completed: ClientHandshakeCompleted<E::Crypto>,
    ) where
        Self: 'v;

    /// The handshake failed with `error`: write it into the record of why
    /// the connection closed.
    fn close<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        error: HandshakeError<E::AlertError, <Self as ClientTransport>::Error>,
    ) where
        Self: 'v;
}

// ---- the calls ----

/// The value of a step's result, or, when the step failed, the error
/// written through `close` and the call's end.
macro_rules! step {
    ($host:ident, $close:path, $result:expr) => {
        match $result {
            Ok(value) => value,
            Err(error) => {
                $host.with(|mut view| $close(view.as_pin(), error));
                return;
            }
        }
    };
}

/// A server's advancing call; what it does is in the
/// [module documentation](self). `first` is the first ClientHello when it
/// was read with the first flight; otherwise the call reads it within
/// `limits`.
#[call(yields = EstablishedLayerReady)]
pub async fn server_advancing<W, E>(
    host: &mut impl LentAccess<Family = W>,
    tls: E,
    first: Option<FirstClientHello>,
    limits: MessageLimits,
) where
    E: ServerHandshakeSteps,
    W: ServerAdvancingCapability<E>,
{
    let first = match first {
        Some(first) => first,
        None => step!(
            host,
            W::close,
            read_first_client_hello(host, limits)
                .await
                .map_err(|error| error.map(Into::into, W::convert_read_error))
        ),
    };
    let (written, state) = step!(host, W::close, tls.write_server_hello(first, host).await);
    // this version does not receive 0-RTT: a secret for it is dropped
    let ServerHelloWritten { aead, secrets, .. } = written;
    host.with(|mut view| W::install_handshake(view.as_pin(), aead, secrets));
    yield EstablishedLayerReady;
    let (send, state) = step!(host, W::close, E::write_server_finished(state, host).await);
    host.with(|mut view| W::install_one_rtt_send(view.as_pin(), aead, send));
    let (completed, state) = step!(host, W::close, E::read_client_finished(state, host).await);
    host.with(|mut view| W::complete(view.as_pin(), completed));
    step!(host, W::close, E::write_tickets(state, host).await);
}

/// A client's advancing call; what it does is in the
/// [module documentation](self).
#[call(yields = EstablishedLayerReady)]
pub async fn client_advancing<W, E>(host: &mut impl LentAccess<Family = W>, tls: E)
where
    E: ClientHandshakeSteps,
    W: ClientAdvancingCapability<E>,
{
    // this version does not send 0-RTT: what an offer gives is dropped
    let (_, state) = step!(host, W::close, tls.write_client_hello(host).await);
    let (read, state) = step!(host, W::close, E::read_server_hello(state, host).await);
    let aead = read.aead;
    host.with(|mut view| W::install_handshake(view.as_pin(), aead, read.secrets));
    let (completed, state) = step!(host, W::close, E::read_server_finished(state, host).await);
    host.with(|mut view| W::complete(view.as_pin(), aead, completed));
    yield EstablishedLayerReady;
    // the tickets are read until the connection ends: the step only fails
    let _: Infallible = step!(host, W::close, E::read_tickets(state, host).await);
}

// ---- the CRYPTO data, for both sides ----

/// Takes its CRYPTO positions from the positions `H` of a kind of
/// advancing call.
type CryptoPositions<Icr, Ics, Iv> = (Icr, Ics, Iv);

macro_rules! crypto_capabilities {
    ($kind:ident) => {
        /// The engine reads the CRYPTO data of the connection node's
        /// receiver; reading never fails.
        impl<T, L, Tls, B, Icr, Ics, Iv, Hx> Read
            for NodeCallFamily<T, L, Connection, $kind<Tls>, (CryptoPositions<Icr, Ics, Iv>, Hx), B>
        where
            T: Choices,
            L: LineagePartList<T> + ConnectionErrorsOf,
            B: CallBundle,
            for<'x> <L as LineageLists<'x, T>>::Connection:
                GetAt<CryptoReceiver<T::CryptoReceiveBuffer>, Icr>,
        {
            type Error = ConnectionErrorOf<L>;

            fn poll_read<'v, Output: BufMut + ?Sized>(
                host: Pin<&mut Self::ReceiverView<'v>>,
                cx: &mut Context<'_>,
                destination: &mut Output,
            ) -> Poll<Result<usize, Self::Error>>
            where
                Self: 'v,
            {
                host.get_mut()
                    .lineage
                    .get_mut::<CryptoReceiver<T::CryptoReceiveBuffer>, Icr>()
                    .poll_read(cx, destination)
                    .map(Ok)
            }
        }

        /// The engine moves the level of the connection node's receiver;
        /// a move that breaks a rule is a connection error of version 1.
        impl<T, L, Tls, B, Icr, Ics, Iv, Hx> CryptoInput
            for NodeCallFamily<T, L, Connection, $kind<Tls>, (CryptoPositions<Icr, Ics, Iv>, Hx), B>
        where
            T: Choices,
            L: LineagePartList<T> + ConnectionErrorsOf,
            B: CallBundle,
            <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<ConnectionError, Iv>,
            for<'x> <L as LineageLists<'x, T>>::Connection:
                GetAt<CryptoReceiver<T::CryptoReceiveBuffer>, Icr>,
        {
            type LevelError = ConnectionErrorOf<L>;

            fn move_input_to<'v>(
                view: Pin<&mut Self::ReceiverView<'v>>,
                level: CryptoLevel,
            ) -> Result<(), Self::LevelError>
            where
                Self: 'v,
            {
                view.get_mut()
                    .lineage
                    .get_mut::<CryptoReceiver<T::CryptoReceiveBuffer>, Icr>()
                    .move_input_to(level)
                    .map_err(|source| {
                        v1_error::<L, Iv>(ConnectionError::CryptoLevelMove { source })
                    })
            }
        }

        /// The engine writes into the connection node's sender; writing
        /// never waits, and data past the largest offset is a connection
        /// error of version 1.
        impl<T, L, Tls, B, Icr, Ics, Iv, Hx> Write
            for NodeCallFamily<T, L, Connection, $kind<Tls>, (CryptoPositions<Icr, Ics, Iv>, Hx), B>
        where
            T: Choices,
            L: LineagePartList<T> + ConnectionErrorsOf,
            B: CallBundle,
            <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<ConnectionError, Iv>,
            for<'x> <L as LineageLists<'x, T>>::Connection:
                GetAt<CryptoSender<T::CryptoSendBuffer>, Ics>,
        {
            type Error = ConnectionErrorOf<L>;

            fn poll_write<'v, Input: Buf + ?Sized>(
                host: Pin<&mut Self::ReceiverView<'v>>,
                _: &mut Context<'_>,
                input: &mut Input,
            ) -> Poll<Result<usize, Self::Error>>
            where
                Self: 'v,
            {
                Poll::Ready(
                    host.get_mut()
                        .lineage
                        .get_mut::<CryptoSender<T::CryptoSendBuffer>, Ics>()
                        .write_from(input)
                        .map_err(|source| {
                            v1_error::<L, Iv>(ConnectionError::CryptoDataEnd { source })
                        }),
                )
            }
        }

        /// The engine moves the level of the connection node's sender.
        impl<T, L, Tls, B, Icr, Ics, Iv, Hx> CryptoOutput
            for NodeCallFamily<T, L, Connection, $kind<Tls>, (CryptoPositions<Icr, Ics, Iv>, Hx), B>
        where
            T: Choices,
            L: LineagePartList<T> + ConnectionErrorsOf,
            B: CallBundle,
            <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<ConnectionError, Iv>,
            for<'x> <L as LineageLists<'x, T>>::Connection:
                GetAt<CryptoSender<T::CryptoSendBuffer>, Ics>,
        {
            fn move_output_to<'v>(view: Pin<&mut Self::ReceiverView<'v>>, level: CryptoLevel)
            where
                Self: 'v,
            {
                view.get_mut()
                    .lineage
                    .get_mut::<CryptoSender<T::CryptoSendBuffer>, Ics>()
                    .move_output_to(level);
            }
        }
    };
}
crypto_capabilities!(ServerAdvancingKind);
crypto_capabilities!(ClientAdvancingKind);

// ---- the transport parameters ----

/// The peer's transport parameters `peer`, sent by an endpoint in the role
/// `sender`, read into the slots of the parts `L`.
///
/// # Errors
///
/// They could not be read: version 1's error, or for the value of a
/// parameter of another part, that part's.
fn read_peer<L, Iv>(
    peer: &[u8],
    sender: Role,
) -> Result<TransportParameterSlots<L>, ConnectionErrorOf<L>>
where
    L: TransportParameterValueErrorsOf,
    L::ConnectionErrors: CoprodInjector<ConnectionError, Iv>,
{
    let mut source = peer;
    source
        .sync_read_transport_parameters_unpin(sender, PhantomData::<L>)
        .map(|parameters| parameters.known)
        .map_err(read_transport_parameters_error::<L, Iv>)
}

/// The transport parameters of version 1 a server sends, from those
/// configured: its first connection ID as `initial_source_connection_id`,
/// the client's first Destination Connection ID as
/// `original_destination_connection_id` and, after a Retry, the Retry's
/// Source Connection ID as `retry_source_connection_id` (RFC 9000 §7.3);
/// the stateless reset token of its first connection ID, and, for a
/// zero-length one, neither a token nor a preferred address (§18.2).
fn server_parameters(
    configured: &TransportParameterSlots,
    local: FirstLocalConnectionId,
    destination: InitialDestinationConnectionIds,
) -> TransportParameterSlots {
    let mut parameters = TransportParameters::<Bytes>::new();
    parameters.known = *configured;
    *parameters.slot_mut::<InitialSourceConnectionId, _>() =
        Some(InitialSourceConnectionId::new(local.id()));
    *parameters.slot_mut::<OriginalDestinationConnectionId, _>() =
        Some(OriginalDestinationConnectionId::new(destination.original()));
    *parameters.slot_mut::<RetrySourceConnectionId, _>() =
        destination.retry_source().map(RetrySourceConnectionId::new);
    match local.reset_token() {
        Some(token) => {
            *parameters.slot_mut::<StatelessResetToken, _>() =
                Some(StatelessResetToken::new(token));
        }
        None => {
            *parameters.slot_mut::<StatelessResetToken, _>() = None;
            *parameters.slot_mut::<PreferredAddress, _>() = None;
        }
    }
    parameters.known
}

/// The transport parameters of version 1 a client sends, from those
/// configured: its first connection ID as `initial_source_connection_id`
/// (RFC 9000 §7.3), and none of those only a server sends (§18.2).
fn client_parameters(
    configured: &TransportParameterSlots,
    local: FirstLocalConnectionId,
) -> TransportParameterSlots {
    let mut parameters = TransportParameters::<Bytes>::new();
    parameters.known = *configured;
    *parameters.slot_mut::<InitialSourceConnectionId, _>() =
        Some(InitialSourceConnectionId::new(local.id()));
    *parameters.slot_mut::<OriginalDestinationConnectionId, _>() = None;
    *parameters.slot_mut::<RetrySourceConnectionId, _>() = None;
    *parameters.slot_mut::<StatelessResetToken, _>() = None;
    *parameters.slot_mut::<PreferredAddress, _>() = None;
    parameters.known
}

/// `slots` as an endpoint in the role `sender` sends them.
fn encode(slots: &TransportParameterSlots, sender: Role) -> OpaqueData<Bytes> {
    let mut parameters = TransportParameters::<Bytes>::new();
    parameters.known = *slots;
    let mut encoded = Vec::new();
    // invariant: the slots hold only parameters the sender may send, as
    // `server_parameters` and `client_parameters` make them, and no unknown
    // ones, so they are valid; a vector takes every byte
    encoded
        .sync_write_transport_parameters_unpin(parameters, sender)
        .expect("the parameters a side settles are valid");
    // invariant: the parameters of version 1 alone are far below 2^16 bytes
    OpaqueData::new(Bytes::from(encoded)).expect("transport parameters fit their extension")
}

/// The parameters this side sends, settled from those configured with
/// `settle` the first time; as sent afterwards, as a ClientHello written
/// again after a HelloRetryRequest sends them (RFC 9846 §4.1.2).
fn send_local(
    local: &mut LocalTransportParameters<TransportParameterSlots>,
    settle: impl FnOnce(&TransportParameterSlots) -> TransportParameterSlots,
) -> &TransportParameterSlots {
    if local.sent().is_none() {
        local.send_with(settle);
    }
    // invariant: sent just above when it was not
    local.sent().expect("the parameters are sent")
}

// ---- the server ----

/// The positions a server's advancing call takes by, besides those of the
/// CRYPTO data: in the connection node, `Ilt` of this side's transport
/// parameters, `Ipt` of the peer's, `Ifl` of the first local connection ID,
/// `Iid` of the client's first Destination Connection IDs, `Iph` of the
/// peer's handshake connection ID, `Ik` of the Handshake keys, `Io` of the
/// 1-RTT keys, `Ib` of the backend, `Ic` of the confirmation, `Ihd` of the
/// HANDSHAKE_DONE source, `Isc` of the core of the send strategy, `Ie` of
/// the exporter and `Irc` of the record of why the connection closed;
/// `Idx` of HANDSHAKE_DONE's intent among the composition's, `Ja` of
/// `initial_source_connection_id` among the slots of the peer's transport
/// parameters, and `Ia` of what the call is started from in the facts of
/// the connection node.
type ServerPositions<Ilt, Ipt, Ifl, Iid, Iph, Ik, Io, Ib, Ic, Ihd, Isc, Ie, Irc, Idx, Ja, Ia> = (
    (Ilt, Ipt, Ifl, Iid, Iph),
    (Ik, Io, Ib, Ic),
    (Ihd, Isc, Ie, Irc),
    (Idx, Ja, Ia),
);

/// The server's side of the transport parameters: the client's are read
/// and checked, and this side's are settled and sent.
///
/// The client's `initial_source_connection_id` must state the Source
/// Connection ID of its first Initial packet that opened (RFC 9000 §7.3);
/// a parameter only a server may send is a failure of reading. Once they
/// pass, the client's parameters are known. This version accepts no 0-RTT.
impl<
    T,
    L,
    Tls,
    B,
    Target,
    Icr,
    Ics,
    Iv,
    Ilt,
    Ipt,
    Ifl,
    Iid,
    Iph,
    Ik,
    Io,
    Ib,
    Ic,
    Ihd,
    Isc,
    Ie,
    Irc,
    Idx,
    Ja,
    Ia,
> ServerTransport<Target>
    for NodeCallFamily<
        T,
        L,
        Connection,
        ServerAdvancingKind<Tls>,
        (
            CryptoPositions<Icr, Ics, Iv>,
            ServerPositions<
                Ilt,
                Ipt,
                Ifl,
                Iid,
                Iph,
                Ik,
                Io,
                Ib,
                Ic,
                Ihd,
                Isc,
                Ie,
                Irc,
                Idx,
                Ja,
                Ia,
            >,
        ),
        B,
    >
where
    T: Choices,
    L: LineagePartList<T> + TransportParameterValueErrorsOf,
    B: CallBundle,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<ConnectionError, Iv>,
    TransportParameterSlots<L>: Selector<Option<InitialSourceConnectionId>, Ja>,
    for<'x> <L as LineageLists<'x, T>>::Connection: GetAt<LocalTransportParameters<TransportParameterSlots>, Ilt>
        + GetAt<PeerTransportParameters<TransportParameterSlots<L>>, Ipt>
        + GetAt<FirstLocalConnectionId, Ifl>
        + GetAt<InitialDestinationConnectionIds, Iid>
        + GetAt<PeerHandshakeConnectionId, Iph>,
{
    type Error = ConnectionErrorOf<L>;

    fn negotiate<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        peer: &[u8],
        _: &SelectedTarget<Target>,
        _: Option<&TicketState<Target>>,
    ) -> Result<Negotiated, Self::Error>
    where
        Self: 'v,
    {
        let NodeLoan { lineage, .. } = view.get_mut();
        let chosen = lineage.get::<PeerHandshakeConnectionId, Iph>().get();
        let slots = read_peer::<L, Iv>(peer, Role::Client)?;
        check_initial_source::<_, Ja>(&slots, chosen).map_err(|source| {
            v1_error::<L, Iv>(ConnectionError::PeerTransportParameters { source })
        })?;
        lineage
            .get_mut::<PeerTransportParameters<TransportParameterSlots<L>>, Ipt>()
            .set_known(slots);
        let first = *lineage.get::<FirstLocalConnectionId, Ifl>();
        let destination = *lineage.get::<InitialDestinationConnectionIds, Iid>();
        let local = lineage.get_mut::<LocalTransportParameters<TransportParameterSlots>, Ilt>();
        let sent = send_local(local, |configured| {
            server_parameters(configured, first, destination)
        });
        Ok(Negotiated {
            local: encode(sent, Role::Server),
            early_data: false,
        })
    }
}

impl<
    T,
    L,
    Tls,
    B,
    Icr,
    Ics,
    Iv,
    Ilt,
    Ipt,
    Ifl,
    Iid,
    Iph,
    Ik,
    Io,
    Ib,
    Ic,
    Ihd,
    Isc,
    Ie,
    Irc,
    Idx,
    Ja,
    Ia,
> ServerAdvancingCapability<Tls>
    for NodeCallFamily<
        T,
        L,
        Connection,
        ServerAdvancingKind<Tls>,
        (
            CryptoPositions<Icr, Ics, Iv>,
            ServerPositions<
                Ilt,
                Ipt,
                Ifl,
                Iid,
                Iph,
                Ik,
                Io,
                Ib,
                Ic,
                Ihd,
                Isc,
                Ie,
                Irc,
                Idx,
                Ja,
                Ia,
            >,
        ),
        B,
    >
where
    T: Choices<Side = Server<Tls>>,
    Tls: ServerHandshakeSteps + 'static,
    Tls::AlertError: 'static,
    L: LineagePartList<T> + TransportParameterValueErrorsOf,
    B: CallBundle,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<ConnectionError, Iv>,
    TransportParameterSlots<L>: Selector<Option<InitialSourceConnectionId>, Ja>,
    SendTypes<T, L>: SendStrategyTypes,
    SendStrategyCore<SendStrategyOf<T, L>>: PublishIntent<HandshakeDoneIntent, Idx>,
    for<'x> <L as LineageLists<'x, T>>::Connection: GetAt<CryptoReceiver<T::CryptoReceiveBuffer>, Icr>
        + GetAt<CryptoSender<T::CryptoSendBuffer>, Ics>
        + GetAt<LocalTransportParameters<TransportParameterSlots>, Ilt>
        + GetAt<PeerTransportParameters<TransportParameterSlots<L>>, Ipt>
        + GetAt<FirstLocalConnectionId, Ifl>
        + GetAt<InitialDestinationConnectionIds, Iid>
        + GetAt<PeerHandshakeConnectionId, Iph>
        + GetAt<HandshakeKeys<T::Crypto>, Ik>
        + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>
        + GetAt<PacketProtectionBackend<T::Crypto>, Ib>
        + GetAt<HandshakeConfirmation, Ic>
        + GetAt<HandshakeDoneSource, Ihd>
        + GetAt<SendStrategyCore<SendStrategyOf<T, L>>, Isc>
        + GetAt<ConnectionExporter<Exporter<Tls::Crypto>>, Ie>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Irc>,
{
    fn install_handshake<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        aead: AeadAlgorithm,
        secrets: HandshakeTrafficSecrets,
    ) where
        Self: 'v,
    {
        let lineage = &mut view.get_mut().lineage;
        let backend = lineage
            .get::<PacketProtectionBackend<T::Crypto>, Ib>()
            .0
            .clone();
        lineage
            .get_mut::<HandshakeKeys<T::Crypto>, Ik>()
            .install(level_keys(&backend, aead, &secrets));
    }

    fn install_one_rtt_send<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        aead: AeadAlgorithm,
        secret: OneRttSendTrafficSecret,
    ) where
        Self: 'v,
    {
        let lineage = &mut view.get_mut().lineage;
        let backend = lineage
            .get::<PacketProtectionBackend<T::Crypto>, Ib>()
            .0
            .clone();
        lineage
            .get_mut::<OneRttKeys<T::Crypto, InstantOf<T>>, Io>()
            .install_send(backend, aead, secret.0);
    }

    fn complete<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        completed: ServerHandshakeCompleted<Tls::Crypto, Tls::Target>,
    ) where
        Self: 'v,
    {
        let lineage = &mut view.get_mut().lineage;
        let ServerHandshakeCompleted {
            one_rtt_receive,
            exporter,
            ..
        } = completed;
        lineage
            .get_mut::<OneRttKeys<T::Crypto, InstantOf<T>>, Io>()
            .install_receive(one_rtt_receive.0);
        // a server's handshake is confirmed when it completes (RFC 9001
        // §4.1.2); its Handshake keys go with the confirmation
        *lineage.get_mut::<HandshakeConfirmation, Ic>() = HandshakeConfirmation::Confirmed;
        let mut source = *lineage.get::<HandshakeDoneSource, Ihd>();
        source.due::<_, Idx>(lineage.get_mut::<SendStrategyCore<SendStrategyOf<T, L>>, Isc>());
        *lineage.get_mut::<HandshakeDoneSource, Ihd>() = source;
        lineage
            .get_mut::<ConnectionExporter<Exporter<Tls::Crypto>>, Ie>()
            .hold(exporter);
    }

    fn close<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        error: HandshakeError<Tls::AlertError, ConnectionErrorOf<L>>,
    ) where
        Self: 'v,
    {
        view.get_mut()
            .lineage
            .get_mut::<CloseReasonRecord<CloseCauseOf<T, L>>, Irc>()
            .record(CloseReason::Local(Arc::new(LocalCloseCause::Handshake(
                error,
            ))));
    }
}

/// The Handshake keys, both directions derived with `backend` from
/// `secrets` for `aead`.
fn level_keys<C: sakuya_packet_protection::backend::CryptoBackend>(
    backend: &C,
    aead: AeadAlgorithm,
    secrets: &HandshakeTrafficSecrets,
) -> LevelKeys<C> {
    LevelKeys {
        send: DirectionKeys::derive(backend, aead, &secrets.send),
        receive: DirectionKeys::derive(backend, aead, &secrets.receive),
    }
}

/// The kind of a server's advancing call, whose engine starts as `Tls`. It
/// reads the record of why the connection closed: once it is written, the
/// call is not needed any more.
pub struct ServerAdvancingKind<Tls>(PhantomData<fn() -> Tls>);

impl<Tls> fmt::Debug for ServerAdvancingKind<Tls> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServerAdvancingKind")
    }
}

impl<
    T,
    L,
    Tls,
    Icr,
    Ics,
    Iv,
    Ilt,
    Ipt,
    Ifl,
    Iid,
    Iph,
    Ik,
    Io,
    Ib,
    Ic,
    Ihd,
    Isc,
    Ie,
    Irc,
    Idx,
    Ja,
    Ia,
>
    CallKind<
        T,
        L,
        Connection,
        (
            CryptoPositions<Icr, Ics, Iv>,
            ServerPositions<
                Ilt,
                Ipt,
                Ifl,
                Iid,
                Iph,
                Ik,
                Io,
                Ib,
                Ic,
                Ihd,
                Isc,
                Ie,
                Irc,
                Idx,
                Ja,
                Ia,
            >,
        ),
    > for ServerAdvancingKind<Tls>
where
    T: Choices<Side = Server<Tls>>,
    Tls: ServerHandshakeSteps + 'static,
    Tls::AlertError: 'static,
    L: LineagePartList<T> + TransportParameterValueErrorsOf,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<ConnectionError, Iv>,
    TransportParameterSlots<L>: Selector<Option<InitialSourceConnectionId>, Ja>,
    SendTypes<T, L>: SendStrategyTypes,
    SendStrategyCore<SendStrategyOf<T, L>>: PublishIntent<HandshakeDoneIntent, Idx>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, Ia>,
    for<'x> <L as LineageLists<'x, T>>::Connection: GetAt<CryptoReceiver<T::CryptoReceiveBuffer>, Icr>
        + GetAt<CryptoSender<T::CryptoSendBuffer>, Ics>
        + GetAt<LocalTransportParameters<TransportParameterSlots>, Ilt>
        + GetAt<PeerTransportParameters<TransportParameterSlots<L>>, Ipt>
        + GetAt<FirstLocalConnectionId, Ifl>
        + GetAt<InitialDestinationConnectionIds, Iid>
        + GetAt<PeerHandshakeConnectionId, Iph>
        + GetAt<HandshakeKeys<T::Crypto>, Ik>
        + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>
        + GetAt<PacketProtectionBackend<T::Crypto>, Ib>
        + GetAt<HandshakeConfirmation, Ic>
        + GetAt<HandshakeDoneSource, Ihd>
        + GetAt<SendStrategyCore<SendStrategyOf<T, L>>, Isc>
        + GetAt<ConnectionExporter<Exporter<Tls::Crypto>>, Ie>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Irc>,
    (
        CryptoPositions<Icr, Ics, Iv>,
        ServerPositions<Ilt, Ipt, Ifl, Iid, Iph, Ik, Io, Ib, Ic, Ihd, Isc, Ie, Irc, Idx, Ja, Ia>,
    ): 'static,
{
    type Call<B: CallBundle> = LentCall<
        NodeCallFamily<
            T,
            L,
            Connection,
            ServerAdvancingKind<Tls>,
            (
                CryptoPositions<Icr, Ics, Iv>,
                ServerPositions<
                    Ilt,
                    Ipt,
                    Ifl,
                    Iid,
                    Iph,
                    Ik,
                    Io,
                    Ib,
                    Ic,
                    Ihd,
                    Isc,
                    Ie,
                    Irc,
                    Idx,
                    Ja,
                    Ia,
                >,
            ),
            B,
        >,
        ServerAdvancing<Tls>,
    >;
    fn start<B: CallBundle>(args: &mut ArgsOf<T, L, Connection>) -> Self::Call<B> {
        let args = Selector::<ConnectionArgs<T, L>, Ia>::get_mut(args);
        // invariant: the connection node is built once, and only this call
        // takes the start
        let (engine, limits) = args
            .handshake
            .take()
            .expect("the advancing call starts once");
        let first = args.first_flight.take_first_client_hello();
        LentCall::new(ServerAdvancing::new(engine, first, limits))
    }
    fn reads(reads: &mut ReadSet) {
        reads.add::<CloseReasonRecord<CloseCauseOf<T, L>>>();
    }
    fn no_longer_needed<'v>(lineage: &LineageOf<'v, T, L, Connection>) -> bool {
        lineage
            .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Irc>()
            .is_written()
    }
}

// ---- the client ----

/// The positions a client's advancing call takes by, besides those of the
/// CRYPTO data: as a server's, without those of HANDSHAKE_DONE; with `Jo`
/// of `original_destination_connection_id` and `Jr` of
/// `retry_source_connection_id` among the slots of the peer's transport
/// parameters.
type ClientPositions<Ilt, Ipt, Ifl, Iid, Iph, Ik, Io, Ib, Ie, Irc, Ja, Jo, Jr, Ia> = (
    (Ilt, Ipt, Ifl, Iid, Iph),
    (Ik, Io, Ib),
    (Ie, Irc),
    (Ja, Jo, Jr, Ia),
);

/// The client's side of the transport parameters: this side's are settled
/// and sent, and the server's are read and checked.
///
/// The server's `original_destination_connection_id` must state the
/// Destination Connection ID of the client's first Initial packet, its
/// `initial_source_connection_id` the Source Connection ID of its first
/// Initial packet that opened, and without a Retry it must send no
/// `retry_source_connection_id` (RFC 9000 §7.3). Once they pass, the
/// server's parameters are known.
impl<T, L, Tls, B, Icr, Ics, Iv, Ilt, Ipt, Ifl, Iid, Iph, Ik, Io, Ib, Ie, Irc, Ja, Jo, Jr, Ia>
    ClientTransport
    for NodeCallFamily<
        T,
        L,
        Connection,
        ClientAdvancingKind<Tls>,
        (
            CryptoPositions<Icr, Ics, Iv>,
            ClientPositions<Ilt, Ipt, Ifl, Iid, Iph, Ik, Io, Ib, Ie, Irc, Ja, Jo, Jr, Ia>,
        ),
        B,
    >
where
    T: Choices,
    L: LineagePartList<T> + TransportParameterValueErrorsOf,
    B: CallBundle,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<ConnectionError, Iv>,
    TransportParameterSlots<L>: Selector<Option<InitialSourceConnectionId>, Ja>
        + Selector<Option<OriginalDestinationConnectionId>, Jo>
        + Selector<Option<RetrySourceConnectionId>, Jr>,
    for<'x> <L as LineageLists<'x, T>>::Connection: GetAt<LocalTransportParameters<TransportParameterSlots>, Ilt>
        + GetAt<PeerTransportParameters<TransportParameterSlots<L>>, Ipt>
        + GetAt<FirstLocalConnectionId, Ifl>
        + GetAt<InitialDestinationConnectionIds, Iid>
        + GetAt<PeerHandshakeConnectionId, Iph>,
{
    type Error = ConnectionErrorOf<L>;

    fn local<'v>(view: Pin<&mut Self::ReceiverView<'v>>) -> OpaqueData<Bytes>
    where
        Self: 'v,
    {
        let lineage = &mut view.get_mut().lineage;
        let first = *lineage.get::<FirstLocalConnectionId, Ifl>();
        let local = lineage.get_mut::<LocalTransportParameters<TransportParameterSlots>, Ilt>();
        encode(
            send_local(local, |configured| client_parameters(configured, first)),
            Role::Client,
        )
    }

    fn peer<'v>(view: Pin<&mut Self::ReceiverView<'v>>, peer: &[u8]) -> Result<(), Self::Error>
    where
        Self: 'v,
    {
        let lineage = &mut view.get_mut().lineage;
        let chosen = lineage.get::<PeerHandshakeConnectionId, Iph>().get();
        let original = lineage
            .get::<InitialDestinationConnectionIds, Iid>()
            .original();
        let slots = read_peer::<L, Iv>(peer, Role::Server)?;
        check_server_destination::<_, Jo, Jr>(&slots, original)
            .and_then(|()| check_initial_source::<_, Ja>(&slots, chosen))
            .map_err(|source| {
                v1_error::<L, Iv>(ConnectionError::PeerTransportParameters { source })
            })?;
        lineage
            .get_mut::<PeerTransportParameters<TransportParameterSlots<L>>, Ipt>()
            .set_known(slots);
        Ok(())
    }
}

impl<T, L, Tls, B, Icr, Ics, Iv, Ilt, Ipt, Ifl, Iid, Iph, Ik, Io, Ib, Ie, Irc, Ja, Jo, Jr, Ia>
    ClientAdvancingCapability<Tls>
    for NodeCallFamily<
        T,
        L,
        Connection,
        ClientAdvancingKind<Tls>,
        (
            CryptoPositions<Icr, Ics, Iv>,
            ClientPositions<Ilt, Ipt, Ifl, Iid, Iph, Ik, Io, Ib, Ie, Irc, Ja, Jo, Jr, Ia>,
        ),
        B,
    >
where
    T: Choices<Side = Client<Tls>>,
    Tls: ClientHandshakeSteps + 'static,
    Tls::AlertError: 'static,
    L: LineagePartList<T> + TransportParameterValueErrorsOf,
    B: CallBundle,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<ConnectionError, Iv>,
    TransportParameterSlots<L>: Selector<Option<InitialSourceConnectionId>, Ja>
        + Selector<Option<OriginalDestinationConnectionId>, Jo>
        + Selector<Option<RetrySourceConnectionId>, Jr>,
    for<'x> <L as LineageLists<'x, T>>::Connection: GetAt<CryptoReceiver<T::CryptoReceiveBuffer>, Icr>
        + GetAt<CryptoSender<T::CryptoSendBuffer>, Ics>
        + GetAt<LocalTransportParameters<TransportParameterSlots>, Ilt>
        + GetAt<PeerTransportParameters<TransportParameterSlots<L>>, Ipt>
        + GetAt<FirstLocalConnectionId, Ifl>
        + GetAt<InitialDestinationConnectionIds, Iid>
        + GetAt<PeerHandshakeConnectionId, Iph>
        + GetAt<HandshakeKeys<T::Crypto>, Ik>
        + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>
        + GetAt<PacketProtectionBackend<T::Crypto>, Ib>
        + GetAt<ConnectionExporter<Exporter<Tls::Crypto>>, Ie>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Irc>,
{
    fn install_handshake<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        aead: AeadAlgorithm,
        secrets: HandshakeTrafficSecrets,
    ) where
        Self: 'v,
    {
        let lineage = &mut view.get_mut().lineage;
        let backend = lineage
            .get::<PacketProtectionBackend<T::Crypto>, Ib>()
            .0
            .clone();
        lineage
            .get_mut::<HandshakeKeys<T::Crypto>, Ik>()
            .install(level_keys(&backend, aead, &secrets));
    }

    fn complete<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        aead: AeadAlgorithm,
        completed: ClientHandshakeCompleted<Tls::Crypto>,
    ) where
        Self: 'v,
    {
        let lineage = &mut view.get_mut().lineage;
        let ClientHandshakeCompleted {
            secrets, exporter, ..
        } = completed;
        let backend = lineage
            .get::<PacketProtectionBackend<T::Crypto>, Ib>()
            .0
            .clone();
        lineage
            .get_mut::<OneRttKeys<T::Crypto, InstantOf<T>>, Io>()
            .install(backend, aead, secrets.send, secrets.receive);
        lineage
            .get_mut::<ConnectionExporter<Exporter<Tls::Crypto>>, Ie>()
            .hold(exporter);
    }

    fn close<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        error: HandshakeError<Tls::AlertError, ConnectionErrorOf<L>>,
    ) where
        Self: 'v,
    {
        view.get_mut()
            .lineage
            .get_mut::<CloseReasonRecord<CloseCauseOf<T, L>>, Irc>()
            .record(CloseReason::Local(Arc::new(LocalCloseCause::Handshake(
                error,
            ))));
    }
}

/// The kind of a client's advancing call, whose engine starts as `Tls`. It
/// reads the record of why the connection closed: once it is written, the
/// call is not needed any more.
pub struct ClientAdvancingKind<Tls>(PhantomData<fn() -> Tls>);

impl<Tls> fmt::Debug for ClientAdvancingKind<Tls> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientAdvancingKind")
    }
}

impl<T, L, Tls, Icr, Ics, Iv, Ilt, Ipt, Ifl, Iid, Iph, Ik, Io, Ib, Ie, Irc, Ja, Jo, Jr, Ia>
    CallKind<
        T,
        L,
        Connection,
        (
            CryptoPositions<Icr, Ics, Iv>,
            ClientPositions<Ilt, Ipt, Ifl, Iid, Iph, Ik, Io, Ib, Ie, Irc, Ja, Jo, Jr, Ia>,
        ),
    > for ClientAdvancingKind<Tls>
where
    T: Choices<Side = Client<Tls>>,
    Tls: ClientHandshakeSteps + 'static,
    Tls::AlertError: 'static,
    L: LineagePartList<T> + TransportParameterValueErrorsOf,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<ConnectionError, Iv>,
    TransportParameterSlots<L>: Selector<Option<InitialSourceConnectionId>, Ja>
        + Selector<Option<OriginalDestinationConnectionId>, Jo>
        + Selector<Option<RetrySourceConnectionId>, Jr>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, Ia>,
    for<'x> <L as LineageLists<'x, T>>::Connection: GetAt<CryptoReceiver<T::CryptoReceiveBuffer>, Icr>
        + GetAt<CryptoSender<T::CryptoSendBuffer>, Ics>
        + GetAt<LocalTransportParameters<TransportParameterSlots>, Ilt>
        + GetAt<PeerTransportParameters<TransportParameterSlots<L>>, Ipt>
        + GetAt<FirstLocalConnectionId, Ifl>
        + GetAt<InitialDestinationConnectionIds, Iid>
        + GetAt<PeerHandshakeConnectionId, Iph>
        + GetAt<HandshakeKeys<T::Crypto>, Ik>
        + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>
        + GetAt<PacketProtectionBackend<T::Crypto>, Ib>
        + GetAt<ConnectionExporter<Exporter<Tls::Crypto>>, Ie>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Irc>,
    (
        CryptoPositions<Icr, Ics, Iv>,
        ClientPositions<Ilt, Ipt, Ifl, Iid, Iph, Ik, Io, Ib, Ie, Irc, Ja, Jo, Jr, Ia>,
    ): 'static,
{
    type Call<B: CallBundle> = LentCall<
        NodeCallFamily<
            T,
            L,
            Connection,
            ClientAdvancingKind<Tls>,
            (
                CryptoPositions<Icr, Ics, Iv>,
                ClientPositions<Ilt, Ipt, Ifl, Iid, Iph, Ik, Io, Ib, Ie, Irc, Ja, Jo, Jr, Ia>,
            ),
            B,
        >,
        ClientAdvancing<Tls>,
    >;
    fn start<B: CallBundle>(args: &mut ArgsOf<T, L, Connection>) -> Self::Call<B> {
        let args = Selector::<ConnectionArgs<T, L>, Ia>::get_mut(args);
        // invariant: the connection node is built once, and only this call
        // takes the start
        let (engine, _) = args
            .handshake
            .take()
            .expect("the advancing call starts once");
        LentCall::new(ClientAdvancing::new(engine))
    }
    fn reads(reads: &mut ReadSet) {
        reads.add::<CloseReasonRecord<CloseCauseOf<T, L>>>();
    }
    fn no_longer_needed<'v>(lineage: &LineageOf<'v, T, L, Connection>) -> bool {
        lineage
            .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Irc>()
            .is_written()
    }
}
