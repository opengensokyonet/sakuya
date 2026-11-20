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
//!   [`EstablishedLayerChange::Ready`]; once its Finished is written, the 1-RTT
//!   keys to send with; once the client's Finished is verified, the 1-RTT
//!   keys to receive with, and the handshake is complete and confirmed
//!   (RFC 9001 §4.1.1, §4.1.2): the HANDSHAKE_DONE frame is due. It then
//!   writes its session tickets and ends.
//! - A client installs the Handshake keys once the ServerHello is read;
//!   once the server's Finished is verified and its own written, the 1-RTT
//!   keys, and yields [`EstablishedLayerChange::Ready`]. It then reads
//!   session tickets until the connection ends.
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
//! A server receives 0-RTT: when its handshake admits early data, it
//! installs the 0-RTT keys to receive with in the same lend as the
//! Handshake keys, before it yields [`EstablishedLayerChange::Ready`], and
//! otherwise refuses 0-RTT, which drops the 0-RTT packets that wait. Whether
//! its transport parameters admit 0-RTT is decided as they are settled
//! ([`ResumeLocalTransportParameters`]).
//!
//! A client sends 0-RTT when its ClientHello offers it: it installs the
//! 0-RTT keys to send with and the server's remembered transport
//! parameters, and yields [`EstablishedLayerChange::Ready`] at once. When
//! the handshake completes, a server that accepted 0-RTT keeps that
//! layer, once its new parameters are checked against the remembered
//! ones; one that rejected it has the call yield
//! [`EstablishedLayerChange::ZeroRttRejected`], and the layer is built
//! anew on the new parameters, unless the connection closes already. The
//! 0-RTT keys close either way.
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
use nitori_crypto::AeadAlgorithm;
use nitori_io::{Read, Write};
use nitori_tls::{
    client::engine::{
        ClientHandshakeCapability, ClientHandshakeCompleted, ClientHandshakeSteps, ClientTransport,
        EarlyDataOffered, EarlyDataOutcome,
    },
    engine::{CryptoInput, CryptoLevel, CryptoOutput, HandshakeError},
    extension::OpaqueData,
    message::MessageLimits,
    schedule::{
        Exporter, HandshakeTrafficSecrets, OneRttSendTrafficSecret, ZeroRttReceiveTrafficSecret,
    },
    server::{
        engine::{
            FirstClientHello, Negotiated, ServerHandshakeCapability, ServerHandshakeCompleted,
            ServerHandshakeSteps, ServerHelloWritten, ServerTransport, read_first_client_hello,
        },
        targets::SelectedTarget,
        ticket::TicketState,
    },
};
use sakuya_link::Link;
use sakuya_stream_v1::connection::CloseReason;
use sakuya_wire::{
    parameters::ParametersOf,
    parts::{CoprodInjector, Selector},
};
use sakuya_wire_v1::{
    encryption_level::EncryptionLevel,
    role::Role,
    transport_parameters::{
        TransportParameterSlots, TransportParameterSpace, TransportParameters,
        codec::{
            read_remembered_transport_parameters, read_transport_parameters,
            write_transport_parameters,
        },
        connection_id::{
            InitialSourceConnectionId, OriginalDestinationConnectionId, RetrySourceConnectionId,
        },
        preferred_address::PreferredAddress,
        stateless_reset_token::StatelessResetToken,
    },
};

use super::{
    Choices, Client, CloseCauseOf, ConnectionArgs, EventsOf, Server,
    address_token::{AddressTokenSink, ConnectionNewTokenIssuer},
    application_handles::connection::{
        ClientHandshakeFacts, ConnectionHandleStateOf, ServerHandshakeFacts,
    },
    close::{CloseReasonRecord, LocalCloseCause},
    component_events::{CloseReasonWritten, LocalTransportParametersSent, ZeroRttRejected},
    confirmation::HandshakeConfirmation,
    connection_ids::{
        FirstLocalConnectionId, InitialDestinationConnectionIds, PeerHandshakeConnectionId, PeerOf,
    },
    crypto::{CryptoReceiver, send::CryptoSender},
    error::{ConnectionError, V1ConnectionErrorOf},
    events::{
        ConnectionEventSink, ConnectionEvents, ConnectionState, EventInitiator, KeyChange,
        PacketEvents,
    },
    handshake_done::HandshakeDoneSource,
    keys::{
        DirectionKeys, HandshakeKeys, LevelKeys, OneRttKeys, PacketProtectionBackend,
        ZeroRttReceiving, ZeroRttSending,
    },
    new_token::NewTokenSource,
    parameters::{
        AcceptedZeroRttParameters, LocalTransportParameters, PeerTransportParameters,
        ResumeLocalTransportParameters, SendLocalTransportParameters, check_initial_source,
        check_server_destination, read_transport_parameters_error,
    },
    receive::v1_error,
    retry::ClientRetryPolicy,
    send::SendTypes,
    send_planning::{ComponentPublishing, HostSendStrategyTypes},
    streams::send::StreamIntent,
};
use crate::v1::StreamSetFamilyOf;
use crate::v1::{CryptoReceiveBufferOf, CryptoSendBufferOf, SendParametersOf};
use crate::{
    call::{CallBundle, CallKind, NodeCallFamily, NodeLoan},
    clock::InstantOf,
    component::{ArgsOf, Build, DataComponent, LineageOf, ParentsOf, RequestOf},
    component_event::{EventSubscriptions, Happened, TriggeredEvents},
    error::{ConnectionErrorOf, ConnectionErrorsOf, TransportParameterValueErrorsOf},
    layer::{self, Connection, EstablishedArgs, NodeKey},
    others::OtherNodes,
    request::StructureRequest,
    role::LinkPathRole,
    share::{ConnectionArgsOf, FlatMut, LineageLists, LineagePartList, NodeData},
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

/// What the advancing call yields when the established layer is to change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstablishedLayerChange {
    /// The established layer can be built: the peer's transport
    /// parameters are known, or remembered for 0-RTT, and this side's are
    /// sent.
    Ready,
    /// The server rejected the client's 0-RTT: the layer built on the
    /// remembered parameters ends, and one is built on the server's new
    /// parameters (RFC 9001 §4.6.2).
    ZeroRttRejected,
}

/// It asks for the established layer, or for it built anew.
impl<K, Lk: Link> From<EstablishedLayerChange> for StructureRequest<K, Lk> {
    fn from(change: EstablishedLayerChange) -> Self {
        let args = EstablishedArgs {};
        match change {
            EstablishedLayerChange::Ready => StructureRequest::AddEstablished { args },
            EstablishedLayerChange::ZeroRttRejected => {
                StructureRequest::RebuildEstablished { args }
            }
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

/// The exporter subscribes to the reason for closing written: once it is
/// written, the connection lets its exporter go, and only the clones given
/// out keep it.
impl<T: Choices, L, X: 'static, I, Ic> DataComponent<T, L, layer::Connection, (I, Ic)>
    for ConnectionExporter<X>
where
    L: LineagePartList<T> + ConnectionErrorsOf,
    for<'v> <L as LineageLists<'v, T>>::Connection:
        GetAt<Self, I> + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>,
{
    fn subscribes(out: &mut EventSubscriptions) {
        out.add::<CloseReasonWritten>();
    }
    fn on_events<'v, B: CallBundle>(
        _: TriggeredEvents<'_>,
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
    /// The ServerHello is written, with `selected` the target and
    /// application protocol the rest of the handshake and the established
    /// layer hold to: keep it for the layer.
    fn hello_written<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        selected: SelectedTarget<E::Target>,
    ) where
        Self: 'v;

    /// Install the Handshake keys, derived from `secrets` for `aead`.
    fn install_handshake<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        aead: AeadAlgorithm,
        secrets: HandshakeTrafficSecrets,
    ) where
        Self: 'v;

    /// Decide on 0-RTT, as the ServerHello admitted it: with `secret`,
    /// install the 0-RTT keys to receive with, derived from it for `aead`
    /// (RFC 9001 §4.1.4); without one, refuse 0-RTT, and the 0-RTT packets
    /// that wait are dropped (§4.6.2).
    fn install_zero_rtt_receive<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        aead: AeadAlgorithm,
        secret: Option<ZeroRttReceiveTrafficSecret>,
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
    /// exporter and what the application learns of the handshake.
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
    /// The ClientHello is written, offering 0-RTT with `offered` or not.
    /// With an offer, install the 0-RTT keys to send with and the server's
    /// remembered transport parameters, which 0-RTT keeps to (RFC 9000
    /// §7.4.1), and return `true`: the established layer comes now, with
    /// the application protocol the ticket remembers. Otherwise, or when
    /// the offer cannot be used, return `false`: no established layer comes
    /// before the handshake completes.
    fn hello_written<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        offered: Option<EarlyDataOffered>,
    ) -> bool
    where
        Self: 'v;

    /// Install the Handshake keys, derived from `secrets` for `aead`.
    fn install_handshake<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        aead: AeadAlgorithm,
        secrets: HandshakeTrafficSecrets,
    ) where
        Self: 'v;

    /// The handshake completed: install the 1-RTT keys, derived from the
    /// secrets of `completed` for `aead`, and keep the exporter and what
    /// the application learns of the handshake. A client that sent 0-RTT
    /// stops sending it, and the server's transport parameters of this
    /// handshake replace the remembered ones.
    ///
    /// Returns how the established layer changes, which the call yields:
    /// [`EstablishedLayerChange::Ready`] without an early layer,
    /// [`EstablishedLayerChange::ZeroRttRejected`] when the server rejected
    /// the 0-RTT the early layer ran on, and `None` when the early layer
    /// stays, as the server accepted it, or when the connection closes
    /// already, where the record of why it closed ends the layer.
    ///
    /// # Errors
    ///
    /// When the client sent 0-RTT, the server accepted it and lowered a
    /// limit it relied on. Nothing is installed; the call writes the error
    /// into the record of why the connection closed.
    fn complete<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        aead: AeadAlgorithm,
        completed: ClientHandshakeCompleted<E::Crypto>,
    ) -> Result<Option<EstablishedLayerChange>, <Self as ClientTransport>::Error>
    where
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
#[call(yields = EstablishedLayerChange)]
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
    let ServerHelloWritten {
        aead,
        secrets,
        selected,
        zero_rtt,
    } = written;
    // in one lend with the request for the established layer: the driver
    // builds the layer before any call reads a 0-RTT packet
    host.with(|mut view| {
        W::hello_written(view.as_pin(), selected);
        W::install_handshake(view.as_pin(), aead, secrets);
        W::install_zero_rtt_receive(view.as_pin(), aead, zero_rtt);
    });
    yield EstablishedLayerChange::Ready;
    let (send, state) = step!(host, W::close, E::write_server_finished(state, host).await);
    host.with(|mut view| W::install_one_rtt_send(view.as_pin(), aead, send));
    let (completed, state) = step!(host, W::close, E::read_client_finished(state, host).await);
    host.with(|mut view| W::complete(view.as_pin(), completed));
    step!(host, W::close, E::write_tickets(state, host).await);
}

/// A client's advancing call; what it does is in the
/// [module documentation](self).
#[call(yields = EstablishedLayerChange)]
pub async fn client_advancing<W, E>(host: &mut impl LentAccess<Family = W>, tls: E)
where
    E: ClientHandshakeSteps,
    W: ClientAdvancingCapability<E>,
{
    // The three steps of the handshake are boxed, each until it is
    // awaited: the call's future keeps no room for the largest of them for
    // as long as the connection lasts.
    let (offered, state) = step!(host, W::close, Box::pin(tls.write_client_hello(host)).await);
    let early = host.with(|mut view| W::hello_written(view.as_pin(), offered));
    if early {
        // with 0-RTT, the layer runs on the remembered parameters
        yield EstablishedLayerChange::Ready;
    }
    let (read, state) = step!(
        host,
        W::close,
        Box::pin(E::read_server_hello(state, host)).await
    );
    let aead = read.aead;
    host.with(|mut view| W::install_handshake(view.as_pin(), aead, read.secrets));
    let (completed, state) = step!(
        host,
        W::close,
        Box::pin(E::read_server_finished(state, host)).await
    );
    let change = step!(
        host,
        W::close,
        host.with(|mut view| W::complete(view.as_pin(), aead, completed))
            .map_err(|source| HandshakeError::Transport { source })
    );
    debug_assert!(
        early || change != Some(EstablishedLayerChange::ZeroRttRejected),
        "a layer built anew without an early one"
    );
    if let Some(change) = change {
        yield change;
    }
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
                GetAt<CryptoReceiver<CryptoReceiveBufferOf<T>>, Icr>,
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
                    .get_mut::<CryptoReceiver<CryptoReceiveBufferOf<T>>, Icr>()
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
            <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<V1ConnectionErrorOf<L>, Iv>,
            for<'x> <L as LineageLists<'x, T>>::Connection:
                GetAt<CryptoReceiver<CryptoReceiveBufferOf<T>>, Icr>,
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
                    .get_mut::<CryptoReceiver<CryptoReceiveBufferOf<T>>, Icr>()
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
            <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<V1ConnectionErrorOf<L>, Iv>,
            for<'x> <L as LineageLists<'x, T>>::Connection:
                GetAt<CryptoSender<CryptoSendBufferOf<T>>, Ics>,
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
                let lineage = &mut host.get_mut().lineage;
                let written = lineage
                    .get_mut::<CryptoSender<CryptoSendBufferOf<T>>, Ics>()
                    .write_from(input)
                    .map_err(|source| v1_error::<L, Iv>(ConnectionError::CryptoDataEnd { source }));
                Poll::Ready(written.map(|(len, changed)| {
                    lineage.publish(changed);
                    len
                }))
            }
        }

        /// The engine moves the level of the connection node's sender.
        impl<T, L, Tls, B, Icr, Ics, Iv, Hx> CryptoOutput
            for NodeCallFamily<T, L, Connection, $kind<Tls>, (CryptoPositions<Icr, Ics, Iv>, Hx), B>
        where
            T: Choices,
            L: LineagePartList<T> + ConnectionErrorsOf,
            B: CallBundle,
            <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<V1ConnectionErrorOf<L>, Iv>,
            for<'x> <L as LineageLists<'x, T>>::Connection:
                GetAt<CryptoSender<CryptoSendBufferOf<T>>, Ics>,
        {
            fn move_output_to<'v>(view: Pin<&mut Self::ReceiverView<'v>>, level: CryptoLevel)
            where
                Self: 'v,
            {
                view.get_mut()
                    .lineage
                    .get_mut::<CryptoSender<CryptoSendBufferOf<T>>, Ics>()
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
    L::ConnectionErrors: CoprodInjector<V1ConnectionErrorOf<L>, Iv>,
{
    let mut source = peer;
    read_transport_parameters(&mut source, sender, PhantomData::<L>)
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

/// `slots`, of every part of `L`, as an endpoint in the role `sender`
/// sends them.
fn encode<L>(slots: TransportParameterSlots<L>, sender: Role) -> OpaqueData<Bytes>
where
    L: ParametersOf<TransportParameterSpace>,
{
    let mut parameters = TransportParameters::<Bytes, L>::new();
    parameters.known = slots;
    let mut encoded = Vec::new();
    // invariant: the slots hold only parameters the sender may send, as
    // `server_parameters` and `client_parameters` make them, and no unknown
    // ones, so they are valid; a vector takes every byte
    write_transport_parameters(&mut encoded, parameters, sender)
        .expect("the parameters a side settles are valid");
    // invariant: the parameters of version 1 and of the extensions are far
    // below 2^16 bytes
    OpaqueData::new(Bytes::from(encoded)).expect("transport parameters fit their extension")
}

/// Settle the parameters of version 1 this side sends from those
/// configured with `settle`, the first time; afterwards they stay as sent,
/// as a ClientHello written again after a HelloRetryRequest sends them (RFC
/// 9846 §4.1.2). Every part's, these among them, are then joined
/// ([`SendLocalTransportParameters`]).
fn send_local(
    local: &mut LocalTransportParameters<crate::v1::Part>,
    settle: impl FnOnce(&TransportParameterSlots) -> TransportParameterSlots,
) -> Option<Happened<LocalTransportParametersSent>> {
    if local.sent().is_some() {
        return None;
    }
    local.send_with(settle)
}

/// Give the connection's events what `give` gives, at the instant of this
/// poll from `others`, when they record this connection; with a receiver
/// that records nothing, nothing of it is compiled in.
fn give_events<'v, T, L, B, Iev>(
    lineage: &mut LineageOf<'v, T, L, Connection>,
    others: &OtherNodes<'v, T, L, B>,
    give: impl FnOnce(&mut EventsOf<T, L>, InstantOf<T>),
) where
    T: Choices,
    L: LineagePartList<T>,
    B: CallBundle,
    for<'x> <L as LineageLists<'x, T>>::Connection: GetAt<ConnectionEventSink<EventsOf<T, L>>, Iev>,
{
    if <EventsOf<T, L> as ConnectionEvents<InstantOf<T>>>::ENABLED {
        let now = others.now();
        if let Some(events) = lineage
            .get_mut::<ConnectionEventSink<EventsOf<T, L>>, Iev>()
            .active::<InstantOf<T>>()
        {
            give(events, now);
        }
    }
}

/// Both directions of the keys of `level` were installed.
fn keys_installed<X: ConnectionEvents<I>, I: Copy>(events: &mut X, at: I, level: EncryptionLevel) {
    for sender in [Role::Client, Role::Server] {
        events.key_updated(at, KeyChange::new(level, sender));
    }
}

// ---- the server ----

/// The positions a server's advancing call takes by, besides those of the
/// CRYPTO data: in the connection node, `Ilt` of this side's transport
/// parameters of version 1, `Ils` of every part's, `Irs` of every part's
/// with its policy on resumption, `Ipt` of the peer's, `Ifl` of the first
/// local connection ID, `Iid` of the client's first Destination Connection
/// IDs, `Iph` of the peer's handshake connection ID, `Ik` of the Handshake
/// keys, `Io` of the 1-RTT keys, `Iz` of the 0-RTT keys, `Ib` of the
/// backend, `Ic` of the confirmation, `Ihd` of the
/// HANDSHAKE_DONE source (for the call itself, with `Int` of the NEW_TOKEN
/// source and `Ir` of a link path's role: `(Ihd, Int, Ir)`), `Ie` of the
/// exporter and `Irc` of the record of
/// why the connection closed; `Ja` of
/// `initial_source_connection_id` among the slots of the peer's transport
/// parameters, and `Ia` of what the call is started from in the facts of
/// the connection node.
type ServerPositions<
    Ilt,
    Ils,
    Irs,
    Ipt,
    Ifl,
    Iid,
    Iph,
    Ik,
    Io,
    Iz,
    Ib,
    Ic,
    Ihd,
    Ie,
    Irc,
    Ih,
    Ja,
    Ia,
    Iev,
> = (
    (Ilt, Ils, Irs, Ipt, Ifl, Iid, Iph),
    (Ik, Io, Iz, Ib, Ic),
    (Ihd, Ie, Irc, Ih),
    (Ja, Ia, Iev),
);

/// The server's side of the transport parameters: the client's are read
/// and checked, and this side's are settled and sent.
///
/// The client's `initial_source_connection_id` must state the Source
/// Connection ID of its first Initial packet that opened (RFC 9000 §7.3);
/// a parameter only a server may send is a failure of reading. Once they
/// pass, the client's parameters are known.
///
/// When the client resumes with a ticket, every part settles its own
/// parameters against those the ticket remembers, by its policy and the
/// rules 0-RTT relies on ([`ResumeLocalTransportParameters`]): the
/// connection accepts 0-RTT when every part does (RFC 9000 §7.4.1). Version
/// 1 then fills its connection IDs into what it settled on, and every part's
/// parameters are sent.
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
    Ils,
    Irs,
    Ipt,
    Ifl,
    Iid,
    Iph,
    Ik,
    Io,
    Iz,
    Ib,
    Ic,
    Ihd,
    Ie,
    Irc,
    Ih,
    Ja,
    Ia,
    Iev,
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
                Ils,
                Irs,
                Ipt,
                Ifl,
                Iid,
                Iph,
                Ik,
                Io,
                Iz,
                Ib,
                Ic,
                Ihd,
                Ie,
                Irc,
                Ih,
                Ja,
                Ia,
                Iev,
            >,
        ),
        B,
    >
where
    T: Choices,
    L: LineagePartList<T> + TransportParameterValueErrorsOf,
    B: CallBundle,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<V1ConnectionErrorOf<L>, Iv>,
    EventsOf<T, L>: PacketEvents<InstantOf<T>, L>,
    TransportParameterSlots<L>: Selector<Option<InitialSourceConnectionId>, Ja>,
    for<'x> L: SendLocalTransportParameters<<L as LineageLists<'x, T>>::Connection, Ils>
        + ResumeLocalTransportParameters<<L as LineageLists<'x, T>>::Connection, Irs>,
    for<'x> <L as LineageLists<'x, T>>::Connection: GetAt<LocalTransportParameters<crate::v1::Part>, Ilt>
        + GetAt<PeerTransportParameters<TransportParameterSlots<L>>, Ipt>
        + GetAt<FirstLocalConnectionId, Ifl>
        + GetAt<ConnectionEventSink<EventsOf<T, L>>, Iev>
        + GetAt<InitialDestinationConnectionIds, Iid>
        + GetAt<PeerHandshakeConnectionId, Iph>,
{
    type Error = ConnectionErrorOf<L>;

    fn negotiate<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        peer: &[u8],
        selected: &SelectedTarget<Target>,
        resumed: Option<&TicketState<Target>>,
    ) -> Result<Negotiated, Self::Error>
    where
        Self: 'v,
    {
        let NodeLoan { lineage, others } = view.get_mut();
        let chosen = lineage.get::<PeerHandshakeConnectionId, Iph>().get();
        let slots = read_peer::<L, Iv>(peer, Role::Client)?;
        check_initial_source::<_, Ja>(&slots, chosen).map_err(|source| {
            v1_error::<L, Iv>(ConnectionError::PeerTransportParameters { source })
        })?;
        give_events::<T, L, B, Iev>(lineage, others, |events, now| {
            events.parameters_set(now, EventInitiator::Remote, &slots);
        });
        let known = lineage
            .get_mut::<PeerTransportParameters<TransportParameterSlots<L>>, Ipt>()
            .receive(slots);
        if let Some(known) = known {
            lineage.publish(known);
        }
        // each part settles what it configured against what the ticket
        // remembers before anything is sent; without a ticket nothing is
        // decided, and 0-RTT is not looked at
        let early_data = resumed.is_some_and(|resumed| {
            <L as ResumeLocalTransportParameters<_, Irs>>::resume_local(
                lineage,
                &resumed.resumable.transport_parameters,
                selected.application_protocol.as_ref(),
            )
        });
        let first = *lineage.get::<FirstLocalConnectionId, Ifl>();
        let destination = *lineage.get::<InitialDestinationConnectionIds, Iid>();
        let mut local = lineage.get_mut::<LocalTransportParameters<crate::v1::Part>, Ilt>();
        let sent = send_local(&mut local, |settled| {
            server_parameters(settled, first, destination)
        });
        if let Some(sent) = sent {
            lineage.publish(sent);
        }
        let local = <L as SendLocalTransportParameters<_, Ils>>::send_local(lineage);
        give_events::<T, L, B, Iev>(lineage, others, |events, now| {
            events.parameters_set(now, EventInitiator::Local, &local);
        });
        Ok(Negotiated {
            local: encode::<L>(local, Role::Server),
            early_data,
        })
    }
}

impl<
    T,
    L,
    Tls,
    Ti,
    B,
    Icr,
    Ics,
    Iv,
    Ilt,
    Ils,
    Irs,
    Ipt,
    Ifl,
    Iid,
    Iph,
    Ik,
    Io,
    Iz,
    Ib,
    Ic,
    Ihd,
    Int,
    Ir,
    Ie,
    Irc,
    Ih,
    Ja,
    Ia,
    Iev,
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
                Ils,
                Irs,
                Ipt,
                Ifl,
                Iid,
                Iph,
                Ik,
                Io,
                Iz,
                Ib,
                Ic,
                (Ihd, Int, Ir),
                Ie,
                Irc,
                Ih,
                Ja,
                Ia,
                Iev,
            >,
        ),
        B,
    >
where
    T: Choices<Side = Server<Tls, Ti>>,
    Ti: ConnectionNewTokenIssuer<PeerOf<T>> + 'static,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        GetAt<LinkPathRole<InstantOf<T>>, Ir>,
    Tls: ServerHandshakeSteps + 'static,
    Tls::AlertError: 'static,
    L: LineagePartList<T> + TransportParameterValueErrorsOf,
    B: CallBundle,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<V1ConnectionErrorOf<L>, Iv>,
    EventsOf<T, L>: PacketEvents<InstantOf<T>, L>,
    TransportParameterSlots<L>: Selector<Option<InitialSourceConnectionId>, Ja>,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
    SendTypes<T, L>: HostSendStrategyTypes,
    for<'x> L: SendLocalTransportParameters<<L as LineageLists<'x, T>>::Connection, Ils>
        + ResumeLocalTransportParameters<<L as LineageLists<'x, T>>::Connection, Irs>,
    for<'x> <L as LineageLists<'x, T>>::Connection: GetAt<CryptoReceiver<CryptoReceiveBufferOf<T>>, Icr>
        + GetAt<CryptoSender<CryptoSendBufferOf<T>>, Ics>
        + GetAt<LocalTransportParameters<crate::v1::Part>, Ilt>
        + GetAt<PeerTransportParameters<TransportParameterSlots<L>>, Ipt>
        + GetAt<FirstLocalConnectionId, Ifl>
        + GetAt<ConnectionEventSink<EventsOf<T, L>>, Iev>
        + GetAt<InitialDestinationConnectionIds, Iid>
        + GetAt<PeerHandshakeConnectionId, Iph>
        + GetAt<HandshakeKeys<T::Crypto>, Ik>
        + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>
        + GetAt<ZeroRttReceiving<T::Crypto, InstantOf<T>>, Iz>
        + GetAt<PacketProtectionBackend<T::Crypto>, Ib>
        + GetAt<HandshakeConfirmation, Ic>
        + GetAt<HandshakeDoneSource, Ihd>
        + GetAt<NewTokenSource<Ti>, Int>
        + GetAt<ConnectionExporter<Exporter<Tls::Crypto>>, Ie>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Irc>
        + GetAt<ConnectionHandleStateOf<T, L>, Ih>,
{
    fn hello_written<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        selected: SelectedTarget<Tls::Target>,
    ) where
        Self: 'v,
    {
        view.get_mut()
            .lineage
            .get_mut::<ConnectionHandleStateOf<T, L>, Ih>()
            .keep_selection(selected);
    }

    fn install_handshake<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        aead: AeadAlgorithm,
        secrets: HandshakeTrafficSecrets,
    ) where
        Self: 'v,
    {
        let NodeLoan { lineage, others } = view.get_mut();
        let backend = lineage
            .get::<PacketProtectionBackend<T::Crypto>, Ib>()
            .0
            .clone();
        let installed = lineage
            .get_mut::<HandshakeKeys<T::Crypto>, Ik>()
            .install(level_keys(&backend, aead, &secrets));
        lineage.publish(installed);
        give_events::<T, L, B, Iev>(lineage, others, |events, now| {
            keys_installed(events, now, EncryptionLevel::Handshake);
        });
    }

    fn install_zero_rtt_receive<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        aead: AeadAlgorithm,
        secret: Option<ZeroRttReceiveTrafficSecret>,
    ) where
        Self: 'v,
    {
        let NodeLoan { lineage, others } = view.get_mut();
        let Some(secret) = secret else {
            let refused = lineage
                .get_mut::<ZeroRttReceiving<T::Crypto, InstantOf<T>>, Iz>()
                .refuse();
            if let Some(refused) = refused {
                lineage.publish(refused);
            }
            return;
        };
        let backend = lineage
            .get::<PacketProtectionBackend<T::Crypto>, Ib>()
            .0
            .clone();
        let installed = lineage
            .get_mut::<ZeroRttReceiving<T::Crypto, InstantOf<T>>, Iz>()
            .open(DirectionKeys::derive(&backend, aead, &secret.0));
        // a connection that closed already stays refused
        if let Some(installed) = installed {
            lineage.publish(installed);
            give_events::<T, L, B, Iev>(lineage, others, |events, now| {
                let key = KeyChange::new(EncryptionLevel::ZeroRtt, Role::Client);
                events.key_updated(now, key);
            });
        }
    }

    fn install_one_rtt_send<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        aead: AeadAlgorithm,
        secret: OneRttSendTrafficSecret,
    ) where
        Self: 'v,
    {
        let NodeLoan { lineage, others } = view.get_mut();
        let backend = lineage
            .get::<PacketProtectionBackend<T::Crypto>, Ib>()
            .0
            .clone();
        let installed = lineage
            .get_mut::<OneRttKeys<T::Crypto, InstantOf<T>>, Io>()
            .install_send(backend, aead, secret.0);
        lineage.publish(installed);
        give_events::<T, L, B, Iev>(lineage, others, |events, now| {
            let key = KeyChange::new(EncryptionLevel::OneRtt, Role::Server);
            events.key_updated(now, key);
        });
    }

    fn complete<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        completed: ServerHandshakeCompleted<Tls::Crypto, Tls::Target>,
    ) where
        Self: 'v,
    {
        let NodeLoan { lineage, others } = view.get_mut();
        let ServerHandshakeCompleted {
            one_rtt_receive,
            exporter,
            selected,
            resumed,
        } = completed;
        let installed = lineage
            .get_mut::<OneRttKeys<T::Crypto, InstantOf<T>>, Io>()
            .install_receive(one_rtt_receive.0);
        lineage.publish(installed);
        give_events::<T, L, B, Iev>(lineage, others, |events, now| {
            let key = KeyChange::new(EncryptionLevel::OneRtt, Role::Client);
            events.key_updated(now, key);
            let chosen = selected.application_protocol.as_ref();
            events.alpn_information(now, chosen.map(|name| name.name().as_ref()));
            events.connection_state(now, ConnectionState::HandshakeComplete);
            events.connection_state(now, ConnectionState::HandshakeConfirmed);
        });
        // a server's handshake is confirmed when it completes (RFC 9001
        // §4.1.2); its Handshake keys go with the confirmation
        let confirmed = lineage.get_mut::<HandshakeConfirmation, Ic>().confirm();
        if let Some(confirmed) = confirmed {
            lineage.publish(confirmed);
        }
        let due = lineage.get_mut::<HandshakeDoneSource, Ihd>().due();
        if let Some(due) = due {
            lineage.publish(due);
        }
        // a token for the address the handshake was made with: the peer of
        // the active link path (RFC 9000 §8.1.3)
        let mut active = None;
        others.each_link_path_read::<LinkPathRole<InstantOf<T>>, Ir>(|key, role| {
            if *role == LinkPathRole::Active
                && let NodeKey::LinkPath(_, link) = key
            {
                active = Some(link.peer.clone());
            }
        });
        let issued =
            active.and_then(|peer| lineage.get_mut::<NewTokenSource<Ti>, Int>().issue(&peer));
        if let Some(issued) = issued {
            lineage.publish(issued);
        }
        lineage
            .get_mut::<ConnectionExporter<Exporter<Tls::Crypto>>, Ie>()
            .hold(exporter);
        let exporter = lineage
            .get::<ConnectionExporter<Exporter<Tls::Crypto>>, Ie>()
            .exporter()
            .cloned();
        lineage
            .get_mut::<ConnectionHandleStateOf<T, L>, Ih>()
            .handshake_completed(ServerHandshakeFacts { selected, resumed }, exporter);
    }

    fn close<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        error: HandshakeError<Tls::AlertError, ConnectionErrorOf<L>>,
    ) where
        Self: 'v,
    {
        let lineage = &mut view.get_mut().lineage;
        let written = lineage
            .get_mut::<CloseReasonRecord<CloseCauseOf<T, L>>, Irc>()
            .record(CloseReason::Local(Arc::new(LocalCloseCause::Handshake(
                error,
            ))));
        if let Some(written) = written {
            lineage.publish(written);
        }
    }
}

/// The Handshake keys, both directions derived with `backend` from
/// `secrets` for `aead`.
fn level_keys<C: sakuya_packet_protection_v1::backend::CryptoBackend>(
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
/// subscribes to the reason for closing written: once it is, the call is
/// not needed any more.
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
    Ti,
    Icr,
    Ics,
    Iv,
    Ilt,
    Ils,
    Irs,
    Ipt,
    Ifl,
    Iid,
    Iph,
    Ik,
    Io,
    Iz,
    Ib,
    Ic,
    Ihd,
    Int,
    Ir,
    Ie,
    Irc,
    Ih,
    Ja,
    Ia,
    Iev,
>
    CallKind<
        T,
        L,
        Connection,
        (
            CryptoPositions<Icr, Ics, Iv>,
            ServerPositions<
                Ilt,
                Ils,
                Irs,
                Ipt,
                Ifl,
                Iid,
                Iph,
                Ik,
                Io,
                Iz,
                Ib,
                Ic,
                (Ihd, Int, Ir),
                Ie,
                Irc,
                Ih,
                Ja,
                Ia,
                Iev,
            >,
        ),
    > for ServerAdvancingKind<Tls>
where
    T: Choices<Side = Server<Tls, Ti>>,
    Ti: ConnectionNewTokenIssuer<PeerOf<T>> + 'static,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        GetAt<LinkPathRole<InstantOf<T>>, Ir>,
    Tls: ServerHandshakeSteps + 'static,
    Tls::AlertError: 'static,
    L: LineagePartList<T> + TransportParameterValueErrorsOf,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<V1ConnectionErrorOf<L>, Iv>,
    EventsOf<T, L>: PacketEvents<InstantOf<T>, L>,
    TransportParameterSlots<L>: Selector<Option<InitialSourceConnectionId>, Ja>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, Ia>,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
    SendTypes<T, L>: HostSendStrategyTypes,
    for<'x> L: SendLocalTransportParameters<<L as LineageLists<'x, T>>::Connection, Ils>
        + ResumeLocalTransportParameters<<L as LineageLists<'x, T>>::Connection, Irs>,
    for<'x> <L as LineageLists<'x, T>>::Connection: GetAt<CryptoReceiver<CryptoReceiveBufferOf<T>>, Icr>
        + GetAt<CryptoSender<CryptoSendBufferOf<T>>, Ics>
        + GetAt<LocalTransportParameters<crate::v1::Part>, Ilt>
        + GetAt<PeerTransportParameters<TransportParameterSlots<L>>, Ipt>
        + GetAt<FirstLocalConnectionId, Ifl>
        + GetAt<ConnectionEventSink<EventsOf<T, L>>, Iev>
        + GetAt<InitialDestinationConnectionIds, Iid>
        + GetAt<PeerHandshakeConnectionId, Iph>
        + GetAt<HandshakeKeys<T::Crypto>, Ik>
        + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>
        + GetAt<ZeroRttReceiving<T::Crypto, InstantOf<T>>, Iz>
        + GetAt<PacketProtectionBackend<T::Crypto>, Ib>
        + GetAt<HandshakeConfirmation, Ic>
        + GetAt<HandshakeDoneSource, Ihd>
        + GetAt<NewTokenSource<Ti>, Int>
        + GetAt<ConnectionExporter<Exporter<Tls::Crypto>>, Ie>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Irc>
        + GetAt<ConnectionHandleStateOf<T, L>, Ih>,
    (
        CryptoPositions<Icr, Ics, Iv>,
        ServerPositions<
            Ilt,
            Ils,
            Irs,
            Ipt,
            Ifl,
            Iid,
            Iph,
            Ik,
            Io,
            Iz,
            Ib,
            Ic,
            (Ihd, Int, Ir),
            Ie,
            Irc,
            Ih,
            Ja,
            Ia,
            Iev,
        >,
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
                    Ils,
                    Irs,
                    Ipt,
                    Ifl,
                    Iid,
                    Iph,
                    Ik,
                    Io,
                    Iz,
                    Ib,
                    Ic,
                    (Ihd, Int, Ir),
                    Ie,
                    Irc,
                    Ih,
                    Ja,
                    Ia,
                    Iev,
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
    fn subscribes(out: &mut EventSubscriptions) {
        out.add::<CloseReasonWritten>();
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
type ClientPositions<
    Ilt,
    Ils,
    Ipt,
    Ifl,
    Iid,
    Iph,
    Ik,
    Io,
    Ib,
    Iz,
    Ie,
    Irc,
    Ih,
    Ja,
    Jo,
    Jr,
    Ia,
    Iev,
    Izp,
> = (
    (Ilt, Ils, Ipt, Ifl, Iid, Iph),
    (Ik, Io, Ib, Iz),
    (Ie, Irc, Ih),
    (Ja, Jo, Jr, Ia, Iev, Izp),
);

/// The client's side of the transport parameters: this side's are settled
/// and sent, and the server's are read and checked.
///
/// The server's `original_destination_connection_id` must state the
/// Destination Connection ID of the client's first Initial packet, its
/// `initial_source_connection_id` the Source Connection ID of its first
/// Initial packet that opened, and its `retry_source_connection_id` the
/// Source Connection ID of the Retry the client received, or be absent
/// without one (RFC 9000 §7.3). Once they pass, the
/// server's parameters are known.
impl<
    T,
    L,
    Tls,
    B,
    Icr,
    Ics,
    Iv,
    Ilt,
    Ils,
    Ipt,
    Ifl,
    Iid,
    Iph,
    Ik,
    Io,
    Ib,
    Iz,
    Ie,
    Irc,
    Ih,
    Ja,
    Jo,
    Jr,
    Ia,
    Iev,
    Izp,
> ClientTransport
    for NodeCallFamily<
        T,
        L,
        Connection,
        ClientAdvancingKind<Tls>,
        (
            CryptoPositions<Icr, Ics, Iv>,
            ClientPositions<
                Ilt,
                Ils,
                Ipt,
                Ifl,
                Iid,
                Iph,
                Ik,
                Io,
                Ib,
                Iz,
                Ie,
                Irc,
                Ih,
                Ja,
                Jo,
                Jr,
                Ia,
                Iev,
                Izp,
            >,
        ),
        B,
    >
where
    T: Choices,
    L: LineagePartList<T> + TransportParameterValueErrorsOf,
    B: CallBundle,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<V1ConnectionErrorOf<L>, Iv>,
    EventsOf<T, L>: PacketEvents<InstantOf<T>, L>,
    TransportParameterSlots<L>: Selector<Option<InitialSourceConnectionId>, Ja>
        + Selector<Option<OriginalDestinationConnectionId>, Jo>
        + Selector<Option<RetrySourceConnectionId>, Jr>,
    for<'x> L: SendLocalTransportParameters<<L as LineageLists<'x, T>>::Connection, Ils>,
    for<'x> <L as LineageLists<'x, T>>::Connection: GetAt<LocalTransportParameters<crate::v1::Part>, Ilt>
        + GetAt<PeerTransportParameters<TransportParameterSlots<L>>, Ipt>
        + GetAt<FirstLocalConnectionId, Ifl>
        + GetAt<ConnectionEventSink<EventsOf<T, L>>, Iev>
        + GetAt<InitialDestinationConnectionIds, Iid>
        + GetAt<PeerHandshakeConnectionId, Iph>,
{
    type Error = ConnectionErrorOf<L>;

    fn local<'v>(view: Pin<&mut Self::ReceiverView<'v>>) -> OpaqueData<Bytes>
    where
        Self: 'v,
    {
        let NodeLoan { lineage, others } = view.get_mut();
        let first = *lineage.get::<FirstLocalConnectionId, Ifl>();
        let mut local = lineage.get_mut::<LocalTransportParameters<crate::v1::Part>, Ilt>();
        // the first time only: a ClientHello written again sends the same
        let first_time = local.sent().is_none();
        let sent = send_local(&mut local, |configured| {
            client_parameters(configured, first)
        });
        if let Some(sent) = sent {
            lineage.publish(sent);
        }
        let local = L::send_local(lineage);
        if first_time {
            give_events::<T, L, B, Iev>(lineage, others, |events, now| {
                events.parameters_set(now, EventInitiator::Local, &local);
            });
        }
        encode::<L>(local, Role::Client)
    }

    fn peer<'v>(view: Pin<&mut Self::ReceiverView<'v>>, peer: &[u8]) -> Result<(), Self::Error>
    where
        Self: 'v,
    {
        let NodeLoan { lineage, others } = view.get_mut();
        let chosen = lineage.get::<PeerHandshakeConnectionId, Iph>().get();
        let initial = *lineage.get::<InitialDestinationConnectionIds, Iid>();
        let slots = read_peer::<L, Iv>(peer, Role::Server)?;
        check_server_destination::<_, Jo, Jr>(&slots, initial.original(), initial.retry_source())
            .and_then(|()| check_initial_source::<_, Ja>(&slots, chosen))
            .map_err(|source| {
                v1_error::<L, Iv>(ConnectionError::PeerTransportParameters { source })
            })?;
        give_events::<T, L, B, Iev>(lineage, others, |events, now| {
            events.parameters_set(now, EventInitiator::Remote, &slots);
        });
        // with 0-RTT offered, the remembered ones govern until the
        // handshake completes
        let known = lineage
            .get_mut::<PeerTransportParameters<TransportParameterSlots<L>>, Ipt>()
            .receive(slots);
        if let Some(known) = known {
            lineage.publish(known);
        }
        Ok(())
    }
}

impl<
    T,
    L,
    Tls,
    Tk,
    Rp,
    Lc,
    B,
    Icr,
    Ics,
    Iv,
    Ilt,
    Ils,
    Ipt,
    Ifl,
    Iid,
    Iph,
    Ik,
    Io,
    Ib,
    Iz,
    Ie,
    Irc,
    Ih,
    Ja,
    Jo,
    Jr,
    Ia,
    Iev,
    Izp,
> ClientAdvancingCapability<Tls>
    for NodeCallFamily<
        T,
        L,
        Connection,
        ClientAdvancingKind<Tls>,
        (
            CryptoPositions<Icr, Ics, Iv>,
            ClientPositions<
                Ilt,
                Ils,
                Ipt,
                Ifl,
                Iid,
                Iph,
                Ik,
                Io,
                Ib,
                Iz,
                Ie,
                Irc,
                Ih,
                Ja,
                Jo,
                Jr,
                Ia,
                Iev,
                Izp,
            >,
        ),
        B,
    >
where
    T: Choices<Side = Client<Tls, Tk, Rp, Lc>>,
    Tls: ClientHandshakeSteps + 'static,
    Tls::AlertError: 'static,
    Tk: AddressTokenSink + 'static,
    Rp: ClientRetryPolicy + 'static,
    Lc: 'static,
    L: LineagePartList<T> + TransportParameterValueErrorsOf + AcceptedZeroRttParameters<Izp>,
    B: CallBundle,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<V1ConnectionErrorOf<L>, Iv>,
    EventsOf<T, L>: PacketEvents<InstantOf<T>, L>,
    TransportParameterSlots<L>: Selector<Option<InitialSourceConnectionId>, Ja>
        + Selector<Option<OriginalDestinationConnectionId>, Jo>
        + Selector<Option<RetrySourceConnectionId>, Jr>,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
    SendTypes<T, L>: HostSendStrategyTypes,
    for<'x> L: SendLocalTransportParameters<<L as LineageLists<'x, T>>::Connection, Ils>,
    for<'x> <L as LineageLists<'x, T>>::Connection: GetAt<CryptoReceiver<CryptoReceiveBufferOf<T>>, Icr>
        + GetAt<CryptoSender<CryptoSendBufferOf<T>>, Ics>
        + GetAt<LocalTransportParameters<crate::v1::Part>, Ilt>
        + GetAt<PeerTransportParameters<TransportParameterSlots<L>>, Ipt>
        + GetAt<FirstLocalConnectionId, Ifl>
        + GetAt<ConnectionEventSink<EventsOf<T, L>>, Iev>
        + GetAt<InitialDestinationConnectionIds, Iid>
        + GetAt<PeerHandshakeConnectionId, Iph>
        + GetAt<HandshakeKeys<T::Crypto>, Ik>
        + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>
        + GetAt<PacketProtectionBackend<T::Crypto>, Ib>
        + GetAt<ZeroRttSending<T::Crypto>, Iz>
        + GetAt<ConnectionExporter<Exporter<Tls::Crypto>>, Ie>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Irc>
        + GetAt<ConnectionHandleStateOf<T, L>, Ih>,
{
    fn hello_written<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        offered: Option<EarlyDataOffered>,
    ) -> bool
    where
        Self: 'v,
    {
        let NodeLoan { lineage, others } = view.get_mut();
        // a connection that closed already sends no 0-RTT; an offer whose
        // remembered parameters do not read is not used: the server may
        // accept it, and gets no 0-RTT packets
        let usable = offered.filter(|_| {
            !lineage
                .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Irc>()
                .is_written()
        });
        let remembered = usable.and_then(|offered| {
            let mut source = offered.transport_parameters.clone();
            read_remembered_transport_parameters::<L, _>(&mut source, PhantomData)
                .ok()
                .map(|remembered| (offered, remembered))
        });
        let Some((offered, remembered)) = remembered else {
            lineage
                .get_mut::<ConnectionHandleStateOf<T, L>, Ih>()
                .no_early_layer();
            return false;
        };
        let EarlyDataOffered {
            aead,
            secret,
            application_protocol,
            ..
        } = offered;
        let remembered = lineage
            .get_mut::<PeerTransportParameters<TransportParameterSlots<L>>, Ipt>()
            .remember(remembered);
        lineage.publish(remembered);
        let backend = lineage
            .get::<PacketProtectionBackend<T::Crypto>, Ib>()
            .0
            .clone();
        let installed = lineage
            .get_mut::<ZeroRttSending<T::Crypto>, Iz>()
            .open(DirectionKeys::derive(&backend, aead, &secret.0));
        lineage.publish(installed);
        give_events::<T, L, B, Iev>(lineage, others, |events, now| {
            let key = KeyChange::new(EncryptionLevel::ZeroRtt, Role::Client);
            events.key_updated(now, key);
        });
        // the early layer runs with the application protocol of the
        // ticket's connection; a server that accepts 0-RTT selects the same
        lineage
            .get_mut::<ConnectionHandleStateOf<T, L>, Ih>()
            .keep_selection(application_protocol);
        true
    }

    fn install_handshake<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        aead: AeadAlgorithm,
        secrets: HandshakeTrafficSecrets,
    ) where
        Self: 'v,
    {
        let NodeLoan { lineage, others } = view.get_mut();
        let backend = lineage
            .get::<PacketProtectionBackend<T::Crypto>, Ib>()
            .0
            .clone();
        let installed = lineage
            .get_mut::<HandshakeKeys<T::Crypto>, Ik>()
            .install(level_keys(&backend, aead, &secrets));
        lineage.publish(installed);
        give_events::<T, L, B, Iev>(lineage, others, |events, now| {
            keys_installed(events, now, EncryptionLevel::Handshake);
        });
    }

    fn complete<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        aead: AeadAlgorithm,
        completed: ClientHandshakeCompleted<Tls::Crypto>,
    ) -> Result<Option<EstablishedLayerChange>, ConnectionErrorOf<L>>
    where
        Self: 'v,
    {
        let NodeLoan { lineage, others } = view.get_mut();
        let ClientHandshakeCompleted {
            secrets,
            exporter,
            identity,
            application_protocol,
            early_data,
        } = completed;
        // the client sent 0-RTT when the remembered parameters are held
        let early = {
            let peer = lineage.get::<PeerTransportParameters<TransportParameterSlots<L>>, Ipt>();
            match (peer.remembered_and_received(), early_data) {
                (None, _) => None,
                (Some((remembered, received)), EarlyDataOutcome::Accepted) => {
                    L::check_accepted(remembered, received)?;
                    Some(EarlyLayerFate::Kept)
                }
                // an engine that took the offer back, after a
                // HelloRetryRequest, was rejected: a server that sends one
                // always rejects 0-RTT (RFC 9001 §4.6.2)
                (Some(_), EarlyDataOutcome::Rejected | EarlyDataOutcome::NotOffered) => {
                    Some(EarlyLayerFate::Rejected)
                }
            }
        };
        let backend = lineage
            .get::<PacketProtectionBackend<T::Crypto>, Ib>()
            .0
            .clone();
        let installed = lineage
            .get_mut::<OneRttKeys<T::Crypto, InstantOf<T>>, Io>()
            .install(backend, aead, secrets.send, secrets.receive);
        lineage.publish(installed);
        // no more 0-RTT packets once the 1-RTT keys are in place (RFC 9001
        // §4.9.3), and the server's new parameters apply to 1-RTT packets
        // (RFC 9000 §7.4.1)
        let closed = lineage.get_mut::<ZeroRttSending<T::Crypto>, Iz>().close();
        if let Some(closed) = closed {
            lineage.publish(closed);
        }
        if early == Some(EarlyLayerFate::Rejected) {
            // the 0-RTT packets in flight leave with their recovery state
            // (RFC 9002 §6.4)
            lineage.publish(Happened::<ZeroRttRejected>::new());
        }
        let known = lineage
            .get_mut::<PeerTransportParameters<TransportParameterSlots<L>>, Ipt>()
            .settle_received();
        if let Some(known) = known {
            lineage.publish(known);
        }
        give_events::<T, L, B, Iev>(lineage, others, |events, now| {
            if early.is_some() {
                let key = KeyChange::new(EncryptionLevel::ZeroRtt, Role::Client);
                events.key_discarded(now, key);
            }
            keys_installed(events, now, EncryptionLevel::OneRtt);
            let chosen = application_protocol.as_ref();
            events.alpn_information(now, chosen.map(|name| name.name().as_ref()));
            events.connection_state(now, ConnectionState::HandshakeComplete);
        });
        lineage
            .get_mut::<ConnectionExporter<Exporter<Tls::Crypto>>, Ie>()
            .hold(exporter);
        let exporter = lineage
            .get::<ConnectionExporter<Exporter<Tls::Crypto>>, Ie>()
            .exporter()
            .cloned();
        // a layer that ends for a written reason is not built anew: its
        // streams get the reason (only the first end of a layer is kept)
        let closing = lineage
            .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Irc>()
            .is_written();
        let mut state = lineage.get_mut::<ConnectionHandleStateOf<T, L>, Ih>();
        if early != Some(EarlyLayerFate::Kept) {
            // the established layer, built next, runs with the protocol
            // the handshake selected; after a rejection it may differ from
            // the ticket's (RFC 9001 §4.6.2)
            state.keep_selection(application_protocol.clone());
        }
        state.handshake_completed(
            ClientHandshakeFacts {
                identity,
                application_protocol,
                early_data,
            },
            exporter,
        );
        Ok(match early {
            None => Some(EstablishedLayerChange::Ready),
            Some(EarlyLayerFate::Kept) => None,
            Some(EarlyLayerFate::Rejected) if closing => None,
            Some(EarlyLayerFate::Rejected) => Some(EstablishedLayerChange::ZeroRttRejected),
        })
    }

    fn close<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        error: HandshakeError<Tls::AlertError, ConnectionErrorOf<L>>,
    ) where
        Self: 'v,
    {
        let lineage = &mut view.get_mut().lineage;
        let written = lineage
            .get_mut::<CloseReasonRecord<CloseCauseOf<T, L>>, Irc>()
            .record(CloseReason::Local(Arc::new(LocalCloseCause::Handshake(
                error,
            ))));
        if let Some(written) = written {
            lineage.publish(written);
        }
    }
}

/// What becomes of a client's early established layer as its handshake
/// completes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EarlyLayerFate {
    /// The server accepted 0-RTT: the layer stays.
    Kept,
    /// The server rejected 0-RTT: the layer is built anew.
    Rejected,
}

/// The kind of a client's advancing call, whose engine starts as `Tls`. It
/// subscribes to the reason for closing written: once it is, the call is
/// not needed any more.
pub struct ClientAdvancingKind<Tls>(PhantomData<fn() -> Tls>);

impl<Tls> fmt::Debug for ClientAdvancingKind<Tls> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientAdvancingKind")
    }
}

impl<
    T,
    L,
    Tls,
    Tk,
    Rp,
    Lc,
    Icr,
    Ics,
    Iv,
    Ilt,
    Ils,
    Ipt,
    Ifl,
    Iid,
    Iph,
    Ik,
    Io,
    Ib,
    Iz,
    Ie,
    Irc,
    Ih,
    Ja,
    Jo,
    Jr,
    Ia,
    Iev,
    Izp,
>
    CallKind<
        T,
        L,
        Connection,
        (
            CryptoPositions<Icr, Ics, Iv>,
            ClientPositions<
                Ilt,
                Ils,
                Ipt,
                Ifl,
                Iid,
                Iph,
                Ik,
                Io,
                Ib,
                Iz,
                Ie,
                Irc,
                Ih,
                Ja,
                Jo,
                Jr,
                Ia,
                Iev,
                Izp,
            >,
        ),
    > for ClientAdvancingKind<Tls>
where
    T: Choices<Side = Client<Tls, Tk, Rp, Lc>>,
    Tls: ClientHandshakeSteps + 'static,
    Tls::AlertError: 'static,
    Tk: AddressTokenSink + 'static,
    Rp: ClientRetryPolicy + 'static,
    Lc: 'static,
    L: LineagePartList<T> + TransportParameterValueErrorsOf + AcceptedZeroRttParameters<Izp>,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<V1ConnectionErrorOf<L>, Iv>,
    EventsOf<T, L>: PacketEvents<InstantOf<T>, L>,
    TransportParameterSlots<L>: Selector<Option<InitialSourceConnectionId>, Ja>
        + Selector<Option<OriginalDestinationConnectionId>, Jo>
        + Selector<Option<RetrySourceConnectionId>, Jr>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, Ia>,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
    SendTypes<T, L>: HostSendStrategyTypes,
    for<'x> L: SendLocalTransportParameters<<L as LineageLists<'x, T>>::Connection, Ils>,
    for<'x> <L as LineageLists<'x, T>>::Connection: GetAt<CryptoReceiver<CryptoReceiveBufferOf<T>>, Icr>
        + GetAt<CryptoSender<CryptoSendBufferOf<T>>, Ics>
        + GetAt<LocalTransportParameters<crate::v1::Part>, Ilt>
        + GetAt<PeerTransportParameters<TransportParameterSlots<L>>, Ipt>
        + GetAt<FirstLocalConnectionId, Ifl>
        + GetAt<ConnectionEventSink<EventsOf<T, L>>, Iev>
        + GetAt<InitialDestinationConnectionIds, Iid>
        + GetAt<PeerHandshakeConnectionId, Iph>
        + GetAt<HandshakeKeys<T::Crypto>, Ik>
        + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>
        + GetAt<PacketProtectionBackend<T::Crypto>, Ib>
        + GetAt<ZeroRttSending<T::Crypto>, Iz>
        + GetAt<ConnectionExporter<Exporter<Tls::Crypto>>, Ie>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Irc>
        + GetAt<ConnectionHandleStateOf<T, L>, Ih>,
    (
        CryptoPositions<Icr, Ics, Iv>,
        ClientPositions<
            Ilt,
            Ils,
            Ipt,
            Ifl,
            Iid,
            Iph,
            Ik,
            Io,
            Ib,
            Iz,
            Ie,
            Irc,
            Ih,
            Ja,
            Jo,
            Jr,
            Ia,
            Iev,
            Izp,
        >,
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
                ClientPositions<
                    Ilt,
                    Ils,
                    Ipt,
                    Ifl,
                    Iid,
                    Iph,
                    Ik,
                    Io,
                    Ib,
                    Iz,
                    Ie,
                    Irc,
                    Ih,
                    Ja,
                    Jo,
                    Jr,
                    Ia,
                    Iev,
                    Izp,
                >,
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
    fn subscribes(out: &mut EventSubscriptions) {
        out.add::<CloseReasonWritten>();
    }
    fn no_longer_needed<'v>(lineage: &LineageOf<'v, T, L, Connection>) -> bool {
        lineage
            .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Irc>()
            .is_written()
    }
}
