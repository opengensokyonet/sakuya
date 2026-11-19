//! A server endpoint and a client endpoint on UDP sockets of the loopback
//! interface: the client connects, the server accepts, the handshake
//! completes, the client closes, and both endpoints shut down.
//!
//! The server presents an Ed25519 certificate for example.com, issued by an
//! Ed25519 root that the client's verifier trusts; both are built here.

#![cfg(target_os = "linux")]

use core::{
    fmt,
    future::Future,
    net::SocketAddr,
    num::{NonZeroU32, NonZeroUsize},
    time::Duration,
};
use std::{
    cell::RefCell,
    pin::pin,
    rc::Rc,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
};

use bytes::Bytes;
use frunk_core::{Coprod, hlist};
use futures_util::StreamExt as _;
use nitori_crypto::{NamedGroup, SignatureScheme, SigningKey as _};
use nitori_crypto_aws_lc::{AwsLcBackend, Ed25519SigningKey};
use nitori_io::{ReadChunkHostExt as _, calls::WriteAllHostExt as _};
use nitori_tls::{
    cipher_suite::CipherSuite,
    client::{
        ServerTarget,
        engine::{ClientHandshake, ClientHandshakeSettings, EarlyDataOutcome},
        identity::NoClientCertificate,
        offering::PreferenceOffering,
        ticket::{ClientTicketStore, StoredTicket, TakeOnceTicketMap},
    },
    clock::SystemClock,
    extension::alpn::{ProtocolName, ProtocolNameList},
    key_log::{KeyLog, KeyLogLabel},
    message::HelloRandom,
    message::{MessageLimits, new_session_ticket::TicketLifetime},
    server::{
        choice::{GroupPreference, PreferenceTable},
        engine::{ServerHandshake, ServerHandshakeSettings},
        identity::CertifiedKey,
        layers::PassThroughLayers,
        peer::NoCertificateRequest,
        targets::SniTargets,
        ticket::ZeroRttOnceTicketTable,
    },
    verify::{
        AnchorStore, NoRevocationCheck, SpkiDistrustList, WebPkiVerifier,
        transparency::{EmbeddedSctPolicy, LogList, StaleLogListAction},
    },
};
use sakuya_clock_tokio::TokioClock;
use sakuya_connection::connection_id::local::{
    ConnectionIdIssuer, IssuedConnectionId, LocalConnectionIdStrategy, NewConnectionIdIntent,
    NewConnectionIdSummary, RetiredByPeerViolationError, SequenceMapLocalConnectionIdStrategy,
};
use sakuya_connection::feedback::InjectSummary;
use sakuya_connection::frame_source::FrameSource;
use sakuya_connection::prelude::*;
use sakuya_connection::shared::SharedConnectionDriver;
use sakuya_connection::v1::application_handles::connection::ConnectionHandle;
use sakuya_connection::v1::retry::ContinueOnRetry;
use sakuya_connection::v1::{self, close::LocalCloseCause};
use sakuya_connection::write::{
    InFlightClass, OpenPacket, PacketPosition, PacketWriting, SummaryOf, Supplied,
};
use sakuya_datagram_routing::route::recognizer::{ConnectionIdGenerator, ConnectionIdLengths};
use sakuya_endpoint::role::{ClientConnectionChoices, ServerConnectionChoices};
use sakuya_endpoint::{
    address_token::{
        AddressTokenKey, AddressTokenLifetimes, AddressTokens, AeadAddressTokens,
        AeadNewTokenIssuer, TokenOutcome,
    },
    choices::{EndpointChoices, PeerOf},
    client_token::BoundedAddressTokenStore,
    config::{
        BindingDeclarations, ClientConfig, ClientCryptoReceiveCapacities, EndpointConfig,
        ServerConfig, ServerCryptoReceiveCapacities,
    },
    endpoint::{AddBindingError, BindingHandleConnectError, Endpoint},
    handshake::{ClientHandshakeConfig, ServerHandshakeConfig},
    incoming::{Incoming, RetryError, TerminableIncoming},
    outgoing::StartOutgoingError,
    retry::{CapacityFraction, EncodeStatelessRetryError, LoadStatelessRetryPolicy},
    role::{AcceptingServer, ConnectingClient, NoClient, NoServer},
    stateless_check::ReturnedToken,
};
use sakuya_link::{
    ConnectingLinkBinding as _, EcnMarking, Link as _, OutgoingDatagram, PeerAddressCodec,
};
use sakuya_packet_protection::{backend::ring::RingBackend, retry::verify_retry_integrity_tag};
use sakuya_recovery::loss::{LossThresholds, PacketThreshold, RECOMMENDED_TIME_THRESHOLD};
use sakuya_recovery::packet_number_space::PacketNumberSpaceKind;
use sakuya_stream::connection::{CloseReason, ImmediateClose, LayerEnd, TransportImmediateClose};
use sakuya_stream::send_options::destination::Unfulfilled;
use sakuya_udp_tokio::{UdpBinding, UdpBindingConfig, UdpLink};
use sakuya_wire::v1::stream_count::StreamCount;
use sakuya_wire::{
    connection_id::{ConnectionId, ConnectionIdLength, StatelessResetToken},
    v1::{
        transport_error::TransportErrorCode,
        transport_parameters::{
            TransportParameters,
            integer::{
                ActiveConnectionIdLimit, InitialMaxData, InitialMaxStreamDataBidiLocal,
                InitialMaxStreamDataBidiRemote, InitialMaxStreamDataUni, InitialMaxStreamsBidi,
                InitialMaxStreamsUni, MaxIdleTimeout,
            },
        },
    },
    var_int::VarInt,
};
use time::UtcDateTime;

/// How long any step may take.
const DEADLINE: Duration = Duration::from_secs(5);

// ---- the endpoint's choices ----

/// The endpoints of the tests: UDP on tokio.
struct Udp;

type Links = Coprod![UdpLink<TokioClock>];

impl EndpointChoices for Udp {
    type Links = Links;
    type Bindings = frunk_core::HList![UdpBinding<TokioClock>];
    type Clock = TokioClock;
    type Crypto = RingBackend;
    type Random = AwsLcBackend;
    type WallClock = SystemClock;
    type ConnectionIds = CountingConnectionIds;
    type Recognizer = ConnectionIdLengths;
    /// The family of `std` locks, as an endpoint on several threads has,
    /// though the tests run on one.
    type Synchronization = sakuya_sync_std::endpoint::LockingEndpointSynchronization;
}

/// Connection IDs of eight bytes from a counter shared by the endpoint,
/// with tokens from the same count.
#[derive(Clone)]
struct CountingConnectionIds(Arc<AtomicU64>);

impl ConnectionIdGenerator for CountingConnectionIds {
    type Config = Self;

    fn new(config: &Self) -> Self {
        config.clone()
    }

    fn generate(&mut self) -> (ConnectionId, StatelessResetToken) {
        let n = self.0.fetch_add(1, Ordering::Relaxed);
        let cid = ConnectionId::new(&n.to_be_bytes()).expect("eight bytes");
        let mut token = [0; 16];
        token[..8].copy_from_slice(&n.to_be_bytes());
        (cid, StatelessResetToken::new(token))
    }

    fn stateless_reset_token(_: &Self, _: &ConnectionId) -> Option<StatelessResetToken> {
        None
    }
}

// ---- the connections' choices ----

/// The application's error type for closing.
#[derive(Debug, PartialEq, Eq)]
struct AppClose(u32);
impl fmt::Display for AppClose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the application closed with {}", self.0)
    }
}
impl std::error::Error for AppClose {}
impl v1::close::ApplicationClose for AppClose {
    fn code(&self) -> sakuya_wire::v1::application_error::ApplicationErrorCode {
        sakuya_wire::v1::application_error::ApplicationErrorCode::new(VarInt::from_u32(self.0))
    }
}

/// What the tests choose of version 1: their application error, and the
/// default of everything else; the endpoint fixes the rest.
struct Mine;

impl<T: v1::MakerChoices> v1::HostChoices<T> for Mine {
    type ApplicationError = AppClose;
}

/// The choices of the server's connections.
type ServerChoices =
    ServerConnectionChoices<Udp, Mine, ServerStarts, AeadNewTokenIssuer<AwsLcBackend>>;
/// The choices of the client's connections.
type ClientChoices =
    ClientConnectionChoices<Udp, Mine, ClientStarts, ClientTokens, ContinueOnRetry>;

type Parts = frunk_core::HList![v1::Part];
sakuya_connection::composition!(impl for Mine: ServerChoices, Parts);
sakuya_connection::composition!(impl for Mine: ClientChoices, Parts);

type Server = AcceptingServer<
    Mine,
    Parts,
    ServerStarts,
    AeadAddressTokens<AwsLcBackend>,
    LoadStatelessRetryPolicy,
>;
/// Where the client keeps the address validation tokens servers give it.
type ClientTokens =
    BoundedAddressTokenStore<ServerTarget, sakuya_endpoint::choices::SynchronizationOf<Udp>>;
type Client = ConnectingClient<Mine, Parts, ClientStarts, ClientTokens, ContinueOnRetry>;

/// What the client's connections choose where they send NEW_CONNECTION_ID
/// in 0-RTT: as [`Mine`], with a local connection ID strategy that issues
/// as soon as it is told a limit ([`EagerConnectionIds`]).
struct Eager;

impl<T: v1::MakerChoices> v1::HostChoices<T> for Eager {
    type ApplicationError = AppClose;
    type LocalConnectionIds = EagerConnectionIds<
        v1::connection_ids::LocalConnectionIdRegistrationOf<T>,
        sakuya_connection::clock::InstantOf<T>,
    >;
}

/// The choices of the client's connections with [`Eager`].
type EagerClientChoices =
    ClientConnectionChoices<Udp, Eager, ClientStarts, ClientTokens, ContinueOnRetry>;
sakuya_connection::composition!(impl for Eager: EagerClientChoices, Parts);
type EagerClient = ConnectingClient<Eager, Parts, ClientStarts, ClientTokens, ContinueOnRetry>;

/// What the client's [`EagerConnectionIds`] did, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disclosed {
    /// It was told it may issue up to this many.
    Issuable(u64),
    /// It was told the server rejected 0-RTT, with this connection's limit.
    Rejected(u64),
    /// The NEW_CONNECTION_ID frame of this sequence number was written.
    Written(u64),
    /// A packet with it was acknowledged.
    Delivered(u64),
    /// Its frame came back as lost.
    Lost(u64),
}

thread_local! {
    /// What the client's [`EagerConnectionIds`] of this thread did since it
    /// was last taken.
    static DISCLOSED: RefCell<Vec<Disclosed>> = const { RefCell::new(Vec::new()) };
}

/// What the client's [`EagerConnectionIds`] did since the last call.
fn take_disclosed() -> Vec<Disclosed> {
    DISCLOSED.with(|disclosed| std::mem::take(&mut *disclosed.borrow_mut()))
}

fn disclose(what: Disclosed) {
    DISCLOSED.with(|disclosed| disclosed.borrow_mut().push(what));
}

/// sakuya's local connection ID strategy, but told the handshake is
/// confirmed as soon as it is told a limit: a client that sends 0-RTT
/// issues connection IDs at once, up to the remembered limit, and sends
/// their NEW_CONNECTION_ID frames in 0-RTT packets, as RFC 9000 allows
/// (§12.5, §7.4.1); sakuya's own waits for the confirmation. It notes what
/// it does ([`take_disclosed`]).
#[derive(Debug)]
struct EagerConnectionIds<R, I>(SequenceMapLocalConnectionIdStrategy<R, I>);

impl<Id, R, I> LocalConnectionIdStrategy<Id, I, R> for EagerConnectionIds<R, I>
where
    I: Ord + Copy + core::ops::Add<Duration, Output = I>,
{
    fn new(first: Option<IssuedConnectionId<R>>, preferred: Option<IssuedConnectionId<R>>) -> Self {
        Self(<SequenceMapLocalConnectionIdStrategy<R, I> as LocalConnectionIdStrategy<
            Id,
            I,
            R,
        >>::new(first, preferred))
    }

    fn on_issuable<C>(&mut self, issuer: &mut C, peer_limit: u64) -> bool
    where
        C: ConnectionIdIssuer<Registration = R>,
    {
        disclose(Disclosed::Issuable(peer_limit));
        let confirmed =
            LocalConnectionIdStrategy::<Id, I, R>::on_handshake_confirmed(&mut self.0, issuer);
        LocalConnectionIdStrategy::<Id, I, R>::on_issuable(&mut self.0, issuer, peer_limit)
            || confirmed
    }

    fn on_zero_rtt_rejected<C>(&mut self, issuer: &mut C, peer_limit: u64) -> bool
    where
        C: ConnectionIdIssuer<Registration = R>,
    {
        disclose(Disclosed::Rejected(peer_limit));
        LocalConnectionIdStrategy::<Id, I, R>::on_zero_rtt_rejected(&mut self.0, issuer, peer_limit)
    }

    fn on_handshake_confirmed<C>(&mut self, issuer: &mut C) -> bool
    where
        C: ConnectionIdIssuer<Registration = R>,
    {
        LocalConnectionIdStrategy::<Id, I, R>::on_handshake_confirmed(&mut self.0, issuer)
    }

    fn on_retired_by_peer<C>(
        &mut self,
        issuer: &mut C,
        sequence: u64,
        packet_destination: &ConnectionId,
        now: I,
        pto: Duration,
    ) -> Result<bool, RetiredByPeerViolationError>
    where
        C: ConnectionIdIssuer<Registration = R>,
    {
        LocalConnectionIdStrategy::<Id, I, R>::on_retired_by_peer(
            &mut self.0,
            issuer,
            sequence,
            packet_destination,
            now,
            pto,
        )
    }

    fn next_deadline(&self) -> Option<I> {
        LocalConnectionIdStrategy::<Id, I, R>::next_deadline(&self.0)
    }

    fn on_deadline<C>(&mut self, issuer: &mut C, now: I) -> bool
    where
        C: ConnectionIdIssuer<Registration = R>,
    {
        LocalConnectionIdStrategy::<Id, I, R>::on_deadline(&mut self.0, issuer, now)
    }

    fn waiting_disclosures(&self) -> impl Iterator<Item = NewConnectionIdIntent> + '_ {
        LocalConnectionIdStrategy::<Id, I, R>::waiting_disclosures(&self.0)
    }
}

impl<R, I> FrameSource for EagerConnectionIds<R, I> {
    type Summary = NewConnectionIdSummary;
    type Class = InFlightClass;
    type Item<'a> = u64;

    fn supply<W, P, Idx>(
        &mut self,
        item: u64,
        packet: OpenPacket<W, InFlightClass, P>,
    ) -> Supplied<W, InFlightClass, P>
    where
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<NewConnectionIdSummary, Idx>,
        P: PacketPosition,
    {
        let before = packet.remaining();
        let supplied = self.0.supply::<W, P, Idx>(item, packet);
        let written = match &supplied {
            Supplied::Open(packet) => packet.remaining() < before,
            Supplied::Closed(_) => true,
        };
        if written {
            disclose(Disclosed::Written(item));
        }
        supplied
    }

    fn delivered(&mut self, space: PacketNumberSpaceKind, summary: NewConnectionIdSummary) {
        disclose(Disclosed::Delivered(summary.sequence));
        self.0.delivered(space, summary);
    }

    fn lost(&mut self, space: PacketNumberSpaceKind, summary: &NewConnectionIdSummary) {
        disclose(Disclosed::Lost(summary.sequence));
        self.0.lost(space, summary);
    }

    fn unfulfilled(&mut self, item: u64, cause: Unfulfilled) {
        self.0.unfulfilled(item, cause);
    }
}

// ---- the handshakes ----

type Verifier = WebPkiVerifier<
    AwsLcBackend,
    AnchorStore,
    SpkiDistrustList,
    NoRevocationCheck,
    EmbeddedSctPolicy,
    SystemClock,
>;

type ServerEngine = ServerHandshake<
    AwsLcBackend,
    PreferenceTable,
    ServerTickets,
    PassThroughLayers,
    SniTargets<&'static str>,
    CertifiedKey<Ed25519SigningKey>,
    NoCertificateRequest,
    SystemClock,
    (),
>;

type ClientEngine = ClientHandshake<
    AwsLcBackend,
    PreferenceOffering,
    Arc<WatchedTickets>,
    Verifier,
    NoClientCertificate,
    SystemClock,
    Arc<RecordedLabels>,
>;

fn h3() -> ProtocolName<Bytes> {
    ProtocolName::new(Bytes::from_static(b"h3")).unwrap()
}

type ServerTickets = ZeroRttOnceTicketTable<&'static str, AwsLcBackend, SystemClock>;

/// Makes each server connection's engine afresh, on one table of tickets
/// that the engines share (a clone of the table shares it).
#[derive(Clone)]
struct ServerStarts {
    tickets: ServerTickets,
}

impl ServerStarts {
    /// Engines whose table of tickets allows 0-RTT when `early_data` is set.
    fn new(early_data: bool) -> Self {
        Self {
            tickets: ZeroRttOnceTicketTable::new(
                AwsLcBackend,
                SystemClock,
                2,
                TicketLifetime::new(3600).unwrap(),
                early_data,
                16,
            ),
        }
    }
}

impl ServerHandshakeConfig for ServerStarts {
    type Start = ServerEngine;

    fn start(&self) -> ServerEngine {
        let mut targets = SniTargets::new();
        targets.insert("example.com", "web", vec![h3()]);
        ServerHandshake::new(
            AwsLcBackend,
            PreferenceTable::new(
                vec![CipherSuite::TLS_AES_128_GCM_SHA256],
                vec![NamedGroup::X25519],
                GroupPreference::KeyShareFirst,
            ),
            self.tickets.clone(),
            PassThroughLayers,
            targets,
            CertifiedKey::new(vec![Bytes::from(pki::leaf())], pki::key(2)).unwrap(),
            NoCertificateRequest,
            SystemClock,
            (),
            ServerHandshakeSettings::default(),
        )
    }

    fn limits(&self) -> MessageLimits {
        ServerHandshakeSettings::default().limits
    }

    fn requests_client_certificate(&self) -> bool {
        false
    }
}

/// The labels the client's engines logged a secret under.
#[derive(Default)]
struct RecordedLabels(Mutex<Vec<KeyLogLabel>>);

impl KeyLog for RecordedLabels {
    fn log(&self, label: KeyLogLabel, _: &HelloRandom, _: &[u8]) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(label);
    }
}

impl RecordedLabels {
    fn has(&self, label: KeyLogLabel) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&label)
    }
}

/// Makes each client connection's engine, which logs to `labels`.
#[derive(Clone)]
struct ClientStarts {
    labels: Arc<RecordedLabels>,
    tickets: Arc<WatchedTickets>,
}

impl ClientStarts {
    /// Engines logging to `labels`, with a store of tickets of their own.
    fn new(labels: &Arc<RecordedLabels>) -> Self {
        Self {
            labels: Arc::clone(labels),
            tickets: Arc::new(WatchedTickets {
                tickets: TakeOnceTicketMap::new(SystemClock, Duration::from_secs(86_400), 4),
                stored: tokio::sync::watch::Sender::new(0),
            }),
        }
    }
}

/// The client's tickets, counting the ones stored: a connection that is to
/// be resumed waits for a ticket before it closes.
struct WatchedTickets {
    tickets: TakeOnceTicketMap<SystemClock>,
    stored: tokio::sync::watch::Sender<usize>,
}

impl ClientTicketStore for WatchedTickets {
    fn take(&self, target: &ServerTarget) -> Option<StoredTicket> {
        self.tickets.take(target)
    }

    fn store(&self, target: &ServerTarget, ticket: StoredTicket) {
        self.tickets.store(target, ticket);
        self.stored.send_modify(|stored| *stored += 1);
    }
}

impl ClientHandshakeConfig for ClientStarts {
    type ServerName = ServerTarget;
    type Start = ClientEngine;

    fn start(&self, server_name: &ServerTarget) -> ClientEngine {
        ClientHandshake::new(
            AwsLcBackend,
            PreferenceOffering::new(
                vec![CipherSuite::TLS_AES_128_GCM_SHA256],
                vec![NamedGroup::X25519],
                vec![NamedGroup::X25519],
            )
            .unwrap(),
            Arc::clone(&self.tickets),
            pki::verifier(1),
            NoClientCertificate,
            SystemClock,
            Arc::clone(&self.labels),
            server_name.clone(),
            Some(ProtocolNameList::new(vec![h3()]).unwrap()),
            ClientHandshakeSettings::default(),
        )
    }

    fn limits(&self) -> MessageLimits {
        ClientHandshakeSettings::default().limits
    }
}

// ---- the configurations ----

macro_rules! v1_config {
    ($t:ty) => {{
        let mut parameters = TransportParameters::<Vec<u8>>::new();
        parameters.set(MaxIdleTimeout::new(VarInt::from_u32(30_000)));
        sakuya_endpoint::v1::ConnectionConfig::<$t, Parts> {
            transport_parameters: parameters.known,
            ..Default::default()
        }
    }};
}

/// The configuration of a connection's version 1 with `max_data` as its
/// initial maximum data and the stream limits of a connection that moves data.
macro_rules! v1_config_flowing {
    ($t:ty, $max_data:expr) => {
        v1_config_flowing!($t, $max_data, 2)
    };
    ($t:ty, $max_data:expr, $connection_id_limit:expr) => {{
        let mut parameters = TransportParameters::<Vec<u8>>::new();
        parameters
            .set(ActiveConnectionIdLimit::new(VarInt::from_u32($connection_id_limit)).unwrap());
        parameters.set(MaxIdleTimeout::new(VarInt::from_u32(30_000)));
        parameters.set(InitialMaxData::new(VarInt::from_u32($max_data)));
        parameters.set(InitialMaxStreamDataBidiLocal::new(VarInt::from_u32(
            1 << 20,
        )));
        parameters.set(InitialMaxStreamDataBidiRemote::new(VarInt::from_u32(
            1 << 20,
        )));
        parameters.set(InitialMaxStreamDataUni::new(VarInt::from_u32(1 << 20)));
        parameters.set(InitialMaxStreamsBidi::new(StreamCount::new(100).unwrap()));
        parameters.set(InitialMaxStreamsUni::new(StreamCount::new(100).unwrap()));
        sakuya_endpoint::v1::ConnectionConfig::<$t, Parts> {
            transport_parameters: parameters.known,
            ..Default::default()
        }
    }};
}

fn thresholds() -> LossThresholds {
    LossThresholds::recommended(Duration::from_millis(1)).unwrap()
}

fn endpoint_config<S, C>(server: S::Config, client: C::Config) -> EndpointConfig<Udp, S, C>
where
    S: sakuya_endpoint::role::ServerRole<Udp>,
    C: sakuya_endpoint::role::ClientRole<Udp>,
{
    EndpointConfig {
        server,
        client,
        clock: TokioClock,
        crypto: RingBackend,
        random: AwsLcBackend,
        wall_clock: SystemClock,
        connection_ids: CountingConnectionIds(Arc::new(AtomicU64::new(0x5e5e_0000_0000_0000))),
        recognizer: ConnectionIdLengths::new([ConnectionIdLength::new(8).unwrap()]),
    }
}

fn aead_tokens() -> AeadAddressTokens<AwsLcBackend> {
    AeadAddressTokens::new(
        AwsLcBackend,
        AddressTokenKey::generate(&AwsLcBackend).unwrap(),
        AddressTokenLifetimes::default(),
        Default::default(),
    )
    .unwrap()
}

fn server_config() -> ServerConfig<
    ServerChoices,
    Parts,
    ServerStarts,
    AeadAddressTokens<AwsLcBackend>,
    LoadStatelessRetryPolicy,
> {
    server_config_with(aead_tokens())
}

fn server_config_with<Tk>(
    tokens: Tk,
) -> ServerConfig<ServerChoices, Parts, ServerStarts, Tk, LoadStatelessRetryPolicy> {
    server_config_on(
        ServerStarts::new(false),
        tokens,
        hlist![v1_config!(ServerChoices)],
    )
}

/// A server that moves data and lets clients resume with 0-RTT, with
/// `max_data` as its initial maximum data.
fn resuming_server_config<Tk>(
    starts: ServerStarts,
    tokens: Tk,
    max_data: u32,
) -> ServerConfig<ServerChoices, Parts, ServerStarts, Tk, LoadStatelessRetryPolicy> {
    server_config_on(
        starts,
        tokens,
        hlist![v1_config_flowing!(ServerChoices, max_data)],
    )
}

/// A server as [`resuming_server_config`] makes it, which lets the client
/// keep `connection_id_limit` connection IDs of its own.
fn resuming_server_config_with_limit<Tk>(
    starts: ServerStarts,
    tokens: Tk,
    max_data: u32,
    connection_id_limit: u32,
) -> ServerConfig<ServerChoices, Parts, ServerStarts, Tk, LoadStatelessRetryPolicy> {
    server_config_on(
        starts,
        tokens,
        hlist![v1_config_flowing!(
            ServerChoices,
            max_data,
            connection_id_limit
        )],
    )
}

fn server_config_on<Tk>(
    starts: ServerStarts,
    tokens: Tk,
    versions: frunk_core::HList![sakuya_endpoint::v1::ConnectionConfig<ServerChoices, Parts>],
) -> ServerConfig<ServerChoices, Parts, ServerStarts, Tk, LoadStatelessRetryPolicy> {
    ServerConfig::new(
        starts,
        ServerCryptoReceiveCapacities {
            initial: 16 * 1024 + 4,
            handshake: 4096,
        },
        thresholds(),
        versions,
        tokens,
        LoadStatelessRetryPolicy::new(
            CapacityFraction::new(1, NonZeroU32::new(2).unwrap()).unwrap(),
        ),
    )
    .unwrap()
}

fn client_config(
    labels: &Arc<RecordedLabels>,
) -> ClientConfig<ClientChoices, Parts, ClientStarts, ClientTokens, ContinueOnRetry> {
    client_config_with(labels, thresholds())
}

fn client_config_with(
    labels: &Arc<RecordedLabels>,
    thresholds: LossThresholds,
) -> ClientConfig<ClientChoices, Parts, ClientStarts, ClientTokens, ContinueOnRetry> {
    client_config_on(
        ClientStarts::new(labels),
        thresholds,
        hlist![v1_config!(ClientChoices)],
    )
}

/// A client that moves data and offers 0-RTT when its starts hold a ticket.
fn resuming_client_config(
    starts: ClientStarts,
) -> ClientConfig<ClientChoices, Parts, ClientStarts, ClientTokens, ContinueOnRetry> {
    client_config_on(
        starts,
        thresholds(),
        hlist![v1_config_flowing!(ClientChoices, 16 << 20)],
    )
}

/// A client as [`resuming_client_config`] makes it, whose connections
/// issue their connection IDs at once ([`Eager`]).
fn eager_resuming_client_config(
    starts: ClientStarts,
) -> ClientConfig<EagerClientChoices, Parts, ClientStarts, ClientTokens, ContinueOnRetry> {
    ClientConfig::new(
        starts,
        ClientCryptoReceiveCapacities {
            initial: 16 * 1024 + 4,
            handshake: 64 * 1024 + 4,
            one_rtt: 16 * 1024 + 4,
        },
        thresholds(),
        hlist![v1_config_flowing!(EagerClientChoices, 16 << 20)],
        ClientTokens::new(),
        ContinueOnRetry,
    )
    .unwrap()
}

fn client_config_on(
    starts: ClientStarts,
    thresholds: LossThresholds,
    versions: frunk_core::HList![sakuya_endpoint::v1::ConnectionConfig<ClientChoices, Parts>],
) -> ClientConfig<ClientChoices, Parts, ClientStarts, ClientTokens, ContinueOnRetry> {
    ClientConfig::new(
        starts,
        ClientCryptoReceiveCapacities {
            initial: 16 * 1024 + 4,
            handshake: 64 * 1024 + 4,
            one_rtt: 16 * 1024 + 4,
        },
        thresholds,
        versions,
        ClientTokens::new(),
        ContinueOnRetry,
    )
    .unwrap()
}

// ---- running ----

fn run(test: impl Future<Output = ()>) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime builds");
    tokio::task::LocalSet::new().block_on(&runtime, test);
}

async fn within<T>(what: &str, future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .unwrap_or_else(|_| panic!("{what} within {DEADLINE:?}"))
}

fn bind() -> UdpBinding<TokioClock> {
    UdpBinding::bind(
        UdpBindingConfig::new(SocketAddr::from(([127, 0, 0, 1], 0))),
        TokioClock,
    )
    .expect("a loopback socket binds")
}

#[test]
fn a_client_and_a_server_endpoint_handshake_on_the_loopback_interface() {
    run(async {
        let (server, server_reflow) =
            Endpoint::<Udp, Server, NoClient>::new(endpoint_config(server_config(), ())).unwrap();
        let server_reflow = tokio::task::spawn_local(server_reflow);
        let server_socket = bind();
        let server_address = server_socket.local_address();
        let (_server_handle, server_driver) = server
            .add_accepting_binding(server_socket, BindingDeclarations::default())
            .unwrap();
        let server_driver = tokio::task::spawn_local(server_driver);
        let mut incoming = server.incoming();

        let labels = Arc::new(RecordedLabels::default());
        let (client, client_reflow) =
            Endpoint::<Udp, NoServer, Client>::new(endpoint_config((), client_config(&labels)))
                .unwrap();
        let client_reflow = tokio::task::spawn_local(client_reflow);
        let (client_handle, client_driver) = client
            .add_connect_only_binding(bind(), BindingDeclarations::default())
            .unwrap();
        let client_driver = tokio::task::spawn_local(client_driver);

        let outgoing = within(
            "the client takes a link",
            client_handle.connect(
                server_address,
                ServerTarget::from_host_name("example.com").unwrap(),
            ),
        )
        .await
        .unwrap();
        let client_connection = Rc::new(RefCell::new(outgoing.start().unwrap()));
        let client_conn = ConnectionHandle::new(client_connection.clone());
        let client_connection =
            tokio::task::spawn_local(SharedConnectionDriver::new(client_connection));

        let Some(Incoming::Terminable(half)) =
            within("an incoming connection", incoming.next()).await
        else {
            panic!("the server endpoint ends before a connection comes");
        };
        assert!(!half.facts().born_from_zero_rtt);
        let server_connection = Rc::new(RefCell::new(half.accept().unwrap()));
        let server_conn = ConnectionHandle::new(server_connection.clone());
        let server_connection =
            tokio::task::spawn_local(SharedConnectionDriver::new(server_connection));

        // The connection handles the endpoint gave see the handshake
        // complete on both sides.
        within(
            "the client's handshake completes",
            client_conn.handshake_completed(),
        )
        .await
        .expect("the client's handshake completed");
        within(
            "the server's handshake completes",
            server_conn.handshake_completed(),
        )
        .await
        .expect("the server's handshake completed");
        assert!(labels.has(KeyLogLabel::ClientTrafficSecret0));
        // The client's Initial and Handshake packets sent to the server's
        // connection ID belong to the connection: none of them makes
        // another incoming connection.
        assert!(
            tokio::time::timeout(Duration::from_millis(100), incoming.next())
                .await
                .is_err(),
            "the client's later packets make no other incoming connection"
        );

        client_conn.close(AppClose(7));
        let CloseReason::Local(cause) = within("the client's close", client_conn.closed()).await
        else {
            panic!("the client closes for its own reason");
        };
        assert!(matches!(*cause, LocalCloseCause::Application(AppClose(7))));
        // the reasons of an endpoint's connections show as errors, the end
        // of a link among them
        let _: &dyn std::error::Error = &*cause;
        let CloseReason::Peer(ImmediateClose::Application(close)) =
            within("the server's close", server_conn.closed()).await
        else {
            panic!("the server closes for the client's reason");
        };
        assert_eq!(close.code.get(), VarInt::from_u32(7));
        within("the client's connection ends", client_connection)
            .await
            .unwrap();
        within("the server's connection ends", server_connection)
            .await
            .unwrap();

        drop(incoming);
        server.close();
        client.close();
        within("the server's binding driver ends", server_driver)
            .await
            .unwrap();
        within("the server's reflow driver ends", server_reflow)
            .await
            .unwrap();
        within("the client's binding driver ends", client_driver)
            .await
            .unwrap();
        within("the client's reflow driver ends", client_reflow)
            .await
            .unwrap();
    });
}

/// A server endpoint, its incoming stream, and the address of its socket,
/// with its drivers spawned.
struct Running<D> {
    endpoint: Endpoint<Udp, Server, NoClient>,
    address: SocketAddr,
    drivers: D,
}

fn server() -> Running<(tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>)> {
    server_on(server_config())
}

fn server_on(
    config: ServerConfig<
        ServerChoices,
        Parts,
        ServerStarts,
        AeadAddressTokens<AwsLcBackend>,
        LoadStatelessRetryPolicy,
    >,
) -> Running<(tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>)> {
    let (endpoint, reflow) =
        Endpoint::<Udp, Server, NoClient>::new(endpoint_config(config, ())).unwrap();
    let reflow = tokio::task::spawn_local(reflow);
    let socket = bind();
    let address = socket.local_address();
    let (_handle, driver) = endpoint
        .add_accepting_binding(socket, BindingDeclarations::default())
        .unwrap();
    let driver = tokio::task::spawn_local(driver);
    Running {
        endpoint,
        address,
        drivers: (reflow, driver),
    }
}

#[test]
fn a_refused_connection_ends_on_the_client_without_a_handshake() {
    run(async {
        let server = server();
        let mut incoming = server.endpoint.incoming();
        let labels = Arc::new(RecordedLabels::default());
        let (client, client_reflow) =
            Endpoint::<Udp, NoServer, Client>::new(endpoint_config((), client_config(&labels)))
                .unwrap();
        let client_reflow = tokio::task::spawn_local(client_reflow);
        let (handle, client_driver) = client
            .add_connect_only_binding(bind(), BindingDeclarations::default())
            .unwrap();
        let client_driver = tokio::task::spawn_local(client_driver);
        let outgoing = within(
            "the client takes a link",
            handle.connect(
                server.address,
                ServerTarget::from_host_name("example.com").unwrap(),
            ),
        )
        .await
        .unwrap();
        let connection = tokio::task::spawn_local(outgoing.start().unwrap());

        let Some(Incoming::Terminable(half)) =
            within("an incoming connection", incoming.next()).await
        else {
            panic!("the server endpoint ends before a connection comes");
        };
        let refused = half.refuse(TransportImmediateClose {
            code: TransportErrorCode::CONNECTION_REFUSED,
            frame_type: None,
            reason_phrase: Bytes::from_static(b"not now"),
        });
        assert!(within("the refusal is sent", refused).await.is_ok());

        // The client ends on the close, long before its idle timeout.
        within("the client's connection ends", connection)
            .await
            .unwrap();
        assert!(!labels.has(KeyLogLabel::ClientTrafficSecret0));

        client.close();
        server.endpoint.close();
        assert!(
            within("the incoming stream ends", incoming.next())
                .await
                .is_none()
        );
        let (server_reflow, server_driver) = server.drivers;
        within("the server's reflow driver ends", server_reflow)
            .await
            .unwrap();
        within("the server's binding driver ends", server_driver)
            .await
            .unwrap();
        within("the client's reflow driver ends", client_reflow)
            .await
            .unwrap();
        within("the client's binding driver ends", client_driver)
            .await
            .unwrap();
    });
}

#[test]
fn a_closed_endpoint_makes_no_connection() {
    run(async {
        let server = server();
        let labels = Arc::new(RecordedLabels::default());
        let (client, _client_reflow) =
            Endpoint::<Udp, NoServer, Client>::new(endpoint_config((), client_config(&labels)))
                .unwrap();
        let (handle, _client_driver) = client
            .add_connect_only_binding(bind(), BindingDeclarations::default())
            .unwrap();

        server.endpoint.close();
        server.endpoint.close();
        let mut incoming = server.endpoint.incoming();
        assert!(incoming.next().await.is_none());
        assert!(matches!(
            server
                .endpoint
                .add_accepting_binding(bind(), BindingDeclarations::default()),
            Err(AddBindingError::EndpointClosed { .. })
        ));

        let outgoing = within(
            "the client takes a link",
            handle.connect(
                server.address,
                ServerTarget::from_host_name("example.com").unwrap(),
            ),
        )
        .await
        .unwrap();
        client.close();
        let Err(StartOutgoingError::EndpointClosed { half, .. }) = outgoing.start() else {
            panic!("a closed endpoint starts no connection");
        };
        assert!(matches!(
            half.start(),
            Err(StartOutgoingError::EndpointClosed { .. })
        ));
        assert!(matches!(
            handle
                .connect(
                    server.address,
                    ServerTarget::from_host_name("example.com").unwrap()
                )
                .await,
            Err(BindingHandleConnectError::EndpointClosed(_))
        ));
        let (server_reflow, server_driver) = server.drivers;
        within("the server's reflow driver ends", server_reflow)
            .await
            .unwrap();
        within("the server's binding driver ends", server_driver)
            .await
            .unwrap();
    });
}

#[test]
fn thresholds_finer_than_the_clock_give_the_outgoing_connection_back() {
    run(async {
        let server = server();
        let labels = Arc::new(RecordedLabels::default());
        let (client, _client_reflow) =
            Endpoint::<Udp, NoServer, Client>::new(endpoint_config((), client_config(&labels)))
                .unwrap();
        let (handle, _client_driver) = client
            .add_connect_only_binding(bind(), BindingDeclarations::default())
            .unwrap();
        let mut outgoing = within(
            "the client takes a link",
            handle.connect(
                server.address,
                ServerTarget::from_host_name("example.com").unwrap(),
            ),
        )
        .await
        .unwrap();

        // Made against a clock finer than the endpoint's, of 1 ms.
        let fine = Duration::from_micros(100);
        let fine = LossThresholds::new(
            PacketThreshold::RECOMMENDED,
            RECOMMENDED_TIME_THRESHOLD,
            fine,
            fine,
        )
        .unwrap();
        *outgoing.config_mut() = client_config_with(&labels, fine);
        let Err(StartOutgoingError::TimerGranularity { mut half, source }) = outgoing.start()
        else {
            panic!("thresholds finer than the clock start no connection");
        };
        assert_eq!(source.clock_granularity(), Duration::from_millis(1));

        *half.config_mut() = client_config(&labels);
        assert!(half.start().is_ok());
    });
}

#[test]
fn a_datagram_of_an_unknown_version_gets_a_version_negotiation_packet() {
    run(async {
        let server = server();
        let _incoming = server.endpoint.incoming();
        let peer = bind();
        let link = within("a link to the server", peer.connect(server.address))
            .await
            .unwrap();
        // A long header of version 0x1a2a3a4a, with an eight-byte destination
        // and a four-byte source connection ID, padded to 1200 bytes.
        let mut datagram = vec![0xc0, 0x1a, 0x2a, 0x3a, 0x4a, 8];
        datagram.extend([0xd1; 8]);
        datagram.push(4);
        datagram.extend([0x5c; 4]);
        datagram.resize(1200, 0);
        let batch = [OutgoingDatagram {
            payload: Bytes::from(datagram),
            ecn: EcnMarking::NotEct,
        }];
        within("the datagram is sent", link.send(&batch))
            .await
            .unwrap();

        let answer = within("an answer arrives", link.recv()).await.unwrap();
        let answer = answer.payload();
        assert_eq!(answer[0] & 0xc0, 0xc0, "a long header with the 0x40 bit");
        assert_eq!(
            &answer[1..5],
            &[0, 0, 0, 0],
            "version 0: Version Negotiation"
        );
        assert_eq!(answer[5], 4);
        assert_eq!(
            &answer[6..10],
            &[0x5c; 4],
            "the client's source connection ID"
        );
        assert_eq!(answer[10], 8);
        assert_eq!(&answer[11..19], &[0xd1; 8]);
        let versions: Vec<u32> = answer[19..]
            .chunks(4)
            .map(|v| u32::from_be_bytes(v.try_into().unwrap()))
            .collect();
        assert_eq!(versions[0], 1, "version 1 is offered");
        assert_eq!(versions.len(), 2, "with one reserved version");
        assert_eq!(versions[1] & 0x0f0f_0f0f, 0x0a0a_0a0a);
    });
}

/// A long header packet of version 1 that fills a datagram of `len` bytes:
/// an Initial with an empty token when `initial`, otherwise 0-RTT; its
/// protected fields are made up.
fn long_packet(initial: bool, dcid: &[u8], scid: &[u8], len: usize) -> Bytes {
    let mut packet = vec![if initial { 0xc0 } else { 0xd0 }, 0, 0, 0, 1];
    packet.push(dcid.len() as u8);
    packet.extend_from_slice(dcid);
    packet.push(scid.len() as u8);
    packet.extend_from_slice(scid);
    if initial {
        packet.push(0);
    }
    let rest = len - packet.len() - 2;
    packet.extend([0x40 | (rest >> 8) as u8, rest as u8]);
    packet.resize(len, 0x2c);
    Bytes::from(packet)
}

async fn send_on(link: &UdpLink<TokioClock>, payload: Bytes) {
    let batch = [OutgoingDatagram {
        payload,
        ecn: EcnMarking::NotEct,
    }];
    within("the datagram is sent", link.send(&batch))
        .await
        .unwrap();
}

#[test]
fn an_incoming_connection_born_from_zero_rtt_waits_for_its_initial() {
    run(async {
        let server = server();
        let mut incoming = server.endpoint.incoming();
        let peer = bind();
        let link = within("a link to the server", peer.connect(server.address))
            .await
            .unwrap();
        let dcid = [0x0d; 8];
        send_on(&link, long_packet(false, &dcid, &[0x5c; 4], 100)).await;
        let Some(Incoming::Terminable(half)) =
            within("an incoming connection", incoming.next()).await
        else {
            panic!("the server endpoint ends before a connection comes");
        };
        assert!(half.facts().born_from_zero_rtt);
        let mut arrived = pin!(half.initial_arrived());

        // An Initial with another source connection ID belongs to another
        // attempt: it makes an incoming connection of its own.
        send_on(&link, long_packet(true, &dcid, &[0x77; 4], 1200)).await;
        let other = within(
            "another incoming connection",
            futures_util::future::select(arrived.as_mut(), incoming.next()),
        )
        .await;
        let futures_util::future::Either::Right((Some(Incoming::Terminable(other)), _)) = other
        else {
            panic!("the Initial of another attempt completed the wait");
        };
        assert!(!other.facts().born_from_zero_rtt);

        // The client's Initial, too small, is dropped; at 1200 bytes it
        // arrives.
        send_on(&link, long_packet(true, &dcid, &[0x5c; 4], 600)).await;
        send_on(&link, long_packet(true, &dcid, &[0x5c; 4], 1200)).await;
        let half = within("the Initial arrives", arrived).await;
        assert_eq!(
            half.facts().token,
            sakuya_endpoint::stateless_check::ReturnedToken::Absent
        );
        assert_eq!(
            server
                .endpoint
                .dropped_input_counts()
                .late_initial_queue_full,
            0
        );
        drop((half, other));
    });
}

/// A version 1 Initial that fills a datagram of `len` bytes and carries
/// `token`; its protected fields are made up.
fn initial_with_token(dcid: &[u8], scid: &[u8], token: &[u8], len: usize) -> Bytes {
    let mut packet = vec![0xc0, 0, 0, 0, 1];
    packet.push(dcid.len() as u8);
    packet.extend_from_slice(dcid);
    packet.push(scid.len() as u8);
    packet.extend_from_slice(scid);
    // A two-byte variable-length integer (RFC 9000 §16).
    packet.extend([0x40 | (token.len() >> 8) as u8, token.len() as u8]);
    packet.extend_from_slice(token);
    let rest = len - packet.len() - 2;
    packet.extend([0x40 | (rest >> 8) as u8, rest as u8]);
    packet.resize(len, 0x2c);
    Bytes::from(packet)
}

/// The destination and source connection IDs and the token of the Retry
/// `packet`, whose integrity tag is checked against `original_dcid`.
fn read_retry(packet: &[u8], original_dcid: &ConnectionId) -> (ConnectionId, ConnectionId, Bytes) {
    use sakuya_wire::{
        header::codec::read_long_header,
        v1::header::{LongPacketType, TypeFields, codec::read_long_packet},
    };
    verify_retry_integrity_tag(&RingBackend, original_dcid, packet)
        .expect("the integrity tag binds the original destination connection ID");
    let mut input = packet;
    let header = read_long_header(&mut input).unwrap();
    let read = read_long_packet(&mut input, header).unwrap();
    assert_eq!(read.packet_type(), LongPacketType::Retry);
    let TypeFields::Retry { token, .. } = read.fields() else {
        panic!("expected Retry fields, got {:?}", read.fields());
    };
    (*read.dcid(), *read.scid(), Bytes::copy_from_slice(token))
}

#[test]
fn a_retried_connection_comes_back_with_its_token() {
    run(async {
        let server = server();
        let mut incoming = server.endpoint.incoming();
        let peer = bind();
        let link = within("a link to the server", peer.connect(server.address))
            .await
            .unwrap();
        let dcid = [0x0d; 8];
        let original_dcid = ConnectionId::new(&dcid).unwrap();
        send_on(&link, long_packet(true, &dcid, &[0x5c; 4], 1200)).await;
        let Some(Incoming::Terminable(half)) =
            within("an incoming connection", incoming.next()).await
        else {
            panic!("the server endpoint ends before a connection comes");
        };
        assert_eq!(half.facts().token, ReturnedToken::Absent);
        assert!(within("the Retry is sent", half.retry()).await.is_ok());

        let answer = within("the Retry arrives", link.recv()).await.unwrap();
        let (retry_dcid, retry_scid, token) = read_retry(answer.payload(), &original_dcid);
        assert_eq!(retry_dcid, ConnectionId::new(&[0x5c; 4]).unwrap());
        assert_ne!(retry_scid, original_dcid);
        assert!(!token.is_empty());

        // The client's next Initial, to the Retry's source connection ID and
        // with its token, makes another incoming connection.
        send_on(
            &link,
            initial_with_token(retry_scid.as_bytes(), &[0x5c; 4], &token, 1200),
        )
        .await;
        let Some(Incoming::Terminable(retried)) =
            within("the retried connection", incoming.next()).await
        else {
            panic!("the server endpoint ends before the retried connection comes");
        };
        assert_eq!(
            retried.facts().token,
            ReturnedToken::Retry {
                original_dcid,
                retry_scid,
            }
        );
        let Err(RetryError::AlreadyRetried(retried)) =
            within("the second Retry is refused", retried.retry()).await
        else {
            panic!("a client that returned a Retry token is retried again");
        };
        drop(retried);
    });
}

#[test]
fn a_client_goes_on_after_a_retry_and_completes_its_handshake() {
    run(async {
        let server = server();
        let mut incoming = server.endpoint.incoming();

        let labels = Arc::new(RecordedLabels::default());
        let (client, client_reflow) =
            Endpoint::<Udp, NoServer, Client>::new(endpoint_config((), client_config(&labels)))
                .unwrap();
        let client_reflow = tokio::task::spawn_local(client_reflow);
        let (client_handle, client_driver) = client
            .add_connect_only_binding(bind(), BindingDeclarations::default())
            .unwrap();
        let client_driver = tokio::task::spawn_local(client_driver);
        let outgoing = within(
            "the client takes a link",
            client_handle.connect(
                server.address,
                ServerTarget::from_host_name("example.com").unwrap(),
            ),
        )
        .await
        .unwrap();
        let client_connection = Rc::new(RefCell::new(outgoing.start().unwrap()));
        let client_conn = ConnectionHandle::new(client_connection.clone());
        let client_connection =
            tokio::task::spawn_local(SharedConnectionDriver::new(client_connection));

        let Some(Incoming::Terminable(half)) =
            within("an incoming connection", incoming.next()).await
        else {
            panic!("the server endpoint ends before a connection comes");
        };
        assert!(within("the Retry is sent", half.retry()).await.is_ok());
        // The client sends its ClientHello again, to the Retry's source
        // connection ID and with its token.
        let Some(Incoming::Terminable(retried)) =
            within("the retried connection", incoming.next()).await
        else {
            panic!("the server endpoint ends before the retried connection comes");
        };
        assert!(matches!(retried.facts().token, ReturnedToken::Retry { .. }));
        let server_connection = Rc::new(RefCell::new(retried.accept().unwrap()));
        let server_conn = ConnectionHandle::new(server_connection.clone());
        let server_connection =
            tokio::task::spawn_local(SharedConnectionDriver::new(server_connection));

        // The server's transport parameters state the Retry, which the
        // client checks.
        within(
            "the client's handshake completes",
            client_conn.handshake_completed(),
        )
        .await
        .expect("the client's handshake completed");
        within(
            "the server's handshake completes",
            server_conn.handshake_completed(),
        )
        .await
        .expect("the server's handshake completed");

        client_conn.close(AppClose(7));
        within("the client's close", client_conn.closed()).await;
        within("the server's close", server_conn.closed()).await;
        within("the client's connection ends", client_connection)
            .await
            .unwrap();
        within("the server's connection ends", server_connection)
            .await
            .unwrap();
        drop(incoming);
        server.endpoint.close();
        client.close();
        let (reflow, driver) = server.drivers;
        within("the server's drivers end", async {
            reflow.await.unwrap();
            driver.await.unwrap();
        })
        .await;
        within("the client's binding driver ends", client_driver)
            .await
            .unwrap();
        within("the client's reflow driver ends", client_reflow)
            .await
            .unwrap();
    });
}

#[test]
fn a_client_answered_by_version_negotiation_ends_with_the_versions_listed() {
    run(async {
        // a server of no version this client supports, on a plain socket
        let socket = std::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        socket.set_nonblocking(true).unwrap();
        let address = socket.local_addr().unwrap();

        let labels = Arc::new(RecordedLabels::default());
        let (client, client_reflow) =
            Endpoint::<Udp, NoServer, Client>::new(endpoint_config((), client_config(&labels)))
                .unwrap();
        let client_reflow = tokio::task::spawn_local(client_reflow);
        let (client_handle, client_driver) = client
            .add_connect_only_binding(bind(), BindingDeclarations::default())
            .unwrap();
        let client_driver = tokio::task::spawn_local(client_driver);
        let outgoing = within(
            "the client takes a link",
            client_handle.connect(
                address,
                ServerTarget::from_host_name("example.com").unwrap(),
            ),
        )
        .await
        .unwrap();
        let client_connection = Rc::new(RefCell::new(outgoing.start().unwrap()));
        let client_conn = ConnectionHandle::new(client_connection.clone());
        let client_connection =
            tokio::task::spawn_local(SharedConnectionDriver::new(client_connection));

        let mut buffer = [0; 2048];
        let (_, from) = within("the client's Initial", async {
            loop {
                match socket.recv_from(&mut buffer) {
                    Ok(received) => break received,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                    Err(error) => panic!("{error}"),
                }
            }
        })
        .await;
        let dcid_len = usize::from(buffer[5]);
        let dcid = buffer[6..6 + dcid_len].to_vec();
        let scid_len = usize::from(buffer[6 + dcid_len]);
        let scid = buffer[7 + dcid_len..7 + dcid_len + scid_len].to_vec();
        // the connection IDs echoed (RFC 9000 §17.2.1), and two versions
        // that are not 1
        let mut answer = vec![0xc0, 0, 0, 0, 0, u8::try_from(scid_len).unwrap()];
        answer.extend_from_slice(&scid);
        answer.push(u8::try_from(dcid_len).unwrap());
        answer.extend_from_slice(&dcid);
        answer.extend_from_slice(&[0x6b, 0x33, 0x43, 0xcf, 0x0a, 0x1a, 0x2a, 0x3a]);
        socket.send_to(&answer, from).unwrap();

        let CloseReason::VersionNegotiation { versions } =
            within("the client's end", client_conn.closed()).await
        else {
            panic!("the client ends for the Version Negotiation packet");
        };
        assert_eq!(
            versions
                .iter()
                .map(|version| version.get())
                .collect::<Vec<_>>(),
            [0x6b33_43cf, 0x0a1a_2a3a]
        );
        within("the client's connection ends", client_connection)
            .await
            .unwrap();
        client.close();
        within("the client's binding driver ends", client_driver)
            .await
            .unwrap();
        within("the client's reflow driver ends", client_reflow)
            .await
            .unwrap();
    });
}

#[test]
fn a_connection_born_from_zero_rtt_is_retried_once_its_initial_arrived() {
    run(async {
        let server = server();
        let mut incoming = server.endpoint.incoming();
        let peer = bind();
        let link = within("a link to the server", peer.connect(server.address))
            .await
            .unwrap();
        let dcid = [0x0d; 8];
        // Three times this datagram is less than a Retry.
        send_on(&link, long_packet(false, &dcid, &[0x5c; 4], 30)).await;
        let Some(Incoming::Terminable(half)) =
            within("an incoming connection", incoming.next()).await
        else {
            panic!("the server endpoint ends before a connection comes");
        };
        assert!(half.facts().born_from_zero_rtt);
        let Err(RetryError::AmplificationLimited(half)) =
            within("the Retry is refused", half.retry()).await
        else {
            panic!("a Retry beyond three times the bytes received is sent");
        };

        let arrived = half.initial_arrived();
        send_on(&link, long_packet(true, &dcid, &[0x5c; 4], 1200)).await;
        let half = within("the Initial arrives", arrived).await;
        assert!(within("the Retry is sent", half.retry()).await.is_ok());
        let answer = within("the Retry arrives", link.recv()).await.unwrap();
        read_retry(answer.payload(), &ConnectionId::new(&dcid).unwrap());
    });
}

#[test]
fn a_closed_endpoint_sends_no_retry() {
    run(async {
        let server = server();
        let mut incoming = server.endpoint.incoming();
        let peer = bind();
        let link = within("a link to the server", peer.connect(server.address))
            .await
            .unwrap();
        send_on(&link, long_packet(true, &[0x0d; 8], &[0x5c; 4], 1200)).await;
        let Some(Incoming::Terminable(half)) =
            within("an incoming connection", incoming.next()).await
        else {
            panic!("the server endpoint ends before a connection comes");
        };
        server.endpoint.close();
        assert!(matches!(
            within("the Retry is refused", half.retry()).await,
            Err(RetryError::EndpointClosed { .. })
        ));
    });
}

/// The tokens of [`aead_tokens`] on an endpoint whose peers they cannot bind
/// a token to.
#[derive(Clone)]
struct UnbindingTokens(AeadAddressTokens<AwsLcBackend>);

impl<Peer: PeerAddressCodec + Eq> AddressTokens<Peer> for UnbindingTokens {
    type NewTokenIssuer = <AeadAddressTokens<AwsLcBackend> as AddressTokens<Peer>>::NewTokenIssuer;

    fn new_token_issuer(&self) -> Self::NewTokenIssuer {
        AddressTokens::<Peer>::new_token_issuer(&self.0)
    }

    fn binds(&self, _: &Peer) -> bool {
        false
    }

    fn issue_retry(
        &self,
        peer: &Peer,
        original_dcid: &ConnectionId,
        now: UtcDateTime,
    ) -> Result<Bytes, nitori_crypto::RandomError> {
        self.0.issue_retry(peer, original_dcid, now)
    }

    fn validate(&self, token: &[u8], peer: &Peer, now: UtcDateTime) -> TokenOutcome {
        self.0.validate(token, peer, now)
    }
}

type ServerWithTokens<Tk> =
    AcceptingServer<Mine, Parts, ServerStarts, Tk, LoadStatelessRetryPolicy>;

/// A server endpoint on `tokens`, and the incoming connection that a client's
/// Initial makes on it; the endpoint and the client's link are kept alive
/// with it.
async fn incoming_on<Tk>(
    tokens: Tk,
) -> (
    Endpoint<Udp, ServerWithTokens<Tk>, NoClient>,
    UdpLink<TokioClock>,
    TerminableIncoming<Udp, ServerWithTokens<Tk>>,
)
where
    Tk: AddressTokens<PeerOf<Udp>, NewTokenIssuer = AeadNewTokenIssuer<AwsLcBackend>>
        + Clone
        + 'static,
{
    let (endpoint, reflow) = Endpoint::<Udp, ServerWithTokens<Tk>, NoClient>::new(endpoint_config(
        server_config_with(tokens),
        (),
    ))
    .unwrap();
    let _reflow = tokio::task::spawn_local(reflow);
    let socket = bind();
    let address = socket.local_address();
    let (_handle, driver) = endpoint
        .add_accepting_binding(socket, BindingDeclarations::default())
        .unwrap();
    let _driver = tokio::task::spawn_local(driver);
    let mut incoming = endpoint.incoming();
    let peer = bind();
    let link = within("a link to the server", peer.connect(address))
        .await
        .unwrap();
    send_on(&link, long_packet(true, &[0x0d; 8], &[0x5c; 4], 1200)).await;
    let Some(Incoming::Terminable(half)) = within("an incoming connection", incoming.next()).await
    else {
        panic!("the server endpoint ends before a connection comes");
    };
    (endpoint, link, half)
}

/// Refuses `half`, which shows that its registration is still there.
async fn assert_refusable<Tk>(half: TerminableIncoming<Udp, ServerWithTokens<Tk>>)
where
    Tk: AddressTokens<PeerOf<Udp>, NewTokenIssuer = AeadNewTokenIssuer<AwsLcBackend>>
        + Clone
        + 'static,
{
    let refused = half.refuse(TransportImmediateClose {
        code: TransportErrorCode::CONNECTION_REFUSED,
        frame_type: None,
        reason_phrase: Bytes::from_static(b"not now"),
    });
    assert!(within("the refusal is sent", refused).await.is_ok());
}

#[test]
fn a_peer_a_token_cannot_be_bound_to_gets_no_retry() {
    run(async {
        let (_endpoint, _link, half) = incoming_on(UnbindingTokens(aead_tokens())).await;
        assert!(matches!(
            within("the Retry is refused", half.retry()).await,
            Err(RetryError::UnbindablePeer(_))
        ));
    });
}

/// What [`FaultyTokens`] does instead of issuing a Retry token.
#[derive(Clone, Copy)]
enum Fault {
    /// The random source fails.
    Random,
    /// The token is empty.
    Empty,
}

/// The tokens of [`aead_tokens`], except that issuing a Retry token goes
/// wrong as `fault` says.
#[derive(Clone)]
struct FaultyTokens {
    inner: AeadAddressTokens<AwsLcBackend>,
    fault: Fault,
}

impl AddressTokens<PeerOf<Udp>> for FaultyTokens {
    type NewTokenIssuer =
        <AeadAddressTokens<AwsLcBackend> as AddressTokens<PeerOf<Udp>>>::NewTokenIssuer;

    fn new_token_issuer(&self) -> Self::NewTokenIssuer {
        AddressTokens::<PeerOf<Udp>>::new_token_issuer(&self.inner)
    }

    fn binds(&self, peer: &PeerOf<Udp>) -> bool {
        self.inner.binds(peer)
    }

    fn issue_retry(
        &self,
        _: &PeerOf<Udp>,
        _: &ConnectionId,
        _: UtcDateTime,
    ) -> Result<Bytes, nitori_crypto::RandomError> {
        match self.fault {
            Fault::Random => Err(nitori_crypto::RandomError),
            Fault::Empty => Ok(Bytes::new()),
        }
    }

    fn validate(&self, token: &[u8], peer: &PeerOf<Udp>, now: UtcDateTime) -> TokenOutcome {
        self.inner.validate(token, peer, now)
    }
}

/// A token source that fails to issue gets no Retry sent, and gives the
/// incoming connection back, which can still be refused.
#[test]
fn a_failing_random_source_gets_no_retry() {
    run(async {
        let tokens = FaultyTokens {
            inner: aead_tokens(),
            fault: Fault::Random,
        };
        let (_endpoint, _link, half) = incoming_on(tokens).await;
        let Err(RetryError::Random { half, .. }) =
            within("the Retry is refused", half.retry()).await
        else {
            panic!("a failing random source sends a Retry");
        };
        assert_refusable(half).await;
    });
}

/// An empty Retry token cannot be encoded: no Retry is sent, and the
/// incoming connection is given back, which can still be refused.
#[test]
fn an_empty_retry_token_gets_no_retry() {
    run(async {
        let tokens = FaultyTokens {
            inner: aead_tokens(),
            fault: Fault::Empty,
        };
        let (_endpoint, _link, half) = incoming_on(tokens).await;
        let Err(RetryError::Encode { half, source }) =
            within("the Retry is refused", half.retry()).await
        else {
            panic!("an empty token is encoded into a Retry");
        };
        assert!(matches!(source, EncodeStatelessRetryError::EmptyToken));
        assert_refusable(half).await;
    });
}

// ---- 0-RTT ----

/// What the client sends in 0-RTT.
const EARLY_REQUEST: &[u8] = b"a request in 0-RTT";
/// What the server answers.
const EARLY_ANSWER: &[u8] = b"an answer to 0-RTT";

/// Starts the client's connection to `address` on `handle`, and gives the
/// handle of the connection and its driver.
macro_rules! connect {
    ($handle:expr, $address:expr) => {{
        let outgoing = within(
            "the client takes a link",
            $handle.connect(
                $address,
                ServerTarget::from_host_name("example.com").unwrap(),
            ),
        )
        .await
        .unwrap();
        let connection = Rc::new(RefCell::new(outgoing.start().unwrap()));
        let handle = ConnectionHandle::new(connection.clone());
        let driver = tokio::task::spawn_local(SharedConnectionDriver::new(connection));
        (handle, driver)
    }};
}

/// Accepts a terminable incoming connection, and gives the handle of the
/// connection and its driver.
macro_rules! accept {
    ($half:expr) => {{
        let connection = Rc::new(RefCell::new($half.accept().unwrap()));
        let handle = ConnectionHandle::new(connection.clone());
        let driver = tokio::task::spawn_local(SharedConnectionDriver::new(connection));
        (handle, driver)
    }};
}

/// The next incoming connection, terminable.
macro_rules! next_incoming {
    ($incoming:expr) => {
        match within("an incoming connection", $incoming.next()).await {
            Some(Incoming::Terminable(half)) => half,
            _ => panic!("the server endpoint ends before a connection comes"),
        }
    };
}

/// A first connection from `client_handle` to `address`, which ends after
/// the client stored a ticket: what the second connection resumes.
macro_rules! first_connection {
    ($client_handle:expr, $address:expr, $incoming:expr, $stored:expr) => {{
        let (client_conn, client_driver) = connect!($client_handle, $address);
        let half = next_incoming!($incoming);
        let (server_conn, server_driver) = accept!(half);
        within(
            "the client's handshake completes",
            client_conn.handshake_completed(),
        )
        .await
        .expect("the client's handshake completed");
        within(
            "the server's handshake completes",
            server_conn.handshake_completed(),
        )
        .await
        .expect("the server's handshake completed");
        // the server's NewSessionTicket comes after its Finished
        within(
            "a ticket is stored",
            $stored.wait_for(|stored| *stored >= 1),
        )
        .await
        .unwrap();
        client_conn.close(AppClose(1));
        within("the client's close", client_conn.closed()).await;
        within("the server's close", server_conn.closed()).await;
        within("the client's connection ends", client_driver)
            .await
            .unwrap();
        within("the server's connection ends", server_driver)
            .await
            .unwrap();
    }};
}

/// The client writes `EARLY_REQUEST` on a new stream of `layer` and ends it,
/// and reads the answer to its end.
macro_rules! request_and_read_answer {
    ($layer:expr) => {{
        let (mut writer, mut reader) = within("a stream opens", $layer.open_bi())
            .await
            .expect("the early layer opens a stream");
        within(
            "the request is written",
            writer.write_all_unpin(Bytes::from_static(EARLY_REQUEST)),
        )
        .await
        .expect("the request is written");
        writer.close().expect("the request ends");
        let mut answer = Vec::new();
        while let Some(chunk) = within(
            "the answer is read",
            reader.read_chunk_unpin(NonZeroUsize::new(1024).unwrap()),
        )
        .await
        .expect("the answer is read")
        {
            answer.extend_from_slice(&chunk);
        }
        answer
    }};
}

/// The server accepts a stream on `layer`, reads the request to its end and
/// answers with `EARLY_ANSWER`.
macro_rules! read_request_and_answer {
    ($layer:expr) => {{
        let (mut writer, mut reader) = within("a stream is accepted", $layer.accept_bi())
            .await
            .expect("the layer accepts a stream");
        let mut request = Vec::new();
        while let Some(chunk) = within(
            "the request is read",
            reader.read_chunk_unpin(NonZeroUsize::new(1024).unwrap()),
        )
        .await
        .expect("the request is read")
        {
            request.extend_from_slice(&chunk);
        }
        within(
            "the answer is written",
            writer.write_all_unpin(Bytes::from_static(EARLY_ANSWER)),
        )
        .await
        .expect("the answer is written");
        writer.close().expect("the answer ends");
        request
    }};
}

#[test]
fn a_resuming_client_sends_a_request_in_0rtt_that_the_server_accepts() {
    run(async {
        let tickets = ServerStarts::new(true);
        let server = server_on(resuming_server_config(tickets, aead_tokens(), 16 << 20));
        let mut incoming = server.endpoint.incoming();
        let labels = Arc::new(RecordedLabels::default());
        let starts = ClientStarts::new(&labels);
        let mut stored = starts.tickets.stored.subscribe();
        let (client, client_reflow) = Endpoint::<Udp, NoServer, Client>::new(endpoint_config(
            (),
            resuming_client_config(starts),
        ))
        .unwrap();
        let client_reflow = tokio::task::spawn_local(client_reflow);
        let (client_handle, client_driver) = client
            .add_connect_only_binding(bind(), BindingDeclarations::default())
            .unwrap();
        let client_driver = tokio::task::spawn_local(client_driver);

        first_connection!(client_handle, server.address, incoming, stored);

        // the second connection resumes
        let (client_conn, client_task) = connect!(client_handle, server.address);
        let early = within("the client's early layer", client_conn.early())
            .await
            .expect("the connection is open")
            .expect("the client offers 0-RTT");
        let client_exchange =
            tokio::task::spawn_local(async move { request_and_read_answer!(early) });

        let half = next_incoming!(incoming);
        // the client's Initial came first, with its 0-RTT behind it
        assert!(!half.facts().born_from_zero_rtt);
        let (server_conn, server_task) = accept!(half);
        let server_early = within("the server's early layer", server_conn.early())
            .await
            .expect("the connection is open")
            .expect("the server accepts 0-RTT");
        let request = read_request_and_answer!(server_early);
        assert_eq!(request, EARLY_REQUEST);
        let answer = within("the client's exchange", client_exchange)
            .await
            .unwrap();
        assert_eq!(answer, EARLY_ANSWER);

        let facts = within(
            "the client's handshake completes",
            client_conn.handshake_completed(),
        )
        .await
        .expect("the client's handshake completed");
        assert_eq!(facts.early_data, EarlyDataOutcome::Accepted);
        let facts = within(
            "the server's handshake completes",
            server_conn.handshake_completed(),
        )
        .await
        .expect("the server's handshake completed");
        assert!(facts.resumed);

        client_conn.close(AppClose(7));
        within("the client's close", client_conn.closed()).await;
        within("the server's close", server_conn.closed()).await;
        within("the client's connection ends", client_task)
            .await
            .unwrap();
        within("the server's connection ends", server_task)
            .await
            .unwrap();

        drop(incoming);
        server.endpoint.close();
        client.close();
        let (reflow, driver) = server.drivers;
        within("the server's drivers end", async {
            reflow.await.unwrap();
            driver.await.unwrap();
        })
        .await;
        within("the client's binding driver ends", client_driver)
            .await
            .unwrap();
        within("the client's reflow driver ends", client_reflow)
            .await
            .unwrap();
    });
}

#[test]
fn a_resuming_client_goes_on_with_its_0rtt_after_a_retry() {
    run(async {
        let tickets = ServerStarts::new(true);
        let server = server_on(resuming_server_config(tickets, aead_tokens(), 16 << 20));
        let mut incoming = server.endpoint.incoming();
        let labels = Arc::new(RecordedLabels::default());
        let starts = ClientStarts::new(&labels);
        let mut stored = starts.tickets.stored.subscribe();
        let (client, client_reflow) = Endpoint::<Udp, NoServer, Client>::new(endpoint_config(
            (),
            resuming_client_config(starts),
        ))
        .unwrap();
        let client_reflow = tokio::task::spawn_local(client_reflow);
        let (client_handle, client_driver) = client
            .add_connect_only_binding(bind(), BindingDeclarations::default())
            .unwrap();
        let client_driver = tokio::task::spawn_local(client_driver);

        first_connection!(client_handle, server.address, incoming, stored);

        let (client_conn, client_task) = connect!(client_handle, server.address);
        let early = within("the client's early layer", client_conn.early())
            .await
            .expect("the connection is open")
            .expect("the client offers 0-RTT");
        let client_exchange =
            tokio::task::spawn_local(async move { request_and_read_answer!(early) });

        // the server retries the second connection
        let half = next_incoming!(incoming);
        assert!(within("the Retry is sent", half.retry()).await.is_ok());
        // The client's 0-RTT packets to the connection ID it first used
        // may arrive after the Retry: each makes an incoming connection of
        // its own, which is dropped.
        let retried = loop {
            let next = next_incoming!(incoming);
            if matches!(next.facts().token, ReturnedToken::Retry { .. }) {
                break next;
            }
            assert!(next.facts().born_from_zero_rtt, "{:?}", next.facts());
        };
        let (server_conn, server_task) = accept!(retried);
        let server_early = within("the server's early layer", server_conn.early())
            .await
            .expect("the connection is open")
            .expect("the server accepts 0-RTT");
        let request = read_request_and_answer!(server_early);
        assert_eq!(request, EARLY_REQUEST);
        let answer = within("the client's exchange", client_exchange)
            .await
            .unwrap();
        assert_eq!(answer, EARLY_ANSWER);

        let facts = within(
            "the client's handshake completes",
            client_conn.handshake_completed(),
        )
        .await
        .expect("the client's handshake completed");
        assert_eq!(facts.early_data, EarlyDataOutcome::Accepted);
        within(
            "the server's handshake completes",
            server_conn.handshake_completed(),
        )
        .await
        .expect("the server's handshake completed");

        client_conn.close(AppClose(7));
        within("the client's close", client_conn.closed()).await;
        within("the server's close", server_conn.closed()).await;
        within("the client's connection ends", client_task)
            .await
            .unwrap();
        within("the server's connection ends", server_task)
            .await
            .unwrap();

        drop(incoming);
        server.endpoint.close();
        client.close();
        let (reflow, driver) = server.drivers;
        within("the server's drivers end", async {
            reflow.await.unwrap();
            driver.await.unwrap();
        })
        .await;
        within("the client's binding driver ends", client_driver)
            .await
            .unwrap();
        within("the client's reflow driver ends", client_reflow)
            .await
            .unwrap();
    });
}

#[test]
fn a_server_that_lowered_a_limit_rejects_0rtt_and_the_client_asks_again_on_a_new_layer() {
    run(async {
        let tokens = aead_tokens();
        // both servers resume from one table of tickets
        let tickets = ServerStarts::new(true);
        let first = server_on(resuming_server_config(
            tickets.clone(),
            tokens.clone(),
            16 << 20,
        ));
        let mut first_incoming = first.endpoint.incoming();
        let lowered = server_on(resuming_server_config(tickets, tokens, 8 << 20));
        let mut incoming = lowered.endpoint.incoming();
        let labels = Arc::new(RecordedLabels::default());
        let starts = ClientStarts::new(&labels);
        let mut stored = starts.tickets.stored.subscribe();
        let (client, client_reflow) = Endpoint::<Udp, NoServer, Client>::new(endpoint_config(
            (),
            resuming_client_config(starts),
        ))
        .unwrap();
        let client_reflow = tokio::task::spawn_local(client_reflow);
        let (client_handle, client_driver) = client
            .add_connect_only_binding(bind(), BindingDeclarations::default())
            .unwrap();
        let client_driver = tokio::task::spawn_local(client_driver);

        first_connection!(client_handle, first.address, first_incoming, stored);

        let (client_conn, client_task) = connect!(client_handle, lowered.address);
        let early = within("the client's early layer", client_conn.early())
            .await
            .expect("the connection is open")
            .expect("the client offers 0-RTT");
        // the request in 0-RTT fails once the early layer ends
        let ended = early.clone();
        let client_early = tokio::task::spawn_local(async move {
            let Ok((mut writer, _reader)) = early.open_bi().await else {
                return;
            };
            let _ = writer
                .write_all_unpin(Bytes::from_static(EARLY_REQUEST))
                .await;
            let _ = writer.close();
        });

        let half = next_incoming!(incoming);
        let (server_conn, server_task) = accept!(half);

        let end = within("the client's early layer ends", ended.ended()).await;
        assert!(
            matches!(end, LayerEnd::ZeroRttRejected),
            "the early layer ended with {end:?}"
        );
        within("the client's request in 0-RTT", client_early)
            .await
            .unwrap();
        // the layer after the handshake is a new one, on which the request
        // goes again
        let layer = within("the client's layer", client_conn.established())
            .await
            .expect("the client's handshake completed");
        let client_exchange =
            tokio::task::spawn_local(async move { request_and_read_answer!(layer) });
        let server_layer = within("the server's layer", server_conn.established())
            .await
            .expect("the server's handshake completed");
        let request = read_request_and_answer!(server_layer);
        assert_eq!(request, EARLY_REQUEST);
        let answer = within("the client's exchange", client_exchange)
            .await
            .unwrap();
        assert_eq!(answer, EARLY_ANSWER);
        let facts = within(
            "the client's handshake completes",
            client_conn.handshake_completed(),
        )
        .await
        .expect("the client's handshake completed");
        assert_eq!(facts.early_data, EarlyDataOutcome::Rejected);

        client_conn.close(AppClose(7));
        within("the client's close", client_conn.closed()).await;
        within("the server's close", server_conn.closed()).await;
        within("the client's connection ends", client_task)
            .await
            .unwrap();
        within("the server's connection ends", server_task)
            .await
            .unwrap();

        drop((incoming, first_incoming));
        first.endpoint.close();
        lowered.endpoint.close();
        client.close();
        for server in [first, lowered] {
            let (reflow, driver) = server.drivers;
            within("the server's drivers end", async {
                reflow.await.unwrap();
                driver.await.unwrap();
            })
            .await;
        }
        within("the client's binding driver ends", client_driver)
            .await
            .unwrap();
        within("the client's reflow driver ends", client_reflow)
            .await
            .unwrap();
    });
}

/// How much the client writes in its early layer to a server that raised
/// its limit: more than the remembered `initial_max_data` lets through,
/// less than the raised one and the stream's.
const RAISED_WRITE: usize = 64 * 1024;

#[test]
fn a_server_that_raised_a_limit_accepts_0rtt_and_the_client_sends_to_the_new_limit() {
    run(async {
        let tokens = aead_tokens();
        // both servers resume from one table of tickets; the ticket is the
        // first one's, whose connection takes 1000 bytes
        let tickets = ServerStarts::new(true);
        let first = server_on(resuming_server_config(
            tickets.clone(),
            tokens.clone(),
            1000,
        ));
        let mut first_incoming = first.endpoint.incoming();
        let raised = server_on(resuming_server_config(tickets, tokens, 16 << 20));
        let mut incoming = raised.endpoint.incoming();
        let labels = Arc::new(RecordedLabels::default());
        let starts = ClientStarts::new(&labels);
        let mut stored = starts.tickets.stored.subscribe();
        let (client, client_reflow) = Endpoint::<Udp, NoServer, Client>::new(endpoint_config(
            (),
            resuming_client_config(starts),
        ))
        .unwrap();
        let client_reflow = tokio::task::spawn_local(client_reflow);
        let (client_handle, client_driver) = client
            .add_connect_only_binding(bind(), BindingDeclarations::default())
            .unwrap();
        let client_driver = tokio::task::spawn_local(client_driver);

        first_connection!(client_handle, first.address, first_incoming, stored);

        let (client_conn, client_task) = connect!(client_handle, raised.address);
        let early = within("the client's early layer", client_conn.early())
            .await
            .expect("the connection is open")
            .expect("the client offers 0-RTT");
        // the write ends only once the connection takes all of it: the
        // remembered limit holds it back until the server's of this
        // handshake are known, and the server reads nothing before
        let client_write = tokio::task::spawn_local(async move {
            let (mut writer, reader) = within("a stream opens", early.open_bi())
                .await
                .expect("the early layer opens a stream");
            within(
                "the client writes beyond the remembered limit",
                writer.write_all_unpin(Bytes::from(vec![7; RAISED_WRITE])),
            )
            .await
            .expect("the data is written");
            writer.close().expect("the stream ends");
            (writer, reader)
        });

        let half = next_incoming!(incoming);
        let (server_conn, server_task) = accept!(half);
        let server_early = within("the server's early layer", server_conn.early())
            .await
            .expect("the connection is open")
            .expect("the server accepts 0-RTT");
        let facts = within(
            "the client's handshake completes",
            client_conn.handshake_completed(),
        )
        .await
        .expect("the client's handshake completed");
        assert_eq!(facts.early_data, EarlyDataOutcome::Accepted);
        let kept = within("the client's write", client_write).await.unwrap();
        let (_writer, mut reader) = within("a stream is accepted", server_early.accept_bi())
            .await
            .expect("the layer accepts a stream");
        let mut read = 0;
        while let Some(chunk) = within(
            "the data is read",
            reader.read_chunk_unpin(NonZeroUsize::new(16 * 1024).unwrap()),
        )
        .await
        .expect("the data is read")
        {
            read += chunk.len();
        }
        assert_eq!(read, RAISED_WRITE);
        drop(kept);

        client_conn.close(AppClose(7));
        within("the client's close", client_conn.closed()).await;
        within("the server's close", server_conn.closed()).await;
        within("the client's connection ends", client_task)
            .await
            .unwrap();
        within("the server's connection ends", server_task)
            .await
            .unwrap();

        drop((incoming, first_incoming));
        first.endpoint.close();
        raised.endpoint.close();
        client.close();
        for server in [first, raised] {
            let (reflow, driver) = server.drivers;
            within("the server's drivers end", async {
                reflow.await.unwrap();
                driver.await.unwrap();
            })
            .await;
        }
        within("the client's binding driver ends", client_driver)
            .await
            .unwrap();
        within("the client's reflow driver ends", client_reflow)
            .await
            .unwrap();
    });
}

// ---- NEW_CONNECTION_ID in 0-RTT ----

/// Takes what the client's [`EagerConnectionIds`] did into `log` until
/// `done` holds of it.
async fn disclosed_until(
    what: &str,
    log: &mut Vec<Disclosed>,
    done: impl Fn(&[Disclosed]) -> bool,
) {
    within(what, async {
        loop {
            log.extend(take_disclosed());
            if done(log) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
}

/// Where `what` first is in `log`.
fn first_at(log: &[Disclosed], what: Disclosed) -> Option<usize> {
    log.iter().position(|each| *each == what)
}

/// A client that issues its connection IDs at once sends their
/// NEW_CONNECTION_ID frames in 0-RTT, up to the remembered limit of 4, and
/// the server that accepts it acknowledges them.
#[test]
fn a_client_sends_new_connection_id_in_0rtt_that_the_server_accepts() {
    run(async {
        let tickets = ServerStarts::new(true);
        let server = server_on(resuming_server_config_with_limit(
            tickets,
            aead_tokens(),
            16 << 20,
            4,
        ));
        let mut incoming = server.endpoint.incoming();
        let labels = Arc::new(RecordedLabels::default());
        let starts = ClientStarts::new(&labels);
        let mut stored = starts.tickets.stored.subscribe();
        let (client, client_reflow) = Endpoint::<Udp, NoServer, EagerClient>::new(endpoint_config(
            (),
            eager_resuming_client_config(starts),
        ))
        .unwrap();
        let client_reflow = tokio::task::spawn_local(client_reflow);
        let (client_handle, client_driver) = client
            .add_connect_only_binding(bind(), BindingDeclarations::default())
            .unwrap();
        let client_driver = tokio::task::spawn_local(client_driver);

        first_connection!(client_handle, server.address, incoming, stored);
        take_disclosed();

        let (client_conn, client_task) = connect!(client_handle, server.address);
        let early = within("the client's early layer", client_conn.early())
            .await
            .expect("the connection is open")
            .expect("the client offers 0-RTT");
        let client_exchange =
            tokio::task::spawn_local(async move { request_and_read_answer!(early) });
        let half = next_incoming!(incoming);
        let (server_conn, server_task) = accept!(half);
        let server_early = within("the server's early layer", server_conn.early())
            .await
            .expect("the connection is open")
            .expect("the server accepts 0-RTT");
        assert_eq!(read_request_and_answer!(server_early), EARLY_REQUEST);
        assert_eq!(
            within("the client's exchange", client_exchange)
                .await
                .unwrap(),
            EARLY_ANSWER
        );
        let facts = within(
            "the client's handshake completes",
            client_conn.handshake_completed(),
        )
        .await
        .expect("the client's handshake completed");
        assert_eq!(facts.early_data, EarlyDataOutcome::Accepted);

        let mut log = Vec::new();
        disclosed_until("the server acknowledges the three", &mut log, |log| {
            (1..=3).all(|sequence| first_at(log, Disclosed::Delivered(sequence)).is_some())
        })
        .await;
        // told the remembered limit first, and the known one once the
        // handshake completed: what was written before went in 0-RTT
        assert_eq!(log.first(), Some(&Disclosed::Issuable(4)), "{log:?}");
        let known = log
            .iter()
            .skip(1)
            .position(|each| *each == Disclosed::Issuable(4))
            .map(|at| at + 1)
            .expect("the known limit is told");
        for sequence in 1..=3 {
            let written = first_at(&log, Disclosed::Written(sequence)).expect("written");
            assert!(written < known, "{sequence} is written in 0-RTT: {log:?}");
        }
        assert!(
            !log.iter()
                .any(|each| matches!(each, Disclosed::Lost(_) | Disclosed::Rejected(_))),
            "{log:?}"
        );

        client_conn.close(AppClose(7));
        within("the client's close", client_conn.closed()).await;
        within("the server's close", server_conn.closed()).await;
        within("the client's connection ends", client_task)
            .await
            .unwrap();
        within("the server's connection ends", server_task)
            .await
            .unwrap();

        drop(incoming);
        server.endpoint.close();
        client.close();
        let (reflow, driver) = server.drivers;
        within("the server's drivers end", async {
            reflow.await.unwrap();
            driver.await.unwrap();
        })
        .await;
        within("the client's binding driver ends", client_driver)
            .await
            .unwrap();
        within("the client's reflow driver ends", client_reflow)
            .await
            .unwrap();
    });
}

/// A server that lowered the client's connection ID limit to 2 rejects
/// 0-RTT: the NEW_CONNECTION_ID frames the client sent in 0-RTT come back,
/// the connection IDs beyond the new limit are withdrawn, and the one
/// within it goes again in 1-RTT, which the server acknowledges.
#[test]
fn a_rejected_client_sends_new_connection_id_again_within_the_new_limit() {
    run(async {
        let tokens = aead_tokens();
        let tickets = ServerStarts::new(true);
        let first = server_on(resuming_server_config_with_limit(
            tickets.clone(),
            tokens.clone(),
            16 << 20,
            4,
        ));
        let mut first_incoming = first.endpoint.incoming();
        let lowered = server_on(resuming_server_config_with_limit(
            tickets,
            tokens,
            16 << 20,
            2,
        ));
        let mut incoming = lowered.endpoint.incoming();
        let labels = Arc::new(RecordedLabels::default());
        let starts = ClientStarts::new(&labels);
        let mut stored = starts.tickets.stored.subscribe();
        let (client, client_reflow) = Endpoint::<Udp, NoServer, EagerClient>::new(endpoint_config(
            (),
            eager_resuming_client_config(starts),
        ))
        .unwrap();
        let client_reflow = tokio::task::spawn_local(client_reflow);
        let (client_handle, client_driver) = client
            .add_connect_only_binding(bind(), BindingDeclarations::default())
            .unwrap();
        let client_driver = tokio::task::spawn_local(client_driver);

        first_connection!(client_handle, first.address, first_incoming, stored);
        take_disclosed();

        let (client_conn, client_task) = connect!(client_handle, lowered.address);
        let early = within("the client's early layer", client_conn.early())
            .await
            .expect("the connection is open")
            .expect("the client offers 0-RTT");
        let ended = early.clone();
        let client_early = tokio::task::spawn_local(async move {
            let Ok((mut writer, _reader)) = early.open_bi().await else {
                return;
            };
            let _ = writer
                .write_all_unpin(Bytes::from_static(EARLY_REQUEST))
                .await;
            let _ = writer.close();
        });
        let half = next_incoming!(incoming);
        let (server_conn, server_task) = accept!(half);
        let end = within("the client's early layer ends", ended.ended()).await;
        assert!(matches!(end, LayerEnd::ZeroRttRejected), "{end:?}");
        within("the client's request in 0-RTT", client_early)
            .await
            .unwrap();
        // the connection goes on: an exchange on the layer built anew
        let layer = within("the client's layer", client_conn.established())
            .await
            .expect("the client's handshake completed");
        let client_exchange =
            tokio::task::spawn_local(async move { request_and_read_answer!(layer) });
        let server_layer = within("the server's layer", server_conn.established())
            .await
            .expect("the server's handshake completed");
        assert_eq!(read_request_and_answer!(server_layer), EARLY_REQUEST);
        assert_eq!(
            within("the client's exchange", client_exchange)
                .await
                .unwrap(),
            EARLY_ANSWER
        );

        let mut log = Vec::new();
        disclosed_until("the server acknowledges the one kept", &mut log, |log| {
            first_at(log, Disclosed::Delivered(1)).is_some()
        })
        .await;
        assert_eq!(log.first(), Some(&Disclosed::Issuable(4)), "{log:?}");
        let rejected = first_at(&log, Disclosed::Rejected(2)).expect("told of the rejection");
        for sequence in 1..=3 {
            let written = first_at(&log, Disclosed::Written(sequence)).expect("written");
            assert!(
                written < rejected,
                "{sequence} is written in 0-RTT: {log:?}"
            );
        }
        let after = &log[rejected..];
        let again = first_at(after, Disclosed::Written(1)).expect("1 goes again");
        let delivered = first_at(after, Disclosed::Delivered(1)).expect("1 is acknowledged");
        assert!(again < delivered, "1 goes again in 1-RTT: {log:?}");
        assert!(
            after
                .iter()
                .all(|each| !matches!(each, Disclosed::Written(2..) | Disclosed::Delivered(2..))),
            "nothing beyond the new limit: {log:?}"
        );
        assert!(
            !log.iter()
                .any(|each| matches!(each, Disclosed::Delivered(2..))),
            "{log:?}"
        );

        client_conn.close(AppClose(7));
        within("the client's close", client_conn.closed()).await;
        within("the server's close", server_conn.closed()).await;
        within("the client's connection ends", client_task)
            .await
            .unwrap();
        within("the server's connection ends", server_task)
            .await
            .unwrap();

        drop((incoming, first_incoming));
        first.endpoint.close();
        lowered.endpoint.close();
        client.close();
        for server in [first, lowered] {
            let (reflow, driver) = server.drivers;
            within("the server's drivers end", async {
                reflow.await.unwrap();
                driver.await.unwrap();
            })
            .await;
        }
        within("the client's binding driver ends", client_driver)
            .await
            .unwrap();
        within("the client's reflow driver ends", client_reflow)
            .await
            .unwrap();
    });
}

// ---- the certificates ----

/// The output of a future that is ready at once.
fn ready<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("future not ready"),
    }
}

/// The certificates and keys of the tests: Ed25519, signed with
/// nitori_crypto_aws_lc.
mod pki {
    use super::*;

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match content.len() {
            len @ 0..=127 => out.push(len as u8),
            len @ 128..=255 => out.extend([0x81, len as u8]),
            len => out.extend([0x82, (len >> 8) as u8, len as u8]),
        }
        out.extend_from_slice(content);
        out
    }

    fn seq(parts: &[&[u8]]) -> Vec<u8> {
        tlv(0x30, &parts.concat())
    }

    fn name(common_name: &str) -> Vec<u8> {
        let attribute = seq(&[
            &tlv(0x06, &[0x55, 0x04, 0x03]),
            &tlv(0x0c, common_name.as_bytes()),
        ]);
        seq(&[&tlv(0x31, &attribute)])
    }

    fn ed25519() -> Vec<u8> {
        seq(&[&tlv(0x06, &[0x2b, 0x65, 0x70])])
    }

    fn bits(bytes: &[u8]) -> Vec<u8> {
        tlv(0x03, &[&[0], bytes].concat())
    }

    fn extension(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
        let critical = if critical {
            tlv(0x01, &[0xff])
        } else {
            Vec::new()
        };
        seq(&[&tlv(0x06, oid), &critical, &tlv(0x04, value)])
    }

    /// The Ed25519 key with the 32-byte seed `[seed; 32]`.
    pub fn key(seed: u8) -> Ed25519SigningKey {
        let mut pkcs8 = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        pkcs8.extend([seed; 32]);
        Ed25519SigningKey::from_pkcs8(&pkcs8).unwrap()
    }

    fn certificate(
        serial: u8,
        issuer: &str,
        subject: &str,
        public_key: &[u8],
        extensions: &[Vec<u8>],
        signer: &Ed25519SigningKey,
    ) -> Vec<u8> {
        let extensions: Vec<&[u8]> = extensions.iter().map(Vec::as_slice).collect();
        let validity = seq(&[&tlv(0x17, b"250101000000Z"), &tlv(0x17, b"491231235959Z")]);
        let tbs = seq(&[
            &tlv(0xa0, &tlv(0x02, &[2])),
            &tlv(0x02, &[serial]),
            &ed25519(),
            &name(issuer),
            &validity,
            &name(subject),
            &seq(&[&ed25519(), &bits(public_key)]),
            &tlv(0xa3, &seq(&extensions)),
        ]);
        let signature = ready(signer.sign(SignatureScheme::ED25519, &tbs)).unwrap();
        seq(&[&tbs, &ed25519(), &bits(signature.as_bytes())])
    }

    /// A root, self-signed by `key(seed)`.
    pub fn root(seed: u8) -> Vec<u8> {
        let root = key(seed);
        let basic_constraints = extension(&[0x55, 0x1d, 0x13], true, &seq(&[&tlv(0x01, &[0xff])]));
        certificate(
            seed,
            "Test Root",
            "Test Root",
            root.public_key(),
            &[basic_constraints],
            &root,
        )
    }

    /// The certificate of `key(2)` for example.com, issued by `root(1)`.
    pub fn leaf() -> Vec<u8> {
        let alternative_names = extension(
            &[0x55, 0x1d, 0x11],
            false,
            &seq(&[&tlv(0x82, b"example.com")]),
        );
        let server_auth = extension(
            &[0x55, 0x1d, 0x25],
            false,
            &seq(&[&tlv(
                0x06,
                &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01],
            )]),
        );
        certificate(
            2,
            "Test Root",
            "example.com",
            key(2).public_key(),
            &[alternative_names, server_auth],
            &key(1),
        )
    }

    /// The client's verifier: it trusts `root(seed)` alone, and skips the
    /// check of certificate transparency, as the certificates carry no
    /// SCTs.
    pub fn verifier(seed: u8) -> Verifier {
        let transparency = EmbeddedSctPolicy::with_list_age(
            LogList::new(Vec::new(), UtcDateTime::UNIX_EPOCH),
            Duration::ZERO,
            StaleLogListAction::SkipCheck,
        );
        WebPkiVerifier::new(
            AwsLcBackend,
            AnchorStore::from_certificates([root(seed).as_slice()]).unwrap(),
            SpkiDistrustList::default(),
            NoRevocationCheck,
            transparency,
            SystemClock,
        )
    }
}
