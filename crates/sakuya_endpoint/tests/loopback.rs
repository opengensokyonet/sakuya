//! A server endpoint and a client endpoint on UDP sockets of the loopback
//! interface: the client connects, the server accepts, the handshake
//! completes, the client closes, and both endpoints shut down.
//!
//! The server presents an Ed25519 certificate for example.com, issued by an
//! Ed25519 root that the client's verifier trusts; both are built here.

#![cfg(target_os = "linux")]

use core::{fmt, future::Future, net::SocketAddr, num::NonZeroU32, time::Duration};
use std::{
    pin::pin,
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
use nitori_tls::{
    cipher_suite::CipherSuite,
    client::{
        ServerTarget,
        engine::{ClientHandshake, ClientHandshakeSettings},
        identity::NoClientCertificate,
        offering::PreferenceOffering,
        ticket::TakeOnceTicketMap,
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
use sakuya_connection::v1::retry::ContinueOnRetry;
use sakuya_connection::v1::{self, close::LocalCloseCause};
use sakuya_datagram_routing::route::recognizer::{ConnectionIdGenerator, ConnectionIdLengths};
use sakuya_endpoint::role::{ClientConnectionChoices, ServerConnectionChoices};
use sakuya_endpoint::{
    address_token::{
        AddressTokenKey, AddressTokenLifetimes, AddressTokens, AeadAddressTokens, TokenOutcome,
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
use sakuya_stream::connection::{CloseReason, ImmediateClose, TransportImmediateClose};
use sakuya_udp_tokio::{UdpBinding, UdpBindingConfig, UdpLink};
use sakuya_wire::{
    connection_id::{ConnectionId, ConnectionIdLength, StatelessResetToken},
    v1::{
        transport_error::TransportErrorCode,
        transport_parameters::{TransportParameters, integer::MaxIdleTimeout},
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
    type Clock = TokioClock;
    type Crypto = RingBackend;
    type Random = AwsLcBackend;
    type WallClock = SystemClock;
    type ConnectionIds = CountingConnectionIds;
    type Recognizer = ConnectionIdLengths;
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
type ServerChoices = ServerConnectionChoices<Udp, Mine, ServerStarts>;
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
type ClientTokens = BoundedAddressTokenStore<ServerTarget>;
type Client = ConnectingClient<Mine, Parts, ClientStarts, ClientTokens, ContinueOnRetry>;

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
    ZeroRttOnceTicketTable<&'static str, AwsLcBackend, SystemClock>,
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
    Arc<TakeOnceTicketMap<SystemClock>>,
    Verifier,
    NoClientCertificate,
    SystemClock,
    Arc<RecordedLabels>,
>;

fn h3() -> ProtocolName<Bytes> {
    ProtocolName::new(Bytes::from_static(b"h3")).unwrap()
}

/// Makes each server connection's engine afresh.
#[derive(Clone)]
struct ServerStarts;

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
            ZeroRttOnceTicketTable::new(
                AwsLcBackend,
                SystemClock,
                2,
                TicketLifetime::new(3600).unwrap(),
                false,
                16,
            ),
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
    tickets: Arc<TakeOnceTicketMap<SystemClock>>,
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
    ServerConfig::new(
        ServerStarts,
        ServerCryptoReceiveCapacities {
            initial: 16 * 1024 + 4,
            handshake: 4096,
        },
        thresholds(),
        hlist![v1_config!(ServerChoices)],
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
    ClientConfig::new(
        ClientStarts {
            labels: Arc::clone(labels),
            tickets: Arc::new(TakeOnceTicketMap::new(
                SystemClock,
                Duration::from_secs(86_400),
                4,
            )),
        },
        ClientCryptoReceiveCapacities {
            initial: 16 * 1024 + 4,
            handshake: 64 * 1024 + 4,
            one_rtt: 16 * 1024 + 4,
        },
        thresholds,
        hlist![v1_config!(ClientChoices)],
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
        let (client_connection, client_conn) = outgoing.start().unwrap();
        let client_connection = tokio::task::spawn_local(client_connection);

        let Some(Incoming::Terminable(half)) =
            within("an incoming connection", incoming.next()).await
        else {
            panic!("the server endpoint ends before a connection comes");
        };
        assert!(!half.facts().born_from_zero_rtt);
        let (server_connection, server_conn) = half.accept().unwrap();
        let server_connection = tokio::task::spawn_local(server_connection);

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
    let (endpoint, reflow) =
        Endpoint::<Udp, Server, NoClient>::new(endpoint_config(server_config(), ())).unwrap();
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
        let (connection, _conn) = outgoing.start().unwrap();
        let connection = tokio::task::spawn_local(connection);

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
        let (client_connection, client_conn) = outgoing.start().unwrap();
        let client_connection = tokio::task::spawn_local(client_connection);

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
        let (server_connection, server_conn) = retried.accept().unwrap();
        let server_connection = tokio::task::spawn_local(server_connection);

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
        let (client_connection, client_conn) = outgoing.start().unwrap();
        let client_connection = tokio::task::spawn_local(client_connection);

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
    Tk: AddressTokens<PeerOf<Udp>> + Clone + 'static,
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
    Tk: AddressTokens<PeerOf<Udp>> + Clone + 'static,
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
