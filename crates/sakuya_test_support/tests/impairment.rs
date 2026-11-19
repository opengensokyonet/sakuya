//! A client and a server endpoint on a network in memory that loses,
//! reorders, duplicates and corrupts datagrams, falls into blackholes,
//! changes its path MTU and rebinds the client, on tokio's paused time.
//!
//! In each scenario the client connects, opens a bidirectional stream and
//! sends a request with its end; the server answers with [`ANSWER_LEN`]
//! bytes and its end; the client reads the whole answer and closes. Each
//! scenario runs twice with the same seed: the fates of the datagrams must
//! be the same both times, the answer complete, and neither side may close
//! for a protocol error: the client closes for its application's reason and
//! the server for the client's.
//!
//! The migration scenarios (a client rebound to a new port or a new IP, a
//! copied datagram sent from another address, a server that disabled active
//! migration) assert that the connection follows its client and the client
//! gets its answer: see [`a_client_rebound_to_a_new_port_after_the_handshake_gets_its_answer`].
//!
//! The connections' events are received by [`QlogWriter`]; the scenarios
//! that read them give a directory under Cargo's directory for the tests'
//! temporary files, the others none, which records nothing.
#![feature(type_alias_impl_trait)]

use core::{
    fmt,
    future::Future,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    num::{NonZeroU32, NonZeroUsize},
    time::Duration,
};
use std::{
    cell::RefCell,
    path::{Path, PathBuf},
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use bytes::Bytes;
use frunk_core::{Coprod, hlist};
use futures_util::StreamExt as _;
use nitori_crypto::NamedGroup;
use nitori_crypto_aws_lc::{AwsLcBackend, Ed25519SigningKey};
use nitori_io::{ReadChunkHostExt as _, calls::WriteAllHostExt as _};
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
    verify::AnchorStore,
};
use sakuya_clock_tokio::TokioClock;
use sakuya_connection::prelude::*;
use sakuya_connection::v1::application_handles::connection::ConnectionHandle;
use sakuya_connection::v1::retry::ContinueOnRetry;
use sakuya_connection::v1::{self, close::LocalCloseCause};
use sakuya_connection::{
    driver::LendNode,
    shared::{DrivenFromOutside, SharedConnectionDriver},
};
use sakuya_datagram_routing::route::recognizer::{ConnectionIdGenerator, ConnectionIdLengths};
use sakuya_endpoint::role::{ClientConnectionChoices, ServerConnectionChoices};
use sakuya_endpoint::{
    address_token::{
        AddressTokenKey, AddressTokenLifetimes, AeadAddressTokens, AeadNewTokenIssuer,
    },
    choices::EndpointChoices,
    client_token::BoundedAddressTokenStore,
    config::{
        BindingDeclarations, ClientConfig, ClientCryptoReceiveCapacities, EndpointConfig,
        ServerConfig, ServerCryptoReceiveCapacities,
    },
    endpoint::Endpoint,
    handshake::{ClientHandshakeConfig, ServerHandshakeConfig},
    incoming::{Incoming, IncomingStream, TerminableIncoming},
    outgoing::Outgoing,
    retry::{CapacityFraction, LoadStatelessRetryPolicy},
    role::{AcceptingServer, ConnectingClient, NoClient, NoServer},
};
use sakuya_link::{ConnectingLinkBinding as _, Link as _};
use sakuya_packet_protection::backend::ring::RingBackend;
use sakuya_qlog::{QUIC_EVENT_SCHEMA, QlogConfig, QlogWriter};
use sakuya_recovery::loss::LossThresholds;
use sakuya_stream::connection::{CloseReason, ImmediateClose};
use sakuya_test_support::{
    network::{
        Blackhole, DatagramFate, Direction, DirectionImpairments, DropCause, Impairments,
        MemoryLink, MemoryNetwork, Probability, RandomLoss, Reorder,
    },
    pki,
    verify::{TestRootsVerifier, test_roots_verifier},
};
use sakuya_wire::{
    connection_id::{ConnectionId, ConnectionIdLength, NonEmptyCid, StatelessResetToken},
    v1::transport_error::TransportErrorCode,
    v1::{
        stream_count::StreamCount,
        transport_parameters::{
            TransportParameters,
            disable_active_migration::DisableActiveMigration,
            integer::{
                InitialMaxData, InitialMaxStreamDataBidiLocal, InitialMaxStreamDataBidiRemote,
                InitialMaxStreamsBidi, MaxIdleTimeout,
            },
            preferred_address::{PreferredAddress, PreferredAddressFamilies},
        },
    },
    var_int::VarInt,
};
use tokio::task::{JoinHandle, spawn_local};

/// How long, on the paused clock, any step may take.
const DEADLINE: Duration = Duration::from_secs(600);

/// The idle timeout both sides advertise.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// How many bytes the server answers with.
const ANSWER_LEN: usize = 100_000;

/// What the client asks.
const REQUEST: &[u8] = b"GET /answer";

/// The one-way delay of every scenario: an RTT of 20 ms.
const DELAY: Duration = Duration::from_millis(10);

fn server_address() -> SocketAddr {
    SocketAddr::from(([10, 0, 0, 1], 443))
}

fn client_address() -> SocketAddr {
    SocketAddr::from(([10, 0, 0, 2], 50_000))
}

// ==== the composition ====

/// The endpoints of the test: the network in memory, on tokio's clock.
struct InMemory;

type Link = MemoryLink<TokioClock>;

impl EndpointChoices for InMemory {
    type Links = Coprod![Link];
    type Bindings = frunk_core::HList![sakuya_test_support::network::MemoryBinding<TokioClock>];
    type Clock = TokioClock;
    type Crypto = RingBackend;
    type Random = AwsLcBackend;
    type WallClock = SystemClock;
    type ConnectionIds = CountingConnectionIds;
    type Recognizer = ConnectionIdLengths;
    type Synchronization =
        sakuya_endpoint::synchronization::RefCellEndpointSynchronization<std::hash::RandomState>;
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

/// What the tests choose of version 1: their application error, qlog for
/// the connections' events, and the default of everything else.
struct Mine;

impl<T: v1::MakerChoices> v1::HostChoices<T> for Mine {
    type ApplicationError = AppClose;
    type Events<L> = QlogWriter<L, TokioClock>;
}

type ServerChoices =
    ServerConnectionChoices<InMemory, Mine, ServerStarts, AeadNewTokenIssuer<AwsLcBackend>>;
type ClientChoices =
    ClientConnectionChoices<InMemory, Mine, ClientStarts, ClientTokens, ContinueOnRetry>;

type Parts = frunk_core::HList![v1::Part];

type Server = AcceptingServer<
    Mine,
    Parts,
    ServerStarts,
    AeadAddressTokens<AwsLcBackend>,
    LoadStatelessRetryPolicy,
>;
type ClientTokens =
    BoundedAddressTokenStore<ServerTarget, sakuya_endpoint::choices::SynchronizationOf<InMemory>>;
type Client = ConnectingClient<Mine, Parts, ClientStarts, ClientTokens, ContinueOnRetry>;
sakuya_connection::composition!(impl for Mine: ServerChoices, Parts);
sakuya_connection::composition!(impl for Mine: ClientChoices, Parts);

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
    TestRootsVerifier<AwsLcBackend, SystemClock>,
    NoClientCertificate,
    SystemClock,
    (),
>;

fn h3() -> ProtocolName<Bytes> {
    ProtocolName::new(Bytes::from_static(b"h3")).unwrap()
}

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
            CertifiedKey::new(
                vec![Bytes::from(pki::leaf(2, 1, "example.com"))],
                pki::key(2),
            )
            .unwrap(),
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

#[derive(Clone)]
struct ClientStarts {
    tickets: Arc<TakeOnceTicketMap<SystemClock>>,
}

impl ClientHandshakeConfig for ClientStarts {
    type ServerName = ServerTarget;
    type Start = ClientEngine;

    fn start(&self, server_name: &ServerTarget) -> ClientEngine {
        let roots = AnchorStore::from_certificates([pki::root(1).as_slice()]).unwrap();
        ClientHandshake::new(
            AwsLcBackend,
            PreferenceOffering::new(
                vec![CipherSuite::TLS_AES_128_GCM_SHA256],
                vec![NamedGroup::X25519],
                vec![NamedGroup::X25519],
            )
            .unwrap(),
            Arc::clone(&self.tickets),
            test_roots_verifier(AwsLcBackend, roots, SystemClock),
            NoClientCertificate,
            SystemClock,
            (),
            server_name.clone(),
            Some(ProtocolNameList::new(vec![h3()]).unwrap()),
            ClientHandshakeSettings::default(),
        )
    }

    fn limits(&self) -> MessageLimits {
        ClientHandshakeSettings::default().limits
    }
}

/// Version 1's configuration of the connections, which write qlog into
/// `$qlog` when it is a directory, give the preferred address
/// `$preferred` when there is one, and send `disable_active_migration` when
/// `$disable_active_migration` is true.
macro_rules! v1_config {
    ($t:ty, $qlog:expr) => {
        v1_config!($t, $qlog, None::<PreferredAddress>)
    };
    ($t:ty, $qlog:expr, $preferred:expr) => {
        v1_config!($t, $qlog, $preferred, false)
    };
    ($t:ty, $qlog:expr, $preferred:expr, $disable_active_migration:expr) => {{
        let mut parameters = TransportParameters::<Vec<u8>>::new();
        if $disable_active_migration {
            parameters.set(DisableActiveMigration);
        }
        if let Some(preferred) = $preferred {
            parameters.set(preferred);
        }
        let idle = u32::try_from(IDLE_TIMEOUT.as_millis()).unwrap();
        parameters.set(MaxIdleTimeout::new(VarInt::from_u32(idle)));
        // room for the whole answer without waiting for flow control
        parameters.set(InitialMaxData::new(VarInt::from_u32(1 << 20)));
        parameters.set(InitialMaxStreamDataBidiLocal::new(VarInt::from_u32(
            1 << 20,
        )));
        parameters.set(InitialMaxStreamDataBidiRemote::new(VarInt::from_u32(
            1 << 20,
        )));
        parameters.set(InitialMaxStreamsBidi::new(StreamCount::new(4).unwrap()));
        sakuya_endpoint::v1::ConnectionConfig::<$t, Parts> {
            transport_parameters: parameters.known,
            events: QlogConfig {
                dir: $qlog,
                clock: Some(TokioClock),
            },
            ..Default::default()
        }
    }};
}

fn thresholds() -> LossThresholds {
    LossThresholds::recommended(Duration::from_millis(1)).unwrap()
}

fn endpoint_config<S, C>(server: S::Config, client: C::Config) -> EndpointConfig<InMemory, S, C>
where
    S: sakuya_endpoint::role::ServerRole<InMemory>,
    C: sakuya_endpoint::role::ClientRole<InMemory>,
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

fn server_config(
    qlog: Option<PathBuf>,
    preferred: Option<PreferredAddressFamilies>,
    disable_active_migration: bool,
) -> ServerConfig<
    ServerChoices,
    Parts,
    ServerStarts,
    AeadAddressTokens<AwsLcBackend>,
    LoadStatelessRetryPolicy,
> {
    let tokens = AeadAddressTokens::new(
        AwsLcBackend,
        AddressTokenKey::generate(&AwsLcBackend).unwrap(),
        AddressTokenLifetimes::default(),
        Default::default(),
    )
    .unwrap();
    ServerConfig::new(
        ServerStarts,
        ServerCryptoReceiveCapacities {
            initial: 16 * 1024 + 4,
            handshake: 4096,
        },
        thresholds(),
        hlist![v1_config!(
            ServerChoices,
            qlog,
            preferred.map(|addresses| PreferredAddress {
                addresses,
                // placeholders, which each connection replaces
                connection_id: NonEmptyCid::new(ConnectionId::new(&[0; 8]).unwrap()).unwrap(),
                stateless_reset_token: StatelessResetToken::new([0; 16]),
            }),
            disable_active_migration
        )],
        tokens,
        LoadStatelessRetryPolicy::new(
            CapacityFraction::new(1, NonZeroU32::new(2).unwrap()).unwrap(),
        ),
    )
    .unwrap()
}

fn client_config(
    qlog: Option<PathBuf>,
) -> ClientConfig<ClientChoices, Parts, ClientStarts, ClientTokens, ContinueOnRetry> {
    ClientConfig::new(
        ClientStarts {
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
        thresholds(),
        hlist![v1_config!(ClientChoices, qlog)],
        ClientTokens::new(),
        ContinueOnRetry,
    )
    .unwrap()
}

// ==== the run ====

/// Runs `test` on a current-thread runtime whose time is paused: when no
/// task can go on, time jumps to the next timer.
fn run_paused<T>(test: impl Future<Output = T>) -> T {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .expect("a runtime builds");
    tokio::task::LocalSet::new().block_on(&runtime, test)
}

async fn within<T>(what: &str, future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .unwrap_or_else(|_| panic!("{what} within {DEADLINE:?} of the paused clock"))
}

/// The answer the server sends: bytes that tell their offset.
fn answer() -> Vec<u8> {
    (0..ANSWER_LEN)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect()
}

/// When the network changes during a run.
#[derive(Clone, Copy)]
enum Change {
    /// Nothing changes.
    None,
    /// Once the handshake has completed on both sides, the links of both
    /// addresses report `size` as their limit.
    LinkLimit(usize),
    /// Once the handshake has completed on both sides, the path carries
    /// datagrams of up to `mtu` bytes in both directions, dropping larger
    /// ones without a word.
    PathMtu(usize),
}

/// What a run ended with.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    to_server: Vec<DatagramFate>,
    to_client: Vec<DatagramFate>,
    /// How many datagrams had been numbered in each direction when the
    /// network changed.
    changed_at: Option<(u64, u64)>,
    /// The size confirmed on the server link before the client closed.
    server_conclusion: usize,
}

/// Where the endpoints of a run are, and the preferred address the server
/// gives, if it gives one.
struct Addresses {
    server: SocketAddr,
    client: SocketAddr,
    preferred: Option<PreferredAddressFamilies>,
    /// The bindings the server adds for its preferred address.
    preferred_bindings: Vec<SocketAddr>,
    /// Whether the server sends `disable_active_migration`.
    disable_active_migration: bool,
}

impl Addresses {
    /// The server and the client at their usual addresses, without a
    /// preferred address.
    fn plain() -> Self {
        Self {
            server: server_address(),
            client: client_address(),
            preferred: None,
            preferred_bindings: Vec::new(),
            disable_active_migration: false,
        }
    }
}

/// A server's connection of the tests.
type ServerConnection = impl DrivenFromOutside + LendNode<ServerChoices, Parts> + 'static;
/// A client's connection of the tests.
type ClientConnection = impl DrivenFromOutside + LendNode<ClientChoices, Parts> + 'static;

/// The connection `half` accepts.
#[define_opaque(ServerConnection)]
fn accepted(half: TerminableIncoming<InMemory, Server>) -> ServerConnection {
    half.accept().unwrap()
}

/// The connection `outgoing` starts.
#[define_opaque(ClientConnection)]
fn started(outgoing: Outgoing<InMemory, Client>) -> ClientConnection {
    outgoing.start().unwrap()
}

/// Two endpoints on a network in memory, with a connection between them
/// whose handshake has completed on both sides.
struct Pair {
    network: MemoryNetwork<TokioClock>,
    /// The server's link to the client, which the scenarios with a
    /// preferred address do not hold: a link held stays the binding's for
    /// its peer even once the endpoint stopped receiving on it.
    server_link: Option<Link>,
    server: Endpoint<InMemory, Server, NoClient>,
    client: Endpoint<InMemory, NoServer, Client>,
    incoming: IncomingStream<InMemory, Server>,
    server_conn: ConnectionHandle<ServerChoices, Parts, Rc<RefCell<ServerConnection>>>,
    client_conn: ConnectionHandle<ClientChoices, Parts, Rc<RefCell<ClientConnection>>>,
    server_connection: JoinHandle<()>,
    client_connection: JoinHandle<()>,
    drivers: Vec<(&'static str, JoinHandle<()>)>,
}

impl Pair {
    /// Two endpoints on a network whose fates follow from `seed`, impaired
    /// as `impairments` says, once their connection's handshake has
    /// completed on both sides; the connections write qlog into `qlog` when
    /// it is a directory.
    async fn connect(seed: u64, impairments: Impairments, qlog: Option<&Path>) -> Self {
        Self::connect_at(seed, impairments, qlog, &Addresses::plain()).await
    }

    /// Two endpoints as [`connect`](Self::connect) makes them, at `at`.
    async fn connect_at(
        seed: u64,
        impairments: Impairments,
        qlog: Option<&Path>,
        at: &Addresses,
    ) -> Self {
        let network = MemoryNetwork::new(TokioClock, seed, at.server, impairments);
        let mut drivers = Vec::new();

        let (server, server_reflow) = Endpoint::<InMemory, Server, NoClient>::new(endpoint_config(
            server_config(
                qlog.map(Path::to_path_buf),
                at.preferred,
                at.disable_active_migration,
            ),
            (),
        ))
        .unwrap();
        drivers.push(("the server's reflow driver", spawn_local(server_reflow)));
        let server_binding = network.bind(at.server);
        let (_server_handle, server_driver) = server
            .add_accepting_binding(server_binding.clone(), BindingDeclarations::default())
            .unwrap();
        drivers.push(("the server's binding driver", spawn_local(server_driver)));
        for &preferred in &at.preferred_bindings {
            let (_handle, driver) = server
                .add_accepting_binding(network.bind(preferred), BindingDeclarations::default())
                .unwrap();
            drivers.push(("a preferred address's binding driver", spawn_local(driver)));
        }
        let mut incoming = server.incoming();

        let (client, client_reflow) = Endpoint::<InMemory, NoServer, Client>::new(endpoint_config(
            (),
            client_config(qlog.map(Path::to_path_buf)),
        ))
        .unwrap();
        drivers.push(("the client's reflow driver", spawn_local(client_reflow)));
        let (client_handle, client_driver) = client
            .add_connect_only_binding(network.bind(at.client), BindingDeclarations::default())
            .unwrap();
        drivers.push(("the client's binding driver", spawn_local(client_driver)));

        let outgoing = within(
            "the client takes a link",
            client_handle.connect(
                at.server,
                ServerTarget::from_host_name("example.com").unwrap(),
            ),
        )
        .await
        .unwrap();
        let client_connection = Rc::new(RefCell::new(started(outgoing)));
        let client_conn = ConnectionHandle::new(client_connection.clone());
        let client_connection = spawn_local(SharedConnectionDriver::new(client_connection));

        let Some(Incoming::Terminable(half)) =
            within("an incoming connection", incoming.next()).await
        else {
            panic!("the server endpoint ends before a connection comes");
        };
        let server_connection = Rc::new(RefCell::new(accepted(half)));
        let server_conn = ConnectionHandle::new(server_connection.clone());
        let server_connection = spawn_local(SharedConnectionDriver::new(server_connection));

        within("the client's handshake", client_conn.handshake_completed())
            .await
            .expect("the client's handshake completes");
        within("the server's handshake", server_conn.handshake_completed())
            .await
            .expect("the server's handshake completes");
        // The binding returns the live link with this peer.
        let server_link = match at.preferred {
            None => Some(server_binding.connect(at.client).await.unwrap()),
            Some(_) => None,
        };
        Self {
            network,
            server_link,
            server,
            client,
            incoming,
            server_conn,
            client_conn,
            server_connection,
            client_connection,
            drivers,
        }
    }

    /// Waits for both connections to end, closes both endpoints and waits
    /// for their drivers; the fates of the datagrams of each direction.
    async fn finish(self) -> (Vec<DatagramFate>, Vec<DatagramFate>) {
        within("the client's connection ends", self.client_connection)
            .await
            .unwrap();
        within("the server's connection ends", self.server_connection)
            .await
            .unwrap();
        drop(self.incoming);
        self.server.close();
        self.client.close();
        for (what, driver) in self.drivers {
            within(what, driver).await.unwrap();
        }
        (
            self.network.fates(Direction::ToServer),
            self.network.fates(Direction::ToClient),
        )
    }

    /// The server's link to the client.
    fn server_link(&self) -> &Link {
        self.server_link
            .as_ref()
            .expect("the scenario holds the server's link")
    }

    /// How many datagrams have been numbered in each direction so far.
    fn counts(&self) -> (u64, u64) {
        let len = |direction| self.network.fates(direction).len() as u64;
        (len(Direction::ToServer), len(Direction::ToClient))
    }
}

/// One run of a scenario: the request and the answer over `impairments`,
/// with fates that follow from `seed`, changed as `change` says; the
/// connections write qlog into `qlog` when it is a directory.
fn exchange(seed: u64, impairments: Impairments, change: Change, qlog: Option<&Path>) -> Outcome {
    run_paused(async move {
        let pair = Pair::connect(seed, impairments, qlog).await;
        let client_layer = pair.client_conn.established().await.expect("established");
        let server_layer = pair.server_conn.established().await.expect("established");

        if let Change::LinkLimit(limit) | Change::PathMtu(limit) = change {
            // Change a path whose larger size has already been confirmed.
            within("a larger size confirmed on the server link", async {
                while pair.server_link().datagram_size_conclusion() <= limit {
                    tokio::time::sleep(DELAY).await;
                }
            })
            .await;
        }
        let changed_at = match change {
            Change::None => None,
            Change::LinkLimit(size) => {
                pair.network.set_max_datagram_size(server_address(), size);
                pair.network.set_max_datagram_size(client_address(), size);
                Some(pair.counts())
            }
            Change::PathMtu(mtu) => {
                pair.network.set_path_mtu(Direction::ToServer, Some(mtu));
                pair.network.set_path_mtu(Direction::ToClient, Some(mtu));
                Some(pair.counts())
            }
        };

        let server_application = spawn_local(async move {
            let (mut writer, mut reader) = server_layer
                .accept_bi()
                .await
                .expect("the client's stream is accepted");
            let mut request = Vec::new();
            while let Some(chunk) = reader
                .read_chunk_unpin(NonZeroUsize::new(1024).unwrap())
                .await
                .expect("the request is read")
            {
                request.extend_from_slice(&chunk);
            }
            let mut data = Bytes::from(answer());
            if matches!(change, Change::PathMtu(_)) {
                // Send a full packet and a short tail in successive flights.
                // The tails still elicit ACKs when the large packets disappear.
                while !data.is_empty() {
                    let chunk = data.split_to(1800.min(data.len()));
                    writer
                        .write_all_unpin(chunk)
                        .await
                        .expect("the answer is written");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            } else {
                writer
                    .write_all_unpin(data)
                    .await
                    .expect("the answer is written");
            }
            writer.close().expect("the answer ends");
            request
        });

        let (mut writer, mut reader) = client_layer
            .try_open_bi()
            .expect("the server grants streams");
        writer
            .write_all_unpin(Bytes::from_static(REQUEST))
            .await
            .expect("the request is written");
        writer.close().expect("the request ends");
        let mut received = Vec::new();
        let read_answer = async {
            while let Some(chunk) = reader
                .read_chunk_unpin(NonZeroUsize::new(4096).unwrap())
                .await
                .expect("the answer is read")
            {
                received.extend_from_slice(&chunk);
            }
        };
        if let Change::PathMtu(limit) = change {
            // Watch the shared conclusion during the transfer. Loss of large
            // packets takes it back to 1200, then smaller probes succeed.
            let reprobe = async {
                while pair.server_link().datagram_size_conclusion() != 1200 {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                while !(1201..=limit).contains(&pair.server_link().datagram_size_conclusion()) {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            };
            futures_util::future::join(
                within("the answer arrives", read_answer),
                within("black hole detection and a new confirmed size", reprobe),
            )
            .await;
        } else {
            within("the answer arrives", read_answer).await;
        }
        let request = within("the server's application ends", server_application)
            .await
            .unwrap();
        assert_eq!(request, REQUEST);
        assert!(received == answer(), "the whole answer arrives in order");

        let server_conclusion = pair.server_link().datagram_size_conclusion();
        pair.client_conn.close(AppClose(7));
        let CloseReason::Local(cause) =
            within("the client's close", pair.client_conn.closed()).await
        else {
            panic!("the client closes for its own reason");
        };
        assert!(matches!(*cause, LocalCloseCause::Application(AppClose(7))));
        match within("the server's close", pair.server_conn.closed()).await {
            CloseReason::Peer(ImmediateClose::Application(close)) => {
                assert_eq!(close.code.get(), VarInt::from_u32(7));
            }
            // the client's close can be lost: the server then ends at its
            // idle timeout, which is no protocol error either
            CloseReason::IdleTimeout => {}
            other => panic!("the server closes for the client's reason, not {other:?}"),
        }
        let (to_server, to_client) = pair.finish().await;
        Outcome {
            to_server,
            to_client,
            changed_at,
            server_conclusion,
        }
    })
}

/// Runs the scenario twice with `seed` and checks that both runs met the
/// same fates; the first run's outcome.
fn twice(seed: u64, impairments: &Impairments, change: impl Fn() -> Change) -> Outcome {
    let first = exchange(seed, impairments.clone(), change(), None);
    let second = exchange(seed, impairments.clone(), change(), None);
    assert_eq!(first, second, "the same seed meets the same fates");
    summarize(seed, &first.to_server, &first.to_client);
    first
}

/// Prints what crossed the network in each direction, for whoever reads
/// the test's output.
fn summarize(seed: u64, to_server: &[DatagramFate], to_client: &[DatagramFate]) {
    for (direction, fates) in [("to-server", to_server), ("to-client", to_client)] {
        let count = |f: fn(&DatagramFate) -> bool| fates.iter().filter(|fate| f(fate)).count();
        println!(
            "[impairment] seed {seed} {direction}: {} datagrams, largest {} bytes, {} dropped, \
             {} corrupted, {} duplicated, {} reordered",
            fates.len(),
            fates.iter().map(|fate| fate.len).max().unwrap_or(0),
            count(|fate| fate.dropped.is_some()),
            count(|fate| fate.corrupted.is_some()),
            count(|fate| fate.duplicated),
            count(|fate| fate.reordered),
        );
    }
}

fn dropped(fates: &[DatagramFate]) -> usize {
    fates.iter().filter(|fate| fate.dropped.is_some()).count()
}

fn plain() -> DirectionImpairments {
    DirectionImpairments {
        delay: DELAY,
        ..DirectionImpairments::default()
    }
}

/// The datagrams of `fates` numbered after `from`.
fn after(fates: &[DatagramFate], from: u64) -> Vec<DatagramFate> {
    fates
        .iter()
        .filter(|fate| fate.number > from)
        .cloned()
        .collect()
}

// ==== reading qlog ====

/// An empty directory for the qlog of the scenario `name`, under Cargo's
/// directory for the tests' temporary files.
fn qlog_dir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("qlog")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the qlog directory is made");
    dir
}

/// One event of a qlog file: its time, its name and its whole record.
#[derive(Debug)]
struct QlogEvent {
    time: f64,
    name: String,
    record: String,
}

impl QlogEvent {
    fn has(&self, text: &str) -> bool {
        self.record.contains(text)
    }
}

/// The events of the one file of `dir` whose name ends in `suffix`,
/// checked as JSON-SEQ records of qlog (main-schema §5, §11.2): each record
/// starts with RS and ends with LF, is one object whose brackets balance
/// outside its strings, the first is the header of a sequential file of
/// the QUIC events of the vantage point `vantage`, and the events are in
/// the order of their times.
fn qlog_events(dir: &Path, vantage: &str) -> Vec<QlogEvent> {
    let suffix = format!("_{vantage}.sqlog");
    let mut paths = std::fs::read_dir(dir)
        .expect("the qlog directory reads")
        .map(|entry| entry.expect("an entry reads").path())
        .filter(|path| path.to_str().is_some_and(|path| path.ends_with(&suffix)));
    let path = paths
        .next()
        .unwrap_or_else(|| panic!("a file {suffix} in {dir:?}"));
    assert!(paths.next().is_none(), "one file {suffix} in {dir:?}");
    let text = String::from_utf8(std::fs::read(&path).expect("the file reads")).expect("UTF-8");
    let mut records = text.split('\u{1e}');
    assert_eq!(records.next(), Some(""), "the file starts with RS");
    let records: Vec<&str> = records.collect();
    for record in &records {
        assert!(record.ends_with('\n'), "a record ends with LF: {record:?}");
        let record = &record[..record.len() - 1];
        assert!(
            record.starts_with('{') && record.ends_with('}'),
            "a record is an object: {record}"
        );
        assert!(balanced(record), "the brackets balance: {record}");
    }
    let (header, events) = records.split_first().expect("a header");
    for member in [
        r#""file_schema":"urn:ietf:params:qlog:file:sequential""#,
        r#""serialization_format":"application/qlog+json-seq""#,
        r#""time_format":"relative_to_epoch""#,
        r#""clock_type":"monotonic","epoch":"unknown""#,
    ] {
        assert!(header.contains(member), "the header has {member}: {header}");
    }
    assert!(header.contains(&format!(r#""vantage_point":{{"type":"{vantage}"}}"#)));
    assert!(header.contains(&format!(r#""event_schemas":["{QUIC_EVENT_SCHEMA}"]"#)));
    let events: Vec<QlogEvent> = events
        .iter()
        .map(|record| {
            let time = between(record, r#"{"time":"#, ",")
                .parse()
                .expect("the time is a number");
            let name = between(record, r#","name":""#, "\"").to_owned();
            QlogEvent {
                time,
                name,
                record: (*record).to_owned(),
            }
        })
        .collect();
    for pair in events.windows(2) {
        assert!(
            pair[0].time <= pair[1].time,
            "in the order of time: {pair:?}"
        );
    }
    events
}

/// The text of `record` after the first `start` up to the next `end`.
fn between<'a>(record: &'a str, start: &str, end: &str) -> &'a str {
    let from = record
        .find(start)
        .unwrap_or_else(|| panic!("{start} in {record}"))
        + start.len();
    let to = record[from..]
        .find(end)
        .unwrap_or_else(|| panic!("{end} in {record}"));
    &record[from..from + to]
}

/// Whether the brackets and braces of `json` balance, outside its strings.
fn balanced(json: &str) -> bool {
    let mut open = Vec::new();
    let mut in_string = false;
    let mut escaped = false;
    for c in json.chars() {
        if in_string {
            match (escaped, c) {
                (true, _) => escaped = false,
                (false, '\\') => escaped = true,
                (false, '"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '{' | '[' => open.push(c),
            '}' if open.pop() != Some('{') => return false,
            ']' if open.pop() != Some('[') => return false,
            _ => {}
        }
    }
    open.is_empty() && !in_string
}

/// Runs the scenario twice with `seed`, each run writing qlog into a new
/// directory named after `name`, and checks that both runs met the same
/// fates and wrote the same events, by name, in the same order; the first
/// run's outcome and the second run's events of the client and the server.
fn twice_logged(
    seed: u64,
    impairments: &Impairments,
    name: &str,
) -> (Outcome, Vec<QlogEvent>, Vec<QlogEvent>) {
    let run = || {
        // the client's first connection ID is random: each run its own file
        let qlog = qlog_dir(name);
        let outcome = exchange(seed, impairments.clone(), Change::None, Some(&qlog));
        (
            outcome,
            qlog_events(&qlog, "client"),
            qlog_events(&qlog, "server"),
        )
    };
    let (first, first_client, first_server) = run();
    let (second, client, server) = run();
    assert_eq!(first, second, "the same seed meets the same fates");
    let names = |events: &[QlogEvent]| {
        events
            .iter()
            .map(|event| event.name.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(names(&first_client), names(&client), "the client's events");
    assert_eq!(names(&first_server), names(&server), "the server's events");
    summarize(seed, &first.to_server, &first.to_client);
    (first, client, server)
}

/// The packet an event of `packet_sent`, `packet_received` or
/// `packet_lost` is about: its type and number.
fn packet_of(event: &QlogEvent) -> (String, u64) {
    let header = between(&event.record, r#""header":{"#, "}");
    let packet_type = between(header, r#""packet_type":""#, "\"").to_owned();
    let key = r#""packet_number":"#;
    let at = header.find(key).expect("a packet number") + key.len();
    let number = header[at..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .expect("a packet number");
    (packet_type, number)
}

/// The data a STREAM or CRYPTO frame carries: for a STREAM frame, its
/// stream; the range of bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Carried {
    Stream {
        stream_id: u64,
        range: core::ops::Range<u64>,
    },
    Crypto {
        range: core::ops::Range<u64>,
    },
}

/// The STREAM and CRYPTO frames of the packet event `event` that carry
/// bytes, as this crate's qlog writes them.
fn carried(event: &QlogEvent) -> Vec<Carried> {
    let record = &event.record;
    let number = |frame: &str, key: &str| {
        frame.find(key).map(|at| {
            let digits: String = frame[at + key.len()..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            digits.parse::<u64>().expect("a number")
        })
    };
    let mut frames = Vec::new();
    for kind in ["stream", "crypto"] {
        let start = format!(r#"{{"frame_type":"{kind}""#);
        let mut from = 0;
        while let Some(at) = record[from..].find(&start) {
            let at = from + at;
            // the frame's object ends after its `raw` object
            let end = at + record[at..].find("}}").expect("the frame ends") + 2;
            let frame = &record[at..end];
            from = end;
            let offset = number(frame, r#""offset":"#).unwrap_or(0);
            let length = number(frame, r#""length":"#).expect("a length");
            if length == 0 {
                continue;
            }
            let range = offset..offset + length;
            frames.push(match kind {
                "stream" => Carried::Stream {
                    stream_id: number(frame, r#""stream_id":"#).expect("a stream"),
                    range,
                },
                _ => Carried::Crypto { range },
            });
        }
    }
    frames
}

/// Whether `ranges` cover all of `range`.
fn covered(range: &core::ops::Range<u64>, ranges: &[core::ops::Range<u64>]) -> bool {
    let mut ranges = ranges.to_vec();
    ranges.sort_by_key(|range| range.start);
    let mut through = range.start;
    for other in ranges {
        if other.start > through {
            break;
        }
        through = through.max(other.end);
        if through >= range.end {
            return true;
        }
    }
    through >= range.end
}

/// For each packet `sender` declared lost that `receiver` never received,
/// the stream and CRYPTO data it carried reached `receiver` in other
/// packets: of the same stream, or for CRYPTO data of the same packet type
/// (its packet number space). The other frames are not compared: PING is
/// not sent again, and flow control frames are sent again with newer
/// values (RFC 9000 §13.3). The number of the packets checked.
fn lost_data_arrives(sender: &[QlogEvent], receiver: &[QlogEvent]) -> usize {
    let received: Vec<((String, u64), Vec<Carried>)> = receiver
        .iter()
        .filter(|event| event.name == "quic:packet_received")
        .map(|event| (packet_of(event), carried(event)))
        .collect();
    let mut checked = 0;
    for lost in sender
        .iter()
        .filter(|event| event.name == "quic:packet_lost")
    {
        let packet = packet_of(lost);
        let sent = sender
            .iter()
            .find(|event| event.name == "quic:packet_sent" && packet_of(event) == packet)
            .unwrap_or_else(|| panic!("the lost packet {packet:?} was sent"));
        if received.iter().any(|(other, _)| *other == packet) {
            // declared lost, but it arrived
            continue;
        }
        checked += 1;
        for data in carried(sent) {
            let mut elsewhere = Vec::new();
            for ((packet_type, _), frames) in &received {
                for frame in frames {
                    match (&data, frame) {
                        (
                            Carried::Stream { stream_id, .. },
                            Carried::Stream {
                                stream_id: other,
                                range,
                            },
                        ) if stream_id == other => elsewhere.push(range.clone()),
                        (Carried::Crypto { .. }, Carried::Crypto { range })
                            if *packet_type == packet.0 =>
                        {
                            elsewhere.push(range.clone());
                        }
                        _ => {}
                    }
                }
            }
            let (Carried::Stream { range, .. } | Carried::Crypto { range }) = &data;
            assert!(
                covered(range, &elsewhere),
                "{data:?} of the lost packet {packet:?} arrives in other packets"
            );
        }
    }
    checked
}

// ==== the scenarios ====

#[test]
fn the_answer_arrives_over_a_network_without_impairments() {
    let outcome = twice(1, &Impairments::both(plain()), || Change::None);
    assert_eq!(dropped(&outcome.to_server) + dropped(&outcome.to_client), 0);
}

#[test]
fn the_answer_arrives_when_three_in_ten_datagrams_are_lost_at_most_three_in_a_row() {
    let impairments = Impairments::both(DirectionImpairments {
        loss: Some(RandomLoss {
            rate: Probability::percent(30),
            burst: 3,
        }),
        ..plain()
    });
    let (outcome, client, server) = twice_logged(42, &impairments, "loss");
    assert!(dropped(&outcome.to_server) > 0 && dropped(&outcome.to_client) > 0);
    // what the lost packets carried reaches the peer in others
    let checked = lost_data_arrives(&client, &server) + lost_data_arrives(&server, &client);
    println!("[impairment] seed 42: {checked} packets declared lost and never received");
    assert!(checked > 0, "some packets declared lost were lost");
}

#[test]
fn the_answer_arrives_when_the_first_flights_are_dropped_by_number() {
    // the droplist the interop runner's amplification limit test uses: the
    // client's second to seventh datagrams
    let impairments = Impairments {
        to_server: DirectionImpairments {
            drop_list: (2..=7).collect(),
            ..plain()
        },
        to_client: plain(),
    };
    let outcome = twice(2, &impairments, || Change::None);
    assert_eq!(
        dropped(&outcome.to_server),
        6.min(outcome.to_server.len() - 1)
    );
}

#[test]
fn the_answer_arrives_when_datagrams_are_reordered_and_duplicated() {
    let impairments = Impairments::both(DirectionImpairments {
        reorder: Some(Reorder {
            rate: Probability::percent(10),
            delay: Duration::from_millis(15),
        }),
        duplicate: Probability::percent(5),
        ..plain()
    });
    let outcome = twice(7, &impairments, || Change::None);
    let all = || outcome.to_server.iter().chain(&outcome.to_client);
    assert!(all().any(|fate| fate.reordered) && all().any(|fate| fate.duplicated));
}

#[test]
fn the_answer_arrives_when_datagrams_are_corrupted_near_their_start() {
    let impairments = Impairments::both(DirectionImpairments {
        corrupt: Probability::percent(5),
        ..plain()
    });
    let (outcome, client, server) = twice_logged(11, &impairments, "corruption");
    let all = || outcome.to_server.iter().chain(&outcome.to_client);
    assert!(all().any(|fate| fate.corrupted.is_some()));
    // a corrupted packet does not open and is dropped, or a corrupted
    // connection ID leaves its datagram to no connection; a packet fails to
    // open only on a side some corrupted datagram went to, and neither side
    // closes for an error
    let failed = |events: &[QlogEvent]| {
        events
            .iter()
            .filter(|event| {
                event.name == "quic:packet_dropped"
                    && event.has(r#""trigger":"decryption_failure""#)
            })
            .count()
    };
    let corrupted =
        |fates: &[DatagramFate]| fates.iter().filter(|fate| fate.corrupted.is_some()).count();
    for (side, events, toward) in [
        ("client", &client, &outcome.to_client),
        ("server", &server, &outcome.to_server),
    ] {
        assert!(
            failed(events) == 0 || corrupted(toward) > 0,
            "the {side} fails to open packets only when datagrams to it are corrupted"
        );
        assert!(
            !events
                .iter()
                .any(|event| event.name == "quic:connection_closed"
                    && event.has(r#""connection_error""#)),
            "the {side} does not close for a transport error"
        );
    }
    assert!(
        failed(&client) + failed(&server) > 0,
        "some corrupted packet does not open"
    );
}

#[test]
fn the_answer_arrives_across_a_blackhole() {
    // the handshake fits in the first 100 ms; then two seconds of silence
    let impairments = Impairments::both(DirectionImpairments {
        blackhole: Some(Blackhole {
            on: Duration::from_millis(100),
            off: Duration::from_secs(2),
            repeat: 1,
        }),
        ..plain()
    });
    let outcome = twice(3, &impairments, || Change::None);
    assert!(dropped(&outcome.to_server) + dropped(&outcome.to_client) > 0);
}

#[test]
fn a_memory_link_accepts_the_prefix_before_an_oversized_datagram() {
    use sakuya_link::{EcnMarking, OutgoingDatagram};

    run_paused(async {
        let network =
            MemoryNetwork::new(TokioClock, 0, server_address(), Impairments::both(plain()));
        let binding = network.bind(client_address());
        let link = binding.connect(server_address()).await.unwrap();
        network.set_max_datagram_size(client_address(), 1280);
        let batch = [1280, 1281, 1200].map(|size| OutgoingDatagram {
            payload: Bytes::from(vec![0; size]),
            ecn: EcnMarking::NotEct,
        });
        assert_eq!(link.send(&batch).await.unwrap().count.get(), 1);
        assert!(link.send(&batch[1..]).await.is_err());
        assert_eq!(link.send(&batch[2..]).await.unwrap().count.get(), 1);
        let lengths: Vec<_> = network
            .fates(Direction::ToServer)
            .iter()
            .map(|fate| fate.len)
            .collect();
        assert_eq!(lengths, [1280, 1200]);
    });
}

/// The server uses a size confirmed by a marked probe to carry stream
/// data, within the memory link's 1452-byte limit.
#[test]
fn a_confirmed_datagram_size_probe_raises_the_size_used_for_the_answer() {
    let (outcome, _, server) = twice_logged(23, &Impairments::both(plain()), "pmtu");
    let size = outcome.server_conclusion;
    assert!((1201..=1452).contains(&size));
    let packet_length = format!(r#"],"raw":{{"length":{size},"#);
    assert!(server.iter().any(|event| {
        event.name == "quic:packet_sent"
            && event.has(r#""is_mtu_probe_packet":true"#)
            && event.has(&packet_length)
    }));
    let largest_stream_packet = server
        .iter()
        .filter(|event| event.name == "quic:packet_sent" && event.has(r#""frame_type":"stream""#))
        .map(|event| {
            between(&event.record, r#"],"raw":{"length":"#, ",")
                .parse::<usize>()
                .unwrap()
        })
        .max()
        .expect("stream data was sent");
    assert!((1201..=size).contains(&largest_stream_packet));
    assert!(outcome.to_client.iter().all(|fate| fate.len <= 1452));
}

#[test]
fn after_the_links_report_a_lower_limit_no_larger_datagram_is_sent() {
    const LIMIT: usize = 1280;
    let outcome = twice(5, &Impairments::both(plain()), || Change::LinkLimit(LIMIT));
    let (to_server, to_client) = outcome.changed_at.expect("the network changed");
    assert!(
        outcome
            .to_client
            .iter()
            .any(|fate| fate.number <= to_client && fate.len > LIMIT)
    );
    for (fates, from) in [
        (&outcome.to_server, to_server),
        (&outcome.to_client, to_client),
    ] {
        let after = after(fates, from);
        assert!(!after.is_empty());
        assert!(after.iter().all(|fate| fate.len <= LIMIT));
    }
}

#[test]
fn the_answer_arrives_when_the_path_mtu_falls_without_a_word() {
    const MTU: usize = 1250;
    let outcome = twice(9, &Impairments::both(plain()), || Change::PathMtu(MTU));
    let (_, changed) = outcome.changed_at.expect("the path MTU changed");
    let after = after(&outcome.to_client, changed);
    assert!(
        after
            .iter()
            .any(|fate| fate.dropped == Some(DropCause::PathMtu))
    );
    // Every larger datagram sent after the change is dropped before it
    // reaches the peer, so none can be acknowledged.
    assert!(
        after
            .iter()
            .filter(|fate| fate.len > MTU)
            .all(|fate| fate.dropped == Some(DropCause::PathMtu))
    );
    assert!((1201..=MTU).contains(&outcome.server_conclusion));
}

/// A link whose limit falls below 1200 bytes cannot carry QUIC (RFC 9000
/// §14): the server, whose only link path it is, closes with
/// NO_VIABLE_PATH; the client hears that close or ends at its idle timeout.
#[test]
fn a_link_whose_limit_falls_below_1200_bytes_ends_the_connection_with_no_viable_path() {
    let run = || {
        run_paused(async {
            let pair = Pair::connect(17, Impairments::both(plain()), None).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
            pair.network.set_max_datagram_size(server_address(), 1100);
            let server_closed = within("the server's close", pair.server_conn.closed()).await;
            let CloseReason::Local(cause) = &server_closed else {
                panic!("the server closes for its own reason, not {server_closed:?}");
            };
            let Some(ImmediateClose::Transport(close)) = cause.immediate_close() else {
                panic!("the server closes with a transport error, not {cause}");
            };
            assert_eq!(close.code, TransportErrorCode::NO_VIABLE_PATH);
            match within("the client's close", pair.client_conn.closed()).await {
                CloseReason::Peer(ImmediateClose::Transport(close)) => {
                    assert_eq!(close.code, TransportErrorCode::NO_VIABLE_PATH);
                }
                CloseReason::IdleTimeout => {}
                other => panic!("the client ends for the server's close, not {other:?}"),
            }
            pair.finish().await
        })
    };
    let (to_server, to_client) = run();
    assert_eq!(
        (to_server.clone(), to_client.clone()),
        run(),
        "the same seed meets the same fates"
    );
    summarize(17, &to_server, &to_client);
}

/// A path whose MTU falls below 1200 bytes without a word, as a tunnel
/// that drops larger datagrams does, carries no full-sized packet: neither
/// side learns that it cannot carry QUIC (RFC 9000 §14) and the default
/// strategy does not tell this black hole apart, so both end at their idle
/// timeout, with no protocol error, no panic, and no wait without end.
#[test]
fn a_path_whose_mtu_falls_below_1200_bytes_without_a_word_ends_at_the_idle_timeout() {
    const MTU: usize = 1100;
    let run = || {
        run_paused(async {
            let pair = Pair::connect(19, Impairments::both(plain()), None).await;
            let client_layer = pair.client_conn.established().await.expect("established");
            let server_layer = pair.server_conn.established().await.expect("established");
            tokio::time::sleep(Duration::from_millis(200)).await;
            pair.network.set_path_mtu(Direction::ToServer, Some(MTU));
            pair.network.set_path_mtu(Direction::ToClient, Some(MTU));
            let changed = pair.counts();
            // the answer would take full-sized packets; whatever the
            // streams meet once the connections end is theirs
            let server_application = spawn_local(async move {
                let Ok((mut writer, _reader)) = server_layer.accept_bi().await else {
                    return;
                };
                if writer.write_all_unpin(Bytes::from(answer())).await.is_ok() {
                    let _ = writer.close();
                }
            });
            // the client's halves are kept until the end
            let (mut writer, reader) = client_layer
                .try_open_bi()
                .expect("the server grants streams");
            if writer
                .write_all_unpin(Bytes::from_static(REQUEST))
                .await
                .is_ok()
            {
                let _ = writer.close();
            }
            let server_closed = within("the server's end", pair.server_conn.closed()).await;
            assert!(
                matches!(server_closed, CloseReason::IdleTimeout),
                "the server ends at its idle timeout, not {server_closed:?}"
            );
            let client_closed = within("the client's end", pair.client_conn.closed()).await;
            assert!(
                matches!(client_closed, CloseReason::IdleTimeout),
                "the client ends at its idle timeout, not {client_closed:?}"
            );
            within("the server's application ends", server_application)
                .await
                .unwrap();
            drop((writer, reader));
            let (to_server, to_client) = pair.finish().await;
            (changed, to_server, to_client)
        })
    };
    let (changed, to_server, to_client) = run();
    assert_eq!(
        (changed, to_server.clone(), to_client.clone()),
        run(),
        "the same seed meets the same fates"
    );
    // full-sized datagrams went after the change, and the path dropped
    // every one of them
    for (fates, from) in [(&to_server, changed.0), (&to_client, changed.1)] {
        let after = after(fates, from);
        assert!(
            after
                .iter()
                .all(|fate| fate.len <= MTU || fate.dropped == Some(DropCause::PathMtu))
        );
    }
    assert!(
        after(&to_client, changed.1)
            .iter()
            .any(|fate| fate.dropped == Some(DropCause::PathMtu))
    );
    summarize(19, &to_server, &to_client);
}

// ==== migration ====

/// How the client's datagrams reach the server from another address.
#[derive(Clone, Copy)]
enum Movement {
    /// The client's NAT rebinds: its datagrams come from the address.
    Rebind(SocketAddr),
    /// An attacker sends a copy of the client's next datagram from the
    /// address, ahead of the original (RFC 9000 §9.3.3).
    Spoof(SocketAddr),
}

/// What a run of a migration scenario saw.
#[derive(Debug, PartialEq, Eq)]
struct MigrationRun {
    to_server: Vec<DatagramFate>,
    to_client: Vec<DatagramFate>,
    /// How many datagrams had been numbered in each direction when the
    /// client's datagrams began to come from another address.
    before: (u64, u64),
    /// The datagrams the server sent to the address its packets came from
    /// in `Movement`, by their number of bytes.
    to_moved: Vec<usize>,
    /// The names and records of the events of each side.
    client: Vec<(String, String)>,
    server: Vec<(String, String)>,
}

/// Whether `events` hold a packet event `name` with a frame of `frame`.
fn has_frame(events: &[(String, String)], name: &str, frame: &str) -> bool {
    let frame = format!(r#""frame_type":"{frame}""#);
    events
        .iter()
        .any(|(event, record)| event == name && record.contains(&frame))
}

/// One run: the connection is up and quiet, then the client's datagrams
/// reach the server from another address as `movement` says, the client
/// asks and the server answers; the client reads the whole answer and
/// closes. The connections write qlog into the directory `name`.
fn migration_exchange(name: &str, seed: u64, at: Addresses, movement: Movement) -> MigrationRun {
    // the client's first connection ID is random: each run its own file
    let qlog = qlog_dir(name);
    run_paused(async move {
        let pair = Pair::connect_at(seed, Impairments::both(plain()), Some(&qlog), &at).await;
        let client_layer = pair.client_conn.established().await.expect("established");
        let server_layer = pair.server_conn.established().await.expect("established");
        // the handshake's last acknowledgements cross before the move
        tokio::time::sleep(Duration::from_millis(200)).await;
        let before = pair.counts();
        let sent_before = pair.network.sent_to(at.server).len();

        let server_application = spawn_local(async move {
            let (mut writer, mut reader) = server_layer
                .accept_bi()
                .await
                .expect("the client's stream is accepted");
            let mut request = Vec::new();
            while let Some(chunk) = reader
                .read_chunk_unpin(NonZeroUsize::new(1024).unwrap())
                .await
                .expect("the request is read")
            {
                request.extend_from_slice(&chunk);
            }
            writer
                .write_all_unpin(Bytes::from(answer()))
                .await
                .expect("the answer is written");
            writer.close().expect("the answer ends");
            request
        });

        let moved = match movement {
            Movement::Rebind(to) => {
                pair.network.rebind(at.client, to);
                to
            }
            Movement::Spoof(from) => from,
        };
        let (mut writer, mut reader) = client_layer
            .try_open_bi()
            .expect("the server grants streams");
        writer
            .write_all_unpin(Bytes::from_static(REQUEST))
            .await
            .expect("the request is written");
        writer.close().expect("the request ends");
        if matches!(movement, Movement::Spoof(_)) {
            // the client's next datagram is on its way for the network's
            // delay: copy it at once and send the copy from `moved` first
            let mut tries = 0;
            let copy = loop {
                if let Some(copy) = pair.network.sent_to(at.server).get(sent_before) {
                    break copy.clone();
                }
                tries += 1;
                assert!(tries < 100_000, "the client sends a datagram");
                tokio::task::yield_now().await;
            };
            pair.network.inject(moved, at.server, &copy);
        }

        let mut received = Vec::new();
        within("the answer arrives", async {
            while let Some(chunk) = reader
                .read_chunk_unpin(NonZeroUsize::new(4096).unwrap())
                .await
                .expect("the answer is read")
            {
                received.extend_from_slice(&chunk);
            }
        })
        .await;
        let request = within("the server's application ends", server_application)
            .await
            .unwrap();
        assert_eq!(request, REQUEST);
        assert!(received == answer(), "the whole answer arrives in order");

        pair.client_conn.close(AppClose(7));
        let CloseReason::Local(cause) =
            within("the client's close", pair.client_conn.closed()).await
        else {
            panic!("the client closes for its own reason");
        };
        assert!(matches!(*cause, LocalCloseCause::Application(AppClose(7))));
        match within("the server's close", pair.server_conn.closed()).await {
            CloseReason::Peer(ImmediateClose::Application(close)) => {
                assert_eq!(close.code.get(), VarInt::from_u32(7));
            }
            // the client's close can be lost: the server then ends at its
            // idle timeout, which is no protocol error either
            CloseReason::IdleTimeout => {}
            other => panic!("the server closes for the client's reason, not {other:?}"),
        }
        let to_moved = pair
            .network
            .sent_to(moved)
            .iter()
            .map(Bytes::len)
            .collect::<Vec<_>>();
        let (to_server, to_client) = pair.finish().await;
        let events = |vantage| {
            qlog_events(&qlog, vantage)
                .into_iter()
                .map(|event| (event.name, event.record))
                .collect()
        };
        MigrationRun {
            to_server,
            to_client,
            before,
            to_moved,
            client: events("client"),
            server: events("server"),
        }
    })
}

/// Runs a migration scenario twice with `seed` and checks that both runs
/// met the same fates and sent the same datagrams to the moved address;
/// the first run.
fn migration_twice(
    name: &str,
    seed: u64,
    at: impl Fn() -> Addresses,
    movement: Movement,
) -> MigrationRun {
    let first = migration_exchange(name, seed, at(), movement);
    let second = migration_exchange(name, seed, at(), movement);
    assert_eq!(
        (
            &first.to_server,
            &first.to_client,
            first.before,
            &first.to_moved
        ),
        (
            &second.to_server,
            &second.to_client,
            second.before,
            &second.to_moved
        ),
        "the same seed meets the same fates"
    );
    let names = |events: &[(String, String)]| {
        events
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(names(&first.client), names(&second.client));
    assert_eq!(names(&first.server), names(&second.server));
    summarize(seed, &first.to_server, &first.to_client);
    first
}

/// After the move the client's datagrams reach the server and are not
/// dropped, and the server's reach the client at its new address, but for
/// those it sent to the address the client left.
fn assert_followed(run: &MigrationRun) {
    let up = after(&run.to_server, run.before.0);
    let down = after(&run.to_client, run.before.1);
    assert!(!up.is_empty() && up.iter().all(|fate| fate.dropped.is_none()));
    assert!(
        down.iter().any(|fate| fate.dropped.is_none())
            && down
                .iter()
                .all(|fate| matches!(fate.dropped, None | Some(DropCause::NoDestination))),
        "the server follows the client to its new address: {down:?}"
    );
    assert!(
        !run.server
            .iter()
            .any(|(name, record)| name == "quic:packet_dropped"
                && record.contains(r#""reason":"no_link_path""#)),
        "the server takes the packets of the new link"
    );
}

/// Both sides handled the validation of the new path: the server sent
/// PATH_CHALLENGE and the client received it, and the client answered with
/// PATH_RESPONSE, which the server received.
fn assert_validated(run: &MigrationRun) {
    assert!(has_frame(&run.server, "quic:packet_sent", "path_challenge"));
    assert!(has_frame(
        &run.client,
        "quic:packet_received",
        "path_challenge"
    ));
    assert!(has_frame(&run.client, "quic:packet_sent", "path_response"));
    assert!(has_frame(
        &run.server,
        "quic:packet_received",
        "path_response"
    ));
}

/// How many NEW_TOKEN frames the client received.
fn new_tokens(run: &MigrationRun) -> usize {
    run.client
        .iter()
        .filter(|(name, record)| {
            name == "quic:packet_received" && record.contains(r#""frame_type":"new_token""#)
        })
        .count()
}

/// A client whose datagrams come from a new port after the handshake is
/// followed before its new address is validated: the server's binding takes
/// a new link for that address; the server's connection builds a candidate
/// link path for the client's request, which is a non-probing packet, and
/// switches to it at once, the recovery layer moving with it as only the
/// port changed (RFC 9000 §9.3, §9.4). The server validates the new path
/// with PATH_CHALLENGE, which the client answers; the one the server sends
/// to the old address is dropped, as the client is not there any more. The
/// server's application answers the request, and the client reads the whole
/// answer from the new address.
#[test]
fn a_client_rebound_to_a_new_port_after_the_handshake_gets_its_answer() {
    let rebound = SocketAddr::from(([10, 0, 0, 2], 50_001));
    assert_eq!(rebound.ip(), client_address().ip(), "only the port changes");
    let run = migration_twice(
        "rebind-port",
        13,
        Addresses::plain,
        Movement::Rebind(rebound),
    );
    assert_followed(&run);
    assert_validated(&run);
    // a token once the handshake is confirmed, and one for the new address
    // once it is validated, though only the port changed (RFC 9000
    // §8.1.3); nothing is lost to send either again
    assert_eq!(new_tokens(&run), 2, "the client receives two tokens");
}

/// A client whose datagrams come from another IP address after the
/// handshake is followed as well: the server builds a recovery layer for
/// the new path instead of moving the old one (the network address
/// changed), validates the path with PATH_CHALLENGE, which the client
/// answers with PATH_RESPONSE, and the answer reaches the client there.
#[test]
fn a_client_rebound_to_a_new_ip_after_the_handshake_validates_the_path_and_gets_its_answer() {
    let rebound = SocketAddr::from(([10, 0, 0, 3], 50_000));
    let run = migration_twice("rebind-ip", 13, Addresses::plain, Movement::Rebind(rebound));
    assert_followed(&run);
    assert_validated(&run);
    // the server sent to the new address (qlog has no event that tells a
    // moved recovery layer from a new one, so that is not asserted)
    assert!(!run.to_moved.is_empty());
}

/// An attacker copies a datagram of the client and sends the copy to the
/// server from another address ahead of the original (RFC 9000 §9.3.3):
/// the server takes the copy as the highest-numbered non-probing packet and
/// switches to the new address, which it challenges; nobody answers there.
/// The original is a duplicate; the server falls back to the client's
/// address once the client's next packets come from it, and the client
/// completes its request and reads the whole answer.
#[test]
fn a_copied_datagram_from_another_address_does_not_take_the_connection_from_its_client() {
    let attacker = SocketAddr::from(([10, 0, 0, 9], 6000));
    let run = migration_twice("spoof", 13, Addresses::plain, Movement::Spoof(attacker));
    assert!(
        has_frame(&run.server, "quic:packet_sent", "path_challenge"),
        "the server challenges the attacker's address"
    );
    assert!(
        !run.to_moved.is_empty(),
        "the server sends to the attacker's address"
    );
    assert!(
        !run.server
            .iter()
            .any(|(name, record)| name == "quic:packet_dropped"
                && record.contains(r#""reason":"no_link_path""#)),
    );
}

/// A server that sent `disable_active_migration` still follows a client
/// rebound by its NAT: the parameter forbids the client's active migration,
/// not the change of its address (RFC 9000 §9). The client received the
/// parameter; the answer reaches it at the new address.
#[test]
fn a_server_that_disabled_active_migration_still_follows_a_rebound_client() {
    let rebound = SocketAddr::from(([10, 0, 0, 2], 50_001));
    let at = || Addresses {
        disable_active_migration: true,
        ..Addresses::plain()
    };
    let run = migration_twice("rebind-disabled", 13, at, Movement::Rebind(rebound));
    assert_followed(&run);
    assert_validated(&run);
    assert!(
        run.server
            .iter()
            .any(|(_, record)| record.contains(r#""disable_active_migration":true"#)),
        "the server sent the parameter"
    );
}

// ECN is not tested here: the network in memory never marks ECN (its links'
// `may_mark_ecn` is false), so ECN validation and CE marks cannot happen on
// it. The unit tests of `sakuya_connection` and the runner's `ecn` test case
// cover them.

// ==== the server's preferred address ====

/// The port of the preferred addresses of the scenarios.
const PREFERRED_PORT: u16 = 4433;

/// What a run with a preferred address saw.
struct PreferredRun {
    /// The datagrams the client sent to the server's original address.
    to_original: Vec<Bytes>,
    /// Those it sent to each address of the preferred address, in the order
    /// the addresses are given.
    to_preferred: Vec<Vec<Bytes>>,
    client: Vec<QlogEvent>,
    server: Vec<QlogEvent>,
}

/// The Destination Connection ID of a datagram of 1-RTT packets to the
/// server, whose connection IDs are eight bytes long; `None` for a long
/// header.
fn short_dcid(datagram: &Bytes) -> Option<&[u8]> {
    (datagram.first()? & 0x80 == 0).then(|| &datagram[1..9])
}

/// One run at `at`, whose server gives a preferred address of the
/// addresses `preferred`: the client asks twice for the answer on a stream
/// of its own, 200 ms apart, so that the second exchange runs once the
/// migration is over. With `redirect`, the client then asks a third time
/// while the datagrams it sends to the first preferred address go to the
/// server's original address instead, for 300 ms. The connections write
/// qlog into the directory `name`.
fn preferred_exchange(
    name: &str,
    at: Addresses,
    preferred: Vec<SocketAddr>,
    redirect: bool,
) -> PreferredRun {
    let qlog = qlog_dir(name);
    run_paused(async move {
        let pair = Pair::connect_at(17, Impairments::both(plain()), Some(&qlog), &at).await;
        let client_layer = pair.client_conn.established().await.expect("established");
        let server_layer = pair.server_conn.established().await.expect("established");
        let exchanges = if redirect { 3 } else { 2 };
        let server_application = spawn_local(async move {
            for _ in 0..exchanges {
                let (mut writer, mut reader) = server_layer
                    .accept_bi()
                    .await
                    .expect("the client's stream is accepted");
                let mut request = Vec::new();
                while let Some(chunk) = reader
                    .read_chunk_unpin(NonZeroUsize::new(1024).unwrap())
                    .await
                    .expect("the request is read")
                {
                    request.extend_from_slice(&chunk);
                }
                assert_eq!(request, REQUEST);
                writer
                    .write_all_unpin(Bytes::from(answer()))
                    .await
                    .expect("the answer is written");
                writer.close().expect("the answer ends");
            }
        });
        for exchange in 0..exchanges {
            if exchange == 1 {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            if exchange == 2 {
                // the server sends from its preferred address now, and has
                // left its original one
                pair.network.redirect(preferred[0], Some(at.server));
            }
            let (mut writer, mut reader) = client_layer
                .try_open_bi()
                .expect("the server grants streams");
            writer
                .write_all_unpin(Bytes::from_static(REQUEST))
                .await
                .expect("the request is written");
            writer.close().expect("the request ends");
            if exchange == 2 {
                tokio::time::sleep(Duration::from_millis(300)).await;
                pair.network.redirect(preferred[0], None);
            }
            let mut received = Vec::new();
            within("the answer arrives", async {
                while let Some(chunk) = reader
                    .read_chunk_unpin(NonZeroUsize::new(4096).unwrap())
                    .await
                    .expect("the answer is read")
                {
                    received.extend_from_slice(&chunk);
                }
            })
            .await;
            assert!(received == answer(), "the whole answer arrives in order");
        }
        within("the server's application ends", server_application)
            .await
            .unwrap();

        pair.client_conn.close(AppClose(7));
        within("the client's close", pair.client_conn.closed()).await;
        let server_closed = within("the server's close", pair.server_conn.closed()).await;
        assert!(
            matches!(
                server_closed,
                CloseReason::Peer(ImmediateClose::Application(_)) | CloseReason::IdleTimeout
            ),
            "the server closes for the client's reason, not {server_closed:?}"
        );
        let to_original = pair.network.sent_to(at.server);
        let to_preferred = preferred
            .iter()
            .map(|&address| pair.network.sent_to(address))
            .collect();
        pair.finish().await;
        PreferredRun {
            to_original,
            to_preferred,
            client: qlog_events(&qlog, "client"),
            server: qlog_events(&qlog, "server"),
        }
    })
}

/// The server at `server`, the client at `client`, and a preferred address
/// of `preferred`, which the server binds.
fn preferred_addresses(
    server: SocketAddr,
    client: SocketAddr,
    preferred: PreferredAddressFamilies,
    bound: &[SocketAddr],
) -> Addresses {
    Addresses {
        server,
        client,
        preferred: Some(preferred),
        preferred_bindings: bound.to_vec(),
        disable_active_migration: false,
    }
}

/// Whether `events` hold a warning that no link was taken to `address`.
fn connect_failed(events: &[QlogEvent], address: SocketAddr) -> bool {
    events.iter().any(|event| {
        event.name == "loglevel:warning" && event.has(&format!("preferred address {address}"))
    })
}

/// A server gives a preferred address of each family; the client, at an
/// IPv4 address, validates the IPv4 one once its handshake is confirmed
/// and sends everything there afterwards. Its first datagram to the new
/// address carries a connection ID it never sent to the original one: the
/// one of the preferred address (RFC 9000 §9.6.1, §9.5), as the runner's
/// `connectionmigration` checks.
#[test]
fn a_client_migrates_to_the_preferred_address_of_its_family() {
    let v4 = SocketAddr::from(([10, 0, 0, 1], PREFERRED_PORT));
    let v6 = SocketAddr::new("fd00::1".parse().unwrap(), PREFERRED_PORT);
    let at = preferred_addresses(
        server_address(),
        client_address(),
        PreferredAddressFamilies::Both(
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), PREFERRED_PORT),
            SocketAddrV6::new("fd00::1".parse().unwrap(), PREFERRED_PORT, 0, 0),
        ),
        &[v4, v6],
    );
    let run = preferred_exchange("preferred-v4", at, vec![v4, v6], false);
    let [to_v4, to_v6] = <[_; 2]>::try_from(run.to_preferred).unwrap();
    assert!(to_v6.is_empty(), "the IPv6 address is not tried");
    assert!(
        to_v4.len() > 20,
        "the client sends the second exchange to the preferred address"
    );
    let first = short_dcid(&to_v4[0]).expect("a 1-RTT packet probes the new path");
    assert!(
        run.to_original
            .iter()
            .filter_map(short_dcid)
            .all(|dcid| dcid != first),
        "the first packet to the preferred address has a new connection ID"
    );
    assert!(
        to_v4.iter().filter_map(short_dcid).all(|dcid| run
            .to_original
            .iter()
            .filter_map(short_dcid)
            .all(|old| old != dcid)),
        "no connection ID goes to both addresses"
    );
    assert!(!connect_failed(&run.client, v4));
    assert!(
        run.server
            .iter()
            .any(|event| event.name == "quic:packet_sent"
                && event.has(r#""frame_type":"path_challenge""#)),
        "the server probes the path from its preferred address"
    );
}

/// The same with the client at an IPv6 address: the IPv4 address comes
/// first, which no link from the client's address reaches, so the policy
/// is asked again and the client migrates to the IPv6 one.
#[test]
fn a_client_that_takes_no_link_to_one_address_is_asked_again_and_migrates_to_the_other() {
    let server = SocketAddr::new("fd00::1".parse().unwrap(), 443);
    let client = SocketAddr::new("fd00::2".parse().unwrap(), 50_000);
    let v4 = SocketAddr::from(([10, 0, 0, 1], PREFERRED_PORT));
    let v6 = SocketAddr::new("fd00::1".parse().unwrap(), PREFERRED_PORT);
    let at = preferred_addresses(
        server,
        client,
        PreferredAddressFamilies::Both(
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), PREFERRED_PORT),
            SocketAddrV6::new("fd00::1".parse().unwrap(), PREFERRED_PORT, 0, 0),
        ),
        &[v4, v6],
    );
    let run = preferred_exchange("preferred-v6", at, vec![v6, v4], false);
    let [to_v6, to_v4] = <[_; 2]>::try_from(run.to_preferred).unwrap();
    assert!(
        connect_failed(&run.client, v4),
        "the reason the IPv4 address failed is an event"
    );
    assert!(to_v4.is_empty());
    assert!(
        to_v6.len() > 20,
        "the client sends the second exchange to the IPv6 address"
    );
}

/// A preferred address of the other family only: no link reaches it, and
/// the client stays on the server's original address (RFC 9000 §9.6.1).
#[test]
fn a_client_offered_only_the_other_family_stays_on_the_original_address() {
    let v6 = SocketAddr::new("fd00::1".parse().unwrap(), PREFERRED_PORT);
    let at = preferred_addresses(
        server_address(),
        client_address(),
        PreferredAddressFamilies::Ipv6(SocketAddrV6::new(
            "fd00::1".parse().unwrap(),
            PREFERRED_PORT,
            0,
            0,
        )),
        &[v6],
    );
    let run = preferred_exchange("preferred-other-family", at, vec![v6], false);
    assert!(connect_failed(&run.client, v6));
    assert!(run.to_preferred[0].is_empty());
}

/// Once the server moved to its preferred address, the newer packets that
/// arrive at its original address are dropped before their frames are
/// read (RFC 9000 §9.6.2 SHOULD); the client's exchange goes on once they
/// reach the preferred address again.
#[test]
fn newer_packets_at_the_servers_original_address_are_dropped_once_it_moved() {
    let v4 = SocketAddr::from(([10, 0, 0, 1], PREFERRED_PORT));
    let at = preferred_addresses(
        server_address(),
        client_address(),
        PreferredAddressFamilies::Ipv4(SocketAddrV4::new(
            Ipv4Addr::new(10, 0, 0, 1),
            PREFERRED_PORT,
        )),
        &[v4],
    );
    let run = preferred_exchange("preferred-old-address", at, vec![v4], true);
    let first_dropped = run
        .server
        .iter()
        .position(|event| {
            event.name == "quic:packet_dropped" && event.has(r#""reason":"old_local_address""#)
        })
        .expect("the server drops the newer packets at its original address");
    // a packet dropped there builds no link path, which would challenge the
    // client from the original address until its validation gave up
    assert!(
        !run.server[first_dropped..]
            .iter()
            .any(|event| event.name == "quic:packet_sent"
                && event.has(r#""frame_type":"path_challenge""#)),
        "no challenge follows the drop"
    );
}

/// The qlog of both sides of a run with losses: the header, and the events
/// of each kind a run like this gives, in the order of time.
#[test]
fn both_sides_write_their_events_as_qlog() {
    let qlog = qlog_dir("exchange");
    let impairments = Impairments::both(DirectionImpairments {
        loss: Some(RandomLoss {
            rate: Probability::percent(10),
            burst: 2,
        }),
        ..plain()
    });
    let outcome = exchange(21, impairments, Change::None, Some(&qlog));
    assert!(dropped(&outcome.to_server) + dropped(&outcome.to_client) > 0);
    let client = qlog_events(&qlog, "client");
    let server = qlog_events(&qlog, "server");
    for (side, events) in [("client", &client), ("server", &server)] {
        let names = || events.iter().map(|event| event.name.as_str());
        assert_eq!(names().next(), Some("quic:connection_started"), "{side}");
        for name in [
            "quic:version_information",
            "quic:alpn_information",
            "quic:parameters_set",
            "quic:packet_sent",
            "quic:packet_received",
            "quic:recovery_metrics_updated",
            "quic:connection_state_updated",
            "quic:key_updated",
            "quic:key_discarded",
            "quic:stream_state_updated",
            "quic:stream_data_moved",
            "quic:connection_closed",
        ] {
            assert!(names().any(|n| n == name), "{side} writes {name}");
        }
        let any = |name: &str, text: &str| {
            events
                .iter()
                .any(|event| event.name == name && event.has(text))
        };
        for initiator in ["local", "remote"] {
            assert!(
                any(
                    "quic:parameters_set",
                    &format!(r#""initiator":"{initiator}""#)
                ),
                "{side}'s {initiator} parameters"
            );
        }
        assert!(
            any("quic:alpn_information", r#""string_value":"h3""#),
            "{side}"
        );
        assert!(
            any(
                "quic:connection_state_updated",
                r#""new":"handshake_complete""#
            ),
            "{side}"
        );
        assert!(
            any("quic:packet_sent", r#""frame_type":"stream""#),
            "{side}"
        );
        assert!(
            any("quic:packet_received", r#""frame_type":"ack""#),
            "{side}"
        );
        for (from, to) in [("application", "transport"), ("transport", "network")] {
            assert!(
                any(
                    "quic:stream_data_moved",
                    &format!(r#""from":"{from}","to":"{to}""#)
                ) || any(
                    "quic:stream_data_moved",
                    &format!(r#""from":"{to}","to":"{from}""#)
                ),
                "{side} moves stream data between {from} and {to}"
            );
        }
    }
    assert!(
        client
            .iter()
            .chain(&server)
            .any(|event| event.name == "quic:packet_lost"),
        "a loss is declared"
    );
    let closed = |events: &[QlogEvent], text: &str| {
        events
            .iter()
            .any(|event| event.name == "quic:connection_closed" && event.has(text))
    };
    assert!(closed(
        &client,
        r#""initiator":"local","application_error":"unknown","error_code":7"#
    ));
    assert!(
        closed(
            &server,
            r#""initiator":"remote","application_error":"unknown","error_code":7"#
        ) || closed(&server, r#""trigger":"idle_timeout""#)
    );
}
