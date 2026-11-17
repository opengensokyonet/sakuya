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
//! The rebind scenario asserts what sakuya does today, without connection
//! migration: see [`a_client_rebound_after_the_handshake_is_not_followed`].
//!
//! The connections' events are received by [`QlogWriter`]; the scenarios
//! that read them give a directory under Cargo's directory for the tests'
//! temporary files, the others none, which records nothing.

use core::{
    fmt,
    future::Future,
    net::SocketAddr,
    num::{NonZeroU32, NonZeroUsize},
    time::Duration,
};
use std::{
    path::{Path, PathBuf},
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
use sakuya_clock_tokio::TokioClock;
use sakuya_connection::prelude::*;
use sakuya_connection::v1::application_handles::connection::ConnectionHandle;
use sakuya_connection::v1::retry::ContinueOnRetry;
use sakuya_connection::v1::{self, close::LocalCloseCause};
use sakuya_datagram_routing::route::recognizer::{ConnectionIdGenerator, ConnectionIdLengths};
use sakuya_endpoint::role::{ClientConnectionChoices, ServerConnectionChoices};
use sakuya_endpoint::{
    address_token::{AddressTokenKey, AddressTokenLifetimes, AeadAddressTokens},
    choices::EndpointChoices,
    client_token::BoundedAddressTokenStore,
    config::{
        BindingDeclarations, ClientConfig, ClientCryptoReceiveCapacities, EndpointConfig,
        ServerConfig, ServerCryptoReceiveCapacities,
    },
    endpoint::Endpoint,
    handshake::{ClientHandshakeConfig, ServerHandshakeConfig},
    incoming::{Incoming, IncomingStream},
    retry::{CapacityFraction, LoadStatelessRetryPolicy},
    role::{AcceptingServer, ConnectingClient, NoClient, NoServer},
};
use sakuya_packet_protection::backend::ring::RingBackend;
use sakuya_qlog::{QUIC_EVENT_SCHEMA, QlogConfig, QlogWriter};
use sakuya_recovery::loss::LossThresholds;
use sakuya_stream::connection::{CloseReason, ImmediateClose};
use sakuya_test_support::{
    network::{
        Blackhole, DatagramFate, Direction, DirectionImpairments, Impairments, MemoryLink,
        MemoryNetwork, Probability, RandomLoss, Reorder,
    },
    pki,
    verify::{TestRootsVerifier, test_roots_verifier},
};
use sakuya_tls::{
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
use sakuya_wire::{
    connection_id::{ConnectionId, ConnectionIdLength, StatelessResetToken},
    v1::transport_error::TransportErrorCode,
    v1::{
        stream_count::StreamCount,
        transport_parameters::{
            TransportParameters,
            integer::{
                InitialMaxData, InitialMaxStreamDataBidiLocal, InitialMaxStreamDataBidiRemote,
                InitialMaxStreamsBidi, MaxIdleTimeout,
            },
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

type ServerChoices = ServerConnectionChoices<InMemory, Mine, ServerStarts>;
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
type ClientTokens = BoundedAddressTokenStore<ServerTarget>;
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
/// `$qlog` when it is a directory.
macro_rules! v1_config {
    ($t:ty, $qlog:expr) => {{
        let mut parameters = TransportParameters::<Vec<u8>>::new();
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
        hlist![v1_config!(ServerChoices, qlog)],
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
}

/// Two endpoints on a network in memory, with a connection between them
/// whose handshake has completed on both sides.
struct Pair {
    network: MemoryNetwork<TokioClock>,
    server: Endpoint<InMemory, Server, NoClient>,
    client: Endpoint<InMemory, NoServer, Client>,
    incoming: IncomingStream<InMemory, Server>,
    server_conn: ConnectionHandle<ServerChoices, Parts>,
    client_conn: ConnectionHandle<ClientChoices, Parts>,
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
        let network = MemoryNetwork::new(TokioClock, seed, server_address(), impairments);
        let mut drivers = Vec::new();

        let (server, server_reflow) = Endpoint::<InMemory, Server, NoClient>::new(endpoint_config(
            server_config(qlog.map(Path::to_path_buf)),
            (),
        ))
        .unwrap();
        drivers.push(("the server's reflow driver", spawn_local(server_reflow)));
        let (_server_handle, server_driver) = server
            .add_accepting_binding(
                network.bind(server_address()),
                BindingDeclarations::default(),
            )
            .unwrap();
        drivers.push(("the server's binding driver", spawn_local(server_driver)));
        let mut incoming = server.incoming();

        let (client, client_reflow) = Endpoint::<InMemory, NoServer, Client>::new(endpoint_config(
            (),
            client_config(qlog.map(Path::to_path_buf)),
        ))
        .unwrap();
        drivers.push(("the client's reflow driver", spawn_local(client_reflow)));
        let (client_handle, client_driver) = client
            .add_connect_only_binding(
                network.bind(client_address()),
                BindingDeclarations::default(),
            )
            .unwrap();
        drivers.push(("the client's binding driver", spawn_local(client_driver)));

        let outgoing = within(
            "the client takes a link",
            client_handle.connect(
                server_address(),
                ServerTarget::from_host_name("example.com").unwrap(),
            ),
        )
        .await
        .unwrap();
        let (client_connection, client_conn) = outgoing.start().unwrap();
        let client_connection = spawn_local(client_connection);

        let Some(Incoming::Terminable(half)) =
            within("an incoming connection", incoming.next()).await
        else {
            panic!("the server endpoint ends before a connection comes");
        };
        let (server_connection, server_conn) = half.accept().unwrap();
        let server_connection = spawn_local(server_connection);

        within("the client's handshake", client_conn.handshake_completed())
            .await
            .expect("the client's handshake completes");
        within("the server's handshake", server_conn.handshake_completed())
            .await
            .expect("the server's handshake completes");
        Self {
            network,
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
            writer
                .write_all_unpin(Bytes::from(answer()))
                .await
                .expect("the answer is written");
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
        let (to_server, to_client) = pair.finish().await;
        Outcome {
            to_server,
            to_client,
            changed_at,
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
    let outcome = twice(42, &impairments, || Change::None);
    assert!(dropped(&outcome.to_server) > 0 && dropped(&outcome.to_client) > 0);
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
    let outcome = twice(11, &impairments, || Change::None);
    let all = || outcome.to_server.iter().chain(&outcome.to_client);
    assert!(all().any(|fate| fate.corrupted.is_some()));
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

/// sakuya does not probe for datagram sizes above 1200 bytes yet (the
/// policy's probe size is not read by the connection), so no datagram is
/// larger than 1200 bytes and a limit above it changes nothing today; the
/// assertion holds once probing is wired.
#[test]
fn after_the_links_report_a_lower_limit_no_larger_datagram_is_sent() {
    const LIMIT: usize = 1280;
    let outcome = twice(5, &Impairments::both(plain()), || Change::LinkLimit(LIMIT));
    let (to_server, to_client) = outcome.changed_at.expect("the network changed");
    // what was already being sent when the limit changed may be larger: a
    // few datagrams of slack
    const SLACK: u64 = 8;
    for (fates, from) in [
        (&outcome.to_server, to_server),
        (&outcome.to_client, to_client),
    ] {
        for fate in after(fates, from + SLACK) {
            assert!(
                fate.len <= LIMIT,
                "datagram {} of {} bytes after the limit fell to {LIMIT}",
                fate.number,
                fate.len
            );
        }
    }
}

/// As above, nothing is larger than 1200 bytes today, so a path MTU that
/// falls to 1250 bytes drops nothing; once probing is wired this exercises
/// the policy's black hole detection.
#[test]
fn the_answer_arrives_when_the_path_mtu_falls_without_a_word() {
    let outcome = twice(9, &Impairments::both(plain()), || Change::PathMtu(1250));
    let _ = outcome;
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

/// Without connection migration (not implemented yet), a client whose
/// datagrams come from a new address after the handshake is not followed:
/// the server's binding takes a new link for that address, and the server's
/// connection drops what arrives on a link it has no link path for; the
/// server's datagrams go to the old address, which is gone. Neither side
/// closes for a protocol error: both end at their idle timeout.
///
/// Once connection migration is implemented, this test asserts that the
/// answer arrives over the new address instead.
#[test]
fn a_client_rebound_after_the_handshake_is_not_followed() {
    let rebound = SocketAddr::from(([10, 0, 0, 2], 50_001));
    let run = || {
        // the client's first connection ID is random: each run its own file
        let qlog = qlog_dir("rebind");
        run_paused(async move {
            let pair = Pair::connect(13, Impairments::both(plain()), Some(&qlog)).await;
            let client_layer = pair.client_conn.established().await.expect("established");
            // the handshake's last acknowledgements cross before the rebind
            tokio::time::sleep(Duration::from_millis(200)).await;
            let before = pair.counts();

            pair.network.rebind(client_address(), rebound);
            let (mut writer, _reader) = client_layer
                .try_open_bi()
                .expect("the server grants streams");
            writer
                .write_all_unpin(Bytes::from_static(REQUEST))
                .await
                .expect("the request is written");
            writer.close().expect("the request ends");

            let client_closed = within("the client's close", pair.client_conn.closed()).await;
            let server_closed = within("the server's close", pair.server_conn.closed()).await;
            assert!(
                matches!(client_closed, CloseReason::IdleTimeout),
                "the client ends at its idle timeout, not {client_closed:?}"
            );
            assert!(
                matches!(server_closed, CloseReason::IdleTimeout),
                "the server ends at its idle timeout, not {server_closed:?}"
            );
            let (to_server, to_client) = pair.finish().await;
            // after the rebind the client's datagrams still reach the server
            // (from the new address), and the server's go to the old one
            let up = after(&to_server, before.0);
            let down = after(&to_client, before.1);
            assert!(!up.is_empty() && up.iter().all(|fate| fate.dropped.is_none()));
            assert!(
                down.iter().all(|fate| fate.dropped.is_some()),
                "nothing reaches the client's old address"
            );
            // the server's connection drops them for want of a link path
            let server = qlog_events(&qlog, "server");
            assert!(
                server
                    .iter()
                    .any(|event| event.name == "quic:packet_dropped"
                        && event.has(r#""details":{"reason":"no_link_path"},"trigger":"general""#)),
                "the server drops the packets of the new link: {server:?}"
            );
            (to_server, to_client)
        })
    };
    let (to_server, to_client) = run();
    assert_eq!(
        (to_server.clone(), to_client.clone()),
        run(),
        "the same seed meets the same fates"
    );
    summarize(13, &to_server, &to_client);
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
