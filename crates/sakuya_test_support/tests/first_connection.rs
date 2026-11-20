//! Node 1 on UDP: a server endpoint and a client endpoint on sockets of the
//! loopback interface, composed as an application would, and measured.
//!
//! The client connects, the server accepts, the handshake completes, the
//! client opens a bidirectional stream and sends a request with its end,
//! the server reads it and answers on the same stream, the client reads
//! the answer and closes, and both endpoints shut down. Along the way the
//! test counts the heap allocations, the datagrams and the polls and wakes
//! of each task in each phase, and prints them; the numbers are read by
//! the first connection's line, not asserted.
//!
//! The server presents an Ed25519 certificate for example.com, issued by a
//! test root that the client's [`TestRootsVerifier`] trusts.

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
    hash::RandomState,
    net::UdpSocket,
    rc::Rc,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use bytes::Bytes;
use frunk_core::{Coprod, hlist};
use futures_util::StreamExt as _;
use nitori_crypto::NamedGroup;
use nitori_crypto_aws_lc::{AwsLcBackend, Ed25519SigningKey};
use nitori_io::{ReadChunkHostExt as _, calls::WriteAllHostExt as _};
use nitori_sync::MutexSynchronization;
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
    message::{HelloRandom, MessageLimits, new_session_ticket::TicketLifetime},
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
use sakuya_connection::shared::SharedConnectionDriver;
use sakuya_connection::v1::application_handles::connection::ConnectionHandle;
use sakuya_connection::v1::retry::ContinueOnRetry;
use sakuya_connection::v1::{self};
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
    incoming::Incoming,
    retry::{CapacityFraction, LoadStatelessRetryPolicy},
    role::{AcceptingServer, ConnectingClient, NoClient, NoServer},
};
use sakuya_packet_protection::backend::ring::RingBackend;
use sakuya_recovery::loss::LossThresholds;
use sakuya_test_support::{
    measure::{
        AllocationCounts, Counted, CountingAllocator, WakeCountReader, WakeCounts,
        allocation_counts,
    },
    pki,
    verify::{TestRootsVerifier, test_roots_verifier},
};
use sakuya_udp_tokio::{UdpBinding, UdpBindingConfig, UdpLink};
use sakuya_wire::{
    connection_id::{ConnectionId, ConnectionIdLength, StatelessResetToken},
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

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// How long any step may take.
const DEADLINE: Duration = Duration::from_secs(5);

// ==== the composition: what an application writes to get a connection ====

// ---- the endpoint's choices ----

/// The endpoints of the test: UDP on tokio.
struct Udp;

impl EndpointChoices for Udp {
    type Links = Coprod![UdpLink<TokioClock>];
    type Bindings = frunk_core::HList![UdpBinding<TokioClock>];
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
sakuya_connection::composition!(impl for Mine: ServerChoices, Parts);
sakuya_connection::composition!(impl for Mine: ClientChoices, Parts);

// ---- the handshakes ----

/// The family the TLS stores keep their shared state in.
type TlsSynchronization = MutexSynchronization;

type ServerEngine = ServerHandshake<
    AwsLcBackend,
    PreferenceTable,
    ZeroRttOnceTicketTable<
        &'static str,
        AwsLcBackend,
        SystemClock,
        TlsSynchronization,
        RandomState,
    >,
    PassThroughLayers,
    SniTargets<&'static str>,
    CertifiedKey<Ed25519SigningKey>,
    NoCertificateRequest,
    SystemClock,
    (),
>;

type ClientEngine = ClientHandshake<
    AwsLcBackend,
    PreferenceOffering<TlsSynchronization, RandomState>,
    Arc<TakeOnceTicketMap<SystemClock, TlsSynchronization, RandomState>>,
    TestRootsVerifier<AwsLcBackend, SystemClock, TlsSynchronization>,
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

/// Makes each client connection's engine, which logs to `labels` and
/// trusts the test root.
#[derive(Clone)]
struct ClientStarts {
    labels: Arc<RecordedLabels>,
    tickets: Arc<TakeOnceTicketMap<SystemClock, TlsSynchronization, RandomState>>,
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
        // each side lets the other open a few bidirectional streams and
        // send a little on them
        parameters.set(InitialMaxData::new(VarInt::from_u32(65_536)));
        parameters.set(InitialMaxStreamDataBidiLocal::new(VarInt::from_u32(16_384)));
        parameters.set(InitialMaxStreamDataBidiRemote::new(VarInt::from_u32(
            16_384,
        )));
        parameters.set(InitialMaxStreamsBidi::new(StreamCount::new(4).unwrap()));
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

fn server_config() -> ServerConfig<
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
        thresholds(),
        hlist![v1_config!(ClientChoices)],
        ClientTokens::new(),
        ContinueOnRetry,
    )
    .unwrap()
}

fn bind() -> UdpBinding<TokioClock> {
    UdpBinding::bind(
        UdpBindingConfig::new(SocketAddr::from(([127, 0, 0, 1], 0))),
        TokioClock,
    )
    .expect("a loopback socket binds")
}

// ==== the run and its measurements ====

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

/// What crossed a relay in one direction.
#[derive(Default)]
struct Crossed {
    datagrams: AtomicU64,
    bytes: AtomicU64,
}

impl Crossed {
    fn add(&self, len: usize) {
        self.datagrams.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(len as u64, Ordering::Relaxed);
    }

    fn get(&self) -> (u64, u64) {
        (
            self.datagrams.load(Ordering::Relaxed),
            self.bytes.load(Ordering::Relaxed),
        )
    }
}

/// A UDP relay between the client and the server, on threads of its own so
/// that its allocations stay out of the counts, counting what crosses it.
struct Relay {
    address: SocketAddr,
    to_server: Arc<Crossed>,
    to_client: Arc<Crossed>,
    stop: Arc<AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl Relay {
    /// A relay to the server at `server`.
    fn new(server: SocketAddr) -> Self {
        let loopback = SocketAddr::from(([127, 0, 0, 1], 0));
        let client_side = UdpSocket::bind(loopback).expect("a loopback socket binds");
        let server_side = UdpSocket::bind(loopback).expect("a loopback socket binds");
        server_side.connect(server).expect("the server's address");
        for socket in [&client_side, &server_side] {
            socket
                .set_read_timeout(Some(Duration::from_millis(20)))
                .expect("a read timeout");
        }
        let address = client_side.local_addr().expect("a local address");
        let (to_server, to_client) = (Arc::<Crossed>::default(), Arc::<Crossed>::default());
        let stop = Arc::new(AtomicBool::new(false));
        let client = Arc::new(Mutex::new(None::<SocketAddr>));
        let (client_side, server_side) = (Arc::new(client_side), Arc::new(server_side));
        let up = {
            let (from, to, crossed, stop, client) = (
                Arc::clone(&client_side),
                Arc::clone(&server_side),
                Arc::clone(&to_server),
                Arc::clone(&stop),
                Arc::clone(&client),
            );
            std::thread::spawn(move || {
                let mut buffer = [0; 65_536];
                while !stop.load(Ordering::Relaxed) {
                    if let Ok((len, peer)) = from.recv_from(&mut buffer) {
                        *client.lock().unwrap_or_else(PoisonError::into_inner) = Some(peer);
                        crossed.add(len);
                        let _ = to.send(&buffer[..len]);
                    }
                }
            })
        };
        let down = {
            let (from, to, crossed, stop) = (
                server_side,
                client_side,
                Arc::clone(&to_client),
                Arc::clone(&stop),
            );
            std::thread::spawn(move || {
                let mut buffer = [0; 65_536];
                while !stop.load(Ordering::Relaxed) {
                    if let Ok(len) = from.recv(&mut buffer) {
                        crossed.add(len);
                        let peer = *client.lock().unwrap_or_else(PoisonError::into_inner);
                        if let Some(peer) = peer {
                            let _ = to.send_to(&buffer[..len], peer);
                        }
                    }
                }
            })
        };
        Self {
            address,
            to_server,
            to_client,
            stop,
            threads: vec![up, down],
        }
    }

    /// Datagrams and bytes so far: to the server, then to the client.
    fn crossed(&self) -> CrossedCounts {
        [self.to_server.get(), self.to_client.get()]
    }

    fn stop(self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads {
            thread.join().expect("a relay thread ends");
        }
    }
}

/// The counted tasks of a run, by name.
#[derive(Default)]
struct Tasks(Vec<(&'static str, WakeCountReader)>);

impl Tasks {
    /// Spawns `future` on the local set, counted under `name`.
    fn spawn<F: Future + 'static>(
        &mut self,
        name: &'static str,
        future: F,
    ) -> tokio::task::JoinHandle<F::Output> {
        let (counted, reader) = Counted::new(future);
        self.0.push((name, reader));
        tokio::task::spawn_local(counted)
    }

    /// The counts of each task so far, in the order spawned.
    fn counts(&self) -> Vec<(&'static str, WakeCounts)> {
        self.0
            .iter()
            .map(|(name, reader)| (*name, reader.counts()))
            .collect()
    }
}

/// Datagrams and bytes that crossed the relay: to the server, then to the
/// client.
type CrossedCounts = [(u64, u64); 2];

/// The allocations of each phase of a run.
struct Phases {
    last: AllocationCounts,
    last_wakes: Vec<(&'static str, WakeCounts)>,
    wakes: Vec<(&'static str, Vec<(&'static str, WakeCounts)>)>,
    last_crossed: CrossedCounts,
    done: Vec<(&'static str, AllocationCounts, CrossedCounts)>,
}

impl Phases {
    fn start() -> Self {
        Self {
            last: allocation_counts(),
            last_wakes: Vec::new(),
            wakes: Vec::new(),
            last_crossed: [(0, 0); 2],
            done: Vec::new(),
        }
    }

    /// Ends the phase `name` now; `relay` tells what crossed it.
    fn end(&mut self, name: &'static str, relay: Option<&Relay>, tasks: &Tasks) {
        let now = allocation_counts();
        let wakes = tasks.counts();
        let phase = wakes
            .iter()
            .map(|&(task, counts)| {
                let earlier = self
                    .last_wakes
                    .iter()
                    .find(|(t, _)| *t == task)
                    .map_or(WakeCounts::default(), |&(_, c)| c);
                (task, counts.since(earlier))
            })
            .collect();
        self.wakes.push((name, phase));
        self.last_wakes = wakes;
        let crossed = relay.map_or(self.last_crossed, Relay::crossed);
        let [(a, b), (c, d)] = self.last_crossed;
        let [(e, f), (g, h)] = crossed;
        self.done
            .push((name, now.since(self.last), [(e - a, f - b), (g - c, h - d)]));
        self.last = now;
        self.last_crossed = crossed;
    }

    fn print(&self) {
        println!(
            "[first-connection] phase allocations reallocations deallocations bytes \
             to-server-datagrams to-server-bytes to-client-datagrams to-client-bytes"
        );
        for (name, c, [(a, b), (e, f)]) in &self.done {
            println!(
                "[first-connection] {name} {} {} {} {} {a} {b} {e} {f}",
                c.allocations, c.reallocations, c.deallocations, c.bytes
            );
        }
        println!("[first-connection] phase task polls wakes");
        for (name, tasks) in &self.wakes {
            for (task, counts) in tasks {
                println!(
                    "[first-connection] {name} {task} {} {}",
                    counts.polls, counts.wakes
                );
            }
        }
    }
}

/// What the client asks on its stream, and what the server answers.
const REQUEST: &[u8] = b"ping";
const ANSWER: &[u8] = b"pong";

/// How long the run waits for the handshake's tail before the round trip,
/// and for the round trip's acknowledgements after it: above the 25 ms
/// default of max_ack_delay.
const SETTLE: Duration = Duration::from_millis(60);

/// Node 1, measured.
#[test]
fn a_client_and_a_server_exchange_a_request_and_its_answer_on_the_loopback_interface() {
    run(async {
        let mut tasks = Tasks::default();
        let mut phases = Phases::start();

        let (server, server_reflow) =
            Endpoint::<Udp, Server, NoClient>::new(endpoint_config(server_config(), ())).unwrap();
        let server_reflow = tasks.spawn("server-reflow", server_reflow);
        let server_socket = bind();
        let server_address = server_socket.local_address();
        let (_server_handle, server_driver) = server
            .add_accepting_binding(server_socket, BindingDeclarations::default())
            .unwrap();
        let server_driver = tasks.spawn("server-binding", server_driver);
        let mut incoming = server.incoming();

        let labels = Arc::new(RecordedLabels::default());
        let (client, client_reflow) =
            Endpoint::<Udp, NoServer, Client>::new(endpoint_config((), client_config(&labels)))
                .unwrap();
        let client_reflow = tasks.spawn("client-reflow", client_reflow);
        let (client_handle, client_driver) = client
            .add_connect_only_binding(bind(), BindingDeclarations::default())
            .unwrap();
        let client_driver = tasks.spawn("client-binding", client_driver);
        phases.end("endpoints", None, &tasks);
        let relay = Relay::new(server_address);

        let outgoing = within(
            "the client takes a link",
            client_handle.connect(
                relay.address,
                ServerTarget::from_host_name("example.com").unwrap(),
            ),
        )
        .await
        .unwrap();
        let client_connection = Rc::new(RefCell::new(outgoing.start().unwrap()));
        let client_conn = ConnectionHandle::new(client_connection.clone());
        let client_connection = tasks.spawn(
            "client-connection",
            SharedConnectionDriver::new(client_connection),
        );

        let Some(Incoming::Terminable(half)) =
            within("an incoming connection", incoming.next()).await
        else {
            panic!("the server endpoint ends before a connection comes");
        };
        let server_connection = Rc::new(RefCell::new(half.accept().unwrap()));
        let server_conn = ConnectionHandle::new(server_connection.clone());
        let server_connection = tasks.spawn(
            "server-connection",
            SharedConnectionDriver::new(server_connection),
        );

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
        let client_layer = client_conn
            .established()
            .await
            .expect("the client's handshake completed");
        let server_layer = server_conn
            .established()
            .await
            .expect("the server's handshake completed");
        assert!(labels.has(KeyLogLabel::ClientTrafficSecret0));
        phases.end("connect-and-handshake", Some(&relay), &tasks);

        // The server's application waits for the stream on a task of its
        // own. It is spawned before the round trip, which starts once the
        // handshake's last datagrams and their acknowledgements have gone
        // across, so that they stay out of its counts.
        let server_application = tasks.spawn("server-application", async move {
            let (mut writer, mut reader) = server_layer
                .accept_bi()
                .await
                .expect("the client's stream is accepted");
            let mut request = Vec::new();
            while let Some(chunk) = reader
                .read_chunk_unpin(NonZeroUsize::new(64).unwrap())
                .await
                .expect("the request is read")
            {
                request.extend_from_slice(&chunk);
            }
            writer
                .write_all_unpin(Bytes::from_static(ANSWER))
                .await
                .expect("the answer is written");
            writer.close().expect("the answer ends");
            request
        });
        tokio::time::sleep(SETTLE).await;
        phases.end("settle", Some(&relay), &tasks);

        let (mut writer, mut reader) = client_layer
            .try_open_bi()
            .expect("the server grants streams");
        writer
            .write_all_unpin(Bytes::from_static(REQUEST))
            .await
            .expect("the request is written");
        writer.close().expect("the request ends");
        let mut answer = Vec::new();
        within("the answer arrives", async {
            while let Some(chunk) = reader
                .read_chunk_unpin(NonZeroUsize::new(64).unwrap())
                .await
                .expect("the answer is read")
            {
                answer.extend_from_slice(&chunk);
            }
        })
        .await;
        phases.end("round-trip", Some(&relay), &tasks);
        tokio::time::sleep(SETTLE).await;
        phases.end("settle-after", Some(&relay), &tasks);
        let request = within("the server's application ends", server_application)
            .await
            .unwrap();
        assert_eq!(request, REQUEST);
        assert_eq!(answer, ANSWER);

        client_conn.close(AppClose(7));
        within("the client's connection ends", client_connection)
            .await
            .unwrap();
        within("the server's connection ends", server_connection)
            .await
            .unwrap();
        phases.end("close", Some(&relay), &tasks);

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
        phases.end("shutdown", Some(&relay), &tasks);
        relay.stop();

        phases.print();
    });
}
