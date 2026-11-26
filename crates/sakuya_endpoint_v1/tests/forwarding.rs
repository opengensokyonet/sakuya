//! The proof of concept of passthrough forwarding: one endpoint on one UDP
//! socket is the server of some connections and, without being their
//! server, forwards the datagrams of others to another server.
//!
//! The Relay endpoint reads each first ClientHello before it answers
//! anything. For the name it serves, a.example, it accepts the connection.
//! For b.example it hands the connection off: it opens a UDP socket of its
//! own to the backend for the connection, builds the first flight it read
//! again from the layout, and from then on forwards the datagrams as they
//! are, the client's to the backend from that socket and the backend's to
//! the client from the Relay's socket. The client's handshake is with the
//! backend, which presents a certificate for b.example only.
//!
//! The client sends to the backend's connection IDs once it knows them, and
//! those come to the Relay's socket too. The backend gives the Relay each
//! connection ID before it may issue it: before accepting a connection it
//! offers the Relay a batch over a TCP connection, the Relay registers them
//! for the connection that arrived from the socket the offer names and
//! acknowledges, and only then does the backend accept, with a generator
//! that issues from that batch alone.
//!
//! It is an experiment: the designed passthrough forwarding goes with the
//! Relay layer of nested ECH, and rewrites the client's Initial CRYPTO into
//! the middle ClientHello. Here there is no ECH, so the middle ClientHello
//! is the one the client sent and the first flight is built with the same
//! CRYPTO data; later datagrams are forwarded as they are.

#![cfg(target_os = "linux")]
#![feature(type_alias_impl_trait)]

use core::{
    fmt,
    future::{Future, poll_fn},
    net::{Ipv4Addr, SocketAddr},
    num::{NonZeroU32, NonZeroUsize},
    pin::pin,
    task::Poll,
    time::Duration,
};
use std::{
    cell::{Cell, RefCell},
    collections::{HashMap, VecDeque},
    hash::RandomState,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};

use bytes::Bytes;
use frunk_core::{Coprod, coproduct::Coproduct, hlist};
use futures_util::{Stream as _, StreamExt as _};
use kasen_handshake::{
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
    verify::{
        AnchorStore, NoRevocationCheck, SpkiDistrustList, WebPkiVerifier,
        transparency::{EmbeddedSctPolicy, LogList, StaleLogListAction},
    },
};
use nitori_crypto::{NamedGroup, SignatureScheme, SigningKey as _};
use nitori_crypto_aws_lc::{AwsLcBackend, Ed25519SigningKey};
use nitori_io::{ReadChunkHostExt as _, calls::WriteAllHostExt as _};
use nitori_sync::MutexSynchronization;
use sakuya_clock_tokio::TokioClock;
use sakuya_connection::prelude::*;
use sakuya_connection::v1::{
    self,
    application_handles::connection::ConnectionHandle,
    first_flight::{InitialPacketLayout, PacketLayout},
    retry::ContinueOnRetry,
};
use sakuya_connection::{
    driver::LendNode,
    shared::{DrivenFromOutside, SharedConnectionDriver},
};
use sakuya_datagram_routing_v1::route::recognizer::{ConnectionIdGenerator, ConnectionIdLengths};
use sakuya_endpoint_v1::{
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
    passthrough::PassthroughHandoff,
    retry::{CapacityFraction, LoadStatelessRetryPolicy},
    role::ServerConnectionChoices,
    role::{AcceptingServer, ClientConnectionChoices, ConnectingClient, NoClient, NoServer},
};
use sakuya_link::{EcnMarking, Link as _, OutgoingDatagram};
use sakuya_packet_protection_ring::RingBackend;
use sakuya_packet_protection_v1::{
    backend::AEAD_TAG_LEN,
    header_protection::HeaderProtectionKey,
    initial::{INITIAL_AEAD, InitialSecrets},
    packet_key::PacketKey,
    packet_number::TruncatedPacketNumber,
};
use sakuya_recovery_v1::loss::LossThresholds;
use sakuya_udp_tokio::{UdpBinding, UdpBindingConfig, UdpLink};
use sakuya_var_int::{VarInt, VarIntField, VarIntWidth};
use sakuya_wire_v1::connection_id::{
    ConnectionId, ConnectionIdLength, NonEmptyCid, StatelessResetToken,
};
use sakuya_wire_v1::{
    frame::{
        crypto::{CryptoFrame, codec::write_crypto_frame},
        padding::{PaddingRun, codec::write_padding_run},
        ping::{PingFrame, codec::write_ping_frame},
    },
    header::{LongPacketHeader, codec::write_long_packet_header},
};
use time::UtcDateTime;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, ReadBuf},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{mpsc, oneshot},
};

/// How long any step may take.
const DEADLINE: Duration = Duration::from_secs(5);

/// How long the Relay keeps forwarding a connection after the last
/// datagram in either direction.
const IDLE: Duration = Duration::from_secs(1);

/// How many connection IDs the backend gives the Relay for each
/// connection: its first, and those it may issue later.
const BATCH: usize = 8;

// ---- the endpoints' choices ----

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
    type ConnectionIds = Ids;
    type Recognizer = ConnectionIdLengths;
    type Synchronization =
        sakuya_endpoint_v1::synchronization::RefCellEndpointSynchronization<std::hash::RandomState>;
}

/// Connection IDs of eight bytes, with tokens from the same bytes: from a
/// counter the endpoint shares, or, for a connection given them, from a
/// list prepared beforehand.
#[derive(Clone)]
enum Ids {
    /// From the counter.
    Counting(Arc<AtomicU64>),
    /// From the list; how many it gave is counted in the cell.
    Prepared(VecDeque<ConnectionId>, Arc<AtomicUsize>),
}

impl ConnectionIdGenerator for Ids {
    type Config = Self;

    fn new(config: &Self) -> Self {
        config.clone()
    }

    fn generate(&mut self) -> (ConnectionId, StatelessResetToken) {
        let cid = match self {
            Self::Counting(next) => counted(next.fetch_add(1, Ordering::Relaxed)),
            Self::Prepared(list, given) => {
                given.fetch_add(1, Ordering::Relaxed);
                list.pop_front()
                    .expect("the backend gave the Relay enough connection IDs")
            }
        };
        let mut token = [0; 16];
        token[..8].copy_from_slice(cid.as_bytes());
        (cid, StatelessResetToken::new(token))
    }

    fn stateless_reset_token(_: &Self, _: &ConnectionId) -> Option<StatelessResetToken> {
        None
    }
}

/// The connection ID of the count `n`.
fn counted(n: u64) -> ConnectionId {
    ConnectionId::new(&n.to_be_bytes()).expect("eight bytes")
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
    fn code(&self) -> sakuya_wire_v1::application_error::ApplicationErrorCode {
        sakuya_wire_v1::application_error::ApplicationErrorCode::new(VarInt::from_u32(self.0))
    }
}

/// What the tests choose of version 1: their application error, and the
/// default of everything else.
struct Mine;

impl<T: v1::state_choices::StateMakerChoices> v1::common_choices::CommonHostChoices<T> for Mine {
    type ApplicationError = AppClose;
}
impl<T: v1::state_choices::StateMakerChoices> v1::state_choices::StateHostChoices<T> for Mine {}

type ServerChoices =
    ServerConnectionChoices<Udp, Mine, ServerStarts, AeadNewTokenIssuer<AwsLcBackend>>;
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
type ClientTokens =
    BoundedAddressTokenStore<ServerTarget, sakuya_endpoint_v1::choices::SynchronizationOf<Udp>>;
type Client = ConnectingClient<Mine, Parts, ClientStarts, ClientTokens, ContinueOnRetry>;

/// A server's connection of the tests.
type ServerConnection = impl DrivenFromOutside + LendNode<ServerChoices, Parts> + 'static;
/// A client's connection of the tests.
type ClientConnection = impl DrivenFromOutside + LendNode<ClientChoices, Parts> + 'static;

/// The connection `half` accepts.
#[define_opaque(ServerConnection)]
fn accepted(half: TerminableIncoming<Udp, Server>) -> ServerConnection {
    half.accept().unwrap()
}

/// The connection `outgoing` starts.
#[define_opaque(ClientConnection)]
fn started(outgoing: Outgoing<Udp, Client>) -> ClientConnection {
    outgoing.start().unwrap()
}

/// Spawn `connection` in a wrapper of one thread and give its handle.
fn spawned<T, L, D: DrivenFromOutside + 'static>(
    connection: D,
) -> ConnectionHandle<T, L, Rc<RefCell<D>>> {
    let shared = Rc::new(RefCell::new(connection));
    tokio::task::spawn_local(SharedConnectionDriver::new(shared.clone()));
    ConnectionHandle::new(shared)
}

type ServerHandle = ConnectionHandle<ServerChoices, Parts, Rc<RefCell<ServerConnection>>>;
type ClientHandle = ConnectionHandle<ClientChoices, Parts, Rc<RefCell<ClientConnection>>>;

// ---- the handshakes ----

/// The family the TLS stores keep their shared state in.
type TlsSynchronization = MutexSynchronization;

type Verifier = WebPkiVerifier<
    AwsLcBackend,
    AnchorStore<TlsSynchronization>,
    SpkiDistrustList<TlsSynchronization>,
    NoRevocationCheck,
    EmbeddedSctPolicy<TlsSynchronization>,
    SystemClock,
>;

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
    Verifier,
    NoClientCertificate,
    SystemClock,
    (),
>;

fn h3() -> ProtocolName<Bytes> {
    ProtocolName::new(Bytes::from_static(b"h3")).unwrap()
}

/// Makes each server connection's engine for `name`, with a certificate
/// of `key(seed)` for that name alone.
#[derive(Clone)]
struct ServerStarts {
    name: &'static str,
    seed: u8,
}

impl ServerHandshakeConfig for ServerStarts {
    type Start = ServerEngine;

    fn start(&self) -> ServerEngine {
        let mut targets = SniTargets::new();
        targets.insert(self.name, "web", vec![h3()]);
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
                vec![Bytes::from(pki::leaf(self.name, self.seed))],
                pki::key(self.seed),
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

/// Makes each client connection's engine, which trusts `root(1)`.
#[derive(Clone)]
struct ClientStarts {
    tickets: Arc<TakeOnceTicketMap<SystemClock, TlsSynchronization, RandomState>>,
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

// ---- the configurations ----

/// The default configuration of version 1, whose transport parameters let
/// the peer open streams.
macro_rules! v1_config {
    ($t:ty) => {
        sakuya_endpoint_v1::v1::ConnectionConfig::<$t, Parts>::default()
    };
}

fn thresholds() -> LossThresholds {
    LossThresholds::recommended(Duration::from_millis(1)).unwrap()
}

/// An endpoint's configuration, its connection IDs counted from `first`.
fn endpoint_config<S, C>(
    server: S::Config,
    client: C::Config,
    first: u64,
) -> EndpointConfig<Udp, S, C>
where
    S: sakuya_endpoint_v1::role::ServerRole<Udp>,
    C: sakuya_endpoint_v1::role::ClientRole<Udp>,
{
    EndpointConfig {
        server,
        client,
        clock: TokioClock,
        crypto: RingBackend,
        random: AwsLcBackend,
        wall_clock: SystemClock,
        connection_ids: Ids::Counting(Arc::new(AtomicU64::new(first))),
        recognizer: ConnectionIdLengths::new([ConnectionIdLength::new(8).unwrap()]),
    }
}

fn server_config(
    starts: ServerStarts,
) -> ServerConfig<
    ServerChoices,
    Parts,
    ServerStarts,
    AeadAddressTokens<AwsLcBackend>,
    LoadStatelessRetryPolicy,
> {
    ServerConfig::new(
        starts,
        ServerCryptoReceiveCapacities {
            initial: 16 * 1024 + 4,
            handshake: 4096,
        },
        thresholds(),
        hlist![v1_config!(ServerChoices)],
        AeadAddressTokens::new(
            AwsLcBackend,
            AddressTokenKey::generate(&AwsLcBackend).unwrap(),
            AddressTokenLifetimes::default(),
            Default::default(),
        )
        .unwrap(),
        LoadStatelessRetryPolicy::new(
            CapacityFraction::new(1, NonZeroU32::new(2).unwrap()).unwrap(),
        ),
    )
    .unwrap()
}

fn client_config() -> ClientConfig<ClientChoices, Parts, ClientStarts, ClientTokens, ContinueOnRetry>
{
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

/// Waits until `done` holds.
async fn until(what: &str, done: impl Fn() -> bool) {
    within(what, async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
}

fn bind() -> UdpBinding<TokioClock> {
    UdpBinding::bind(
        UdpBindingConfig::new(SocketAddr::from(([127, 0, 0, 1], 0))),
        TokioClock,
    )
    .expect("a loopback socket binds")
}

// ---- the Relay ----

/// What the Relay's tasks share, and what the test reads of them.
#[derive(Default)]
struct RelayState {
    /// How many incoming connections the Relay endpoint gave.
    incomings: Cell<usize>,
    /// The connections the Relay accepted.
    accepted: RefCell<Vec<ServerHandle>>,
    /// The connections being forwarded, by the Relay's socket to the
    /// backend for each: where the offers of the backend's connection IDs
    /// for it go.
    forwarding: RefCell<HashMap<SocketAddr, mpsc::UnboundedSender<Offer>>>,
    /// The client's first destination connection ID of each connection
    /// handed off.
    handed_off: RefCell<Vec<ConnectionId>>,
    /// The datagrams the Relay forwarded from clients to the backend.
    forwarded: RefCell<Vec<Bytes>>,
}

/// Connection IDs the backend offers for one connection, to be registered
/// before `registered` is told.
struct Offer {
    ids: Vec<NonEmptyCid>,
    registered: oneshot::Sender<()>,
}

/// The Relay's application: it reads each first ClientHello, accepts the
/// connections for a.example, hands those for b.example off and forwards
/// them to `backend`, and answers nothing else.
async fn relay(
    mut incoming: IncomingStream<Udp, Server>,
    backend: SocketAddr,
    state: Rc<RelayState>,
) {
    while let Some(item) = incoming.next().await {
        let Incoming::Terminable(half) = item;
        state.incomings.set(state.incomings.get() + 1);
        let state = Rc::clone(&state);
        tokio::task::spawn_local(async move {
            let Ok((hello, half)) = half.read_client_hello().await else {
                return;
            };
            let name = hello
                .client_hello()
                .server_name()
                .map(|name| name.host_name().clone());
            match name.as_deref() {
                Some(b"a.example") => {
                    state.accepted.borrow_mut().push(spawned(accepted(half)));
                }
                Some(b"b.example") => {
                    let handoff = half.into_passthrough_handoff().unwrap();
                    forward(handoff, backend, state).await;
                }
                _ => {}
            }
        });
    }
}

/// What the forwarding of one connection waits for next.
enum Event {
    Offer(Offer),
    FromClient(Bytes),
    FromBackend(usize),
    Idle,
}

/// Forwards the connection `handoff` gives to `backend` from a socket of
/// its own, until it is idle for [`IDLE`].
async fn forward(handoff: PassthroughHandoff<Udp>, backend: SocketAddr, state: Rc<RelayState>) {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    socket.connect(backend).await.unwrap();
    let own = socket.local_addr().unwrap();
    let (offers_sender, mut offers) = mpsc::unbounded_channel();
    state.forwarding.borrow_mut().insert(own, offers_sender);
    state.handed_off.borrow_mut().push(handoff.client_dcid);
    for datagram in rebuild_first_flight(&handoff) {
        socket.send(&datagram).await.unwrap();
    }
    let PassthroughHandoff { link, receiver, .. } = handoff;
    let registrar = receiver.registrar();
    // a receive in progress goes on across the other events: dropping it
    // could leave a datagram it was judging to the other candidates
    let mut from_client = pin!(futures_util::stream::unfold(
        receiver,
        |mut receiver| async {
            let datagram = receiver.recv().await;
            Some((datagram, receiver))
        }
    ));
    let mut buffer = vec![0; 65_536];
    let mut idle = pin!(tokio::time::sleep(IDLE));
    loop {
        let event = poll_fn(|cx| {
            if let Poll::Ready(Some(offer)) = offers.poll_recv(cx) {
                return Poll::Ready(Event::Offer(offer));
            }
            if let Poll::Ready(Some(datagram)) = from_client.as_mut().poll_next(cx) {
                return Poll::Ready(Event::FromClient(Bytes::copy_from_slice(
                    datagram.payload(),
                )));
            }
            let mut read = ReadBuf::new(&mut buffer);
            if let Poll::Ready(result) = socket.poll_recv(cx, &mut read) {
                result.unwrap();
                return Poll::Ready(Event::FromBackend(read.filled().len()));
            }
            if idle.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Event::Idle);
            }
            Poll::Pending
        })
        .await;
        match event {
            Event::Offer(offer) => {
                for id in offer.ids {
                    registrar.register(id);
                }
                let _ = offer.registered.send(());
            }
            Event::FromClient(datagram) => {
                state.forwarded.borrow_mut().push(datagram.clone());
                socket.send(&datagram).await.unwrap();
            }
            Event::FromBackend(len) => {
                let batch = [OutgoingDatagram {
                    payload: Bytes::copy_from_slice(&buffer[..len]),
                    ecn: EcnMarking::NotEct,
                }];
                link.send(&batch).await.unwrap();
            }
            Event::Idle => break,
        }
        idle.as_mut().reset(tokio::time::Instant::now() + IDLE);
    }
    state.forwarding.borrow_mut().remove(&own);
    // dropping the receiver revokes the registrations under the client's
    // first destination connection ID and the backend's connection IDs
}

/// The Relay's end of the channel with the backend: each offer names the
/// Relay's socket a connection arrived at the backend from and the
/// connection IDs for it; the Relay registers them and answers 1, or 0 for
/// a socket it does not forward from.
async fn control(listener: TcpListener, state: Rc<RelayState>) {
    let (mut stream, _) = listener.accept().await.unwrap();
    loop {
        // the IPv4 address and the port of the socket, and the count of
        // eight-byte connection IDs that follow
        let mut head = [0; 7];
        if stream.read_exact(&mut head).await.is_err() {
            return;
        }
        let socket = SocketAddr::from((
            Ipv4Addr::new(head[0], head[1], head[2], head[3]),
            u16::from_be_bytes([head[4], head[5]]),
        ));
        let mut ids = vec![0; 8 * usize::from(head[6])];
        stream.read_exact(&mut ids).await.unwrap();
        let ids = ids
            .chunks(8)
            .map(|id| NonEmptyCid::new(ConnectionId::new(id).unwrap()).unwrap())
            .collect();
        let entry = state.forwarding.borrow().get(&socket).cloned();
        let answer = match entry {
            Some(entry) => {
                let (registered, done) = oneshot::channel();
                let _ = entry.send(Offer { ids, registered });
                u8::from(done.await.is_ok())
            }
            None => 0,
        };
        stream.write_all(&[answer]).await.unwrap();
    }
}

/// The datagrams of the first flight `handoff` read, built again from its
/// layout: each Initial packet with its packet number, length and CRYPTO
/// data, each 0-RTT packet as it arrived.
fn rebuild_first_flight(handoff: &PassthroughHandoff<Udp>) -> Vec<Vec<u8>> {
    let secrets = InitialSecrets::derive(&RingBackend, &handoff.client_dcid);
    let keys = (
        PacketKey::derive(&RingBackend, INITIAL_AEAD, &secrets.client),
        HeaderProtectionKey::derive(&RingBackend, INITIAL_AEAD, &secrets.client),
    );
    let crypto = handoff.client_hello.encoded().encoded();
    let token = handoff.layout.token().cloned().unwrap_or_default();
    handoff
        .layout
        .datagrams()
        .iter()
        .map(|datagram| {
            let mut bytes = Vec::with_capacity(datagram.size());
            for packet in datagram.packets() {
                match packet {
                    PacketLayout::Initial(initial) => {
                        bytes.extend(rebuild_initial(handoff, &token, crypto, initial, &keys))
                    }
                    PacketLayout::ZeroRtt(index) => {
                        bytes.extend_from_slice(&handoff.zero_rtt[*index])
                    }
                }
            }
            bytes
        })
        .filter(|datagram| !datagram.is_empty())
        .collect()
}

/// The Initial packet `initial` describes, protected with the client's
/// Initial `keys`: its CRYPTO frames carry the ranges of `crypto` it
/// carried, with a PING if it had one, padded to its length.
fn rebuild_initial(
    handoff: &PassthroughHandoff<Udp>,
    token: &Bytes,
    crypto: &Bytes,
    initial: &InitialPacketLayout,
    (packet_key, header_key): &(PacketKey<RingBackend>, HeaderProtectionKey<RingBackend>),
) -> Vec<u8> {
    let pn_length = initial.packet_number_length();
    let bits = 8 * pn_length.get();
    let truncated = TruncatedPacketNumber::new(
        (initial.packet_number().get() & ((1 << bits) - 1)) as u32,
        pn_length,
    )
    .unwrap();
    let header = |length| {
        LongPacketHeader::initial(
            handoff.client_dcid,
            handoff.client_scid,
            VarIntWidth::shortest(VarInt::try_from(token.len()).unwrap()),
            token.clone(),
            pn_length,
            length,
        )
        .unwrap()
    };
    // a two-byte Length field, whose value makes the packet as long as it
    // was
    let length_offset =
        header(VarIntField::new(VarInt::ZERO, VarIntWidth::Two).unwrap()).length_offset();
    let length = initial.length() - length_offset - 2;
    let header =
        header(VarIntField::new(VarInt::try_from(length).unwrap(), VarIntWidth::Two).unwrap());
    let pn_offset = header.packet_number_offset();
    let mut packet = Vec::with_capacity(initial.length());
    write_long_packet_header(&mut packet, header);
    packet.extend_from_slice(truncated.as_bytes());
    let header_len = packet.len();
    for range in initial.crypto() {
        let data = crypto.slice(range.start as usize..range.end as usize);
        let frame = CryptoFrame::new(
            VarIntField::shortest(VarInt::try_from(range.start).unwrap()),
            VarIntWidth::shortest(VarInt::try_from(data.len()).unwrap()),
            data,
        )
        .unwrap();
        write_crypto_frame(&mut packet, frame);
    }
    if initial.ping() {
        write_ping_frame(&mut packet, PingFrame);
    }
    if let Some(padding) = NonZeroUsize::new(initial.length() - AEAD_TAG_LEN - packet.len()) {
        write_padding_run(&mut packet, PaddingRun::new(padding));
    }
    packet.resize(initial.length(), 0);
    packet_key
        .seal(initial.packet_number(), &mut packet, header_len)
        .unwrap();
    header_key.apply(&mut packet, pn_offset).unwrap();
    packet
}

// ---- the backend ----

/// A connection the backend accepted, with the connection IDs it was given
/// and how many of them it generated.
type BackendConnection = (ServerHandle, Vec<ConnectionId>, Arc<AtomicUsize>);

/// What the backend's task shares with the test.
#[derive(Default)]
struct BackendState {
    /// The connections the backend accepted, each with the connection IDs
    /// it was given and how many of them it generated.
    accepted: RefCell<Vec<BackendConnection>>,
}

/// The backend's application: before accepting each connection, it offers
/// the Relay [`BATCH`] connection IDs for it, and accepts only once the
/// Relay registered them, with a generator that issues from them alone.
async fn backend(
    mut incoming: IncomingStream<Udp, Server>,
    mut control: TcpStream,
    state: Rc<BackendState>,
) {
    let mut next = 0xbbbb_0000_0000_0000_u64;
    while let Some(item) = incoming.next().await {
        let Incoming::Terminable(mut half) = item;
        let Coproduct::Inl(SocketAddr::V4(relay_side)) = half.facts().peer else {
            panic!("the Relay forwards from an IPv4 socket");
        };
        let ids: Vec<ConnectionId> = (0..BATCH as u64).map(|n| counted(next + n)).collect();
        next += BATCH as u64;
        let mut offer = Vec::new();
        offer.extend(relay_side.ip().octets());
        offer.extend(relay_side.port().to_be_bytes());
        offer.push(BATCH as u8);
        for id in &ids {
            offer.extend_from_slice(id.as_bytes());
        }
        control.write_all(&offer).await.unwrap();
        let mut answer = [0];
        control.read_exact(&mut answer).await.unwrap();
        if answer != [1] {
            continue;
        }
        let given = Arc::new(AtomicUsize::new(0));
        half.use_connection_ids(Ids::Prepared(
            ids.iter().copied().collect(),
            Arc::clone(&given),
        ));
        state
            .accepted
            .borrow_mut()
            .push((spawned(accepted(half)), ids, given));
    }
}

// ---- the streams ----

/// Answers the first bidirectional stream the peer opens with what it
/// sent.
async fn echo(handle: &ServerHandle) {
    let layer = handle.established().await.unwrap();
    let (mut writer, mut reader) = layer.accept_bi().await.unwrap();
    let mut received = Vec::new();
    while let Some(nitori_io::ChunkSegment {
        chunk,
        metadata: (),
    }) = reader
        .read_chunk_unpin(NonZeroUsize::new(64 * 1024).unwrap())
        .await
        .unwrap()
    {
        received.extend_from_slice(&chunk);
    }
    writer
        .write_all_unpin(Bytes::from(received), ())
        .await
        .unwrap();
    writer.close().unwrap();
}

/// Sends `message` on a bidirectional stream and gives back the answer.
async fn ask(handle: &ClientHandle, message: &'static [u8]) -> Vec<u8> {
    let layer = handle.established().await.unwrap();
    let (mut writer, mut reader) = layer.open_bi().await.unwrap();
    writer
        .write_all_unpin(Bytes::from_static(message), ())
        .await
        .unwrap();
    writer.close().unwrap();
    let mut answer = Vec::new();
    while let Some(nitori_io::ChunkSegment {
        chunk,
        metadata: (),
    }) = reader
        .read_chunk_unpin(NonZeroUsize::new(64 * 1024).unwrap())
        .await
        .unwrap()
    {
        answer.extend_from_slice(&chunk);
    }
    answer
}

/// A datagram whose packet is a short header to `dcid`, which does not
/// open.
fn short_header(dcid: &ConnectionId) -> Vec<u8> {
    let mut datagram = vec![0x40];
    datagram.extend_from_slice(dcid.as_bytes());
    datagram.resize(64, 0x5b);
    datagram
}

#[test]
fn a_relay_serves_one_connection_and_forwards_another_on_the_same_socket() {
    run(async {
        // the backend, for b.example
        let (backend_endpoint, backend_reflow) =
            Endpoint::<Udp, Server, NoClient>::new(endpoint_config(
                server_config(ServerStarts {
                    name: "b.example",
                    seed: 3,
                }),
                (),
                0xb000_0000_0000_0000,
            ))
            .unwrap();
        tokio::task::spawn_local(backend_reflow);
        let backend_socket = bind();
        let backend_address = backend_socket.local_address();
        let (_backend_binding, backend_driver) = backend_endpoint
            .add_accepting_binding(backend_socket, BindingDeclarations::default())
            .unwrap();
        tokio::task::spawn_local(backend_driver);

        // the Relay, which serves a.example and forwards the rest
        let mut relay_config = server_config(ServerStarts {
            name: "a.example",
            seed: 2,
        });
        relay_config.keep_first_flight_layout = true;
        let (relay_endpoint, relay_reflow) = Endpoint::<Udp, Server, NoClient>::new(
            endpoint_config(relay_config, (), 0xa000_0000_0000_0000),
        )
        .unwrap();
        tokio::task::spawn_local(relay_reflow);
        let relay_socket = bind();
        let relay_address = relay_socket.local_address();
        let (_relay_binding, relay_driver) = relay_endpoint
            .add_accepting_binding(relay_socket, BindingDeclarations::default())
            .unwrap();
        tokio::task::spawn_local(relay_driver);
        let relay_state = Rc::new(RelayState::default());
        tokio::task::spawn_local(relay(
            relay_endpoint.incoming(),
            backend_address,
            Rc::clone(&relay_state),
        ));

        // the channel over which the backend gives the Relay its
        // connection IDs
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let control_address = listener.local_addr().unwrap();
        tokio::task::spawn_local(control(listener, Rc::clone(&relay_state)));
        let backend_state = Rc::new(BackendState::default());
        tokio::task::spawn_local(backend(
            backend_endpoint.incoming(),
            TcpStream::connect(control_address).await.unwrap(),
            Rc::clone(&backend_state),
        ));

        // two clients connect to the Relay's one socket at once
        let (client, client_reflow) = Endpoint::<Udp, NoServer, Client>::new(endpoint_config(
            (),
            client_config(),
            0xc000_0000_0000_0000,
        ))
        .unwrap();
        tokio::task::spawn_local(client_reflow);
        let (client_binding, client_driver) = client
            .add_connect_only_binding(bind(), BindingDeclarations::default())
            .unwrap();
        tokio::task::spawn_local(client_driver);
        let mut clients = Vec::new();
        for name in ["a.example", "b.example"] {
            let outgoing = within(
                "the client takes a link",
                client_binding.connect(relay_address, ServerTarget::from_host_name(name).unwrap()),
            )
            .await
            .unwrap();
            clients.push(spawned(started(outgoing)));
        }
        let [served, forwarded]: [ClientHandle; 2] = clients.try_into().ok().unwrap();

        // Each client completes its handshake: the one for a.example with
        // the Relay, the one for b.example with the backend, whose
        // certificate is for b.example alone. Had the Relay answered the
        // second as its server even once, the client would have taken the
        // Relay's connection ID and dropped the backend's packets (RFC 9000
        // §7.2).
        within(
            "the served handshake completes",
            served.handshake_completed(),
        )
        .await
        .unwrap();
        within(
            "the forwarded handshake completes",
            forwarded.handshake_completed(),
        )
        .await
        .unwrap();
        assert_eq!(relay_state.accepted.borrow().len(), 1);
        assert_eq!(backend_state.accepted.borrow().len(), 1);
        assert_eq!(relay_state.handed_off.borrow().len(), 1);
        assert_eq!(relay_state.incomings.get(), 2);

        // each carries a stream both ways
        let relay_side = relay_state.accepted.borrow()[0].clone();
        let backend_side = backend_state.accepted.borrow()[0].0.clone();
        let (answer_a, ()) = within("the served stream", async {
            futures_util::future::join(ask(&served, b"to a.example"), echo(&relay_side)).await
        })
        .await;
        let (answer_b, ()) = within("the forwarded stream", async {
            futures_util::future::join(ask(&forwarded, b"to b.example"), echo(&backend_side)).await
        })
        .await;
        assert_eq!(answer_a, b"to a.example");
        assert_eq!(answer_b, b"to b.example");

        // The backend issued connection IDs after its first, each from the
        // batch the Relay registered before the backend accepted; a
        // datagram to one of them comes to the Relay's socket and is
        // forwarded.
        let (ids, given) = {
            let accepted = backend_state.accepted.borrow();
            (accepted[0].1.clone(), Arc::clone(&accepted[0].2))
        };
        until("the backend issues a later connection ID", || {
            given.load(Ordering::Relaxed) >= 2
        })
        .await;
        let probe = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let to_issued = short_header(&ids[1]);
        probe.send_to(&to_issued, relay_address).await.unwrap();
        until("the Relay forwards a datagram to an issued ID", || {
            relay_state
                .forwarded
                .borrow()
                .iter()
                .any(|datagram| datagram[..] == to_issued[..])
        })
        .await;
        // Once the connection ends and the forwarding is idle, the Relay
        // revokes its registrations: the one under the client's first
        // destination connection ID, and the backend's batch.
        let registered = relay_endpoint.registration_count();
        forwarded.close(AppClose(7));
        within("the forwarded connection closes", forwarded.closed()).await;
        until("the forwarding ends", || {
            relay_state.forwarding.borrow().is_empty()
        })
        .await;
        until("the Relay revokes the forwarding's registrations", || {
            relay_endpoint.registration_count() == registered - 1 - BATCH
        })
        .await;

        served.close(AppClose(7));
        within("the served connection closes", served.closed()).await;
        relay_endpoint.close();
        backend_endpoint.close();
        client.close();
    });
}

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

    /// The certificate of `key(seed)` for `host`, issued by `root(1)`.
    pub fn leaf(host: &str, seed: u8) -> Vec<u8> {
        let alternative_names = extension(
            &[0x55, 0x1d, 0x11],
            false,
            &seq(&[&tlv(0x82, host.as_bytes())]),
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
            seed,
            "Test Root",
            host,
            key(seed).public_key(),
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

    /// The output of a future that is ready at once.
    fn ready<T>(future: impl Future<Output = T>) -> T {
        match pin!(future).poll(&mut core::task::Context::from_waker(
            core::task::Waker::noop(),
        )) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("the signature is ready at once"),
        }
    }
}
