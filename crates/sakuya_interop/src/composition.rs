//! The composition of the programs' endpoints and connections: UDP on
//! tokio, QUIC version 1 with the components sakuya has, the handshake
//! engines with the runner's certificates, and the key log.
//!
//! It follows `sakuya_test_support`'s `tests/first_connection.rs`, with
//! the hq-interop ALPN, the runner's ECDSA certificate on the server, a
//! client that takes the server's key from its leaf certificate without
//! verifying the chain ([`crate::verify`]), random connection IDs and
//! larger limits. With the feature `extensions`, the DATAGRAM and
//! reliable stream reset extensions are parts of every connection; each
//! announces its transport parameter only in the test case for it
//! ([`Extensions`]), so that the runner's test cases run with the
//! transport parameters of QUIC version 1 alone.

use core::{
    fmt,
    num::{NonZeroU32, NonZeroU64},
    time::Duration,
};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use bytes::Bytes;
use frunk_core::{Coprod, hlist};
use nitori_crypto::{NamedGroup, Random as _, SignatureScheme, SigningKey};
use nitori_crypto_aws_lc::{AwsLcBackend, EcdsaSigningKey};
use nitori_tls::{
    cipher_suite::CipherSuite,
    client::{
        ServerTarget,
        engine::{ClientHandshake, ClientHandshakeSettings},
        identity::NoClientCertificate,
        offering::PreferenceOffering,
        ticket::{ClientTicketStore, StoredTicket, TakeOnceTicketMap},
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
};
use rustls_pki_types::{PrivateKeyDer, pem::PemObject as _};
use sakuya_clock_tokio::TokioClock;
use sakuya_connection::v1;
use sakuya_connection::v1::aead_usage::KeyUpdateThreshold;
use sakuya_connection::v1::retry::ContinueOnRetry;
#[cfg(feature = "extensions")]
use sakuya_connection_datagram::{self as datagram, DatagramChoices, DatagramConnectionArgs};
#[cfg(feature = "extensions")]
use sakuya_connection_reset_stream_at as reset_stream_at;
use sakuya_datagram_routing::route::recognizer::{ConnectionIdGenerator, ConnectionIdLengths};
#[cfg(feature = "extensions")]
use sakuya_endpoint::part::PassThroughPart;
use sakuya_endpoint::{
    address_token::{
        AddressTokenKey, AddressTokenLifetimes, AeadAddressTokens, AeadNewTokenIssuer,
    },
    choices::EndpointChoices,
    client_token::BoundedAddressTokenStore,
    config::{
        ClientConfig, ClientCryptoReceiveCapacities, EndpointConfig, ServerConfig,
        ServerCryptoReceiveCapacities,
    },
    handshake::{ClientHandshakeConfig, ServerHandshakeConfig},
    retry::{
        LoadStatelessRetryPolicy, StatelessRetryDecision, StatelessRetryInput, StatelessRetryPolicy,
    },
    role::{
        AcceptingServer, ClientConnectionChoices, ClientRole, ConnectingClient,
        ServerConnectionChoices, ServerRole,
    },
};
use sakuya_packet_protection::backend::ring::RingBackend;
use sakuya_qlog::{QlogConfig, QlogWriter};
use sakuya_recovery::loss::LossThresholds;
use sakuya_udp_tokio::{UdpBinding, UdpBindingConfig, UdpLink};
use sakuya_wire::{
    connection_id::{ConnectionId, ConnectionIdLength, NonEmptyCid, StatelessResetToken},
    v1::{
        application_error::ApplicationErrorCode,
        stream_count::StreamCount,
        transport_parameters::{
            TransportParameters,
            integer::{
                InitialMaxData, InitialMaxStreamDataBidiLocal, InitialMaxStreamDataBidiRemote,
                InitialMaxStreamDataUni, InitialMaxStreamsBidi, MaxIdleTimeout,
            },
            preferred_address::{PreferredAddress, PreferredAddressFamilies},
        },
    },
    var_int::VarInt,
};
use snafu::{ResultExt as _, Snafu};
use tokio::sync::watch;

use crate::{hq, key_log::KeyLogFile, verify::LeafKeyVerifier};

// ---- the endpoint's choices ----

/// The endpoints of the programs: UDP on tokio.
pub(crate) struct Udp;

impl EndpointChoices for Udp {
    type Links = Coprod![UdpLink<TokioClock>];
    type Bindings = frunk_core::HList![UdpBinding<TokioClock>];
    type Clock = TokioClock;
    type Crypto = RingBackend;
    type Random = AwsLcBackend;
    type WallClock = SystemClock;
    type ConnectionIds = RandomConnectionIds;
    type Recognizer = ConnectionIdLengths;
    /// The family of `std` locks: the programs spawn locally, yet keep the
    /// composition an endpoint on several threads would have.
    type Synchronization = sakuya_sync_std::endpoint::LockingEndpointSynchronization;
}

/// The length of the connection IDs this side issues.
const CID_LENGTH: u8 = 8;

/// Connection IDs and stateless reset tokens drawn at random.
#[derive(Clone)]
pub(crate) struct RandomConnectionIds;

impl ConnectionIdGenerator for RandomConnectionIds {
    type Config = Self;

    fn new(_: &Self) -> Self {
        Self
    }

    fn generate(&mut self) -> (ConnectionId, StatelessResetToken) {
        // invariant: the operating system's generator does not fail on
        // Linux once the system is up
        let bytes: [u8; CID_LENGTH as usize] = AwsLcBackend.random().expect("random bytes");
        let token: [u8; 16] = AwsLcBackend.random().expect("random bytes");
        (
            ConnectionId::new(&bytes).expect("eight bytes"),
            StatelessResetToken::new(token),
        )
    }

    fn stateless_reset_token(_: &Self, _: &ConnectionId) -> Option<StatelessResetToken> {
        None
    }
}

// ---- the connections' choices ----

/// The application's reason for closing a connection: an application error
/// code.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct HqClose(pub(crate) u32);

impl fmt::Display for HqClose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the application closed with {}", self.0)
    }
}

impl std::error::Error for HqClose {}

impl v1::close::ApplicationClose for HqClose {
    fn code(&self) -> ApplicationErrorCode {
        ApplicationErrorCode::new(VarInt::from_u32(self.0))
    }
}

/// What the programs choose of version 1: their application error, qlog
/// for the connections' events, written where `QLOGDIR` says, and the
/// default of everything else. The endpoint fixes the rest
/// ([`ServerChoices`], [`ClientChoices`]).
pub(crate) struct InteropChoices;

impl<T: v1::MakerChoices> v1::HostChoices<T> for InteropChoices {
    type ApplicationError = HqClose;
    type Events<L> = QlogWriter<QlogWriterParts, TokioClock>;
}

/// The default queues of the DATAGRAM extension.
#[cfg(feature = "extensions")]
impl DatagramChoices for InteropChoices {}

/// The default of the reliable stream reset extension.
#[cfg(feature = "extensions")]
impl reset_stream_at::ResetStreamAtChoices for InteropChoices {}

/// The choices of the server's connections.
pub(crate) type ServerChoices =
    ServerConnectionChoices<Udp, InteropChoices, ServerStarts, AeadNewTokenIssuer<AwsLcBackend>>;
/// The choices of the client's connections.
pub(crate) type ClientChoices =
    ClientConnectionChoices<Udp, InteropChoices, ClientStarts, ClientTokens, ContinueOnRetry>;

/// The parts of the connections: version 1, and the two extensions with
/// the feature `extensions`.
#[cfg(feature = "extensions")]
pub(crate) type Parts = frunk_core::HList![v1::Part, datagram::Part, reset_stream_at::Part];
/// The parts of the connections: version 1, and the two extensions with
/// the feature `extensions`.
#[cfg(not(feature = "extensions"))]
pub(crate) type Parts = frunk_core::HList![v1::Part];
/// The endpoint's parts for [`Parts`]: version 1, and the two extensions,
/// configured with what their connections are given.
#[cfg(feature = "extensions")]
pub(crate) type EndpointParts = frunk_core::HList![
    v1::Part,
    PassThroughPart<datagram::Part>,
    PassThroughPart<reset_stream_at::Part>
];
/// The endpoint's parts for [`Parts`]: version 1.
#[cfg(not(feature = "extensions"))]
pub(crate) type EndpointParts = frunk_core::HList![v1::Part];
/// The parts of qlog's writer for [`Parts`]: version 1, and the two
/// extensions.
#[cfg(feature = "extensions")]
pub(crate) type QlogWriterParts = frunk_core::HList![
    v1::Part,
    sakuya_qlog_datagram::Part,
    sakuya_qlog_reset_stream_at::Part
];
/// The parts of qlog's writer for [`Parts`]: version 1.
#[cfg(not(feature = "extensions"))]
pub(crate) type QlogWriterParts = frunk_core::HList![v1::Part];
sakuya_connection::composition!(impl Send for InteropChoices: ServerChoices, Parts);
sakuya_connection::composition!(impl Send for InteropChoices: ClientChoices, Parts);

pub(crate) type Server = AcceptingServer<
    InteropChoices,
    EndpointParts,
    ServerStarts,
    AeadAddressTokens<AwsLcBackend>,
    RetryPolicy,
>;
/// Where the client keeps the address validation tokens servers give it.
pub(crate) type ClientTokens =
    BoundedAddressTokenStore<ServerTarget, sakuya_endpoint::choices::SynchronizationOf<Udp>>;
pub(crate) type Client =
    ConnectingClient<InteropChoices, EndpointParts, ClientStarts, ClientTokens, ContinueOnRetry>;

/// The stateless Retry policy of the server: always for the `retry` test
/// case, otherwise under load.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RetryPolicy {
    always: bool,
    load: LoadStatelessRetryPolicy,
}

impl<Peer> StatelessRetryPolicy<Peer> for RetryPolicy {
    fn decide(&self, input: &StatelessRetryInput<'_, Peer>) -> StatelessRetryDecision {
        if self.always {
            StatelessRetryDecision::SendRetry
        } else {
            self.load.decide(input)
        }
    }
}

// ---- the key log ----

/// The key log of the programs: the file `SSLKEYLOGFILE` names, or none.
#[derive(Clone, Debug, Default)]
pub(crate) struct OptionalKeyLog(Option<Arc<KeyLogFile>>);

impl OptionalKeyLog {
    /// The key log appending to `path`, or none without a path.
    pub(crate) fn open(path: Option<&Path>) -> std::io::Result<Self> {
        path.map(KeyLogFile::append_to)
            .transpose()
            .map(|file| Self(file.map(Arc::new)))
    }
}

impl KeyLog for OptionalKeyLog {
    fn log(&self, label: KeyLogLabel, client_random: &HelloRandom, secret: &[u8]) {
        if let Some(file) = &self.0 {
            file.log(label, client_random, secret);
        }
    }
}

// ---- the handshakes ----

/// The signing key of the server's certificate, shared by the engines of
/// its connections.
#[derive(Clone, Debug)]
pub(crate) struct SharedKey(Arc<EcdsaSigningKey>);

impl SigningKey for SharedKey {
    type Error = <EcdsaSigningKey as SigningKey>::Error;
    type Signing<'a> = <EcdsaSigningKey as SigningKey>::Signing<'a>;

    fn schemes(&self) -> &[SignatureScheme] {
        self.0.schemes()
    }

    fn sign<'a>(&'a self, scheme: SignatureScheme, message: &'a [u8]) -> Self::Signing<'a> {
        self.0.sign(scheme, message)
    }
}

/// The server's session tickets, in memory; every connection's engine
/// holds a clone, and clones share the table.
type ServerTickets = ZeroRttOnceTicketTable<&'static str, AwsLcBackend, SystemClock>;

pub(crate) type ServerEngine = ServerHandshake<
    AwsLcBackend,
    PreferenceTable,
    ServerTickets,
    PassThroughLayers,
    SniTargets<&'static str>,
    CertifiedKey<SharedKey>,
    NoCertificateRequest,
    SystemClock,
    OptionalKeyLog,
>;

pub(crate) type ClientEngine = ClientHandshake<
    AwsLcBackend,
    PreferenceOffering,
    Arc<WatchedTicketStore>,
    LeafKeyVerifier,
    NoClientCertificate,
    SystemClock,
    OptionalKeyLog,
>;

fn alpn() -> ProtocolName<Bytes> {
    // invariant: the name is between 1 and 255 bytes
    ProtocolName::new(Bytes::from_static(hq::ALPN)).expect("a protocol name")
}

/// The cipher suites to offer: all three of QUIC, or ChaCha20 alone.
pub(crate) fn cipher_suites(chacha20_only: bool) -> Vec<CipherSuite> {
    if chacha20_only {
        vec![CipherSuite::TLS_CHACHA20_POLY1305_SHA256]
    } else {
        vec![
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_AES_256_GCM_SHA384,
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
        ]
    }
}

fn groups() -> Vec<NamedGroup> {
    vec![NamedGroup::X25519, NamedGroup::SECP256R1]
}

/// Makes each server connection's engine.
#[derive(Clone)]
pub(crate) struct ServerStarts {
    chain: Vec<Bytes>,
    key: SharedKey,
    cipher_suites: Vec<CipherSuite>,
    tickets: ServerTickets,
    key_log: OptionalKeyLog,
}

/// The server's certificate cannot be loaded.
#[derive(Debug, Snafu)]
pub enum CertificateError {
    /// A file cannot be read.
    #[snafu(display("cannot read {path}"))]
    Read {
        /// The file.
        path: String,
        /// Why.
        source: std::io::Error,
    },
    /// The chain cannot be read.
    #[snafu(display("the certificate chain cannot be read"))]
    Chain {
        /// Why.
        source: nitori_tls::server::identity::PemChainError,
    },
    /// The private key is not PEM.
    #[snafu(display("the private key is not PEM"))]
    KeyPem {
        /// Why.
        source: rustls_pki_types::pem::Error,
    },
    /// The private key is not an ECDSA key.
    #[snafu(display("the private key is not an ECDSA key"))]
    Key {
        /// Why.
        source: nitori_crypto_aws_lc::EcdsaKeyDerError,
    },
}

fn read(path: &Path) -> Result<Vec<u8>, CertificateError> {
    std::fs::read(path).context(ReadSnafu {
        path: path.display().to_string(),
    })
}

impl ServerStarts {
    /// The engines presenting the chain in `certs/cert.pem` with the key
    /// in `certs/priv.key`, issuing session tickets that allow 0-RTT when
    /// `early_data`.
    pub(crate) fn load(
        certs: &Path,
        cipher_suites: Vec<CipherSuite>,
        early_data: bool,
        key_log: OptionalKeyLog,
    ) -> Result<Self, CertificateError> {
        let chain_pem = read(&certs.join("cert.pem"))?;
        let key_pem = read(&certs.join("priv.key"))?;
        let key = PrivateKeyDer::from_pem_slice(&key_pem).context(KeyPemSnafu)?;
        let key = EcdsaSigningKey::from_der(&key).context(KeySnafu)?;
        let chain = CertifiedKey::from_pem_chain(&chain_pem, ())
            .context(ChainSnafu)?
            .certificates()
            .to_vec();
        Ok(Self {
            chain,
            key: SharedKey(Arc::new(key)),
            cipher_suites,
            tickets: ZeroRttOnceTicketTable::new(
                AwsLcBackend,
                SystemClock,
                2,
                // invariant: an hour is within a week
                TicketLifetime::new(3600).expect("a ticket lifetime"),
                early_data,
                1024,
            ),
            key_log,
        })
    }
}

impl ServerHandshakeConfig for ServerStarts {
    type Start = ServerEngine;

    fn start(&self) -> ServerEngine {
        // Clients send the runner's host names, or an address, or no SNI:
        // every name gets the one target.
        let mut targets = SniTargets::new();
        targets.set_fallback("hq", vec![alpn()]);
        ServerHandshake::new(
            AwsLcBackend,
            PreferenceTable::new(
                self.cipher_suites.clone(),
                groups(),
                GroupPreference::KeyShareFirst,
            ),
            self.tickets.clone(),
            PassThroughLayers,
            targets,
            // invariant: `load` read at least one certificate
            CertifiedKey::new(self.chain.clone(), self.key.clone()).expect("a chain"),
            NoCertificateRequest,
            SystemClock,
            self.key_log.clone(),
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

/// Makes each client connection's engine, which takes the server's key
/// from its leaf certificate without verifying the chain
/// ([`LeafKeyVerifier`]).
#[derive(Clone)]
pub(crate) struct ClientStarts {
    verifier: LeafKeyVerifier,
    cipher_suites: Vec<CipherSuite>,
    tickets: Arc<WatchedTicketStore>,
    key_log: OptionalKeyLog,
}

impl ClientStarts {
    /// The engines offering `cipher_suites`, and 0-RTT when a ticket
    /// allows it, with `key_log`.
    pub(crate) fn new(cipher_suites: Vec<CipherSuite>, key_log: OptionalKeyLog) -> Self {
        Self {
            verifier: LeafKeyVerifier::new(),
            cipher_suites,
            tickets: Arc::new(WatchedTicketStore::new(TakeOnceTicketMap::new(
                SystemClock,
                Duration::from_secs(86_400),
                4,
            ))),
            key_log,
        }
    }

    /// The number of tickets the engines have stored so far, which changes
    /// with each one a server sends.
    pub(crate) fn tickets_stored(&self) -> watch::Receiver<usize> {
        self.tickets.stored.subscribe()
    }
}

/// The client's tickets, in memory, counting the ones stored: a connection
/// that is to be resumed waits for a ticket before it closes.
pub(crate) struct WatchedTicketStore {
    tickets: TakeOnceTicketMap<SystemClock>,
    stored: watch::Sender<usize>,
}

impl WatchedTicketStore {
    fn new(tickets: TakeOnceTicketMap<SystemClock>) -> Self {
        Self {
            tickets,
            stored: watch::Sender::new(0),
        }
    }
}

impl ClientTicketStore for WatchedTicketStore {
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
            // invariant: the key share group is one of the groups
            PreferenceOffering::new(
                self.cipher_suites.clone(),
                groups(),
                vec![NamedGroup::X25519],
            )
            .expect("an offering"),
            Arc::clone(&self.tickets),
            self.verifier.clone(),
            NoClientCertificate,
            SystemClock,
            self.key_log.clone(),
            server_name.clone(),
            // invariant: one protocol name
            Some(ProtocolNameList::new(vec![alpn()]).expect("a protocol list")),
            ClientHandshakeSettings::default(),
        )
    }

    fn limits(&self) -> MessageLimits {
        ClientHandshakeSettings::default().limits
    }
}

// ---- the configurations ----

/// The configuration of version 1 for both sides: the default, with the
/// transport parameters both sides send: room for the runner's files (up
/// to 10 MB on a stream) and for many streams, and no unidirectional
/// streams of the peer; the stream set raises the limits as the
/// application reads. A bidirectional stream takes a whole file at once: a
/// peer may give up on a write its stream's credit holds back for a few
/// seconds (mvfst's HTTP/0.9 server resets the stream after 5 s), and the
/// stream set raises a stream's limit only once half of it was read.
macro_rules! v1_config {
    ($t:ty, $qlog:expr) => {
        v1_config!($t, $qlog, None::<PreferredAddress>)
    };
    ($t:ty, $qlog:expr, $preferred:expr) => {{
        let mut parameters = TransportParameters::<Vec<u8>>::new();
        if let Some(preferred) = $preferred {
            parameters.set(preferred);
        }
        parameters.set(MaxIdleTimeout::new(VarInt::from_u32(30_000)));
        parameters.set(InitialMaxData::new(VarInt::from_u32(16 << 20)));
        parameters.set(InitialMaxStreamDataBidiLocal::new(VarInt::from_u32(
            16 << 20,
        )));
        parameters.set(InitialMaxStreamDataBidiRemote::new(VarInt::from_u32(
            16 << 20,
        )));
        parameters.set(InitialMaxStreamDataUni::new(VarInt::from_u32(1 << 20)));
        // invariant: 100 is below 2^60
        parameters.set(InitialMaxStreamsBidi::new(
            StreamCount::new(100).expect("a stream count"),
        ));
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

/// Which extensions a side announces: those of the test case it runs.
/// Without the feature `extensions` both are false: no test case sets
/// them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(not(feature = "extensions"), allow(dead_code))]
pub(crate) struct Extensions {
    /// `max_datagram_frame_size`, the recommended 65535.
    pub(crate) datagram: bool,
    /// `reset_stream_at`.
    pub(crate) reset_stream_at: bool,
}

#[cfg(feature = "extensions")]
impl Extensions {
    /// What the DATAGRAM extension is given: its parameter when it is
    /// announced, and the default queues.
    fn datagram<C: Default>(self) -> DatagramConnectionArgs<C> {
        DatagramConnectionArgs {
            transport_parameters: hlist![self.datagram.then(|| {
                sakuya_wire_datagram::MaxDatagramFrameSize::new(VarInt::from(
                    datagram::RECOMMENDED_MAX_DATAGRAM_FRAME_SIZE,
                ))
            })],
            queues: C::default(),
            resumed_parameters_policy: v1::parameters::UseConfiguredParameters,
        }
    }

    /// What the reliable stream reset extension is given: its parameter
    /// when it is announced.
    fn reset_stream_at(self) -> reset_stream_at::ResetStreamAtConnectionArgs {
        reset_stream_at::ResetStreamAtConnectionArgs {
            transport_parameters: hlist![
                self.reset_stream_at
                    .then_some(sakuya_wire_reset_stream_at::ResetStreamAt)
            ],
            resumed_parameters_policy: v1::parameters::UseConfiguredParameters,
        }
    }
}

/// The configurations of the parts ([`Parts`]): version 1's `$v1`, and
/// the extensions' from `$extensions`.
#[cfg(feature = "extensions")]
macro_rules! part_configs {
    ($v1:expr, $extensions:expr) => {
        hlist![$v1, $extensions.datagram(), $extensions.reset_stream_at()]
    };
}
/// The configurations of the parts ([`Parts`]): version 1's `$v1`, and
/// the extensions' from `$extensions`.
#[cfg(not(feature = "extensions"))]
macro_rules! part_configs {
    ($v1:expr, $extensions:expr) => {{
        let _: Extensions = $extensions;
        hlist![$v1]
    }};
}

fn thresholds() -> LossThresholds {
    // invariant: the recommended thresholds hold for a granularity of 1 ms
    LossThresholds::recommended(Duration::from_millis(1)).expect("thresholds")
}

/// The endpoint's configuration with the configurations of its two roles.
pub(crate) fn endpoint_config<S, C>(
    server: S::Config,
    client: C::Config,
) -> EndpointConfig<Udp, S, C>
where
    S: ServerRole<Udp>,
    C: ClientRole<Udp>,
{
    EndpointConfig {
        server,
        client,
        clock: TokioClock,
        crypto: RingBackend,
        random: AwsLcBackend,
        wall_clock: SystemClock,
        connection_ids: RandomConnectionIds,
        // invariant: 8 is a valid length
        recognizer: ConnectionIdLengths::new([
            ConnectionIdLength::new(CID_LENGTH.into()).expect("a length")
        ]),
    }
}

/// The server role's configuration.
///
/// With `preferred`, the server gives that preferred address; the server
/// binds it as well.
pub(crate) fn server_config(
    starts: ServerStarts,
    always_retry: bool,
    extensions: Extensions,
    preferred: Option<PreferredAddressFamilies>,
    qlog_dir: Option<PathBuf>,
) -> ServerConfig<
    ServerChoices,
    EndpointParts,
    ServerStarts,
    AeadAddressTokens<AwsLcBackend>,
    RetryPolicy,
> {
    // the connection ID and the token are placeholders: version 1 issues
    // the connection ID and fills both in for each connection
    let preferred = preferred.map(|addresses| PreferredAddress {
        addresses,
        // invariant: eight bytes are a connection ID that is not empty
        connection_id: NonEmptyCid::new(
            ConnectionId::new(&[0; 8]).expect("eight bytes are a connection ID"),
        )
        .expect("eight bytes are not empty"),
        stateless_reset_token: StatelessResetToken::new([0; StatelessResetToken::LEN]),
    });
    // invariant: the system's generator gives a key, and the defaults are
    // consistent
    let tokens = AeadAddressTokens::new(
        AwsLcBackend,
        AddressTokenKey::generate(&AwsLcBackend).expect("a token key"),
        AddressTokenLifetimes::default(),
        Default::default(),
    )
    .expect("an address token component");
    let load = LoadStatelessRetryPolicy::new(
        sakuya_endpoint::retry::CapacityFraction::new(1, NonZeroU32::new(2).expect("two"))
            .expect("a half"),
    );
    ServerConfig::new(
        starts,
        ServerCryptoReceiveCapacities {
            initial: 16 * 1024 + 4,
            handshake: 4096,
        },
        thresholds(),
        part_configs!(v1_config!(ServerChoices, qlog_dir, preferred), extensions),
        tokens,
        RetryPolicy {
            always: always_retry,
            load,
        },
    )
    .expect("a consistent server configuration")
}

/// How many packets sealed with one generation of 1-RTT keys make the
/// client initiate a key update under `keyupdate`: the runner's transfer of
/// 3 MB has the client seal far more ACK packets than that.
pub(crate) const KEY_UPDATE_AFTER: NonZeroU64 = NonZeroU64::new(100).unwrap();

/// The client role's configuration; with `update_keys`, the client
/// initiates a 1-RTT key update once [`KEY_UPDATE_AFTER`] packets were
/// sealed with a generation.
pub(crate) fn client_config(
    starts: ClientStarts,
    extensions: Extensions,
    update_keys: bool,
    qlog_dir: Option<PathBuf>,
) -> ClientConfig<ClientChoices, EndpointParts, ClientStarts, ClientTokens, ContinueOnRetry> {
    let mut v1 = v1_config!(ClientChoices, qlog_dir);
    if update_keys {
        v1.key_update = KeyUpdateThreshold {
            after_packets: Some(KEY_UPDATE_AFTER),
        };
    }
    ClientConfig::new(
        starts,
        ClientCryptoReceiveCapacities {
            initial: 16 * 1024 + 4,
            // the amplificationlimit test's chain of nine certificates
            handshake: 64 * 1024 + 4,
            one_rtt: 16 * 1024 + 4,
        },
        thresholds(),
        part_configs!(v1, extensions),
        ClientTokens::new(),
        ContinueOnRetry,
    )
    .expect("a consistent client configuration")
}

/// A UDP binding on `address`.
pub(crate) fn bind(
    address: SocketAddr,
) -> Result<UdpBinding<TokioClock>, sakuya_udp_tokio::BindError> {
    UdpBinding::bind(UdpBindingConfig::new(address), TokioClock)
}
