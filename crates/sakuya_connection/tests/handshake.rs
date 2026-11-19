//! A client and a server connection run their handshake against each
//! other, with nitori_tls's engines, over links in memory and the tests'
//! clock.
//!
//! The server presents an Ed25519 certificate for example.com, issued by an
//! Ed25519 root that the client's verifier trusts; both are built here. A
//! stand-in part in each connection notes what the tests look at as it
//! changes: the confirmation, the keys of the Initial and Handshake levels,
//! the record of why the connection closed, what only the side has, and
//! the packet number spaces of the logical path.
#![allow(
    clippy::arc_with_non_send_sync,
    reason = "the tests' routing domains are on one thread; deliverers are given as `Arc`s"
)]
#![feature(impl_trait_in_assoc_type, type_alias_impl_trait, yield_expr)]

mod common;

/// Allocations are counted, for the measurements of the exchanges.
#[global_allocator]
static ALLOCATOR: sakuya_test_support::measure::CountingAllocator =
    sakuya_test_support::measure::CountingAllocator;

use std::{
    cell::{Cell, RefCell},
    fmt::Debug,
    future::Future,
    num::NonZeroUsize,
    pin::pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use common::events::Recorded;
use common::{Outer, TestClock, TestLink, TestReceiver, advance_to, ms, now};
use nitori_crypto::{NamedGroup, SignatureScheme, SigningKey as _};
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
    clock::ManualClock,
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
use sakuya_connection::prelude::*;
use sakuya_connection::v1::events::{CloseTrigger, ConnectionState, EventInitiator, KeyChange};
use sakuya_connection::v1::{HostChoices, HostOf, SendParametersOf};
use sakuya_connection::{
    call::CallBundle,
    clock::{ConnectionChoices, InstantOf},
    component::{ArgsOf, Build, DataComponent, LineageOf, ParentsOf, RequestOf},
    component_event::{EventSubscriptions, Happened, NodeStarted, TriggeredEvents},
    connection_id::DestinationConnectionIdStrategy,
    dispatch::{DispatchFacts, FrameDispatch},
    driver::{LendNode, LendableLayer, NotLent},
    error::ConnectionErrorsOf,
    layer::{self, LinkPathArgs, LogicalPathArgs},
    others::OtherNodes,
    role::LinkPathRole,
    share::{
        LayerShare, LineageLists, LineagePartList, LinkPathIdentifierOf, LogicalPathKeyShare,
        SoleLogicalPath,
    },
    share::{PartList, RemainsOf},
    shared::{DrivenFromOutside, SharedConnectionDriver},
    take::GetAt,
    v1::{
        self, CloseCauseOf, Side,
        advancing::{ConnectionExporter, HandshakeStart},
        amplification::{AddressValidation, AntiAmplificationFactor},
        application_handles::{
            connection::ConnectionHandle, credential::HandleCredential,
            established_layer::TryOpenStreamError,
        },
        close::{CloseReasonRecord, LocalCloseCause},
        close_request::CloseRequestCell,
        component_events::{
            CloseReasonWritten, DestinationConnectionIdsChanged, HandshakeConfirmed,
            HandshakeDonePendingChanged, KeysDiscarded, KeysInstalled, LinkPathRoleChanged,
            LocalConnectionIdsChanged, RetryReceived, SpaceRetired, level,
        },
        confirmation::HandshakeConfirmation,
        connection_ids::{ConnectionIdsOf, FirstLocalConnectionId},
        crypto::CryptoReceiveCapacities,
        first_flight::FirstFlight,
        handshake_done::ClientOnlyStart,
        input::InitialPathReceiver,
        keys::{DirectionKeys, HandshakeKeys, InitialKeys},
        link::LinkFacts,
        retry::ContinueOnRetry,
        streams::StreamsOf,
    },
};
use sakuya_datagram_routing::{
    claim::{
        deliverer::DatagramDeliverer,
        delivery::DatagramDelivery,
        erased::ErasedDatagramDeliverer,
        queue::{
            DatagramDeliveryPoster, DatagramDeliveryQueue, RefCellDatagramDeliveryPoster,
            RefCellDatagramDeliveryQueue,
        },
    },
    route::{
        association::{MatchAssociation, PacketForms, RouteMatcher},
        index::{HashMapRouteEntryRegistration, HashMapRouteIndex, RouteIndex},
        recognizer::ConnectionIdLengths,
        reset::StatelessResetTokens,
        router::DatagramRouter,
    },
};
use sakuya_link::{ArrivalFacts, BindingId, LinkId, MIN_DATAGRAM_SIZE, ReceivedDatagram};
use sakuya_packet_protection::{
    backend::ring::RingBackend,
    initial::{INITIAL_AEAD, InitialSecrets},
};
use sakuya_recovery::{
    loss::LossThresholds,
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaceState, PacketNumberSpaces},
    receive_journals::MaxAckRanges,
};
use sakuya_stream::{
    connection::{AbortCause, CloseReason, ImmediateClose, LayerEnd},
    receive::read::ReadError,
    send::{finish::CloseError, write::WriteError},
};
use sakuya_wire::v1::encryption_level::EncryptionLevel;
use sakuya_wire::{
    connection_id::{ConnectionId, ConnectionIdLength, NonEmptyCid, StatelessResetToken},
    parameters::ParametersPart,
    parts::{CNil, HList, HNil},
    v1::{
        frame::set::{FrameSetPart, FrameTypeValues},
        role::Role,
        stream_count::StreamCount,
        transport_error::TransportErrorCode,
        transport_parameters::{
            TransportParameterSpace, TransportParameters,
            integer::{
                ActiveConnectionIdLimit, InitialMaxData, InitialMaxStreamDataBidiLocal,
                InitialMaxStreamDataBidiRemote, InitialMaxStreamsBidi, MaxIdleTimeout,
            },
        },
    },
    var_int::VarInt,
    version::Version,
};
use time::UtcDateTime;

const PATH: SoleLogicalPath = SoleLogicalPath;

/// The Destination Connection ID of the client's first Initial packet.
const CLIENT_DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
/// The client's own connection ID.
const CLIENT_CID: [u8; 8] = [0xc1, 0xc1, 0xc1, 0xc1, 0x01, 0x02, 0x03, 0x04];
/// The server's own connection ID.
const SERVER_CID: [u8; 8] = [0x5e, 0x5e, 0x5e, 0x5e, 0x01, 0x02, 0x03, 0x04];

fn cid(bytes: &[u8; 8]) -> ConnectionId {
    // invariant: eight bytes is a valid connection ID length
    ConnectionId::new(bytes).expect("eight bytes")
}

fn first_local(bytes: &[u8; 8], token: u8) -> FirstLocalConnectionId {
    FirstLocalConnectionId::Issued {
        id: NonEmptyCid::new(cid(bytes)).expect("not empty"),
        reset_token: StatelessResetToken::new([token; 16]),
    }
}

// ---- the certificates ----

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
    /// SCTs and the log list is past its age.
    pub fn verifier(seed: u8, clock: &Arc<ManualClock>) -> Verifier {
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
            Arc::clone(clock),
        )
    }
}

/// The output of a future that is ready at once.
fn ready<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("future not ready"),
    }
}

/// 2026-11-04T00:00:00Z, for the validity of the certificates.
fn tls_now() -> UtcDateTime {
    UtcDateTime::UNIX_EPOCH + Duration::from_secs(1_793_750_400)
}

type Verifier = WebPkiVerifier<
    AwsLcBackend,
    AnchorStore,
    SpkiDistrustList,
    NoRevocationCheck,
    EmbeddedSctPolicy,
    Arc<ManualClock>,
>;

// ---- the engines and the choices ----

type ServerEngine = ServerHandshake<
    AwsLcBackend,
    PreferenceTable,
    ZeroRttOnceTicketTable<&'static str, AwsLcBackend, Arc<ManualClock>>,
    PassThroughLayers,
    SniTargets<&'static str>,
    CertifiedKey<Ed25519SigningKey>,
    NoCertificateRequest,
    Arc<ManualClock>,
    (),
>;

type ClientEngine = ClientHandshake<
    AwsLcBackend,
    PreferenceOffering,
    Arc<TakeOnceTicketMap<Arc<ManualClock>>>,
    Verifier,
    NoClientCertificate,
    Arc<ManualClock>,
    (),
>;

fn h3() -> ProtocolName<Bytes> {
    ProtocolName::new(Bytes::from_static(b"h3")).unwrap()
}

fn server_engine(clock: &Arc<ManualClock>) -> ServerEngine {
    let mut targets = SniTargets::new();
    targets.insert("example.com", "web", vec![h3()]);
    ServerHandshake::new(
        AwsLcBackend,
        PreferenceTable::new(
            vec![
                CipherSuite::TLS_AES_128_GCM_SHA256,
                CipherSuite::TLS_AES_256_GCM_SHA384,
            ],
            vec![NamedGroup::X25519, NamedGroup::SECP256R1],
            GroupPreference::KeyShareFirst,
        ),
        ZeroRttOnceTicketTable::new(
            AwsLcBackend,
            Arc::clone(clock),
            2,
            TicketLifetime::new(3600).unwrap(),
            true,
            16,
        ),
        PassThroughLayers,
        targets,
        CertifiedKey::new(vec![Bytes::from(pki::leaf())], pki::key(2)).unwrap(),
        NoCertificateRequest,
        Arc::clone(clock),
        (),
        ServerHandshakeSettings::default(),
    )
}

/// The client's engine, whose verifier trusts `root(root_seed)`.
fn client_engine(clock: &Arc<ManualClock>, root_seed: u8) -> ClientEngine {
    ClientHandshake::new(
        AwsLcBackend,
        PreferenceOffering::new(
            vec![
                CipherSuite::TLS_AES_128_GCM_SHA256,
                CipherSuite::TLS_AES_256_GCM_SHA384,
            ],
            vec![NamedGroup::X25519, NamedGroup::SECP256R1],
            vec![NamedGroup::X25519],
        )
        .unwrap(),
        Arc::new(TakeOnceTicketMap::new(
            Arc::clone(clock),
            Duration::from_secs(86_400),
            4,
        )),
        pki::verifier(root_seed, clock),
        NoClientCertificate,
        Arc::clone(clock),
        (),
        ServerTarget::from_host_name("example.com").unwrap(),
        Some(ProtocolNameList::new(vec![h3()]).unwrap()),
        ClientHandshakeSettings::default(),
    )
}

macro_rules! choices {
    ($name:ident, $side:ty) => {
        choices!(
            $name,
            $side,
            sakuya_connection::send_strategy::ranked::RankedSendStrategy<I>
        );
    };
    ($name:ident, $side:ty, $strategy:ty) => {
        choices!(
            $name,
            $side,
            $strategy,
            sakuya_connection::v1::streams::owned::OwnedStreamSetFamily
        );
    };
    ($name:ident, $side:ty, $strategy:ty, $streams:ty) => {
        pub(crate) struct $name;
        impl ConnectionChoices for $name {
            type Clock = TestClock;
            type Link = TestLink;
        }
        impl v1::MakerChoices for $name {
            type Crypto = RingBackend;
            type Side = $side;
            type Receiver = TestReceiver;
            type ResetTokenRegistry = common::TestResetTokenRegistry;
            type ConnectionIdIssuer = common::TestConnectionIdIssuer;
        }
        impl v1::Choices for $name {
            type Host = Self;
        }
        impl v1::HostChoices<$name> for $name {
            type ApplicationError = common::AppClose;
            type SendStrategy<I: sakuya_connection::send_strategy::SendStrategyTypes> = $strategy;
            type DestinationConnectionIds = common::TestDestinationConnectionIds;
            type LocalConnectionIds = common::TestLocalConnectionIds;
            type ImmediateClosePolicy = common::TestImmediateClosePolicy;
            type MigrationPolicy = common::TestMigrationPolicy;
            type Events<L> = common::events::RecordingEvents;
            type Streams = $streams;
        }
    };
}
choices!(ServerChoices, v1::Server<ServerEngine, common::TestNewTokenIssuer>);
// the client's strategy plans as the ranked one does, and ends the intents
// a test marks when its link path's role next changes
choices!(
    ClientChoices,
    v1::Client<ClientEngine, common::TestTokenSink, ContinueOnRetry, ()>,
    common::ending::IntentEndingSendStrategy<I>
);

/// The parts of the tests' connections: version 1, and the part that notes
/// what the tests look at.
type Parts = HList![v1::Part, watch::Part];
sakuya_connection::composition!(impl for ServerChoices: ServerChoices, Parts);
sakuya_connection::composition!(impl for ClientChoices: ClientChoices, Parts);

// ---- what the tests look at ----

thread_local! {
    /// What each side's watch noted last: the server's first.
    static NOTED: RefCell<[Noted; 2]> = RefCell::new([Noted::default(), Noted::default()]);
    /// The token the client of the next run starts with; empty for none.
    static CLIENT_TOKEN: RefCell<Bytes> = const { RefCell::new(Bytes::new()) };
    /// How many of the first datagrams the client of the next run sends
    /// the link loses, as the network would: they are sent and never
    /// arrive.
    static CLIENT_DATAGRAMS_LOST: Cell<usize> = const { Cell::new(0) };
    /// Whether the server of the next run reads its first flight before
    /// its connection is made, as an endpoint that decides first does.
    static SERVER_READS_FIRST: Cell<bool> = const { Cell::new(false) };
}

/// What the watch of one side noted.
#[derive(Debug, Default, Clone)]
struct Noted {
    confirmed: bool,
    initial_keys: String,
    handshake_keys: String,
    /// The record of why the connection closed, as it shows.
    record: Option<String>,
    /// The alert this side's handshake failed with.
    alert: Option<u8>,
    /// The close the peer sent.
    peer_close: Option<ImmediateClose>,
    /// What only this side has, as it shows.
    own: String,
    /// The exporter the connection keeps, as it shows.
    exporter: String,
    /// The packet number spaces the logical path keeps.
    spaces: Vec<PacketNumberSpaceKind>,
    /// Whether the established layer was built with its stream set.
    streams: bool,
    /// How many of this side's connection IDs the logical path's local
    /// connection ID strategy keeps active.
    local_connection_ids: usize,
    /// How many of the peer's connection IDs the logical path's destination
    /// connection ID strategy offers for its first link path.
    offered_connection_ids: usize,
}

fn index(role: Role) -> usize {
    match role {
        Role::Server => 0,
        Role::Client => 1,
    }
}

fn noted(role: Role) -> Noted {
    NOTED.with(|n| n.borrow()[index(role)].clone())
}

fn note(role: Role, change: impl FnOnce(&mut Noted)) {
    NOTED.with(|n| change(&mut n.borrow_mut()[index(role)]));
}

mod watch {
    use super::*;

    /// The part that notes what the tests look at; it has nothing else.
    pub struct Part;
    impl LogicalPathKeyShare for Part {
        type Fields = HNil;
    }
    impl<L> sakuya_connection::error::ConnectionErrorPart<L> for Part {
        type ConnectionError = core::convert::Infallible;
    }
    impl sakuya_connection::v1::streams::resets::StreamResetsPart for Part {
        type Fold<Prev: sakuya_connection::v1::streams::resets::StreamResets> = Prev;
    }
    impl ParametersPart<TransportParameterSpace> for Part {
        type Parameters = HNil;
    }
    impl sakuya_connection::send_strategy::SendIntentPart for Part {
        type FrameSourceId = CNil;
        type SendIntents = CNil;
        type FrameSources = HNil;

        fn intent_item(intent: &CNil) -> CNil {
            match *intent {}
        }
    }
    impl<
        T: sakuya_connection::clock::ConnectionChoices,
        L: sakuya_connection::share::LogicalPathKeys,
        V,
    > sakuya_connection::frame_source::DriverContentPart<T, L, V, ()> for Part
    {
        fn pending<J>(
            _: &sakuya_connection::take::Lineage<'_, V>,
            _: &sakuya_connection::share::LinkPathIdentifierOf<T, L>,
            _: &mut sakuya_connection::send_strategy::DriverContent<J>,
            _: impl Fn(sakuya_wire::parts::CNil) -> J,
        ) {
        }
    }
    impl<T, L> sakuya_connection::frame_source::EstablishedSourceComponentsPart<T, L> for Part {
        type Components = HNil;
    }
    impl<K: sakuya_connection::frame_source::PacketKind>
        sakuya_connection::frame_source::FrameSourcePart<K> for Part
    {
        fn item(intent: &CNil) -> Option<CNil> {
            match *intent {}
        }
        fn source(item: &CNil) -> CNil {
            match *item {}
        }
    }

    const NO_FRAME_TYPES: FrameTypeValues = FrameTypeValues::new(&[]);

    impl FrameSetPart for Part {
        type Run<D> = CNil;
        type Kind = CNil;
        type TypeValue = CNil;
        type FieldsError = CNil;

        const FRAME_TYPE_VALUES: &'static FrameTypeValues = &NO_FRAME_TYPES;

        fn type_value_of(_: VarInt) -> Option<CNil> {
            None
        }

        fn kind_of(type_value: CNil) -> CNil {
            match type_value {}
        }

        fn run_kind<D>(run: &CNil) -> CNil {
            match *run {}
        }

        fn read_run<S: bytes::Buf + nitori_io::SplitTo>(
            _: &mut S,
            type_value: CNil,
        ) -> Result<CNil, CNil> {
            match type_value {}
        }
    }
    impl<T: ConnectionChoices, L> FrameDispatch<T, L, ()> for Part
    where
        for<'v> L: LineageLists<'v, T>,
    {
        fn dispatch<'v, B: CallBundle>(
            _: &mut LineageOf<'v, T, L, layer::LogicalPath>,
            _: &mut OtherNodes<'v, T, L, B>,
            run: CNil,
            _: &DispatchFacts<InstantOf<T>, LinkPathIdentifierOf<T, L>>,
        ) -> Result<(), core::convert::Infallible> {
            match run {}
        }

        fn fields_error(error: CNil) -> core::convert::Infallible {
            match error {}
        }
    }

    /// In the connection node: notes the confirmation, the keys of the
    /// Initial and Handshake levels, the record and what only the side has
    /// whenever one changes.
    #[derive(Debug)]
    pub struct Watch;
    impl<T: v1::Choices, L> Build<T, L, layer::Connection, ()> for Watch
    where
        for<'v> L: LineageLists<'v, T>,
    {
        fn build<'v>(
            _: &mut ParentsOf<'v, T, L, layer::Connection>,
            _: &mut ArgsOf<T, L, layer::Connection>,
        ) -> Self {
            Watch
        }
    }
    impl<T, L, Ic, Ii, Ih, Ir, Io, Ie>
        DataComponent<T, L, layer::Connection, (Ic, Ii, Ih, Ir, Io, Ie)> for Watch
    where
        T: v1::Choices<Crypto = RingBackend, Clock = TestClock>,
        L: LineagePartList<T> + ConnectionErrorsOf,
        <T::Side as Side>::Own: Debug,
        CloseCauseOf<T, L>: Debug,
        for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<HandshakeConfirmation, Ic>
            + GetAt<InitialKeys<RingBackend>, Ii>
            + GetAt<HandshakeKeys<RingBackend>, Ih>
            + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>
            + GetAt<<T::Side as Side>::Own, Io>
            + GetAt<ConnectionExporter<<T::Side as Side>::Exporter>, Ie>,
    {
        fn subscribes(out: &mut EventSubscriptions) {
            // what changes the confirmation, the keys, the record, the
            // side's own data and the exporter, which the handshake holds
            // as it installs the 1-RTT keys
            out.add::<HandshakeConfirmed>()
                .add::<KeysInstalled<level::Initial>>()
                .add::<KeysDiscarded<level::Initial>>()
                .add::<KeysInstalled<level::Handshake>>()
                .add::<KeysDiscarded<level::Handshake>>()
                .add::<KeysInstalled<level::OneRtt>>()
                .add::<CloseReasonWritten>()
                .add::<HandshakeDonePendingChanged>()
                .add::<RetryReceived>()
                .add::<NodeStarted<layer::Connection>>();
        }
        fn on_events<'v, B: CallBundle>(
            _: TriggeredEvents<'_>,
            lineage: LineageOf<'v, T, L, layer::Connection>,
            _: &mut OtherNodes<'v, T, L, B>,
            _: Duration,
        ) -> Option<RequestOf<T, L>> {
            let reason = lineage
                .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>()
                .reason();
            let alert = match reason {
                Some(CloseReason::Local(cause)) => match &**cause {
                    LocalCloseCause::Handshake(error) => error.alert().map(|alert| alert.get()),
                    LocalCloseCause::Connection(_)
                    | LocalCloseCause::Application(_)
                    | LocalCloseCause::LinkEnded(_) => None,
                },
                _ => None,
            };
            let peer_close = match reason {
                Some(CloseReason::Peer(close)) => Some(close.clone()),
                _ => None,
            };
            let snapshot = Noted {
                confirmed: *lineage.get::<HandshakeConfirmation, Ic>()
                    == HandshakeConfirmation::Confirmed,
                initial_keys: format!("{:?}", lineage.get::<InitialKeys<RingBackend>, Ii>()),
                handshake_keys: format!("{:?}", lineage.get::<HandshakeKeys<RingBackend>, Ih>()),
                record: reason.map(|reason| format!("{reason:?}")),
                alert,
                peer_close,
                own: format!("{:?}", lineage.get::<<T::Side as Side>::Own, Io>()),
                exporter: format!(
                    "{:?}",
                    lineage.get::<ConnectionExporter<<T::Side as Side>::Exporter>, Ie>()
                ),
                spaces: Vec::new(),
                streams: false,
                local_connection_ids: 0,
                offered_connection_ids: 0,
            };
            note(<T::Side as Side>::ROLE, |noted| {
                *noted = Noted {
                    spaces: core::mem::take(&mut noted.spaces),
                    streams: noted.streams,
                    local_connection_ids: noted.local_connection_ids,
                    offered_connection_ids: noted.offered_connection_ids,
                    ..snapshot
                };
            });
            None
        }
    }

    /// In the logical path: notes the packet number spaces it keeps
    /// whenever they change.
    #[derive(Debug)]
    pub struct SpaceWatch;
    impl<T: v1::Choices, L> Build<T, L, layer::LogicalPath, ()> for SpaceWatch
    where
        for<'v> L: LineageLists<'v, T>,
    {
        fn build<'v>(
            _: &mut ParentsOf<'v, T, L, layer::LogicalPath>,
            _: &mut ArgsOf<T, L, layer::LogicalPath>,
        ) -> Self {
            SpaceWatch
        }
    }
    impl<T, L, Is> DataComponent<T, L, layer::LogicalPath, Is> for SpaceWatch
    where
        T: v1::Choices<Clock = TestClock>,
        for<'v> L: LineageLists<'v, T>,
        for<'v> <L as LineageLists<'v, T>>::LogicalPath:
            GetAt<PacketNumberSpaces<PacketNumberSpaceState>, Is>,
    {
        fn subscribes(out: &mut EventSubscriptions) {
            out.add::<SpaceRetired>()
                .add::<NodeStarted<layer::LogicalPath>>();
        }
        fn on_events<'v, B: CallBundle>(
            _: TriggeredEvents<'_>,
            lineage: LineageOf<'v, T, L, layer::LogicalPath>,
            _: &mut OtherNodes<'v, T, L, B>,
            _: Duration,
        ) -> Option<RequestOf<T, L>> {
            let spaces = lineage.get::<PacketNumberSpaces<PacketNumberSpaceState>, Is>();
            let kept = PacketNumberSpaceKind::ALL
                .into_iter()
                .filter(|kind| spaces.get(*kind).is_some())
                .collect();
            note(<T::Side as Side>::ROLE, |noted| noted.spaces = kept);
            None
        }
    }

    /// In the logical path: notes how many connection IDs of this side the
    /// local connection ID strategy keeps active, and how many of the
    /// peer's the destination strategy offers for the first link path,
    /// whenever the connection IDs change.
    #[derive(Debug)]
    pub struct ConnectionIdsWatch;
    impl<T: v1::Choices, L> Build<T, L, layer::LogicalPath, ()> for ConnectionIdsWatch
    where
        for<'v> L: LineageLists<'v, T>,
    {
        fn build<'v>(
            _: &mut ParentsOf<'v, T, L, layer::LogicalPath>,
            _: &mut ArgsOf<T, L, layer::LogicalPath>,
        ) -> Self {
            ConnectionIdsWatch
        }
    }
    impl<T, L, Ii> DataComponent<T, L, layer::LogicalPath, Ii> for ConnectionIdsWatch
    where
        T: v1::Choices<
                Clock = TestClock,
                Link = TestLink,
                Host: v1::HostChoices<
                    T,
                    DestinationConnectionIds = common::TestDestinationConnectionIds,
                    LocalConnectionIds = common::TestLocalConnectionIds,
                >,
            >,
        for<'v> L: LineageLists<'v, T>,
        for<'v> <L as LineageLists<'v, T>>::LogicalPath: GetAt<ConnectionIdsOf<T>, Ii>,
    {
        fn subscribes(out: &mut EventSubscriptions) {
            out.add::<DestinationConnectionIdsChanged>()
                .add::<LocalConnectionIdsChanged>()
                .add::<NodeStarted<layer::LogicalPath>>()
                .add::<NodeStarted<layer::LinkPath>>();
        }
        fn on_events<'v, B: CallBundle>(
            _: TriggeredEvents<'_>,
            lineage: LineageOf<'v, T, L, layer::LogicalPath>,
            others: &mut OtherNodes<'v, T, L, B>,
            _: Duration,
        ) -> Option<RequestOf<T, L>> {
            let ids = lineage.get::<ConnectionIdsOf<T>, Ii>();
            let local = ids.local_strategy().inner().active().count();
            let offered = others
                .link_path_keys()
                .find_map(|key| match key {
                    layer::NodeKey::LinkPath(_, link) => Some(link.clone()),
                    _ => None,
                })
                .map_or(0, |link| {
                    <common::TestDestinationConnectionIds as DestinationConnectionIdStrategy<
                        LinkId<(), ()>,
                        Duration,
                        common::TestResetTokenRegistrar,
                    >>::offer(ids.destination(), &link)
                    .count()
                });
            note(<T::Side as Side>::ROLE, |noted| {
                noted.local_connection_ids = local;
                noted.offered_connection_ids = offered;
            });
            None
        }
    }

    /// In the established layer: notes that the layer holds the stream set
    /// once it is built, subscribing to the layer built.
    #[derive(Debug)]
    pub struct StreamsWatch;
    impl<T: v1::Choices, L> Build<T, L, layer::Established, ()> for StreamsWatch
    where
        for<'v> L: LineageLists<'v, T>,
    {
        fn build<'v>(
            _: &mut ParentsOf<'v, T, L, layer::Established>,
            _: &mut ArgsOf<T, L, layer::Established>,
        ) -> Self {
            StreamsWatch
        }
    }
    impl<T, L, Is> DataComponent<T, L, layer::Established, (Is,)> for StreamsWatch
    where
        T: v1::Choices<Clock = TestClock>,
        L: LineagePartList<T> + ConnectionErrorsOf,
        v1::send::SendTypes<T, L>: v1::send_planning::ComponentPublishing<
                v1::StreamSetFamilyOf<T>,
                v1::streams::send::StreamIntent<SendParametersOf<T>>,
            >,
        for<'v> <L as LineageLists<'v, T>>::Established: GetAt<StreamsOf<T, L>, Is>,
    {
        fn subscribes(out: &mut EventSubscriptions) {
            out.add::<NodeStarted<layer::Established>>();
        }
        fn on_events<'v, B: CallBundle>(
            _: TriggeredEvents<'_>,
            lineage: LineageOf<'v, T, L, layer::Established>,
            _: &mut OtherNodes<'v, T, L, B>,
            _: Duration,
        ) -> Option<RequestOf<T, L>> {
            let _ = lineage.get::<StreamsOf<T, L>, Is>();
            note(<T::Side as Side>::ROLE, |noted| noted.streams = true);
            None
        }
    }

    /// The role a link path takes, as of the instant it takes it.
    type RoleAt = fn(Duration) -> LinkPathRole<Duration>;

    thread_local! {
        /// The role the client's link path takes at the start of the next
        /// poll.
        static CLIENT_ROLE: core::cell::Cell<Option<RoleAt>> =
            const { core::cell::Cell::new(None) };
    }

    /// Let the client's link path take the role `role` gives at the start
    /// of its connection's next poll: as if the connection moved it to
    /// another role and back, which the tests' link cannot make happen.
    pub fn set_client_role(role: RoleAt) {
        CLIENT_ROLE.with(|next| next.set(Some(role)));
        wake_client_setter();
    }

    thread_local! {
        /// Whether the client's connection panics at the start of its next
        /// poll.
        static CLIENT_PANICS: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
        /// The waker of the client's role setter, which runs only once it
        /// is called.
        static CLIENT_SETTER: core::cell::RefCell<Option<Waker>> =
            const { core::cell::RefCell::new(None) };
    }

    /// Wake the client's role setter, so that it runs at the start of the
    /// next poll.
    fn wake_client_setter() {
        CLIENT_SETTER.with(|waker| {
            if let Some(waker) = waker.borrow().as_ref() {
                waker.wake_by_ref();
            }
        });
    }

    /// Let the client's connection panic at the start of its next poll, in
    /// the link path's call before the calls: a panic that unwinds through
    /// the driver, which the harness catches before it drops the driver.
    pub fn panic_client() {
        CLIENT_PANICS.with(|next| next.set(true));
        wake_client_setter();
    }

    /// In the link path: gives the client's link path the role
    /// [`set_client_role`] asked for, or panics as [`panic_client`] asked.
    #[derive(Debug)]
    pub struct RoleSetter;
    impl<T: v1::Choices, L> Build<T, L, layer::LinkPath, ()> for RoleSetter
    where
        for<'v> L: LineageLists<'v, T>,
    {
        fn build<'v>(
            _: &mut ParentsOf<'v, T, L, layer::LinkPath>,
            _: &mut ArgsOf<T, L, layer::LinkPath>,
        ) -> Self {
            RoleSetter
        }
    }
    impl<T, L, Ir> DataComponent<T, L, layer::LinkPath, (Ir,)> for RoleSetter
    where
        T: v1::Choices<Clock = TestClock>,
        for<'v> L: LineageLists<'v, T>,
        for<'v> <L as LineageLists<'v, T>>::LinkPath: GetAt<LinkPathRole<Duration>, Ir>,
    {
        const ACTS_BEFORE_CALLS: bool = true;

        fn before_calls<'v, B: CallBundle>(
            mut lineage: LineageOf<'v, T, L, layer::LinkPath>,
            _: &mut OtherNodes<'v, T, L, B>,
            now: Duration,
            waker: &Waker,
        ) -> Option<RequestOf<T, L>> {
            if <T::Side as Side>::ROLE == Role::Client {
                CLIENT_SETTER.with(|setter| *setter.borrow_mut() = Some(waker.clone()));
            }
            if <T::Side as Side>::ROLE == Role::Client && CLIENT_PANICS.with(core::cell::Cell::take)
            {
                panic!("the test's panic in the client's poll");
            }
            if <T::Side as Side>::ROLE == Role::Client
                && let Some(role) = CLIENT_ROLE.with(core::cell::Cell::take)
            {
                *lineage.get_mut::<LinkPathRole<Duration>, Ir>() = role(now);
                lineage.publish(Happened::<LinkPathRoleChanged>::new());
            }
            None
        }
    }

    macro_rules! none {
        ($($lv:ident),*) => {$(
            impl<T: v1::Choices, L> LayerShare<T, L, layer::$lv> for Part {
                type Data = HNil;
                type Calls = HNil;
            }
        )*};
    }
    none!(LinkEntry, Recovery);
    impl<T: v1::Choices, L> LayerShare<T, L, layer::LinkPath> for Part {
        type Data = HList![RoleSetter];
        type Calls = HNil;
    }
    impl<T: v1::Choices, L> LayerShare<T, L, layer::Established> for Part {
        type Data = HList![StreamsWatch];
        type Calls = HNil;
    }
    impl<T: v1::Choices, L> LayerShare<T, L, layer::Connection> for Part {
        type Data = HList![Watch];
        type Calls = HNil;
    }
    impl<T: v1::Choices, L> LayerShare<T, L, layer::LogicalPath> for Part {
        type Data = HList![SpaceWatch, ConnectionIdsWatch];
        type Calls = HNil;
    }
}

// ---- the network ----

/// A datagram of the tests, as it arrived.
type Datagram = ReceivedDatagram<BytesMut, TestLink>;
/// What routing gives a deliverer of the tests.
type Delivery =
    DatagramDelivery<Datagram, (), sakuya_datagram_routing::claim::finish::ReleaseUnclaimed>;
/// The deliverers of the tests' routing domains.
type Target = dyn ErasedDatagramDeliverer<Datagram, ()>;

/// A deliverer that posts to a connection's receiver.
struct Posting(RefCellDatagramDeliveryPoster<Delivery>);
impl DatagramDeliverer<Datagram, ()> for Posting {
    fn deliver(&self, delivery: Delivery) {
        self.0.post(delivery);
    }
}

/// The routing domain of one side: an entry for each of its connection
/// IDs, posting to the receiver of its connection's first logical path.
struct Routing {
    router: DatagramRouter<
        BytesMut,
        TestLink,
        HashMapRouteIndex<Target, (), std::hash::RandomState>,
        ConnectionIdLengths,
        common::TestResetTokenRegistry,
    >,
    reset_tokens: common::TestResetTokenRegistry,
    _registrations: Vec<HashMapRouteEntryRegistration<Target, (), std::hash::RandomState>>,
}

impl Routing {
    /// A routing domain for `ids`, and the receiver it posts to.
    fn new(ids: &[ConnectionId]) -> (Self, TestReceiver) {
        let queue = RefCellDatagramDeliveryQueue::new(NonZeroUsize::new(64).expect("not zero"))
            .expect("a capacity a queue can have");
        let index = HashMapRouteIndex::<Target, (), std::hash::RandomState>::new();
        let registrations = ids
            .iter()
            .map(|id| {
                index.register(
                    RouteMatcher::new(
                        MatchAssociation::LocalCid(NonEmptyCid::new(*id).expect("not empty")),
                        PacketForms::ALL,
                        Version::V1,
                    ),
                    Arc::new(Posting(queue.poster())) as Arc<Target>,
                )
            })
            .collect();
        let reset_tokens = common::TestResetTokenRegistry::new();
        let router = DatagramRouter::new(
            index,
            ConnectionIdLengths::new([ConnectionIdLength::new(8).expect("a length")]),
        )
        .with_stateless_reset(reset_tokens.clone());
        (
            Self {
                router,
                reset_tokens,
                _registrations: registrations,
            },
            queue,
        )
    }

    /// Route `payload`, arrived over `link` now.
    fn deliver(&self, payload: Bytes, link: &LinkId<(), ()>) {
        self.router.route(arrived(payload, link));
    }
}

fn arrived(payload: Bytes, link: &LinkId<(), ()>) -> Datagram {
    ReceivedDatagram::new(
        BytesMut::from(&payload[..]),
        ArrivalFacts::new(TestLink(link.clone()), now(), None),
    )
}

fn link() -> LinkId<(), ()> {
    LinkId::new::<()>((), (), &BindingId::new())
}

/// The capacities of the CRYPTO data a server receives: the least the
/// default message limits allow.
fn server_capacities() -> CryptoReceiveCapacities {
    CryptoReceiveCapacities::server(MessageLimits::default(), false, 16 * 1024 + 4, 4096)
        .expect("the least capacities the limits allow")
}

/// The capacities of the CRYPTO data a client receives.
fn client_capacities() -> CryptoReceiveCapacities {
    CryptoReceiveCapacities::client(
        MessageLimits::default(),
        16 * 1024 + 4,
        64 * 1024 + 4,
        16 * 1024 + 4,
    )
    .expect("the least capacities the limits allow")
}

/// A connection of the parts `Parts` in scope, of the choices `$t`, whose
/// first link path is over `$link`: version 1's facts `$args`, nothing for
/// the watch, and `$rest` for the parts after it.
macro_rules! connection {
    ($t:ty, $args:expr, $link:expr, [$($before:expr),*] [$($after:expr),*]) => {
        <$t as sakuya_connection::composition::Composition<$t, Parts>>::connection(
            TestClock,
            frunk_core::hlist![$($before,)* $args $(, $after)*],
            LogicalPathArgs { path: PATH },
            LinkPathArgs {
                path: PATH,
                link: TestLink($link),
                role: LinkPathRole::Active,
                peer_switched_local_id: false,
            },
        )
        .0
    };
}

/// A connection made later (`Later`): until it is, it lends nothing and
/// is not driven, as a handle taken before it was made sees it.
struct Later<D>(Option<D>);

impl<T, L, D> LendNode<T, L> for Later<D>
where
    T: ConnectionChoices,
    L: PartList<T>,
    for<'v> L: LineageLists<'v, T>,
    D: LendNode<T, L>,
{
    fn lend<Lv: LendableLayer, R>(
        &mut self,
        at: Lv::At<T, L>,
        op: impl for<'v> FnOnce(LineageOf<'v, T, L, Lv>, InstantOf<T>) -> (R, Option<RequestOf<T, L>>),
    ) -> Result<R, NotLent<'_, RemainsOf<T, L>>> {
        match &mut self.0 {
            Some(connection) => connection.lend::<Lv, R>(at, op),
            None => Err(NotLent::Absent),
        }
    }
}

impl<D: Future<Output = ()> + Unpin> Future for Later<D> {
    type Output = ();
    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        match &mut self.get_mut().0 {
            Some(connection) => core::pin::Pin::new(connection).poll(cx),
            None => Poll::Pending,
        }
    }
}

impl<D: DrivenFromOutside> DrivenFromOutside for Later<D> {
    fn driving_dropped(&mut self) {
        if let Some(connection) = &mut self.0 {
            connection.driving_dropped();
        }
    }
}

/// Whether `datagram` starts with an Initial packet.
fn starts_with_initial(datagram: &[u8]) -> bool {
    datagram
        .first()
        .is_some_and(|&byte| byte & 0x80 != 0 && (byte >> 4) & 0b11 == 0)
}

/// The harness of the runs for the parts `Parts` in scope: version 1's
/// facts ([`args`]), what a run left ([`Run`]) and the run of a handshake
/// ([`handshake`]); `$server` and `$client` are what each side's parts
/// after version 1 are given, in the order of `Parts`.
macro_rules! harness {
    (server: [$($server:expr),*], client: [$($client:expr),*]) => {
        harness!(server: [] [$($server),*], client: [] [$($client),*]);
    };
    (
        server: [$($server_before:expr),*] [$($server:expr),*],
        client: [$($client_before:expr),*] [$($client:expr),*]
    ) => {
/// Version 1's facts for a connection of the choices `T`.
#[allow(clippy::too_many_arguments)]
fn args<T>(
    handshake: HandshakeStart<<T::Side as Side>::Tls>,
    side: <T::Side as Side>::Start,
    validation: AddressValidation,
    crypto_receive: CryptoReceiveCapacities,
    first_flight: FirstFlight<T>,
    receiver: TestReceiver,
    routing: &Routing,
    first_local_connection_id: FirstLocalConnectionId,
) -> v1::ConnectionArgs<T, Parts>
where
    T: v1::Choices<
            Crypto = RingBackend,
            Link = TestLink,
            Receiver = TestReceiver,
            ResetTokenRegistry = common::TestResetTokenRegistry,
            ConnectionIdIssuer = common::TestConnectionIdIssuer,
            Host: v1::HostChoices<
                T,
                DestinationConnectionIds = common::TestDestinationConnectionIds,
                ImmediateClosePolicy = common::TestImmediateClosePolicy,
                ResumedParametersPolicy = v1::parameters::UseConfiguredParameters,
                ApplicationError = common::AppClose,
            >,
        >,
    <HostOf<T> as HostChoices<T>>::Recovery<LinkId<(), ()>>:
        sakuya_recovery::factory::RecoveryFactory<TestLink, Config: Default>,
{
    let mut parameters = TransportParameters::<Vec<u8>>::new();
    parameters.set(MaxIdleTimeout::new(VarInt::from_u32(30_000)));
    // each side lets the other open a few bidirectional streams and send
    // a little on them
    parameters.set(InitialMaxData::new(VarInt::from_u32(65_536)));
    parameters.set(InitialMaxStreamDataBidiLocal::new(VarInt::from_u32(16_384)));
    parameters.set(InitialMaxStreamDataBidiRemote::new(VarInt::from_u32(
        16_384,
    )));
    parameters.set(InitialMaxStreamsBidi::new(
        StreamCount::new(4).expect("a stream count"),
    ));
    // each side takes as many of the other's connection IDs as sakuya's
    // local connection ID strategy keeps issued
    parameters.set(
        ActiveConnectionIdLimit::new(VarInt::from_u32(4)).expect("at least 2"),
    );
    v1::ConnectionArgs {
        crypto: RingBackend,
        handshake,
        side,
        client_dcid: cid(&CLIENT_DCID),
        original_destination_connection_id: None,
        anti_amplification: AntiAmplificationFactor::new(3).expect("3 is a factor"),
        transport_parameters: parameters.known,
        first_link: LinkFacts { validation },
        // the recommended values for timers that fire to the millisecond
        recovery: Default::default(),
        loss_thresholds: LossThresholds::recommended(ms(1))
            .expect("the test clock's timers fire to the millisecond"),
        max_ack_ranges: MaxAckRanges::DEFAULT,
        key_update: Default::default(),
        crypto_receive,
        first_flight,
        initial_receiver: InitialPathReceiver::new(receiver),
        max_datagrams_per_poll: NonZeroUsize::new(16).expect("not zero"),
        max_held_inputs: 16,
        destination_connection_ids:
            sakuya_connection::connection_id::sequence_map::SequenceMapDestinationConnectionIdStrategyConfig::new(8),
        reset_token_registry: routing.reset_tokens.clone(),
        local_connection_id_issuer: common::local_connection_id_issuer(&first_local_connection_id),
        first_local_connection_id,
        max_datagrams_per_send: NonZeroUsize::new(16).expect("not zero"),
        immediate_close_policy: common::TestImmediateClosePolicy,
        resumed_parameters_policy: v1::parameters::UseConfiguredParameters,
        close_request: CloseRequestCell::new(),
        stream_set: Default::default(),
        events: Default::default(),
    }
}

/// The client's connection of these parts.
type ClientConnection = impl DrivenFromOutside + LendNode<ClientChoices, Parts> + 'static;

/// The client's connection made with `args`, over `link`.
#[define_opaque(ClientConnection)]
fn client_connection(
    args: v1::ConnectionArgs<ClientChoices, Parts>,
    link: LinkId<(), ()>,
) -> ClientConnection {
    connection!(ClientChoices, args, link, [$($client_before),*] [$($client),*])
}

/// The server's connection of these parts.
type ServerConnection = impl DrivenFromOutside + LendNode<ServerChoices, Parts> + 'static;

/// The server's connection made with `args`, over `link`.
#[define_opaque(ServerConnection)]
fn server_connection(
    args: v1::ConnectionArgs<ServerChoices, Parts>,
    link: LinkId<(), ()>,
) -> ServerConnection {
    connection!(ServerChoices, args, link, [$($server_before),*] [$($server),*])
}

/// What a run of a handshake left.
struct Run {
    /// The datagrams the client sent, in order.
    client_sent: Vec<Bytes>,
    /// Whether the server's connection ended.
    server_ended: bool,
    /// Whether the client's connection ended.
    client_ended: bool,
    /// Whether a poll of the client's connection panicked; the harness
    /// caught the panic, dropped the driver and polled it no more.
    #[allow(dead_code, reason = "not every harness's tests make it panic")]
    client_panicked: bool,
    /// How many times the drivers' waker was woken, as of the last time
    /// the test was asked whether it is done.
    #[allow(dead_code, reason = "only the measurements read it")]
    driver_wakes: usize,
    /// The client's connection handle.
    client_handle: ConnectionHandle<ClientChoices, Parts, Rc<RefCell<ClientConnection>>>,
    /// The server's connection handle.
    server_handle: ConnectionHandle<ServerChoices, Parts, Rc<RefCell<Later<ServerConnection>>>>,
    /// The client's link.
    #[allow(dead_code, reason = "not every harness's tests end the link")]
    client_link: LinkId<(), ()>,
}

/// Run a client of the engine `client` against a server until `done` says
/// so, or for at most 3 s of the tests' clock; `done` is called once every
/// millisecond, after the datagrams of that millisecond went across, and
/// may act on the connections' handles.
fn handshake(
    client: ClientEngine,
    clock: &Arc<ManualClock>,
    mut done: impl FnMut(&Run) -> bool,
) -> Run {
    NOTED.with(|n| *n.borrow_mut() = [Noted::default(), Noted::default()]);
    common::events::reset();
    common::reset_links();
    advance_to(ms(0));
    let (client_link, server_link) = (link(), link());
    let (client_routing, client_receiver) = Routing::new(&[cid(&CLIENT_CID)]);
    let client_args = args::<ClientChoices>(
        HandshakeStart::new(client, MessageLimits::default()),
        ClientOnlyStart::new(
            CLIENT_TOKEN.with(|token| token.take()),
            common::TestTokenSink,
            ContinueOnRetry,
            (),
        ),
        AddressValidation::Validated,
        client_capacities(),
        FirstFlight::Datagrams(Vec::new()),
        client_receiver,
        &client_routing,
        first_local(&CLIENT_CID, 0xc1),
    );
    let client_shared = Rc::new(RefCell::new(client_connection(client_args, client_link.clone())));
    let client_handle = ConnectionHandle::new(client_shared.clone());
    let mut client = Some(SharedConnectionDriver::new(client_shared));
    let outer = Outer::new();
    assert!(outer.poll(client.as_mut().expect("made")).is_pending());
    let first: Vec<Bytes> = common::take_sent()
        .into_iter()
        .map(|(_, datagram)| datagram)
        .collect();
    assert!(!first.is_empty(), "the client sends its first flight");
    let first_sent = first.clone();
    // the server's connection is made once its first datagrams arrive: the
    // first flight, or, when the link loses it, what the client sends
    // later
    let (server_routing, server_receiver) = Routing::new(&[cid(&CLIENT_DCID), cid(&SERVER_CID)]);
    let server_args = args::<ServerChoices>(
        HandshakeStart::new(server_engine(clock), MessageLimits::default()),
        v1::new_token::ServerOnlyStart::new(common::TestNewTokenIssuer),
        AddressValidation::NotValidated,
        server_capacities(),
        FirstFlight::Datagrams(Vec::new()),
        server_receiver,
        &server_routing,
        first_local(&SERVER_CID, 0x5e),
    );
    // the server's handle is there before its connection, as the
    // application's would be: it answers once the connection is made
    let server_shared = Rc::new(RefCell::new(Later(None)));
    let server_handle = ConnectionHandle::new(server_shared.clone());
    let mut server_args = Some(server_args);
    let mut server = None;
    // the datagrams that arrive before the server's connection is made
    let mut waiting: Vec<Bytes> = Vec::new();
    let lose = |datagram: Bytes, waiting: &mut Vec<Bytes>| {
        let lost = CLIENT_DATAGRAMS_LOST.with(|lost| {
            let loses = lost.get() > 0;
            lost.set(lost.get().saturating_sub(1));
            loses
        });
        if !lost {
            waiting.push(datagram);
        }
    };
    for datagram in first {
        lose(datagram, &mut waiting);
    }
    let mut run = Run {
        client_sent: first_sent,
        server_ended: false,
        client_ended: false,
        client_panicked: false,
        driver_wakes: 0,
        client_handle,
        server_handle,
        client_link: client_link.clone(),
    };
    for millis in 0..3000 {
        advance_to(ms(millis));
        loop {
            let mut moved = false;
            if server.is_none() && !waiting.is_empty() {
                let mut args = server_args.take().expect("made once");
                let datagrams = waiting
                    .drain(..)
                    .map(|datagram| arrived(datagram, &server_link));
                args.first_flight = if SERVER_READS_FIRST.with(Cell::get) {
                    let mut state = v1::first_flight::FirstFlightReadState::<ServerChoices>::new(
                        &RingBackend,
                        &cid(&CLIENT_DCID),
                        &server_capacities(),
                        MaxAckRanges::DEFAULT,
                        16,
                    );
                    // the first flight holds the whole ClientHello: the
                    // reading takes nothing from its receiver
                    let (_, mut receiver) = Routing::new(&[cid(&CLIENT_DCID)]);
                    let read = poll_now(v1::first_flight::read_first_flight::<
                        ServerChoices,
                        Parts,
                        _,
                        _,
                        _,
                        _,
                        _,
                    >(
                        &mut state,
                        datagrams,
                        &mut receiver,
                        MessageLimits::default(),
                    ));
                    assert!(matches!(read, Poll::Ready(Ok(()))), "the first flight was read");
                    FirstFlight::Read(state)
                } else {
                    FirstFlight::Datagrams(datagrams.collect())
                };
                server_shared.borrow_mut().0 = Some(server_connection(args, server_link.clone()));
                server = Some(SharedConnectionDriver::new(server_shared.clone()));
            }
            if !run.server_ended
                && let Some(server) = &mut server
            {
                run.server_ended = outer.poll(server).is_ready();
            }
            for (_, datagram) in common::take_sent() {
                moved = true;
                client_routing.deliver(datagram, &client_link);
            }
            if !run.client_ended
                && !run.client_panicked
                && let Some(driver) = &mut client
            {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| outer.poll(driver))) {
                    Ok(polled) => run.client_ended = polled.is_ready(),
                    Err(_) => {
                        // the host caught the panic; it drops the driver
                        run.client_panicked = true;
                        client = None;
                    }
                }
            }
            for (_, datagram) in common::take_sent() {
                moved = true;
                run.client_sent.push(datagram.clone());
                if server.is_some() {
                    server_routing.deliver(datagram, &server_link);
                } else {
                    lose(datagram, &mut waiting);
                }
            }
            if !moved {
                break;
            }
        }
        run.driver_wakes = outer.wakes();
        if done(&run) {
            break;
        }
    }
    run
}

    };
}

harness!(server: [HNil], client: [HNil]);

fn tls_clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(tls_now()))
}

// ---- the tests ----

#[test]
fn a_client_and_a_server_complete_and_confirm_the_handshake() {
    let clock = tls_clock();
    let complete = |noted: &Noted| {
        noted.confirmed
            && noted.initial_keys == "Discarded"
            && noted.handshake_keys == "Discarded"
            && noted.spaces == [PacketNumberSpaceKind::ApplicationData]
    };
    let run = handshake(client_engine(&clock, 1), &clock, |_| {
        complete(&noted(Role::Server))
            && complete(&noted(Role::Client))
            && noted(Role::Server).own == "Delivered"
    });
    let (server, client) = (noted(Role::Server), noted(Role::Client));
    // each side's events: the connection starts first, packets of every
    // level arrive whole, the recovery state is reported, nothing is lost,
    // and only packets of a level whose keys are gone are dropped
    for role in [Role::Server, Role::Client] {
        let events = common::events::recorded(role);
        assert_eq!(events.first(), Some(&Recorded::Started), "{role:?}");
        for level in [
            EncryptionLevel::Initial,
            EncryptionLevel::Handshake,
            EncryptionLevel::OneRtt,
        ] {
            assert!(
                events.iter().any(|event| matches!(
                    event,
                    Recorded::Received { level: received, whole: true, .. } if *received == level
                )),
                "{role:?} received a packet of {level:?}: {events:#?}"
            );
        }
        assert!(
            events
                .iter()
                .any(|event| matches!(event, Recorded::Metrics { .. })),
            "{role:?}"
        );
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Recorded::Lost { .. })
                    || matches!(event, Recorded::Dropped { reason, .. } if reason != "NoReceiveKeys")),
            "{role:?}: {events:#?}"
        );
        let count = |wanted: &Recorded| events.iter().filter(|event| *event == wanted).count();
        // this side's parameters and the peer's, once each
        assert_eq!(
            count(&Recorded::Parameters(EventInitiator::Local)),
            1,
            "{role:?}"
        );
        assert_eq!(
            count(&Recorded::Parameters(EventInitiator::Remote)),
            1,
            "{role:?}"
        );
        assert_eq!(count(&Recorded::Version(Version::V1)), 1, "{role:?}");
        assert_eq!(
            count(&Recorded::State(ConnectionState::HandshakeComplete)),
            1,
            "{role:?}"
        );
        assert_eq!(
            count(&Recorded::State(ConnectionState::HandshakeConfirmed)),
            1,
            "{role:?}"
        );
        for level in [EncryptionLevel::Initial, EncryptionLevel::Handshake] {
            for sender in [Role::Client, Role::Server] {
                let key = KeyChange {
                    level,
                    sender,
                    key_phase: None,
                    trigger: None,
                };
                assert_eq!(count(&Recorded::KeyUpdated(key)), 1, "{role:?} {key:?}");
                assert_eq!(count(&Recorded::KeyDiscarded(key)), 1, "{role:?} {key:?}");
            }
        }
        for sender in [Role::Client, Role::Server] {
            let key = KeyChange {
                level: EncryptionLevel::OneRtt,
                sender,
                key_phase: None,
                trigger: None,
            };
            assert_eq!(count(&Recorded::KeyUpdated(key)), 1, "{role:?} {key:?}");
        }
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, Recorded::Alpn(_)))
                .count(),
            1,
            "{role:?}"
        );
    }
    // every packet a side sealed is the one the other side opened: the
    // same level and packet number, both whole
    let sent_and_received = |sender: Role, receiver: Role| {
        let sent: Vec<_> = common::events::recorded(sender)
            .into_iter()
            .filter_map(|event| match event {
                Recorded::Sent {
                    level,
                    number,
                    whole,
                } => Some((level, number, whole)),
                _ => None,
            })
            .collect();
        let received: Vec<_> = common::events::recorded(receiver)
            .into_iter()
            .filter_map(|event| match event {
                Recorded::Received {
                    level,
                    number,
                    whole,
                } => Some((level, number, whole)),
                _ => None,
            })
            .collect();
        (sent, received)
    };
    for (sender, receiver) in [(Role::Client, Role::Server), (Role::Server, Role::Client)] {
        let (sent, received) = sent_and_received(sender, receiver);
        assert!(!sent.is_empty() && sent.iter().all(|(_, _, whole)| *whole));
        for packet in &received {
            assert!(
                sent.contains(packet),
                "{receiver:?} opened {packet:?}, which {sender:?} sealed"
            );
        }
    }
    // both connections were open when the run dropped them: each records
    // its close last, an abort of this side
    for role in [Role::Server, Role::Client] {
        let events = common::events::recorded(role);
        assert_eq!(
            events[events.len() - 2..],
            [
                Recorded::Closed {
                    initiator: EventInitiator::Local,
                    trigger: CloseTrigger::Aborted,
                },
                Recorded::State(ConnectionState::Closed),
            ],
            "{role:?}"
        );
    }
    for (side, noted) in [("server", &server), ("client", &client)] {
        assert!(noted.confirmed, "the {side}'s handshake is confirmed");
        assert_eq!(noted.initial_keys, "Discarded", "the {side}'s Initial keys");
        assert_eq!(
            noted.handshake_keys, "Discarded",
            "the {side}'s Handshake keys"
        );
        assert_eq!(
            noted.spaces,
            [PacketNumberSpaceKind::ApplicationData],
            "the {side} retired its Initial and Handshake spaces"
        );
        assert_eq!(noted.record, None, "the {side}'s connection is not closing");
        assert_eq!(noted.exporter, "Held(..)", "the {side} keeps its exporter");
        assert!(
            noted.streams,
            "the {side}'s established layer holds the stream set"
        );
    }
    // the connection handles give the handshake's results and the layers
    let client_facts =
        ready(run.client_handle.handshake_completed()).expect("the client's handshake completed");
    let server_facts =
        ready(run.server_handle.handshake_completed()).expect("the server's handshake completed");
    assert_eq!(
        client_facts.application_protocol, server_facts.selected.application_protocol,
        "both sides name the protocol selected"
    );
    assert!(!server_facts.resumed);
    assert!(
        ready(run.client_handle.early()).expect("settled").is_none(),
        "a client without 0-RTT has no early layer"
    );
    let server_early = ready(run.server_handle.early())
        .expect("settled")
        .expect("a server's layer comes before its handshake completes");
    let server_layer = ready(run.server_handle.established()).expect("established");
    assert_eq!(server_layer.selected(), &server_facts.selected);
    assert_eq!(
        server_early.application_protocol(),
        server_layer.application_protocol()
    );
    let client_layer = ready(run.client_handle.established()).expect("established");
    assert_eq!(
        client_layer.application_protocol(),
        client_facts.application_protocol.as_ref()
    );
    // the drivers were dropped when the run returned: the connections
    // ended without a close, the exporter is let go, and the layers ended
    // with the same reason; the handshakes still completed
    assert!(matches!(
        ready(run.client_handle.closed()),
        CloseReason::Aborted(AbortCause::DriverDropped)
    ));
    assert!(matches!(
        ready(run.server_handle.closed()),
        CloseReason::Aborted(AbortCause::DriverDropped)
    ));
    assert!(
        ready(run.client_handle.exporter())
            .expect("completed")
            .is_none(),
        "the exporter is let go once the connection closed"
    );
    assert!(matches!(
        ready(server_layer.ended()),
        LayerEnd::ConnectionClosed(CloseReason::Aborted(AbortCause::DriverDropped))
    ));
    assert!(matches!(
        client_layer.try_open_bi(),
        Err(TryOpenStreamError::LayerEnded { .. })
    ));
    assert!(matches!(
        ready(server_early.accept_uni()),
        Err(error) if matches!(error.end(), LayerEnd::ConnectionClosed(_))
    ));
    // the server sent HANDSHAKE_DONE, and the client acknowledged it
    assert_eq!(server.own, "Delivered");
    assert!(!run.server_ended && !run.client_ended);
    let initials: Vec<_> = run
        .client_sent
        .iter()
        .filter(|datagram| starts_with_initial(datagram))
        .collect();
    assert!(!initials.is_empty(), "the client sent Initial packets");
    for datagram in initials {
        assert!(
            datagram.len() >= MIN_DATAGRAM_SIZE,
            "a client's Initial datagram of {} bytes",
            datagram.len()
        );
    }
}

#[test]
fn a_client_whose_first_initial_datagram_is_lost_sends_its_hello_again_and_the_handshake_completes()
{
    let clock = tls_clock();
    // the link loses the client's first datagram; the server's connection
    // is made when the first one that arrives does, after the client's
    // probe timeout expired and handed the ClientHello, still in flight,
    // back to be sent again
    CLIENT_DATAGRAMS_LOST.with(|lost| lost.set(1));
    let run = handshake(client_engine(&clock, 1), &clock, |_| {
        noted(Role::Server).confirmed && noted(Role::Client).confirmed
    });
    CLIENT_DATAGRAMS_LOST.with(|lost| lost.set(0));
    // the client's events: the first Initial packet, never acknowledged
    // while later ones are, was declared lost on an acknowledgment
    let events = common::events::recorded(Role::Client);
    assert!(
        events.iter().any(|event| matches!(
            event,
            Recorded::Lost {
                space: PacketNumberSpaceKind::Initial,
                number: 0,
                ..
            }
        )),
        "{events:#?}"
    );
    // nothing could happen before the probe timeout, which expires at
    // 999 ms with the initial round trip time
    assert!(now() >= ms(999), "confirmed at {:?}", now());
    let (server, client) = (noted(Role::Server), noted(Role::Client));
    assert!(client.confirmed, "the client's handshake is confirmed");
    assert!(server.confirmed, "the server's handshake is confirmed");
    ready(run.client_handle.handshake_completed()).expect("the client's handshake completed");
    ready(run.server_handle.handshake_completed()).expect("the server's handshake completed");
    // the first datagram was lost, and the ClientHello went again in the
    // probe datagrams after it
    let initials: Vec<_> = run
        .client_sent
        .iter()
        .filter(|datagram| starts_with_initial(datagram))
        .collect();
    assert!(initials.len() >= 2, "{} Initial datagrams", initials.len());
    for datagram in initials {
        assert!(datagram.len() >= MIN_DATAGRAM_SIZE);
    }
    assert!(!run.server_ended && !run.client_ended);
}

#[test]
fn both_probe_datagrams_of_a_client_carry_its_hello_and_the_second_completes_the_handshake() {
    let clock = tls_clock();
    // the link loses the first flight and the first probe datagram: only
    // the second probe datagram of the first probe timeout arrives
    CLIENT_DATAGRAMS_LOST.with(|lost| lost.set(2));
    let run = handshake(client_engine(&clock, 1), &clock, |_| {
        noted(Role::Server).confirmed && noted(Role::Client).confirmed
    });
    CLIENT_DATAGRAMS_LOST.with(|lost| lost.set(0));
    assert!(noted(Role::Client).confirmed && noted(Role::Server).confirmed);
    // the first probe timeout expires at 999 ms; the second would be
    // 1998 ms later: the ClientHello arrived with the first one's probes
    assert!(
        now() >= ms(999) && now() < ms(2997),
        "confirmed at {:?}",
        now()
    );
    // the first flight, then the two probe datagrams: each leads its
    // Initial packet with the ClientHello's CRYPTO frame, from offset 0
    let payloads: Vec<_> = run.client_sent[..3]
        .iter()
        .map(|datagram| client_initial_payload(datagram))
        .collect();
    for (at, payload) in payloads.iter().enumerate() {
        assert_eq!(payload[..2], [0x06, 0x00], "datagram {at}: {payload:?}");
    }
    assert_eq!(
        payloads[1], payloads[2],
        "both probes carry the same CRYPTO frame and PING"
    );
    assert!(!run.server_ended && !run.client_ended);
}

#[test]
fn a_client_that_fails_to_verify_the_server_closes_with_the_alert() {
    let clock = tls_clock();
    // the client trusts another root than the server's certificate's
    let run = handshake(client_engine(&clock, 3), &clock, |_| {
        noted(Role::Server).peer_close.is_some()
    });
    let client = noted(Role::Client);
    let alert = client
        .alert
        .expect("the client's handshake failed with an alert");
    assert!(
        client
            .record
            .as_deref()
            .is_some_and(|record| record.starts_with("Local(Handshake(Alert")),
        "{:?}",
        client.record
    );
    let Some(ImmediateClose::Transport(close)) = noted(Role::Server).peer_close else {
        panic!(
            "the server received a transport close: {:?}",
            noted(Role::Server)
        );
    };
    assert_eq!(close.code, TransportErrorCode::crypto_error(alert));
    assert_eq!(
        close.code.get().get(),
        0x0100 + u64::from(alert),
        "CRYPTO_ERROR with the alert"
    );
    // a Frame Type of 0
    assert_eq!(close.frame_type, None);
    assert_eq!(
        client.exporter, "Released",
        "a closed connection keeps no exporter"
    );
    assert!(!run.server_ended, "the server closes in its own time");
    // the client, closing, keeps only the receiving halves of its keys,
    // and still records the packets that come; the server drains and
    // discards every half it had, the 1-RTT keys only sending
    let client_events = common::events::recorded(Role::Client);
    let discarded = |events: &[Recorded]| {
        events
            .iter()
            .filter_map(|event| match event {
                Recorded::KeyDiscarded(key) => Some((key.level, key.sender)),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        discarded(&client_events),
        [
            (EncryptionLevel::Initial, Role::Client),
            (EncryptionLevel::Handshake, Role::Client),
        ]
    );
    let closed_at = client_events
        .iter()
        .position(|event| matches!(event, Recorded::Closed { .. }))
        .expect("the client closed");
    assert!(
        client_events[closed_at..]
            .iter()
            .any(|event| matches!(event, Recorded::Received { whole: true, .. })),
        "{client_events:#?}"
    );
    assert_eq!(
        discarded(&common::events::recorded(Role::Server)),
        [
            (EncryptionLevel::Initial, Role::Server),
            (EncryptionLevel::Initial, Role::Client),
            (EncryptionLevel::Handshake, Role::Server),
            (EncryptionLevel::Handshake, Role::Client),
            (EncryptionLevel::OneRtt, Role::Server),
        ]
    );
    // each side's events say who closed and why, once
    let closed = |role| {
        common::events::recorded(role)
            .into_iter()
            .filter(|event| matches!(event, Recorded::Closed { .. }))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        closed(Role::Client),
        [Recorded::Closed {
            initiator: EventInitiator::Local,
            trigger: CloseTrigger::Error,
        }]
    );
    assert_eq!(
        closed(Role::Server),
        [Recorded::Closed {
            initiator: EventInitiator::Remote,
            trigger: CloseTrigger::PeerClose,
        }]
    );
}

#[test]
fn a_client_that_only_closes_discards_its_receiving_halves_when_its_closing_period_ends() {
    let clock = tls_clock();
    // the client trusts another root than the server's certificate's: it
    // closes, and the server drains without answering
    let run = handshake(client_engine(&clock, 3), &clock, |run| run.client_ended);
    assert!(run.client_ended, "the client's closing period ended");
    let discarded: Vec<_> = common::events::recorded(Role::Client)
        .iter()
        .filter_map(|event| match event {
            Recorded::KeyDiscarded(key) => Some((key.level, key.sender)),
            _ => None,
        })
        .collect();
    // the sending halves as it closed, the receiving halves as it ended
    assert_eq!(
        discarded,
        [
            (EncryptionLevel::Initial, Role::Client),
            (EncryptionLevel::Handshake, Role::Client),
            (EncryptionLevel::Initial, Role::Server),
            (EncryptionLevel::Handshake, Role::Server),
        ]
    );
}

#[test]
fn a_connection_dropped_before_its_first_poll_records_nothing() {
    let clock = tls_clock();
    common::events::reset();
    common::reset_links();
    advance_to(ms(0));
    let (routing, receiver) = Routing::new(&[cid(&CLIENT_CID)]);
    let args = args::<ClientChoices>(
        HandshakeStart::new(client_engine(&clock, 1), MessageLimits::default()),
        ClientOnlyStart::new(Bytes::new(), common::TestTokenSink, ContinueOnRetry, ()),
        AddressValidation::Validated,
        client_capacities(),
        FirstFlight::Datagrams(Vec::new()),
        receiver,
        &routing,
        first_local(&CLIENT_CID, 0xc1),
    );
    let connection = connection!(ClientChoices, args, link(), [][HNil]);
    drop(connection);
    // the connection never started: no close without a start
    assert_eq!(common::events::recorded(Role::Client), []);
}

#[test]
fn a_server_that_read_its_first_flight_first_records_the_packets_it_read() {
    let clock = tls_clock();
    SERVER_READS_FIRST.with(|reads| reads.set(true));
    let _run = handshake(client_engine(&clock, 1), &clock, |_| {
        noted(Role::Server).confirmed && noted(Role::Client).confirmed
    });
    let events = common::events::recorded(Role::Server);
    assert_eq!(events.first(), Some(&Recorded::Started));
    // the client's first Initial packet, read before the connection was
    // made, once, and every packet opened is one the client sealed
    let received: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            Recorded::Received {
                level,
                number,
                whole,
            } => Some((*level, *number, *whole)),
            _ => None,
        })
        .collect();
    assert_eq!(
        received
            .iter()
            .filter(|packet| **packet == (EncryptionLevel::Initial, 0, true))
            .count(),
        1,
        "{events:#?}"
    );
    let sent: Vec<_> = common::events::recorded(Role::Client)
        .into_iter()
        .filter_map(|event| match event {
            Recorded::Sent {
                level,
                number,
                whole,
            } => Some((level, number, whole)),
            _ => None,
        })
        .collect();
    for packet in &received {
        assert!(sent.contains(packet), "the server opened {packet:?}");
    }
}

#[test]
fn an_application_close_is_an_event_on_both_sides() {
    let clock = tls_clock();
    let mut asked = false;
    let _run = handshake(client_engine(&clock, 1), &clock, |run| {
        if !asked && noted(Role::Client).confirmed {
            asked = true;
            run.client_handle.close(common::AppClose(7));
        }
        noted(Role::Server).peer_close.is_some()
    });
    // the client, closing, drops the sending half of its 1-RTT keys; the
    // server, draining, both
    let one_rtt_discarded = |role| {
        common::events::recorded(role)
            .into_iter()
            .filter_map(|event| match event {
                Recorded::KeyDiscarded(key) if key.level == EncryptionLevel::OneRtt => {
                    Some(key.sender)
                }
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(one_rtt_discarded(Role::Client), [Role::Client]);
    assert_eq!(
        one_rtt_discarded(Role::Server),
        [Role::Server, Role::Client]
    );
    let closed = |role| {
        common::events::recorded(role)
            .into_iter()
            .filter(|event| matches!(event, Recorded::Closed { .. }))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        closed(Role::Client),
        [Recorded::Closed {
            initiator: EventInitiator::Local,
            trigger: CloseTrigger::Application,
        }]
    );
    assert_eq!(
        closed(Role::Server),
        [Recorded::Closed {
            initiator: EventInitiator::Remote,
            trigger: CloseTrigger::PeerClose,
        }]
    );
}

/// The output of `future` if it is ready on its first poll.
fn poll_now<F: Future>(future: F) -> Poll<F::Output> {
    pin!(future).poll(&mut Context::from_waker(Waker::noop()))
}

/// Read what the stream reader `$reader` has now into the `Vec<u8>`
/// `$into`; whether it read the stream's end.
macro_rules! read_now {
    ($reader:expr, $into:expr) => {{
        let maximum = NonZeroUsize::new(64).expect("not zero");
        loop {
            match poll_now($reader.read_chunk_unpin(maximum)) {
                Poll::Ready(Ok(Some(chunk))) => $into.extend_from_slice(&chunk),
                Poll::Ready(Ok(None)) => break true,
                Poll::Ready(Err(error)) => panic!("the stream is read: {error:?}"),
                Poll::Pending => break false,
            }
        }
    }};
}

/// A measurement, not a check, of the harness `handshake` of where it
/// expands: once both sides are established, the client and the server
/// exchange `MEASURE_EXCHANGES` requests and answers (by default none), one
/// bidirectional stream each, one after the other, through the shared
/// connection. It prints how many times the drivers were woken and how
/// many heap operations the test's thread made during the exchanges; a
/// profiler run with the count and without it gives what else the
/// exchanges cost.
macro_rules! exchange_measurement {
    ($name:ident) => {
        #[test]
        #[ignore = "a measurement, run by hand"]
        fn $name() {
            let exchanges: usize = std::env::var("MEASURE_EXCHANGES")
                .ok()
                .and_then(|count| count.parse().ok())
                .unwrap_or(0);
            let clock = tls_clock();
            let mut client_layer = None;
            let mut server_layer = None;
            let mut client_stream = None;
            let mut server_stream = None;
            let (mut request, mut answer) = (Vec::new(), Vec::new());
            let mut answered = false;
            let mut finished = 0;
            let mut before = None;
            let mut wakes = 0;
            let mut allocations = sakuya_test_support::measure::AllocationCounts::default();
            handshake(client_engine(&clock, 1), &clock, |run| {
                if client_layer.is_none()
                    && let Poll::Ready(Ok(layer)) = poll_now(run.client_handle.established())
                {
                    client_layer = Some(layer);
                }
                if server_layer.is_none()
                    && let Poll::Ready(layer) = poll_now(run.server_handle.established())
                {
                    server_layer = Some(layer.expect("the server's handshake completed"));
                }
                let (Some(client), Some(server)) = (&client_layer, &server_layer) else {
                    return false;
                };
                let (wakes_before, allocations_before) = *before.get_or_insert((
                    run.driver_wakes,
                    sakuya_test_support::measure::allocation_counts(),
                ));
                wakes = run.driver_wakes - wakes_before;
                allocations =
                    sakuya_test_support::measure::allocation_counts().since(allocations_before);
                if finished == exchanges {
                    return true;
                }
                if client_stream.is_none() {
                    let (mut writer, reader) =
                        client.try_open_bi().expect("the server grants streams");
                    ready(writer.write_all_unpin(Bytes::from_static(b"ping"))).expect("written");
                    writer.close().expect("the request ends");
                    client_stream = Some((writer, reader));
                }
                if server_stream.is_none()
                    && let Poll::Ready(stream) = poll_now(server.accept_bi())
                {
                    server_stream = Some(stream.expect("the client's stream is accepted"));
                }
                if let Some((writer, reader)) = &mut server_stream
                    && !answered
                    && read_now!(reader, request)
                {
                    ready(writer.write_all_unpin(Bytes::from_static(b"pong"))).expect("written");
                    writer.close().expect("the answer ends");
                    answered = true;
                }
                if let Some((_, reader)) = &mut client_stream
                    && answered
                    && read_now!(reader, answer)
                {
                    assert_eq!((&request[..], &answer[..]), (&b"ping"[..], &b"pong"[..]));
                    request.clear();
                    answer.clear();
                    answered = false;
                    client_stream = None;
                    server_stream = None;
                    finished += 1;
                }
                false
            });
            assert_eq!(finished, exchanges, "the exchanges finished within 3 s");
            println!(
                "exchanges={exchanges} driver_wakes={wakes} allocations={} reallocations={} \
                 deallocations={} bytes={}",
                allocations.allocations,
                allocations.reallocations,
                allocations.deallocations,
                allocations.bytes,
            );
        }
    };
}

/// Node 1: over the tests' in-memory link, a client and a server complete
/// the handshake, the client opens a bidirectional stream and sends a
/// request with its end, and the server reads it and answers on the same
/// stream.
/// The Token field of the Initial packet `datagram` starts with.
fn initial_token(datagram: &[u8]) -> &[u8] {
    let mut at = 5;
    at += 1 + usize::from(datagram[at]);
    at += 1 + usize::from(datagram[at]);
    let (len, width) = match datagram[at] >> 6 {
        0 => (usize::from(datagram[at]), 1),
        1 => (
            usize::from(u16::from_be_bytes([datagram[at] & 0x3f, datagram[at + 1]])),
            2,
        ),
        _ => unreachable!("the tests' tokens are shorter than 16384 bytes"),
    };
    &datagram[at + width..at + width + len]
}

/// The payload of the first packet of `datagram`, an Initial packet of
/// the client, opened with the keys of its Initial secret (RFC 9001 §5.2).
fn client_initial_payload(datagram: &[u8]) -> Vec<u8> {
    assert!(starts_with_initial(datagram), "an Initial packet");
    let token = initial_token(datagram);
    // the token's length takes one byte for the tests' tokens here
    let at = 5 + 1 + 8 + 1 + 8 + 1 + token.len();
    assert!(token.len() < 64);
    let length = usize::from(u16::from_be_bytes([datagram[at] & 0x3f, datagram[at + 1]]));
    assert_eq!(datagram[at] >> 6, 1, "a two-byte Length field");
    let pn_offset = at + 2;
    let mut packet = datagram[..pn_offset + length].to_vec();
    let secrets = InitialSecrets::derive(&RingBackend, &cid(&CLIENT_DCID));
    let keys = DirectionKeys::derive(&RingBackend, INITIAL_AEAD, &secrets.client);
    let truncated = keys.header.remove(&mut packet, pn_offset).expect("sampled");
    let header_len = pn_offset + truncated.encoded_len().get();
    let number = truncated.decode(None);
    keys.packet
        .open(number, &mut packet, header_len)
        .expect("opened")
        .to_vec()
}

#[test]
fn every_initial_packet_of_a_client_carries_the_token_it_started_with() {
    let clock = tls_clock();
    let token = Bytes::from(vec![0x70; 100]);
    CLIENT_TOKEN.with(|cell| *cell.borrow_mut() = token.clone());
    let run = handshake(client_engine(&clock, 1), &clock, |_| {
        noted(Role::Client).confirmed
    });
    ready(run.client_handle.handshake_completed()).expect("the client's handshake completed");
    let initials: Vec<_> = run
        .client_sent
        .iter()
        .filter(|datagram| starts_with_initial(datagram))
        .collect();
    assert!(
        initials.len() >= 2,
        "the client sent its ClientHello and an acknowledgment"
    );
    for datagram in initials {
        assert_eq!(initial_token(datagram), &token[..]);
        assert!(datagram.len() >= MIN_DATAGRAM_SIZE);
    }
}

#[test]
fn once_confirmed_each_side_issues_connection_ids_up_to_the_peer_s_limit_and_the_peer_takes_them() {
    let clock = tls_clock();
    let issued = |noted: &Noted| {
        noted.confirmed && noted.local_connection_ids == 4 && noted.offered_connection_ids == 4
    };
    handshake(client_engine(&clock, 1), &clock, |_| {
        issued(&noted(Role::Server)) && issued(&noted(Role::Client))
    });
    for (side, role) in [("server", Role::Server), ("client", Role::Client)] {
        let noted = noted(role);
        assert!(noted.confirmed, "the {side}'s handshake is confirmed");
        assert_eq!(
            noted.local_connection_ids, 4,
            "the {side} keeps its handshake connection ID and three more issued"
        );
        assert_eq!(
            noted.offered_connection_ids, 4,
            "the {side} took the peer's NEW_CONNECTION_ID frames"
        );
    }
}

#[test]
fn once_confirmed_a_server_gives_one_token_and_its_client_keeps_it() {
    let clock = tls_clock();
    handshake(client_engine(&clock, 1), &clock, |_| {
        noted(Role::Server).confirmed && !common::tokens_kept().is_empty()
    });
    let issued = common::new_tokens_issued();
    assert_eq!(
        issued,
        [Bytes::from_static(b"token-1")],
        "one token, once confirmed"
    );
    assert_eq!(
        common::tokens_kept(),
        issued,
        "the client keeps what the server gave"
    );
}

#[test]
fn a_server_whose_issuer_gives_no_token_sends_none() {
    let clock = tls_clock();
    common::set_new_token_issuing(false);
    handshake(client_engine(&clock, 1), &clock, |_| {
        noted(Role::Server).confirmed && noted(Role::Client).confirmed
    });
    common::set_new_token_issuing(true);
    assert_eq!(common::new_tokens_issued(), Vec::<Bytes>::new());
    assert_eq!(common::tokens_kept(), Vec::<Bytes>::new());
}

exchange_measurement!(measure_exchanges_on_the_default_stream_set);

#[test]
fn a_client_and_a_server_exchange_a_request_and_its_answer_on_a_stream() {
    let clock = tls_clock();
    let mut client_stream = None;
    let mut server_layer = None;
    let mut server_stream = None;
    let (mut request, mut answer) = (Vec::new(), Vec::new());
    let mut answered = false;
    let mut done = false;
    handshake(client_engine(&clock, 1), &clock, |run| {
        if client_stream.is_none()
            && let Poll::Ready(layer) = poll_now(run.client_handle.established())
        {
            let layer = layer.expect("the client's handshake completed");
            let (mut writer, reader) = layer.try_open_bi().expect("the server grants streams");
            ready(writer.write_all_unpin(Bytes::from_static(b"ping")))
                .expect("the request is written");
            writer.close().expect("the request ends");
            client_stream = Some((writer, reader));
        }
        if server_layer.is_none()
            && let Poll::Ready(layer) = poll_now(run.server_handle.established())
        {
            server_layer = Some(layer.expect("the server's handshake completed"));
        }
        if server_stream.is_none()
            && let Some(layer) = &server_layer
            && let Poll::Ready(stream) = poll_now(layer.accept_bi())
        {
            server_stream = Some(stream.expect("the client's stream is accepted"));
        }
        if let Some((writer, reader)) = &mut server_stream
            && !answered
            && read_now!(reader, request)
        {
            assert_eq!(request, b"ping");
            ready(writer.write_all_unpin(Bytes::from_static(b"pong")))
                .expect("the answer is written");
            writer.close().expect("the answer ends");
            answered = true;
        }
        if let Some((_, reader)) = &mut client_stream
            && !done
        {
            done = read_now!(reader, answer);
        }
        done
    });
    assert!(done, "the client read the answer's end within 3 s");
    assert_eq!(request, b"ping");
    assert_eq!(answer, b"pong");
}

/// What reading `reader` gives now, its data going into `into`: `Ok(true)`
/// at the end, `Ok(false)` once it waits, or the error.
macro_rules! read_what_comes {
    ($reader:expr, $into:expr) => {{
        let maximum = NonZeroUsize::new(64).expect("not zero");
        loop {
            match poll_now($reader.read_chunk_unpin(maximum)) {
                Poll::Ready(Ok(Some(chunk))) => $into.extend_from_slice(&chunk),
                Poll::Ready(Ok(None)) => break Ok(true),
                Poll::Ready(Err(error)) => break Err(error),
                Poll::Pending => break Ok(false),
            }
        }
    }};
}

/// The client's writer turns into one with a shared credential and is
/// cloned: dropping one of the two writers does not give the stream up,
/// and the server goes on waiting for more; dropping the last one does, and
/// the stream's termination policy resets it, which the server reads.
#[test]
fn a_stream_is_given_up_once_the_last_of_its_shared_writers_is_dropped() {
    let clock = tls_clock();
    let mut writers: Option<(Option<_>, Option<_>)> = None;
    let mut client_reader = None;
    let mut server_layer = None;
    let mut server_stream = None;
    let mut read = Vec::new();
    let mut step = 0;
    let mut waited = 0;
    let mut reset = false;
    handshake(client_engine(&clock, 1), &clock, |run| {
        if writers.is_none()
            && let Poll::Ready(Ok(layer)) = poll_now(run.client_handle.established())
        {
            let (mut writer, reader) = layer.try_open_bi().expect("a stream");
            client_reader = Some(reader);
            ready(writer.write_all_unpin(Bytes::from_static(b"ab"))).expect("written");
            let writer = writer.into_shared::<Arc<HandleCredential>>();
            let second = writer.clone();
            writers = Some((Some(writer), Some(second)));
        }
        if server_layer.is_none()
            && let Poll::Ready(layer) = poll_now(run.server_handle.established())
        {
            server_layer = Some(layer.expect("the server's handshake completed"));
        }
        if server_stream.is_none()
            && let Some(layer) = &server_layer
            && let Poll::Ready(stream) = poll_now(layer.accept_bi())
        {
            server_stream = Some(stream.expect("the client's stream is accepted"));
        }
        let Some((_, reader)) = &mut server_stream else {
            return false;
        };
        let read_now = read_what_comes!(reader, read);
        let (first, second) = writers.as_mut().expect("opened before accepted");
        match step {
            0 if read == b"ab" => {
                drop(first.take());
                step = 1;
            }
            1 => {
                assert!(
                    matches!(read_now, Ok(false)),
                    "one writer is left: {read_now:?}"
                );
                waited += 1;
                if waited == 100 {
                    drop(second.take());
                    step = 2;
                }
            }
            2 => {
                if let Err(error) = read_now {
                    assert!(matches!(error, ReadError::Reset { .. }), "{error:?}");
                    reset = true;
                }
            }
            _ => {}
        }
        reset
    });
    assert!(reset, "the server read the reset within 3 s");
    assert_eq!(read, b"ab");
    drop(client_reader);
}

/// The server's reader turns into one with a shared credential, behind an
/// `Rc`, and is cloned: the client goes on writing while one of the two
/// readers is left, and both read the same stream; once the last one is
/// dropped, the server asks the client to stop, and the client's writes
/// fail.
#[test]
fn reading_is_given_up_once_the_last_of_the_shared_readers_is_dropped() {
    let clock = tls_clock();
    let mut client_writer = None;
    let mut client_reader = None;
    let mut server_layer = None;
    let mut server_writer = None;
    let mut readers: Option<(Option<_>, Option<_>)> = None;
    let mut read = Vec::new();
    let mut step = 0;
    let mut stopped = false;
    handshake(client_engine(&clock, 1), &clock, |run| {
        if client_writer.is_none()
            && let Poll::Ready(Ok(layer)) = poll_now(run.client_handle.established())
        {
            let (mut writer, reader) = layer.try_open_bi().expect("a stream");
            ready(writer.write_all_unpin(Bytes::from_static(b"a"))).expect("written");
            client_writer = Some(writer);
            client_reader = Some(reader);
        }
        if server_layer.is_none()
            && let Poll::Ready(layer) = poll_now(run.server_handle.established())
        {
            server_layer = Some(layer.expect("the server's handshake completed"));
        }
        if readers.is_none()
            && let Some(layer) = &server_layer
            && let Poll::Ready(stream) = poll_now(layer.accept_bi())
        {
            let (writer, reader) = stream.expect("the client's stream is accepted");
            server_writer = Some(writer);
            let reader = reader.into_shared::<Rc<HandleCredential>>();
            let second = reader.clone();
            readers = Some((Some(reader), Some(second)));
        }
        let (Some(writer), Some((first, second))) = (&mut client_writer, &mut readers) else {
            return false;
        };
        match step {
            0 => {
                let reader = first.as_mut().expect("kept");
                read_what_comes!(reader, read).expect("the stream goes on");
                if read == b"a" {
                    drop(first.take());
                    ready(writer.write_all_unpin(Bytes::from_static(b"b")))
                        .expect("one reader is left");
                    step = 1;
                }
            }
            1 => {
                let reader = second.as_mut().expect("kept");
                read_what_comes!(reader, read).expect("the stream goes on");
                if read == b"ab" {
                    drop(second.take());
                    step = 2;
                }
            }
            2 => {
                if let Poll::Ready(Err(error)) =
                    poll_now(writer.write_all_unpin(Bytes::from_static(b"c")))
                {
                    assert!(
                        !matches!(
                            error,
                            nitori_io::calls::WriteAllError::Receiver {
                                source: WriteError::LayerEnded { .. },
                                ..
                            }
                        ),
                        "the stream is stopped, not the layer: {error:?}"
                    );
                    stopped = true;
                }
            }
            _ => {}
        }
        stopped
    });
    assert!(stopped, "the client's writes failed within 3 s");
    assert_eq!(read, b"ab");
    drop((client_reader, server_writer));
}

/// Both parts of a stream are done — the client's request was
/// acknowledged and the client read the answer's end — while the client
/// still holds its writer and reader: the stream set keeps them for it, and
/// every operation gives the last result again, not the layer's end.
#[test]
fn a_done_stream_whose_handles_are_held_gives_its_last_results() {
    let clock = tls_clock();
    let mut client_stream = None;
    let mut server_layer = None;
    let mut server_stream = None;
    let (mut request, mut answer) = (Vec::new(), Vec::new());
    let mut answered = false;
    let mut done = false;
    let mut looked = false;
    handshake(client_engine(&clock, 1), &clock, |run| {
        if client_stream.is_none()
            && let Poll::Ready(Ok(layer)) = poll_now(run.client_handle.established())
        {
            let (mut writer, reader) = layer.try_open_bi().expect("the server grants streams");
            ready(writer.write_all_unpin(Bytes::from_static(b"ping"))).expect("written");
            writer.close().expect("the request ends");
            client_stream = Some((writer, reader));
        }
        if server_layer.is_none()
            && let Poll::Ready(layer) = poll_now(run.server_handle.established())
        {
            server_layer = Some(layer.expect("the server's handshake completed"));
        }
        if server_stream.is_none()
            && let Some(layer) = &server_layer
            && let Poll::Ready(stream) = poll_now(layer.accept_bi())
        {
            server_stream = Some(stream.expect("the client's stream is accepted"));
        }
        if !answered
            && let Some((writer, reader)) = &mut server_stream
            && read_now!(reader, request)
        {
            ready(writer.write_all_unpin(Bytes::from_static(b"pong"))).expect("written");
            writer.close().expect("the answer ends");
            answered = true;
        }
        let Some((writer, reader)) = &mut client_stream else {
            return false;
        };
        if done {
            // the next millisecond: both parts are done and held
            let mut again = Vec::new();
            assert!(
                matches!(read_what_comes!(reader, again), Ok(true)),
                "the reader reads the end again"
            );
            assert!(again.is_empty());
            assert!(matches!(
                poll_now(writer.all_acknowledged()),
                Poll::Ready(Ok(()))
            ));
            let Poll::Ready(Err(error)) =
                poll_now(writer.write_all_unpin(Bytes::from_static(b"late")))
            else {
                panic!("a write after the end fails");
            };
            assert!(
                !matches!(
                    error,
                    nitori_io::calls::WriteAllError::Receiver {
                        source: WriteError::LayerEnded { .. },
                        ..
                    }
                ),
                "the stream ended, not the layer: {error:?}"
            );
            looked = true;
            return true;
        }
        done = read_now!(reader, answer)
            && matches!(poll_now(writer.all_acknowledged()), Poll::Ready(Ok(())));
        false
    });
    assert!(
        looked,
        "the request was acknowledged and the answer read within 3 s"
    );
    assert_eq!(request, b"ping");
    assert_eq!(answer, b"pong");
}

/// The events of a stream on both sides: the client opens a bidirectional
/// stream, writes a request and ends it; the server reads it to its end.
/// Each side's parts leave idle, as this side's on the client and as the
/// peer's on the server; the client's sending part ends in "Data Recvd" once
/// the server acknowledged everything, the server's receiving part in "Data
/// Read"; the bytes the client's writer moved to its transport are those the
/// server's reader took from its own.
#[test]
fn both_sides_give_the_states_of_a_streams_parts_and_the_data_moved() {
    use common::events::{SharedRecorded, shared_recorded};
    use sakuya_connection::v1::events::{DataLocation, StreamStateChange};
    use sakuya_stream::{receive::ReceiveStreamState, send::SendStreamState};

    let clock = tls_clock();
    let mut server_layer = None;
    let mut client_stream = None;
    let mut server_stream = None;
    let mut request = Vec::new();
    let mut read_end = false;
    let delivered = |recorded: &[SharedRecorded]| {
        recorded.iter().any(|event| {
            matches!(
                event,
                SharedRecorded::StreamState {
                    change: StreamStateChange::Sending {
                        new: Some(SendStreamState::DataRecvd),
                        ..
                    },
                    ..
                }
            )
        })
    };
    handshake(client_engine(&clock, 1), &clock, |run| {
        if client_stream.is_none()
            && let Poll::Ready(layer) = poll_now(run.client_handle.established())
        {
            let layer = layer.expect("the client's handshake completed");
            let (mut writer, reader) = layer.try_open_bi().expect("the server grants streams");
            ready(writer.write_all_unpin(Bytes::from_static(b"request")))
                .expect("the request is written");
            writer.close().expect("the request ends");
            client_stream = Some((writer, reader));
        }
        if server_layer.is_none()
            && let Poll::Ready(layer) = poll_now(run.server_handle.established())
        {
            server_layer = Some(layer.expect("the server's handshake completed"));
        }
        if server_stream.is_none()
            && let Some(layer) = &server_layer
            && let Poll::Ready(stream) = poll_now(layer.accept_bi())
        {
            server_stream = Some(stream.expect("the client's stream is accepted"));
        }
        if let Some((_, reader)) = &mut server_stream
            && !read_end
        {
            read_end = read_now!(reader, request);
        }
        read_end && delivered(&shared_recorded(Role::Client))
    });
    assert_eq!(request, b"request");

    let client = shared_recorded(Role::Client);
    let server = shared_recorded(Role::Server);
    let has = |recorded: &[SharedRecorded], change: StreamStateChange, trigger: EventInitiator| {
        recorded.iter().any(|event| {
            matches!(
                event,
                SharedRecorded::StreamState { change: c, trigger: t, .. }
                    if *c == change && *t == trigger
            )
        })
    };
    let made_sending = StreamStateChange::Sending {
        old: None,
        new: Some(SendStreamState::Ready),
    };
    let made_receiving = StreamStateChange::Receiving {
        old: None,
        new: Some(ReceiveStreamState::Recv),
    };
    assert!(
        has(&client, made_sending, EventInitiator::Local),
        "{client:?}"
    );
    assert!(
        has(&client, made_receiving, EventInitiator::Local),
        "{client:?}"
    );
    assert!(
        has(&server, made_sending, EventInitiator::Remote),
        "{server:?}"
    );
    assert!(
        has(&server, made_receiving, EventInitiator::Remote),
        "{server:?}"
    );
    assert!(delivered(&client), "{client:?}");
    assert!(
        server.iter().any(|event| matches!(
            event,
            SharedRecorded::StreamState {
                change: StreamStateChange::Receiving {
                    new: Some(ReceiveStreamState::DataRead),
                    ..
                },
                trigger: EventInitiator::Local,
                ..
            }
        )),
        "{server:?}"
    );
    let moved = |recorded: &[SharedRecorded], from: DataLocation, to: DataLocation| -> u64 {
        recorded
            .iter()
            .filter_map(|event| match event {
                SharedRecorded::StreamDataMoved(moved) if moved.from == from && moved.to == to => {
                    Some(moved.length)
                }
                _ => None,
            })
            .sum()
    };
    let length = b"request".len() as u64;
    assert_eq!(
        moved(&client, DataLocation::Application, DataLocation::Transport),
        length
    );
    assert_eq!(
        moved(&server, DataLocation::Transport, DataLocation::Application),
        length
    );
}

/// Over the tests' in-memory link, the server grants the client four
/// bidirectional streams, and the client opens ten, one after the other,
/// each with a request and its end, each answered with its end; the server
/// holds every writer and reader to the end. A stream the server read to
/// its end and whose answer the client acknowledged is reclaimed all the
/// same, and the server's MAX_STREAMS lets the client open the next
/// (RFC 9000 §4.6): without it, the fifth would wait for good.
#[test]
fn a_client_opens_more_streams_than_first_granted_as_the_server_reclaims_finished_ones() {
    const STREAMS: usize = 10;
    let clock = tls_clock();
    let mut server_layer = None;
    let mut client_stream = None;
    let mut server_streams = Vec::new();
    let mut finished = 0;
    handshake(client_engine(&clock, 1), &clock, |run| {
        let Poll::Ready(Ok(client)) = poll_now(run.client_handle.established()) else {
            return false;
        };
        if server_layer.is_none()
            && let Poll::Ready(layer) = poll_now(run.server_handle.established())
        {
            server_layer = Some(layer.expect("the server's handshake completed"));
        }
        if client_stream.is_none() && finished < STREAMS {
            match client.try_open_bi() {
                Ok((mut writer, reader)) => {
                    ready(writer.write_all_unpin(Bytes::from_static(b"ping")))
                        .expect("the request is written");
                    writer.close().expect("the request ends");
                    client_stream = Some((writer, reader, Vec::new()));
                }
                // the server has not granted more yet
                Err(TryOpenStreamError::AtLimit) => {}
                Err(error) => panic!("the client opens a stream: {error:?}"),
            }
        }
        if let Some(layer) = &server_layer {
            while let Poll::Ready(stream) = poll_now(layer.accept_bi()) {
                let (writer, reader) = stream.expect("the client's stream is accepted");
                server_streams.push((writer, reader, Vec::new(), false));
            }
        }
        for (writer, reader, request, answered) in &mut server_streams {
            if !*answered && read_now!(reader, *request) {
                assert_eq!(request, b"ping");
                ready(writer.write_all_unpin(Bytes::from_static(b"pong")))
                    .expect("the answer is written");
                writer.close().expect("the answer ends");
                *answered = true;
            }
        }
        let answered = match &mut client_stream {
            Some((_, reader, answer)) => read_now!(reader, *answer),
            None => false,
        };
        if answered {
            let (_, _, answer) = client_stream.take().expect("a stream");
            assert_eq!(answer, b"pong");
            finished += 1;
        }
        finished == STREAMS
    });
    assert_eq!(
        finished, STREAMS,
        "the client finished every stream within 3 s"
    );
    assert_eq!(server_streams.len(), STREAMS);
}

/// Over the tests' in-memory link, the server answers with as much as the
/// client lets it send on the stream at once. Once the server has processed
/// a Handshake packet the client's address is validated (RFC 9000 §8.1), so
/// the anti-amplification limit no longer holds the answer to three times
/// what the client sends: it arrives well within the harness's 3 s.
#[test]
fn a_server_sends_past_the_anti_amplification_limit_once_the_handshake_validates_the_client() {
    const ANSWER: usize = 16_384;
    let clock = tls_clock();
    let mut client_stream = None;
    let mut server_layer = None;
    let mut server_stream = None;
    let (mut request, mut answer) = (Vec::new(), Vec::new());
    let mut answered = false;
    let mut done = false;
    handshake(client_engine(&clock, 1), &clock, |run| {
        if client_stream.is_none()
            && let Poll::Ready(layer) = poll_now(run.client_handle.established())
        {
            let layer = layer.expect("the client's handshake completed");
            let (mut writer, reader) = layer.try_open_bi().expect("the server grants streams");
            ready(writer.write_all_unpin(Bytes::from_static(b"get")))
                .expect("the request is written");
            writer.close().expect("the request ends");
            client_stream = Some((writer, reader));
        }
        if server_layer.is_none()
            && let Poll::Ready(layer) = poll_now(run.server_handle.established())
        {
            server_layer = Some(layer.expect("the server's handshake completed"));
        }
        if server_stream.is_none()
            && let Some(layer) = &server_layer
            && let Poll::Ready(stream) = poll_now(layer.accept_bi())
        {
            server_stream = Some(stream.expect("the client's stream is accepted"));
        }
        if let Some((writer, reader)) = &mut server_stream
            && !answered
            && read_now!(reader, request)
        {
            ready(writer.write_all_unpin(Bytes::from(vec![7; ANSWER])))
                .expect("the answer is written");
            writer.close().expect("the answer ends");
            answered = true;
        }
        if let Some((_, reader)) = &mut client_stream
            && !done
        {
            done = read_now!(reader, answer);
        }
        done
    });
    assert!(done, "the client read the answer's end within 3 s");
    assert_eq!(request, b"get");
    assert_eq!(answer.len(), ANSWER);
}

/// Over the tests' in-memory link, a client completes the handshake and
/// opens a stream; then its link ends. The connection ends at once, with
/// the link's end as its reason, which the layer and the stream report
/// too, and the client sends nothing more.
#[test]
fn a_client_whose_link_ends_reports_the_end_everywhere_and_sends_nothing_more() {
    let clock = tls_clock();
    let mut stream = None;
    let mut layer = None;
    let mut sent_before_end = None;
    let run = handshake(client_engine(&clock, 1), &clock, |run| {
        if stream.is_none()
            && let Poll::Ready(established) = poll_now(run.client_handle.established())
        {
            let established = established.expect("the client's handshake completed");
            stream = Some(
                established
                    .try_open_bi()
                    .expect("the server grants streams"),
            );
            layer = Some(established);
            sent_before_end = Some(run.client_sent.len());
            common::end_link(&run.client_link);
        }
        run.client_ended
    });
    assert!(run.client_ended, "the client's connection ended");
    assert_eq!(
        Some(run.client_sent.len()),
        sent_before_end,
        "nothing is sent once the link ended"
    );
    let link_ended = |reason: &CloseReason<CloseCauseOf<ClientChoices, Parts>>| {
        matches!(
            reason,
            CloseReason::Local(cause) if matches!(**cause, LocalCloseCause::LinkEnded(()))
        )
    };
    let closed = ready(run.client_handle.closed());
    assert!(link_ended(&closed), "{closed:?}");
    let layer = layer.expect("the client's layer");
    assert!(matches!(
        ready(layer.ended()),
        LayerEnd::ConnectionClosed(reason) if link_ended(&reason)
    ));
    let (mut writer, _) = stream.expect("the client's stream");
    let Poll::Ready(Err(error)) = poll_now(writer.write_all_unpin(Bytes::from_static(b"late")))
    else {
        panic!("the write fails at once");
    };
    assert!(
        matches!(
            error.host_error(),
            Some(WriteError::LayerEnded { source })
                if matches!(source.end(), LayerEnd::ConnectionClosed(reason) if link_ended(reason))
        ),
        "{error:?}"
    );
}

/// A waker that counts how often it was woken.
#[derive(Default)]
struct Wakes(std::sync::atomic::AtomicUsize);

impl std::task::Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// A future kept across the harness's calls, polled with a waker of its
/// own that counts its wakes.
struct Waiting<F: Future> {
    future: core::pin::Pin<Box<F>>,
    wakes: Arc<Wakes>,
}

impl<F: Future> Waiting<F> {
    fn new(future: F) -> Self {
        Self {
            future: Box::pin(future),
            wakes: Arc::default(),
        }
    }

    fn poll(&mut self) -> Poll<F::Output> {
        let waker = Waker::from(Arc::clone(&self.wakes));
        self.future.as_mut().poll(&mut Context::from_waker(&waker))
    }

    /// How often its waker was woken.
    fn wakes(&self) -> usize {
        self.wakes.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Whether `end` is the end of a layer whose driver panicked.
fn panicked<C>(end: &LayerEnd<C>) -> bool {
    matches!(
        end,
        LayerEnd::ConnectionClosed(CloseReason::Aborted(AbortCause::Panicked))
    )
}

/// Over the tests' in-memory link, a client completes the handshake and
/// waits on its layer: to read a stream, to write past the stream's limit,
/// to open a stream past the server's limit, and to accept one. Then a
/// poll of the client's connection panics, the host catches the panic and
/// drops the driver, which runs no end action: every wait that was pending
/// is woken and ends with the layer's end, the driver's panic.
#[test]
fn a_panic_in_the_clients_poll_ends_every_wait_on_its_streams() {
    let clock = tls_clock();
    let maximum = NonZeroUsize::new(64).expect("not zero");
    let mut layer = None;
    let mut read = None;
    let mut write = None;
    let mut open = None;
    let mut accept = None;
    let mut others = Vec::new();
    let run = handshake(client_engine(&clock, 1), &clock, |run| {
        if run.client_panicked {
            return true;
        }
        if layer.is_some() {
            return false;
        }
        let Poll::Ready(Ok(client)) = poll_now(run.client_handle.established()) else {
            return false;
        };
        let (mut writer, mut reader) = client.try_open_bi().expect("the server grants streams");
        // the server grants four bidirectional streams
        for _ in 0..3 {
            others.push(client.try_open_bi().expect("the server grants streams"));
        }
        let mut reading = Waiting::new(async move { reader.read_chunk_unpin(maximum).await });
        // past the 16 KiB the server grants the stream
        let mut writing =
            Waiting::new(async move { writer.write_all_unpin(Bytes::from(vec![7; 20_000])).await });
        let mut opening = Waiting::new(client.open_bi_owned());
        let mut accepting = Waiting::new(client.accept_bi_owned());
        assert!(reading.poll().is_pending(), "the server sent nothing");
        assert!(writing.poll().is_pending(), "the stream's limit holds it");
        assert!(opening.poll().is_pending(), "the server's limit holds it");
        assert!(accepting.poll().is_pending(), "the server opened nothing");
        watch::panic_client();
        (read, write, open, accept) =
            (Some(reading), Some(writing), Some(opening), Some(accepting));
        layer = Some(client);
        false
    });
    assert!(run.client_panicked, "the client's poll panicked");
    let (mut read, mut write, mut open, mut accept) = (
        read.expect("waits"),
        write.expect("waits"),
        open.expect("waits"),
        accept.expect("waits"),
    );
    assert!(matches!(
        ready(run.client_handle.closed()),
        CloseReason::Aborted(AbortCause::Panicked)
    ));
    let layer = layer.expect("the client's layer");
    assert!(panicked(&ready(layer.ended())));
    for (wait, wakes) in [
        ("read", read.wakes()),
        ("write", write.wakes()),
        ("open", open.wakes()),
        ("accept", accept.wakes()),
    ] {
        assert!(wakes > 0, "the {wait} is woken");
    }
    let Poll::Ready(Err(error)) = read.poll() else {
        panic!("the read ends");
    };
    assert!(
        matches!(&error, ReadError::LayerEnded { source } if panicked(source.end())),
        "{error:?}"
    );
    let Poll::Ready(Err(error)) = write.poll() else {
        panic!("the write ends");
    };
    assert!(
        matches!(error.host_error(), Some(WriteError::LayerEnded { source }) if panicked(source.end())),
        "{error:?}"
    );
    assert!(matches!(open.poll(), Poll::Ready(Err(error)) if panicked(error.end())));
    assert!(matches!(accept.poll(), Poll::Ready(Err(error)) if panicked(error.end())));
    // every later operation reports the end at once
    let (mut writer, _) = others.pop().expect("a stream");
    assert!(matches!(
        writer.close(),
        Err(CloseError::LayerEnded { source }) if panicked(source.end())
    ));
    assert!(matches!(
        layer.try_open_uni(),
        Err(TryOpenStreamError::LayerEnded { source }) if panicked(source.end())
    ));
}

/// The compositions of the locked stream set, whose capabilities can be
/// held apart from the connection as well as through it: the other tests
/// run on the default set, held by the connection.
mod locked_set {
    use sakuya_connection::v1::streams::locked::LockedStreamSetFamily;

    use super::*;

    choices!(
        ServerChoices,
        v1::Server<ServerEngine, common::TestNewTokenIssuer>,
        sakuya_connection::send_strategy::ranked::RankedSendStrategy<I>,
        LockedStreamSetFamily
    );
    choices!(
        ClientChoices,
        v1::Client<ClientEngine, common::TestTokenSink, ContinueOnRetry, ()>,
        common::ending::IntentEndingSendStrategy<I>,
        LockedStreamSetFamily
    );
    /// The parts of these connections, as of the others.
    type Parts = HList![v1::Part, watch::Part];
    sakuya_connection::composition!(impl for ServerChoices: ServerChoices, Parts);
    sakuya_connection::composition!(impl for ClientChoices: ClientChoices, Parts);

    harness!(server: [HNil], client: [HNil]);

    exchange_measurement!(measure_exchanges_on_the_locked_stream_set);

    /// A request and its answer on a stream through the shared connection
    /// of the locked set: the layer's handle opens and accepts it.
    #[test]
    fn a_client_and_a_server_exchange_a_request_and_its_answer_through_the_connection() {
        let clock = tls_clock();
        let mut client_stream = None;
        let mut server_layer = None;
        let mut server_stream = None;
        let (mut request, mut answer) = (Vec::new(), Vec::new());
        let mut answered = false;
        let mut done = false;
        handshake(client_engine(&clock, 1), &clock, |run| {
            if client_stream.is_none()
                && let Poll::Ready(Ok(layer)) = poll_now(run.client_handle.established())
            {
                let (mut writer, reader) = layer.try_open_bi().expect("the server grants streams");
                ready(writer.write_all_unpin(Bytes::from_static(b"ping"))).expect("written");
                writer.close().expect("the request ends");
                client_stream = Some((writer, reader));
            }
            if server_layer.is_none()
                && let Poll::Ready(layer) = poll_now(run.server_handle.established())
            {
                server_layer = Some(layer.expect("the server's handshake completed"));
            }
            if server_stream.is_none()
                && let Some(layer) = &server_layer
                && let Poll::Ready(stream) = poll_now(layer.accept_bi())
            {
                server_stream = Some(stream.expect("the client's stream is accepted"));
            }
            if let Some((writer, reader)) = &mut server_stream
                && !answered
                && read_now!(reader, request)
            {
                ready(writer.write_all_unpin(Bytes::from_static(b"pong"))).expect("written");
                writer.close().expect("the answer ends");
                answered = true;
            }
            if let Some((_, reader)) = &mut client_stream
                && !done
            {
                done = read_now!(reader, answer);
            }
            done
        });
        assert!(done, "the client read the answer's end within 3 s");
        assert_eq!(request, b"ping");
        assert_eq!(answer, b"pong");
    }

    /// The client's strategy ends the intent of a stream's data when the
    /// client's link path changes role: the intent goes back to the stream,
    /// whose destination falls back and publishes it again at once, and the
    /// data reaches the server. While the link path is settling the data waits
    /// with the strategy; it is the return to the active role that ends it.
    /// The client's strategy keeps only what is published through its intake,
    /// as the locked set publishes.
    #[test]
    fn a_stream_intent_the_strategy_ends_is_published_again_and_its_data_arrives() {
        let clock = tls_clock();
        let mut step = 0;
        let mut client_stream = None;
        let mut published = (0, 0);
        let mut server_layer = None;
        let mut server_stream = None;
        let mut read = Vec::new();
        let mut done = false;
        handshake(client_engine(&clock, 1), &clock, |run| {
            let Poll::Ready(Ok(client)) = poll_now(run.client_handle.established()) else {
                return false;
            };
            match step {
                0 => watch::set_client_role(|now| LinkPathRole::Settling(now + ms(60_000))),
                1 => {
                    common::ending::end_at_next_role_change("Stream {");
                    let (mut writer, reader) =
                        client.try_open_bi().expect("the server grants streams");
                    ready(writer.write_all_unpin(Bytes::from_static(b"hello")))
                        .expect("the data is written");
                    writer.close().expect("the stream ends");
                    client_stream = Some((writer, reader));
                    published.0 = common::ending::published("Stream {");
                    watch::set_client_role(|_| LinkPathRole::Active);
                }
                2 => published.1 = common::ending::published("Stream {"),
                _ => {}
            }
            step += 1;
            if server_layer.is_none()
                && let Poll::Ready(layer) = poll_now(run.server_handle.established())
            {
                server_layer = Some(layer.expect("the server's handshake completed"));
            }
            if server_stream.is_none()
                && let Some(layer) = &server_layer
                && let Poll::Ready(stream) = poll_now(layer.accept_bi())
            {
                server_stream = Some(stream.expect("the client's stream is accepted"));
            }
            if let Some((_, reader)) = &mut server_stream
                && !done
            {
                done = read_now!(reader, read);
            }
            done
        });
        assert!(
            published.0 > 0,
            "the data's intent is published while settling"
        );
        assert_eq!(
            published.1,
            2 * published.0,
            "each intent ended is published again at once"
        );
        assert!(done, "the server read the stream's end within 3 s");
        assert_eq!(read, b"hello");
    }

    /// The same exchange as on a stream through the shared connection, on one
    /// with independent shares: the layer's handle opens and accepts it with
    /// the detached methods.
    #[test]
    fn a_client_and_a_server_exchange_a_request_and_its_answer_on_a_detached_stream() {
        let clock = tls_clock();
        let mut client_stream = None;
        let mut server_layer = None;
        let mut server_stream = None;
        let (mut request, mut answer) = (Vec::new(), Vec::new());
        let mut answered = false;
        let mut done = false;
        handshake(client_engine(&clock, 1), &clock, |run| {
            if client_stream.is_none()
                && let Poll::Ready(Ok(layer)) = poll_now(run.client_handle.established())
            {
                let (mut writer, reader) = layer
                    .try_open_bi_detached()
                    .expect("the server grants streams");
                ready(writer.write_all_unpin(Bytes::from_static(b"ping"))).expect("written");
                writer.close().expect("the request ends");
                client_stream = Some((writer, reader.into_shared::<Arc<HandleCredential>>()));
            }
            if server_layer.is_none()
                && let Poll::Ready(layer) = poll_now(run.server_handle.established())
            {
                server_layer = Some(layer.expect("the server's handshake completed"));
            }
            if server_stream.is_none()
                && let Some(layer) = &server_layer
                && let Poll::Ready(stream) = poll_now(layer.accept_bi_detached())
            {
                server_stream = Some(stream.expect("the client's stream is accepted"));
            }
            if let Some((writer, reader)) = &mut server_stream
                && !answered
                && read_now!(reader, request)
            {
                ready(writer.write_all_unpin(Bytes::from_static(b"pong"))).expect("written");
                writer.close().expect("the answer ends");
                answered = true;
            }
            if let Some((_, reader)) = &mut client_stream
                && !done
            {
                let mut clone = reader.clone();
                done = read_now!(clone, answer);
            }
            done
        });
        assert!(done, "the client read the answer's end within 3 s");
        assert_eq!(request, b"ping");
        assert_eq!(answer, b"pong");
    }
}

/// A client and a server whose compositions have the reliable stream reset
/// extension, each announcing `reset_stream_at` or not.
#[cfg(feature = "reset_stream_at")]
mod reliable {
    use std::cell::Cell;

    use sakuya_connection::{
        reset_stream_at::{self, ResetAtError, ResetStreamAtChoices, ResetStreamAtConnectionArgs},
        v1::parameters::UseConfiguredParameters,
    };
    use sakuya_stream::receive::read::ReadError;
    use sakuya_wire::{
        reset_stream_at::ResetStreamAt, v1::application_error::ApplicationErrorCode,
    };

    use super::*;

    /// The parts of these connections: version 1, the watch, and the
    /// extension.
    type Parts = HList![v1::Part, watch::Part, reset_stream_at::Part];
    // the DATAGRAM extension's tests compose this extension too
    impl ResetStreamAtChoices for ServerChoices {}
    impl ResetStreamAtChoices for ClientChoices {}
    sakuya_connection::composition!(impl for crate::ServerChoices: crate::ServerChoices, Parts);
    sakuya_connection::composition!(impl for crate::ClientChoices: crate::ClientChoices, Parts);

    thread_local! {
        /// Whether each side announces `reset_stream_at`: the server's
        /// first.
        static ANNOUNCES: Cell<[bool; 2]> = const { Cell::new([true, true]) };
    }

    /// The extension's facts of the side of `role`, as the test set them.
    fn slots(role: Role) -> ResetStreamAtConnectionArgs {
        let announces = ANNOUNCES.with(|announces| announces.get()[index(role)]);
        ResetStreamAtConnectionArgs {
            transport_parameters: frunk_core::hlist![announces.then_some(ResetStreamAt)],
            resumed_parameters_policy: UseConfiguredParameters,
        }
    }

    harness!(server: [HNil, slots(Role::Server)], client: [HNil, slots(Role::Client)]);

    /// Run a handshake with the server announcing `reset_stream_at` if
    /// `server` and the client if `client`, as [`handshake`] does.
    fn run_announcing(
        server: bool,
        client: bool,
        clock: &Arc<ManualClock>,
        done: impl FnMut(&Run) -> bool,
    ) -> Run {
        ANNOUNCES.with(|announces| announces.set([server, client]));
        handshake(client_engine(clock, 1), clock, done)
    }

    fn code(value: u32) -> ApplicationErrorCode {
        ApplicationErrorCode::new(VarInt::from_u32(value))
    }

    /// The client writes 10 bytes on a stream and resets it at a reliable
    /// size of 4: the server, which announced `reset_stream_at`, reads the
    /// first 4 bytes and then the reset, with its code and reliable size
    /// (draft-ietf-quic-reliable-stream-reset §4, §5). The client could
    /// reset so only because the server's parameter reached it.
    #[test]
    fn a_reset_at_a_reliable_size_delivers_the_prefix_and_then_the_reset() {
        let clock = tls_clock();
        let mut client_stream = None;
        let mut server_layer = None;
        let mut server_stream = None;
        let mut read = Vec::new();
        let mut reset = None;
        run_announcing(true, true, &clock, |run| {
            if client_stream.is_none()
                && let Poll::Ready(layer) = poll_now(run.client_handle.established())
            {
                let layer = layer.expect("the client's handshake completed");
                let (mut writer, reader) = layer.try_open_bi().expect("the server grants streams");
                ready(writer.write_all_unpin(Bytes::from_static(b"0123456789")))
                    .expect("the data is written");
                writer
                    .reset_at(code(7), VarInt::from_u32(4))
                    .expect("the server announced reset_stream_at");
                client_stream = Some((writer, reader));
            }
            if server_layer.is_none()
                && let Poll::Ready(layer) = poll_now(run.server_handle.established())
            {
                server_layer = Some(layer.expect("the server's handshake completed"));
            }
            if server_stream.is_none()
                && let Some(layer) = &server_layer
                && let Poll::Ready(stream) = poll_now(layer.accept_bi())
            {
                server_stream = Some(stream.expect("the client's stream is accepted"));
            }
            if let Some((_, reader)) = &mut server_stream
                && reset.is_none()
            {
                let maximum = NonZeroUsize::new(64).expect("not zero");
                loop {
                    match poll_now(reader.read_chunk_unpin(maximum)) {
                        Poll::Ready(Ok(Some(chunk))) => read.extend_from_slice(&chunk),
                        Poll::Ready(Ok(None)) => panic!("the stream was reset, not ended"),
                        Poll::Ready(Err(ReadError::Reset { reset: facts, .. })) => {
                            reset = Some(facts);
                            break;
                        }
                        Poll::Ready(Err(error)) => panic!("the stream is reset: {error:?}"),
                        Poll::Pending => break,
                    }
                }
            }
            reset.is_some()
        });
        let reset = reset.expect("the server read the reset within 3 s");
        assert_eq!(read, b"0123");
        assert_eq!(reset.code(), code(7));
        assert_eq!(reset.reliable_size(), VarInt::from_u32(4));
        let (server, client) = (noted(Role::Server), noted(Role::Client));
        assert_eq!(
            server.record, None,
            "the server's connection is not closing"
        );
        assert_eq!(
            client.record, None,
            "the client's connection is not closing"
        );
    }

    /// A server that does not announce `reset_stream_at` takes no
    /// RESET_STREAM_AT: the client's writer refuses to reset at a reliable
    /// size, and the stream stays as it was (draft §3).
    #[test]
    fn a_reset_at_a_reliable_size_needs_the_peers_parameter() {
        let clock = tls_clock();
        let mut refused = None;
        run_announcing(false, true, &clock, |run| {
            if let Poll::Ready(layer) = poll_now(run.client_handle.established()) {
                let layer = layer.expect("the client's handshake completed");
                let (mut writer, _) = layer.try_open_bi().expect("the server grants streams");
                ready(writer.write_all_unpin(Bytes::from_static(b"0123456789")))
                    .expect("the data is written");
                refused = Some(writer.reset_at(code(7), VarInt::from_u32(4)));
                writer.reset(code(8)).expect("a plain reset is taken");
                return true;
            }
            false
        });
        assert!(
            matches!(refused, Some(Err(ResetAtError::NotSupportedByPeer))),
            "{refused:?}"
        );
    }
}

/// A client and a server whose compositions have the DATAGRAM extension,
/// each announcing a `max_datagram_frame_size` or not; the tests send and
/// receive through the handles of the established layers the connection
/// handles give.
#[cfg(feature = "datagram")]
mod datagram {
    use std::cell::Cell;

    use sakuya_connection::datagram::{
        self, DatagramChoices, DatagramConnectionArgs, DatagramOverflow, DatagramQueueBounds,
        ServerReceivedDatagram,
        application::SendDatagramError,
        owned::OwnedDatagramQueuesConfig,
        send::{DatagramSettlement, DatagramState},
    };
    use sakuya_wire::datagram::MaxDatagramFrameSize;

    use super::*;

    impl DatagramChoices for ServerChoices {}

    impl DatagramChoices for ClientChoices {}

    /// The parts of these connections: version 1, the extension, and the
    /// watch; with the reliable stream reset extension too, version 1 is
    /// not first: the watch and that extension come before it, and the
    /// DATAGRAM extension last. Both orders run the same tests; one binary
    /// with both harnesses would not link with its debug information.
    #[cfg(not(feature = "reset_stream_at"))]
    type Parts = HList![v1::Part, datagram::Part, watch::Part];
    #[cfg(feature = "reset_stream_at")]
    type Parts = HList![
        watch::Part,
        sakuya_connection::reset_stream_at::Part,
        v1::Part,
        datagram::Part
    ];
    sakuya_connection::composition!(impl for crate::ServerChoices: crate::ServerChoices, Parts);
    sakuya_connection::composition!(impl for crate::ClientChoices: crate::ClientChoices, Parts);

    thread_local! {
        /// The `max_datagram_frame_size` each side announces: the
        /// server's first; 0 leaves it out.
        static ANNOUNCES: Cell<[u32; 2]> = const { Cell::new([65535, 65535]) };
        /// The server's bounds of the datagrams received; the default
        /// unless a test sets them.
        static SERVER_RECEIVES: Cell<Option<DatagramQueueBounds>> = const { Cell::new(None) };
    }

    /// The extension's facts of the side of `role`, as the test set them.
    fn datagram_args(role: Role) -> DatagramConnectionArgs<OwnedDatagramQueuesConfig> {
        let size = ANNOUNCES.with(|announces| announces.get()[index(role)]);
        DatagramConnectionArgs {
            transport_parameters: frunk_core::hlist![
                (size > 0).then(|| MaxDatagramFrameSize::new(VarInt::from_u32(size)))
            ],
            queues: OwnedDatagramQueuesConfig {
                receive: match role {
                    Role::Server => SERVER_RECEIVES.with(Cell::get).unwrap_or_default(),
                    Role::Client => DatagramQueueBounds::default(),
                },
                ..OwnedDatagramQueuesConfig::default()
            },
            resumed_parameters_policy: Default::default(),
        }
    }

    #[cfg(not(feature = "reset_stream_at"))]
    harness!(server: [datagram_args(Role::Server), HNil], client: [datagram_args(Role::Client), HNil]);
    #[cfg(feature = "reset_stream_at")]
    harness!(
        server: [
            HNil,
            sakuya_connection::reset_stream_at::ResetStreamAtConnectionArgs {
                transport_parameters: frunk_core::hlist![Some(
                    sakuya_wire::reset_stream_at::ResetStreamAt
                )],
                resumed_parameters_policy: Default::default(),
            }
        ] [datagram_args(Role::Server)],
        client: [
            HNil,
            sakuya_connection::reset_stream_at::ResetStreamAtConnectionArgs {
                transport_parameters: frunk_core::hlist![Some(
                    sakuya_wire::reset_stream_at::ResetStreamAt
                )],
                resumed_parameters_policy: Default::default(),
            }
        ] [datagram_args(Role::Client)]
    );

    /// Run a handshake with the server announcing `server` and the client
    /// `client` as their `max_datagram_frame_size`, as [`handshake`] does.
    fn run_announcing(
        server: u32,
        client: u32,
        clock: &Arc<ManualClock>,
        done: impl FnMut(&Run) -> bool,
    ) -> Run {
        ANNOUNCES.with(|announces| announces.set([server, client]));
        handshake(client_engine(clock, 1), clock, done)
    }

    /// The client opens a stream and sends a datagram through the same
    /// handle of its established layer, and the server accepts the stream
    /// and receives the datagram through the same handle of its own: the
    /// capabilities find their shares wherever the parts are.
    #[test]
    fn one_layer_handle_opens_streams_and_exchanges_datagrams() {
        let clock = tls_clock();
        let mut client_stream = None;
        let mut server_stream = None;
        let mut read = Vec::new();
        let mut received = None;
        run_announcing(65535, 65535, &clock, |run| {
            let Poll::Ready(Ok(client)) = poll_now(run.client_handle.established()) else {
                return false;
            };
            if client_stream.is_none() {
                let (mut writer, reader) = client.try_open_bi().expect("the server grants streams");
                ready(writer.write_all_unpin(Bytes::from_static(b"hello")))
                    .expect("the data is written");
                writer.close().expect("the stream ends");
                client
                    .datagram_writer()
                    .send(Bytes::from_static(b"ping"))
                    .expect("the server announced support")
                    .release();
                client_stream = Some((writer, reader));
            }
            let Poll::Ready(Ok(server)) = poll_now(run.server_handle.established()) else {
                return false;
            };
            if server_stream.is_none()
                && let Poll::Ready(stream) = poll_now(server.accept_bi())
            {
                server_stream = Some(stream.expect("the client's stream is accepted"));
            }
            if let Some((_, reader)) = &mut server_stream {
                let maximum = NonZeroUsize::new(64).expect("not zero");
                while let Poll::Ready(Ok(Some(chunk))) = poll_now(reader.read_chunk_unpin(maximum))
                {
                    read.extend_from_slice(&chunk);
                }
            }
            if received.is_none()
                && let Poll::Ready(datagram) = poll_now(server.recv_datagram())
            {
                let datagram: ServerReceivedDatagram = datagram.expect("the layer goes on");
                received = Some(datagram.into_bytes());
            }
            read == b"hello" && received.is_some()
        });
        assert_eq!(read, b"hello");
        assert_eq!(received, Some(Bytes::from_static(b"ping")));
        let (server, client) = (noted(Role::Server), noted(Role::Client));
        assert_eq!(
            server.record, None,
            "the server's connection is not closing"
        );
        assert_eq!(
            client.record, None,
            "the client's connection is not closing"
        );
    }

    /// Over the tests' in-memory link, a client completes the handshake,
    /// waits to receive a datagram, and sends one whose ticket waits to be
    /// settled; before the datagram is written, a poll of the client's
    /// connection panics, the host catches the panic and drops the driver.
    /// Both waits are woken: the receive ends with the layer's end, the
    /// driver's panic, and the ticket settles as withdrawn as the layer
    /// ended.
    #[test]
    fn a_panic_in_the_clients_poll_ends_the_waits_on_its_datagrams() {
        let clock = tls_clock();
        let mut layer = None;
        let mut receive = None;
        let mut settle = None;
        let run = run_announcing(65535, 65535, &clock, |run| {
            if run.client_panicked {
                return true;
            }
            if layer.is_some() {
                return false;
            }
            let Poll::Ready(Ok(client)) = poll_now(run.client_handle.established()) else {
                return false;
            };
            let mut receiving = Waiting::new(client.recv_datagram_owned());
            let mut ticket = client
                .datagram_writer()
                .send(Bytes::from_static(b"ping"))
                .expect("the server announced support");
            assert_eq!(ticket.state(), DatagramState::Waiting);
            let mut settling = Waiting::new(async move {
                let settlement = ticket.settled().await;
                (settlement, ticket)
            });
            assert!(receiving.poll().is_pending(), "the server sent nothing");
            assert!(settling.poll().is_pending(), "the datagram waits");
            watch::panic_client();
            (receive, settle) = (Some(receiving), Some(settling));
            layer = Some(client);
            false
        });
        assert!(run.client_panicked, "the client's poll panicked");
        let (mut receive, mut settle) = (receive.expect("waits"), settle.expect("waits"));
        assert!(receive.wakes() > 0, "the receive is woken");
        assert!(settle.wakes() > 0, "the ticket's wait is woken");
        assert!(matches!(receive.poll(), Poll::Ready(Err(error)) if panicked(error.end())));
        let Poll::Ready((settlement, ticket)) = settle.poll() else {
            panic!("the ticket settles");
        };
        assert_eq!(
            settlement,
            DatagramSettlement::Withdrawn(datagram::send::DatagramWithdrawCause::LayerEnded)
        );
        assert_eq!(
            ticket.state(),
            DatagramState::Withdrawn(datagram::send::DatagramWithdrawCause::LayerEnded)
        );
        ticket.release();
        let layer = layer.expect("the client's layer");
        assert!(matches!(
            layer.datagram_writer().send(Bytes::from_static(b"late")),
            Err(SendDatagramError::LayerEnded { source }) if panicked(source.end())
        ));
    }

    /// A datagram written into a packet whose acknowledgment has not come
    /// when the client's poll panics settles as lost: its packet's fate is
    /// never known. One more datagram sent after it moves it out of the
    /// send queue first, so that it is woken from among those in flight.
    #[test]
    fn a_panic_in_the_clients_poll_settles_a_datagram_in_flight_as_lost() {
        let clock = tls_clock();
        let mut ticket = None;
        let mut settle = None;
        let mut later = None;
        let run = run_announcing(65535, 65535, &clock, |run| {
            if run.client_panicked {
                return true;
            }
            if settle.is_some() {
                return false;
            }
            let Poll::Ready(Ok(client)) = poll_now(run.client_handle.established()) else {
                return false;
            };
            let ticket = ticket.get_or_insert_with(|| {
                client
                    .datagram_writer()
                    .send(Bytes::from_static(b"ping"))
                    .expect("the server announced support")
            });
            if ticket.state() != DatagramState::Sent {
                return false;
            }
            let mut ticket = core::mem::replace(
                ticket,
                client
                    .datagram_writer()
                    .send(Bytes::from_static(b"pong"))
                    .expect("the server announced support"),
            );
            let mut settling = Waiting::new(async move {
                let settlement = ticket.settled().await;
                (settlement, ticket)
            });
            assert!(settling.poll().is_pending(), "the datagram is in flight");
            watch::panic_client();
            settle = Some(settling);
            later = Some(client);
            false
        });
        assert!(run.client_panicked, "the client's poll panicked");
        let mut settle = settle.expect("a datagram was in flight before an acknowledgment");
        assert!(settle.wakes() > 0, "the ticket's wait is woken");
        let Poll::Ready((settlement, sent)) = settle.poll() else {
            panic!("the ticket settles");
        };
        assert_eq!(settlement, DatagramSettlement::Lost);
        assert_eq!(sent.state(), DatagramState::Lost);
        sent.release();
        ticket.expect("sent").release();
        drop(later);
    }

    /// The server keeps two datagrams received at most and takes no new
    /// one beyond them; the client sends three, which the server does not
    /// read. Its layer counts the one it dropped. Once the server closes
    /// the connection, its layer is gone, and what its queues received
    /// stays: it reads the first datagram while the connection closes and
    /// the second once the connection ended, and only then the layer's end;
    /// the count of what was dropped stays all along.
    #[test]
    fn what_a_layer_received_is_read_after_it_ended_and_its_drops_still_count() {
        let clock = tls_clock();
        SERVER_RECEIVES.with(|bounds| {
            bounds.set(Some(DatagramQueueBounds {
                datagrams: NonZeroUsize::new(2).expect("not zero"),
                bytes: 1024,
                overflow: DatagramOverflow::RejectNew,
            }))
        });
        let mut sent = false;
        let mut server_layer = None;
        let mut closed = false;
        let mut during_close = None;
        run_announcing(65535, 65535, &clock, |run| {
            let Poll::Ready(Ok(client)) = poll_now(run.client_handle.established()) else {
                return false;
            };
            if !sent {
                let writer = client.datagram_writer();
                for payload in [&b"one"[..], b"two", b"three"] {
                    writer
                        .send(Bytes::from_static(payload))
                        .expect("the server announced support")
                        .release();
                }
                sent = true;
            }
            if server_layer.is_none()
                && let Poll::Ready(layer) = poll_now(run.server_handle.established())
            {
                server_layer = Some(layer.expect("the server's handshake completed"));
            }
            let Some(server) = &server_layer else {
                return false;
            };
            if !closed {
                if server.dropped_datagrams() == 1 {
                    run.server_handle.close(common::AppClose(7));
                    closed = true;
                }
                return false;
            }
            if during_close.is_none() {
                assert!(
                    matches!(poll_now(server.ended()), Poll::Ready(_)),
                    "the layer ended with the close"
                );
                assert!(!run.server_ended, "the connection closes");
                let Poll::Ready(first) = poll_now(Datagrams::recv_datagram(server)) else {
                    panic!("what was received is there at once");
                };
                let first: ServerReceivedDatagram = first.expect("received before the end");
                during_close = Some((first.into_bytes(), server.dropped_datagrams()));
            }
            true
        });
        SERVER_RECEIVES.with(|bounds| bounds.set(None));
        assert_eq!(
            during_close,
            Some((Bytes::from_static(b"one"), 1)),
            "read while the connection closes"
        );
        let server = server_layer.expect("the server's layer");
        let Poll::Ready(Ok(second)) = poll_now(Datagrams::recv_datagram(&server)) else {
            panic!("the second is read once the connection ended");
        };
        assert_eq!(second.into_bytes(), Bytes::from_static(b"two"));
        assert!(matches!(
            poll_now(Datagrams::recv_datagram(&server)),
            Poll::Ready(Err(_))
        ));
        assert_eq!(server.dropped_datagrams(), 1);
    }

    /// A ticket turned into one with a shared credential is cloned: the
    /// clones read the same datagram, and dropping one of them does not
    /// withdraw it; dropping the last withdraws a datagram not written yet.
    #[test]
    fn a_shared_ticket_settles_its_datagram_and_its_last_drop_withdraws() {
        let clock = tls_clock();
        let mut tickets = None;
        let mut received = Vec::new();
        let mut settled = None;
        run_announcing(65535, 65535, &clock, |run| {
            let (Poll::Ready(Ok(client)), Poll::Ready(Ok(server))) = (
                poll_now(run.client_handle.established()),
                poll_now(run.server_handle.established()),
            ) else {
                return false;
            };
            if tickets.is_none() {
                let ticket = client
                    .datagram_writer()
                    .send(Bytes::from_static(b"shared"))
                    .expect("the server announced support")
                    .into_shared::<Rc<HandleCredential>>();
                let other = ticket.clone();
                drop(ticket);
                tickets = Some(other);
                let dropped = client
                    .datagram_writer()
                    .send(Bytes::from_static(b"dropped"))
                    .expect("the server announced support");
                assert_eq!(dropped.state(), DatagramState::Waiting);
                drop(dropped);
            }
            while let Poll::Ready(datagram) = poll_now(Datagrams::recv_datagram(&server)) {
                let datagram: ServerReceivedDatagram = datagram.expect("the layer goes on");
                received.push(datagram.into_bytes());
            }
            if let Some(ticket) = &mut tickets
                && settled.is_none()
                && let Poll::Ready(settlement) = poll_now(ticket.settled())
            {
                settled = Some(settlement);
            }
            settled.is_some()
        });
        assert_eq!(
            received,
            [Bytes::from_static(b"shared")],
            "the drop of one clone withdrew nothing, the drop of the last its datagram"
        );
        assert_eq!(settled, Some(DatagramSettlement::Acknowledged));
        tickets.expect("sent").release();
    }

    #[test]
    fn a_client_and_a_server_exchange_datagrams() {
        let clock = tls_clock();
        let mut ticket = None;
        let mut answered = false;
        let mut answer = None;
        let mut settled = None;
        run_announcing(65535, 65535, &clock, |run| {
            let (Poll::Ready(Ok(client)), Poll::Ready(Ok(server))) = (
                poll_now(run.client_handle.established()),
                poll_now(run.server_handle.established()),
            ) else {
                return false;
            };
            if ticket.is_none() {
                let writer = Datagrams::datagram_writer(&client);
                ticket = Some(
                    writer
                        .send(Bytes::from_static(b"ping"))
                        .expect("the server announced support"),
                );
            }
            if !answered && let Poll::Ready(received) = poll_now(Datagrams::recv_datagram(&server))
            {
                let received: ServerReceivedDatagram = received.expect("the layer goes on");
                assert!(!received.received_zero_rtt());
                assert_eq!(received.into_bytes(), Bytes::from_static(b"ping"));
                Datagrams::datagram_writer(&server)
                    .send(Bytes::from_static(b"pong"))
                    .expect("the client announced support")
                    .release();
                answered = true;
            }
            if answer.is_none()
                && let Poll::Ready(received) = poll_now(Datagrams::recv_datagram(&client))
            {
                answer = Some(received.expect("the layer goes on"));
            }
            if let Some(ticket) = &mut ticket
                && settled.is_none()
                && let Poll::Ready(settlement) = poll_now(ticket.settled())
            {
                settled = Some(settlement);
            }
            answer.is_some() && settled.is_some()
        });
        assert_eq!(answer, Some(Bytes::from_static(b"pong")));
        assert_eq!(settled, Some(DatagramSettlement::Acknowledged));
        let ticket = ticket.expect("sent");
        assert_eq!(ticket.state(), DatagramState::Acknowledged);
        ticket.release();
        let (server, client) = (noted(Role::Server), noted(Role::Client));
        assert_eq!(
            server.record, None,
            "the server's connection is not closing"
        );
        assert_eq!(
            client.record, None,
            "the client's connection is not closing"
        );
    }

    /// A server that announces no `max_datagram_frame_size` takes no
    /// DATAGRAM frame: the client's writer refuses to send (RFC 9221 §3).
    #[test]
    fn nothing_is_sent_to_a_server_that_did_not_announce_support() {
        let clock = tls_clock();
        let mut refused = None;
        run_announcing(0, 65535, &clock, |run| {
            let Poll::Ready(Ok(client)) = poll_now(run.client_handle.established()) else {
                return false;
            };
            let writer = Datagrams::datagram_writer(&client);
            refused = Some(
                writer
                    .send(Bytes::from_static(b"ping"))
                    .map(|ticket| ticket.release()),
            );
            true
        });
        assert!(
            matches!(refused, Some(Err(SendDatagramError::NotSupportedByPeer))),
            "{refused:?}"
        );
    }

    /// A datagram over the server's limit, counted with a Length field, is
    /// refused with the limit (RFC 9221 §3); one at the limit is taken.
    #[test]
    fn a_datagram_over_the_servers_limit_is_too_large() {
        let clock = tls_clock();
        let mut results = None;
        run_announcing(100, 65535, &clock, |run| {
            let Poll::Ready(Ok(client)) = poll_now(run.client_handle.established()) else {
                return false;
            };
            let writer = Datagrams::datagram_writer(&client);
            let limits = writer.datagram_limits();
            let at_limit = writer
                .send(Bytes::from(vec![0; 97]))
                .map(|ticket| ticket.release());
            let over = writer
                .send(Bytes::from(vec![0; 98]))
                .map(|ticket| ticket.release());
            results = Some((limits.peer, at_limit, over));
            true
        });
        let (limit, at_limit, over) = results.expect("the client's layer was built");
        assert_eq!(limit, 97);
        assert!(at_limit.is_ok(), "{at_limit:?}");
        assert!(
            matches!(over, Err(SendDatagramError::TooLarge { limit: 97 })),
            "{over:?}"
        );
    }
}

/// A client and a server whose DATAGRAM queues are the locked ones, which
/// also give a share of the send queue apart from the connection, and
/// publish through the strategy's intake.
#[cfg(feature = "datagram")]
mod locked_datagram {
    use sakuya_connection::datagram::{
        self, DatagramChoices, DatagramConnectionArgs, ServerReceivedDatagram,
        application::DetachedDatagrams,
        locked::{LockedDatagramQueuesConfig, LockedDatagramQueuesFamily},
        send::{DatagramSettlement, DatagramState},
    };

    use super::*;

    choices!(ServerChoices, v1::Server<ServerEngine, common::TestNewTokenIssuer>);
    choices!(
        ClientChoices,
        v1::Client<ClientEngine, common::TestTokenSink, ContinueOnRetry, ()>,
        common::ending::IntentEndingSendStrategy<I>
    );

    impl DatagramChoices for ServerChoices {
        type DatagramQueues = LockedDatagramQueuesFamily;
    }

    impl DatagramChoices for ClientChoices {
        type DatagramQueues = LockedDatagramQueuesFamily;
    }

    /// The parts of these connections: version 1, the extension, and the
    /// watch.
    type Parts = HList![v1::Part, datagram::Part, watch::Part];
    sakuya_connection::composition!(impl for ServerChoices: ServerChoices, Parts);
    sakuya_connection::composition!(impl for ClientChoices: ClientChoices, Parts);

    /// The extension's facts: the recommended `max_datagram_frame_size`
    /// and the default bounds.
    fn datagram_args() -> DatagramConnectionArgs<LockedDatagramQueuesConfig> {
        DatagramConnectionArgs::default()
    }

    harness!(server: [datagram_args(), HNil], client: [datagram_args(), HNil]);

    /// The client's strategy ends a datagram's intent when the client's
    /// link path changes role: the queues let its destination decide at
    /// once, which publishes it again with the same ticket, before any
    /// other send; the datagram then reaches the server and is
    /// acknowledged.
    #[test]
    fn a_datagram_intent_the_strategy_ends_is_published_again_at_once() {
        let clock = tls_clock();
        let mut step = 0;
        let mut ticket = None;
        let mut published = (0, 0);
        let mut state = None;
        let mut received = None;
        let mut settled = None;
        handshake(client_engine(&clock, 1), &clock, |run| {
            let (Poll::Ready(Ok(client)), Poll::Ready(Ok(server))) = (
                poll_now(run.client_handle.established()),
                poll_now(run.server_handle.established()),
            ) else {
                return false;
            };
            match step {
                0 => watch::set_client_role(|now| LinkPathRole::Settling(now + ms(60_000))),
                1 => {
                    common::ending::end_at_next_role_change("DatagramIntent");
                    ticket = Some(
                        Datagrams::datagram_writer(&client)
                            .send(Bytes::from_static(b"ping"))
                            .expect("the server announced support"),
                    );
                    published.0 = common::ending::published("DatagramIntent");
                    watch::set_client_role(|_| LinkPathRole::Active);
                }
                2 => {
                    published.1 = common::ending::published("DatagramIntent");
                    state = ticket.as_ref().map(|ticket| ticket.state());
                }
                _ => {}
            }
            step += 1;
            if received.is_none()
                && let Poll::Ready(datagram) = poll_now(Datagrams::recv_datagram(&server))
            {
                let datagram: ServerReceivedDatagram = datagram.expect("the layer goes on");
                received = Some(datagram.into_bytes());
            }
            if let Some(ticket) = &mut ticket
                && settled.is_none()
                && let Poll::Ready(settlement) = poll_now(ticket.settled())
            {
                settled = Some(settlement);
            }
            received.is_some() && settled.is_some()
        });
        assert_eq!(
            published,
            (1, 2),
            "published again once, with no other send"
        );
        assert!(
            matches!(state, Some(DatagramState::Waiting | DatagramState::Sent)),
            "the ticket goes on: {state:?}"
        );
        assert_eq!(received, Some(Bytes::from_static(b"ping")));
        assert_eq!(settled, Some(DatagramSettlement::Acknowledged));
        ticket.expect("sent").release();
    }

    /// A ticket turned into one with a shared credential is cloned: the
    /// clones read the same datagram, and dropping one of them does not
    /// withdraw it. The writer with an independent share sends as well,
    /// and its ticket settles alike.
    #[test]
    fn a_shared_ticket_and_a_detached_writer_settle_their_datagrams() {
        let clock = tls_clock();
        let mut tickets = None;
        let mut detached = None;
        let mut received = Vec::new();
        let mut settled = (None, None);
        handshake(client_engine(&clock, 1), &clock, |run| {
            let (Poll::Ready(Ok(client)), Poll::Ready(Ok(server))) = (
                poll_now(run.client_handle.established()),
                poll_now(run.server_handle.established()),
            ) else {
                return false;
            };
            if tickets.is_none() {
                let ticket = client
                    .datagram_writer()
                    .send(Bytes::from_static(b"shared"))
                    .expect("the server announced support")
                    .into_shared::<Rc<HandleCredential>>();
                let other = ticket.clone();
                drop(ticket);
                tickets = Some(other);
                detached = Some(
                    client
                        .datagram_writer_detached()
                        .send(Bytes::from_static(b"detached"))
                        .expect("the server announced support"),
                );
            }
            while let Poll::Ready(datagram) = poll_now(Datagrams::recv_datagram(&server)) {
                let datagram: ServerReceivedDatagram = datagram.expect("the layer goes on");
                received.push(datagram.into_bytes());
            }
            if let Some(ticket) = &mut tickets
                && settled.0.is_none()
                && let Poll::Ready(settlement) = poll_now(ticket.settled())
            {
                settled.0 = Some(settlement);
            }
            if let Some(ticket) = &mut detached
                && settled.1.is_none()
                && let Poll::Ready(settlement) = poll_now(ticket.settled())
            {
                settled.1 = Some(settlement);
            }
            settled.0.is_some() && settled.1.is_some()
        });
        received.sort();
        assert_eq!(
            received,
            [
                Bytes::from_static(b"detached"),
                Bytes::from_static(b"shared")
            ],
            "the drop of one clone withdrew nothing"
        );
        assert_eq!(
            settled,
            (
                Some(DatagramSettlement::Acknowledged),
                Some(DatagramSettlement::Acknowledged)
            )
        );
        tickets.expect("sent").release();
        detached.expect("sent").release();
    }
}
