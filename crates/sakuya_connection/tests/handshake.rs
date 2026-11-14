//! A client and a server connection run their handshake against each
//! other, with sakuya_tls's engines, over links in memory and the tests'
//! clock.
//!
//! The server presents an Ed25519 certificate for example.com, issued by an
//! Ed25519 root that the client's verifier trusts; both are built here. A
//! stand-in part in each connection notes what the tests look at as it
//! changes: the confirmation, the keys of the Initial and Handshake levels,
//! the record of why the connection closed, what only the side has, and
//! the packet number spaces of the logical path.
#![feature(impl_trait_in_assoc_type, yield_expr)]

mod common;

use std::{
    cell::RefCell,
    fmt::Debug,
    future::Future,
    num::NonZeroUsize,
    pin::pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use common::{Outer, TestClock, TestLink, TestReceiver, advance_to, ms, now};
use nitori_crypto::{NamedGroup, SignatureScheme, SigningKey as _};
use nitori_crypto_aws_lc::{AwsLcBackend, Ed25519SigningKey};
use sakuya_connection::{
    call::CallBundle,
    clock::{ConnectionChoices, InstantOf},
    component::{ArgsOf, Build, DataComponent, LineageOf, ParentsOf, ReadSet, RequestOf},
    dispatch::{DispatchFacts, FrameDispatch},
    driver::ConnectionDriver,
    error::ConnectionErrorsOf,
    layer::{self, LinkPathArgs, LogicalPathArgs},
    others::OtherNodes,
    role::LinkPathRole,
    share::{
        LayerShare, LineageLists, LineagePartList, LinkPathIdentifierOf, LogicalPathKeyShare,
        SoleLogicalPath,
    },
    take::GetAt,
    v1::{
        self, CloseCauseOf, Side,
        advancing::HandshakeStart,
        amplification::{AddressValidation, AntiAmplificationFactor},
        close::{CloseReasonRecord, LocalCloseCause},
        close_request::CloseRequestCell,
        confirmation::HandshakeConfirmation,
        connection_ids::FirstLocalConnectionId,
        crypto::{
            CryptoReceiveCapacities, FragmentedCryptoReceiveBuffer, send::OffsetMapCryptoSendBuffer,
        },
        first_flight::FirstFlight,
        input::InitialPathReceiver,
        keys::{HandshakeKeys, InitialKeys},
        link::LinkFacts,
    },
};
use sakuya_datagram_routing::{
    claim::{
        deliverer::DatagramDeliverer,
        delivery::DatagramDelivery,
        erased::ErasedDatagramDeliverer,
        queue::{DatagramDeliveryPoster, DatagramDeliveryQueue},
    },
    route::{
        association::{MatchAssociation, PacketForms, RouteMatcher},
        index::{RouteEntryRegistration, RouteIndex},
        recognizer::ConnectionIdLengths,
        reset::StatelessResetTokens,
        router::DatagramRouter,
    },
};
use sakuya_link::{ArrivalFacts, BindingId, LinkId, MIN_DATAGRAM_SIZE, ReceivedDatagram};
use sakuya_packet_protection::backend::ring::RingBackend;
use sakuya_recovery::{
    factory::NewRenoRecoveryFactoryConfig,
    loss::LossThresholds,
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaceState, PacketNumberSpaces},
    receive_journals::MaxAckRanges,
};
use sakuya_stream::connection::{CloseReason, ImmediateClose};
use sakuya_tls::{
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
use sakuya_wire::{
    connection_id::{ConnectionId, ConnectionIdLength, NonEmptyCid, StatelessResetToken},
    parameters::ParametersPart,
    parts::{CNil, HList, HNil},
    v1::{
        frame::set::{FrameSetPart, FrameTypeValues},
        role::Role,
        transport_error::TransportErrorCode,
        transport_parameters::{
            TransportParameterSpace, TransportParameters, integer::MaxIdleTimeout,
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
        struct $name;
        impl ConnectionChoices for $name {
            type Clock = TestClock;
            type Link = TestLink;
        }
        impl v1::Choices for $name {
            type Crypto = RingBackend;
            type Side = $side;
            type CryptoReceiveBuffer = FragmentedCryptoReceiveBuffer;
            type CryptoSendBuffer = OffsetMapCryptoSendBuffer;
            type Recovery<V: Clone + Eq + Debug + 'static> =
                sakuya_recovery::factory::NewRenoRecoveryFactory<V>;
            type AckObligation = sakuya_recovery::ack_obligation::Rfc9000AckObligation<Duration>;
            type SendJournals<S: 'static, P: Clone + Eq + Debug + 'static> =
                sakuya_recovery::send_journals::DequeSendJournals<Duration, S, P>;
            type ApplicationError = common::AppClose;
            type Receiver = TestReceiver;
            type SendStrategy<I: sakuya_connection::send_strategy::SendStrategyTypes> =
                sakuya_connection::send_strategy::ranked::RankedSendStrategy<I>;
            type DestinationConnectionIds = common::TestDestinationConnectionIds;
            type ResetTokenRegistry = common::TestResetTokenRegistry;
            type ImmediateClosePolicy = common::TestImmediateClosePolicy;
        }
    };
}
choices!(ServerChoices, v1::Server<ServerEngine>);
choices!(ClientChoices, v1::Client<ClientEngine>);

/// The parts of the tests' connections: version 1, and the part that notes
/// what the tests look at.
type Parts = HList![v1::Part, watch::Part];

// ---- what the tests look at ----

thread_local! {
    /// What each side's watch noted last: the server's first.
    static NOTED: RefCell<[Noted; 2]> = RefCell::new([Noted::default(), Noted::default()]);
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
    /// The packet number spaces the logical path keeps.
    spaces: Vec<PacketNumberSpaceKind>,
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
    impl sakuya_connection::error::ConnectionErrorPart for Part {
        type ConnectionError = core::convert::Infallible;
    }
    impl ParametersPart<TransportParameterSpace> for Part {
        type Parameters = HNil;
    }
    impl sakuya_connection::send_strategy::SendIntentPart for Part {
        type FrameSourceId = CNil;
        type SendIntents = CNil;
        type FrameSources = HNil;
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
        type FieldsError<E> = CNil;

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

        fn read_run<H>(_: &mut H, type_value: CNil) -> Result<CNil, CNil>
        where
            H: bytes::Buf + nitori_call::Receiver<Family = nitori_call::Direct<H>> + Unpin,
            nitori_call::Direct<H>: nitori_io::ReadChunk<Chunk: Default>,
        {
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
    impl<T, L, Ic, Ii, Ih, Ir, Io> DataComponent<T, L, layer::Connection, (Ic, Ii, Ih, Ir, Io)>
        for Watch
    where
        T: v1::Choices<Crypto = RingBackend, Clock = TestClock>,
        L: LineagePartList<T> + ConnectionErrorsOf,
        <T::Side as Side>::Own: Debug,
        CloseCauseOf<T, L>: Debug,
        for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<HandshakeConfirmation, Ic>
            + GetAt<InitialKeys<RingBackend>, Ii>
            + GetAt<HandshakeKeys<RingBackend>, Ih>
            + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>
            + GetAt<<T::Side as Side>::Own, Io>,
    {
        fn reads(reads: &mut ReadSet) {
            reads
                .add::<HandshakeConfirmation>()
                .add::<InitialKeys<RingBackend>>()
                .add::<HandshakeKeys<RingBackend>>()
                .add::<CloseReasonRecord<CloseCauseOf<T, L>>>()
                .add::<<T::Side as Side>::Own>();
        }
        fn reread<'v, B: CallBundle>(
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
                    LocalCloseCause::Connection(_) | LocalCloseCause::Application(_) => None,
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
                spaces: Vec::new(),
            };
            note(<T::Side as Side>::ROLE, |noted| {
                *noted = Noted {
                    spaces: core::mem::take(&mut noted.spaces),
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
        fn reads(reads: &mut ReadSet) {
            reads.add::<PacketNumberSpaces<PacketNumberSpaceState>>();
        }
        fn reread<'v, B: CallBundle>(
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

    macro_rules! none {
        ($($lv:ident),*) => {$(
            impl<T: v1::Choices, L> LayerShare<T, L, layer::$lv> for Part {
                type Data = HNil;
                type Calls = HNil;
            }
        )*};
    }
    none!(LinkEntry, LinkPath, Established, Recovery);
    impl<T: v1::Choices, L> LayerShare<T, L, layer::Connection> for Part {
        type Data = HList![Watch];
        type Calls = HNil;
    }
    impl<T: v1::Choices, L> LayerShare<T, L, layer::LogicalPath> for Part {
        type Data = HList![SpaceWatch];
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
struct Posting(DatagramDeliveryPoster<Delivery>);
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
        Target,
        ConnectionIdLengths,
        common::TestResetTokenRegistry,
    >,
    reset_tokens: common::TestResetTokenRegistry,
    _registrations: Vec<RouteEntryRegistration<Target, ()>>,
}

impl Routing {
    /// A routing domain for `ids`, and the receiver it posts to.
    fn new(ids: &[ConnectionId]) -> (Self, TestReceiver) {
        let queue = DatagramDeliveryQueue::new(NonZeroUsize::new(64).expect("not zero"))
            .expect("a capacity a queue can have");
        let index = RouteIndex::<Target, ()>::new();
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
        let reset_tokens = StatelessResetTokens::new();
        let router = DatagramRouter::new(
            index,
            ConnectionIdLengths::new([ConnectionIdLength::new(8).expect("a length")]),
        )
        .with_stateless_reset(Arc::clone(&reset_tokens));
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

/// Version 1's facts for a connection of the choices `T`.
#[allow(clippy::too_many_arguments)]
fn args<T>(
    handshake: HandshakeStart<<T::Side as Side>::Tls>,
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
            DestinationConnectionIds = common::TestDestinationConnectionIds,
            ResetTokenRegistry = common::TestResetTokenRegistry,
            ImmediateClosePolicy = common::TestImmediateClosePolicy,
            ApplicationError = common::AppClose,
        >,
    T::Recovery<LinkId<(), ()>>:
        sakuya_recovery::factory::RecoveryFactory<TestLink, Config = NewRenoRecoveryFactoryConfig>,
{
    let mut parameters = TransportParameters::<Vec<u8>>::new();
    parameters.set(MaxIdleTimeout::new(VarInt::from_u32(30_000)));
    v1::ConnectionArgs {
        crypto: RingBackend,
        handshake,
        client_dcid: cid(&CLIENT_DCID),
        original_destination_connection_id: None,
        anti_amplification: AntiAmplificationFactor::new(3).expect("3 is a factor"),
        transport_parameters: parameters.known,
        first_link: LinkFacts { validation },
        recovery: NewRenoRecoveryFactoryConfig::recommended(ms(1)),
        loss_thresholds: LossThresholds::recommended(ms(1))
            .expect("the test clock's timers fire to the millisecond"),
        max_ack_ranges: MaxAckRanges::DEFAULT,
        crypto_receive,
        first_flight,
        initial_receiver: InitialPathReceiver::new(receiver),
        max_datagrams_per_poll: NonZeroUsize::new(16).expect("not zero"),
        max_held_inputs: 16,
        destination_connection_ids:
            sakuya_connection::connection_id::sequence_map::SequenceMapDestinationConnectionIdStrategyConfig::new(8),
        reset_token_registry: Arc::clone(&routing.reset_tokens),
        first_local_connection_id,
        max_datagrams_per_send: NonZeroUsize::new(16).expect("not zero"),
        immediate_close_policy: common::TestImmediateClosePolicy,
        close_request: CloseRequestCell::new(),
    }
}

/// A connection of version 1 and the watch, of the choices `$t`, whose
/// first link path is over `$link`.
macro_rules! connection {
    ($t:ty, $args:expr, $link:expr) => {
        ConnectionDriver::<$t, Parts, _, _, _>::new(
            TestClock,
            frunk_core::hlist![$args, HNil],
            LogicalPathArgs { path: PATH },
            LinkPathArgs {
                path: PATH,
                link: TestLink($link),
                role: LinkPathRole::Active,
                peer_switched_local_id: false,
            },
        )
    };
}

/// Whether `datagram` starts with an Initial packet.
fn starts_with_initial(datagram: &[u8]) -> bool {
    datagram
        .first()
        .is_some_and(|&byte| byte & 0x80 != 0 && (byte >> 4) & 0b11 == 0)
}

/// What a run of a handshake left.
struct Run {
    /// The datagrams the client sent, in order.
    client_sent: Vec<Bytes>,
    /// Whether the server's connection ended.
    server_ended: bool,
    /// Whether the client's connection ended.
    client_ended: bool,
}

/// Run a client of the engine `client` against a server until `done` says
/// so, or for at most 3 s of the tests' clock.
fn handshake(client: ClientEngine, clock: &Arc<ManualClock>, done: impl Fn() -> bool) -> Run {
    NOTED.with(|n| *n.borrow_mut() = [Noted::default(), Noted::default()]);
    common::reset_links();
    advance_to(ms(0));
    let (client_link, server_link) = (link(), link());
    let (client_routing, client_receiver) = Routing::new(&[cid(&CLIENT_CID)]);
    let mut client = connection!(
        ClientChoices,
        args::<ClientChoices>(
            HandshakeStart::new(client, MessageLimits::default()),
            AddressValidation::Validated,
            client_capacities(),
            FirstFlight::Datagrams(Vec::new()),
            client_receiver,
            &client_routing,
            first_local(&CLIENT_CID, 0xc1),
        ),
        client_link.clone()
    );
    let outer = Outer::new();
    let mut run = Run {
        client_sent: Vec::new(),
        server_ended: false,
        client_ended: false,
    };
    assert!(outer.poll(&mut client).is_pending());
    let first: Vec<Bytes> = common::take_sent()
        .into_iter()
        .map(|(_, datagram)| datagram)
        .collect();
    assert!(!first.is_empty(), "the client sends its first flight");
    run.client_sent.extend(first.iter().cloned());
    // the server's connection is made once the first datagram arrives
    let (server_routing, server_receiver) = Routing::new(&[cid(&CLIENT_DCID), cid(&SERVER_CID)]);
    let mut server = connection!(
        ServerChoices,
        args::<ServerChoices>(
            HandshakeStart::new(server_engine(clock), MessageLimits::default()),
            AddressValidation::NotValidated,
            server_capacities(),
            FirstFlight::Datagrams(
                first
                    .iter()
                    .map(|datagram| arrived(datagram.clone(), &server_link))
                    .collect()
            ),
            server_receiver,
            &server_routing,
            first_local(&SERVER_CID, 0x5e),
        ),
        server_link.clone()
    );
    for millis in 0..3000 {
        advance_to(ms(millis));
        loop {
            let mut moved = false;
            if !run.server_ended {
                run.server_ended = outer.poll(&mut server).is_ready();
            }
            for (_, datagram) in common::take_sent() {
                moved = true;
                client_routing.deliver(datagram, &client_link);
            }
            if !run.client_ended {
                run.client_ended = outer.poll(&mut client).is_ready();
            }
            for (_, datagram) in common::take_sent() {
                moved = true;
                run.client_sent.push(datagram.clone());
                server_routing.deliver(datagram, &server_link);
            }
            if !moved {
                break;
            }
        }
        if done() {
            break;
        }
    }
    run
}

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
    let run = handshake(client_engine(&clock, 1), &clock, || {
        complete(&noted(Role::Server))
            && complete(&noted(Role::Client))
            && noted(Role::Server).own == "Delivered"
    });
    let (server, client) = (noted(Role::Server), noted(Role::Client));
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
    }
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
fn a_client_that_fails_to_verify_the_server_closes_with_the_alert() {
    let clock = tls_clock();
    // the client trusts another root than the server's certificate's
    let run = handshake(client_engine(&clock, 3), &clock, || {
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
    assert!(!run.server_ended, "the server closes in its own time");
}
