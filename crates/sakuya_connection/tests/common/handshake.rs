//! What the handshake tests share: the two sides' engines and their
//! choices, the part that notes what the tests look at, the routing of the
//! datagrams, and the harness of the runs.
#![allow(dead_code)]

use sakuya_connection::role::LinkPathRoleChanged;
use std::{
    cell::{Cell, RefCell},
    fmt::Debug,
    future::Future,
    hash::RandomState,
    num::NonZeroUsize,
    pin::pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};

use crate::common::{self, TestClock, TestLink, TestReceiver, now};
use bytes::{Bytes, BytesMut};
use nitori_crypto::{NamedGroup, SignatureScheme, SigningKey as _};
use nitori_crypto_aws_lc::{AwsLcBackend, Ed25519SigningKey};
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
use sakuya_connection::v1::SendParametersOf;
use sakuya_connection::{
    call::CallBundle,
    clock::{ConnectionChoices, InstantOf},
    component::{ArgsOf, Build, DataComponent, LineageOf, ParentsOf, RequestOf},
    component_event::{EventSubscriptions, Happened, NodeStarted, TriggeredEvents},
    connection_id::DestinationConnectionIdStrategy,
    dispatch::{DispatchFacts, FrameDispatch},
    driver::{LendNode, LendableLayer, NotLent},
    error::ConnectionErrorsOf,
    layer::{self},
    others::OtherNodes,
    role::LinkPathRole,
    share::{
        LayerShare, LineageLists, LineagePartList, LinkPathIdentifierOf, LogicalPathKeyShare,
        SoleLogicalPath,
    },
    share::{PartList, RemainsOf},
    shared::DrivenFromOutside,
    take::GetAt,
    v1::{
        self, CloseCauseOf, Side,
        advancing::ConnectionExporter,
        close::{CloseReasonRecord, LocalCloseCause},
        component_events::{
            CloseReasonWritten, DestinationConnectionIdsChanged, HandshakeConfirmed,
            HandshakeDonePendingChanged, KeysDiscarded, KeysInstalled, LocalConnectionIdsChanged,
            RetryReceived, SpaceRetired, level,
        },
        confirmation::HandshakeConfirmation,
        connection_ids::{ConnectionIdsOf, FirstLocalConnectionId},
        crypto::CryptoReceiveCapacities,
        keys::{HandshakeKeys, InitialKeys},
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
use sakuya_link::{ArrivalFacts, BindingId, LinkId, ReceivedDatagram};
use sakuya_packet_protection_v1::backend::ring::RingBackend;
use sakuya_recovery_v1::packet_number_space::{
    PacketNumberSpaceKind, PacketNumberSpaceState, PacketNumberSpaces,
};
use sakuya_stream_v1::connection::{AbortCause, CloseReason, ImmediateClose, LayerEnd};
use sakuya_wire::{
    connection_id::{ConnectionId, ConnectionIdLength, NonEmptyCid, StatelessResetToken},
    parameters::ParametersPart,
    parts::{CNil, HList, HNil},
    var_int::VarInt,
};
use sakuya_wire_v1::header::VERSION;
use sakuya_wire_v1::{
    frame::set::{FrameSetPart, FrameTypeValues},
    role::Role,
    transport_parameters::TransportParameterSpace,
};
use time::UtcDateTime;

pub(crate) const PATH: SoleLogicalPath = SoleLogicalPath;

/// The Destination Connection ID of the client's first Initial packet.
pub(crate) const CLIENT_DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
/// The client's own connection ID.
pub(crate) const CLIENT_CID: [u8; 8] = [0xc1, 0xc1, 0xc1, 0xc1, 0x01, 0x02, 0x03, 0x04];
/// The server's own connection ID.
pub(crate) const SERVER_CID: [u8; 8] = [0x5e, 0x5e, 0x5e, 0x5e, 0x01, 0x02, 0x03, 0x04];

pub(crate) fn cid(bytes: &[u8; 8]) -> ConnectionId {
    // invariant: eight bytes is a valid connection ID length
    ConnectionId::new(bytes).expect("eight bytes")
}

pub(crate) fn first_local(bytes: &[u8; 8], token: u8) -> FirstLocalConnectionId {
    FirstLocalConnectionId::Issued {
        id: NonEmptyCid::new(cid(bytes)).expect("not empty"),
        reset_token: StatelessResetToken::new([token; 16]),
    }
}

// ---- the certificates ----

/// The certificates and keys of the tests: Ed25519, signed with
/// nitori_crypto_aws_lc.
pub(crate) mod pki {
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
    pub fn verifier(seed: u8, clock: &Arc<ManualClock<TlsSynchronization>>) -> Verifier {
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
pub(crate) fn ready<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("future not ready"),
    }
}

/// 2026-11-04T00:00:00Z, for the validity of the certificates.
pub(crate) fn tls_now() -> UtcDateTime {
    UtcDateTime::UNIX_EPOCH + Duration::from_secs(1_793_750_400)
}

/// The family the TLS stores of the tests keep their shared state in.
pub(crate) type TlsSynchronization = MutexSynchronization;

pub(crate) type Verifier = WebPkiVerifier<
    AwsLcBackend,
    AnchorStore<TlsSynchronization>,
    SpkiDistrustList<TlsSynchronization>,
    NoRevocationCheck,
    EmbeddedSctPolicy<TlsSynchronization>,
    Arc<ManualClock<TlsSynchronization>>,
>;

// ---- the engines and the choices ----

pub(crate) type ServerEngine = ServerHandshake<
    AwsLcBackend,
    PreferenceTable,
    ZeroRttOnceTicketTable<
        &'static str,
        AwsLcBackend,
        Arc<ManualClock<TlsSynchronization>>,
        TlsSynchronization,
        RandomState,
    >,
    PassThroughLayers,
    SniTargets<&'static str>,
    CertifiedKey<Ed25519SigningKey>,
    NoCertificateRequest,
    Arc<ManualClock<TlsSynchronization>>,
    (),
>;

pub(crate) type ClientEngine = ClientHandshake<
    AwsLcBackend,
    PreferenceOffering<TlsSynchronization, RandomState>,
    Arc<TakeOnceTicketMap<Arc<ManualClock<TlsSynchronization>>, TlsSynchronization, RandomState>>,
    Verifier,
    NoClientCertificate,
    Arc<ManualClock<TlsSynchronization>>,
    (),
>;

pub(crate) fn h3() -> ProtocolName<Bytes> {
    ProtocolName::new(Bytes::from_static(b"h3")).unwrap()
}

pub(crate) fn server_engine(clock: &Arc<ManualClock<TlsSynchronization>>) -> ServerEngine {
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
pub(crate) fn client_engine(
    clock: &Arc<ManualClock<TlsSynchronization>>,
    root_seed: u8,
) -> ClientEngine {
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

/// The choices `$name` of the side `$side`, whose receiver of the
/// connection's events is `$events`, with the send strategy `$strategy`
/// (by default the ranked one) and the stream sets `$streams` (by default
/// the owned ones).
macro_rules! choices {
    ($name:ident, $side:ty, $events:ty) => {
        choices!(
            $name,
            $side,
            $events,
            sakuya_connection::send_strategy::ranked::RankedSendStrategy<I>
        );
    };
    ($name:ident, $side:ty, $events:ty, $strategy:ty) => {
        choices!(
            $name,
            $side,
            $events,
            $strategy,
            sakuya_connection::v1::streams::owned::OwnedStreamSetFamily
        );
    };
    ($name:ident, $side:ty, $events:ty, $strategy:ty, $streams:ty) => {
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
            type Events<L> = $events;
            type Streams = $streams;
        }
    };
}

// ---- what the tests look at ----

thread_local! {
    /// What each side's watch noted last: the server's first.
    pub(crate) static NOTED: RefCell<[Noted; 2]> = RefCell::new([Noted::default(), Noted::default()]);
    /// The token the client of the next run starts with; empty for none.
    pub(crate) static CLIENT_TOKEN: RefCell<Bytes> = const { RefCell::new(Bytes::new()) };
    /// How many of the first datagrams the client of the next run sends
    /// the link loses, as the network would: they are sent and never
    /// arrive.
    pub(crate) static CLIENT_DATAGRAMS_LOST: Cell<usize> = const { Cell::new(0) };
    /// The datagrams the client of the next run sends that the link loses
    /// besides those, by their index among all it sends.
    pub(crate) static CLIENT_DATAGRAMS_LOST_AT: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
    /// How many of the first datagrams the server of the next run sends
    /// the link loses.
    pub(crate) static SERVER_DATAGRAMS_LOST: Cell<usize> = const { Cell::new(0) };
    /// For how many milliseconds the link of the next run holds the
    /// datagrams that arrive before the server's connection is made.
    pub(crate) static FIRST_FLIGHT_DELAY_MS: Cell<u64> = const { Cell::new(0) };
    /// Whether the server of the next run reads its first flight before
    /// its connection is made, as an endpoint that decides first does.
    pub(crate) static SERVER_READS_FIRST: Cell<bool> = const { Cell::new(false) };
    /// Whether the endpoint of the next run's server validated the
    /// client's address before the connection, as a Retry would: the
    /// anti-amplification limit does not hold the server back.
    pub(crate) static SERVER_ADDRESS_VALIDATED: Cell<bool> = const { Cell::new(false) };
}

/// What the watch of one side noted.
#[derive(Debug, Default, Clone)]
pub(crate) struct Noted {
    pub(crate) confirmed: bool,
    pub(crate) initial_keys: String,
    pub(crate) handshake_keys: String,
    /// The record of why the connection closed, as it shows.
    pub(crate) record: Option<String>,
    /// The alert this side's handshake failed with.
    pub(crate) alert: Option<u8>,
    /// The close the peer sent.
    pub(crate) peer_close: Option<ImmediateClose>,
    /// What only this side has, as it shows.
    pub(crate) own: String,
    /// The exporter the connection keeps, as it shows.
    pub(crate) exporter: String,
    /// The packet number spaces the logical path keeps.
    pub(crate) spaces: Vec<PacketNumberSpaceKind>,
    /// Whether the established layer was built with its stream set.
    pub(crate) streams: bool,
    /// How many of this side's connection IDs the logical path's local
    /// connection ID strategy keeps active.
    pub(crate) local_connection_ids: usize,
    /// How many of the peer's connection IDs the logical path's destination
    /// connection ID strategy offers for its first link path.
    pub(crate) offered_connection_ids: usize,
}

pub(crate) fn index(role: Role) -> usize {
    match role {
        Role::Server => 0,
        Role::Client => 1,
    }
}

pub(crate) fn noted(role: Role) -> Noted {
    NOTED.with(|n| n.borrow()[index(role)].clone())
}

pub(crate) fn note(role: Role, change: impl FnOnce(&mut Noted)) {
    NOTED.with(|n| change(&mut n.borrow_mut()[index(role)]));
}

pub(crate) mod watch {
    use super::*;

    /// The part that notes what the tests look at; it has nothing else.
    pub struct Part;
    impl LogicalPathKeyShare for Part {
        type Fields = HNil;
    }
    impl<L> sakuya_connection::error::ConnectionErrorPart<L> for Part {
        type ConnectionError = core::convert::Infallible;
    }
    impl sakuya_stream_v1::resets::StreamResetsPart for Part {
        type Fold<Prev: sakuya_stream_v1::resets::StreamResets> = Prev;
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
        v1::send::SendTypes<T, L>: v1::send_planning::HostSendStrategyTypes,
        v1::StreamSetFamilyOf<T>: v1::send_planning::ComponentPublishing<
                v1::send::SendTypes<T, L>,
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
pub(crate) type Datagram = ReceivedDatagram<BytesMut, TestLink>;
/// What routing gives a deliverer of the tests.
pub(crate) type Delivery =
    DatagramDelivery<Datagram, (), sakuya_datagram_routing::claim::finish::ReleaseUnclaimed>;
/// The deliverers of the tests' routing domains.
pub(crate) type Target = dyn ErasedDatagramDeliverer<Datagram, ()>;

/// A deliverer that posts to a connection's receiver.
pub(crate) struct Posting(RefCellDatagramDeliveryPoster<Delivery>);
impl DatagramDeliverer<Datagram, ()> for Posting {
    fn deliver(&self, delivery: Delivery) {
        self.0.post(delivery);
    }
}

/// The routing domain of one side: an entry for each of its connection
/// IDs, posting to the receiver of its connection's first logical path.
pub(crate) struct Routing {
    pub(crate) router: DatagramRouter<
        BytesMut,
        TestLink,
        HashMapRouteIndex<Target, (), std::hash::RandomState>,
        ConnectionIdLengths,
        common::TestResetTokenRegistry,
    >,
    pub(crate) reset_tokens: common::TestResetTokenRegistry,
    pub(crate) _registrations:
        Vec<HashMapRouteEntryRegistration<Target, (), std::hash::RandomState>>,
}

impl Routing {
    /// A routing domain for `ids`, and the receiver it posts to.
    pub(crate) fn new(ids: &[ConnectionId]) -> (Self, TestReceiver) {
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
                        VERSION,
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
    pub(crate) fn deliver(&self, payload: Bytes, link: &LinkId<(), ()>) {
        self.router.route(arrived(payload, link));
    }
}

pub(crate) fn arrived(payload: Bytes, link: &LinkId<(), ()>) -> Datagram {
    ReceivedDatagram::new(
        BytesMut::from(&payload[..]),
        ArrivalFacts::new(TestLink(link.clone()), now(), None),
    )
}

pub(crate) fn link() -> LinkId<(), ()> {
    LinkId::new::<()>((), (), &BindingId::new())
}

/// The capacities of the CRYPTO data a server receives: the least the
/// default message limits allow.
pub(crate) fn server_capacities() -> CryptoReceiveCapacities {
    CryptoReceiveCapacities::server(MessageLimits::default(), false, 16 * 1024 + 4, 4096)
        .expect("the least capacities the limits allow")
}

/// The capacities of the CRYPTO data a client receives.
pub(crate) fn client_capacities() -> CryptoReceiveCapacities {
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
pub(crate) struct Later<D>(pub(crate) Option<D>);

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
pub(crate) fn starts_with_initial(datagram: &[u8]) -> bool {
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
        sakuya_recovery_v1::factory::RecoveryFactory<TestLink, Config: Default>,
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
    /// The datagrams the server sent, in order, each with when it was
    /// sent and whether the link lost it.
    #[allow(dead_code, reason = "not every harness's tests look at them")]
    server_sent: Vec<(Duration, Bytes, bool)>,
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
    clock: &Arc<ManualClock<TlsSynchronization>>,
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
        if SERVER_ADDRESS_VALIDATED.with(Cell::get) {
            AddressValidation::Validated
        } else {
            AddressValidation::NotValidated
        },
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
    let lost_at = |index: usize| CLIENT_DATAGRAMS_LOST_AT.with(|at| at.borrow().contains(&index));
    for (index, datagram) in first.into_iter().enumerate() {
        if !lost_at(index) {
            lose(datagram, &mut waiting);
        }
    }
    let mut run = Run {
        client_sent: first_sent,
        server_sent: Vec::new(),
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
            if server.is_none()
                && !waiting.is_empty()
                && now() >= ms(FIRST_FLIGHT_DELAY_MS.with(Cell::get))
            {
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
                let lost = SERVER_DATAGRAMS_LOST.with(|lost| {
                    let loses = lost.get() > 0;
                    lost.set(lost.get().saturating_sub(1));
                    loses
                });
                run.server_sent.push((now(), datagram.clone(), lost));
                if !lost {
                    client_routing.deliver(datagram, &client_link);
                }
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
                let index = run.client_sent.len();
                run.client_sent.push(datagram.clone());
                if lost_at(index) {
                    continue;
                }
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

pub(crate) fn tls_clock() -> Arc<ManualClock<TlsSynchronization>> {
    Arc::new(ManualClock::new(tls_now()))
}

/// The output of `future` if it is ready on its first poll.
pub(crate) fn poll_now<F: Future>(future: F) -> Poll<F::Output> {
    pin!(future).poll(&mut Context::from_waker(Waker::noop()))
}

/// A waker that counts how often it was woken.
#[derive(Default)]
pub(crate) struct Wakes(std::sync::atomic::AtomicUsize);

impl std::task::Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// A future kept across the harness's calls, polled with a waker of its
/// own that counts its wakes.
pub(crate) struct Waiting<F: Future> {
    pub(crate) future: core::pin::Pin<Box<F>>,
    pub(crate) wakes: Arc<Wakes>,
}

impl<F: Future> Waiting<F> {
    pub(crate) fn new(future: F) -> Self {
        Self {
            future: Box::pin(future),
            wakes: Arc::default(),
        }
    }

    pub(crate) fn poll(&mut self) -> Poll<F::Output> {
        let waker = Waker::from(Arc::clone(&self.wakes));
        self.future.as_mut().poll(&mut Context::from_waker(&waker))
    }

    /// How often its waker was woken.
    pub(crate) fn wakes(&self) -> usize {
        self.wakes.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Whether `end` is the end of a layer whose driver panicked.
pub(crate) fn panicked<C>(end: &LayerEnd<C>) -> bool {
    matches!(
        end,
        LayerEnd::ConnectionClosed(CloseReason::Aborted(AbortCause::Panicked))
    )
}
