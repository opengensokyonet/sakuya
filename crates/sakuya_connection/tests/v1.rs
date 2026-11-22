//! Version 1's components on the tree: what the connection is made with,
//! the entries of its logical links and the roles of its link paths.
#![feature(impl_trait_in_assoc_type, yield_expr)]
#![allow(
    clippy::arc_with_non_send_sync,
    reason = "the tests' routing domains are on one thread; deliverers are given as `Arc`s"
)]

mod common;

use sakuya_connection::role::LinkPathRoleChanged;
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    fmt::Debug,
    num::NonZeroUsize,
    sync::Arc,
    time::Duration,
};

use bytes::BytesMut;
use common::{
    Mine, Outer, TestClock, TestLink, TestReceiver, advance_to, log, ms,
    strategy::take_strategy_events, take_log,
};
use frunk_core::coproduct::CoproductSelector;
use frunk_core::hlist_pat;
use nitori_crypto::{AeadAlgorithm, HashAlgorithm};
use nitori_tls::schedule::TrafficSecret;
use nitori_tls::{engine::CryptoLevel, message::MessageLimits};
use sakuya_connection::v1::{HostChoices, HostOf};
use sakuya_connection::{
    call::CallBundle,
    clock::{ConnectionChoices, InstantOf},
    component::{ArgsOf, Build, DataComponent, LineageOf, ParentsOf, RequestOf},
    component_event::{EventSubscriptions, Happened, NodeStarted, TriggeredEvents},
    connection_id::DestinationConnectionIdStrategy as _,
    dispatch::{DispatchFacts, FrameDispatch, FrameSetDispatch},
    error::ConnectionErrorsOf,
    feedback::InjectSummary,
    frame_source::{FindFrameSource, FrameSource, FrameSourceKind},
    layer::{self, EstablishedArgs, LinkPathArgs, LogicalPathArgs, NodeKey},
    others::OtherNodes,
    request::StructureRequest,
    role::LinkPathRole,
    share::{
        FlatMut, FlatRef, LayerShare, LineageLists, LineagePartList, LinkPathIdentifierOf,
        LogicalPathKeyShare, LogicalPathKeys, NodeData, SoleLogicalPath,
    },
    take::{GetAt, Lineage, Take, TakeEach},
    v1::{
        self, CloseCauseOf,
        aead_usage::AeadUsage,
        amplification::{AddressValidation, AntiAmplification, AntiAmplificationFactor},
        application_handles::connection::ConnectionHandle,
        close::{CloseReasonRecord, LocalCloseCause},
        close_request::CloseRequestCell,
        component_events::{
            AckPendingChanged, AckReceived, CongestionChanged, DestinationConnectionIdsChanged,
            KeysDiscarded, KeysInstalled, PacketsLost, PacketsSent, RttSampled, SpaceRetired,
            level,
        },
        confirmation::HandshakeConfirmation,
        crypto::{
            CryptoReceiveCapacities, CryptoReceiver, FragmentedCryptoReceiveBuffer,
            send::{CryptoSender, OffsetMapCryptoSendBuffer},
        },
        ecn::LinkPathEcnState,
        feedback::AckSummary,
        first_flight::{
            FirstFlight, FirstFlightReadState, PacketLayout, ReadFirstFlightError,
            read_first_flight,
        },
        idle::IdleTimeout,
        input::{InitialPathReceiver, LogicalPathInput},
        key_phase::KeyPhaseNumbers,
        keys::{DirectionKeys, HandshakeKeys, InitialKeys, KeyGeneration, LevelKeys, OneRttKeys},
        link::LinkFacts,
        loss_detection::LossDetectionOf,
        parameters::PeerTransportParameters,
        pto::ProbeTimeout,
        receive::{DropReason, PacketOutcome, ReceivedPacket, receive_packet},
        recovery::{
            CongestionPartOf, LinkPathCongestionState, RecoveryFactoryOf, RttOf, lend_congestion,
        },
        spaces::{AckObligationsOf, SendJournalsOf},
    },
};
use sakuya_datagram_routing_v1::{
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
        router::DatagramRouter,
    },
};
use sakuya_link::{
    ArrivalFacts, BindingId, EcnMarking, LinkId, MIN_DATAGRAM_SIZE, ReceivedDatagram,
};
use sakuya_packet_protection_ring::RingBackend;
use sakuya_packet_protection_v1::{
    header_protection::HeaderProtectionKey,
    initial::{INITIAL_AEAD, InitialSecrets},
};
use sakuya_recovery_v1::{
    ack_obligation::AckObligation,
    congestion::CongestionController,
    factory::{NewRenoRecoveryFactory, NewRenoRecoveryFactoryConfig, RecoveryFactory},
    loss::{LossThresholds, loss_delay},
    loss_detection::InFlightCharge,
    pacing::{Pacer, PacingInput},
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaceState, PacketNumberSpaces},
    pto::probe_timeout,
    receive_journals::{MaxAckRanges, ReceiveJournals},
    rtt::{RttEstimator, RttSample},
    send_journals::{PacketSendAttempt, SendJournals},
};
use sakuya_stream_v1::connection::CloseReason;
use sakuya_wire::parts::{
    CNil, CoprodInjector, CoprodUninjector, Coproduct, HList, HNil, PartsError, Selector,
};
use sakuya_wire_v1::header::VERSION;
use sakuya_wire_v1::{
    connection_id::{ConnectionId, ConnectionIdLength, NonEmptyCid},
    parameters::ParametersPart,
    var_int::VarInt,
};
use sakuya_wire_v1::{
    frame::{
        FrameType,
        set::{FrameSet, FrameSetPart, FrameTypeValues},
    },
    packet_number::PacketNumber,
    protected_packet::{Packet, into_packets},
    transport_parameters::{
        TransportParameterSlots, TransportParameterSpace, TransportParameters,
        integer::MaxIdleTimeout,
    },
};

const PATH: SoleLogicalPath = SoleLogicalPath;

/// When a recovery layer moves, from the link path over the first logical
/// link to the one over the second.
type Move = (Duration, LinkId<(), ()>, LinkId<(), ()>);

thread_local! {
    /// When the probe asks for a link path over a second logical link.
    static ADD: Cell<Option<(Duration, LinkId<(), ()>)>> = const { Cell::new(None) };
    /// When the probe of each link path built from now on closes its role.
    static CLOSE_AT: Cell<Option<Duration>> = const { Cell::new(None) };
    /// Whether that probe puts its role into `Draining` instead.
    static DRAIN: Cell<bool> = const { Cell::new(false) };
    /// When the probe sets the peer's maximum idle timeout to 10 s and
    /// processes a packet, as the calls will.
    static PEER_AT: Cell<Option<Duration>> = const { Cell::new(None) };
    /// When the probe of a spying connection makes its second link path
    /// active, and when it then lends the first one's congestion access.
    static LEND_AT: Cell<Option<(Duration, Duration)>> = const { Cell::new(None) };
    /// What the feeder of the first recovery layer of a server does, and
    /// when.
    static FEED: RefCell<VecDeque<(Duration, probe::Step)>> = const { RefCell::new(VecDeque::new()) };
    /// What the closer of the next server connection does, and when.
    static CLOSER: RefCell<VecDeque<(Duration, probe::CloserStep)>> = const { RefCell::new(VecDeque::new()) };
    /// When the probe of a server connection hands CRYPTO frames to the
    /// connection's CRYPTO receiver, as the calls will.
    static CRYPTO_AT: Cell<Option<Duration>> = const { Cell::new(None) };
    /// When the probe of a server connection writes its ServerHello's
    /// stand-in into the connection's CRYPTO output, as the handshake
    /// engine will.
    static CRYPTO_WRITE_AT: Cell<Option<Duration>> = const { Cell::new(None) };
    /// How many bytes that stand-in has: `server hello` when 0.
    static CRYPTO_WRITE_LEN: Cell<usize> = const { Cell::new(0) };
    /// What the packet feeder of the next server connection's logical path
    /// does, and when.
    static PACKETS: RefCell<VecDeque<(Duration, probe::PacketStep)>> = const { RefCell::new(VecDeque::new()) };
    /// How many ACK ranges the receive journals of the next connection keep.
    static MAX_ACK_RANGES: Cell<MaxAckRanges> = const { Cell::new(MaxAckRanges::DEFAULT) };
    /// After how many packets sealed with one generation the next
    /// connection initiates a 1-RTT key update, besides the limit.
    static KEY_UPDATE_AFTER: Cell<Option<core::num::NonZeroU64>> = const { Cell::new(None) };
    /// How many inputs the receiving call of the next connection handles in
    /// one poll.
    static MAX_PER_POLL: Cell<usize> = const { Cell::new(16) };
    /// How many inputs a logical path of the next connection holds.
    static MAX_HELD: Cell<usize> = const { Cell::new(16) };
    /// How many datagrams the sending call of a link path of the next
    /// connection hands to its link at once.
    static MAX_PER_SEND: Cell<usize> = const { Cell::new(16) };
    /// The first datagrams the next connection is made with.
    static FIRST_DATAGRAMS: RefCell<Vec<Datagram>> = const { RefCell::new(Vec::new()) };
    /// Whether the next connection is made with a first flight read before
    /// it was made, as a server that decides before answering makes it.
    static FIRST_READ: Cell<bool> = const { Cell::new(false) };
    /// What reading the first flight left, for the next connection made
    /// with a first flight read; nothing read when there is none.
    static READ_STATE: RefCell<Option<Box<dyn core::any::Any>>> = const { RefCell::new(None) };
    /// Whether the routing domain of the next connection has a rival entry
    /// for the same connection ID, so that every datagram is a competing
    /// candidate.
    static RIVAL: Cell<bool> = const { Cell::new(false) };
    /// The routing domain of the last connection made.
    static ROUTING: RefCell<Option<TestRouting>> = const { RefCell::new(None) };
    /// The last line the feeder of a recovery layer logged.
    static LAST_STATUS: RefCell<Option<String>> = const { RefCell::new(None) };
    /// The cell the application of the last connection made asks to close
    /// it through.
    static CLOSE_REQUEST: RefCell<Option<CloseRequestCell<common::AppClose>>> = const { RefCell::new(None) };
    /// When the probe asks for the recovery layer of the link path over the
    /// first logical link to move to the one over the second.
    static MOVE: Cell<Option<Move>> = const { Cell::new(None) };
    /// Whether the routing domain of the next connection routes this side's
    /// own connection ID to it too.
    static ROUTE_SERVER_CID: Cell<bool> = const { Cell::new(false) };
    /// What the probe's part has to send, as the driver's own content, until
    /// its frame source is given it.
    static FILLERS: RefCell<Vec<probe::FillerIntent>> = const { RefCell::new(Vec::new()) };
}

/// The parts of the tests' connections.
type Parts = HList![v1::Part, probe::Part];
sakuya_connection::composition!(impl for Mine: Mine, Parts);
sakuya_connection::composition!(impl for ClientMine: ClientMine, Parts);
sakuya_connection::composition!(impl for SpyMine: SpyMine, Parts);

fn link() -> LinkId<(), ()> {
    LinkId::new::<()>((), (), &BindingId::new())
}

fn reset() {
    take_log();
    take_strategy_events();
    common::strategy::forget_stale_overheads();
    common::strategy::plan_normally();
    advance_to(ms(0));
    common::set_accepted_after(Duration::ZERO);
    ADD.with(|a| a.set(None));
    CLOSE_AT.with(|c| c.set(None));
    DRAIN.with(|d| d.set(false));
    PEER_AT.with(|p| p.set(None));
    LEND_AT.with(|p| p.set(None));
    FEED.with(|f| f.borrow_mut().clear());
    CLOSER.with(|c| c.borrow_mut().clear());
    CRYPTO_AT.with(|c| c.set(None));
    CRYPTO_WRITE_AT.with(|c| c.set(None));
    CRYPTO_WRITE_LEN.with(|c| c.set(0));
    PACKETS.with(|p| p.borrow_mut().clear());
    MAX_ACK_RANGES.with(|m| m.set(MaxAckRanges::DEFAULT));
    KEY_UPDATE_AFTER.with(|k| k.set(None));
    MAX_PER_POLL.with(|m| m.set(16));
    MAX_HELD.with(|m| m.set(16));
    MAX_PER_SEND.with(|m| m.set(16));
    FIRST_DATAGRAMS.with(|f| f.borrow_mut().clear());
    FIRST_READ.with(|f| f.set(false));
    READ_STATE.with(|r| r.borrow_mut().take());
    RIVAL.with(|r| r.set(false));
    ROUTING.with(|r| r.borrow_mut().take());
    LAST_STATUS.with(|l| l.borrow_mut().take());
    CLOSE_REQUEST.with(|c| c.borrow_mut().take());
    FILLERS.with(|f| f.borrow_mut().clear());
    MOVE.with(|m| m.set(None));
    ROUTE_SERVER_CID.with(|r| r.set(false));
    common::reset_migration();
    common::take_used_by_peer();
    common::reset_links();
    common::set_new_token_issuing(true);
    common::reset_close_policy();
}

/// The cell the application of the last connection made asks to close it
/// through.
fn close_request() -> CloseRequestCell<common::AppClose> {
    CLOSE_REQUEST
        .with(|c| c.borrow().clone())
        .expect("a connection was made")
}

/// A datagram of the tests, as it arrived.
type Datagram = ReceivedDatagram<BytesMut, TestLink>;
/// What routing gives a deliverer of the tests.
type Delivery =
    DatagramDelivery<Datagram, (), sakuya_datagram_routing_v1::claim::finish::ReleaseUnclaimed>;
/// The deliverers of the tests' routing domain.
type Target = dyn ErasedDatagramDeliverer<Datagram, ()>;

/// A deliverer that posts to a connection's receiver.
struct Posting(RefCellDatagramDeliveryPoster<Delivery>);
impl DatagramDeliverer<Datagram, ()> for Posting {
    fn deliver(&self, delivery: Delivery) {
        self.0.post(delivery);
    }
}

/// A routing domain with one route entry, the client's first Destination
/// Connection ID, for every packet form; it reads short headers with
/// 8-byte connection IDs, and detects stateless resets by the tokens the
/// connection registers.
struct TestRouting {
    router: DatagramRouter<
        BytesMut,
        TestLink,
        HashMapRouteIndex<Target, (), std::hash::RandomState>,
        ConnectionIdLengths,
        common::TestResetTokenRegistry,
    >,
    /// Where the connection registers the reset tokens of the peer's
    /// connection IDs, which the router detects resets by.
    reset_tokens: common::TestResetTokenRegistry,
    _registration: HashMapRouteEntryRegistration<Target, (), std::hash::RandomState>,
    /// The entry of this side's own connection ID, when it is routed too.
    _own: Option<HashMapRouteEntryRegistration<Target, (), std::hash::RandomState>>,
    /// When there is a rival: its entry for the same connection ID, and
    /// its receiver, which keeps every candidate it is given and never
    /// judges one.
    _rival: Option<(
        HashMapRouteEntryRegistration<Target, (), std::hash::RandomState>,
        TestReceiver,
    )>,
}

/// The receiver of the initial path of a connection about to be made,
/// registered in a new routing domain that [`deliver`] routes into.
fn initial_receiver() -> InitialPathReceiver<TestReceiver> {
    InitialPathReceiver::new(test_receiver())
}

/// A receiver registered in a new routing domain that [`deliver`] routes
/// into.
fn test_receiver() -> TestReceiver {
    // invariant: 64 is within the largest capacity
    let queue = RefCellDatagramDeliveryQueue::new(NonZeroUsize::new(64).expect("not zero"))
        .expect("a capacity a queue can have");
    let index = HashMapRouteIndex::<Target, (), std::hash::RandomState>::new();
    let registration = index.register(
        RouteMatcher::new(
            MatchAssociation::LocalCid(NonEmptyCid::new(client_dcid()).expect("not empty")),
            PacketForms::ALL,
            VERSION,
        ),
        Arc::new(Posting(queue.poster())) as Arc<Target>,
    );
    let own = ROUTE_SERVER_CID.with(Cell::get).then(|| {
        index.register(
            RouteMatcher::new(
                MatchAssociation::LocalCid(NonEmptyCid::new(server_cid()).expect("not empty")),
                PacketForms::ALL,
                VERSION,
            ),
            Arc::new(Posting(queue.poster())) as Arc<Target>,
        )
    });
    let rival = RIVAL.with(Cell::get).then(|| {
        let queue = RefCellDatagramDeliveryQueue::new(NonZeroUsize::new(64).expect("not zero"))
            .expect("a capacity a queue can have");
        let registration = index.register(
            RouteMatcher::new(
                MatchAssociation::LocalCid(NonEmptyCid::new(client_dcid()).expect("not empty")),
                PacketForms::ALL,
                VERSION,
            ),
            Arc::new(Posting(queue.poster())) as Arc<Target>,
        );
        (registration, queue)
    });
    let reset_tokens = <common::TestResetTokenRegistry as sakuya_datagram_routing_v1::route::reset::StatelessResetTokens<_, _>>::new();
    let router = DatagramRouter::new(
        index,
        ConnectionIdLengths::new([ConnectionIdLength::new(8).expect("a length")]),
    )
    .with_stateless_reset(reset_tokens.clone());
    ROUTING.with(|r| {
        *r.borrow_mut() = Some(TestRouting {
            router,
            reset_tokens,
            _registration: registration,
            _own: own,
            _rival: rival,
        });
    });
    queue
}

/// Route `datagram`, arrived over `link` at `at`, in the routing domain of
/// the last connection made.
fn deliver(datagram: BytesMut, link: &LinkId<(), ()>, at: Duration) {
    let datagram = ReceivedDatagram::new(
        datagram,
        ArrivalFacts::new(TestLink(link.clone()), at, None),
    );
    ROUTING.with(|r| {
        r.borrow()
            .as_ref()
            .expect("a connection was made")
            .router
            .route(datagram);
    });
}

/// The choices of a client: the tests' clock and link, version 1 as the
/// client.
struct ClientMine;
impl ConnectionChoices for ClientMine {
    type Clock = TestClock;
    type Link = TestLink;
}
impl v1::MakerChoices for ClientMine {
    type Crypto = RingBackend;
    type Side = v1::Client<common::PendingClientEngine, (), v1::retry::ContinueOnRetry, ()>;
    type Receiver = TestReceiver;
    type ResetTokenRegistry = common::TestResetTokenRegistry;
    type ConnectionIdIssuer = common::TestConnectionIdIssuer;
}
impl v1::Choices for ClientMine {
    type Host = Self;
}
impl v1::HostChoices<ClientMine> for ClientMine {
    type ApplicationError = common::AppClose;
    type DestinationConnectionIds = common::TestDestinationConnectionIds;
    type LocalConnectionIds = common::TestLocalConnectionIds;
    type ImmediateClosePolicy = common::TestImmediateClosePolicy;
    type MigrationPolicy = common::TestMigrationPolicy;
}

/// The choices of a server whose recovery factory logs the other link
/// paths it is shown when it lends.
struct SpyMine;
impl ConnectionChoices for SpyMine {
    type Clock = TestClock;
    type Link = TestLink;
}
impl v1::MakerChoices for SpyMine {
    type Crypto = RingBackend;
    type Side = v1::Server<common::PendingServerEngine, common::TestNewTokenIssuer>;
    type Receiver = TestReceiver;
    type ResetTokenRegistry = common::TestResetTokenRegistry;
    type ConnectionIdIssuer = common::TestConnectionIdIssuer;
}
impl v1::Choices for SpyMine {
    type Host = Self;
}
impl v1::HostChoices<SpyMine> for SpyMine {
    type Recovery<V: Clone + Eq + Debug + 'static> = spy::SpyFactory<V>;
    type ApplicationError = common::AppClose;
    type DestinationConnectionIds = common::TestDestinationConnectionIds;
    type LocalConnectionIds = common::TestLocalConnectionIds;
    type ImmediateClosePolicy = common::TestImmediateClosePolicy;
    type MigrationPolicy = common::TestMigrationPolicy;
}

/// A recovery factory that makes what sakuya's makes and logs, when it
/// lends, the other link paths it sees.
mod spy {
    use super::*;
    use sakuya_connection::v1::recovery::OtherCongestionParts;
    use sakuya_link::EcnMarking;
    use sakuya_recovery_v1::{
        congestion::{
            CongestionContext, CongestionController, InFlightPacket, RemovedPacket, SealedPacket,
            SpuriouslyLostPacket,
        },
        ecn::{EcnContext, EcnPolicy},
        factory::{LendCongestion, PacedNewReno, RecoveryFactory},
        pto::{PtoAction, PtoExpiry, PtoPolicy},
    };

    #[derive(Debug)]
    pub struct SpyFactory<V>(NewRenoRecoveryFactory<V>);
    impl<V> RecoveryFactory<TestLink> for SpyFactory<V> {
        type Config = NewRenoRecoveryFactoryConfig;
        type Via = V;
        type Rtt = <NewRenoRecoveryFactory<V> as RecoveryFactory<TestLink>>::Rtt;
        type CongestionPart = PacedNewReno<Duration>;
        type Pmtu = <NewRenoRecoveryFactory<V> as RecoveryFactory<TestLink>>::Pmtu;
        fn new(config: &NewRenoRecoveryFactoryConfig) -> Self {
            Self(RecoveryFactory::<TestLink>::new(config))
        }
        fn create(
            &mut self,
            link: &TestLink,
            initial_rtt: Option<Duration>,
        ) -> (Self::Rtt, Self::CongestionPart, Self::Pmtu) {
            self.0.create(link, initial_rtt)
        }
    }
    impl<'s, V, K: Debug>
        LendCongestion<
            Duration,
            OtherCongestionParts<'s, K, LinkId<(), ()>, PacedNewReno<Duration>>,
        > for SpyFactory<V>
    {
        type Part = PacedNewReno<Duration>;
        type SentState = <PacedNewReno<Duration> as CongestionController<Duration>>::SentState;
        type LossState = <PacedNewReno<Duration> as CongestionController<Duration>>::LossState;
        type Access<'a>
            = Logged<'a>
        where
            Self: 'a,
            's: 'a;
        fn lend<'a>(
            &'a mut self,
            this: &'a mut PacedNewReno<Duration>,
            others: &'a OtherCongestionParts<'s, K, LinkId<(), ()>, PacedNewReno<Duration>>,
        ) -> Logged<'a> {
            others.each(|key, _, rtt| {
                log(format!("lent beside {key:?}, smoothed {:?}", rtt.smoothed))
            });
            Logged(this)
        }
        fn next_deadline(&self, this: &PacedNewReno<Duration>) -> Option<Duration> {
            LendCongestion::<Duration, ()>::next_deadline(&self.0, this)
        }
    }

    /// What the spy lends: sakuya's controller, logging the events of
    /// congestion control as it hears of them.
    pub struct Logged<'a>(&'a mut PacedNewReno<Duration>);
    impl CongestionController<Duration> for Logged<'_> {
        type SentState = ();
        type LossState = ();
        fn window(&self) -> usize {
            self.0.window()
        }
        fn on_packet_sealed(&mut self, packet: &SealedPacket<Duration>) {
            self.0.on_packet_sealed(packet);
        }
        fn on_spurious_loss(
            &mut self,
            loss: (),
            packets: impl Iterator<Item = SpuriouslyLostPacket<Duration>>,
            context: &CongestionContext<Duration>,
        ) {
            let packets: Vec<_> = packets.collect();
            log(format!(
                "congestion: spurious {:?}",
                packets.iter().map(|p| p.sent_at).collect::<Vec<_>>()
            ));
            self.0.on_spurious_loss(loss, packets.into_iter(), context);
        }
        fn on_ce(
            &mut self,
            increase: u64,
            reference_sent_at: Duration,
            context: &CongestionContext<Duration>,
        ) {
            self.0.on_ce(increase, reference_sent_at, context);
        }
        fn on_lost(
            &mut self,
            packets: impl Iterator<Item = InFlightPacket<Duration, ()>>,
            context: &CongestionContext<Duration>,
        ) {
            let packets: Vec<_> = packets.collect();
            log(format!(
                "congestion: lost {} bytes, {} in flight",
                packets.iter().map(|p| p.bytes).sum::<usize>(),
                context.bytes_in_flight
            ));
            self.0.on_lost(packets.into_iter(), context);
        }
        fn on_persistent_congestion(&mut self, context: &CongestionContext<Duration>) {
            log("congestion: persistent");
            self.0.on_persistent_congestion(context);
        }
        fn wants_recovery_send(&mut self) -> bool {
            self.0.wants_recovery_send()
        }
        fn on_acked(
            &mut self,
            packets: impl Iterator<Item = InFlightPacket<Duration, ()>>,
            context: &CongestionContext<Duration>,
        ) {
            let packets: Vec<_> = packets.collect();
            log(format!(
                "congestion: acked {} bytes, {} in flight, sampled {}",
                packets.iter().map(|p| p.bytes).sum::<usize>(),
                context.bytes_in_flight,
                context.rtt_sampled
            ));
            self.0.on_acked(packets.into_iter(), context);
        }
        fn on_removed(
            &mut self,
            packets: impl Iterator<Item = RemovedPacket<()>>,
            context: &CongestionContext<Duration>,
        ) {
            let packets: Vec<_> = packets.collect();
            log(format!(
                "congestion: removed {} bytes, {} in flight",
                packets.iter().map(|p| p.bytes).sum::<usize>(),
                context.bytes_in_flight
            ));
            self.0.on_removed(packets.into_iter(), context);
        }
        fn on_max_datagram_size_changed(
            &mut self,
            new: usize,
            handshake_confirmed: bool,
            context: &CongestionContext<Duration>,
        ) {
            log(format!(
                "size in use {new}, handshake confirmed {handshake_confirmed}"
            ));
            self.0
                .on_max_datagram_size_changed(new, handshake_confirmed, context);
        }
    }
    impl Pacer<Duration> for Logged<'_> {
        fn next_release(&self) -> Option<Duration> {
            self.0.next_release()
        }
        fn allowance(&self) -> usize {
            self.0.allowance()
        }
        fn refill(&mut self, at: Duration, input: PacingInput) -> bool {
            self.0.refill(at, input)
        }
        fn on_charged(&mut self, bytes: usize) {
            self.0.on_charged(bytes);
        }
    }
    impl PtoPolicy<Duration> for Logged<'_> {
        fn on_pto_expired(&mut self, expiry: &PtoExpiry<Duration>) -> PtoAction {
            log("PTO policy consulted");
            self.0.on_pto_expired(expiry)
        }
        fn on_duplicate_initial_crypto(&mut self) -> bool {
            self.0.on_duplicate_initial_crypto()
        }
    }
    impl EcnPolicy<Duration> for Logged<'_> {
        fn marking(&mut self, context: &EcnContext<Duration>) -> EcnMarking {
            self.0.marking(context)
        }
        fn wants_revalidation(&mut self, context: &EcnContext<Duration>) -> bool {
            self.0.wants_revalidation(context)
        }
    }
}

/// A probe part: it logs what version 1 built and changes what a test
/// needs changed.
mod probe {
    use super::*;

    pub struct Part;
    impl LogicalPathKeyShare for Part {
        type Fields = HNil;
    }
    impl<L> sakuya_connection::error::ConnectionErrorPart<L> for Part {
        type ConnectionError = core::convert::Infallible;
    }
    impl sakuya_stream_sets::resets::StreamResetsPart for Part {
        type Fold<Prev: sakuya_stream_sets::resets::StreamResets> = Prev;
    }
    impl ParametersPart<TransportParameterSpace> for Part {
        type Parameters = HNil;
    }

    /// The summary of a frame the probe writes, as the tests number it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Summary(pub u64);

    /// The probe's frame source, the only one of its part.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum FrameSourceId {
        /// The frames the probe writes.
        Frames,
    }

    /// Content the probe has to send in Initial packets, as the driver's
    /// own: `len` PING frames, which it needs room for in the last position
    /// and `length_field` bytes more for any other (the Length field of a
    /// frame that goes on to the end), unless it `writes` nothing when it
    /// is given its turn. It ranks
    /// among the control frames, and holds its place when `holds_place`.
    /// Once given to its frame source it is gone.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FillerIntent {
        pub id: u8,
        pub len: usize,
        pub length_field: usize,
        pub holds_place: bool,
        pub writes: bool,
    }
    impl sakuya_connection::send_strategy::SendIntent for FillerIntent {
        type FrameSourceId = FrameSourceId;
        type Class = sakuya_wire_v1::frame::write::InFlightClass;
        fn frame_source(&self) -> FrameSourceId {
            FrameSourceId::Frames
        }
        fn min_lengths(&self) -> sakuya_connection::send_strategy::MinimumLengths {
            sakuya_connection::send_strategy::MinimumLengths {
                with_length: self.len + self.length_field,
                as_last: self.len,
            }
        }
    }
    impl sakuya_connection::send_strategy::ranked::RankedIntent for FillerIntent {
        fn rank(&self) -> sakuya_connection::send_strategy::ranked::SendRank {
            sakuya_connection::send_strategy::ranked::SendRank {
                priority: sakuya_connection::send_strategy::ranked::SendPriority::Control,
                holds_place: self.holds_place,
            }
        }
    }

    /// The probe's frames, as a kind of frame source: the fillers are
    /// planned, and what comes back of their summaries is logged.
    pub enum Frames {}
    impl FrameSourceKind for Frames {
        type Item<'a> = FillerIntent;
        type Summary<I> = Summary;
    }
    /// The source of the probe's frames writes the fillers it is given and
    /// logs that it was given each, and what comes back of their summaries.
    pub struct LoggingSource;
    impl FrameSource for LoggingSource {
        type Summary = Summary;
        type Class = sakuya_wire_v1::frame::write::InFlightClass;
        type Item<'a> = FillerIntent;
        fn supply<W, P, Idx>(
            &mut self,
            filler: FillerIntent,
            mut packet: sakuya_connection::write::OpenPacket<
                W,
                sakuya_wire_v1::frame::write::InFlightClass,
                P,
            >,
        ) -> sakuya_connection::write::Supplied<W, sakuya_wire_v1::frame::write::InFlightClass, P>
        where
            W: sakuya_connection::write::PacketWriting,
            sakuya_connection::write::SummaryOf<W>: InjectSummary<Summary, Idx>,
            P: sakuya_connection::write::PacketPosition,
        {
            FILLERS.with(|f| f.borrow_mut().retain(|kept| kept.id != filler.id));
            if filler.writes {
                for _ in 0..filler.len {
                    packet
                        .write_frame(
                            sakuya_wire_v1::frame::ping::PingFrame,
                            <sakuya_connection::write::SummaryOf<W>>::inject_summary(Summary(
                                u64::from(filler.id),
                            )),
                        )
                        .expect("the filler was given the room it needs");
                }
                log(format!("filler {} wrote", filler.id));
            } else {
                log(format!("filler {} wrote nothing", filler.id));
            }
            sakuya_connection::write::Supplied::Open(packet)
        }
        fn delivered(&mut self, space: PacketNumberSpaceKind, summary: Summary) {
            log(format!("delivered {space:?} {}", summary.0));
        }
        fn lost(&mut self, space: PacketNumberSpaceKind, summary: &Summary) {
            log(format!("lost {space:?} {}", summary.0));
        }
        fn unfulfilled(
            &mut self,
            _: FillerIntent,
            _: sakuya_stream_v1::send_options::destination::Unfulfilled,
        ) {
        }
    }
    impl<T: ConnectionChoices, L, V> FindFrameSource<T, L, V, ()> for Frames {
        type Source<'l, 'r>
            = LoggingSource
        where
            V: 'l,
            'r: 'l;
        fn find<'l, 'r>(_: &'l mut Lineage<'r, V>, _: InstantOf<T>) -> LoggingSource {
            LoggingSource
        }
    }

    /// The probe sends its fillers, and nothing through the intake.
    impl sakuya_connection::send_strategy::SendIntentPart for Part {
        type FrameSourceId = FrameSourceId;
        type SendIntents = frunk_core::Coprod![FillerIntent];
        type FrameSources = frunk_core::HList![Frames];

        fn intent_item(
            intent: &frunk_core::Coprod![FillerIntent],
        ) -> Coproduct<FillerIntent, CNil> {
            match intent {
                Coproduct::Inl(filler) => Coproduct::Inl(*filler),
                Coproduct::Inr(never) => match *never {},
            }
        }
    }
    /// The fillers wait for a link path in the order they were set.
    impl<
        T: sakuya_connection::clock::ConnectionChoices,
        L: sakuya_connection::share::LogicalPathKeys,
        V,
    > sakuya_connection::frame_source::DriverContentPart<T, L, V, ()> for Part
    {
        fn pending<J>(
            _: &sakuya_connection::take::Lineage<'_, V>,
            _: &sakuya_connection::share::LinkPathIdentifierOf<T, L>,
            out: &mut sakuya_connection::send_strategy::DriverContent<J>,
            inject: impl Fn(frunk_core::Coprod![FillerIntent]) -> J,
        ) {
            FILLERS.with(|f| {
                out.intents.extend(
                    f.borrow()
                        .iter()
                        .map(|filler| inject(Coproduct::Inl(*filler))),
                );
            });
        }
    }
    /// The probe's frame source finds nothing in the established layer.
    impl<T, L> sakuya_connection::frame_source::EstablishedSourceComponentsPart<T, L> for Part {
        type Components = HNil;
    }
    /// The fillers go in Initial packets only.
    impl<K: sakuya_connection::frame_source::PacketKind>
        sakuya_connection::frame_source::FrameSourcePart<K> for Part
    {
        fn item(
            intent: &frunk_core::Coprod![FillerIntent],
        ) -> Option<Coproduct<FillerIntent, CNil>> {
            (K::KIND == sakuya_connection::send_strategy::PlannedPacketKind::Initial).then(|| {
                <Self as sakuya_connection::send_strategy::SendIntentPart>::intent_item(intent)
            })
        }
        fn source(item: &Coproduct<FillerIntent, CNil>) -> FrameSourceId {
            match item {
                Coproduct::Inl(_) => FrameSourceId::Frames,
                Coproduct::Inr(never) => match *never {},
            }
        }
    }

    const NO_FRAME_TYPES: FrameTypeValues = FrameTypeValues::new(&[]);

    /// The probe claims no frames.
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

    /// In the connection: asks for a second link path at its deadline, and
    /// logs whether the Initial keys are live.
    #[derive(Debug)]
    pub struct Adder(Option<(Duration, LinkId<(), ()>)>);
    impl<T: v1::Choices<Link = TestLink>, L> Build<T, L, layer::Connection, ()> for Adder
    where
        for<'v> L: LineageLists<'v, T>,
    {
        fn build<'v>(
            _: &mut ParentsOf<'v, T, L, layer::Connection>,
            _: &mut ArgsOf<T, L, layer::Connection>,
        ) -> Self {
            Adder(ADD.with(Cell::take))
        }
    }
    impl<T, L, I, J, K> DataComponent<T, L, layer::Connection, (I, J, K)> for Adder
    where
        T: v1::Choices<Link = TestLink, Clock = TestClock>,
        for<'v> L: LineageLists<'v, T>,
        L: sakuya_connection::share::LogicalPathKeys<Key = SoleLogicalPath>,
        for<'v> <L as LineageLists<'v, T>>::Connection:
            GetAt<Adder, I> + GetAt<InitialKeys<RingBackend>, J> + TakeEach<'v, HList![Adder], K>,
    {
        const DEADLINE: bool = true;
        fn subscribes(out: &mut EventSubscriptions) {
            out.add::<KeysInstalled<level::Initial>>()
                .add::<KeysDiscarded<level::Initial>>()
                .add::<NodeStarted<layer::Connection>>();
        }
        fn deadline<'v>(lineage: &LineageOf<'v, T, L, layer::Connection>) -> Option<Duration> {
            lineage.get::<Adder, I>().0.as_ref().map(|(at, _)| *at)
        }
        fn expire<'v, B: CallBundle>(
            lineage: LineageOf<'v, T, L, layer::Connection>,
            _: &mut OtherNodes<'v, T, L, B>,
            _: Duration,
        ) -> Option<RequestOf<T, L>> {
            let (hlist_pat![mut adder], _) = Take::<HList![Adder], K>::take(lineage);
            let (_, second) = adder.0.take()?;
            Some(StructureRequest::AddLinkPath {
                args: LinkPathArgs {
                    path: PATH,
                    link: TestLink(second),
                    role: LinkPathRole::Candidate,
                    peer_switched_local_id: true,
                },
            })
        }
        fn on_events<'v, B: CallBundle>(
            _: TriggeredEvents<'_>,
            lineage: LineageOf<'v, T, L, layer::Connection>,
            _: &mut OtherNodes<'v, T, L, B>,
            _: Duration,
        ) -> Option<RequestOf<T, L>> {
            let live = lineage
                .get::<InitialKeys<RingBackend>, J>()
                .send()
                .is_some();
            log(format!("initial keys live: {live}"));
            None
        }
    }

    /// In the connection: asks for a recovery layer to move at its deadline,
    /// from the link path over the first logical link to the one over the
    /// second.
    #[derive(Debug)]
    pub struct Mover(Option<Move>);
    impl<T: v1::Choices<Link = TestLink>, L> Build<T, L, layer::Connection, ()> for Mover
    where
        for<'v> L: LineageLists<'v, T>,
    {
        fn build<'v>(
            _: &mut ParentsOf<'v, T, L, layer::Connection>,
            _: &mut ArgsOf<T, L, layer::Connection>,
        ) -> Self {
            Mover(MOVE.with(Cell::take))
        }
    }
    impl<T, L, I, K> DataComponent<T, L, layer::Connection, (I, K)> for Mover
    where
        T: v1::Choices<Link = TestLink, Clock = TestClock>,
        for<'v> L: LineageLists<'v, T>,
        L: sakuya_connection::share::LogicalPathKeys<Key = SoleLogicalPath>,
        for<'v> <L as LineageLists<'v, T>>::Connection:
            GetAt<Mover, I> + TakeEach<'v, HList![Mover], K>,
    {
        const DEADLINE: bool = true;
        fn deadline<'v>(lineage: &LineageOf<'v, T, L, layer::Connection>) -> Option<Duration> {
            lineage.get::<Mover, I>().0.as_ref().map(|(at, ..)| *at)
        }
        fn expire<'v, B: CallBundle>(
            lineage: LineageOf<'v, T, L, layer::Connection>,
            _: &mut OtherNodes<'v, T, L, B>,
            _: Duration,
        ) -> Option<RequestOf<T, L>> {
            let (hlist_pat![mut mover], _) = Take::<HList![Mover], K>::take(lineage);
            let (_, from, to) = mover.0.take()?;
            Some(StructureRequest::MoveRecovery {
                path: PATH,
                from,
                to,
            })
        }
    }

    /// In the connection: at its deadline, the peer's parameters become
    /// known with a maximum idle timeout of 10 s and a packet is processed.
    #[derive(Debug)]
    pub struct PeerSetter(Option<Duration>);
    impl Build<Mine, Parts, layer::Connection, ()> for PeerSetter {
        fn build<'v>(
            _: &mut ParentsOf<'v, Mine, Parts, layer::Connection>,
            _: &mut ArgsOf<Mine, Parts, layer::Connection>,
        ) -> Self {
            PeerSetter(PEER_AT.with(Cell::take))
        }
    }
    impl<I, K> DataComponent<Mine, Parts, layer::Connection, (I, K)> for PeerSetter
    where
        for<'v> <Parts as LineageLists<'v, Mine>>::Connection: GetAt<PeerSetter, I>
            + TakeEach<
                'v,
                HList![
                    PeerSetter,
                    PeerTransportParameters<TransportParameterSlots<Parts>>,
                    IdleTimeout<Duration>
                ],
                K,
            >,
    {
        const DEADLINE: bool = true;
        fn deadline<'v>(
            lineage: &LineageOf<'v, Mine, Parts, layer::Connection>,
        ) -> Option<Duration> {
            lineage.get::<PeerSetter, I>().0
        }
        fn expire<'v, B: CallBundle>(
            lineage: LineageOf<'v, Mine, Parts, layer::Connection>,
            _: &mut OtherNodes<'v, Mine, Parts, B>,
            now: Duration,
        ) -> Option<RequestOf<Mine, Parts>> {
            let (hlist_pat![mut setter, mut peer, mut idle], mut rest) =
                Take::<
                    HList![
                        PeerSetter,
                        PeerTransportParameters<TransportParameterSlots<Parts>>,
                        IdleTimeout<Duration>
                    ],
                    K,
                >::take(lineage);
            setter.0 = None;
            let mut slots =
                TransportParameters::<Vec<u8>, HList![sakuya_wire_v1::Part]>::new().known;
            *slots.get_mut::<Option<MaxIdleTimeout>, _>() =
                Some(MaxIdleTimeout::new(VarInt::from_u32(10_000)));
            let known = peer.receive(slots).expect("nothing was remembered");
            rest.publish(known);
            idle.packet_processed(now);
            log(format!("packet processed at {now:?}"));
            None
        }
    }

    /// In the connection: at its deadline, hands a CRYPTO frame with data to
    /// the 1-RTT level and one to the Initial level, then reads the level
    /// being read.
    #[derive(Debug)]
    pub struct CryptoFeeder(Option<Duration>);
    impl Build<Mine, Parts, layer::Connection, ()> for CryptoFeeder {
        fn build<'v>(
            _: &mut ParentsOf<'v, Mine, Parts, layer::Connection>,
            _: &mut ArgsOf<Mine, Parts, layer::Connection>,
        ) -> Self {
            CryptoFeeder(CRYPTO_AT.with(Cell::take))
        }
    }
    impl<I, K> DataComponent<Mine, Parts, layer::Connection, (I, K)> for CryptoFeeder
    where
        for<'v> <Parts as LineageLists<'v, Mine>>::Connection: GetAt<CryptoFeeder, I>
            + TakeEach<'v, HList![CryptoFeeder, CryptoReceiver<FragmentedCryptoReceiveBuffer>], K>,
    {
        const DEADLINE: bool = true;
        fn deadline<'v>(
            lineage: &LineageOf<'v, Mine, Parts, layer::Connection>,
        ) -> Option<Duration> {
            lineage.get::<CryptoFeeder, I>().0
        }
        fn expire<'v, B: CallBundle>(
            lineage: LineageOf<'v, Mine, Parts, layer::Connection>,
            _: &mut OtherNodes<'v, Mine, Parts, B>,
            _: Duration,
        ) -> Option<RequestOf<Mine, Parts>> {
            let (hlist_pat![mut feeder, mut receiver], _) = Take::<
                HList![CryptoFeeder, CryptoReceiver<FragmentedCryptoReceiveBuffer>],
                K,
            >::take(lineage);
            feeder.0 = None;
            let zero = VarInt::from_u32(0);
            let one_rtt =
                receiver.receive_frame(CryptoLevel::OneRtt, zero, bytes::Bytes::from_static(b"x"));
            log(format!("1-RTT: {one_rtt:?}"));
            let initial = receiver.receive_frame(
                CryptoLevel::Initial,
                zero,
                bytes::Bytes::from_static(b"hello"),
            );
            let mut read = Vec::new();
            receiver.read_into(&mut read);
            log(format!(
                "Initial: {initial:?}, read {:?}",
                String::from_utf8_lossy(&read)
            ));
            None
        }
    }

    /// In the connection: at its deadline, writes `server hello`, or as
    /// many bytes as `CRYPTO_WRITE_LEN` says, at the level the CRYPTO
    /// output writes.
    #[derive(Debug)]
    pub struct CryptoWriter(Option<Duration>);
    impl Build<Mine, Parts, layer::Connection, ()> for CryptoWriter {
        fn build<'v>(
            _: &mut ParentsOf<'v, Mine, Parts, layer::Connection>,
            _: &mut ArgsOf<Mine, Parts, layer::Connection>,
        ) -> Self {
            CryptoWriter(CRYPTO_WRITE_AT.with(Cell::take))
        }
    }
    impl<I, K> DataComponent<Mine, Parts, layer::Connection, (I, K)> for CryptoWriter
    where
        for<'v> <Parts as LineageLists<'v, Mine>>::Connection: GetAt<CryptoWriter, I>
            + TakeEach<'v, HList![CryptoWriter, CryptoSender<OffsetMapCryptoSendBuffer>], K>,
    {
        const DEADLINE: bool = true;
        fn deadline<'v>(
            lineage: &LineageOf<'v, Mine, Parts, layer::Connection>,
        ) -> Option<Duration> {
            lineage.get::<CryptoWriter, I>().0
        }
        fn expire<'v, B: CallBundle>(
            lineage: LineageOf<'v, Mine, Parts, layer::Connection>,
            _: &mut OtherNodes<'v, Mine, Parts, B>,
            _: Duration,
        ) -> Option<RequestOf<Mine, Parts>> {
            let (hlist_pat![mut writer, mut sender], mut rest) = Take::<
                HList![CryptoWriter, CryptoSender<OffsetMapCryptoSendBuffer>],
                K,
            >::take(lineage);
            writer.0 = None;
            let data = match CRYPTO_WRITE_LEN.with(Cell::get) {
                0 => bytes::Bytes::from_static(b"server hello"),
                len => bytes::Bytes::from(vec![0x5e; len]),
            };
            let written = sender.write(data).expect("the bytes fit");
            rest.publish(written);
            None
        }
    }

    /// What the packet feeder does at one instant.
    #[derive(Debug)]
    #[allow(clippy::large_enum_variant)]
    pub enum PacketStep {
        /// Receive the packet, as the receiving call will, and log what came
        /// of it.
        Receive(ReceivedPacket<BytesMut, TestLink>),
        /// Install Handshake keys that receive with the client's Initial
        /// secret, as the handshake will.
        InstallHandshakeKeys,
        /// Install 1-RTT keys that only send, as a server does before the
        /// handshake completes.
        InstallOneRttSendKeys,
        /// Install 1-RTT keys of both directions: the server's secret to
        /// send, the client's to receive.
        InstallOneRttKeys,
        /// Log the generations of the 1-RTT keys, when the previous one goes,
        /// the packets that failed authentication and the lowest packet
        /// number received with the current generation.
        InspectOneRtt,
        /// Log the sending generation of the 1-RTT keys, when the peer
        /// acknowledged a packet of it, and the lowest packet number sent
        /// with it.
        InspectKeyUpdate,
        /// Note the packet number as sent with the sending generation, as
        /// starting a 1-RTT packet will: `(generation, number)`.
        NoteSent(u64, u64),
        /// Note an ACK frame up to the packet number as sent in a 1-RTT
        /// packet, as writing one will.
        NoteAckFrameSent(u64),
        /// Count this many packets as sealed with the current sending
        /// generation of the 1-RTT keys, as sending them would.
        Seal(u64),
        /// Mark 0-RTT as rejected, every packet number of the Application
        /// Data space below this one a rejected 0-RTT packet, as a client's
        /// rejected 0-RTT does.
        RejectZeroRtt(u64),
        /// Log the CRYPTO data ready at the level being read; the largest
        /// packet number, the ranges and the ACK obligation of the Initial
        /// space; the idle timeout's deadline; and the reason for closing.
        Inspect,
        /// Log the retirements the destination connection ID strategy has
        /// waiting to be written, and the ACK obligation of the
        /// Application Data space.
        InspectOwed,
        /// Log how many inputs the logical path holds, and the largest
        /// packet number processed in the Handshake space.
        InspectHeld,
        /// Log the credit of the anti-amplification limit of the logical
        /// link, as if its address were not validated.
        InspectCredit(LinkId<(), ()>),
        /// Log the connection IDs the destination connection ID strategy
        /// offers for the link path over the logical link.
        InspectOffer(LinkId<(), ()>),
        /// Tell the destination connection ID strategy the connection ID to
        /// send the handshake with, as a client's composition does with the
        /// one it chose.
        HandshakeConnectionId(ConnectionId),
        /// Take every record out of the send journals of the space, as an
        /// acknowledgment of all of them would, and log each one's packet
        /// number and state; a gone space logs nothing.
        TakeRecords(PacketNumberSpaceKind),
        /// Tell the destination connection ID strategy that a datagram was
        /// sent with the connection ID of the sequence number over the
        /// logical link, as the sending call will, lending it each link
        /// path's registrar of reset tokens.
        UseConnectionId(LinkId<(), ()>, u64),
        /// Log which halves of the keys of each level are there.
        InspectKeys,
        /// Make the link path over the logical link active, as path
        /// validation will.
        Activate(LinkId<(), ()>),
        /// Log the largest packet number processed in the Application Data
        /// space.
        InspectLargest,
    }

    /// In a logical path: does its steps at their instants.
    #[derive(Debug)]
    pub struct PacketFeeder(VecDeque<(Duration, PacketStep)>);
    macro_rules! packet_feeder {
        ($t:ty) => {
            impl Build<$t, Parts, layer::LogicalPath, ()> for PacketFeeder {
                fn build<'v>(
                    _: &mut ParentsOf<'v, $t, Parts, layer::LogicalPath>,
                    _: &mut ArgsOf<$t, Parts, layer::LogicalPath>,
                ) -> Self {
                    PacketFeeder(PACKETS.with(|p| core::mem::take(&mut *p.borrow_mut())))
                }
            }
        };
    }
    packet_feeder!(Mine);
    packet_feeder!(ClientMine);
    packet_feeder!(SpyMine);
    impl<
        T,
        L,
        I,
        Ii,
        Ih,
        Io,
        Iz,
        Ij,
        Im,
        Ia,
        It,
        Iu,
        Ikp,
        Ir,
        Ie,
        Ik,
        Hd,
        Ic,
        Icr,
        Izr,
        Ip,
        Ian,
        Icid,
        Iph,
        Iev,
        Isj,
        Irg,
        Ilr,
        Hm,
    >
        DataComponent<
            T,
            L,
            layer::LogicalPath,
            (
                I,
                (Ii, Ih, Io, Iz),
                (Ij, Im, Ia, It, Iu, Ikp, Icid, Iph, Iev),
                (Ir, Ie, Ik, Hd),
                (Ic, Icr, Izr),
                (Ip, Ian, Isj, Irg, Ilr, Hm),
            ),
        > for PacketFeeder
    where
        T: v1::Choices<
                Clock = TestClock,
                Link = TestLink,
                Crypto = RingBackend,
                Host: v1::HostChoices<T, CryptoReceiveBuffer = FragmentedCryptoReceiveBuffer>,
            >,
        L: LineagePartList<T>
            + FrameSetDispatch<T, L, Hd>
            + sakuya_connection::feedback::FeedbackSummariesOf
            + sakuya_stream_sets::resets::StreamResetsOf
            + v1::migration::rules::MigrationRules<T, Hm>,
        CloseCauseOf<T, L>: Debug,
        <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<v1::error::V1ConnectionErrorOf<L>, Ie>
            + CoprodUninjector<v1::error::V1ConnectionErrorOf<L>, Ie>,
        <L as FrameSet>::Kind: CoproductSelector<FrameType, Ik>,
        v1::EventsOf<T, L>: v1::events::PacketEvents<Duration, L>,
        for<'v> <L as LineageLists<'v, T>>::LogicalPath: GetAt<PacketFeeder, I>
            + GetAt<InitialKeys<RingBackend>, Ii>
            + GetAt<HandshakeKeys<RingBackend>, Ih>
            + GetAt<OneRttKeys<RingBackend, Duration>, Io>
            + GetAt<<T::Side as v1::Side>::OwnZeroRttKeys<RingBackend, Duration>, Iz>
            + GetAt<PacketNumberSpaces<ReceiveJournals<Duration>>, Ij>
            + GetAt<MaxAckRanges, Im>
            + GetAt<AckObligationsOf<T>, Ia>
            + GetAt<IdleTimeout<Duration>, It>
            + GetAt<AeadUsage, Iu>
            + GetAt<KeyPhaseNumbers, Ikp>
            + GetAt<v1::connection_ids::ConnectionIdsOf<T>, Icid>
            + GetAt<v1::connection_ids::PeerHandshakeConnectionId, Iph>
            + GetAt<v1::events::ConnectionEventSink<v1::EventsOf<T, L>>, Iev>
            + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>
            + GetAt<CryptoReceiver<FragmentedCryptoReceiveBuffer>, Icr>
            + GetAt<LogicalPathInput<TestLink, T::Receiver>, Ip>
            + GetAt<SendJournalsOf<T, L>, Isj>
            + GetAt<v1::zero_rtt_rejection::ZeroRttRejection, Izr>,
        for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
        for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
            GetAt<LinkPathRole<Duration>, Ir>,
        for<'s> NodeData<T, L, layer::LinkEntry>: FlatMut<'s>,
        for<'s> <NodeData<T, L, layer::LinkEntry> as FlatMut<'s>>::Out:
            TakeEach<'s, HList![AntiAmplification], Ian>,
        for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out: TakeEach<
                's,
                HList![
                    v1::connection_ids::LinkPathResetTokenRegistrar<
                        v1::connection_ids::ResetTokenRegistrarOf<T>,
                    >
                ],
                Irg,
            > + TakeEach<'s, HList![LinkPathRole<Duration>], Ilr>,
    {
        const DEADLINE: bool = true;
        fn deadline<'v>(lineage: &LineageOf<'v, T, L, layer::LogicalPath>) -> Option<Duration> {
            lineage
                .get::<PacketFeeder, I>()
                .0
                .front()
                .map(|(at, _)| *at)
        }
        fn expire<'v, B: CallBundle>(
            mut lineage: LineageOf<'v, T, L, layer::LogicalPath>,
            others: &mut OtherNodes<'v, T, L, B>,
            _: Duration,
        ) -> Option<RequestOf<T, L>> {
            let (_, step) = lineage.get_mut::<PacketFeeder, I>().0.pop_front()?;
            match step {
                PacketStep::Receive(packet) => {
                    let outcome = receive_packet::<
                        T,
                        L,
                        B,
                        BytesMut,
                        Ii,
                        Ih,
                        Io,
                        Iz,
                        Ij,
                        Im,
                        Ia,
                        It,
                        Iu,
                        Ikp,
                        Ir,
                        Ie,
                        Ik,
                        Hd,
                        Icid,
                        Iph,
                        Iev,
                        Hm,
                    >(&mut lineage, others, packet);
                    log(describe::<L, Ie>(outcome));
                }
                PacketStep::InstallHandshakeKeys => {
                    let secrets = InitialSecrets::derive(&RingBackend, &client_dcid());
                    let installed =
                        lineage
                            .get_mut::<HandshakeKeys<RingBackend>, Ih>()
                            .install(LevelKeys {
                                send: DirectionKeys::derive(
                                    &RingBackend,
                                    INITIAL_AEAD,
                                    &secrets.server,
                                ),
                                receive: DirectionKeys::derive(
                                    &RingBackend,
                                    INITIAL_AEAD,
                                    &secrets.client,
                                ),
                            });
                    lineage.publish(installed);
                }
                PacketStep::InstallOneRttSendKeys => {
                    let secrets = InitialSecrets::derive(&RingBackend, &client_dcid());
                    let installed = lineage
                        .get_mut::<OneRttKeys<RingBackend, Duration>, Io>()
                        .install_send(RingBackend, INITIAL_AEAD, secrets.server);
                    lineage.publish(installed);
                }
                PacketStep::InstallOneRttKeys => {
                    let installed = lineage
                        .get_mut::<OneRttKeys<RingBackend, Duration>, Io>()
                        .install(RingBackend, ONE_RTT_AEAD, server_secret(), client_secret());
                    lineage.publish(installed);
                }
                PacketStep::InspectOneRtt => {
                    let keys = lineage.get::<OneRttKeys<RingBackend, Duration>, Io>();
                    let (receive, send) = (keys.receive(), keys.send());
                    let current = receive.map(|keys| keys.current().generation());
                    let next = receive.map(|keys| keys.next().generation());
                    let previous = receive.map(|keys| keys.previous().is_some());
                    let until = keys.previous_deadline();
                    let send = send.map(|keys| keys.generation().generation());
                    let failed = lineage.get::<AeadUsage, Iu>().failed_authentication();
                    let lowest = current.and_then(|current| {
                        lineage
                            .get::<KeyPhaseNumbers, Ikp>()
                            .lowest_received(current)
                            .map(|number| number.get())
                    });
                    log(format!(
                        "receive {current:?}, next {next:?}, previous {previous:?} until \
                         {until:?}, send {send:?}, failed {failed}, lowest {lowest:?}"
                    ));
                }
                PacketStep::InspectKeyUpdate => {
                    let (send, confirmed) =
                        match lineage.get::<OneRttKeys<RingBackend, Duration>, Io>() {
                            OneRttKeys::Live(keys) => (
                                Some(keys.send().generation().generation()),
                                keys.send_confirmed_at(),
                            ),
                            _ => (None, None),
                        };
                    let lowest = send.and_then(|send| {
                        lineage
                            .get::<KeyPhaseNumbers, Ikp>()
                            .lowest_sent(send)
                            .map(|number| number.get())
                    });
                    log(format!(
                        "send {send:?}, confirmed at {confirmed:?}, lowest sent {lowest:?}"
                    ));
                }
                PacketStep::NoteSent(generation, number) => {
                    lineage
                        .get_mut::<KeyPhaseNumbers, Ikp>()
                        .sent(generation, PacketNumber::new(number).unwrap());
                }
                PacketStep::Seal(count) => {
                    let mut usage = lineage.get_mut::<AeadUsage, Iu>();
                    for _ in 0..count {
                        usage.sealed();
                    }
                }
                PacketStep::RejectZeroRtt(first_after) => {
                    *lineage.get_mut::<v1::zero_rtt_rejection::ZeroRttRejection, Izr>() =
                        v1::zero_rtt_rejection::ZeroRttRejection::Rejected {
                            first_after: PacketNumber::new(first_after).unwrap(),
                        };
                }
                PacketStep::NoteAckFrameSent(largest) => {
                    lineage
                        .get_mut::<KeyPhaseNumbers, Ikp>()
                        .ack_frame_sent(PacketNumber::new(largest).unwrap());
                }
                PacketStep::InspectHeld => {
                    let held = lineage
                        .get::<LogicalPathInput<TestLink, T::Receiver>, Ip>()
                        .held_len();
                    let largest = lineage
                        .get::<PacketNumberSpaces<ReceiveJournals<Duration>>, Ij>()
                        .get(PacketNumberSpaceKind::Handshake)
                        .and_then(|journals| journals.largest())
                        .map(|(number, _)| number.get());
                    log(format!("held {held}, largest Handshake {largest:?}"));
                }
                PacketStep::InspectCredit(link) => {
                    let credit = others
                        .link_entry::<HList![AntiAmplification], Ian>(&link)
                        .map(|hlist_pat![limit]| limit.credit(AddressValidation::NotValidated));
                    log(format!("credit {credit:?}"));
                }
                PacketStep::InspectOwed => {
                    let retirements: Vec<_> = lineage
                        .get::<v1::connection_ids::ConnectionIdsOf<T>, Icid>()
                        .destination()
                        .waiting_retirements()
                        .collect();
                    let due = lineage
                        .get::<AckObligationsOf<T>, Ia>()
                        .get(PacketNumberSpaceKind::ApplicationData)
                        .map(|obligation| obligation.due());
                    log(format!(
                        "owed retirements {retirements:?}, Application Data ACK {due:?}"
                    ));
                }
                PacketStep::InspectOffer(link) => {
                    let offered: Vec<_> = lineage
                        .get::<v1::connection_ids::ConnectionIdsOf<T>, Icid>()
                        .destination()
                        .offer(&link)
                        .map(|offered| (offered.sequence, offered.id.as_bytes().to_vec()))
                        .collect();
                    log(format!("offered {offered:?}"));
                }
                PacketStep::HandshakeConnectionId(id) => {
                    let changed = lineage
                        .get_mut::<v1::connection_ids::ConnectionIdsOf<T>, Icid>()
                        .destination_mut()
                        .on_handshake_connection_id(id);
                    if changed {
                        lineage.publish(Happened::<DestinationConnectionIdsChanged>::new());
                    }
                }
                PacketStep::TakeRecords(space) => {
                    let mut all_journals = lineage.get_mut::<SendJournalsOf<T, L>, Isj>();
                    let journals = all_journals.get_mut(space)?;
                    let all = PacketNumber::ZERO..=PacketNumber::new(1 << 20).unwrap();
                    let records: Vec<_> = journals
                        .take_acknowledged(&all)
                        .map(|record| {
                            if record.pmtu_probe {
                                log(format!(
                                    "probe record {} bytes, packet {}",
                                    record.bytes,
                                    record.number.get()
                                ));
                            }
                            (record.number.get(), format!("{:?}", record.state))
                        })
                        .collect();
                    log(format!("records {space:?}: {records:?}"));
                }
                PacketStep::UseConnectionId(link, sequence) => {
                    let mut all_ids =
                        lineage.get_mut::<v1::connection_ids::ConnectionIdsOf<T>, Icid>();
                    let ids = all_ids.destination_mut();
                    let mut changed = false;
                    others.each_link_path::<HList![
                        v1::connection_ids::LinkPathResetTokenRegistrar<
                            v1::connection_ids::ResetTokenRegistrarOf<T>,
                        >
                    ], Irg>(|_, hlist_pat![mut registrar]| {
                        changed |= ids.on_used(
                            registrar.registrar_mut(),
                            sequence,
                            &link,
                            MIN_DATAGRAM_SIZE,
                        );
                    });
                    if changed {
                        lineage.publish(Happened::<DestinationConnectionIdsChanged>::new());
                    }
                    log(format!("used {sequence}"));
                }
                PacketStep::InspectLargest => {
                    let largest = lineage
                        .get::<PacketNumberSpaces<ReceiveJournals<Duration>>, Ij>()
                        .get(PacketNumberSpaceKind::ApplicationData)
                        .and_then(|journals| journals.largest())
                        .map(|(number, _)| number.get());
                    log(format!("largest Application Data {largest:?}"));
                }
                PacketStep::InspectKeys => {
                    let halves = |send: bool, receive: bool| match (send, receive) {
                        (true, true) => "both",
                        (true, false) => "send",
                        (false, true) => "receive",
                        (false, false) => "none",
                    };
                    let initial = lineage.get::<InitialKeys<RingBackend>, Ii>();
                    let handshake = lineage.get::<HandshakeKeys<RingBackend>, Ih>();
                    let one_rtt = lineage.get::<OneRttKeys<RingBackend, Duration>, Io>();
                    log(format!(
                        "keys: Initial {}, Handshake {}, 1-RTT {}",
                        halves(initial.send().is_some(), initial.receive().is_some()),
                        halves(handshake.send().is_some(), handshake.receive().is_some()),
                        halves(one_rtt.send().is_some(), one_rtt.receive().is_some()),
                    ));
                }
                PacketStep::Activate(link) => {
                    let NodeKey::LogicalPath(path) = others.here().clone() else {
                        unreachable!("a logical path's lend carries its key")
                    };
                    let hlist_pat![mut role] =
                        others.link_path::<HList![LinkPathRole<Duration>], Ilr>(&path, &link)?;
                    *role = LinkPathRole::Active;
                    // as path validation will, which no event of the
                    // role's covers yet
                    others.publish_at(
                        &NodeKey::LinkPath(path, link),
                        Happened::<LinkPathRoleChanged>::new(),
                    );
                }
                PacketStep::Inspect => {
                    let mut read = Vec::new();
                    lineage
                        .get_mut::<CryptoReceiver<FragmentedCryptoReceiveBuffer>, Icr>()
                        .read_into(&mut read);
                    let journals = lineage
                        .get::<PacketNumberSpaces<ReceiveJournals<Duration>>, Ij>()
                        .get(PacketNumberSpaceKind::Initial);
                    let largest = journals
                        .and_then(|journals| journals.largest())
                        .map(|(number, at)| (number.get(), at));
                    let ranges: Vec<_> = journals
                        .map(|journals| journals.ranges())
                        .unwrap_or_default()
                        .iter()
                        .map(|range| (range.start().get(), range.end().get()))
                        .collect();
                    let due = lineage
                        .get::<AckObligationsOf<T>, Ia>()
                        .get(PacketNumberSpaceKind::Initial)
                        .map(|obligation| obligation.due());
                    let idle = lineage.get::<IdleTimeout<Duration>, It>().deadline();
                    let reason = lineage
                        .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
                        .reason()
                        .map(|reason| format!("{reason:?}"));
                    log(format!(
                        "read {:?}, largest {largest:?}, ranges {ranges:?}, due {due:?}, \
                         idle {idle:?}, reason {reason:?}",
                        String::from_utf8_lossy(&read)
                    ));
                }
            }
            None
        }
    }

    /// What came of a packet, in short.
    fn describe<L, Ie>(
        outcome: Result<
            PacketOutcome<BytesMut, TestLink>,
            sakuya_connection::error::ConnectionErrorOf<L>,
        >,
    ) -> String
    where
        L: ConnectionErrorsOf,
        L::ConnectionErrors: CoprodUninjector<v1::error::V1ConnectionErrorOf<L>, Ie>,
    {
        match outcome {
            Ok(PacketOutcome::Processed {
                highest_numbered,
                non_probing,
            }) => {
                format!("processed: highest numbered {highest_numbered}, non-probing {non_probing}")
            }
            Ok(PacketOutcome::Closing) => "read while closing".into(),
            Ok(PacketOutcome::Held(packet)) => format!("held at {:?}", packet.packet().level()),
            Ok(PacketOutcome::AwaitingLinkPath(packet)) => {
                format!("awaiting a link path: {}", packet.number().get())
            }
            Ok(PacketOutcome::Dropped(reason)) => format!(
                "dropped: {}",
                match reason {
                    DropReason::NoLinkPath => "no link path".into(),
                    DropReason::LinkPathNotAdmitted => "link path not admitted".into(),
                    DropReason::OldLocalAddress => "at an old local address".into(),
                    DropReason::Draining => "draining".into(),
                    DropReason::TokenFromServer => "token from the server".into(),
                    DropReason::OtherSourceConnectionId { .. } => {
                        "another source connection ID".into()
                    }
                    DropReason::NoReceiveKeys { level } => format!("no {level:?} keys"),
                    DropReason::NotProtected => "not protected".into(),
                    DropReason::HeaderProtectionNotRemoved { .. } => {
                        "header protection not removed".into()
                    }
                    DropReason::PayloadNotOpened { .. } => "payload not opened".into(),
                    DropReason::Duplicate { number } => format!("duplicate {}", number.get()),
                }
            ),
            Err(PartsError(errors)) => match errors.uninject() {
                Ok(error) => format!("error: {error:?}"),
                Err(_) => "error of another part".into(),
            },
        }
    }

    /// What the closer does at its instants: build the established layer,
    /// close as the application, or log whether the established layer is
    /// there.
    #[derive(Debug, Clone, Copy)]
    pub enum CloserStep {
        Establish,
        Close,
        LogEstablished,
    }

    /// In the connection: does its steps at their instants.
    #[derive(Debug)]
    pub struct Closer(VecDeque<(Duration, CloserStep)>);
    impl Build<Mine, Parts, layer::Connection, ()> for Closer {
        fn build<'v>(
            _: &mut ParentsOf<'v, Mine, Parts, layer::Connection>,
            _: &mut ArgsOf<Mine, Parts, layer::Connection>,
        ) -> Self {
            Closer(CLOSER.with(|c| c.take()))
        }
    }
    impl<I, K> DataComponent<Mine, Parts, layer::Connection, (I, K)> for Closer
    where
        for<'v> <Parts as LineageLists<'v, Mine>>::Connection: GetAt<Closer, I>
            + TakeEach<'v, HList![Closer, CloseReasonRecord<CloseCauseOf<Mine, Parts>>], K>,
    {
        const DEADLINE: bool = true;
        fn deadline<'v>(
            lineage: &LineageOf<'v, Mine, Parts, layer::Connection>,
        ) -> Option<Duration> {
            lineage.get::<Closer, I>().0.front().map(|(at, _)| *at)
        }
        fn expire<'v, B: CallBundle>(
            lineage: LineageOf<'v, Mine, Parts, layer::Connection>,
            others: &mut OtherNodes<'v, Mine, Parts, B>,
            _: Duration,
        ) -> Option<RequestOf<Mine, Parts>> {
            let (hlist_pat![mut closer, mut record], mut rest) = Take::<
                HList![Closer, CloseReasonRecord<CloseCauseOf<Mine, Parts>>],
                K,
            >::take(lineage);
            let (_, step) = closer.0.pop_front()?;
            match step {
                CloserStep::Establish => Some(StructureRequest::AddEstablished {
                    args: EstablishedArgs::default(),
                }),
                CloserStep::Close => {
                    let written = record.record(CloseReason::Local(Arc::new(
                        LocalCloseCause::Application(common::AppClose(7)),
                    )));
                    if let Some(written) = written {
                        rest.publish(written);
                    }
                    log("closed by the application");
                    None
                }
                CloserStep::LogEstablished => {
                    log(format!("established: {}", others.has_established()));
                    None
                }
            }
        }
    }

    /// In a spying connection: at the first instant, makes the candidate
    /// link path active; at the second, lends the other link path's
    /// congestion access from the connection.
    #[derive(Debug)]
    pub struct Lender(Option<(Duration, Duration)>, Option<LinkId<(), ()>>);
    impl Build<SpyMine, Parts, layer::Connection, ()> for Lender {
        fn build<'v>(
            _: &mut ParentsOf<'v, SpyMine, Parts, layer::Connection>,
            _: &mut ArgsOf<SpyMine, Parts, layer::Connection>,
        ) -> Self {
            Lender(LEND_AT.with(Cell::take), None)
        }
    }
    impl<I, K, Ir, Ji, Jr, Jl, Kl>
        DataComponent<SpyMine, Parts, layer::Connection, (I, K, Ir, (Ji, Jr), (Jl, Kl))> for Lender
    where
        for<'v> <Parts as LineageLists<'v, SpyMine>>::Connection:
            GetAt<Lender, I> + TakeEach<'v, HList![Lender, RecoveryFactoryOf<SpyMine, Parts>], K>,
        for<'x> <NodeData<SpyMine, Parts, layer::Recovery> as FlatMut<'x>>::Out:
            TakeEach<'x, HList![CongestionPartOf<SpyMine, Parts>], Ir>,
        for<'a> <NodeData<SpyMine, Parts, layer::Recovery> as FlatRef<'a>>::Out: Selector<&'a CongestionPartOf<SpyMine, Parts>, Ji>
            + Selector<&'a RttOf<SpyMine, Parts>, Jr>,
        for<'s> <NodeData<SpyMine, Parts, layer::LinkPath> as FlatMut<'s>>::Out:
            GetAt<LinkPathRole<Duration>, Jl> + TakeEach<'s, HList![LinkPathRole<Duration>], Kl>,
    {
        const DEADLINE: bool = true;
        fn deadline<'v>(
            lineage: &LineageOf<'v, SpyMine, Parts, layer::Connection>,
        ) -> Option<Duration> {
            lineage.get::<Lender, I>().0.map(|(first, _)| first)
        }
        fn expire<'v, B: CallBundle>(
            lineage: LineageOf<'v, SpyMine, Parts, layer::Connection>,
            others: &mut OtherNodes<'v, SpyMine, Parts, B>,
            now: Duration,
        ) -> Option<RequestOf<SpyMine, Parts>> {
            let (hlist_pat![mut lender, mut factory], _) =
                Take::<HList![Lender, RecoveryFactoryOf<SpyMine, Parts>], K>::take(lineage);
            let (_, lend) = lender.0?;
            if now < lend {
                lender.0 = Some((lend, lend));
                let mut candidate = None;
                others.each_link_path_read::<LinkPathRole<Duration>, Jl>(|key, role| {
                    if let (LinkPathRole::Candidate, NodeKey::LinkPath(_, link)) = (role, key) {
                        candidate = Some(link.clone());
                    }
                });
                let second = candidate?;
                let hlist_pat![mut role] =
                    others.link_path::<HList![LinkPathRole<Duration>], Kl>(&PATH, &second)?;
                *role = LinkPathRole::Active;
                // as path validation will, which no event of the role's
                // covers yet
                others.publish_at(
                    &NodeKey::LinkPath(PATH, second.clone()),
                    Happened::<LinkPathRoleChanged>::new(),
                );
                lender.1 = Some(second);
                return None;
            }
            lender.0 = None;
            let second = lender.1.clone()?;
            let first = others.link_path_keys().find_map(|key| match key {
                NodeKey::LinkPath(_, link) if *link != second => Some(link.clone()),
                _ => None,
            })?;
            log("lending the first link path");
            let lent = others.with_recovery_at::<HList![CongestionPartOf<SpyMine, Parts>], Ir, _>(
                &PATH,
                &first,
                |hlist_pat![mut part], rest| {
                    lend_congestion::<SpyMine, Parts, B, Ji, Jr, _>(
                        &mut *factory,
                        &mut *part,
                        rest,
                        |mut access| {
                            // refilled as a datagram would start, then spent,
                            // so pacing holds the next datagram back
                            let input = PacingInput {
                                window: access.window(),
                                smoothed_rtt: ms(333),
                                max_datagram_size: 1200,
                            };
                            access.refill(now, input);
                            let all = access.allowance();
                            access.on_charged(all);
                        },
                    )
                },
            );
            if lent.is_some() {
                others.publish_at(
                    &NodeKey::Recovery(PATH, first),
                    Happened::<CongestionChanged>::new(),
                );
            }
            None
        }
    }

    /// In each entry: logs when the entry ends.
    #[derive(Debug)]
    pub struct EntryEnd;
    impl<T: v1::Choices, L> Build<T, L, layer::LinkEntry, ()> for EntryEnd
    where
        for<'v> L: LineageLists<'v, T>,
    {
        fn build<'v>(
            _: &mut ParentsOf<'v, T, L, layer::LinkEntry>,
            _: &mut ArgsOf<T, L, layer::LinkEntry>,
        ) -> Self {
            EntryEnd
        }
        fn end<'v, B: CallBundle>(
            self,
            _: &mut ParentsOf<'v, T, L, layer::LinkEntry>,
            _: &mut OtherNodes<'v, T, L, B>,
        ) {
            log("entry ended");
        }
    }
    impl<T: v1::Choices, L> DataComponent<T, L, layer::LinkEntry, ()> for EntryEnd where
        for<'v> L: LineageLists<'v, T>
    {
    }

    /// In each link path: logs the role with its entry's facts and credit
    /// whenever the role changes, and closes the role at its deadline.
    #[derive(Debug)]
    pub struct Watcher(Option<Duration>);
    impl<T: v1::Choices, L: ConnectionErrorsOf, I> Build<T, L, layer::LinkPath, (I,)> for Watcher
    where
        for<'v> L: LineageLists<'v, T>,
        for<'v> <L as LineageLists<'v, T>>::LinkPathParents:
            GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, I>,
        CloseCauseOf<T, L>: Debug,
    {
        fn build<'v>(
            _: &mut ParentsOf<'v, T, L, layer::LinkPath>,
            _: &mut ArgsOf<T, L, layer::LinkPath>,
        ) -> Self {
            Watcher(CLOSE_AT.with(Cell::get))
        }
        fn end<'v, B: CallBundle>(
            self,
            parents: &mut ParentsOf<'v, T, L, layer::LinkPath>,
            others: &mut OtherNodes<'v, T, L, B>,
        ) {
            assert!(
                matches!(others.here(), NodeKey::LinkPath(..)),
                "an end action is given the ended node's key"
            );
            let reason = parents
                .get::<CloseReasonRecord<CloseCauseOf<T, L>>, I>()
                .reason();
            log(format!("link path ended: {reason:?}"));
        }
    }
    impl<T, L, I, J, K, M, N> DataComponent<T, L, layer::LinkPath, (I, J, K, M, N)> for Watcher
    where
        T: v1::Choices<Clock = TestClock>,
        InstantOf<T>: Debug,
        for<'v> L: LineageLists<'v, T>,
        for<'v> <L as LineageLists<'v, T>>::LinkPath: GetAt<Watcher, I>
            + GetAt<LinkPathRole<Duration>, J>
            + GetAt<LinkFacts, K>
            + GetAt<AntiAmplification, M>
            + TakeEach<'v, HList![Watcher, LinkPathRole<Duration>], N>,
    {
        const DEADLINE: bool = true;
        fn subscribes(out: &mut EventSubscriptions) {
            out.add::<LinkPathRoleChanged>()
                .add::<NodeStarted<layer::LinkPath>>();
        }
        fn deadline<'v>(lineage: &LineageOf<'v, T, L, layer::LinkPath>) -> Option<Duration> {
            lineage.get::<Watcher, I>().0
        }
        fn expire<'v, B: CallBundle>(
            lineage: LineageOf<'v, T, L, layer::LinkPath>,
            _: &mut OtherNodes<'v, T, L, B>,
            now: Duration,
        ) -> Option<RequestOf<T, L>> {
            let (hlist_pat![mut watcher, mut role], mut rest) =
                Take::<HList![Watcher, LinkPathRole<Duration>], N>::take(lineage);
            watcher.0 = None;
            let changed = if DRAIN.with(Cell::get) {
                role.drain(now + ms(30))
            } else {
                role.close(now + ms(30))
            };
            if let Some(changed) = changed {
                rest.publish(changed);
            }
            None
        }
        fn on_events<'v, B: CallBundle>(
            _: TriggeredEvents<'_>,
            lineage: LineageOf<'v, T, L, layer::LinkPath>,
            _: &mut OtherNodes<'v, T, L, B>,
            _: Duration,
        ) -> Option<RequestOf<T, L>> {
            let role = lineage.get::<LinkPathRole<Duration>, J>();
            let facts = lineage.get::<LinkFacts, K>();
            let credit = lineage
                .get::<AntiAmplification, M>()
                .credit(facts.validation);
            log(format!(
                "{role:?}, {:?}, credit {credit:?}",
                facts.validation
            ));
            None
        }
    }

    /// In each recovery layer: logs when it is built and ended.
    #[derive(Debug)]
    pub struct LayerWatch;
    impl<T: v1::Choices, L: LogicalPathKeys> Build<T, L, layer::Recovery, ()> for LayerWatch
    where
        for<'v> L: LineageLists<'v, T>,
    {
        fn build<'v>(
            _: &mut ParentsOf<'v, T, L, layer::Recovery>,
            args: &mut ArgsOf<T, L, layer::Recovery>,
        ) -> Self {
            log(format!(
                "recovery built, initial RTT {:?}",
                args.initial_rtt
            ));
            LayerWatch
        }
        fn end<'v, B: CallBundle>(
            self,
            _: &mut ParentsOf<'v, T, L, layer::Recovery>,
            _: &mut OtherNodes<'v, T, L, B>,
        ) {
            log("recovery ended");
        }
    }
    impl<T: v1::Choices, L> DataComponent<T, L, layer::Recovery, ()> for LayerWatch where
        for<'v> L: LineageLists<'v, T>
    {
    }

    /// What the feeder does at one instant, as the calls will.
    #[derive(Debug)]
    pub enum Step {
        /// The link accepted 1200-byte ack-eliciting packets of these
        /// numbers in the space now; then the packet `acked`, if any, was
        /// acknowledged, and losses were detected as an ACK does. It is one
        /// take: the handler sees only what it left.
        Send {
            space: PacketNumberSpaceKind,
            numbers: Vec<u64>,
            acked: Option<u64>,
        },
        /// The handshake is confirmed.
        Confirm,
        /// An ACK arriving now gives an RTT sample of a packet sent at the
        /// instant given.
        Sample(Duration),
        /// The link accepted, now, as many 1200-byte ack-eliciting packets
        /// as `count` in the space, as the sending call will: recorded in
        /// the send journals, each with one frame of the probe, numbered as
        /// its packet, and appended to the loss detection state.
        Sent {
            space: PacketNumberSpaceKind,
            count: u64,
        },
        /// The link accepted, now, a 50-byte packet with only an ACK frame
        /// of the space, as the ACK frame source and the sending call will:
        /// the frame acknowledges the largest packet number received.
        SentAck(PacketNumberSpaceKind),
        /// Log the RTT estimate, the window, the bytes in flight, the probe
        /// permits, the backoff and the first sample's arrival.
        Inspect,
        /// Discard the keys of the level of the Initial or the Handshake
        /// space, as the handshake will.
        Discard(PacketNumberSpaceKind),
        /// A datagram size probe of this many bytes was sealed, as the
        /// sending call will: it awaits its result.
        SealPmtuProbe(usize),
        /// Log the size of the datagram size probe that awaits its result,
        /// and whether the layer is the one of the link path over the
        /// logical link.
        InspectPmtu(LinkId<(), ()>),
        /// The ECN test starts with a marking, and its one marked packet of
        /// the Application Data space, which the link accepted, is declared
        /// lost: the validation fails.
        LoseEcnTest,
        /// The link accepted a marked packet of the Application Data space.
        MarkEcn,
        /// Log the ECN validation's outcome, the marked packets
        /// outstanding, and whether the layer is the one of the link path
        /// over the logical link.
        InspectEcn(LinkId<(), ()>),
    }

    /// In a server's first recovery layer: does its steps at their
    /// instants, and, when it was given any, logs the losses, the bytes in
    /// flight, the probe permits and the backoff whenever they change.
    #[derive(Debug)]
    pub struct Feeder(VecDeque<(Duration, Step)>, bool);
    type Fed<T> = HList![
        Feeder,
        LossDetectionOf<T, Parts>,
        LinkPathCongestionState<Duration>,
        PacketNumberSpaces<PacketNumberSpaceState>,
        HandshakeConfirmation,
        RttOf<T, Parts>,
        SendJournalsOf<T, Parts>,
        AckObligationsOf<T>,
        PacketNumberSpaces<ReceiveJournals<Duration>>,
        CongestionPartOf<T, Parts>,
        ProbeTimeout<Duration>,
        LinkPathEcnState<Duration>
    ];
    /// The feeder of the recovery layers of a connection of the choices `$t`.
    macro_rules! feeder {
        ($t:ty) => {
        impl Build<$t, Parts, layer::Recovery, ()> for Feeder {
            fn build<'v>(
                _: &mut ParentsOf<'v, $t, Parts, layer::Recovery>,
                _: &mut ArgsOf<$t, Parts, layer::Recovery>,
            ) -> Self {
                let steps = FEED.with(|f| core::mem::take(&mut *f.borrow_mut()));
                let given = !steps.is_empty();
                Feeder(steps, given)
            }
        }
        impl<I, Ith, K, Jd, Js, Jp, Ji, Jh>
            DataComponent<$t, Parts, layer::Recovery, (I, Ith, K, (Jd, Js, Jp), (Ji, Jh))> for Feeder
        where
            for<'v> <Parts as LineageLists<'v, $t>>::Recovery: GetAt<Feeder, I>
                + GetAt<InitialKeys<RingBackend>, Ji>
                + GetAt<HandshakeKeys<RingBackend>, Jh>
                + GetAt<LossThresholds, Ith>
                + GetAt<LossDetectionOf<$t, Parts>, Jd>
                + GetAt<LinkPathCongestionState<Duration>, Js>
                + GetAt<ProbeTimeout<Duration>, Jp>
                + TakeEach<'v, Fed<$t>, K>,
        {
            const DEADLINE: bool = true;
            fn subscribes(out: &mut EventSubscriptions) {
                out.add::<PacketsSent>()
                    .add::<AckReceived>()
                    .add::<PacketsLost>()
                    .add::<CongestionChanged>()
                    .add::<SpaceRetired>()
                    .add::<NodeStarted<layer::Recovery>>();
            }
            fn deadline<'v>(lineage: &LineageOf<'v, $t, Parts, layer::Recovery>) -> Option<Duration> {
                lineage.get::<Feeder, I>().0.front().map(|(at, _)| *at)
            }
            fn expire<'v, B: CallBundle>(
                mut lineage: LineageOf<'v, $t, Parts, layer::Recovery>,
                others: &mut OtherNodes<'v, $t, Parts, B>,
                now: Duration,
            ) -> Option<RequestOf<$t, Parts>> {
                // the keys are taken only when discarded
                if let Some((_, Step::Discard(space))) = lineage.get::<Feeder, I>().0.front() {
                    let space = *space;
                    lineage.get_mut::<Feeder, I>().0.pop_front();
                    match space {
                        PacketNumberSpaceKind::Initial => {
                            let discarded =
                                lineage.get_mut::<InitialKeys<RingBackend>, Ji>().discard();
                            if let Some(discarded) = discarded {
                                lineage.publish(discarded);
                            }
                        }
                        PacketNumberSpaceKind::Handshake => {
                            let discarded =
                                lineage.get_mut::<HandshakeKeys<RingBackend>, Jh>().discard();
                            if let Some(discarded) = discarded {
                                lineage.publish(discarded);
                            }
                        }
                        PacketNumberSpaceKind::ApplicationData => {
                            unreachable!("only the Initial and Handshake keys are discarded")
                        }
                    }
                    return None;
                }
                let thresholds = *lineage.get::<LossThresholds, Ith>();
                let (
                    hlist_pat![
                        mut feeder,
                        mut spaces,
                        mut state,
                        mut numbers,
                        mut confirmation,
                        mut rtt,
                        mut journals,
                        mut obligations,
                        mut received,
                        mut part,
                        pto,
                        mut ecn
                    ],
                    mut rest,
                ) = Take::<Fed<$t>, K>::take(lineage);
                let NodeKey::Recovery(_, here) = others.here().clone() else {
                    unreachable!("a recovery layer's lend carries its key")
                };
                let (_, step) = feeder.0.pop_front()?;
                match step {
                    Step::Send {
                        space,
                        numbers: sent,
                        acked,
                    } => {
                        let detection = spaces.get_mut(space)?;
                        for number in sent {
                            let charge = InFlightCharge {
                                bytes: 1200,
                                app_limited: false,
                                sent_state: Default::default(),
                            };
                            let number = PacketNumber::new(number).ok()?;
                            detection.accept(number, now, true, false, Some(charge));
                            state.add_in_flight(1200);
                        }
                        rest.publish(Happened::<PacketsSent>::new());
                        rest.publish(Happened::<CongestionChanged>::new());
                        let acked = PacketNumber::new(acked?).ok()?;
                        numbers.get_mut(space)?.on_ack(acked, acked);
                        for packet in detection.take_acknowledged(&(acked..=acked)) {
                            if let Some(charge) = packet.in_flight {
                                state.remove_in_flight(charge.bytes);
                            }
                        }
                        let delay = loss_delay(&RttEstimator::<Duration>::estimate(&*rtt), &thresholds);
                        let lost = detection
                            .detect_lost(now, acked, delay, thresholds.packet_threshold())
                            .count();
                        assert_eq!(lost, 0, "nothing is lost when the ACK arrives");
                        rest.publish(Happened::<AckReceived>::new());
                    }
                    Step::Confirm => {
                        if let Some(confirmed) = confirmation.confirm() {
                            rest.publish(confirmed);
                        }
                    }
                    Step::Sample(sent_at) => {
                        let sample =
                            RttSample::new(sent_at, now, Duration::ZERO, Duration::MAX, link())?;
                        rtt.on_sample(sample);
                        rest.publish(Happened::<RttSampled>::new());
                    }
                    Step::Sent { space, count } => {
                        let journals = journals.get_mut(space)?;
                        let detection = spaces.get_mut(space)?;
                        for _ in 0..count {
                            let mut attempt = journals.start_attempt(here.clone());
                            let number = attempt.packet_number();
                            attempt.record_frame(
                                InjectSummary::inject_summary(Summary(number.get())),
                                true,
                                true,
                            );
                            let sealed = attempt.seal(1200, false, EcnMarking::NotEct)?;
                            journals.sent(sealed, now);
                            let charge = InFlightCharge {
                                bytes: 1200,
                                app_limited: false,
                                sent_state: Default::default(),
                            };
                            detection.accept(number, now, true, false, Some(charge));
                            state.add_in_flight(1200);
                        }
                        rest.publish(Happened::<PacketsSent>::new());
                        rest.publish(Happened::<CongestionChanged>::new());
                    }
                    Step::SentAck(space) => {
                        let received = received.get_mut(space)?;
                        let (largest, _) = received.largest()?;
                        let before = obligations.get_mut(space)?.ack_written(largest);
                        received.on_ack_written();
                        let journals = journals.get_mut(space)?;
                        let mut attempt = journals.start_attempt(here.clone());
                        let number = attempt.packet_number();
                        attempt.record_frame(InjectSummary::inject_summary(AckSummary { largest, before }), false, false);
                        let sealed = attempt.seal(50, false, EcnMarking::NotEct)?;
                        journals.sent(sealed, now);
                        spaces.get_mut(space)?.accept(number, now, false, false, None);
                        rest.publish(Happened::<PacketsSent>::new());
                        rest.publish(Happened::<AckPendingChanged>::new());
                    }
                    Step::Inspect => {
                        let estimate = RttEstimator::<Duration>::estimate(&*rtt);
                        log(format!(
                            "rtt latest {:?}, smoothed {:?}, window {}, in flight {}, permits {}, \
                             backoff {}, first sample {:?}",
                            estimate.latest,
                            estimate.smoothed,
                            CongestionController::<Duration>::window(&*part),
                            state.bytes_in_flight(),
                            state.probe_permits(),
                            pto.backoff(),
                            state.first_rtt_sample_at(),
                        ));
                    }
                    Step::SealPmtuProbe(size) => state.on_pmtu_probe_sealed(size),
                    Step::InspectPmtu(link) => log(format!(
                        "probe awaited {:?}, over the link given {}",
                        state.pmtu_probe_awaited(),
                        here == link
                    )),
                    Step::LoseEcnTest => {
                        let estimate = RttEstimator::<Duration>::estimate(&*rtt);
                        let marking =
                            ecn.marking(&mut *part, true, false, now, estimate, ms(100));
                        ecn.on_accepted(PacketNumberSpaceKind::ApplicationData, marking);
                        ecn.on_lost(PacketNumberSpaceKind::ApplicationData, 1);
                    }
                    Step::MarkEcn => {
                        ecn.on_accepted(PacketNumberSpaceKind::ApplicationData, EcnMarking::Ect0);
                    }
                    Step::InspectEcn(link) => log(format!(
                        "ECN {:?}, marked outstanding {}, over the link given {}",
                        ecn.outcome(),
                        ecn.marked_outstanding(),
                        here == link
                    )),
                    Step::Discard(_) => unreachable!("discarded before the takes"),
                }
                None
            }
            fn on_events<'v, B: CallBundle>(
                _: TriggeredEvents<'_>,
                lineage: LineageOf<'v, $t, Parts, layer::Recovery>,
                _: &mut OtherNodes<'v, $t, Parts, B>,
                _: Duration,
            ) -> Option<RequestOf<$t, Parts>> {
                if !lineage.get::<Feeder, I>().1 {
                    return None;
                }
                let spaces = lineage.get::<LossDetectionOf<$t, Parts>, Jd>();
                let state = lineage.get::<LinkPathCongestionState<Duration>, Js>();
                let outstanding: usize = spaces.iter().map(|(_, d)| d.outstanding().len()).sum();
                let lost: Vec<_> = spaces
                    .iter()
                    .flat_map(|(_, d)| d.declared_lost())
                    .map(|p| (p.number.get(), p.retain_until))
                    .collect();
                let line = format!(
                    "in flight {}, outstanding {outstanding}, lost {lost:?}, permits {}, backoff {}",
                    state.bytes_in_flight(),
                    state.probe_permits(),
                    lineage.get::<ProbeTimeout<Duration>, Jp>().backoff(),
                );
                // the sending call takes the state it reads on each of its
                // polls: only a change is logged
                let changed = LAST_STATUS.with(|last| {
                    let mut last = last.borrow_mut();
                    let changed = last.as_deref() != Some(line.as_str());
                    *last = Some(line.clone());
                    changed
                });
                if changed {
                    log(line);
                }
                None
            }
        }
        };
    }
    feeder!(Mine);
    feeder!(ClientMine);
    feeder!(SpyMine);

    impl LayerShare<SpyMine, Parts, layer::Connection> for Part {
        type Data = HList![Adder, Lender];
        type Calls = HNil;
    }
    impl LayerShare<Mine, Parts, layer::Connection> for Part {
        type Data = HList![Adder, PeerSetter, Closer, CryptoFeeder, CryptoWriter, Mover];
        type Calls = HNil;
    }
    impl LayerShare<ClientMine, Parts, layer::Connection> for Part {
        type Data = HList![Adder];
        type Calls = HNil;
    }
    impl<T: v1::Choices, L> LayerShare<T, L, layer::LinkEntry> for Part {
        type Data = HList![EntryEnd];
        type Calls = HNil;
    }
    impl<T: v1::Choices, L> LayerShare<T, L, layer::LinkPath> for Part {
        type Data = HList![Watcher];
        type Calls = HNil;
    }
    macro_rules! none {
        ($($lv:ident),*) => {$(
            impl<T: v1::Choices, L> LayerShare<T, L, layer::$lv> for Part {
                type Data = HNil;
                type Calls = HNil;
            }
        )*};
    }
    impl LayerShare<Mine, Parts, layer::Recovery> for Part {
        type Data = HList![LayerWatch, Feeder];
        type Calls = HNil;
    }
    impl LayerShare<SpyMine, Parts, layer::Recovery> for Part {
        type Data = HList![LayerWatch, Feeder];
        type Calls = HNil;
    }
    impl LayerShare<ClientMine, Parts, layer::Recovery> for Part {
        type Data = HList![LayerWatch, Feeder];
        type Calls = HNil;
    }
    impl LayerShare<Mine, Parts, layer::LogicalPath> for Part {
        type Data = HList![PacketFeeder];
        type Calls = HNil;
    }
    impl LayerShare<SpyMine, Parts, layer::LogicalPath> for Part {
        type Data = HList![PacketFeeder];
        type Calls = HNil;
    }
    impl LayerShare<ClientMine, Parts, layer::LogicalPath> for Part {
        type Data = HList![PacketFeeder];
        type Calls = HNil;
    }
    none!(Established);
}

/// The Destination Connection ID of the client's first Initial packet that
/// the tests' connections are made with.
fn client_dcid() -> ConnectionId {
    // invariant: eight bytes is a valid connection ID length
    ConnectionId::new(&CLIENT_DCID).expect("eight bytes")
}

const CLIENT_DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

/// The connection ID the tests' connections are made with as their own.
fn server_cid() -> ConnectionId {
    // invariant: eight bytes is a valid connection ID length
    ConnectionId::new(&SERVER_CID).expect("eight bytes")
}

const SERVER_CID: [u8; 8] = [0x5e, 0x5e, 0x5e, 0x5e, 0x01, 0x02, 0x03, 0x04];

/// Version 1's facts for a connection whose first logical link is
/// `validation`.
fn args<T>(validation: AddressValidation) -> v1::ConnectionArgs<T, Parts>
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
    T::Side: SideCapacities,
    <HostOf<T> as HostChoices<T>>::Recovery<LinkId<(), ()>>:
        RecoveryFactory<TestLink, Config: Default>,
{
    let close_request = CloseRequestCell::new();
    CLOSE_REQUEST.with(|c| *c.borrow_mut() = Some(close_request.clone()));
    let mut parameters = TransportParameters::<Vec<u8>>::new();
    parameters.set(MaxIdleTimeout::new(VarInt::from_u32(30_000)));
    v1::ConnectionArgs {
        crypto: RingBackend,
        handshake: <T::Side as SideCapacities>::handshake(),
        side: <T::Side as SideCapacities>::side(),
        client_dcid: client_dcid(),
        original_destination_connection_id: None,
        anti_amplification: AntiAmplificationFactor::new(2).expect("2 is a factor"),
        transport_parameters: parameters.known,
        first_link: LinkFacts { validation },
        // the recommended values for timers that fire to the millisecond
        recovery: Default::default(),
        loss_thresholds: sakuya_recovery_v1::loss::LossThresholds::recommended(ms(1))
            .expect("the test clock's timers fire to the millisecond"),
        max_ack_ranges: MAX_ACK_RANGES.with(Cell::get),
        key_update: v1::aead_usage::KeyUpdateThreshold {
            after_packets: KEY_UPDATE_AFTER.with(Cell::get),
        },
        crypto_receive: <T::Side as SideCapacities>::crypto_receive(),
        first_flight: first_flight::<T>(),
        initial_receiver: initial_receiver(),
        max_datagrams_per_poll: NonZeroUsize::new(MAX_PER_POLL.with(Cell::get))
            .expect("the tests handle at least one input per poll"),
        max_held_inputs: MAX_HELD.with(Cell::get),
        destination_connection_ids:
            sakuya_connection::connection_id::sequence_map::SequenceMapDestinationConnectionIdStrategyConfig::new(8),
        // after the initial receiver, which made the routing domain
        reset_token_registry: ROUTING.with(|r| {
            r.borrow()
                .as_ref()
                .expect("the initial receiver made a routing domain")
                .reset_tokens
                .clone()
        }),
        first_local_connection_id: v1::connection_ids::FirstLocalConnectionId::Issued {
            id: NonEmptyCid::new(server_cid()).expect("not empty"),
            reset_token: sakuya_wire_v1::connection_id::StatelessResetToken::new([0x5e; 16]),
        },
        local_connection_id_issuer: v1::connection_ids::LocalConnectionIdIssuer::new(
            common::TestConnectionIdIssuer::default(),
            Some(()),
        ),
        max_datagrams_per_send: NonZeroUsize::new(MAX_PER_SEND.with(Cell::get))
            .expect("the tests send at least one datagram at once"),
        immediate_close_policy: common::TestImmediateClosePolicy,
        resumed_parameters_policy: v1::parameters::UseConfiguredParameters,
        close_request,
        stream_set: Default::default(),
        events: Default::default(),
    }
}

/// The first flight the next connection is made with.
fn first_flight<T>() -> FirstFlight<T>
where
    T: v1::Choices<Crypto = RingBackend, Link = TestLink>,
    T::Side: SideCapacities,
{
    if FIRST_READ.with(Cell::get) {
        FirstFlight::Read(<T::Side as SideCapacities>::read_state())
    } else {
        FirstFlight::Datagrams(FIRST_DATAGRAMS.with(|f| core::mem::take(&mut *f.borrow_mut())))
    }
}

/// The CRYPTO capacities of a side: the least the default message limits
/// allow at each level; and for a server, a first flight read before the
/// connection is made.
trait SideCapacities: v1::Side {
    fn handshake() -> v1::advancing::HandshakeStart<<Self as v1::Side>::Tls>;
    fn side() -> <Self as v1::Side>::Start;
    fn crypto_receive() -> CryptoReceiveCapacities;
    fn read_state<T>() -> FirstFlightReadState<T>
    where
        T: v1::Choices<Crypto = RingBackend, Side = Self>;
}
impl SideCapacities for v1::Server<common::PendingServerEngine, common::TestNewTokenIssuer> {
    fn handshake() -> v1::advancing::HandshakeStart<common::PendingServerEngine> {
        v1::advancing::HandshakeStart::new(common::PendingServerEngine, MessageLimits::default())
    }
    fn side() -> v1::new_token::ServerOnlyStart<common::TestNewTokenIssuer> {
        v1::new_token::ServerOnlyStart::new(common::TestNewTokenIssuer)
    }
    fn read_state<T>() -> FirstFlightReadState<T>
    where
        T: v1::Choices<Crypto = RingBackend, Side = Self>,
    {
        READ_STATE
            .with(|r| r.borrow_mut().take())
            .map(|state| {
                *state
                    .downcast()
                    .expect("the state of the connection's choices")
            })
            .unwrap_or_else(|| {
                FirstFlightReadState::new(
                    &RingBackend,
                    &client_dcid(),
                    &Self::crypto_receive(),
                    MaxAckRanges::DEFAULT,
                    MAX_HELD.with(Cell::get),
                )
            })
    }
    fn crypto_receive() -> CryptoReceiveCapacities {
        // ClientHello at Initial; only Finished at Handshake
        CryptoReceiveCapacities::server(MessageLimits::default(), false, 16 * 1024 + 4, 4096)
            .expect("the least capacities the limits allow")
    }
}
impl SideCapacities
    for v1::Client<common::PendingClientEngine, (), v1::retry::ContinueOnRetry, ()>
{
    fn handshake() -> v1::advancing::HandshakeStart<common::PendingClientEngine> {
        v1::advancing::HandshakeStart::new(common::PendingClientEngine, MessageLimits::default())
    }
    fn side() -> <Self as v1::Side>::Start {
        v1::handshake_done::ClientOnlyStart::new(
            bytes::Bytes::new(),
            (),
            v1::retry::ContinueOnRetry,
            (),
        )
    }
    fn read_state<T>() -> FirstFlightReadState<T>
    where
        T: v1::Choices<Crypto = RingBackend, Side = Self>,
    {
        unreachable!("only a server reads its first flight before deciding")
    }
    fn crypto_receive() -> CryptoReceiveCapacities {
        // ServerHello at Initial, Certificate at Handshake, NewSessionTicket
        // at 1-RTT
        CryptoReceiveCapacities::client(
            MessageLimits::default(),
            16 * 1024 + 4,
            64 * 1024 + 4,
            16 * 1024 + 4,
        )
        .expect("the least capacities the limits allow")
    }
}

/// A connection of version 1 and the probe with the choices `$t`.
macro_rules! connection {
    (@args $t:ty, $args:expr, $first:expr) => {
        <$t as sakuya_connection::composition::Composition<$t, Parts>>::connection(
            TestClock,
            frunk_core::hlist![$args, HNil],
            LogicalPathArgs { path: PATH },
            LinkPathArgs {
                path: PATH,
                link: TestLink($first),
                role: LinkPathRole::Active,
                peer_switched_local_id: false,
            },
        )
        .0
    };
    ($t:ty, $validation:expr, $first:expr) => {
        connection!(@args $t, args::<$t>($validation), $first)
    };
}

/// A connection as [`connection!`] makes it, in a wrapper of one thread:
/// the future that drives it there, and its connection handle.
macro_rules! handled_connection {
    ($t:ty, $validation:expr, $first:expr) => {{
        let shared = std::rc::Rc::new(core::cell::RefCell::new(connection!(
            $t,
            $validation,
            $first
        )));
        (
            sakuya_connection::shared::SharedConnectionDriver::new(shared.clone()),
            ConnectionHandle::new(shared),
        )
    }};
}

#[test]
fn a_server_connection_starts_with_live_initial_keys_and_an_active_link_path() {
    reset();
    let _connection = connection!(Mine, AddressValidation::NotValidated, link());
    assert_eq!(
        take_log(),
        [
            "initial keys live: true",
            "recovery built, initial RTT None",
            "Active, NotValidated, credit Some(0)",
        ]
    );
}

#[test]
fn the_connection_receives_crypto_data_as_its_side_does() {
    reset();
    CRYPTO_AT.with(|c| c.set(Some(ms(5))));
    let mut connection = connection!(Mine, AddressValidation::NotValidated, link());
    take_log();
    let outer = Outer::new();
    advance_to(ms(5));
    assert!(outer.poll(&mut connection).is_pending());
    // a server receives no handshake messages at 1-RTT
    assert_eq!(
        take_log(),
        ["1-RTT: Err(Refused)", "Initial: Ok(()), read \"hello\""]
    );
}

#[test]
fn a_later_link_path_is_a_candidate_over_an_entry_the_side_starts() {
    reset();
    ADD.with(|a| a.set(Some((ms(10), link()))));
    let mut server = connection!(Mine, AddressValidation::Validated, link());
    assert_eq!(
        take_log()[1..],
        [
            "recovery built, initial RTT None",
            "Active, Validated, credit None"
        ]
    );
    let outer = Outer::new();
    advance_to(ms(10));
    assert!(outer.poll(&mut server).is_pending());
    assert_eq!(take_log(), ["Candidate, NotValidated, credit Some(0)"]);

    ADD.with(|a| a.set(Some((ms(10), link()))));
    advance_to(ms(0));
    let mut client = connection!(ClientMine, AddressValidation::Validated, link());
    take_log();
    advance_to(ms(10));
    assert!(outer.poll(&mut client).is_pending());
    assert_eq!(take_log(), ["Candidate, Validated, credit None"]);
}

#[test]
fn a_link_path_ends_at_the_end_time_of_its_role() {
    reset();
    ADD.with(|a| a.set(Some((ms(10), link()))));
    CLOSE_AT.with(|c| c.set(Some(ms(20))));
    let mut connection = connection!(Mine, AddressValidation::NotValidated, link());
    let outer = Outer::new();
    advance_to(ms(10));
    assert!(outer.poll(&mut connection).is_pending());
    take_log();
    advance_to(ms(20));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(
        take_log(),
        [
            // the active link path's recovery layer goes as it closes; the
            // candidate had none
            "recovery ended",
            "Closing(50ms), NotValidated, credit Some(0)",
            "Closing(50ms), NotValidated, credit Some(0)",
        ]
    );
    advance_to(ms(50));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(
        take_log(),
        [
            // the roles closed themselves: no reason is written, and the
            // connection goes on without link paths
            "link path ended: None",
            "entry ended",
            "link path ended: None",
            "entry ended",
        ]
    );
}

#[test]
fn the_idle_timeout_follows_the_peer_and_ends_the_connection() {
    reset();
    PEER_AT.with(|p| p.set(Some(ms(5))));
    let mut connection = connection!(Mine, AddressValidation::NotValidated, link());
    take_log();
    let outer = Outer::new();
    advance_to(ms(5));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(take_log(), ["packet processed at 5ms"]);
    // the smaller of 30 s and 10 s, from the packet
    advance_to(ms(10_004));
    assert!(outer.poll(&mut connection).is_pending());
    advance_to(ms(10_005));
    assert!(outer.poll(&mut connection).is_ready(), "ended silently");
    assert_eq!(
        take_log(),
        [
            "recovery ended",
            "link path ended: Some(IdleTimeout)",
            "entry ended"
        ]
    );
}

/// What `future` gives on its first poll.
fn poll_now<F: core::future::Future>(future: F) -> core::task::Poll<F::Output> {
    core::pin::pin!(future).poll(&mut core::task::Context::from_waker(
        core::task::Waker::noop(),
    ))
}

#[test]
fn the_connection_handle_gives_the_idle_timeout_of_a_connection_that_ended_at_once() {
    reset();
    PEER_AT.with(|p| p.set(Some(ms(5))));
    let (mut connection, handle) =
        handled_connection!(Mine, AddressValidation::NotValidated, link());
    let outer = Outer::new();
    advance_to(ms(5));
    assert!(outer.poll(&mut connection).is_pending());
    assert!(poll_now(handle.closed()).is_pending());
    advance_to(ms(10_005));
    assert!(outer.poll(&mut connection).is_ready(), "ended silently");
    let closed = poll_now(handle.closed());
    assert!(
        matches!(closed, core::task::Poll::Ready(CloseReason::IdleTimeout)),
        "{closed:?}"
    );
    assert!(matches!(
        poll_now(handle.handshake_completed()),
        core::task::Poll::Ready(Err(error))
            if matches!(error.reason(), CloseReason::IdleTimeout)
    ));
}

#[test]
fn the_keys_go_once_every_link_path_drains() {
    reset();
    CLOSE_AT.with(|c| c.set(Some(ms(20))));
    DRAIN.with(|d| d.set(true));
    let mut connection = connection!(Mine, AddressValidation::NotValidated, link());
    take_log();
    let outer = Outer::new();
    advance_to(ms(20));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(
        take_log(),
        [
            "recovery ended",
            "Draining(50ms), NotValidated, credit Some(0)",
            "initial keys live: false",
        ]
    );
}

#[test]
fn a_close_of_this_side_closes_the_link_paths_and_ends_the_connection_after_them() {
    reset();
    ADD.with(|a| a.set(Some((ms(10), link()))));
    CLOSER.with(|c| {
        c.borrow_mut().extend([
            (ms(12), probe::CloserStep::Establish),
            (ms(14), probe::CloserStep::LogEstablished),
            (ms(20), probe::CloserStep::Close),
            (ms(21), probe::CloserStep::LogEstablished),
        ])
    });
    let mut connection = connection!(Mine, AddressValidation::NotValidated, link());
    let outer = Outer::new();
    for at in [10, 12, 14] {
        advance_to(ms(at));
        assert!(outer.poll(&mut connection).is_pending());
    }
    assert_eq!(take_log()[4..], ["established: true"]);
    advance_to(ms(20));
    assert!(outer.poll(&mut connection).is_pending());
    let pto = probe_timeout(
        &sakuya_recovery_v1::rtt::RttEstimate::initial(sakuya_recovery_v1::rtt::INITIAL_RTT),
        ms(1),
        PacketNumberSpaceKind::ApplicationData,
        ms(25),
        0,
    );
    let closing = format!(
        "Closing({:?}), NotValidated, credit Some(0)",
        ms(20) + pto * 3
    );
    assert_eq!(
        take_log(),
        [
            "closed by the application".to_owned(),
            // the active link path closes for three probe timeouts and its
            // recovery layer goes; the candidate ends at once
            "recovery ended".to_owned(),
            "link path ended: Some(Local(Application(AppClose(7))))".to_owned(),
            "entry ended".to_owned(),
            closing,
        ]
    );
    advance_to(ms(21));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(take_log(), ["established: false"]);
    advance_to(ms(20) + pto * 3 - ms(1));
    assert!(outer.poll(&mut connection).is_pending());
    advance_to(ms(20) + pto * 3);
    assert!(
        outer.poll(&mut connection).is_ready(),
        "the connection ends with its last link path"
    );
    assert_eq!(
        take_log(),
        [
            "link path ended: Some(Local(Application(AppClose(7))))",
            "entry ended"
        ]
    );
}

// ---- the end of a link ----

#[test]
fn the_end_of_the_last_link_ends_the_connection_at_once_with_nothing_sent() {
    reset();
    let first = link();
    let (mut connection, handle) =
        handled_connection!(Mine, AddressValidation::NotValidated, first.clone());
    let outer = Outer::new();
    assert!(outer.poll(&mut connection).is_pending());
    take_log();
    common::take_sent();
    advance_to(ms(10));
    common::end_link(&first);
    assert!(outer.poll(&mut connection).is_ready(), "it ends at once");
    assert_eq!(
        take_log(),
        [
            "recovery ended",
            "link path ended: Some(Local(LinkEnded(())))",
            "entry ended"
        ]
    );
    assert_eq!(common::take_sent(), [], "nothing goes out");
    assert_eq!(
        common::take_adjusted_levels(),
        [],
        "the close policy is not asked"
    );
    let closed = poll_now(handle.closed());
    assert!(
        matches!(
            &closed,
            core::task::Poll::Ready(CloseReason::Local(cause))
                if matches!(**cause, LocalCloseCause::LinkEnded(()))
        ),
        "{closed:?}"
    );
}

#[test]
fn the_end_of_one_link_ends_its_link_paths_and_the_connection_goes_on() {
    reset();
    let (first, second) = (link(), link());
    ADD.with(|a| a.set(Some((ms(10), second.clone()))));
    let (mut connection, handle) =
        handled_connection!(Mine, AddressValidation::NotValidated, first.clone());
    let outer = Outer::new();
    advance_to(ms(10));
    assert!(outer.poll(&mut connection).is_pending());
    take_log();
    // the second link ends: its candidate goes, the first link stays
    advance_to(ms(20));
    common::end_link(&second);
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(take_log(), ["link path ended: None", "entry ended"]);
    // the first link ends next: it was the last
    advance_to(ms(30));
    common::end_link(&first);
    assert!(outer.poll(&mut connection).is_ready());
    assert_eq!(
        take_log(),
        [
            "recovery ended",
            "link path ended: Some(Local(LinkEnded(())))",
            "entry ended"
        ]
    );
    assert!(matches!(
        poll_now(handle.closed()),
        core::task::Poll::Ready(CloseReason::Local(_))
    ));
}

#[test]
fn the_end_of_the_active_link_leaves_the_candidate_and_the_connection_open() {
    reset();
    let (first, second) = (link(), link());
    ADD.with(|a| a.set(Some((ms(10), second))));
    let (mut connection, handle) =
        handled_connection!(Mine, AddressValidation::NotValidated, first.clone());
    let outer = Outer::new();
    advance_to(ms(10));
    assert!(outer.poll(&mut connection).is_pending());
    take_log();
    advance_to(ms(20));
    common::end_link(&first);
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(
        take_log(),
        ["recovery ended", "link path ended: None", "entry ended"]
    );
    assert!(
        poll_now(handle.closed()).is_pending(),
        "nothing is recorded"
    );
}

#[test]
fn a_link_that_ends_while_the_connection_closes_keeps_the_first_reason() {
    reset();
    let first = link();
    CLOSER.with(|c| c.borrow_mut().push_back((ms(20), probe::CloserStep::Close)));
    let (mut connection, handle) =
        handled_connection!(Mine, AddressValidation::NotValidated, first.clone());
    let outer = Outer::new();
    assert!(outer.poll(&mut connection).is_pending());
    advance_to(ms(20));
    assert!(outer.poll(&mut connection).is_pending());
    take_log();
    // the link ends within the closing period: the link path ends, and the
    // connection with it, for the reason written first
    advance_to(ms(21));
    common::end_link(&first);
    assert!(outer.poll(&mut connection).is_ready());
    assert_eq!(
        take_log(),
        [
            "link path ended: Some(Local(Application(AppClose(7))))",
            "entry ended"
        ]
    );
    assert!(matches!(
        poll_now(handle.closed()),
        core::task::Poll::Ready(CloseReason::Local(cause))
            if matches!(*cause, LocalCloseCause::Application(common::AppClose(7)))
    ));
}

#[test]
fn a_connection_dropped_with_no_reason_recorded_ends_aborted() {
    reset();
    let mut connection = connection!(Mine, AddressValidation::NotValidated, link());
    let outer = Outer::new();
    assert!(outer.poll(&mut connection).is_pending());
    take_log();
    // a request no poll took in yet is not the reason
    close_request().request(common::AppClose(9));
    drop(connection);
    assert_eq!(
        take_log(),
        [
            "recovery ended",
            "link path ended: Some(Aborted(DriverDropped))",
            "entry ended"
        ]
    );
}

#[test]
fn a_connection_dropped_before_its_first_poll_ends_aborted() {
    reset();
    let connection = connection!(Mine, AddressValidation::NotValidated, link());
    take_log();
    drop(connection);
    assert_eq!(
        take_log(),
        [
            "recovery ended",
            "link path ended: Some(Aborted(DriverDropped))",
            "entry ended"
        ]
    );
}

#[test]
fn a_link_path_made_active_gets_its_recovery_layer_and_is_seen_beside_another() {
    // what the recovery layers and the factory log, without the probe's roles
    fn recovery_log() -> Vec<String> {
        take_log()
            .into_iter()
            .filter(|line| line.starts_with("recovery") || line.starts_with("lent"))
            .collect()
    }
    reset();
    ADD.with(|a| a.set(Some((ms(5), link()))));
    LEND_AT.with(|l| l.set(Some((ms(10), ms(20)))));
    let mut connection = connection!(SpyMine, AddressValidation::NotValidated, link());
    assert_eq!(recovery_log(), ["recovery built, initial RTT None"]);
    let outer = Outer::new();
    advance_to(ms(5));
    assert!(outer.poll(&mut connection).is_pending());
    // the candidate has no recovery layer
    assert_eq!(recovery_log(), [] as [&str; 0]);
    advance_to(ms(10));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(recovery_log(), ["recovery built, initial RTT None"]);
    advance_to(ms(20));
    assert!(outer.poll(&mut connection).is_pending());
    let log = recovery_log();
    // the factory sees the other layer only, read only, with its estimate:
    // as the first link path's access is lent, and as the second's sending
    // call, woken when its layer was built, lends its own
    assert_eq!(log.len(), 2, "{log:?}");
    for line in &log {
        assert!(
            line.starts_with("lent beside Recovery(SoleLogicalPath, ")
                && line.ends_with("smoothed 333ms"),
            "{log:?}"
        );
    }
    assert_ne!(log[0], log[1], "each beside the other");
    // the pacer's next release is the part's deadline; when it comes the
    // pacer is refilled, and the debug checks of each poll find the
    // deadline gone or later
    let wakes = outer.wakes();
    advance_to(ms(100));
    assert_eq!(outer.wakes(), wakes + 1, "woken for the release");
    assert!(outer.poll(&mut connection).is_pending());
    // the sleep that ended is polled once more and wakes the connection for
    // nothing; that poll sleeps until the next deadline
    assert_eq!(outer.wakes(), wakes + 2);
    assert!(outer.poll(&mut connection).is_pending());
    // refilled: nothing more until the idle timeout
    advance_to(ms(1000));
    assert_eq!(outer.wakes(), wakes + 2);
}

/// The feeder of the next server's first recovery layer does `steps`.
fn feed(steps: impl IntoIterator<Item = (Duration, probe::Step)>) {
    FEED.with(|f| f.borrow_mut().extend(steps));
}

/// The lines the feeder logged since the last call: each a change of what
/// it logs.
fn statuses() -> Vec<String> {
    take_log()
        .into_iter()
        .filter(|line| line.starts_with("in flight"))
        .collect()
}

/// The last line the feeder logged since the last call; `None` if none.
fn status() -> Option<String> {
    statuses().pop()
}

#[test]
fn the_time_threshold_declares_lost_what_it_waits_on() {
    reset();
    feed([(
        ms(10),
        probe::Step::Send {
            space: PacketNumberSpaceKind::Initial,
            numbers: vec![0, 1, 2],
            acked: Some(2),
        },
    )]);
    let mut connection = connection!(Mine, AddressValidation::Validated, link());
    take_log();
    let outer = Outer::new();
    advance_to(ms(10));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(
        status().as_deref(),
        Some("in flight 2400, outstanding 2, lost [], permits 0, backoff 0")
    );
    // 9/8 of the initial RTT of 333 ms after they were sent; meanwhile the
    // probe timeout waits on the time threshold
    advance_to(ms(384));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(status(), None);
    advance_to(ms(385));
    assert!(outer.poll(&mut connection).is_pending());
    // kept for three probe timeouts of 999 ms; NewReno asks to send one
    // datagram as its window comes down
    assert_eq!(
        status().as_deref(),
        Some(
            "in flight 0, outstanding 0, lost [(0, 3.382s), (1, 3.382s)], permits 1, \
             backoff 0"
        )
    );
}

#[test]
fn the_probe_timeout_backs_off_and_grants_probe_permits() {
    reset();
    feed([(
        ms(10),
        probe::Step::Send {
            space: PacketNumberSpaceKind::Initial,
            numbers: vec![0],
            acked: None,
        },
    )]);
    let mut connection = connection!(Mine, AddressValidation::Validated, link());
    let outer = Outer::new();
    advance_to(ms(10));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(
        status().as_deref(),
        Some("in flight 1200, outstanding 1, lost [], permits 0, backoff 0")
    );
    // 333 ms + 4 × 166.5 ms, without max_ack_delay in the Initial space
    advance_to(ms(1008));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(status(), None);
    advance_to(ms(1009));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(
        status().as_deref(),
        Some("in flight 1200, outstanding 1, lost [], permits 2, backoff 1")
    );
    // twice as long, from the expiry: no probe was sent since
    advance_to(ms(3006));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(status(), None);
    advance_to(ms(3007));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(
        status().as_deref(),
        Some("in flight 1200, outstanding 1, lost [], permits 4, backoff 2")
    );
}

#[test]
fn the_probe_timeout_leaves_out_application_data_until_the_handshake_is_confirmed() {
    use probe::PacketStep::{HandshakeConnectionId, InstallOneRttSendKeys};
    reset();
    // the strategy plans nothing: nothing is sent, and what is gathered
    // stays
    common::strategy::plan_nothing();
    // a connection ID to send to and the 1-RTT keys to send with, so that
    // a PING of the space can go once the handshake is confirmed
    feed_packets([
        (
            ms(1200),
            HandshakeConnectionId(ConnectionId::new(&CLIENT_SCID).expect("eight bytes")),
        ),
        (ms(1201), InstallOneRttSendKeys),
    ]);
    feed([
        (
            ms(10),
            probe::Step::Send {
                space: PacketNumberSpaceKind::ApplicationData,
                numbers: vec![0],
                acked: None,
            },
        ),
        (ms(1500), probe::Step::Confirm),
    ]);
    let mut connection = connection!(Mine, AddressValidation::Validated, link());
    let outer = Outer::new();
    advance_to(ms(10));
    assert!(outer.poll(&mut connection).is_pending());
    take_log();
    // it would have expired at 1034 ms, with the peer's max_ack_delay of
    // 25 ms by default
    advance_to(ms(1100));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(status(), None);
    let _ = run(&mut connection, 1101..=1499);
    assert_eq!(
        strategy_events("path 0: content ProbePingIntent"),
        Vec::<String>::new()
    );
    // once confirmed it is past and expires at once
    advance_to(ms(1500));
    let mut lines = Vec::new();
    for _ in 0..3 {
        assert!(outer.poll(&mut connection).is_pending());
        lines.extend(statuses());
    }
    assert_eq!(
        lines.last().map(String::as_str),
        Some("in flight 1200, outstanding 1, lost [], permits 2, backoff 1"),
        "{lines:?}"
    );
    // the space is probed with a PING only once it is probed at all
    assert_eq!(
        strategy_events("path 0: content ProbePingIntent"),
        ["path 0: content ProbePingIntent { space: ApplicationData }"]
    );
}

#[test]
fn a_late_poll_expires_the_probe_timeout_once_and_counts_the_next_from_then() {
    reset();
    feed([(
        ms(10),
        probe::Step::Send {
            space: PacketNumberSpaceKind::Initial,
            numbers: vec![0],
            acked: None,
        },
    )]);
    let mut connection = connection!(Mine, AddressValidation::Validated, link());
    let outer = Outer::new();
    advance_to(ms(10));
    assert!(outer.poll(&mut connection).is_pending());
    take_log();
    // due at 1009 ms, polled long after
    advance_to(ms(5000));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(
        statuses(),
        ["in flight 1200, outstanding 1, lost [], permits 2, backoff 1"]
    );
    advance_to(ms(6997));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(status(), None);
    advance_to(ms(6998));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(
        status().as_deref(),
        Some("in flight 1200, outstanding 1, lost [], permits 4, backoff 2")
    );
}

#[test]
fn a_client_probes_with_nothing_in_flight_until_a_handshake_packet_is_acknowledged() {
    reset();
    feed([
        (
            ms(10),
            probe::Step::Send {
                space: PacketNumberSpaceKind::Initial,
                numbers: vec![0],
                acked: None,
            },
        ),
        (
            ms(20),
            probe::Step::Send {
                space: PacketNumberSpaceKind::Initial,
                numbers: vec![],
                acked: Some(0),
            },
        ),
    ]);
    let mut connection = connection!(ClientMine, AddressValidation::Validated, link());
    let outer = Outer::new();
    advance_to(ms(10));
    assert!(outer.poll(&mut connection).is_pending());
    advance_to(ms(20));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(
        status().as_deref(),
        Some("in flight 0, outstanding 0, lost [], permits 0, backoff 0")
    );
    // from when nothing was left in flight, in the Initial space: there are
    // no Handshake keys yet
    advance_to(ms(1018));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(status(), None);
    advance_to(ms(1019));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(
        status().as_deref(),
        Some("in flight 0, outstanding 0, lost [], permits 2, backoff 1")
    );
    advance_to(ms(3016));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(status(), None);
    advance_to(ms(3017));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(
        status().as_deref(),
        Some("in flight 0, outstanding 0, lost [], permits 4, backoff 2")
    );
}

#[test]
fn a_client_whose_handshake_packet_was_acknowledged_does_not_probe_with_nothing_in_flight() {
    reset();
    feed([(
        ms(10),
        probe::Step::Send {
            space: PacketNumberSpaceKind::Handshake,
            numbers: vec![0],
            acked: Some(0),
        },
    )]);
    let mut connection = connection!(ClientMine, AddressValidation::Validated, link());
    let outer = Outer::new();
    advance_to(ms(10));
    assert!(outer.poll(&mut connection).is_pending());
    take_log();
    advance_to(ms(5000));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(status(), None);
}

#[test]
fn a_server_does_not_probe_with_nothing_in_flight() {
    reset();
    feed([(
        ms(10),
        probe::Step::Send {
            space: PacketNumberSpaceKind::Initial,
            numbers: vec![0],
            acked: Some(0),
        },
    )]);
    let mut connection = connection!(Mine, AddressValidation::Validated, link());
    let outer = Outer::new();
    advance_to(ms(10));
    assert!(outer.poll(&mut connection).is_pending());
    take_log();
    advance_to(ms(5000));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(status(), None);
}

#[test]
fn the_idle_timeout_is_at_least_three_probe_timeouts_of_the_current_rtt() {
    reset();
    PEER_AT.with(|p| p.set(Some(ms(5))));
    feed([(ms(4010), probe::Step::Sample(ms(10)))]);
    let mut connection = connection!(Mine, AddressValidation::Validated, link());
    let outer = Outer::new();
    advance_to(ms(5));
    assert!(outer.poll(&mut connection).is_pending());
    // a sample of 4 s: a probe timeout of 4 s + 4 × 2 s + 25 ms, three of
    // which are longer than the peer's 10 s
    advance_to(ms(4010));
    assert!(outer.poll(&mut connection).is_pending());
    advance_to(ms(10_005));
    assert!(outer.poll(&mut connection).is_pending());
    advance_to(ms(36_079));
    assert!(outer.poll(&mut connection).is_pending());
    advance_to(ms(36_080));
    assert!(outer.poll(&mut connection).is_ready(), "ended silently");
}

/// The sizes of the data of each layer of a version 1 connection, for the
/// choice between keeping child nodes inline and allocating them when they
/// are built. It only prints: run it with `--nocapture`.
#[test]
fn sizes_of_the_layers() {
    use core::mem::size_of;
    type V1 = HList![v1::Part];
    macro_rules! sizes {
        ($($lv:ident),*) => {$(
            eprintln!(
                "{}: {} bytes",
                stringify!($lv),
                size_of::<NodeData<Mine, V1, layer::$lv>>()
            );
        )*};
    }
    sizes!(
        Connection,
        LinkEntry,
        LogicalPath,
        LinkPath,
        Established,
        Recovery
    );
    eprintln!("RTT: {} bytes", size_of::<RttOf<Mine, V1>>());
    eprintln!(
        "congestion part: {} bytes",
        size_of::<CongestionPartOf<Mine, V1>>()
    );
    eprintln!(
        "PMTU: {} bytes",
        size_of::<sakuya_connection::v1::recovery::PmtuOf<Mine, V1>>()
    );
}

/// Version 1 alone dispatches every frame its set reads: the positions of
/// what its dispatch takes are found from the composition.
#[test]
fn version_1_dispatches_the_frames_it_reads() {
    use sakuya_connection::dispatch::FrameSetDispatch;
    fn dispatches<T: ConnectionChoices, L, Hs>()
    where
        for<'v> L: LineageLists<'v, T>,
        L: FrameSetDispatch<T, L, Hs>,
    {
    }
    dispatches::<Mine, HList![v1::Part], _>();
}

/// What filling leaves of a link path's lineage, where each part finds its
/// frame sources, still holds the logical path's connection IDs to change:
/// a frame source can write frames of the destination connection ID
/// strategy, and filling reports a connection ID's use there.
#[test]
fn filling_leaves_the_connection_ids_to_change() {
    use core::marker::PhantomData;
    use sakuya_connection::{
        take::RefsOf,
        v1::{
            connection_ids::ConnectionIdsOf,
            sending::{FillReadTakes, FillTakes},
        },
    };
    /// What is left of `V` once `U` is taken.
    fn rest<'x, V, U, I>(_: PhantomData<V>, _: PhantomData<U>) -> PhantomData<V::Rest>
    where
        V: TakeEach<'x, U, I>,
        U: RefsOf<'x>,
    {
        PhantomData
    }
    /// `V` holds `X`, to read or change.
    fn holds<V: GetAt<X, I>, X, I>(_: PhantomData<V>, _: PhantomData<X>) {}
    let link_path = PhantomData::<<Parts as LineageLists<'static, Mine>>::LinkPath>;
    let keys_left = rest(link_path, PhantomData::<FillTakes<Mine, Parts>>);
    let left = rest(keys_left, PhantomData::<FillReadTakes<Mine>>);
    holds(left, PhantomData::<ConnectionIdsOf<Mine>>);
}

/// The Long Packet Type bits of an Initial packet.
const INITIAL: u8 = 0b00;
/// The Long Packet Type bits of a Handshake packet.
const HANDSHAKE: u8 = 0b10;

/// The keys the client protects its Initial packets with (RFC 9001 §5.2).
fn client_keys() -> DirectionKeys<RingBackend> {
    let secrets = InitialSecrets::derive(&RingBackend, &client_dcid());
    DirectionKeys::derive(&RingBackend, INITIAL_AEAD, &secrets.client)
}

/// The keys the server protects its Initial packets with (RFC 9001 §5.2).
fn server_keys() -> DirectionKeys<RingBackend> {
    let secrets = InitialSecrets::derive(&RingBackend, &client_dcid());
    DirectionKeys::derive(&RingBackend, INITIAL_AEAD, &secrets.server)
}

/// The unprotected first byte of a long header packet of the type
/// `type_bits` with a 4-byte Packet Number field and no reserved bits set.
fn first_byte(type_bits: u8) -> u8 {
    0xc3 | (type_bits << 4)
}

/// A long header packet of the client, of the type `type_bits`, with a
/// 4-byte Packet Number field holding `number`, carrying `payload`,
/// protected with the keys of the client's Initial secret.
fn long_packet(type_bits: u8, number: u64, payload: &[u8]) -> BytesMut {
    long_packet_with(first_byte(type_bits), &[], &client_keys(), number, payload)
}

/// A long header packet of the client, from [`CLIENT_SCID`], as
/// [`long_packet`] makes it.
fn client_long_packet(type_bits: u8, number: u64, payload: &[u8]) -> BytesMut {
    long_packet_from(
        first_byte(type_bits),
        &CLIENT_SCID,
        &[],
        &client_keys(),
        number,
        payload,
    )
}

/// A long header packet whose unprotected first byte is `first`, which
/// gives its type and a 4-byte Packet Number field holding `number`;
/// carrying `token`, if it is an Initial packet, and `payload`; protected
/// with `keys`.
fn long_packet_with(
    first: u8,
    token: &[u8],
    keys: &DirectionKeys<RingBackend>,
    number: u64,
    payload: &[u8],
) -> BytesMut {
    long_packet_from(first, &[], token, keys, number, payload)
}

/// An Initial packet of the client with the Source Connection ID `scid`,
/// numbered `number` and carrying `payload`.
fn initial_from(scid: &[u8], number: u64, payload: &[u8]) -> BytesMut {
    long_packet_from(
        first_byte(INITIAL),
        scid,
        &[],
        &client_keys(),
        number,
        payload,
    )
}

/// As [`long_packet_with`], with the Source Connection ID `scid`.
fn long_packet_from(
    first: u8,
    scid: &[u8],
    token: &[u8],
    keys: &DirectionKeys<RingBackend>,
    number: u64,
    payload: &[u8],
) -> BytesMut {
    let mut packet = vec![first];
    packet.extend_from_slice(&1u32.to_be_bytes());
    packet.push(8);
    packet.extend_from_slice(&CLIENT_DCID);
    packet.push(u8::try_from(scid.len()).unwrap());
    packet.extend_from_slice(scid);
    if (first >> 4) & 0b11 == INITIAL {
        packet.push(u8::try_from(token.len()).unwrap());
        packet.extend_from_slice(token);
    }
    let length = u16::try_from(4 + payload.len() + 16).unwrap();
    packet.extend_from_slice(&(0x4000 | length).to_be_bytes());
    let pn_offset = packet.len();
    packet.extend_from_slice(&u32::try_from(number).unwrap().to_be_bytes());
    packet.extend_from_slice(payload);
    packet.extend_from_slice(&[0; 16]);
    let number = PacketNumber::new(number).unwrap();
    keys.packet
        .seal(number, &mut packet, pn_offset + 4)
        .unwrap();
    keys.header.apply(&mut packet, pn_offset).unwrap();
    BytesMut::from(&packet[..])
}

/// The AEAD of the tests' 1-RTT keys.
const ONE_RTT_AEAD: AeadAlgorithm = AeadAlgorithm::Aes128Gcm;

/// The traffic secret the client sends 1-RTT packets with.
fn client_secret() -> TrafficSecret {
    TrafficSecret::new(HashAlgorithm::Sha256, &[0xc1; 32]).unwrap()
}

/// The traffic secret the server sends 1-RTT packets with.
fn server_secret() -> TrafficSecret {
    TrafficSecret::new(HashAlgorithm::Sha256, &[0x5e; 32]).unwrap()
}

/// The client's 1-RTT keys of `generation`.
fn client_generation(generation: u64) -> KeyGeneration<RingBackend> {
    let mut keys = KeyGeneration::first(&RingBackend, ONE_RTT_AEAD, client_secret());
    for _ in 0..generation {
        keys = keys.next(&RingBackend);
    }
    keys
}

/// A 1-RTT packet of the client to its first Destination Connection ID,
/// with a 4-byte Packet Number field holding `number`, carrying `payload`,
/// protected with the client's keys of `generation` and the Key Phase they
/// give.
fn one_rtt_packet_of(generation: u64, number: u64, payload: &[u8]) -> BytesMut {
    one_rtt_packet_to(CLIENT_DCID, generation, number, payload)
}

/// A 1-RTT packet of the client to `dcid`, as [`one_rtt_packet_of`] makes
/// one.
fn one_rtt_packet_to(dcid: [u8; 8], generation: u64, number: u64, payload: &[u8]) -> BytesMut {
    let keys = client_generation(generation);
    let header = HeaderProtectionKey::derive(&RingBackend, ONE_RTT_AEAD, &client_secret());
    let key_phase = if generation % 2 == 1 { 0x04 } else { 0 };
    let mut packet = vec![0x43 | key_phase];
    packet.extend_from_slice(&dcid);
    let pn_offset = packet.len();
    packet.extend_from_slice(&u32::try_from(number).unwrap().to_be_bytes());
    packet.extend_from_slice(payload);
    packet.extend_from_slice(&[0; 16]);
    keys.packet()
        .seal(
            PacketNumber::new(number).unwrap(),
            &mut packet,
            pn_offset + 4,
        )
        .unwrap();
    header.apply(&mut packet, pn_offset).unwrap();
    BytesMut::from(&packet[..])
}

/// A 1-RTT packet to the client's first Destination Connection ID, which no
/// keys open.
fn one_rtt_packet() -> BytesMut {
    let mut packet = BytesMut::from(&[0x43][..]);
    packet.extend_from_slice(&CLIENT_DCID);
    packet.extend_from_slice(&[0; 24]);
    packet
}

/// The packet `datagram` holds, arrived over `link` at `at`.
fn received(
    datagram: BytesMut,
    link: &LinkId<(), ()>,
    at: Duration,
) -> ReceivedPacket<BytesMut, TestLink> {
    let len = ConnectionIdLength::new(8).unwrap();
    let Some(Ok(Packet::Protected(packet))) = into_packets(datagram, len).next() else {
        panic!("the datagram holds a protected packet")
    };
    ReceivedPacket::new(packet, ArrivalFacts::new(TestLink(link.clone()), at, None))
}

/// What the packet feeder of the next connection does at each instant.
fn feed_packets(steps: impl IntoIterator<Item = (Duration, probe::PacketStep)>) {
    PACKETS.with(|p| p.borrow_mut().extend(steps));
}

/// Poll `connection`, which stays pending, at each millisecond of
/// `millis`, and take the log.
fn run<F: Future + Unpin>(
    connection: &mut F,
    millis: core::ops::RangeInclusive<u64>,
) -> Vec<String> {
    let outer = Outer::new();
    for at in millis {
        advance_to(ms(at));
        assert!(outer.poll(connection).is_pending());
    }
    take_log()
}

/// A CRYPTO frame of "hello" at offset 0 past the first ClientHello, then
/// PADDING: the advancing call reads the ClientHello, which its engine
/// never gets past, and leaves "hello" to whoever reads after it.
fn crypto_hello() -> Vec<u8> {
    crypto_after_hello(0, b"hello")
}

/// The length of the first ClientHello the tests' CRYPTO data starts with.
fn hello_len() -> u8 {
    u8::try_from(client_hello().len()).expect("a short ClientHello")
}

/// A CRYPTO frame of `data` at `offset` past the first ClientHello, then
/// PADDING; at offset 0 the frame starts with the ClientHello itself.
fn crypto_after_hello(offset: u8, data: &[u8]) -> Vec<u8> {
    if offset == 0 {
        crypto_at(0, &[&client_hello()[..], data].concat())
    } else {
        crypto_at(hello_len() + offset, data)
    }
}

/// A PING frame, then PADDING.
fn ping() -> Vec<u8> {
    [&[0x01][..], &[0; 20]].concat()
}

/// PADDING alone.
fn padding() -> Vec<u8> {
    vec![0; 30]
}

#[test]
fn an_initial_packet_is_processed_once() {
    use probe::PacketStep::{Inspect, Receive};
    reset();
    let first = link();
    let packet = long_packet(INITIAL, 0, &crypto_hello());
    let mut changed = long_packet(INITIAL, 1, &crypto_hello());
    let last = changed.len() - 1;
    changed[last] ^= 1;
    feed_packets([
        (ms(5), Receive(received(packet.clone(), &first, ms(5)))),
        (ms(6), Inspect),
        (ms(7), Receive(received(packet, &first, ms(7)))),
        (ms(8), Inspect),
        (ms(9), Receive(received(changed, &first, ms(9)))),
    ]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first);
    take_log();
    assert_eq!(
        run(&mut connection, 5..=9),
        [
            "processed: highest numbered true, non-probing true",
            "read \"hello\", largest Some((0, 5ms)), ranges [(0, 0)], due Some(Now), \
             idle Some(30.005s), reason None",
            "dropped: duplicate 0",
            // a duplicate restarts nothing
            "read \"\", largest Some((0, 5ms)), ranges [(0, 0)], due Some(Now), \
             idle Some(30.005s), reason None",
            "dropped: payload not opened",
        ]
    );
}

#[test]
fn a_packet_needs_a_frame_and_padding_is_one() {
    use probe::PacketStep::{Inspect, Receive};
    reset();
    let first = link();
    feed_packets([
        (
            ms(5),
            Receive(received(long_packet(INITIAL, 0, &padding()), &first, ms(5))),
        ),
        (ms(6), Inspect),
        (
            ms(7),
            Receive(received(long_packet(INITIAL, 1, &[]), &first, ms(7))),
        ),
        (ms(8), Inspect),
    ]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first);
    take_log();
    assert_eq!(
        run(&mut connection, 5..=8),
        [
            // PADDING is a probing frame and elicits no ACK frame
            "processed: highest numbered true, non-probing false",
            "read \"\", largest Some((0, 5ms)), ranges [(0, 0)], due Some(NotDue), \
             idle Some(30.005s), reason None",
            "error: EmptyPacket { level: Initial }",
            // the packet that failed is not recorded
            "read \"\", largest Some((0, 5ms)), ranges [(0, 0)], due Some(NotDue), \
             idle Some(30.005s), reason None",
        ]
    );
}

#[test]
fn a_frame_the_packet_type_cannot_carry_ends_the_connection() {
    use probe::PacketStep::{Inspect, Receive};
    reset();
    let first = link();
    let payload = [&[0x1e][..], &[0; 20]].concat();
    feed_packets([
        (
            ms(5),
            Receive(received(long_packet(INITIAL, 0, &payload), &first, ms(5))),
        ),
        (ms(6), Inspect),
    ]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first);
    take_log();
    assert_eq!(
        run(&mut connection, 5..=6),
        [
            "error: FrameNotPermitted { source: NotAtLevel { level: Initial } }",
            "read \"\", largest None, ranges [], due Some(NotDue), idle None, reason None",
        ]
    );
}

#[test]
fn frames_before_one_not_permitted_are_handled_but_the_packet_is_not_recorded() {
    use probe::PacketStep::{Inspect, Receive};
    reset();
    let first = link();
    // CRYPTO, then HANDSHAKE_DONE
    let crypto = crypto_after_hello(0, b"hello");
    let payload = [&crypto[..crypto.len() - 20], &[0x1e], &[0; 20]].concat();
    feed_packets([
        (
            ms(5),
            Receive(received(long_packet(INITIAL, 0, &payload), &first, ms(5))),
        ),
        (ms(6), Inspect),
    ]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first);
    take_log();
    assert_eq!(
        run(&mut connection, 5..=6),
        [
            "error: FrameNotPermitted { source: NotAtLevel { level: Initial } }",
            "read \"hello\", largest None, ranges [], due Some(NotDue), idle None, reason None",
        ]
    );
}

#[test]
fn reserved_bits_set_end_the_connection() {
    use probe::PacketStep::{Inspect, Receive};
    reset();
    let first = link();
    let packet = long_packet_with(first_byte(INITIAL) | 0x0c, &[], &client_keys(), 0, &ping());
    feed_packets([
        (ms(5), Receive(received(packet, &first, ms(5)))),
        (ms(6), Inspect),
    ]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first);
    take_log();
    assert_eq!(
        run(&mut connection, 5..=6),
        [
            "error: ReservedBitsSet { level: Initial }",
            "read \"\", largest None, ranges [], due Some(NotDue), idle None, reason None",
        ]
    );
}

#[test]
fn packets_wait_for_their_keys_and_a_handshake_packet_discards_initial_keys() {
    use probe::PacketStep::{InstallHandshakeKeys, Receive};
    reset();
    let first = link();
    let handshake = long_packet(HANDSHAKE, 0, &ping());
    feed_packets([
        (ms(5), Receive(received(handshake.clone(), &first, ms(5)))),
        (ms(6), Receive(received(one_rtt_packet(), &first, ms(6)))),
        (ms(7), InstallHandshakeKeys),
        (ms(8), Receive(received(handshake, &first, ms(8)))),
        (
            ms(9),
            Receive(received(long_packet(INITIAL, 0, &padding()), &first, ms(9))),
        ),
    ]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first);
    take_log();
    assert_eq!(
        run(&mut connection, 5..=9),
        [
            "held at Handshake",
            "held at OneRtt",
            "processed: highest numbered true, non-probing true",
            // a server discards them once it processed a Handshake packet
            "initial keys live: false",
            "dropped: no Initial keys",
        ]
    );
}

#[test]
fn a_one_rtt_packet_waits_while_only_the_send_keys_are_installed() {
    use probe::PacketStep::{InstallOneRttSendKeys, Receive};
    reset();
    let first = link();
    feed_packets([
        (ms(5), InstallOneRttSendKeys),
        (ms(6), Receive(received(one_rtt_packet(), &first, ms(6)))),
    ]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first);
    take_log();
    assert_eq!(run(&mut connection, 5..=6), ["held at OneRtt"]);
}

#[test]
fn a_one_rtt_packet_of_the_current_generation_is_processed() {
    use probe::PacketStep::{InspectOneRtt, InstallOneRttKeys, Receive};
    reset();
    let first = link();
    feed_packets([
        (ms(5), InstallOneRttKeys),
        (ms(6), InspectOneRtt),
        (
            ms(7),
            Receive(received(one_rtt_packet_of(0, 3, &ping()), &first, ms(7))),
        ),
        (
            ms(8),
            Receive(received(one_rtt_packet_of(0, 2, &ping()), &first, ms(8))),
        ),
        (ms(9), InspectOneRtt),
    ]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first);
    take_log();
    assert_eq!(
        run(&mut connection, 5..=9),
        [
            "receive Some(0), next Some(1), previous Some(false) until None, send Some(0), \
             failed 0, lowest None",
            "processed: highest numbered true, non-probing true",
            "processed: highest numbered false, non-probing true",
            "receive Some(0), next Some(1), previous Some(false) until None, send Some(0), \
             failed 0, lowest Some(2)",
        ]
    );
}

#[test]
fn a_competing_one_rtt_datagram_is_taken_when_it_opens_and_left_otherwise() {
    use probe::PacketStep::{InspectOneRtt, InstallOneRttKeys};
    reset();
    RIVAL.with(|r| r.set(true));
    let first = link();
    feed_packets([
        (ms(5), InstallOneRttKeys),
        (ms(7), InspectOneRtt),
        (ms(9), InspectOneRtt),
    ]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first.clone());
    take_log();
    deliver(one_rtt_packet_of(0, 3, &ping()), &first, ms(6));
    let log = run(&mut connection, 5..=7);
    // it opened with the current generation: taken, and processed
    assert_eq!(
        log,
        [
            "receive Some(0), next Some(1), previous Some(false) until None, send Some(0), \
          failed 0, lowest Some(3)"
        ]
    );
    // no keys open it: left to the rival, and nothing is counted
    deliver(one_rtt_packet(), &first, ms(8));
    assert_eq!(
        run(&mut connection, 8..=9),
        [
            "receive Some(0), next Some(1), previous Some(false) until None, send Some(0), \
          failed 0, lowest Some(3)"
        ]
    );
}

#[test]
fn a_competing_one_rtt_datagram_waits_for_the_one_rtt_keys() {
    use probe::PacketStep::{InspectHeld, InspectOneRtt, InstallOneRttKeys};
    reset();
    RIVAL.with(|r| r.set(true));
    let first = link();
    feed_packets([
        (ms(6), InspectHeld),
        (ms(7), InstallOneRttKeys),
        (ms(8), InspectOneRtt),
    ]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first.clone());
    take_log();
    deliver(one_rtt_packet_of(0, 3, &ping()), &first, ms(5));
    assert_eq!(
        run(&mut connection, 5..=8),
        [
            "held 1, largest Handshake None",
            // judged again once the keys came, and taken
            "receive Some(0), next Some(1), previous Some(false) until None, send Some(0), \
             failed 0, lowest Some(3)",
        ]
    );
}

/// The 1-RTT keys of `generation` that `sender` protects packets with,
/// which a key update `trigger` initiated made, as the events record them.
fn one_rtt_updated(
    sender: sakuya_wire_v1::role::Role,
    generation: u64,
    trigger: sakuya_connection::v1::events::EventInitiator,
) -> common::events::Recorded {
    common::events::Recorded::KeyUpdated(sakuya_connection::v1::events::KeyChange {
        level: sakuya_wire_v1::encryption_level::EncryptionLevel::OneRtt,
        sender,
        key_phase: Some(generation),
        trigger: Some(trigger),
    })
}

/// The 1-RTT key updates the events of this side, the server, recorded.
fn one_rtt_updates() -> Vec<common::events::Recorded> {
    common::events::recorded(sakuya_wire_v1::role::Role::Server)
        .into_iter()
        .filter(|event| {
            matches!(
                event,
                common::events::Recorded::KeyUpdated(key) if key.key_phase.is_some()
            )
        })
        .collect()
}

#[test]
fn a_flipped_key_phase_promotes_the_next_generation_and_the_send_keys_follow() {
    use probe::PacketStep::{InspectOneRtt, InstallOneRttKeys, Receive};
    reset();
    let first = link();
    feed_packets([
        (ms(5), InstallOneRttKeys),
        (
            ms(6),
            Receive(received(one_rtt_packet_of(0, 0, &ping()), &first, ms(6))),
        ),
        (
            ms(7),
            Receive(received(one_rtt_packet_of(1, 2, &ping()), &first, ms(7))),
        ),
        (ms(8), InspectOneRtt),
        // delayed, numbered below the first of generation 1
        (
            ms(9),
            Receive(received(one_rtt_packet_of(0, 1, &ping()), &first, ms(9))),
        ),
        (ms(10), InspectOneRtt),
        // old keys after newer ones
        (
            ms(11),
            Receive(received(one_rtt_packet_of(0, 3, &ping()), &first, ms(11))),
        ),
        (ms(12), InspectOneRtt),
    ]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first);
    take_log();
    assert_eq!(
        run(&mut connection, 5..=12),
        [
            "processed: highest numbered true, non-probing true",
            "processed: highest numbered true, non-probing true",
            // three probe timeouts of 1.024 s from the promotion
            "receive Some(1), next Some(2), previous Some(true) until Some(3.079s), \
             send Some(1), failed 0, lowest Some(2)",
            "processed: highest numbered false, non-probing true",
            "receive Some(1), next Some(2), previous Some(true) until Some(3.079s), \
             send Some(1), failed 0, lowest Some(2)",
            // tried with the next generation only, which does not open it
            "dropped: payload not opened",
            "receive Some(1), next Some(2), previous Some(true) until Some(3.079s), \
             send Some(1), failed 1, lowest Some(2)",
        ]
    );
    // the peer initiated it: both halves of generation 1, once
    use sakuya_connection::v1::events::EventInitiator::Remote;
    use sakuya_wire_v1::role::Role::{Client, Server};
    assert_eq!(
        one_rtt_updates(),
        [
            one_rtt_updated(Client, 1, Remote),
            one_rtt_updated(Server, 1, Remote)
        ]
    );
}

#[test]
fn the_previous_generation_goes_three_probe_timeouts_after_the_promotion() {
    use probe::PacketStep::{InspectOneRtt, InstallOneRttKeys, Receive};
    reset();
    let first = link();
    feed_packets([
        (ms(5), InstallOneRttKeys),
        (
            ms(6),
            Receive(received(one_rtt_packet_of(1, 5, &ping()), &first, ms(6))),
        ),
        (ms(7), InspectOneRtt),
        (ms(3077), InspectOneRtt),
        (ms(3079), InspectOneRtt),
        (
            ms(3080),
            Receive(received(one_rtt_packet_of(0, 1, &ping()), &first, ms(3080))),
        ),
        (ms(3081), InspectOneRtt),
    ]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first);
    take_log();
    assert_eq!(
        run(&mut connection, 5..=3081),
        [
            "processed: highest numbered true, non-probing true",
            // three probe timeouts of 1.024 s from the promotion
            "receive Some(1), next Some(2), previous Some(true) until Some(3.078s), \
             send Some(1), failed 0, lowest Some(5)",
            "receive Some(1), next Some(2), previous Some(true) until Some(3.078s), \
             send Some(1), failed 0, lowest Some(5)",
            "receive Some(1), next Some(2), previous Some(false) until None, send Some(1), \
             failed 0, lowest Some(5)",
            // tried with the next generation, which has its Key Phase
            "dropped: payload not opened",
            "receive Some(1), next Some(2), previous Some(false) until None, send Some(1), \
             failed 1, lowest Some(5)",
        ]
    );
    // the peer's generation 0 goes, once; who initiated the update that
    // made it the previous one is not kept
    let discarded: Vec<_> = common::events::recorded(sakuya_wire_v1::role::Role::Server)
        .into_iter()
        .filter(|event| {
            matches!(
                event,
                common::events::Recorded::KeyDiscarded(key) if key.key_phase.is_some()
            )
        })
        .collect();
    assert_eq!(
        discarded,
        [common::events::Recorded::KeyDiscarded(
            sakuya_connection::v1::events::KeyChange {
                level: sakuya_wire_v1::encryption_level::EncryptionLevel::OneRtt,
                sender: sakuya_wire_v1::role::Role::Client,
                key_phase: Some(0),
                trigger: None,
            }
        )]
    );
}

#[test]
fn a_second_update_of_the_peer_before_its_first_was_acknowledged_closes_the_connection() {
    use probe::PacketStep::{InstallOneRttKeys, Receive};
    reset();
    let first = link();
    feed_packets([
        (ms(5), InstallOneRttKeys),
        // the peer updates to generation 1, then at once to generation 2
        (
            ms(6),
            Receive(received(one_rtt_packet_of(1, 0, &ping()), &first, ms(6))),
        ),
        (
            ms(7),
            Receive(received(one_rtt_packet_of(2, 1, &ping()), &first, ms(7))),
        ),
    ]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first);
    take_log();
    assert_eq!(
        run(&mut connection, 5..=7),
        [
            "processed: highest numbered true, non-probing true",
            "error: KeyUpdate { source: ConsecutiveUpdates { trigger: PacketNumber(VarInt(0)), \
             number: PacketNumber(VarInt(1)) } }",
        ]
    );
}

#[test]
fn the_peer_updates_again_once_its_update_was_acknowledged() {
    use probe::PacketStep::{InspectOneRtt, InstallOneRttKeys, NoteAckFrameSent, Receive};
    reset();
    let first = link();
    feed_packets([
        (ms(5), InstallOneRttKeys),
        (
            ms(6),
            Receive(received(one_rtt_packet_of(1, 0, &ping()), &first, ms(6))),
        ),
        // an ACK frame up to packet 0 went out with generation 1
        (ms(7), NoteAckFrameSent(0)),
        (
            ms(8),
            Receive(received(one_rtt_packet_of(2, 1, &ping()), &first, ms(8))),
        ),
        (ms(9), InspectOneRtt),
    ]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first);
    take_log();
    assert_eq!(
        run(&mut connection, 5..=9),
        [
            "processed: highest numbered true, non-probing true",
            "processed: highest numbered true, non-probing true",
            // the previous generation, 1, goes three probe timeouts after
            // the second promotion
            "receive Some(2), next Some(3), previous Some(true) until Some(3.08s), \
             send Some(2), failed 0, lowest Some(1)",
        ]
    );
}

#[test]
fn an_ack_of_a_packet_of_the_sending_generation_confirms_it() {
    use probe::PacketStep::{InspectKeyUpdate, InstallOneRttKeys, Receive};
    reset();
    let first = link();
    let sent = |count| probe::Step::Sent {
        space: PacketNumberSpaceKind::ApplicationData,
        count,
    };
    // packet 0 goes before the 1-RTT keys come; once they are there, the
    // sending call notes the next number, 1, as the lowest one sent with
    // generation 0, and packets 1 and 2 follow
    feed([(ms(4), sent(1)), (ms(10), sent(2))]);
    feed_packets([
        (ms(5), InstallOneRttKeys),
        (ms(12), InspectKeyUpdate),
        (
            ms(50),
            Receive(received(
                one_rtt_packet_of(0, 0, &ack_of(&[(0, 0)], false)),
                &first,
                ms(50),
            )),
        ),
        (ms(51), InspectKeyUpdate),
        (
            ms(60),
            Receive(received(
                one_rtt_packet_of(0, 1, &ack_of(&[(0, 1)], false)),
                &first,
                ms(60),
            )),
        ),
        (
            ms(70),
            Receive(received(
                one_rtt_packet_of(0, 2, &ack_of(&[(0, 2)], false)),
                &first,
                ms(70),
            )),
        ),
        (ms(71), InspectKeyUpdate),
    ]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first);
    take_log();
    let log = run(&mut connection, 4..=71);
    assert_eq!(
        lines_of(log, &["send", "processed", "error"]),
        [
            "send Some(0), confirmed at None, lowest sent Some(1)",
            "processed: highest numbered true, non-probing true",
            // packet 0 is below the lowest one noted for the generation
            "send Some(0), confirmed at None, lowest sent Some(1)",
            "processed: highest numbered true, non-probing true",
            "processed: highest numbered true, non-probing true",
            // the first acknowledgment of the generation keeps its instant
            "send Some(0), confirmed at Some(60ms), lowest sent Some(1)",
        ]
    );
}

#[test]
fn an_ack_under_older_keys_of_a_packet_with_newer_ones_closes_the_connection() {
    use probe::PacketStep::{InstallOneRttKeys, NoteSent, Receive};
    reset();
    let first = link();
    feed([(
        ms(10),
        probe::Step::Sent {
            space: PacketNumberSpaceKind::ApplicationData,
            count: 3,
        },
    )]);
    feed_packets([
        (ms(5), InstallOneRttKeys),
        // as if packet 0 had been sealed with generation 0, and packets 1
        // and 2 with generation 1
        (ms(11), NoteSent(0, 0)),
        (ms(12), NoteSent(1, 1)),
        (
            ms(50),
            Receive(received(
                one_rtt_packet_of(0, 0, &ack_of(&[(0, 0)], false)),
                &first,
                ms(50),
            )),
        ),
        (
            ms(60),
            Receive(received(
                one_rtt_packet_of(0, 1, &ack_of(&[(0, 1)], false)),
                &first,
                ms(60),
            )),
        ),
    ]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first);
    take_log();
    let log = run(&mut connection, 5..=60);
    assert_eq!(
        lines_of(log, &["processed", "error"]),
        [
            "processed: highest numbered true, non-probing true",
            "error: KeyUpdate { source: AckWithOldKeys { largest: PacketNumber(VarInt(1)), \
             lowest_newer: PacketNumber(VarInt(1)) } }",
        ]
    );
}

/// Once the server rejected 0-RTT, an ACK frame that acknowledges a
/// packet number of a 0-RTT packet it rejected closes the connection with
/// PROTOCOL_VIOLATION (RFC 9001 §4.6.2); one of a later packet does not.
#[test]
fn an_ack_of_a_rejected_0rtt_packet_closes_the_connection() {
    use probe::PacketStep::{InstallOneRttKeys, NoteSent, Receive, RejectZeroRtt};
    reset();
    let first = link();
    feed([(
        ms(10),
        probe::Step::Sent {
            space: PacketNumberSpaceKind::ApplicationData,
            count: 3,
        },
    )]);
    feed_packets([
        (ms(5), InstallOneRttKeys),
        // as if packets 0 and 1 had been 0-RTT packets the server rejected,
        // and packet 2 a 1-RTT packet
        (ms(11), RejectZeroRtt(2)),
        (ms(12), NoteSent(0, 2)),
        (
            ms(50),
            Receive(received(
                one_rtt_packet_of(0, 0, &ack_of(&[(2, 2)], false)),
                &first,
                ms(50),
            )),
        ),
        (
            ms(60),
            Receive(received(
                one_rtt_packet_of(0, 1, &ack_of(&[(1, 2)], true)),
                &first,
                ms(60),
            )),
        ),
    ]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first);
    take_log();
    let log = run(&mut connection, 5..=60);
    assert_eq!(
        lines_of(log, &["processed", "error"]),
        [
            "processed: highest numbered true, non-probing true",
            "error: RejectedZeroRttPacketAcknowledged { acknowledged: PacketNumber(VarInt(1)), \
             ecn_counts: true }",
        ]
    );
}

#[test]
fn initial_and_handshake_packets_that_fail_authentication_count() {
    use probe::PacketStep::{InspectOneRtt, InstallHandshakeKeys, Receive};
    reset();
    let first = link();
    let changed = |type_bits| {
        let mut packet = long_packet(type_bits, 0, &ping());
        let last = packet.len() - 1;
        packet[last] ^= 1;
        packet
    };
    feed_packets([
        (ms(5), InstallHandshakeKeys),
        (ms(6), InspectOneRtt),
        (ms(7), Receive(received(changed(INITIAL), &first, ms(7)))),
        (ms(8), InspectOneRtt),
        (ms(9), Receive(received(changed(HANDSHAKE), &first, ms(9)))),
        (ms(10), InspectOneRtt),
    ]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first);
    take_log();
    assert_eq!(
        run(&mut connection, 5..=10),
        [
            "receive None, next None, previous None until None, send None, failed 0, \
             lowest None",
            "dropped: payload not opened",
            "receive None, next None, previous None until None, send None, failed 1, \
             lowest None",
            "dropped: payload not opened",
            "receive None, next None, previous None until None, send None, failed 2, \
             lowest None",
        ]
    );
}

#[test]
fn a_handshake_packet_that_fails_keeps_the_initial_keys() {
    use probe::PacketStep::{InstallHandshakeKeys, Receive};
    reset();
    let first = link();
    let handshake_done = [&[0x1e][..], &[0; 20]].concat();
    feed_packets([
        (ms(5), InstallHandshakeKeys),
        (
            ms(6),
            Receive(received(
                long_packet(HANDSHAKE, 0, &handshake_done),
                &first,
                ms(6),
            )),
        ),
        (
            ms(7),
            Receive(received(long_packet(INITIAL, 0, &ping()), &first, ms(7))),
        ),
    ]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first);
    take_log();
    assert_eq!(
        run(&mut connection, 5..=7),
        [
            "error: FrameNotPermitted { source: NotAtLevel { level: Handshake } }",
            "processed: highest numbered true, non-probing true",
        ]
    );
}

#[test]
fn a_client_drops_an_initial_packet_with_a_token() {
    use probe::PacketStep::Receive;
    reset();
    let first = link();
    let initial =
        |token: &[u8]| long_packet_with(first_byte(INITIAL), token, &server_keys(), 0, &ping());
    feed_packets([
        (ms(5), Receive(received(initial(b"token"), &first, ms(5)))),
        (ms(6), Receive(received(initial(&[]), &first, ms(6)))),
    ]);
    let mut connection = connection!(ClientMine, AddressValidation::Validated, first);
    take_log();
    assert_eq!(
        run(&mut connection, 5..=6),
        [
            "dropped: token from the server",
            "processed: highest numbered true, non-probing true",
        ]
    );
}

#[test]
fn a_server_drops_a_long_header_from_another_attempts_source_connection_id() {
    use probe::PacketStep::Receive;
    reset();
    let first = link();
    feed_packets([
        (
            ms(5),
            Receive(received(
                initial_from(&[0xaa; 8], 0, &ping()),
                &first,
                ms(5),
            )),
        ),
        (
            ms(6),
            Receive(received(
                initial_from(&[0xbb; 8], 1, &ping()),
                &first,
                ms(6),
            )),
        ),
    ]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first);
    take_log();
    assert_eq!(
        run(&mut connection, 5..=6),
        [
            "processed: highest numbered true, non-probing true",
            "dropped: another source connection ID",
        ]
    );
}

#[test]
fn past_the_limit_of_ack_ranges_the_oldest_goes_and_what_lies_below_it_is_a_duplicate() {
    use probe::PacketStep::{Inspect, Receive};
    reset();
    MAX_ACK_RANGES.with(|m| m.set(MaxAckRanges::new(core::num::NonZeroUsize::MIN)));
    let first = link();
    let packet = |number, at| received(long_packet(INITIAL, number, &ping()), &first, ms(at));
    feed_packets([
        (ms(5), Receive(packet(1, 5))),
        (ms(6), Receive(packet(3, 6))),
        (ms(7), Inspect),
        (ms(8), Receive(packet(0, 8))),
        (ms(9), Receive(packet(2, 9))),
        (ms(10), Inspect),
    ]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first.clone());
    take_log();
    assert_eq!(
        run(&mut connection, 5..=10),
        [
            "processed: highest numbered true, non-probing true",
            "processed: highest numbered true, non-probing true",
            // the range of 1 went, and the floor rose above it
            "read \"\", largest Some((3, 6ms)), ranges [(3, 3)], due Some(Now), \
             idle Some(30.006s), reason None",
            // never processed, but below the floor
            "dropped: duplicate 0",
            "processed: highest numbered false, non-probing true",
            "read \"\", largest Some((3, 6ms)), ranges [(2, 3)], due Some(Now), \
             idle Some(30.009s), reason None",
        ]
    );
}

#[test]
fn a_connection_close_from_the_peer_drains_the_link_paths() {
    use probe::PacketStep::{Inspect, Receive};
    reset();
    let first = link();
    let close = [&[0x1c, 0x00, 0x00, 0x00][..], &[0; 20]].concat();
    feed_packets([
        (
            ms(5),
            Receive(received(long_packet(INITIAL, 0, &close), &first, ms(5))),
        ),
        (ms(6), Inspect),
        (
            ms(7),
            Receive(received(long_packet(INITIAL, 1, &padding()), &first, ms(7))),
        ),
    ]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first);
    take_log();
    let log = run(&mut connection, 5..=7);
    assert_eq!(log[0], "processed: highest numbered true, non-probing true");
    assert!(
        log.iter().any(|line| line.starts_with("Draining(")),
        "the link path drains: {log:?}"
    );
    let inspect = log
        .iter()
        .find(|line| line.starts_with("read"))
        .expect("inspected");
    // the keys go once the link path drains, and the Initial space with
    // them
    assert!(
        inspect.contains("largest None") && inspect.contains("reason Some(\"Peer("),
        "{inspect}"
    );
    assert_eq!(log.last().map(String::as_str), Some("dropped: draining"));
}

#[test]
fn a_closing_link_path_reads_only_for_a_close() {
    use probe::PacketStep::{Inspect, InstallOneRttSendKeys, Receive};
    reset();
    CLOSE_AT.with(|c| c.set(Some(ms(4))));
    let first = link();
    let close = [&[0x01, 0x1c, 0x00, 0x00, 0x00][..], &[0; 20]].concat();
    feed_packets([
        (
            ms(5),
            Receive(received(long_packet(INITIAL, 0, &ping()), &first, ms(5))),
        ),
        (ms(6), Inspect),
        (
            ms(7),
            Receive(received(long_packet(HANDSHAKE, 0, &ping()), &first, ms(7))),
        ),
        (ms(8), Receive(received(one_rtt_packet(), &first, ms(8)))),
        (ms(9), InstallOneRttSendKeys),
        (ms(10), Receive(received(one_rtt_packet(), &first, ms(10)))),
        (
            ms(11),
            Receive(received(long_packet(INITIAL, 1, &close), &first, ms(11))),
        ),
    ]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first);
    run(&mut connection, 4..=4);
    let log = run(&mut connection, 5..=11);
    assert_eq!(
        log[..6],
        [
            "read while closing",
            // nothing is recorded while closing
            "read \"\", largest None, ranges [], due Some(NotDue), idle None, reason None",
            // no keys come to a closing link path
            "dropped: no Handshake keys",
            "dropped: no OneRtt keys",
            "dropped: no OneRtt keys",
            "read while closing",
        ]
    );
    assert!(
        log.iter().any(|line| line.starts_with("Draining(34ms)")),
        "a closing link path keeps its end as it drains: {log:?}"
    );
}

/// A CRYPTO frame of `data` at `offset`, then PADDING.
fn crypto_at(offset: u8, data: &[u8]) -> Vec<u8> {
    let len = u8::try_from(data.len()).expect("a short segment");
    [&[0x06, offset, len][..], data, &[0; 20]].concat()
}

/// One datagram of `packets`, coalesced.
fn coalesced(packets: impl IntoIterator<Item = BytesMut>) -> BytesMut {
    let mut datagram = BytesMut::new();
    for packet in packets {
        datagram.extend_from_slice(&packet);
    }
    datagram
}

/// One datagram of `before`, then the packet `last` builds from `payload`
/// filled with PADDING so that the datagram is as long as a datagram that
/// carries a client's Initial packet must be.
fn padded(before: &[BytesMut], last: impl Fn(&[u8]) -> BytesMut, payload: &[u8]) -> BytesMut {
    let build = |payload: &[u8]| coalesced(before.iter().cloned().chain([last(payload)]));
    let short = MIN_DATAGRAM_SIZE.saturating_sub(build(payload).len());
    let mut payload = payload.to_vec();
    payload.resize(payload.len() + short, 0);
    build(&payload)
}

#[test]
fn the_receiving_call_receives_each_packet_of_a_datagram_and_counts_the_whole_datagram() {
    use probe::PacketStep::{Inspect, InspectCredit};
    reset();
    // the strategy plans nothing: nothing is sent
    common::strategy::plan_nothing();
    let first = link();
    feed_packets([(ms(6), Inspect), (ms(7), InspectCredit(first.clone()))]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first.clone());
    take_log();
    // the last packet is protected with the server's keys, which the server
    // does not open with
    let datagram = padded(
        &[
            long_packet(INITIAL, 0, &crypto_after_hello(0, b"hel")),
            long_packet(INITIAL, 1, &crypto_after_hello(3, b"lo")),
        ],
        |payload| long_packet_with(first_byte(INITIAL), &[], &server_keys(), 2, payload),
        &ping(),
    );
    let size = datagram.len();
    deliver(datagram, &first, ms(5));
    assert_eq!(
        run(&mut connection, 5..=7),
        [
            "read \"hello\", largest Some((1, 5ms)), ranges [(0, 1)], due Some(Now), \
             idle Some(30.005s), reason None"
                .to_owned(),
            // the factor of the tests is 2
            format!("credit Some(Some({}))", 2 * size),
        ]
    );
}

#[test]
fn the_first_datagrams_are_received_and_counted_as_later_ones_are() {
    use probe::PacketStep::{Inspect, InspectCredit};
    reset();
    // the strategy plans nothing: nothing is sent
    common::strategy::plan_nothing();
    let first = link();
    feed_packets([(ms(6), Inspect), (ms(7), InspectCredit(first.clone()))]);
    let datagram = padded(
        &[],
        |payload| long_packet(INITIAL, 0, payload),
        &crypto_after_hello(0, b"hel"),
    );
    let size = datagram.len();
    FIRST_DATAGRAMS.with(|f| {
        f.borrow_mut().push(ReceivedDatagram::new(
            datagram,
            ArrivalFacts::new(TestLink(first.clone()), ms(0), None),
        ));
    });
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first.clone());
    take_log();
    // delivered before the first poll, received after the first datagram
    let later = padded(
        &[],
        |payload| long_packet(INITIAL, 1, payload),
        &crypto_after_hello(3, b"lo"),
    );
    let later_size = later.len();
    deliver(later, &first, ms(5));
    assert_eq!(
        run(&mut connection, 5..=7),
        [
            "read \"hello\", largest Some((1, 5ms)), ranges [(0, 1)], due Some(Now), \
             idle Some(30.005s), reason None"
                .to_owned(),
            // the first datagram is counted as it is received
            format!("credit Some(Some({}))", 2 * (size + later_size)),
        ]
    );
}

#[test]
fn a_server_made_with_a_read_first_flight_starts_with_what_was_read() {
    use probe::PacketStep::{Inspect, InspectCredit};
    reset();
    // the strategy plans nothing: nothing is sent
    common::strategy::plan_nothing();
    FIRST_READ.with(|f| f.set(true));
    let first = link();
    feed_packets([(ms(6), Inspect), (ms(7), InspectCredit(first.clone()))]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first.clone());
    // the Initial keys read with are live; nothing was received
    assert_eq!(
        take_log(),
        [
            "initial keys live: true",
            "recovery built, initial RTT None",
            "Active, NotValidated, credit Some(0)",
        ]
    );
    // the keys and the CRYPTO receiver read with take what comes next
    let datagram = padded(
        &[],
        |payload| long_packet(INITIAL, 0, payload),
        &crypto_after_hello(0, b"hello"),
    );
    let size = datagram.len();
    deliver(datagram, &first, ms(5));
    assert_eq!(
        run(&mut connection, 5..=7),
        [
            "read \"hello\", largest Some((0, 5ms)), ranges [(0, 0)], due Some(Now), \
             idle Some(30.005s), reason None"
                .to_owned(),
            format!("credit Some(Some({}))", 2 * size),
        ]
    );
}

/// The Long Packet Type bits of a 0-RTT packet.
const ZERO_RTT: u8 = 0b01;

/// A ClientHello with an empty legacy_session_id, offering TLS_AES_128_GCM_SHA256
/// and carrying two unknown extensions.
fn client_hello() -> Vec<u8> {
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0x5a; 32]);
    body.push(0);
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
    body.extend_from_slice(&[0x00, 0x08, 0xfa, 0xfa, 0x00, 0x00, 0x1a, 0x1a, 0x00, 0x00]);
    let len = u8::try_from(body.len()).unwrap();
    [&[0x01, 0x00, 0x00, len][..], &body].concat()
}

/// Read the datagrams delivered to `receiver` as a server's first flight,
/// into a new state.
fn read_first(receiver: &mut TestReceiver) -> (FirstFlightReadState<Mine>, Result<(), String>) {
    let mut state = FirstFlightReadState::<Mine>::new(
        &RingBackend,
        &client_dcid(),
        &<v1::Server<common::PendingServerEngine, common::TestNewTokenIssuer> as SideCapacities>::crypto_receive(),
        MaxAckRanges::DEFAULT,
        MAX_HELD.with(Cell::get),
    );
    let result = {
        let reading = core::pin::pin!(read_first_flight::<Mine, Parts, _, _, _, _, _>(
            &mut state,
            [],
            receiver,
            MessageLimits::default(),
        ));
        match reading.poll(&mut core::task::Context::from_waker(
            core::task::Waker::noop(),
        )) {
            core::task::Poll::Ready(result) => result.map_err(|error| match error {
                ReadFirstFlightError::Connection { source } => format!("connection: {source}"),
                ReadFirstFlightError::PeerClosed { close } => format!("closed: {close:?}"),
                other => other.to_string(),
            }),
            core::task::Poll::Pending => Err("pending".to_owned()),
        }
    };
    (state, result)
}

#[test]
fn reading_the_first_flight_ends_with_the_first_client_hello() {
    use probe::PacketStep::{Inspect, InspectCredit};
    reset();
    // the strategy plans nothing: nothing is sent
    common::strategy::plan_nothing();
    let first = link();
    let mut receiver = test_receiver();
    let hello = client_hello();
    let one = padded(
        &[],
        |payload| long_packet(INITIAL, 0, payload),
        &crypto_at(0, &hello[..20]),
    );
    let two = coalesced([
        padded(
            &[],
            |payload| long_packet(INITIAL, 1, payload),
            &crypto_at(20, &hello[20..]),
        ),
        long_packet(ZERO_RTT, 0, &ping()),
    ]);
    let size = one.len() + two.len();
    deliver(one, &first, ms(1));
    // before the rest of the ClientHello the reading waits
    let (state, result) = read_first(&mut receiver);
    assert_eq!(result, Err("pending".to_owned()));
    assert!(state.first_client_hello().is_none());
    reset();
    common::strategy::plan_nothing();
    let mut receiver = test_receiver();
    deliver(
        padded(
            &[],
            |payload| long_packet(INITIAL, 0, payload),
            &crypto_at(0, &hello[..20]),
        ),
        &first,
        ms(1),
    );
    deliver(two, &first, ms(2));
    let (state, result) = read_first(&mut receiver);
    assert_eq!(result, Ok(()));
    assert_eq!(
        state
            .first_client_hello()
            .map(|first| first.encoded().encoded().to_vec()),
        Some(hello)
    );
    // the 0-RTT packet is held for the handshake to decide on
    assert!(format!("{state:?}").contains("held: 1"), "{state:?}");
    // the connection made from it starts with what was read
    READ_STATE.with(|r| *r.borrow_mut() = Some(Box::new(state)));
    FIRST_READ.with(|f| f.set(true));
    feed_packets([(ms(6), Inspect), (ms(7), InspectCredit(first.clone()))]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first.clone());
    assert_eq!(
        take_log(),
        [
            "initial keys live: true".to_owned(),
            "recovery built, initial RTT None".to_owned(),
            format!("Active, NotValidated, credit Some({})", 2 * size),
        ]
    );
    assert_eq!(
        run(&mut connection, 5..=7),
        [
            // the engine read the ClientHello; the Initial space is owed an
            // ACK frame at once
            "read \"\", largest Some((1, 2ms)), ranges [(0, 1)], due Some(Now), \
             idle None, reason None"
                .to_owned(),
            format!("credit Some(Some({}))", 2 * size),
        ]
    );
}

#[test]
fn reading_the_first_flight_starts_with_the_datagrams_taken_and_keeps_a_layout() {
    reset();
    common::strategy::plan_nothing();
    let first = link();
    let mut receiver = test_receiver();
    let hello = client_hello();
    let one = padded(
        &[],
        |payload| long_packet(INITIAL, 0, payload),
        &crypto_at(0, &hello[..20]),
    );
    let initial_two = padded(
        &[],
        |payload| long_packet(INITIAL, 1, payload),
        &[&crypto_at(20, &hello[20..])[..], &ping()].concat(),
    );
    let two = coalesced([initial_two.clone(), long_packet(ZERO_RTT, 0, &ping())]);
    let (one_len, two_len) = (one.len(), two.len());
    // the first datagram was taken from the receiver already; the second
    // comes through it
    let taken = ReceivedDatagram::new(one, ArrivalFacts::new(TestLink(first.clone()), ms(1), None));
    deliver(two, &first, ms(2));
    let mut state = FirstFlightReadState::<Mine>::new(
        &RingBackend,
        &client_dcid(),
        &<v1::Server<common::PendingServerEngine, common::TestNewTokenIssuer> as SideCapacities>::crypto_receive(),
        MaxAckRanges::DEFAULT,
        MAX_HELD.with(Cell::get),
    );
    state.keep_layout();
    let read = {
        let reading = core::pin::pin!(read_first_flight::<Mine, Parts, _, _, _, _, _>(
            &mut state,
            [taken],
            &mut receiver,
            MessageLimits::default(),
        ));
        reading.poll(&mut core::task::Context::from_waker(
            core::task::Waker::noop(),
        ))
    };
    assert!(matches!(read, core::task::Poll::Ready(Ok(()))));
    assert_eq!(state.received_bytes(), one_len + two_len);
    let layout = state.layout().expect("a layout was kept").clone();
    assert_eq!(layout.token().map(|token| token.len()), Some(0));
    let datagrams = layout.datagrams();
    assert_eq!(
        datagrams
            .iter()
            .map(|datagram| datagram.size())
            .collect::<Vec<_>>(),
        [one_len, two_len]
    );
    let [PacketLayout::Initial(first_initial)] = datagrams[0].packets() else {
        panic!("the first datagram holds one Initial packet: {datagrams:?}");
    };
    assert_eq!(first_initial.packet_number().get(), 0);
    assert_eq!(first_initial.length(), one_len);
    assert_eq!(first_initial.crypto().len(), 1);
    assert_eq!(first_initial.crypto()[0], 0..20);
    assert!(!first_initial.ping());
    let [
        PacketLayout::Initial(second_initial),
        PacketLayout::ZeroRtt(0),
    ] = datagrams[1].packets()
    else {
        panic!("the second datagram holds an Initial and a 0-RTT packet: {datagrams:?}");
    };
    assert_eq!(second_initial.packet_number().get(), 1);
    assert_eq!(second_initial.length(), initial_two.len());
    assert_eq!(second_initial.crypto().len(), 1);
    assert_eq!(second_initial.crypto()[0], 20..hello.len() as u64);
    assert!(second_initial.ping());
    // the 0-RTT packet the layout names is held
    let (first, held, kept) = state.into_parts();
    assert_eq!(held.len(), 1);
    assert_eq!(kept, Some(layout));
    assert_eq!(
        first.map(|first| first.encoded().encoded().to_vec()),
        Some(hello)
    );
}

#[test]
fn reading_the_first_flight_ends_at_a_frame_an_initial_packet_cannot_carry() {
    reset();
    let first = link();
    let mut receiver = test_receiver();
    // a STREAM frame
    deliver(
        padded(
            &[],
            |payload| long_packet(INITIAL, 0, payload),
            &[0x08, 0x00],
        ),
        &first,
        ms(1),
    );
    let (_, result) = read_first(&mut receiver);
    assert_eq!(result, Err("connection: frame not permitted".to_owned()));
}

#[test]
fn reading_the_first_flight_ends_when_the_client_closes() {
    reset();
    let first = link();
    let mut receiver = test_receiver();
    let close = [&[0x1c, 0x0a, 0x00, 0x00][..], &[0; 20]].concat();
    deliver(
        padded(&[], |payload| long_packet(INITIAL, 0, payload), &close),
        &first,
        ms(1),
    );
    let (_, result) = read_first(&mut receiver);
    assert!(
        result
            .as_ref()
            .is_err_and(|error| error.starts_with("closed: ")),
        "{result:?}"
    );
}

#[test]
fn a_server_passes_over_the_initial_packets_of_a_short_datagram() {
    use probe::PacketStep::{Inspect, InspectCredit, InspectHeld};
    reset();
    let first = link();
    feed_packets([
        (ms(6), Inspect),
        (ms(7), InspectHeld),
        (ms(8), InspectCredit(first.clone())),
    ]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first.clone());
    take_log();
    let datagram = coalesced([
        long_packet(INITIAL, 0, &crypto_hello()),
        long_packet(HANDSHAKE, 0, &ping()),
    ]);
    let size = datagram.len();
    assert!(size < MIN_DATAGRAM_SIZE);
    deliver(datagram, &first, ms(5));
    let log = run(&mut connection, 5..=8);
    assert!(
        log[0].starts_with("read \"\", largest None, ranges []"),
        "the Initial packet is not processed: {log:?}"
    );
    assert_eq!(
        log[1..],
        [
            // the Handshake packet after it is received, and waits for its keys
            "held 1, largest Handshake None".to_owned(),
            format!("credit Some(Some({}))", 2 * size),
        ]
    );
}

#[test]
fn a_datagram_whose_packets_wait_for_their_keys_counts_toward_the_limit() {
    use probe::PacketStep::{InspectCredit, InspectHeld};
    reset();
    let first = link();
    feed_packets([(ms(6), InspectHeld), (ms(7), InspectCredit(first.clone()))]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first.clone());
    take_log();
    let datagram = long_packet(HANDSHAKE, 0, &ping());
    let size = datagram.len();
    deliver(datagram, &first, ms(5));
    assert_eq!(
        run(&mut connection, 5..=7),
        [
            "held 1, largest Handshake None".to_owned(),
            format!("credit Some(Some({}))", 2 * size),
        ]
    );
}

#[test]
fn a_packet_without_its_keys_is_held_until_they_come() {
    use probe::PacketStep::{Inspect, InspectHeld, InstallHandshakeKeys};
    reset();
    // the strategy plans nothing: nothing is sent
    common::strategy::plan_nothing();
    let first = link();
    feed_packets([
        (ms(6), Inspect),
        (ms(7), InspectHeld),
        (ms(8), InstallHandshakeKeys),
        (ms(9), InspectHeld),
    ]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first.clone());
    take_log();
    deliver(
        padded(
            &[long_packet(INITIAL, 0, &crypto_hello())],
            |payload| long_packet(HANDSHAKE, 0, payload),
            &ping(),
        ),
        &first,
        ms(5),
    );
    assert_eq!(
        run(&mut connection, 5..=9),
        [
            "read \"hello\", largest Some((0, 5ms)), ranges [(0, 0)], due Some(Now), \
             idle Some(30.005s), reason None",
            "held 1, largest Handshake None",
            // a server discards them once it processed a Handshake packet
            "initial keys live: false",
            "held 0, largest Handshake Some(0)",
        ]
    );
}

#[test]
fn a_poll_receives_at_most_its_limit_and_wakes_itself_for_the_rest() {
    use probe::PacketStep::Inspect;
    reset();
    // the strategy plans nothing: nothing is sent
    common::strategy::plan_nothing();
    MAX_PER_POLL.with(|m| m.set(1));
    let first = link();
    feed_packets([(ms(5), Inspect), (ms(6), Inspect)]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first.clone());
    // the advancing call reads the first ClientHello first
    deliver(
        padded(
            &[],
            |payload| long_packet(INITIAL, 0, payload),
            &crypto_after_hello(0, b""),
        ),
        &first,
        ms(4),
    );
    let _ = settle(&mut connection, 4..=4);
    take_log();
    deliver(
        padded(
            &[],
            |payload| long_packet(INITIAL, 1, payload),
            &crypto_at(hello_len(), b"hel"),
        ),
        &first,
        ms(5),
    );
    deliver(
        padded(
            &[],
            |payload| long_packet(INITIAL, 2, payload),
            &crypto_at(hello_len() + 3, b"lo"),
        ),
        &first,
        ms(5),
    );
    let outer = Outer::new();
    advance_to(ms(5));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(
        outer.wakes(),
        2,
        "the receiving call woke itself, and the CRYPTO data the advancing call"
    );
    assert_eq!(
        take_log(),
        [
            "read \"hel\", largest Some((1, 5ms)), ranges [(0, 1)], due Some(Now), \
          idle Some(30.005s), reason None"
        ]
    );
    advance_to(ms(6));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(
        take_log(),
        [
            "read \"lo\", largest Some((2, 5ms)), ranges [(0, 2)], due Some(Now), \
          idle Some(30.005s), reason None"
        ]
    );
}

#[test]
fn a_connection_error_drops_the_rest_of_its_datagram() {
    use probe::PacketStep::Inspect;
    reset();
    let first = link();
    let handshake_done = [&[0x1e][..], &[0; 20]].concat();
    feed_packets([(ms(6), Inspect)]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first.clone());
    take_log();
    deliver(
        padded(
            &[long_packet(INITIAL, 0, &handshake_done)],
            |payload| long_packet(INITIAL, 1, payload),
            &crypto_hello(),
        ),
        &first,
        ms(5),
    );
    let log = run(&mut connection, 5..=6);
    let inspect = log
        .iter()
        .find(|line| line.starts_with("read"))
        .expect("inspected");
    assert!(
        inspect.starts_with("read \"\", largest None, ranges []")
            && inspect.contains(
                "reason Some(\"Local(Connection(PartsError(Inl(FrameNotPermitted { source: \
                 NotAtLevel { level: Initial } }))))\")"
            ),
        "{inspect}"
    );
}

#[test]
fn past_the_limit_of_held_inputs_the_new_one_is_dropped() {
    use probe::PacketStep::{InspectHeld, InstallHandshakeKeys};
    reset();
    MAX_HELD.with(|m| m.set(1));
    let first = link();
    feed_packets([
        (ms(6), InspectHeld),
        (ms(7), InstallHandshakeKeys),
        (ms(8), InspectHeld),
    ]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first.clone());
    take_log();
    deliver(
        coalesced([
            long_packet(HANDSHAKE, 0, &ping()),
            long_packet(HANDSHAKE, 1, &ping()),
        ]),
        &first,
        ms(5),
    );
    assert_eq!(
        run(&mut connection, 5..=8),
        [
            "held 1, largest Handshake None",
            "initial keys live: false",
            "held 0, largest Handshake Some(0)",
        ]
    );
}

/// An ACK frame of `ranges`, largest first, each `(smallest, largest)` below
/// 64, with an ACK Delay of 0 and, when `ecn`, ECN counts of 0; then
/// PADDING.
fn ack_of(ranges: &[(u8, u8)], ecn: bool) -> Vec<u8> {
    let (first_smallest, largest) = ranges[0];
    let count = u8::try_from(ranges.len() - 1).expect("a short list");
    let mut frame = vec![
        if ecn { 0x03 } else { 0x02 },
        largest,
        0,
        count,
        largest - first_smallest,
    ];
    let mut previous = first_smallest;
    for &(smallest, end) in &ranges[1..] {
        frame.push(previous - end - 2);
        frame.push(end - smallest);
        previous = smallest;
    }
    if ecn {
        frame.extend_from_slice(&[0, 0, 0]);
    }
    frame.extend_from_slice(&[0; 20]);
    frame
}

/// The client's Initial packet `number` with an ACK frame of `ranges`,
/// received over `link` at `at`.
fn ack_received(
    number: u64,
    ranges: &[(u8, u8)],
    link: &LinkId<(), ()>,
    at: Duration,
) -> probe::PacketStep {
    probe::PacketStep::Receive(received(
        long_packet(INITIAL, number, &ack_of(ranges, false)),
        link,
        at,
    ))
}

/// The lines of `log` that start with one of `prefixes`.
fn lines_of(log: Vec<String>, prefixes: &[&str]) -> Vec<String> {
    log.into_iter()
        .filter(|line| prefixes.iter().any(|prefix| line.starts_with(prefix)))
        .collect()
}

#[test]
fn an_ack_of_a_packet_not_sent_closes_the_connection() {
    use probe::PacketStep::Inspect;
    reset();
    let first = link();
    feed_packets([(ms(6), Inspect)]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first.clone());
    take_log();
    deliver(
        padded(
            &[],
            |payload| long_packet(INITIAL, 0, payload),
            &ack_of(&[(0, 0)], false),
        ),
        &first,
        ms(5),
    );
    let log = run(&mut connection, 5..=6);
    let inspect = log
        .iter()
        .find(|line| line.starts_with("read"))
        .expect("inspected");
    assert!(
        inspect.contains(
            "UnsentPacketAcknowledged { space: Initial, largest: PacketNumber(VarInt(0)), \
             next: PacketNumber(VarInt(0)), ecn_counts: false }"
        ),
        "{inspect}"
    );
}

#[test]
fn an_ack_samples_the_rtt_and_settles_what_it_newly_acknowledges() {
    use probe::PacketStep::Receive;
    reset();
    let first = link();
    feed([
        (
            ms(10),
            probe::Step::Sent {
                space: PacketNumberSpaceKind::Initial,
                count: 3,
            },
        ),
        (ms(51), probe::Step::Inspect),
    ]);
    // with ECN counts, which are not looked at yet
    feed_packets([(
        ms(50),
        Receive(received(
            long_packet(INITIAL, 0, &ack_of(&[(0, 2)], true)),
            &first,
            ms(50),
        )),
    )]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first);
    take_log();
    let log = run(&mut connection, 10..=51);
    assert_eq!(
        lines_of(log, &["in flight", "delivered", "lost", "processed", "rtt"]),
        [
            "in flight 3600, outstanding 3, lost [], permits 0, backoff 0",
            "delivered Initial 0",
            "delivered Initial 1",
            "delivered Initial 2",
            "processed: highest numbered true, non-probing true",
            "in flight 0, outstanding 0, lost [], permits 0, backoff 0",
            // the sample is the arrival less the send time; slow start
            // grows the window by what was acknowledged
            "rtt latest 40ms, smoothed 40ms, window 15600, in flight 0, permits 0, backoff 0, \
             first sample Some(50ms)",
        ]
    );
}

#[test]
fn deliveries_go_back_before_losses_and_a_late_ack_tells_of_a_spurious_loss() {
    reset();
    let first = link();
    feed([(
        ms(10),
        probe::Step::Sent {
            space: PacketNumberSpaceKind::Initial,
            count: 5,
        },
    )]);
    feed_packets([
        // 0 and 1 are three packets before 4, 2 is not
        (ms(50), ack_received(0, &[(3, 4)], &first, ms(50))),
        (ms(52), ack_received(1, &[(3, 4), (0, 1)], &first, ms(52))),
        (ms(60), ack_received(2, &[(2, 2)], &first, ms(60))),
    ]);
    let mut connection = connection!(SpyMine, AddressValidation::Validated, first);
    take_log();
    let log = run(&mut connection, 10..=60);
    assert_eq!(
        lines_of(log, &["congestion", "delivered", "lost"]),
        [
            // the losses come before the acknowledgments, each after what it
            // settles left the bytes in flight
            "congestion: lost 2400 bytes, 3600 in flight",
            "congestion: acked 2400 bytes, 1200 in flight, sampled true",
            "delivered Initial 3",
            "delivered Initial 4",
            "lost Initial 0",
            "lost Initial 1",
            // acknowledged late: the records were kept
            "congestion: spurious [10ms, 10ms]",
            "delivered Initial 0",
            "delivered Initial 1",
            // 2 waited on the time threshold: 9/8 of the 40 ms sample after
            // it was sent
            "congestion: lost 1200 bytes, 0 in flight",
            "lost Initial 2",
            "congestion: spurious [10ms]",
            "delivered Initial 2",
        ]
    );
}

#[test]
fn an_ack_that_acknowledges_nothing_new_keeps_the_backoff() {
    reset();
    // the strategy plans nothing: nothing is sent
    common::strategy::plan_nothing();
    let first = link();
    feed([
        (
            ms(10),
            probe::Step::Sent {
                space: PacketNumberSpaceKind::Initial,
                count: 1,
            },
        ),
        (
            ms(60),
            probe::Step::Sent {
                space: PacketNumberSpaceKind::Initial,
                count: 1,
            },
        ),
    ]);
    feed_packets([
        (ms(50), ack_received(0, &[(0, 0)], &first, ms(50))),
        (ms(200), ack_received(1, &[(0, 0)], &first, ms(200))),
        (ms(210), ack_received(2, &[(0, 1)], &first, ms(210))),
    ]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first);
    take_log();
    let outer = Outer::new();
    let mut at = |millis| {
        advance_to(ms(millis));
        assert!(outer.poll(&mut connection).is_pending());
        status()
    };
    assert_eq!(
        at(10).as_deref(),
        Some("in flight 1200, outstanding 1, lost [], permits 0, backoff 0")
    );
    assert_eq!(
        at(50).as_deref(),
        Some("in flight 0, outstanding 0, lost [], permits 0, backoff 0")
    );
    at(60);
    // 40 ms + 4 × 20 ms from the sample, after the packet sent at 60 ms
    assert_eq!(at(179), None);
    assert_eq!(
        at(180).as_deref(),
        Some("in flight 1200, outstanding 1, lost [], permits 2, backoff 1")
    );
    // nothing newly acknowledged: nothing changes
    assert_eq!(at(200), None);
    assert_eq!(
        at(210).as_deref(),
        Some("in flight 0, outstanding 0, lost [], permits 0, backoff 0")
    );
}

#[test]
fn a_client_keeps_the_backoff_until_the_server_has_validated_its_address() {
    reset();
    let first = link();
    let ack = |number, at| {
        probe::PacketStep::Receive(received(
            long_packet_with(
                first_byte(INITIAL),
                &[],
                &server_keys(),
                number,
                // packet 0, then the probe timeout's two probe datagrams,
                // packets 1 and 2
                &ack_of(&[(0, 2)], false),
            ),
            &first,
            ms(at),
        ))
    };
    feed([(
        ms(10),
        probe::Step::Sent {
            space: PacketNumberSpaceKind::Initial,
            count: 1,
        },
    )]);
    feed_packets([(ms(1100), ack(0, 1100))]);
    let mut connection = connection!(ClientMine, AddressValidation::Validated, first.clone());
    take_log();
    let outer = Outer::new();
    let mut at = |millis| {
        advance_to(ms(millis));
        assert!(outer.poll(&mut connection).is_pending());
        status()
    };
    at(10);
    assert_eq!(
        at(1009).as_deref(),
        Some("in flight 1200, outstanding 1, lost [], permits 2, backoff 1")
    );
    // newly acknowledged in the Initial space, with neither the handshake
    // confirmed nor a Handshake packet acknowledged
    assert_eq!(
        at(1100).as_deref(),
        Some("in flight 0, outstanding 0, lost [], permits 0, backoff 1")
    );
}

#[test]
fn a_delivered_ack_frame_stops_what_it_reported_from_being_reported() {
    use probe::PacketStep::{Inspect, Receive};
    reset();
    let first = link();
    feed([(ms(6), probe::Step::SentAck(PacketNumberSpaceKind::Initial))]);
    feed_packets([
        (
            ms(5),
            Receive(received(long_packet(INITIAL, 0, &ping()), &first, ms(5))),
        ),
        (ms(7), Inspect),
        (ms(50), ack_received(1, &[(0, 0)], &first, ms(50))),
        (ms(51), Inspect),
    ]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first);
    take_log();
    let log = run(&mut connection, 5..=51);
    assert_eq!(
        lines_of(log, &["read"]),
        [
            "read \"\", largest Some((0, 5ms)), ranges [(0, 0)], due Some(NotDue), \
             idle Some(30.005s), reason None",
            // the peer knows of 0: only the ACK frame's own packet is left
            "read \"\", largest Some((1, 50ms)), ranges [(1, 1)], due Some(NotDue), \
             idle Some(30.05s), reason None",
        ]
    );
}

#[test]
fn a_lost_ack_frame_owes_again_what_it_answered() {
    use probe::PacketStep::{Inspect, Receive};
    reset();
    // the strategy plans nothing: nothing is sent
    common::strategy::plan_nothing();
    let first = link();
    feed([
        (ms(6), probe::Step::SentAck(PacketNumberSpaceKind::Initial)),
        (
            ms(8),
            probe::Step::Sent {
                space: PacketNumberSpaceKind::Initial,
                count: 3,
            },
        ),
    ]);
    feed_packets([
        (
            ms(5),
            Receive(received(long_packet(INITIAL, 0, &ping()), &first, ms(5))),
        ),
        (ms(7), Inspect),
        // the ACK frame went in packet 0, three packets before 3
        (ms(50), ack_received(1, &[(3, 3)], &first, ms(50))),
        (ms(51), Inspect),
    ]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first);
    take_log();
    let log = run(&mut connection, 5..=51);
    assert_eq!(
        lines_of(log, &["read", "delivered", "lost"]),
        [
            "read \"\", largest Some((0, 5ms)), ranges [(0, 0)], due Some(NotDue), \
             idle Some(30.005s), reason None",
            "delivered Initial 3",
            // an Initial packet is acknowledged at once
            "read \"\", largest Some((1, 50ms)), ranges [(0, 1)], due Some(Now), \
             idle Some(30.05s), reason None",
        ]
    );
}

#[test]
fn a_link_path_that_ends_hands_back_what_it_did_not_settle_as_lost() {
    reset();
    CLOSE_AT.with(|c| c.set(Some(ms(20))));
    let first = link();
    feed([(
        ms(10),
        probe::Step::Sent {
            space: PacketNumberSpaceKind::Initial,
            count: 2,
        },
    )]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first);
    take_log();
    let log = run(&mut connection, 10..=60);
    assert_eq!(
        lines_of(log, &["lost", "link path ended"]),
        ["lost Initial 0", "lost Initial 1", "link path ended: None",]
    );
}

/// The events of the send strategy that start with `prefix`, taken.
fn strategy_events(prefix: &str) -> Vec<String> {
    take_strategy_events()
        .into_iter()
        .filter(|event| event.starts_with(prefix))
        .collect()
}

#[test]
fn the_strategy_core_is_told_of_each_send_key_and_the_confirmation_once() {
    use probe::PacketStep::{InstallHandshakeKeys, InstallOneRttSendKeys};
    reset();
    feed_packets([
        (ms(12), InstallHandshakeKeys),
        (ms(13), InstallOneRttSendKeys),
    ]);
    feed([(ms(14), probe::Step::Confirm)]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, link());
    // the server starts with its Initial keys
    assert_eq!(
        take_strategy_events(),
        ["path 0: added Active", "core: keys Initial"]
    );
    let outer = Outer::new();
    // the NEW_CONNECTION_ID the local connection ID strategy issues once the
    // handshake is confirmed is the link path's to gather, not told to the
    // core
    for (at, told) in [
        (11, &[][..]),
        (12, &["core: keys Handshake"][..]),
        (13, &["core: keys OneRtt"][..]),
        (14, &["core: confirmed"][..]),
        // nothing is told again as the connection is polled on
        (15, &[][..]),
        (500, &[][..]),
        (1500, &[][..]),
    ] {
        advance_to(ms(at));
        assert!(outer.poll(&mut connection).is_pending());
        assert_eq!(strategy_events("core: "), told, "at {at} ms");
    }
}

#[test]
fn the_new_connection_id_is_gathered_and_sent_once_the_handshake_is_confirmed() {
    use probe::PacketStep::{HandshakeConnectionId, InstallHandshakeKeys, InstallOneRttKeys};
    reset();
    // a connection ID to send to (the overhead of a packet is known only
    // with it), the 1-RTT keys (which `open_sent_one_rtt` opens with), and a validated address for
    // the credit; the handshake is confirmed at 14 ms
    feed_packets([
        (
            ms(11),
            HandshakeConnectionId(ConnectionId::new(&CLIENT_SCID).expect("eight bytes")),
        ),
        (ms(12), InstallHandshakeKeys),
        (ms(13), InstallOneRttKeys),
    ]);
    feed([(ms(14), probe::Step::Confirm)]);
    let mut connection = connection!(Mine, AddressValidation::Validated, link());
    take_strategy_events();
    // before the confirmation the local connection ID strategy has nothing
    // to disclose
    let _ = run(&mut connection, 11..=13);
    assert_eq!(strategy_events("path 0: content"), Vec::<String>::new());
    assert_eq!(common::take_sent(), []);
    // once confirmed, the link path gathers the NEW_CONNECTION_ID of the
    // connection ID the strategy issues, writes it and no longer finds it
    let _ = run(&mut connection, 14..=16);
    assert_eq!(
        strategy_events("path 0: "),
        [
            "path 0: content NewConnectionIdIntent { sequence: 1 }",
            "path 0: gone NewConnectionIdIntent { sequence: 1 }",
        ]
    );
    let sent = common::take_sent();
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert!(short_header(&sent[0].1), "a 1-RTT packet");
    let (_, _, payload) = open_sent_one_rtt(&sent[0].1);
    // the frame type, then its sequence number
    assert_eq!(payload[..2], [0x18, 0x01]);
    // nothing is issued again
    let _ = run(&mut connection, 17..=1000);
    assert_eq!(strategy_events("path 0: content"), Vec::<String>::new());
}

/// The validated server has a destination connection ID and 1-RTT keys
/// before it confirms the handshake at 14 ms.
fn prepare_pmtu_handshake() {
    use probe::PacketStep::{HandshakeConnectionId, InstallHandshakeKeys, InstallOneRttKeys};
    common::set_link_ceilings(1452);
    feed_packets([
        (
            ms(11),
            HandshakeConnectionId(ConnectionId::new(&CLIENT_SCID).expect("eight bytes")),
        ),
        (ms(12), InstallHandshakeKeys),
        (ms(13), InstallOneRttKeys),
    ]);
    feed([(ms(14), probe::Step::Confirm)]);
}

#[test]
fn a_confirmed_link_path_sends_one_padded_ping_of_the_probe_size_and_waits_for_its_result() {
    reset();
    prepare_pmtu_handshake();
    feed_packets([(
        ms(100),
        probe::PacketStep::TakeRecords(PacketNumberSpaceKind::ApplicationData),
    )]);
    let mut connection = connection!(SpyMine, AddressValidation::Validated, link());
    let _ = settle(&mut connection, 11..=13);
    assert!(common::take_sent().is_empty());

    let _ = settle(&mut connection, 14..=16);
    let sent = common::take_sent();
    let [(_, disclosure), (_, probe)] = sent.as_slice() else {
        panic!(
            "expected a connection ID and a datagram size probe, got {} datagrams",
            sent.len()
        );
    };
    let (_, _, disclosure) = open_sent_one_rtt(disclosure);
    assert_eq!(disclosure[..2], [0x18, 0x01], "NEW_CONNECTION_ID");
    assert_eq!(probe.len(), 1326);
    let (_, _, payload) = open_sent_one_rtt(probe);
    assert_eq!(payload[0], 0x01, "PING");
    assert!(payload[1..].iter().all(|byte| *byte == 0), "PADDING");

    let log = settle(&mut connection, 17..=100);
    assert_eq!(
        lines_of(log, &["probe record"]),
        ["probe record 1326 bytes, packet 1"]
    );
    assert!(
        common::take_sent().is_empty(),
        "the probe is still outstanding"
    );
}

/// An Application Data ACK from the client.
fn one_rtt_ack_received(
    number: u64,
    ranges: &[(u8, u8)],
    link: &LinkId<(), ()>,
    at: Duration,
) -> probe::PacketStep {
    probe::PacketStep::Receive(received(
        one_rtt_packet_of(0, number, &ack_of(ranges, false)),
        link,
        at,
    ))
}

#[test]
fn losing_a_size_probe_removes_its_bytes_and_a_late_ack_raises_the_size_in_use() {
    reset();
    let first = link();
    prepare_pmtu_handshake();
    // Packets 0 and 1 carry the connection ID and the probe. An ACK of 4
    // puts only the probe past the packet threshold. It also acknowledges
    // 0, so the probe is above the smallest acknowledged number.
    feed([(
        ms(20),
        probe::Step::Sent {
            space: PacketNumberSpaceKind::ApplicationData,
            count: 3,
        },
    )]);
    feed_packets([
        (
            ms(30),
            one_rtt_ack_received(0, &[(4, 4), (0, 0)], &first, ms(30)),
        ),
        (ms(31), one_rtt_ack_received(1, &[(1, 1)], &first, ms(31))),
    ]);
    let mut connection = connection!(SpyMine, AddressValidation::Validated, first);
    let _ = settle(&mut connection, 11..=29);
    assert_eq!(common::take_sent().len(), 2);
    let log = settle(&mut connection, 30..=30);
    assert!(
        log.iter()
            .any(|line| line.starts_with("congestion: removed 1326 bytes")),
        "{log:?}"
    );
    assert!(lines_of(log, &["congestion: lost", "congestion: persistent"]).is_empty());
    let sent = common::take_sent();
    assert_eq!(
        sent.iter().map(|(_, d)| d.len()).collect::<Vec<_>>(),
        [1326],
        "retry"
    );
    let log = settle(&mut connection, 31..=31);
    assert_eq!(
        lines_of(log, &["size in use", "congestion:"]),
        ["size in use 1326, handshake confirmed true"]
    );
    let sent = common::take_sent();
    assert_eq!(
        sent.iter().map(|(_, d)| d.len()).collect::<Vec<_>>(),
        [1389],
        "the next probe"
    );
}

#[test]
fn giving_up_a_size_probe_three_times_retries_its_size() {
    use common::SendOutcome::{Accept, GiveUp};
    reset();
    prepare_pmtu_handshake();
    // First the connection ID goes. Giving up the next three probes
    // must not count toward the three network losses that lower the size.
    common::plan_sends([Accept(1), GiveUp, GiveUp, GiveUp]);
    let mut connection = connection!(SpyMine, AddressValidation::Validated, link());
    let log = settle(&mut connection, 11..=100);
    let given_up = common::take_given_up();
    assert_eq!(
        given_up.iter().map(|d| d.len()).collect::<Vec<_>>(),
        [1326; 3]
    );
    let sent = common::take_sent();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[1].1.len(), 1326);
    assert!(lines_of(log, &["congestion: lost", "congestion: persistent"]).is_empty());
}

#[test]
fn a_link_below_the_minimum_declares_the_probe_lost_without_asking_the_pto_policy() {
    reset();
    let first = link();
    prepare_pmtu_handshake();
    // A candidate can still be validated, so losing the first link's
    // minimum does not end the connection with NO_VIABLE_PATH.
    ADD.with(|adder| adder.set(Some((ms(18), link()))));
    feed_packets([(ms(20), one_rtt_ack_received(0, &[(0, 0)], &first, ms(20)))]);
    let mut connection = connection!(SpyMine, AddressValidation::Validated, first.clone());
    let _ = settle(&mut connection, 11..=20);
    assert_eq!(common::take_sent().len(), 2);
    common::set_link_ceiling(&first, 1172);
    common::report_link_ceiling_changed(&first);
    let log = settle(&mut connection, 21..=100);
    assert_eq!(
        lines_of(log, &["congestion:", "PTO policy consulted"]),
        ["congestion: removed 1326 bytes, 0 in flight"]
    );
    assert!(common::take_sent().is_empty());
}

#[test]
fn the_strategy_core_is_told_once_the_close_reason_is_recorded_that_no_link_path_is_active() {
    reset();
    CLOSER.with(|c| c.borrow_mut().push_back((ms(20), probe::CloserStep::Close)));
    let mut connection = connection!(Mine, AddressValidation::NotValidated, link());
    take_strategy_events();
    let outer = Outer::new();
    advance_to(ms(19));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(strategy_events("core: closed"), Vec::<String>::new());
    advance_to(ms(20));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(
        strategy_events("core: closed"),
        ["core: closed Local(Application(AppClose(7)))"]
    );
    // the link path closes for three probe timeouts; the core is not told
    // again while it does, nor when the connection ends
    let pto = probe_timeout(
        &sakuya_recovery_v1::rtt::RttEstimate::initial(sakuya_recovery_v1::rtt::INITIAL_RTT),
        ms(1),
        PacketNumberSpaceKind::ApplicationData,
        ms(25),
        0,
    );
    advance_to(ms(21));
    assert!(outer.poll(&mut connection).is_pending());
    advance_to(ms(20) + pto * 3);
    assert!(outer.poll(&mut connection).is_ready());
    assert_eq!(strategy_events("core: closed"), Vec::<String>::new());
}

#[test]
fn the_first_link_path_planner_starts_active_and_a_later_one_as_a_candidate() {
    reset();
    ADD.with(|a| a.set(Some((ms(10), link()))));
    let mut connection = connection!(Mine, AddressValidation::NotValidated, link());
    assert_eq!(strategy_events("path"), ["path 0: added Active"]);
    let outer = Outer::new();
    advance_to(ms(10));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(strategy_events("path"), ["path 1: added Candidate"]);
}

#[test]
fn the_planner_is_told_when_its_link_path_closes_and_when_it_ends() {
    reset();
    CLOSE_AT.with(|c| c.set(Some(ms(20))));
    let mut connection = connection!(Mine, AddressValidation::NotValidated, link());
    assert_eq!(strategy_events("path"), ["path 0: added Active"]);
    let outer = Outer::new();
    advance_to(ms(19));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(strategy_events("path"), Vec::<String>::new());
    // the role becomes `Closing` for 30 ms
    advance_to(ms(20));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(strategy_events("path"), ["path 0: role Closing"]);
    advance_to(ms(49));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(strategy_events("path"), Vec::<String>::new());
    advance_to(ms(50));
    let _ = outer.poll(&mut connection);
    assert_eq!(strategy_events("path"), ["path 0: ended"]);
}

#[test]
fn the_planner_is_told_when_its_link_path_drains() {
    reset();
    CLOSE_AT.with(|c| c.set(Some(ms(20))));
    DRAIN.with(|d| d.set(true));
    let mut connection = connection!(Mine, AddressValidation::NotValidated, link());
    take_strategy_events();
    let outer = Outer::new();
    advance_to(ms(20));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(strategy_events("path"), ["path 0: role Draining"]);
}

#[test]
fn an_acknowledgment_due_now_is_gathered_asking_room_for_the_shortest_frame() {
    use probe::PacketStep::Receive;
    reset();
    // the strategy plans nothing: nothing is sent
    common::strategy::plan_nothing();
    let first = link();
    feed_packets([(
        ms(5),
        Receive(received(long_packet(INITIAL, 0, &ping()), &first, ms(5))),
    )]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first);
    take_strategy_events();
    let _ = run(&mut connection, 4..=4);
    assert_eq!(take_strategy_events(), Vec::<String>::new());
    // due once the packet is processed at 5 ms: the sending call it wakes
    // gathers it at the next poll
    let _ = run(&mut connection, 5..=6);
    // the frame's type, a Largest Acknowledged, an ACK Delay, an ACK Range
    // Count and a First ACK Range of one byte each
    assert_eq!(
        take_strategy_events(),
        ["path 0: content AckIntent { space: Initial, shortest: 5, piggyback: false }"]
    );
    // nothing it has changes while the acknowledgment is due
    let _ = run(&mut connection, 7..=8);
    assert_eq!(take_strategy_events(), Vec::<String>::new());
}

#[test]
fn an_acknowledgment_that_is_not_due_now_is_not_gathered() {
    use probe::PacketStep::{InstallOneRttKeys, Receive};
    reset();
    let first = link();
    feed_packets([
        (ms(4), InstallOneRttKeys),
        // the client's Initial packet gives the server a connection ID to
        // send to
        (
            ms(5),
            Receive(received(
                initial_from(&CLIENT_SCID, 0, &ping()),
                &first,
                ms(5),
            )),
        ),
        (
            ms(10),
            Receive(received(one_rtt_packet_of(0, 0, &ping()), &first, ms(10))),
        ),
        (
            ms(11),
            Receive(received(one_rtt_packet_of(0, 1, &ping()), &first, ms(11))),
        ),
    ]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first);
    take_strategy_events();
    let _ = run(&mut connection, 4..=9);
    assert_eq!(
        strategy_events("path 0: content"),
        ["path 0: content AckIntent { space: Initial, shortest: 5, piggyback: false }"]
    );
    // one ack-eliciting packet in the Application Data space waits for the
    // maximum ACK delay
    let _ = run(&mut connection, 10..=10);
    assert_eq!(strategy_events("path 0: content"), Vec::<String>::new());
    // a second is acknowledged at once: the sending call it wakes gathers
    // it at the next poll
    let _ = run(&mut connection, 11..=12);
    assert_eq!(
        strategy_events("path 0: content"),
        ["path 0: content AckIntent { space: ApplicationData, shortest: 5, piggyback: false }"]
    );
}

#[test]
fn the_acknowledgment_is_not_gathered_once_it_is_written() {
    use probe::PacketStep::Receive;
    reset();
    let first = link();
    feed_packets([
        (
            ms(5),
            Receive(received(long_packet(INITIAL, 0, &ping()), &first, ms(5))),
        ),
        (
            ms(10),
            Receive(received(long_packet(INITIAL, 1, &ping()), &first, ms(10))),
        ),
    ]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first);
    take_strategy_events();
    // gathered for the first datagram and written there: the next datagram
    // gathers nothing due
    let _ = run(&mut connection, 5..=9);
    assert_eq!(
        take_strategy_events(),
        [
            "path 0: content AckIntent { space: Initial, shortest: 5, piggyback: false }",
            "path 0: gone AckIntent { space: Initial, shortest: 5, piggyback: false }",
        ]
    );
    assert_eq!(common::take_sent().len(), 1, "the ACK");
    // a new packet makes one due again
    let _ = run(&mut connection, 10..=11);
    assert_eq!(
        take_strategy_events(),
        [
            "path 0: content AckIntent { space: Initial, shortest: 5, piggyback: false }",
            "path 0: gone AckIntent { space: Initial, shortest: 5, piggyback: false }",
        ]
    );
    assert_eq!(common::take_sent().len(), 1, "the ACK again");
}

#[test]
fn the_sending_call_is_woken_for_driver_content_only_when_it_changes() {
    use probe::PacketStep::Receive;
    reset();
    // the strategy plans nothing: the sending call waits for what the driver
    // has to send
    common::strategy::plan_nothing();
    let first = link();
    feed_packets([
        (
            ms(5),
            Receive(received(long_packet(INITIAL, 0, &ping()), &first, ms(5))),
        ),
        // the acknowledgment's shortest frame stays as it was
        (
            ms(7),
            Receive(received(long_packet(INITIAL, 1, &ping()), &first, ms(7))),
        ),
        // the Largest Acknowledged needs two bytes
        (
            ms(9),
            Receive(received(long_packet(INITIAL, 100, &ping()), &first, ms(9))),
        ),
    ]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first);
    take_strategy_events();
    let _ = settle(&mut connection, 1..=4);
    common::strategy::take_plans_asked(0);
    // an acknowledgment due now that fits an empty datagram wakes the call,
    // which gathers it
    let _ = settle(&mut connection, 5..=5);
    assert_eq!(common::strategy::take_plans_asked(0), 1);
    assert_eq!(
        take_strategy_events(),
        ["path 0: content AckIntent { space: Initial, shortest: 5, piggyback: false }"]
    );
    // the same content does not wake it again
    let _ = settle(&mut connection, 6..=8);
    assert_eq!(common::strategy::take_plans_asked(0), 0);
    // content that changed does
    let _ = settle(&mut connection, 9..=9);
    assert_eq!(common::strategy::take_plans_asked(0), 1);
    assert_eq!(
        take_strategy_events(),
        [
            "path 0: content AckIntent { space: Initial, shortest: 6, piggyback: false }",
            "path 0: gone AckIntent { space: Initial, shortest: 5, piggyback: false }",
        ]
    );
}

#[test]
fn driver_content_that_does_not_fit_an_empty_datagram_wakes_the_sending_call_once_it_does() {
    reset();
    let first = link();
    CRYPTO_WRITE_AT.with(|c| c.set(Some(ms(4))));
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first.clone());
    take_strategy_events();
    let _ = settle(&mut connection, 1..=3);
    common::strategy::take_plans_asked(0);
    // with no connection ID to send to and no credit, the CRYPTO data the
    // probe writes at 4 ms does not fit: the call is not woken for it
    let _ = settle(&mut connection, 4..=4);
    assert_eq!(common::strategy::take_plans_asked(0), 0);
    // the client's Initial packet gives both: the call is woken, and
    // gathers the data with the acknowledgment of the packet
    deliver(client_initial(0), &first, ms(5));
    let _ = settle(&mut connection, 5..=5);
    assert!(common::strategy::take_plans_asked(0) > 0);
    let events = strategy_events("path 0: content");
    assert_eq!(
        events,
        [
            "path 0: content AckIntent { space: Initial, shortest: 5, piggyback: false }",
            "path 0: content CryptoIntent { level: Initial, shortest: 4 }",
        ]
    );
}

#[test]
fn the_acknowledgment_is_gathered_anew_when_the_shortest_frame_grows() {
    use probe::PacketStep::Receive;
    reset();
    // the strategy plans nothing: nothing is sent
    common::strategy::plan_nothing();
    let first = link();
    feed_packets([
        (
            ms(5),
            Receive(received(long_packet(INITIAL, 0, &ping()), &first, ms(5))),
        ),
        // the Largest Acknowledged of the first range needs two bytes
        (
            ms(6),
            Receive(received(long_packet(INITIAL, 100, &ping()), &first, ms(6))),
        ),
        // the first range grows with no more bytes
        (
            ms(7),
            Receive(received(long_packet(INITIAL, 101, &ping()), &first, ms(7))),
        ),
    ]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first);
    take_strategy_events();
    // each packet is processed after the sending call is polled: what it
    // makes due is gathered at the next poll
    let _ = run(&mut connection, 5..=6);
    assert_eq!(
        take_strategy_events(),
        ["path 0: content AckIntent { space: Initial, shortest: 5, piggyback: false }"]
    );
    let _ = run(&mut connection, 7..=7);
    assert_eq!(
        take_strategy_events(),
        [
            "path 0: content AckIntent { space: Initial, shortest: 6, piggyback: false }",
            "path 0: gone AckIntent { space: Initial, shortest: 5, piggyback: false }",
        ]
    );
    // the frame needs no more room: the sending call is not woken for it
    let _ = run(&mut connection, 8..=9);
    assert_eq!(take_strategy_events(), Vec::<String>::new());
}

#[test]
fn a_probe_timeout_has_its_link_path_gather_a_ping() {
    reset();
    let first = link();
    feed([(
        ms(6),
        probe::Step::Sent {
            space: PacketNumberSpaceKind::Initial,
            count: 1,
        },
    )]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    // the client's Initial packet gives the server a connection ID to send
    // to; its ACK goes at 6 ms
    deliver(
        padded(
            &[],
            |payload| initial_from(&CLIENT_SCID, 0, payload),
            &ping(),
        ),
        &first,
        ms(5),
    );
    let _ = run(&mut connection, 5..=6);
    assert_eq!(common::take_sent().len(), 1, "the ACK");
    take_strategy_events();
    let _ = run(&mut connection, 7..=1004);
    assert_eq!(strategy_events("path 0: content"), Vec::<String>::new());
    // the probe timeout expires at 1005 ms; the sending call it wakes
    // gathers the PING, writes it, and no longer finds it
    let _ = run(&mut connection, 1005..=1006);
    assert_eq!(
        strategy_events("path 0: "),
        [
            "path 0: content ProbePingIntent { space: Initial }",
            "path 0: gone ProbePingIntent { space: Initial }",
        ]
    );
    // the expiry permits two probe datagrams (the default policy), and its
    // space has a PING for each: the second probe is a second PING
    let sent = common::take_sent();
    assert_eq!(sent.len(), 2, "{sent:?}");
    for (_, datagram) in &sent {
        assert_eq!(open_sent_initial(datagram).payload[0], 0x01, "the PING");
    }
}

#[test]
fn a_probe_timeout_sends_two_probe_datagrams_each_with_a_ping_and_no_third() {
    reset();
    let first = link();
    feed([(
        ms(6),
        probe::Step::Sent {
            space: PacketNumberSpaceKind::Initial,
            count: 1,
        },
    )]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    deliver(
        padded(
            &[],
            |payload| initial_from(&CLIENT_SCID, 0, payload),
            &ping(),
        ),
        &first,
        ms(5),
    );
    let _ = run(&mut connection, 5..=6);
    assert_eq!(common::take_sent().len(), 1, "the ACK");
    let _ = run(&mut connection, 7..=1004);
    assert_eq!(common::take_sent(), []);
    // the expiry at 1005 ms permits two probe datagrams (the default
    // policy), and puts a PING of its space, the Initial space, in each
    let _ = run(&mut connection, 1005..=1006);
    let sent = common::take_sent();
    assert_eq!(sent.len(), 2, "{sent:?}");
    for (_, datagram) in &sent {
        let packet = open_sent_initial(datagram);
        assert_eq!(packet.payload[0], 0x01, "the PING");
    }
    // the permits are used up: no third until the next expiry, at 3005 ms
    let _ = run(&mut connection, 1007..=3004);
    assert_eq!(common::take_sent(), []);
}

#[test]
fn a_probe_datagram_whose_crypto_frame_leaves_no_room_for_a_ping_is_one_of_the_two() {
    reset();
    let first = link();
    // more CRYPTO data than one Initial packet holds: two datagrams
    CRYPTO_WRITE_AT.with(|c| c.set(Some(ms(4))));
    CRYPTO_WRITE_LEN.with(|c| c.set(1500));
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    let _ = settle(&mut connection, 1..=4);
    deliver(client_initial(0), &first, ms(5));
    let _ = run(&mut connection, 5..=6);
    assert_eq!(common::take_sent().len(), 2, "the CRYPTO data");
    let _ = run(&mut connection, 7..=1003);
    assert_eq!(common::take_sent(), []);
    // the expiry hands the content of both packets back and permits two
    // probe datagrams: the first is filled with CRYPTO frames and has no
    // room for a PING, yet counts as a probe; the second carries the rest
    // of the data and a PING
    let _ = run(&mut connection, 1004..=1010);
    let sent = common::take_sent();
    assert_eq!(sent.len(), 2, "{sent:?}");
    let payloads: Vec<_> = sent
        .iter()
        .map(|(_, datagram)| open_sent_initial(datagram).payload)
        .collect();
    // after the ACK frame
    assert_eq!(payloads[0][8..10], [0x06, 0x00], "CRYPTO from offset 0");
    assert_eq!(payloads[1][0], 0x06, "the rest of the CRYPTO data");
    // nothing more until the next expiry
    let _ = run(&mut connection, 1011..=2999);
    assert_eq!(common::take_sent(), []);
}

#[test]
fn the_next_probe_timeout_has_its_link_path_gather_a_ping_again() {
    reset();
    let first = link();
    feed([(
        ms(6),
        probe::Step::Sent {
            space: PacketNumberSpaceKind::Initial,
            count: 1,
        },
    )]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    deliver(
        padded(
            &[],
            |payload| initial_from(&CLIENT_SCID, 0, payload),
            &ping(),
        ),
        &first,
        ms(5),
    );
    // the ACK at 6 ms; the probe timeout expires at 1005 ms and its two
    // PINGs (one for each probe datagram it permits) go at 1006 ms, the
    // last of them
    let _ = run(&mut connection, 5..=1006);
    assert_eq!(common::take_sent().len(), 3, "the ACK and the two PINGs");
    take_strategy_events();
    // the next one expires at 1006 ms + 2 × 999 ms and has a PING gathered
    // and written again
    let _ = run(&mut connection, 1007..=3004);
    assert_eq!(strategy_events("path 0: "), Vec::<String>::new());
    let _ = run(&mut connection, 3005..=3005);
    assert_eq!(
        strategy_events("path 0: "),
        [
            "path 0: content ProbePingIntent { space: Initial }",
            "path 0: gone ProbePingIntent { space: Initial }",
        ]
    );
    // two probe datagrams again, a PING in each
    let sent = common::take_sent();
    assert_eq!(sent.len(), 2, "{sent:?}");
    for (_, datagram) in &sent {
        assert_eq!(open_sent_initial(datagram).payload[0], 0x01, "the PING");
    }
}

#[test]
fn the_planner_is_told_what_its_link_path_can_send_when_the_credit_grows() {
    reset();
    let first = link();
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first.clone());
    let datagram = long_packet(INITIAL, 0, &ping());
    let size = datagram.len();
    deliver(datagram, &first, ms(5));
    let _ = run(&mut connection, 5..=5);
    let limits = common::strategy::observed_limits(0).expect("the planner was told");
    // the factor of the tests is 2; the link takes 1200 bytes, and the
    // peer's transport parameters are not known yet
    assert_eq!(limits.anti_amplification_credit, Some(2 * size as u64));
    assert_eq!(limits.link_ceiling, Some(1200));
    assert_eq!(limits.peer_max_udp_payload, 65527);
    assert_eq!(limits.pmtu_conclusion, 1200);
    assert_eq!(limits.probe_permits, 0);
    // nothing is in flight in the initial window of ten 1200-byte
    // datagrams (RFC 9002 §7.2); the sending call refilled the pacer when
    // it first looked for something to send, which releases the window
    assert_eq!(limits.congestion_window_left, 12000);
    assert_eq!(limits.pacing_allowance, 12000);
}

/// What the planner of the Nth link path built was last told the link's
/// datagram size limit is.
fn told_link_ceiling(path: usize) -> Option<usize> {
    common::strategy::observed_limits(path)
        .expect("the planner was told")
        .link_ceiling
}

#[test]
fn the_planner_is_told_the_link_ceiling_when_the_link_reports_a_change() {
    reset();
    let first = link();
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    let _ = run(&mut connection, 1..=1);
    assert_eq!(told_link_ceiling(0), Some(1200));
    common::set_link_ceiling(&first, 1500);
    common::report_link_ceiling_changed(&first);
    let _ = run(&mut connection, 2..=2);
    let limits = common::strategy::observed_limits(0).expect("the planner was told");
    assert_eq!(limits.link_ceiling, Some(1500));
    assert!(limits.supports_minimum());
    // a later change is reported by the next future
    common::set_link_ceiling(&first, 1400);
    common::report_link_ceiling_changed(&first);
    let _ = run(&mut connection, 3..=3);
    assert_eq!(told_link_ceiling(0), Some(1400));
}

#[test]
fn a_link_ceiling_below_1200_reaches_the_strategy_as_a_link_path_that_does_not_carry_it() {
    reset();
    let first = link();
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    let _ = run(&mut connection, 1..=1);
    // an IPv4 tunnel over an MTU of 1200
    common::set_link_ceiling(&first, 1172);
    common::report_link_ceiling_changed(&first);
    let _ = run(&mut connection, 2..=2);
    let limits = common::strategy::observed_limits(0).expect("the planner was told");
    assert_eq!(limits.link_ceiling, Some(1172));
    assert!(!limits.supports_minimum());
    assert_eq!(
        limits.capacity_for(sakuya_wire_v1::frame::write::FlightClass::AckOnly),
        0
    );
    // back at 1200, the link path carries it again
    common::set_link_ceiling(&first, 1200);
    common::report_link_ceiling_changed(&first);
    let _ = run(&mut connection, 3..=3);
    let limits = common::strategy::observed_limits(0).expect("the planner was told");
    assert_eq!(limits.link_ceiling, Some(1200));
    assert!(limits.supports_minimum());
}

#[test]
fn the_only_link_path_that_stops_sending_closes_the_connection_with_no_viable_path() {
    reset();
    let first = link();
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    let _ = run(&mut connection, 1..=1);
    assert_eq!(strategy_events("core: closed"), Vec::<String>::new());
    // an IPv4 tunnel over an MTU of 1200: no other link path can send
    common::set_link_ceiling(&first, 1172);
    common::report_link_ceiling_changed(&first);
    let _ = run(&mut connection, 2..=2);
    let closed = strategy_events("core: closed");
    assert_eq!(closed.len(), 1, "{closed:?}");
    assert!(closed[0].contains("NoViablePath"), "{closed:?}");
}

#[test]
fn the_link_ceiling_is_not_read_again_until_the_link_reports_a_change() {
    reset();
    let first = link();
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    let _ = run(&mut connection, 1..=1);
    common::set_link_ceiling(&first, 1500);
    let _ = run(&mut connection, 2..=2);
    assert_eq!(told_link_ceiling(0), Some(1200));
    common::report_link_ceiling_changed(&first);
    let _ = run(&mut connection, 3..=3);
    assert_eq!(told_link_ceiling(0), Some(1500));
}

#[test]
fn a_link_ceiling_change_is_told_to_the_link_paths_over_that_link_only() {
    reset();
    let first = link();
    let second = link();
    ADD.with(|a| a.set(Some((ms(10), second.clone()))));
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    let _ = run(&mut connection, 1..=10);
    assert_eq!(told_link_ceiling(0), Some(1200));
    assert_eq!(told_link_ceiling(1), Some(1200));
    common::set_link_ceiling(&first, 1500);
    common::set_link_ceiling(&second, 1500);
    common::report_link_ceiling_changed(&second);
    let _ = run(&mut connection, 11..=11);
    assert_eq!(told_link_ceiling(0), Some(1200));
    assert_eq!(told_link_ceiling(1), Some(1500));
}

/// A NEW_CONNECTION_ID frame (RFC 9000 §19.15) numbered `sequence`, with
/// Retire Prior To 0, an 8-byte connection ID and a token made from
/// `sequence`.
fn new_connection_id(sequence: u8) -> Vec<u8> {
    let mut frame = vec![0x18, sequence, 0, 8];
    frame.extend_from_slice(&[sequence + 0x10; 8]);
    frame.extend_from_slice(&[sequence + 0x80; 16]);
    frame
}

#[test]
fn a_server_sends_with_the_source_connection_id_of_the_first_initial_packet_that_opens() {
    use probe::PacketStep::{InspectOffer, Receive};
    reset();
    let first = link();
    let mut changed = initial_from(&[0xbb; 8], 1, &ping());
    // the tag no longer authenticates
    let len = changed.len();
    changed[len - 1] ^= 1;
    feed_packets([
        (ms(4), InspectOffer(first.clone())),
        (ms(5), Receive(received(changed, &first, ms(5)))),
        (ms(6), InspectOffer(first.clone())),
        (
            ms(7),
            Receive(received(
                initial_from(&[0xaa; 8], 2, &ping()),
                &first,
                ms(7),
            )),
        ),
        (
            ms(8),
            Receive(received(
                initial_from(&[0xcc; 8], 3, &ping()),
                &first,
                ms(8),
            )),
        ),
        (ms(9), InspectOffer(first.clone())),
    ]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first);
    take_log();
    assert_eq!(
        run(&mut connection, 4..=9),
        [
            // nothing to send with before the handshake connection ID
            "offered []".to_owned(),
            "dropped: payload not opened".to_owned(),
            "offered []".to_owned(),
            "processed: highest numbered true, non-probing true".to_owned(),
            // from another connection attempt
            "dropped: another source connection ID".to_owned(),
            format!("offered [(0, {:?})]", [0xaa; 8]),
        ]
    );
}

#[test]
fn a_new_connection_id_frame_adds_a_connection_id_to_offer() {
    use probe::PacketStep::{InspectOffer, InstallOneRttKeys, Receive};
    reset();
    let first = link();
    feed_packets([
        (
            ms(5),
            Receive(received(
                initial_from(&[0xaa; 8], 0, &ping()),
                &first,
                ms(5),
            )),
        ),
        (ms(6), InstallOneRttKeys),
        (
            ms(7),
            Receive(received(
                one_rtt_packet_of(0, 0, &new_connection_id(1)),
                &first,
                ms(7),
            )),
        ),
        (ms(8), InspectOffer(first.clone())),
    ]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first);
    take_log();
    assert_eq!(
        run(&mut connection, 5..=8),
        [
            "processed: highest numbered true, non-probing true".to_owned(),
            // NEW_CONNECTION_ID is a probing frame (RFC 9000 §9.1)
            "processed: highest numbered true, non-probing false".to_owned(),
            format!("offered [(0, {:?}), (1, {:?})]", [0xaa; 8], [0x11; 8]),
        ]
    );
}

#[test]
fn a_new_connection_id_frame_past_the_limit_is_a_connection_error() {
    use probe::PacketStep::{InstallOneRttKeys, Receive};
    reset();
    let first = link();
    feed_packets([
        (
            ms(5),
            Receive(received(
                initial_from(&[0xaa; 8], 0, &ping()),
                &first,
                ms(5),
            )),
        ),
        (ms(6), InstallOneRttKeys),
        // the limit this side sends is 2, the default: the handshake
        // connection ID and one more
        (
            ms(7),
            Receive(received(
                one_rtt_packet_of(0, 0, &[new_connection_id(1), new_connection_id(2)].concat()),
                &first,
                ms(7),
            )),
        ),
    ]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first);
    take_log();
    let lines = run(&mut connection, 5..=7);
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(
        lines[1].starts_with("error: NewConnectionId { source: ActiveLimitExceeded"),
        "{lines:?}"
    );
}

#[test]
fn a_new_connection_id_frame_to_a_zero_length_handshake_connection_id_is_a_connection_error() {
    use probe::PacketStep::{InstallOneRttKeys, Receive};
    reset();
    let first = link();
    feed_packets([
        (
            ms(5),
            Receive(received(long_packet(INITIAL, 0, &ping()), &first, ms(5))),
        ),
        (ms(6), InstallOneRttKeys),
        (
            ms(7),
            Receive(received(
                one_rtt_packet_of(0, 0, &new_connection_id(1)),
                &first,
                ms(7),
            )),
        ),
    ]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first);
    take_log();
    let lines = run(&mut connection, 5..=7);
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(
        lines[1].starts_with("error: NewConnectionId { source: ZeroLengthInUse"),
        "{lines:?}"
    );
}

#[test]
fn a_path_challenge_is_answered_with_its_data_on_the_link_path_it_arrived_on() {
    use probe::PacketStep::{InstallHandshakeKeys, InstallOneRttKeys, Receive};
    reset();
    let first = link();
    let mut challenge = vec![0x1a];
    challenge.extend_from_slice(&[0x77; 8]);
    feed_packets([
        (ms(6), InstallHandshakeKeys),
        (ms(7), InstallOneRttKeys),
        (
            ms(9),
            Receive(received(one_rtt_packet_of(0, 0, &challenge), &first, ms(9))),
        ),
    ]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    deliver(client_initial(0), &first, ms(5));
    let _ = settle(&mut connection, 5..=8);
    common::take_sent();
    let log = settle(&mut connection, 9..=10);
    assert!(log.iter().all(|line| !line.starts_with("error")), "{log:?}");
    let response = [&[0x1b][..], &[0x77; 8][..]].concat();
    let answered: Vec<_> = common::take_sent()
        .into_iter()
        .filter(|(_, datagram)| datagram[0] & 0x80 == 0)
        .map(|(_, datagram)| (datagram.len(), open_sent_one_rtt(&datagram).2))
        .filter(|(_, payload)| payload.windows(response.len()).any(|w| w == response))
        .collect();
    assert_eq!(answered.len(), 1, "one PATH_RESPONSE with the data");
    // a datagram with a PATH_RESPONSE is expanded (RFC 9000 §8.2.2)
    assert!(answered[0].0 >= MIN_DATAGRAM_SIZE, "{}", answered[0].0);
}

#[test]
fn a_path_response_that_answers_no_challenge_is_ignored() {
    use probe::PacketStep::{InstallOneRttKeys, Receive};
    reset();
    let first = link();
    let mut response = vec![0x1b];
    response.extend_from_slice(&[9; 8]);
    feed_packets([
        (
            ms(5),
            Receive(received(
                initial_from(&[0xaa; 8], 0, &ping()),
                &first,
                ms(5),
            )),
        ),
        (ms(6), InstallOneRttKeys),
        (
            ms(7),
            Receive(received(one_rtt_packet_of(0, 0, &response), &first, ms(7))),
        ),
    ]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first);
    take_log();
    let lines = run(&mut connection, 5..=7);
    assert!(
        lines.iter().all(|line| !line.starts_with("error")),
        "{lines:?}"
    );
}

#[test]
fn retiring_a_connection_id_never_issued_is_a_connection_error() {
    use probe::PacketStep::{InstallOneRttKeys, Receive};
    reset();
    let first = link();
    feed_packets([
        (
            ms(5),
            Receive(received(
                initial_from(&[0xaa; 8], 0, &ping()),
                &first,
                ms(5),
            )),
        ),
        (ms(6), InstallOneRttKeys),
        // a RETIRE_CONNECTION_ID frame (RFC 9000 §19.16) of sequence
        // number 5: the server issued none but its first, numbered 0
        (
            ms(7),
            Receive(received(one_rtt_packet_of(0, 0, &[0x19, 5]), &first, ms(7))),
        ),
    ]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first);
    take_log();
    let lines = run(&mut connection, 5..=7);
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(
        lines[1], "error: RetireConnectionId { source: NotIssued { sequence: 5 } }",
        "{lines:?}"
    );
}

// ---- sending ----

/// An Initial packet a server sent, opened with the keys the client opens
/// it with.
#[derive(Debug)]
struct SentInitial {
    dcid: Vec<u8>,
    scid: Vec<u8>,
    number: u64,
    payload: Vec<u8>,
    /// The length of the packet in its datagram.
    len: usize,
}

/// A variable-length integer at the start of `bytes` (RFC 9000 §16), and
/// its width.
fn read_var_int(bytes: &[u8]) -> (usize, usize) {
    let width = 1 << (bytes[0] >> 6);
    let value = bytes[1..width]
        .iter()
        .fold(u64::from(bytes[0] & 0x3f), |value, byte| {
            (value << 8) | u64::from(*byte)
        });
    (usize::try_from(value).unwrap(), width)
}

/// The first packet of `datagram`, an Initial packet of the server without
/// a token, opened.
fn open_sent_initial(datagram: &[u8]) -> SentInitial {
    open_initial(datagram, &server_keys())
}

/// The first packet of `datagram`, an Initial packet without a token
/// protected with `keys`, opened.
fn open_initial(datagram: &[u8], keys: &DirectionKeys<RingBackend>) -> SentInitial {
    assert_eq!(datagram[0] & 0xf0, 0xc0, "an Initial packet: {datagram:?}");
    let mut at = 5;
    let dcid_len = usize::from(datagram[at]);
    let dcid = datagram[at + 1..at + 1 + dcid_len].to_vec();
    at += 1 + dcid_len;
    let scid_len = usize::from(datagram[at]);
    let scid = datagram[at + 1..at + 1 + scid_len].to_vec();
    at += 1 + scid_len;
    assert_eq!(datagram[at], 0, "an empty token");
    at += 1;
    let (length, width) = read_var_int(&datagram[at..]);
    let pn_offset = at + width;
    let len = pn_offset + length;
    let mut packet = datagram[..len].to_vec();
    let truncated = keys.header.remove(&mut packet, pn_offset).unwrap();
    let header_len = pn_offset + truncated.encoded_len().get();
    let number = truncated.decode(None);
    let payload = keys
        .packet
        .open(number, &mut packet, header_len)
        .unwrap()
        .to_vec();
    SentInitial {
        dcid,
        scid,
        number: number.get(),
        payload,
        len,
    }
}

/// Whether `datagram` starts with a packet with a short header: a 1-RTT
/// packet.
fn short_header(datagram: &[u8]) -> bool {
    datagram[0] & 0x80 == 0
}

/// The Source Connection ID of the client's Initial packets in the tests
/// of sending.
const CLIENT_SCID: [u8; 8] = [0xc5; 8];

#[test]
fn a_server_answers_the_first_initial_packet_with_an_ack_in_an_initial_packet() {
    reset();
    let first = link();
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first.clone());
    let datagram = padded(
        &[],
        |payload| initial_from(&CLIENT_SCID, 0, payload),
        &ping(),
    );
    let size = datagram.len();
    deliver(datagram, &first, ms(5));
    let _ = run(&mut connection, 5..=6);
    let sent = common::take_sent();
    assert_eq!(sent.len(), 1, "{sent:?}");
    let (_, datagram) = &sent[0];
    let packet = open_sent_initial(datagram);
    // to the client's Source Connection ID, from this side's first one
    assert_eq!(packet.dcid, CLIENT_SCID);
    assert_eq!(packet.scid, SERVER_CID);
    assert_eq!(packet.number, 0);
    // an ACK frame of the packet 0, sent at the instant it arrived: no
    // ACK Delay, and no more ranges
    assert_eq!(packet.payload, [0x02, 0x00, 0x00, 0x00, 0x00]);
    // the datagram's one packet elicits no acknowledgment: it is not padded,
    // and well within three times what arrived; it is its header, its tag
    // and the ACK frame, long enough for the header protection sample
    assert_eq!(packet.len, datagram.len());
    assert_eq!(datagram.len(), 1 + 4 + 1 + 8 + 1 + 8 + 1 + 2 + 1 + 16 + 5);
    assert!(datagram.len() < MIN_DATAGRAM_SIZE);
    assert!(datagram.len() <= 2 * size);
}

#[test]
fn crypto_data_written_is_gathered_and_sent_in_an_initial_packet() {
    reset();
    let first = link();
    CRYPTO_WRITE_AT.with(|c| c.set(Some(ms(4))));
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first.clone());
    take_strategy_events();
    // nothing goes before the client's Initial packet gives the server a
    // connection ID to send to and credit to send with: the data does not
    // fit, and the sending call is not woken for it
    let _ = settle(&mut connection, 4..=4);
    assert_eq!(strategy_events("path 0: content"), Vec::<String>::new());
    assert_eq!(common::take_sent(), []);
    deliver(client_initial(0), &first, ms(5));
    let _ = settle(&mut connection, 5..=6);
    let events = take_strategy_events();
    assert!(
        events
            .iter()
            .any(|event| event == "path 0: content CryptoIntent { level: Initial, shortest: 4 }"),
        "{events:?}"
    );
    let sent = common::take_sent();
    assert_eq!(sent.len(), 1, "{sent:?}");
    let packet = open_sent_initial(&sent[0].1);
    let crypto: Vec<_> = frames_of(&packet.payload)
        .into_iter()
        .filter_map(|run| match run {
            sakuya_wire_v1::frame::FrameRun::Crypto(frame) => {
                Some((frame.offset().get().get(), frame.data().to_vec()))
            }
            _ => None,
        })
        .collect();
    assert_eq!(crypto, [(0, b"server hello".to_vec())]);
}

/// Content of the probe's part, `id`, of `len` PING frames.
fn filler(id: u8, len: usize, holds_place: bool, writes: bool) -> probe::FillerIntent {
    probe::FillerIntent {
        id,
        len,
        length_field: 0,
        holds_place,
        writes,
    }
}

/// What a server sends once a client's Initial packet arrives, with
/// `fillers` to send besides its ACK: the number of PING frames of each
/// datagram, and what the fillers' frame source logged, in order.
fn sent_with_fillers(fillers: &[probe::FillerIntent]) -> (Vec<usize>, Vec<String>) {
    reset();
    FILLERS.with(|f| f.borrow_mut().extend_from_slice(fillers));
    let first = link();
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    deliver(
        padded(
            &[],
            |payload| initial_from(&CLIENT_SCID, 0, payload),
            &ping(),
        ),
        &first,
        ms(5),
    );
    let log = settle(&mut connection, 5..=6);
    let pings = common::take_sent()
        .iter()
        .map(|(_, datagram)| {
            open_sent_initial(datagram)
                .payload
                .iter()
                .filter(|byte| **byte == 0x01)
                .count()
        })
        .collect();
    (pings, lines_of(log, &["filler"]))
}

#[test]
fn content_that_holds_its_place_and_does_not_fit_ends_the_datagram() {
    // after the ACK and the first, the second does not fit what is left:
    // the third, which would, goes after it in the next datagram
    let (pings, log) = sent_with_fillers(&[
        filler(1, 400, true, true),
        filler(2, 900, true, true),
        filler(3, 100, true, true),
    ]);
    assert_eq!(pings, [400, 1000]);
    assert_eq!(log, ["filler 1 wrote", "filler 2 wrote", "filler 3 wrote"]);
}

#[test]
fn content_that_does_not_hold_its_place_and_does_not_fit_is_passed_over() {
    // the second is not given to its source; the third goes where it would
    // have, and the second in the next datagram
    let (pings, log) = sent_with_fillers(&[
        filler(1, 400, false, true),
        filler(2, 900, false, true),
        filler(3, 100, false, true),
    ]);
    assert_eq!(pings, [500, 900]);
    assert_eq!(log, ["filler 1 wrote", "filler 3 wrote", "filler 2 wrote"]);
}

#[test]
fn content_that_holds_its_place_and_writes_nothing_ends_the_datagram() {
    let (pings, log) = sent_with_fillers(&[
        filler(1, 400, true, true),
        filler(2, 10, true, false),
        filler(3, 100, true, true),
    ]);
    assert_eq!(pings, [400, 100]);
    assert_eq!(
        log,
        ["filler 1 wrote", "filler 2 wrote nothing", "filler 3 wrote"]
    );
}

#[test]
fn content_that_does_not_hold_its_place_and_writes_nothing_is_passed_over() {
    let (pings, log) = sent_with_fillers(&[
        filler(1, 400, false, true),
        filler(2, 10, false, false),
        filler(3, 100, false, true),
    ]);
    assert_eq!(pings, [500]);
    assert_eq!(
        log,
        ["filler 1 wrote", "filler 2 wrote nothing", "filler 3 wrote"]
    );
}

/// Content of the probe's part, `id`, of `len` PING frames, which takes
/// `length_field` bytes more of room unless it is in the last position.
fn filler_with_length_field(
    id: u8,
    len: usize,
    length_field: usize,
    holds_place: bool,
    writes: bool,
) -> probe::FillerIntent {
    probe::FillerIntent {
        length_field,
        ..filler(id, len, holds_place, writes)
    }
}

#[test]
fn content_that_does_not_hold_its_place_and_writes_nothing_in_the_last_position_lets_the_next_try_it()
 {
    // 752 bytes are left after the first: the second, which needs 800 with
    // a Length field and 700 as the last, takes the last position, writes
    // nothing and does not hold its place; the third then tries the last
    // position, and writes
    let (pings, log) = sent_with_fillers(&[
        filler(1, 400, false, true),
        filler_with_length_field(2, 700, 100, false, false),
        filler(3, 100, false, true),
    ]);
    assert_eq!(pings, [500]);
    assert_eq!(
        log,
        ["filler 1 wrote", "filler 2 wrote nothing", "filler 3 wrote"]
    );
}

#[test]
fn content_that_holds_its_place_and_writes_nothing_in_the_last_position_ends_the_datagram() {
    // as above, but the second holds its place: the datagram ends with the
    // first, and the third goes after the second in the next
    let (pings, log) = sent_with_fillers(&[
        filler(1, 400, false, true),
        filler_with_length_field(2, 700, 100, true, false),
        filler(3, 100, false, true),
    ]);
    assert_eq!(pings, [400, 100]);
    assert_eq!(
        log,
        ["filler 1 wrote", "filler 2 wrote nothing", "filler 3 wrote"]
    );
}

/// The frames of the packet payload `payload`, read as the receiving side
/// reads them.
fn frames_of(payload: &[u8]) -> Vec<sakuya_wire_v1::frame::FrameRun<&[u8]>> {
    sakuya_wire_v1::frame::set::Frames::new(
        payload,
        core::marker::PhantomData::<HList![sakuya_wire_v1::Part]>,
    )
    .map(|run| run.unwrap().extract())
    .collect()
}

/// The ACK frame the packet payload `payload` starts with.
fn ack_frame_of(payload: &[u8]) -> sakuya_wire_v1::frame::ack::AckFrame {
    match frames_of(payload).into_iter().next() {
        Some(sakuya_wire_v1::frame::FrameRun::Ack(frame)) => frame,
        other => panic!("not an ACK frame: {other:?}"),
    }
}

#[test]
fn the_ack_delay_of_a_handshake_packet_counts_the_wait_for_its_keys() {
    use probe::PacketStep::InstallHandshakeKeys;
    reset();
    let first = link();
    feed_packets([(ms(8), InstallHandshakeKeys)]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first.clone());
    deliver(client_initial(0), &first, ms(5));
    let _ = settle(&mut connection, 5..=5);
    assert_eq!(
        common::take_sent().len(),
        1,
        "the ACK of the Initial packet"
    );
    // the Handshake packet arrives at 6 ms and waits for its keys until 8
    deliver(client_long_packet(HANDSHAKE, 0, &ping()), &first, ms(6));
    let _ = settle(&mut connection, 6..=9);
    let sent = common::take_sent();
    assert_eq!(sent.len(), 1, "{sent:?}");
    let (at, datagram) = &sent[0];
    assert_eq!(*at, ms(8));
    // the probe's Handshake keys seal with the server's Initial secret
    let (kind, packet) = open_long_sent(datagram, &server_keys());
    assert_eq!(kind, HANDSHAKE);
    let frame = ack_frame_of(&packet.payload);
    assert_eq!(frame.largest_acknowledged().get().get(), 0);
    // 2 ms from the arrival, 2000 µs at the default exponent 3
    assert_eq!(frame.ack_delay().get(), VarInt::from_u32(2000 >> 3));
}

#[test]
fn a_delayed_one_rtt_ack_reports_its_delay_and_the_ecn_counts() {
    use probe::PacketStep::{InstallOneRttKeys, Receive};
    reset();
    let first = link();
    let mut packet = received(one_rtt_packet_of(0, 0, &ping()), &first, ms(10));
    let (protected, arrival) = packet.into_parts();
    packet = ReceivedPacket::new(
        protected,
        ArrivalFacts::new(
            arrival.link().clone(),
            arrival.at(),
            Some(sakuya_link::EcnCodepoint::Ect0),
        ),
    );
    feed_packets([
        (ms(4), InstallOneRttKeys),
        (
            ms(5),
            Receive(received(
                initial_from(&CLIENT_SCID, 0, &ping()),
                &first,
                ms(5),
            )),
        ),
        (ms(10), Receive(packet)),
    ]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    let _ = run(&mut connection, 4..=6);
    assert_eq!(
        common::take_sent().len(),
        1,
        "the ACK of the Initial packet"
    );
    // one ack-eliciting packet waits for the maximum ACK delay, 25 ms less
    // the timer granularity of 1 ms
    let _ = settle(&mut connection, 10..=33);
    assert_eq!(common::take_sent(), []);
    let _ = settle(&mut connection, 34..=34);
    let sent = common::take_sent();
    assert_eq!(sent.len(), 1, "{sent:?}");
    let (_, datagram) = &sent[0];
    let (_, number, payload) = open_sent_one_rtt(datagram);
    assert_eq!(number, 0);
    let frame = ack_frame_of(&payload);
    assert_eq!(frame.largest_acknowledged().get().get(), 0);
    // 24 ms from the arrival, 24000 µs at the default exponent 3
    assert_eq!(frame.ack_delay().get(), VarInt::from_u32(24_000 >> 3));
    // the packet arrived marked ECT(0) (RFC 9000 §13.4.1)
    let counts = frame.ecn_counts().expect("ECN counts");
    assert_eq!(
        (counts.ect0.get(), counts.ect1.get(), counts.ce.get()),
        (VarInt::from_u32(1), VarInt::ZERO, VarInt::ZERO)
    );
}

#[test]
fn a_probe_goes_past_a_full_congestion_window_on_a_permit() {
    use probe::Step;
    reset();
    let first = link();
    // ten 1200-byte packets fill the initial window of 12000 bytes
    feed([
        (
            ms(6),
            Step::Sent {
                space: PacketNumberSpaceKind::Initial,
                count: 10,
            },
        ),
        (ms(7), Step::Inspect),
    ]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    deliver(client_initial(0), &first, ms(5));
    let _ = run(&mut connection, 5..=6);
    assert_eq!(common::take_sent().len(), 1, "the ACK");
    let log = run(&mut connection, 7..=7);
    assert!(
        log.iter()
            .any(|line| line.contains("window 12000") && line.contains("in flight 12000")),
        "{log:?}"
    );
    // the probe timeout from the packets sent at 6 ms grants permits: its
    // PING goes in an Initial packet padded to 1200 bytes, past the window
    // (RFC 9002 §7.5)
    let _ = run(&mut connection, 8..=1004);
    assert_eq!(common::take_sent(), []);
    let _ = run(&mut connection, 1005..=1006);
    // the expiry permits two probe datagrams, each with a PING: both go
    // past the window
    let sent = common::take_sent();
    assert_eq!(sent.len(), 2, "{sent:?}");
    for (_, datagram) in &sent {
        assert_eq!(datagram.len(), MIN_DATAGRAM_SIZE);
        let packet = open_sent_initial(datagram);
        assert_eq!(packet.payload[0], 0x01, "a PING");
    }
}

#[test]
fn the_controller_hears_of_the_size_in_use_at_the_first_datagram_and_not_again_while_it_stays() {
    reset();
    let first = link();
    feed([(
        ms(6),
        probe::Step::Sent {
            space: PacketNumberSpaceKind::Initial,
            count: 1,
        },
    )]);
    let mut connection = connection!(SpyMine, AddressValidation::NotValidated, first.clone());
    deliver(
        padded(
            &[],
            |payload| initial_from(&CLIENT_SCID, 0, payload),
            &ping(),
        ),
        &first,
        ms(5),
    );
    take_log();
    let mut log = run(&mut connection, 5..=6);
    assert_eq!(common::take_sent().len(), 1, "the ACK");
    // the probe timeout's PING is the second datagram
    log.extend(run(&mut connection, 1005..=1006));
    assert_eq!(common::take_sent().len(), 1, "the probe");
    let told = lines_of(log, &["size in use"]);
    assert_eq!(told, ["size in use 1200, handshake confirmed false"]);
}

#[test]
fn a_probe_timeout_sends_a_ping_padded_to_1200_bytes_as_the_credit_allows() {
    reset();
    let first = link();
    feed([(
        ms(6),
        probe::Step::Sent {
            space: PacketNumberSpaceKind::Initial,
            count: 1,
        },
    )]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first.clone());
    deliver(
        padded(
            &[],
            |payload| initial_from(&CLIENT_SCID, 0, payload),
            &ping(),
        ),
        &first,
        ms(5),
    );
    let _ = run(&mut connection, 5..=6);
    assert_eq!(common::take_sent().len(), 1, "the ACK");
    // 333 ms + 4 × 166.5 ms from the packet sent at 6 ms
    let _ = run(&mut connection, 1004..=1004);
    assert_eq!(common::take_sent(), []);
    let _ = run(&mut connection, 1005..=1006);
    let sent = common::take_sent();
    assert_eq!(sent.len(), 1, "{sent:?}");
    let (_, datagram) = &sent[0];
    assert_eq!(datagram.len(), MIN_DATAGRAM_SIZE);
    let packet = open_sent_initial(datagram);
    // after the ACK and the packet sent at 6 ms
    assert_eq!(packet.number, 2);
    assert_eq!(packet.payload[0], 0x01, "a PING");
    assert!(packet.payload[1..].iter().all(|byte| *byte == 0), "PADDING");
    // 2400 bytes may go back for the 1200 that arrived; less the ACK and
    // the probe, the next probe does not fit
    let outer = Outer::new();
    for at in (1010..6000).step_by(10) {
        advance_to(ms(at));
        assert!(outer.poll(&mut connection).is_pending());
    }
    assert_eq!(
        common::take_sent(),
        [],
        "held by the anti-amplification limit"
    );
    // held, the call does not wake itself: polls at one instant end with
    // no wake
    let wakes = outer.wakes();
    for _ in 0..3 {
        assert!(outer.poll(&mut connection).is_pending());
    }
    assert_eq!(outer.wakes(), wakes);
    // the client's next datagram lets it go, with the ACK of its packet
    deliver(
        padded(
            &[],
            |payload| initial_from(&CLIENT_SCID, 1, payload),
            &ping(),
        ),
        &first,
        ms(6000),
    );
    let _ = run(&mut connection, 6000..=6001);
    // the expiry's second PING, which the limit held back, goes now as well
    // as the ACK: two probe datagrams
    let sent = common::take_sent();
    assert_eq!(sent.len(), 2, "{sent:?}");
    for (_, datagram) in &sent {
        assert_eq!(datagram.len(), MIN_DATAGRAM_SIZE);
    }
    let packet = open_sent_initial(&sent[0].1);
    // sent at 6001 ms, 1 ms after the packet 1 arrived: an ACK Delay of
    // 1000 µs at the default exponent 3, 125
    assert_eq!(
        packet.payload[..7],
        [0x02, 0x01, 0x40, 0x7d, 0x00, 0x01, 0x01]
    );
    let packet = open_sent_initial(&sent[1].1);
    assert_eq!(packet.payload[0], 0x01, "the held PING");
}

/// A server whose link path has, once polled at 1005 ms, three datagrams to
/// send in one batch: the ACK of two 1-RTT packets in a 1-RTT packet, and
/// the probe timeout's two PINGs (it permits two probe datagrams), each
/// padded in an Initial packet of its own, which is of a lower level and
/// goes after it. Before, it sent the ACK of the client's
/// Initial packet, which is taken.
fn with_the_ack_and_two_probes_at_1005_ms(
    first: &LinkId<(), ()>,
    later: impl IntoIterator<Item = (Duration, probe::PacketStep)>,
) -> impl Future<Output = ()> + Unpin {
    use probe::PacketStep::{InstallOneRttKeys, Receive};
    feed([(
        ms(6),
        probe::Step::Sent {
            space: PacketNumberSpaceKind::Initial,
            count: 1,
        },
    )]);
    feed_packets([
        (ms(4), InstallOneRttKeys),
        (
            ms(5),
            Receive(received(
                initial_from(&CLIENT_SCID, 0, &ping()),
                first,
                ms(5),
            )),
        ),
        // one ack-eliciting packet waits for the maximum ACK delay, a second
        // is acknowledged at once
        (
            ms(1004),
            Receive(received(one_rtt_packet_of(0, 0, &ping()), first, ms(1004))),
        ),
        (
            ms(1005),
            Receive(received(one_rtt_packet_of(0, 1, &ping()), first, ms(1005))),
        ),
    ]);
    feed_packets(later);
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    let _ = run(&mut connection, 4..=6);
    assert_eq!(
        common::take_sent().len(),
        1,
        "the ACK of the Initial packet"
    );
    assert_eq!(common::take_batch_sizes(), [1]);
    let _ = run(&mut connection, 1004..=1004);
    assert_eq!(common::take_sent(), []);
    connection
}

#[test]
fn the_link_accepts_a_prefix_and_the_rest_is_handed_over_again_with_its_send_time() {
    reset();
    let first = link();
    let mut connection = with_the_ack_and_two_probes_at_1005_ms(&first, []);
    common::plan_sends([
        common::SendOutcome::Accept(1),
        common::SendOutcome::Hold(usize::MAX),
    ]);
    let _ = run(&mut connection, 1005..=1006);
    // the ACK accepted; the two PINGs (the expiry's two probe datagrams)
    // handed over again, together
    assert_eq!(common::take_batch_sizes(), [3, 2]);
    let sent = common::take_sent();
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert!(short_header(&sent[0].1));
    // accepted later, at 1100 ms
    advance_to(ms(1100));
    common::release_held_send();
    let _ = run(&mut connection, 1100..=1100);
    let sent = common::take_sent();
    assert_eq!(sent.len(), 2, "{sent:?}");
    for (at, datagram) in &sent {
        assert_eq!(*at, ms(1100));
        assert_eq!(open_sent_initial(datagram).payload[0], 0x01);
    }
    // the next probe timeout counts from when the PINGs were accepted, with
    // the backoff doubled: 1100 ms + 2 × 999 ms
    let log = run(&mut connection, 1101..=3097);
    assert_eq!(lines_of(log, &["in flight"]), Vec::<String>::new());
    let log = run(&mut connection, 3098..=3098);
    let lines = lines_of(log, &["in flight"]);
    assert!(
        lines.last().is_some_and(|line| line.ends_with("backoff 2")),
        "{lines:?}"
    );
}

#[test]
fn a_datagram_the_link_gives_up_is_handed_back_as_lost_and_the_rest_is_sent() {
    reset();
    let first = link();
    let mut connection = with_the_ack_and_two_probes_at_1005_ms(&first, []);
    common::plan_sends([common::SendOutcome::GiveUp, common::SendOutcome::GiveUp]);
    let log = run(&mut connection, 1005..=1006);
    // the first given up; the rest (the expiry's two PING datagrams) handed
    // over again, with the ACK the loss owes again gathered into a datagram
    // after them, and the first of them given up too; then the second PING
    // and the ACK, accepted
    assert_eq!(common::take_batch_sizes(), [3, 3, 2]);
    let given_up = common::take_given_up();
    assert_eq!(given_up.len(), 2);
    assert!(short_header(&given_up[0]), "the 1-RTT ACK");
    assert_eq!(open_sent_initial(&given_up[1]).payload[0], 0x01, "the PING");
    let sent = common::take_sent();
    assert_eq!(sent.len(), 2, "{sent:?}");
    assert_eq!(
        open_sent_initial(&sent[0].1).payload[0],
        0x01,
        "the 2nd PING"
    );
    assert!(short_header(&sent[1].1), "the 1-RTT ACK again");
    // the first PING left the bytes in flight, and was never accepted: the
    // packet sent at 6 ms is there, and the second PING, which was
    // accepted; the ACK sent again counts nothing in flight
    let lines = lines_of(log, &["in flight"]);
    assert!(
        lines
            .last()
            .is_some_and(|line| line.starts_with("in flight 2400, outstanding 4,")),
        "{lines:?}"
    );
}

#[test]
fn a_batch_holds_at_most_its_limit_of_datagrams() {
    reset();
    MAX_PER_SEND.with(|m| m.set(1));
    let first = link();
    let mut connection = with_the_ack_and_two_probes_at_1005_ms(&first, []);
    let _ = run(&mut connection, 1005..=1006);
    // the ACK and the expiry's two PING datagrams, one to a batch
    assert_eq!(common::take_batch_sizes(), [1, 1, 1]);
    let sent = common::take_sent();
    assert_eq!(sent.len(), 3, "{sent:?}");
    assert!(short_header(&sent[0].1));
    assert_eq!(open_sent_initial(&sent[1].1).payload[0], 0x01);
    assert_eq!(open_sent_initial(&sent[2].1).payload[0], 0x01);
}

/// The bytes in flight of the last line of the recovery layer's feeder in
/// `log`.
fn last_in_flight(log: Vec<String>) -> usize {
    let lines = lines_of(log, &["in flight"]);
    let line = lines.last().expect("the feeder logged");
    line["in flight ".len()..]
        .split(',')
        .next()
        .and_then(|bytes| bytes.parse().ok())
        .unwrap_or_else(|| panic!("{line}"))
}

#[test]
fn a_datagram_of_a_level_whose_keys_went_is_not_handed_over() {
    use probe::PacketStep::{InstallHandshakeKeys, Receive, TakeRecords};
    reset();
    let first = link();
    let mut connection = with_the_ack_and_two_probes_at_1005_ms(
        &first,
        [
            (ms(1049), InstallHandshakeKeys),
            (
                ms(1050),
                Receive(received(
                    client_long_packet(HANDSHAKE, 0, &ping()),
                    &first,
                    ms(1050),
                )),
            ),
            (ms(1062), TakeRecords(PacketNumberSpaceKind::Initial)),
        ],
    );
    common::plan_sends([common::SendOutcome::Hold(1)]);
    let log = run(&mut connection, 1005..=1006);
    // the ACK and the expiry's two PING datagrams
    assert_eq!(common::take_batch_sizes(), [3]);
    let sealed = last_in_flight(log);
    // the Initial keys go with the first Handshake packet processed, while
    // the link keeps the batch
    let _ = run(&mut connection, 1049..=1050);
    advance_to(ms(1060));
    common::release_held_send();
    let log = run(&mut connection, 1060..=1061);
    let sent = common::take_sent();
    assert!(short_header(&sent[0].1), "the 1-RTT ACK accepted");
    // the PINGs' datagrams are left out of the next batch; what follows has
    // no Initial packet
    assert!(
        sent[1..]
            .iter()
            .all(|(_, datagram)| datagram[0] & 0xf0 != 0xc0),
        "{sent:?}"
    );
    assert_eq!(common::take_given_up(), [] as [bytes::Bytes; 0]);
    // the Initial space retired with the keys: the Initial packet accepted
    // before left the bytes in flight then, and the two PINGs, which the
    // space's records no longer have, leave them when they are left out
    assert_eq!(sealed - last_in_flight(log), 3 * MIN_DATAGRAM_SIZE);
    let log = run(&mut connection, 1062..=1062);
    assert_eq!(lines_of(log, &["records"]), [] as [String; 0]);
}

#[test]
fn an_ack_frame_the_link_gives_up_at_once_is_planned_again() {
    reset();
    let first = link();
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first.clone());
    take_strategy_events();
    deliver(
        padded(
            &[],
            |payload| initial_from(&CLIENT_SCID, 0, payload),
            &ping(),
        ),
        &first,
        ms(5),
    );
    common::plan_sends([common::SendOutcome::GiveUp]);
    let _ = run(&mut connection, 5..=6);
    // written and given up in one lend: the ACK frame took the
    // acknowledgment off what is due, and its loss owes the frame again,
    // which the next datagram of the same lend gathers
    let given_up = common::take_given_up();
    assert_eq!(given_up.len(), 1);
    assert_eq!(open_sent_initial(&given_up[0]).payload[0], 0x02);
    assert_eq!(
        strategy_events("path 0: "),
        [
            "path 0: content AckIntent { space: Initial, shortest: 5, piggyback: false }",
            "path 0: gone AckIntent { space: Initial, shortest: 5, piggyback: false }",
            "path 0: content AckIntent { space: Initial, shortest: 5, piggyback: false }",
            "path 0: gone AckIntent { space: Initial, shortest: 5, piggyback: false }",
        ]
    );
    let sent = common::take_sent();
    assert_eq!(sent.len(), 1, "{sent:?}");
    let packet = open_sent_initial(&sent[0].1);
    assert_eq!(packet.number, 1);
    // sent again at 5 ms, the instant the packet 0 arrived: no ACK Delay
    assert_eq!(sent[0].0, ms(5));
    assert_eq!(packet.payload, [0x02, 0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn a_client_sends_the_initial_packets_it_sealed_before_its_first_handshake_packet() {
    use probe::PacketStep::{
        HandshakeConnectionId, InstallHandshakeKeys, InstallOneRttKeys, Receive,
    };
    reset();
    let first = link();
    feed([(
        ms(6),
        probe::Step::Sent {
            space: PacketNumberSpaceKind::Initial,
            count: 1,
        },
    )]);
    feed_packets([
        (ms(3), HandshakeConnectionId(server_cid())),
        (ms(4), InstallOneRttKeys),
        (
            ms(1004),
            Receive(received(one_rtt_packet_of(0, 0, &ping()), &first, ms(1004))),
        ),
        (
            ms(1005),
            Receive(received(one_rtt_packet_of(0, 1, &ping()), &first, ms(1005))),
        ),
        (ms(1049), InstallHandshakeKeys),
        (
            ms(1050),
            Receive(received(
                long_packet(HANDSHAKE, 0, &ping()),
                &first,
                ms(1050),
            )),
        ),
        (
            ms(1051),
            Receive(received(
                long_packet_with(first_byte(INITIAL), &[], &server_keys(), 0, &ping()),
                &first,
                ms(1051),
            )),
        ),
    ]);
    let mut connection = connection!(ClientMine, AddressValidation::Validated, first.clone());
    let _ = run(&mut connection, 3..=1004);
    assert_eq!(common::take_sent(), []);
    // the ACK of two 1-RTT packets, and the probe timeout's PING in an
    // Initial packet of a lower level, in a datagram of its own
    common::plan_sends([common::SendOutcome::Hold(1)]);
    let _ = run(&mut connection, 1005..=1006);
    // the ACK and the expiry's two PING datagrams
    assert_eq!(common::take_batch_sizes(), [3]);
    // while the link keeps them, an Initial and a Handshake packet arrive;
    // a client keeps its Initial keys until it sends a Handshake packet
    let _ = run(&mut connection, 1049..=1051);
    advance_to(ms(1060));
    common::release_held_send();
    let _ = run(&mut connection, 1060..=1061);
    // the two PING datagrams wait with the next one: the ACKs of an Initial
    // and of a Handshake packet, coalesced; the first Handshake packet
    // discards the Initial keys, and all go out
    assert_eq!(common::take_batch_sizes(), [3]);
    assert_eq!(common::take_given_up(), [] as [bytes::Bytes; 0]);
    let sent = common::take_sent();
    assert_eq!(sent.len(), 4, "{sent:?}");
    assert!(short_header(&sent[0].1), "the 1-RTT ACK");
    for (_, ping_datagram) in &sent[1..3] {
        assert_eq!(ping_datagram.len(), MIN_DATAGRAM_SIZE);
        let packet = open_initial(ping_datagram, &client_keys());
        assert_eq!(packet.dcid, SERVER_CID);
        assert_eq!(packet.payload[0], 0x01, "the PING");
    }
    let coalesced = &sent[3].1;
    assert_eq!(coalesced.len(), MIN_DATAGRAM_SIZE);
    let packet = open_initial(coalesced, &client_keys());
    assert_eq!(packet.payload[0], 0x02, "the Initial ACK");
    assert_eq!(
        coalesced[packet.len] & 0xf0,
        0xe0,
        "a Handshake packet after it"
    );
    // no Initial packet after: the probe timeouts that come find no keys
    let _ = run(&mut connection, 1062..=8000);
    let sent = common::take_sent();
    assert!(
        sent.iter().all(|(_, datagram)| datagram[0] & 0xf0 != 0xc0),
        "{sent:?}"
    );
}

#[test]
fn a_send_the_link_holds_wakes_the_connection_when_it_is_released() {
    reset();
    let first = link();
    let mut connection = with_the_ack_and_two_probes_at_1005_ms(&first, []);
    common::plan_sends([common::SendOutcome::Hold(usize::MAX)]);
    let outer = Outer::new();
    advance_to(ms(1005));
    for _ in 0..3 {
        assert!(outer.poll(&mut connection).is_pending());
    }
    // the ACK and the expiry's two PING datagrams
    assert_eq!(common::take_batch_sizes(), [3]);
    // nothing is left to do but wait for the link
    let wakes = outer.wakes();
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(outer.wakes(), wakes);
    common::release_held_send();
    assert_eq!(outer.wakes(), wakes + 1);
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(common::take_sent().len(), 3);
}

#[test]
fn a_plan_blocked_once_wakes_the_call_once() {
    reset();
    let first = link();
    // the Initial keys go right after the probe timeout of the Initial
    // space published its PING
    feed([
        (
            ms(6),
            probe::Step::Sent {
                space: PacketNumberSpaceKind::Initial,
                count: 1,
            },
        ),
        (
            ms(1005),
            probe::Step::Discard(PacketNumberSpaceKind::Initial),
        ),
    ]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    deliver(
        padded(
            &[],
            |payload| initial_from(&CLIENT_SCID, 0, payload),
            &ping(),
        ),
        &first,
        ms(5),
    );
    let _ = run(&mut connection, 5..=1004);
    assert_eq!(common::take_sent().len(), 1, "the ACK");
    // the probe timeout publishes the PING, and the keys go
    let outer = Outer::new();
    advance_to(ms(1005));
    assert!(outer.poll(&mut connection).is_pending());
    // A planner that has not heard of it plans the PING in an Initial
    // packet: the call stops, wakes itself once for what it published to
    // be handled, and then waits.
    common::strategy::tell_stale_initial_overhead(50);
    let mut wakes = Vec::new();
    for _ in 0..3 {
        let before = outer.wakes();
        assert!(outer.poll(&mut connection).is_pending());
        wakes.push(outer.wakes() - before);
    }
    assert_eq!(wakes, [1, 0, 0]);
    assert_eq!(common::take_sent(), []);
}

#[test]
fn a_plan_blocked_again_waits_until_the_planner_is_told_something_new() {
    use probe::PacketStep::InstallOneRttSendKeys;
    reset();
    let first = link();
    // the Initial keys go right after the probe timeout of the Initial
    // space published its PING
    feed([
        (
            ms(6),
            probe::Step::Sent {
                space: PacketNumberSpaceKind::Initial,
                count: 1,
            },
        ),
        (
            ms(1005),
            probe::Step::Discard(PacketNumberSpaceKind::Initial),
        ),
    ]);
    feed_packets([(ms(1006), InstallOneRttSendKeys)]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    deliver(
        padded(
            &[],
            |payload| initial_from(&CLIENT_SCID, 0, payload),
            &ping(),
        ),
        &first,
        ms(5),
    );
    let _ = run(&mut connection, 5..=1004);
    assert_eq!(common::take_sent().len(), 1, "the ACK");
    // A planner that keeps planning the probe timeout's PING in an Initial
    // packet, with the Initial keys gone: the call wakes itself once, and
    // then waits instead of waking itself again and again.
    common::strategy::keep_telling_stale_initial_overhead(50);
    let outer = Outer::new();
    let mut wakes_at = |at: u64| {
        advance_to(ms(at));
        (0..8)
            .map(|_| {
                let before = outer.wakes();
                assert!(outer.poll(&mut connection).is_pending());
                outer.wakes() - before
            })
            .collect::<Vec<_>>()
    };
    // the first poll runs the probe timeout, which publishes the PING, and
    // discards the keys; the next plans it and is blocked
    assert_eq!(wakes_at(1005)[1..], [1, 0, 0, 0, 0, 0, 0]);
    // the 1-RTT keys to send with change what the planner is told: the
    // waiting call is woken, plans again, is blocked, wakes itself once
    // and waits
    let wakes = wakes_at(1006);
    assert_eq!(wakes[1..], [1, 0, 0, 0, 0, 0, 0], "{wakes:?}");
    assert_eq!(common::take_sent(), []);
}

#[test]
fn a_datagram_given_up_owes_its_ack_again_and_keeps_its_record() {
    use probe::PacketStep::TakeRecords;
    reset();
    let first = link();
    let mut connection = with_the_ack_and_two_probes_at_1005_ms(
        &first,
        [(
            ms(1010),
            TakeRecords(PacketNumberSpaceKind::ApplicationData),
        )],
    );
    take_strategy_events();
    common::plan_sends([common::SendOutcome::GiveUp, common::SendOutcome::Accept(1)]);
    let _ = run(&mut connection, 1005..=1007);
    // the 1-RTT ACK given up; the ACK is owed again and gathered into a
    // datagram after the two PINGs (the expiry's two probe datagrams),
    // handed over with them; the first PING accepted, then the second PING
    // and the ACK
    let given_up = common::take_given_up();
    assert_eq!(given_up.len(), 1);
    assert!(short_header(&given_up[0]));
    assert_eq!(common::take_batch_sizes(), [3, 3, 2]);
    let sent = common::take_sent();
    assert_eq!(sent.len(), 3, "{sent:?}");
    assert_eq!(open_sent_initial(&sent[0].1).payload[0], 0x01, "the PING");
    assert_eq!(open_sent_initial(&sent[1].1).payload[0], 0x01, "the PING");
    assert!(short_header(&sent[2].1), "the 1-RTT ACK again");
    assert_eq!(
        strategy_events("path 0: "),
        [
            "path 0: content AckIntent { space: ApplicationData, shortest: 5, piggyback: false }",
            "path 0: content ProbePingIntent { space: Initial }",
            "path 0: gone AckIntent { space: ApplicationData, shortest: 5, piggyback: false }",
            "path 0: gone ProbePingIntent { space: Initial }",
            "path 0: content AckIntent { space: ApplicationData, shortest: 5, piggyback: false }",
            "path 0: gone AckIntent { space: ApplicationData, shortest: 5, piggyback: false }",
        ]
    );
    // the given-up packet 0 is kept as one whose send result is unknown,
    // never accepted; the packet 1 that carried the ACK again was sent
    let log = run(&mut connection, 1008..=1010);
    let records = lines_of(log, &["records"]);
    assert_eq!(records.len(), 1, "{records:?}");
    assert!(
        records[0].starts_with("records ApplicationData: [(0, \"Lost { sent_at: None, "),
        "{records:?}"
    );
    assert!(records[0].contains("(1, \"Sent("), "{records:?}");
}

#[test]
fn a_probe_acknowledged_after_it_was_accepted_leaves_nothing_in_flight() {
    reset();
    let first = link();
    feed([(
        ms(6),
        probe::Step::Sent {
            space: PacketNumberSpaceKind::Initial,
            count: 1,
        },
    )]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    deliver(
        padded(
            &[],
            |payload| initial_from(&CLIENT_SCID, 0, payload),
            &ping(),
        ),
        &first,
        ms(5),
    );
    let _ = run(&mut connection, 5..=6);
    assert_eq!(common::take_sent().len(), 1, "the ACK");
    let log = run(&mut connection, 1005..=1006);
    // the expiry's two PING datagrams
    let sent = common::take_sent();
    assert_eq!(sent.len(), 2, "{sent:?}");
    assert_eq!(open_sent_initial(&sent[0].1).number, 2, "the PING");
    assert_eq!(open_sent_initial(&sent[1].1).number, 3, "the second PING");
    let lines = lines_of(log, &["in flight"]);
    assert!(
        lines
            .last()
            .is_some_and(|line| line.starts_with("in flight 3600,") && line.ends_with("backoff 1")),
        "{lines:?}"
    );
    // the client acknowledges the ACK, the packet sent at 6 ms and the PINGs
    deliver(
        padded(
            &[],
            |payload| initial_from(&CLIENT_SCID, 1, payload),
            &ack_of(&[(0, 3)], false),
        ),
        &first,
        ms(1100),
    );
    let log = run(&mut connection, 1100..=1101);
    let lines = lines_of(log, &["in flight"]);
    assert!(
        lines.last().is_some_and(
            |line| line.starts_with("in flight 0, outstanding 0, lost [],")
                && line.ends_with("backoff 0")
        ),
        "{lines:?}"
    );
}

#[test]
fn a_link_path_that_ends_while_the_link_holds_its_batch_hands_back_its_packets() {
    use probe::PacketStep::{Inspect, InspectOwed, TakeRecords};
    reset();
    CLOSE_AT.with(|c| c.set(Some(ms(1010))));
    let first = link();
    let mut connection = with_the_ack_and_two_probes_at_1005_ms(
        &first,
        [
            (ms(1007), Inspect),
            (ms(1008), InspectOwed),
            (ms(1498), InspectOwed),
            (ms(1499), Inspect),
            (ms(1500), TakeRecords(PacketNumberSpaceKind::Initial)),
            (
                ms(1501),
                TakeRecords(PacketNumberSpaceKind::ApplicationData),
            ),
        ],
    );
    common::plan_sends([common::SendOutcome::Hold(usize::MAX)]);
    let _ = run(&mut connection, 1005..=1006);
    // the ACK and the expiry's two PING datagrams
    assert_eq!(common::take_batch_sizes(), [3]);
    take_strategy_events();
    let log = run(&mut connection, 1007..=1499);
    assert!(
        log.iter().any(|line| line.starts_with("link path ended")),
        "{log:?}"
    );
    // the packet the probe recorded at 6 ms was among them, but a probe
    // timeout before handed its content back already, while it stayed in
    // flight: it is not handed back twice
    assert_eq!(lines_of(log.clone(), &["lost"]), Vec::<String>::new());
    // the packets of both datagrams left the send journals with the link
    // path, with those it sent before: the ACK frame of the Initial packet
    // sent at 6 ms is owed again, due now once the link path is gone. No
    // link path is left to gather what is owed.
    let inspected = lines_of(log.clone(), &["read"]);
    assert_eq!(inspected.len(), 2, "{inspected:?}");
    assert!(inspected[0].contains("due Some(NotDue)"), "{inspected:?}");
    assert!(inspected[1].contains("due Some(Now)"), "{inspected:?}");
    // so is the ACK frame of the 1-RTT packet in the batch, and the link
    // path's end gives back the connection ID only it used for the
    // retirement to be written again
    let owed = lines_of(log, &["owed"]);
    assert_eq!(
        owed,
        [
            // before the link path ends, at 1008 ms
            "owed retirements [], Application Data ACK Some(NotDue)",
            // after, at 1498 ms
            "owed retirements [RetireConnectionIdIntent { sequence: 0 }], \
             Application Data ACK Some(Now)",
        ],
        "{owed:?}"
    );
    assert_eq!(strategy_events("path 0: content"), Vec::<String>::new());
    common::release_held_send();
    let log = run(&mut connection, 1500..=1600);
    assert_eq!(
        lines_of(log, &["records"]),
        ["records Initial: []", "records ApplicationData: []"]
    );
    assert_eq!(common::take_batch_sizes(), [] as [usize; 0]);
    assert_eq!(common::take_sent(), []);
}

#[test]
fn the_planner_is_told_what_a_packet_takes_when_the_keys_of_its_level_come() {
    use probe::PacketStep::InstallHandshakeKeys;
    reset();
    let first = link();
    feed_packets([(ms(999), InstallHandshakeKeys)]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    deliver(
        padded(
            &[],
            |payload| initial_from(&CLIENT_SCID, 0, payload),
            &ping(),
        ),
        &first,
        ms(5),
    );
    let _ = run(&mut connection, 5..=998);
    let told = common::strategy::observed_overheads(0).expect("the planner was told");
    assert_eq!(told.handshake, None);
    // in the poll the keys come, before the sending call looks at the plan:
    // the first byte, the version, both connection IDs of 8 bytes with
    // their lengths, a Length field of two bytes, a packet number of one
    // byte and the three bytes the header protection sample needs after
    // it, and the tag
    let outer = Outer::new();
    advance_to(ms(999));
    assert!(outer.poll(&mut connection).is_pending());
    let told = common::strategy::observed_overheads(0).expect("the planner was told");
    assert_eq!(told.handshake, Some(1 + 4 + 1 + 8 + 1 + 8 + 2 + 1 + 3 + 16));
    assert_eq!(
        told.initial,
        told.handshake.map(|handshake| handshake + 1),
        "an Initial packet's empty token takes a byte more"
    );
}

/// The steps, by 8 ms, that give the logical path a connection ID of the
/// peer's with a reset token and use it on the link path over `first`: the
/// handshake connection ID, then the one of sequence 1, whose token is
/// [`RESET_TOKEN`].
fn reset_token_registered(first: &LinkId<(), ()>) -> [(Duration, probe::PacketStep); 4] {
    use probe::PacketStep::{InstallOneRttKeys, Receive, UseConnectionId};
    [
        (
            ms(5),
            Receive(received(initial_from(&[0xaa; 8], 0, &ping()), first, ms(5))),
        ),
        (ms(6), InstallOneRttKeys),
        (
            ms(7),
            Receive(received(
                one_rtt_packet_of(0, 0, &new_connection_id(1)),
                first,
                ms(7),
            )),
        ),
        (ms(8), UseConnectionId(first.clone(), 1)),
    ]
}

/// The reset token of the connection ID of sequence 1 that
/// [`new_connection_id`] gives.
const RESET_TOKEN: [u8; 16] = [0x81; 16];

/// A datagram that ends in `token`, as a stateless reset does (RFC 9000
/// §10.3): the first bits of a short header, then bits that look random,
/// then the token.
fn stateless_reset(token: [u8; 16]) -> BytesMut {
    let mut datagram = BytesMut::from(&[0x5c; 25][..]);
    datagram.extend_from_slice(&token);
    datagram
}

/// The current probe timeout of the tests' connections before any RTT
/// sample, with the default maximum ACK delay.
fn initial_probe_timeout() -> Duration {
    probe_timeout(
        &sakuya_recovery_v1::rtt::RttEstimate::initial(sakuya_recovery_v1::rtt::INITIAL_RTT),
        ms(1),
        PacketNumberSpaceKind::ApplicationData,
        ms(25),
        0,
    )
}

#[test]
fn a_stateless_reset_wakes_the_receiving_call_which_drains_the_link_paths() {
    use probe::PacketStep::Inspect;
    reset();
    let first = link();
    feed_packets(reset_token_registered(&first));
    feed_packets([(ms(12), Inspect)]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    take_log();
    assert_eq!(
        run(&mut connection, 5..=8),
        [
            "processed: highest numbered true, non-probing true",
            "processed: highest numbered true, non-probing false",
            "used 1",
        ]
    );
    take_strategy_events();
    let outer = Outer::new();
    advance_to(ms(10));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(take_log(), Vec::<String>::new());
    let wakes = outer.wakes();
    // routing detects the reset by its token before it routes the datagram
    deliver(stateless_reset(RESET_TOKEN), &first, ms(10));
    assert_eq!(
        outer.wakes(),
        wakes + 1,
        "the reset wakes the receiving call while it waits"
    );
    advance_to(ms(11));
    assert!(outer.poll(&mut connection).is_pending());
    let log = take_log();
    let draining = format!("Draining({:?}), ", ms(11) + initial_probe_timeout() * 3);
    assert!(
        log.iter().any(|line| line.starts_with(&draining)),
        "the link path drains for three probe timeouts: {log:?}"
    );
    assert!(log.contains(&"recovery ended".to_owned()), "{log:?}");
    assert_eq!(
        strategy_events("core: closed"),
        ["core: closed StatelessReset"]
    );
    let log = run(&mut connection, 12..=12);
    assert_eq!(log.len(), 1, "{log:?}");
    assert!(
        log[0].ends_with("reason Some(\"StatelessReset\")"),
        "{log:?}"
    );
}

#[test]
fn a_closing_connection_drains_on_a_stateless_reset_keeping_its_reason_and_end() {
    use probe::PacketStep::Inspect;
    reset();
    let first = link();
    feed_packets(reset_token_registered(&first));
    feed_packets([(ms(12), Inspect)]);
    CLOSER.with(|c| c.borrow_mut().push_back((ms(9), probe::CloserStep::Close)));
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    let end = ms(9) + initial_probe_timeout() * 3;
    take_log();
    let log = run(&mut connection, 5..=9);
    let closing = format!("Closing({end:?}), ");
    assert!(
        log.iter().any(|line| line.starts_with(&closing)),
        "the link path closes: {log:?}"
    );
    take_strategy_events();
    deliver(stateless_reset(RESET_TOKEN), &first, ms(10));
    let log = run(&mut connection, 11..=11);
    let draining = format!("Draining({end:?}), ");
    assert!(
        log.iter().any(|line| line.starts_with(&draining)),
        "the closing link path drains and keeps its end: {log:?}"
    );
    assert_eq!(strategy_events("core: closed"), Vec::<String>::new());
    let log = run(&mut connection, 12..=12);
    assert_eq!(log.len(), 1, "{log:?}");
    assert!(
        log[0].ends_with("reason Some(\"Local(Application(AppClose(7)))\")"),
        "the record keeps the reason written first: {log:?}"
    );
}

#[test]
fn a_stateless_reset_after_the_link_paths_drained_changes_nothing() {
    use probe::PacketStep::{Inspect, Receive};
    reset();
    let first = link();
    let close = [&[0x1c, 0x00, 0x00, 0x00][..], &[0; 20]].concat();
    feed_packets(reset_token_registered(&first));
    feed_packets([
        (
            ms(9),
            Receive(received(one_rtt_packet_of(0, 1, &close), &first, ms(9))),
        ),
        (ms(12), Inspect),
    ]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    take_log();
    let log = run(&mut connection, 5..=9);
    assert!(
        log.iter().any(|line| line.starts_with("Draining(")),
        "the link path drains: {log:?}"
    );
    let outer = Outer::new();
    advance_to(ms(10));
    assert!(outer.poll(&mut connection).is_pending());
    let wakes = outer.wakes();
    deliver(stateless_reset(RESET_TOKEN), &first, ms(10));
    assert_eq!(outer.wakes(), wakes + 1);
    advance_to(ms(11));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(take_log(), Vec::<String>::new());
    let log = run(&mut connection, 12..=12);
    assert_eq!(log.len(), 1, "{log:?}");
    assert!(log[0].contains("reason Some(\"Peer("), "{log:?}");
}

// ---- 1-RTT key updates in the sending call ----

/// The steps that give the server the client's Source Connection ID, its
/// 1-RTT keys and `sealed` packets sealed with their first sending
/// generation, then a 1-RTT packet at 10 ms, whose ACK is due at 35 ms,
/// after the maximum ACK delay; the key update state is inspected at 8 and
/// 40 ms.
fn sealed_with_first_generation(
    first: &LinkId<(), ()>,
    sealed: u64,
) -> [(Duration, probe::PacketStep); 6] {
    use probe::PacketStep::{InspectKeyUpdate, InstallOneRttKeys, Receive, Seal};
    [
        (
            ms(5),
            Receive(received(
                initial_from(&CLIENT_SCID, 0, &ping()),
                first,
                ms(5),
            )),
        ),
        (ms(6), InstallOneRttKeys),
        (ms(7), Seal(sealed)),
        (ms(8), InspectKeyUpdate),
        (
            ms(10),
            Receive(received(one_rtt_packet_of(0, 0, &ping()), first, ms(10))),
        ),
        (ms(40), InspectKeyUpdate),
    ]
}

#[test]
fn the_sending_call_initiates_a_key_update_at_three_quarters_of_the_confidentiality_limit() {
    reset();
    let first = link();
    feed([(ms(4), probe::Step::Confirm)]);
    feed_packets(sealed_with_first_generation(&first, 3 << 21));
    let mut connection = connection!(Mine, AddressValidation::Validated, first);
    take_log();
    let log = run(&mut connection, 4..=40);
    assert_eq!(
        lines_of(log, &["send"]),
        [
            "send Some(0), confirmed at None, lowest sent Some(0)",
            // the filling of the ACK initiated it; the next number of the
            // space is the lowest one of the new generation: packet 0 carried
            // the NEW_CONNECTION_ID frame issued once the handshake was
            // confirmed
            "send Some(1), confirmed at None, lowest sent Some(1)",
        ]
    );
    let sent = common::take_sent();
    assert!(
        sent.iter()
            .any(|(at, datagram)| *at == ms(35) && short_header(datagram)),
        "the ACK of the 1-RTT packet goes out: {sent:?}"
    );
    // this side initiated it: its sending half, until the peer answers
    assert_eq!(
        one_rtt_updates(),
        [one_rtt_updated(
            sakuya_wire_v1::role::Role::Server,
            1,
            sakuya_connection::v1::events::EventInitiator::Local
        )]
    );
}

#[test]
fn the_sending_call_initiates_a_key_update_once_the_threshold_of_packets_was_sealed() {
    reset();
    let first = link();
    KEY_UPDATE_AFTER.with(|k| k.set(core::num::NonZeroU64::new(100)));
    feed([(ms(4), probe::Step::Confirm)]);
    // far below the confidentiality limit, at the threshold
    feed_packets(sealed_with_first_generation(&first, 100));
    let mut connection = connection!(Mine, AddressValidation::Validated, first);
    take_log();
    let log = run(&mut connection, 4..=40);
    assert_eq!(
        lines_of(log, &["send"]),
        [
            "send Some(0), confirmed at None, lowest sent Some(0)",
            "send Some(1), confirmed at None, lowest sent Some(1)",
        ]
    );
    assert_eq!(
        one_rtt_updates(),
        [one_rtt_updated(
            sakuya_wire_v1::role::Role::Server,
            1,
            sakuya_connection::v1::events::EventInitiator::Local
        )]
    );
}

#[test]
fn the_sending_call_initiates_no_key_update_below_the_threshold_of_packets() {
    reset();
    let first = link();
    KEY_UPDATE_AFTER.with(|k| k.set(core::num::NonZeroU64::new(100)));
    feed([(ms(4), probe::Step::Confirm)]);
    // the packets the connection seals itself keep below it too
    feed_packets(sealed_with_first_generation(&first, 50));
    let mut connection = connection!(Mine, AddressValidation::Validated, first);
    take_log();
    let log = run(&mut connection, 4..=40);
    assert_eq!(
        lines_of(log, &["send"]),
        [
            "send Some(0), confirmed at None, lowest sent Some(0)",
            "send Some(0), confirmed at None, lowest sent Some(0)",
        ]
    );
    assert_eq!(one_rtt_updates(), []);
}

#[test]
fn the_sending_call_closes_with_aead_limit_reached_when_only_the_closing_packet_is_left() {
    use probe::PacketStep::Inspect;
    reset();
    let first = link();
    feed_packets(sealed_with_first_generation(&first, (1 << 23) - 1));
    feed_packets([(ms(41), Inspect)]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first);
    take_log();
    let log = run(&mut connection, 4..=41);
    // the handshake is not confirmed: no update may be initiated
    assert!(
        log.iter()
            .any(|line| line == "send Some(0), confirmed at None, lowest sent Some(0)"),
        "{log:?}"
    );
    let inspect = log.last().expect("the inspection");
    assert!(
        inspect.contains("AeadLimitReached { source: ConfidentialityLimitReached }"),
        "{log:?}"
    );
    let sent = common::take_sent();
    assert!(
        sent.iter().all(|(_, datagram)| !short_header(datagram)),
        "no 1-RTT packet goes out: {sent:?}"
    );
}

// ---- closing ----

/// A long header packet of the server at the start of `datagram`, opened
/// with `keys`: its type bits and the packet; an Initial packet has an
/// empty token.
fn open_long_sent(datagram: &[u8], keys: &DirectionKeys<RingBackend>) -> (u8, SentInitial) {
    let type_bits = (datagram[0] >> 4) & 0b11;
    let mut at = 5;
    let dcid_len = usize::from(datagram[at]);
    let dcid = datagram[at + 1..at + 1 + dcid_len].to_vec();
    at += 1 + dcid_len;
    let scid_len = usize::from(datagram[at]);
    let scid = datagram[at + 1..at + 1 + scid_len].to_vec();
    at += 1 + scid_len;
    if type_bits == INITIAL {
        assert_eq!(datagram[at], 0, "an empty token");
        at += 1;
    }
    let (length, width) = read_var_int(&datagram[at..]);
    let pn_offset = at + width;
    let len = pn_offset + length;
    let mut packet = datagram[..len].to_vec();
    let truncated = keys.header.remove(&mut packet, pn_offset).unwrap();
    let header_len = pn_offset + truncated.encoded_len().get();
    let number = truncated.decode(None);
    let payload = keys
        .packet
        .open(number, &mut packet, header_len)
        .unwrap()
        .to_vec();
    (
        type_bits,
        SentInitial {
            dcid,
            scid,
            number: number.get(),
            payload,
            len,
        },
    )
}

/// The 1-RTT packet `packet` of the server, to an 8-byte connection ID and
/// sealed with the first generation of its keys, opened: its connection ID,
/// its packet number and its payload.
fn open_sent_one_rtt(packet: &[u8]) -> (Vec<u8>, u64, Vec<u8>) {
    assert!(short_header(packet), "a 1-RTT packet: {packet:?}");
    let header = HeaderProtectionKey::derive(&RingBackend, ONE_RTT_AEAD, &server_secret());
    let keys = KeyGeneration::first(&RingBackend, ONE_RTT_AEAD, server_secret());
    let mut packet = packet.to_vec();
    let pn_offset = 1 + 8;
    let truncated = header.remove(&mut packet, pn_offset).unwrap();
    let header_len = pn_offset + truncated.encoded_len().get();
    let number = truncated.decode(None);
    let payload = keys
        .packet()
        .open(number, &mut packet, header_len)
        .unwrap()
        .to_vec();
    (packet[1..pn_offset].to_vec(), number.get(), payload)
}

/// The client's first Initial packet, numbered `number`, with a PING, in a
/// datagram of 1200 bytes.
fn client_initial(number: u64) -> BytesMut {
    padded(
        &[],
        |payload| initial_from(&CLIENT_SCID, number, payload),
        &ping(),
    )
}

/// Poll `connection`, which stays pending, at each millisecond of
/// `millis` until it is no longer woken at that instant, so that what a
/// deadline changed reaches the calls, and take the log.
fn settle<F: Future + Unpin>(
    connection: &mut F,
    millis: core::ops::RangeInclusive<u64>,
) -> Vec<String> {
    let outer = Outer::new();
    for at in millis {
        advance_to(ms(at));
        for _ in 0..16 {
            let wakes = outer.wakes();
            assert!(outer.poll(connection).is_pending());
            if outer.wakes() == wakes {
                break;
            }
        }
    }
    take_log()
}

/// The events the strategy recorded since the last call that give a
/// planner new facts of its link path's sealed close packet: the datagrams
/// received since it was sealed.
fn resend_events() -> Vec<String> {
    strategy_events("path ")
        .into_iter()
        .filter(|event| event.contains(": close "))
        .collect()
}

#[test]
fn a_server_closing_in_the_handshake_sends_its_close_in_initial_and_handshake_packets() {
    use probe::PacketStep::{InspectKeys, InstallHandshakeKeys};
    reset();
    let first = link();
    feed_packets([(ms(6), InstallHandshakeKeys), (ms(11), InspectKeys)]);
    CLOSER.with(|c| c.borrow_mut().push_back((ms(10), probe::CloserStep::Close)));
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first.clone());
    deliver(client_initial(0), &first, ms(5));
    let _ = settle(&mut connection, 5..=9);
    assert_eq!(common::take_sent().len(), 1, "the ACK");
    assert_eq!(common::take_adjusted_levels(), []);
    let log = settle(&mut connection, 10..=11);
    let sent = common::take_sent();
    assert_eq!(sent.len(), 1, "{sent:?}");
    let (at, datagram) = &sent[0];
    assert_eq!(*at, ms(10));
    // the probe's Handshake keys seal with the server's Initial secret
    let (kind, initial) = open_long_sent(datagram, &server_keys());
    assert_eq!(kind, INITIAL);
    assert_eq!(
        (initial.dcid.as_slice(), initial.scid.as_slice()),
        (&CLIENT_SCID[..], &SERVER_CID[..])
    );
    assert_eq!(initial.number, 1, "the next after the ACK");
    // an application close goes as APPLICATION_ERROR without its reason
    // phrase, and the frame type 0
    assert_eq!(initial.payload, [0x1c, 0x0c, 0x00, 0x00]);
    let (kind, handshake) = open_long_sent(&datagram[initial.len..], &server_keys());
    assert_eq!(kind, HANDSHAKE);
    assert_eq!(handshake.number, 0);
    assert_eq!(handshake.payload, [0x1c, 0x0c, 0x00, 0x00]);
    assert_eq!(
        initial.len + handshake.len,
        datagram.len(),
        "one datagram of both"
    );
    assert_eq!(
        common::take_adjusted_levels(),
        [
            sakuya_wire_v1::encryption_level::EncryptionLevel::Initial,
            sakuya_wire_v1::encryption_level::EncryptionLevel::Handshake
        ]
    );
    // once sealed, the keys keep only what reads the peer's packets
    assert!(
        log.iter()
            .any(|line| line == "keys: Initial receive, Handshake receive, 1-RTT none"),
        "{log:?}"
    );
    assert!(
        log.iter().any(|line| line == "initial keys live: false"),
        "{log:?}"
    );
}

#[test]
fn a_server_closing_once_confirmed_sends_its_close_in_a_one_rtt_packet_alone() {
    use probe::PacketStep::{InspectKeys, InstallHandshakeKeys, InstallOneRttKeys};
    reset();
    let first = link();
    feed([(ms(8), probe::Step::Confirm)]);
    feed_packets([
        (ms(6), InstallHandshakeKeys),
        (ms(7), InstallOneRttKeys),
        (ms(11), InspectKeys),
    ]);
    CLOSER.with(|c| c.borrow_mut().push_back((ms(10), probe::CloserStep::Close)));
    // longer than a datagram holds, of characters two bytes long
    common::set_close_phrase(Some(bytes::Bytes::from("é".repeat(1000))));
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    deliver(client_initial(0), &first, ms(5));
    let _ = settle(&mut connection, 5..=9);
    common::take_sent();
    let log = settle(&mut connection, 10..=11);
    let sent = common::take_sent();
    assert_eq!(sent.len(), 1, "{sent:?}");
    let (_, datagram) = &sent[0];
    let (dcid, number, payload) = open_sent_one_rtt(datagram);
    assert_eq!(dcid, CLIENT_SCID);
    // packet 0 carried the NEW_CONNECTION_ID frame issued once the
    // handshake was confirmed
    assert_eq!(number, 1);
    // the application's close with its code 7, as the policy gave it
    assert_eq!(payload[..2], [0x1d, 0x07]);
    let (len, width) = read_var_int(&payload[2..]);
    let phrase = &payload[2 + width..];
    assert_eq!(phrase.len(), len, "nothing after the frame");
    // cut to what the datagram holds, at a character boundary
    let phrase = core::str::from_utf8(phrase).expect("cut at a character boundary");
    assert!(phrase.chars().all(|c| c == 'é'));
    assert!(
        (MIN_DATAGRAM_SIZE - 1..=MIN_DATAGRAM_SIZE).contains(&datagram.len()),
        "{}",
        datagram.len()
    );
    assert_eq!(
        common::take_adjusted_levels(),
        [sakuya_wire_v1::encryption_level::EncryptionLevel::OneRtt]
    );
    assert!(
        log.iter()
            .any(|line| line == "keys: Initial receive, Handshake none, 1-RTT receive"),
        "{log:?}"
    );
}

#[test]
fn a_server_closing_before_it_knows_the_client_s_connection_id_seals_once_it_does() {
    use probe::PacketStep::InspectKeys;
    reset();
    let first = link();
    feed_packets([(ms(6), InspectKeys), (ms(21), InspectKeys)]);
    CLOSER.with(|c| c.borrow_mut().push_back((ms(5), probe::CloserStep::Close)));
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first.clone());
    take_log();
    take_strategy_events();
    let log = settle(&mut connection, 5..=19);
    assert_eq!(common::take_sent(), []);
    assert_eq!(resend_events(), [] as [&str; 0]);
    // nothing sealed: the keys keep their sending half
    assert!(
        log.iter()
            .any(|line| line == "keys: Initial both, Handshake none, 1-RTT none"),
        "{log:?}"
    );
    // the client's first Initial packet gives its connection ID while the
    // link path closes
    deliver(client_initial(0), &first, ms(20));
    let log = settle(&mut connection, 20..=21);
    let sent = common::take_sent();
    assert_eq!(sent.len(), 1, "{sent:?}");
    let (_, initial) = open_long_sent(&sent[0].1, &server_keys());
    assert_eq!(initial.dcid, CLIENT_SCID);
    assert_eq!(initial.number, 0, "nothing was sent before");
    assert_eq!(initial.payload, [0x1c, 0x0c, 0x00, 0x00]);
    // the datagram that gave the connection ID came before the close packet
    // was sealed: it is not one the close packet answers
    assert_eq!(resend_events(), ["path 0: close 0"]);
    assert!(
        log.iter()
            .any(|line| line == "keys: Initial receive, Handshake none, 1-RTT none"),
        "{log:?}"
    );
}

#[test]
fn a_closing_link_path_answers_the_first_second_fourth_and_eighth_datagram() {
    reset();
    let first = link();
    CLOSER.with(|c| c.borrow_mut().push_back((ms(10), probe::CloserStep::Close)));
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    deliver(client_initial(0), &first, ms(5));
    let _ = settle(&mut connection, 5..=10);
    let sent = common::take_sent();
    assert_eq!(sent.len(), 2, "the ACK and the close packet: {sent:?}");
    let close = sent[1].1.clone();
    assert_eq!(resend_events(), ["path 0: close 0"]);
    let mut answered = Vec::new();
    for datagram in 1..=9 {
        let at = 10 + datagram;
        deliver(client_initial(datagram), &first, ms(at));
        let _ = settle(&mut connection, at..=at);
        // the planner is given the count of datagrams received since the
        // close packet was sealed, and decides by it
        assert_eq!(
            resend_events(),
            [format!("path 0: close {datagram}")],
            "at {at} ms"
        );
        let sent = common::take_sent();
        if !sent.is_empty() {
            // the close packet as it was sealed
            assert_eq!(sent, [(ms(at), close.clone())]);
            answered.push(datagram);
        }
    }
    assert_eq!(answered, [1, 2, 4, 8]);
}

#[test]
fn the_anti_amplification_limit_holds_back_a_resend_of_the_close_packet() {
    reset();
    let first = link();
    common::set_close_phrase(Some(bytes::Bytes::from(vec![b'a'; 2000])));
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first.clone());
    // HANDSHAKE_DONE in an Initial packet is a connection error: a close of
    // type 0x1c, which keeps the reason phrase the policy gives
    let violation = padded(
        &[],
        |payload| initial_from(&CLIENT_SCID, 0, payload),
        &[0x1e],
    );
    deliver(violation, &first, ms(5));
    let _ = settle(&mut connection, 5..=5);
    let sent = common::take_sent();
    assert_eq!(sent.len(), 1, "{sent:?}");
    let close = sent[0].1.clone();
    // as long as a datagram is: 2400 bytes of credit for the 1200 received
    assert!(close.len() > MIN_DATAGRAM_SIZE - 8, "{}", close.len());
    assert!(close.len() <= MIN_DATAGRAM_SIZE);
    let mut answered = Vec::new();
    for datagram in 1..=8 {
        let at = 5 + datagram;
        // short datagrams add little credit; the fifth is a long one
        let bytes = if datagram == 5 {
            client_initial(datagram)
        } else {
            one_rtt_packet()
        };
        deliver(bytes, &first, ms(at));
        let _ = settle(&mut connection, at..=at);
        if !common::take_sent().is_empty() {
            answered.push(datagram);
        }
    }
    // the first goes on what the close packet left; the second and the
    // fourth find too little credit, and do not wait for it; the eighth
    // goes on what the fifth brought
    assert_eq!(answered, [1, 8]);
}

#[test]
fn every_closing_link_path_seals_its_own_close_packet_before_the_keys_lose_their_sending_half() {
    use probe::PacketStep::{Activate, InspectKeys, InstallOneRttKeys, Receive};
    reset();
    let first = link();
    let second = link();
    ADD.with(|a| a.set(Some((ms(5), second.clone()))));
    feed_packets([
        (
            ms(4),
            Receive(received(
                initial_from(&CLIENT_SCID, 0, &ping()),
                &first,
                ms(4),
            )),
        ),
        (ms(6), InstallOneRttKeys),
        (
            ms(7),
            Receive(received(
                one_rtt_packet_of(0, 0, &new_connection_id(1)),
                &first,
                ms(7),
            )),
        ),
        (ms(8), Activate(second.clone())),
        (ms(12), InspectKeys),
    ]);
    CLOSER.with(|c| c.borrow_mut().push_back((ms(10), probe::CloserStep::Close)));
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    let _ = settle(&mut connection, 4..=8);
    // the second logical link's address is not validated: what arrives
    // over it gives the credit its close packet goes on
    deliver(
        padded(&[], |payload| one_rtt_packet_of(0, 1, payload), &ping()),
        &second,
        ms(9),
    );
    let _ = settle(&mut connection, 9..=9);
    common::take_sent();
    let log = settle(&mut connection, 10..=12);
    let sent = common::take_sent();
    assert_eq!(
        sent.len(),
        2,
        "one close packet over each link path: {sent:?}"
    );
    let mut initial_numbers = Vec::new();
    let mut one_rtt_numbers = Vec::new();
    let mut dcids = Vec::new();
    for (_, datagram) in &sent {
        // the second link path sealed with the Initial keys too
        let (kind, initial) = open_long_sent(datagram, &server_keys());
        assert_eq!(kind, INITIAL);
        let (dcid, number, payload) = open_sent_one_rtt(&datagram[initial.len..]);
        assert_eq!(payload, [0x1d, 0x07, 0x00]);
        assert_eq!(initial.dcid, dcid);
        initial_numbers.push(initial.number);
        one_rtt_numbers.push(number);
        dcids.push(dcid);
    }
    initial_numbers.sort_unstable();
    one_rtt_numbers.sort_unstable();
    dcids.sort_unstable();
    // no packet number protects two packets
    assert_eq!(initial_numbers, [1, 2]);
    assert_eq!(one_rtt_numbers[1], one_rtt_numbers[0] + 1);
    assert_eq!(dcids, [vec![0x11; 8], CLIENT_SCID.to_vec()]);
    assert_eq!(
        log.iter()
            .filter(|line| *line == "initial keys live: false")
            .count(),
        1,
        "{log:?}"
    );
    assert!(
        log.iter()
            .any(|line| line == "keys: Initial receive, Handshake none, 1-RTT receive"),
        "{log:?}"
    );
}

#[test]
fn retire_prior_to_sends_the_retirement_with_a_connection_id_still_offered() {
    use probe::PacketStep::{InstallOneRttKeys, Receive};
    reset();
    let first = link();
    // NEW_CONNECTION_ID numbered 1, retiring prior to 1
    let mut retiring = new_connection_id(1);
    retiring[2] = 1;
    feed_packets([
        (
            ms(4),
            Receive(received(
                initial_from(&CLIENT_SCID, 0, &ping()),
                &first,
                ms(4),
            )),
        ),
        (ms(6), InstallOneRttKeys),
        (
            ms(7),
            Receive(received(one_rtt_packet_of(0, 0, &retiring), &first, ms(7))),
        ),
    ]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    let _ = settle(&mut connection, 4..=6);
    common::take_sent();
    let _ = settle(&mut connection, 7..=8);
    let mut retired = Vec::new();
    for (_, datagram) in common::take_sent() {
        let one_rtt = if short_header(&datagram) {
            &datagram[..]
        } else {
            let (_, initial) = open_long_sent(&datagram, &server_keys());
            &datagram[initial.len..]
        };
        if one_rtt.is_empty() {
            continue;
        }
        let (dcid, _, payload) = open_sent_one_rtt(one_rtt);
        for run in frames_of(&payload) {
            if let sakuya_wire_v1::frame::FrameRun::RetireConnectionId(frame) = run {
                retired.push((dcid.clone(), frame.sequence_number().get().get()));
            }
        }
    }
    // the connection ID numbered 0 is retired, in a packet sent with the
    // one numbered 1 (RFC 9000 §19.16)
    assert_eq!(retired, [(vec![0x11; 8], 0)]);
}

#[test]
fn a_draining_link_path_seals_nothing() {
    use probe::PacketStep::InspectKeys;
    reset();
    let first = link();
    feed_packets([(ms(8), InspectKeys)]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    deliver(client_initial(0), &first, ms(5));
    let _ = settle(&mut connection, 5..=6);
    assert_eq!(common::take_sent().len(), 1, "the ACK");
    take_strategy_events();
    let close = padded(
        &[],
        |payload| initial_from(&CLIENT_SCID, 1, payload),
        &[0x1c, 0x00, 0x00, 0x00],
    );
    deliver(close, &first, ms(7));
    let log = settle(&mut connection, 7..=8);
    assert_eq!(common::take_sent(), []);
    assert_eq!(resend_events(), [] as [&str; 0]);
    assert!(
        log.iter()
            .any(|line| line == "keys: Initial none, Handshake none, 1-RTT none"),
        "{log:?}"
    );
}

#[test]
fn a_draining_link_path_drops_the_send_its_link_holds() {
    reset();
    let first = link();
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    common::plan_sends([common::SendOutcome::Hold(usize::MAX)]);
    deliver(client_initial(0), &first, ms(5));
    let _ = settle(&mut connection, 5..=6);
    assert_eq!(common::take_batch_sizes(), [1], "the ACK, held by the link");
    let close = padded(
        &[],
        |payload| initial_from(&CLIENT_SCID, 1, payload),
        &[0x1c, 0x00, 0x00, 0x00],
    );
    deliver(close, &first, ms(7));
    let _ = settle(&mut connection, 7..=7);
    // the sending call went with the draining role, and the send with it
    common::release_held_send();
    let _ = settle(&mut connection, 8..=9);
    assert_eq!(common::take_sent(), []);
    assert_eq!(common::take_batch_sizes(), [0usize; 0]);
}

#[test]
fn a_close_the_application_asks_for_wakes_the_connection_and_closes_it() {
    reset();
    let mut connection = connection!(Mine, AddressValidation::NotValidated, link());
    let outer = Outer::new();
    assert!(outer.poll(&mut connection).is_pending());
    take_log();
    advance_to(ms(20));
    let before = outer.wakes();
    let asking = close_request();
    std::thread::spawn(move || {
        asking.request(common::AppClose(9));
        asking.request(common::AppClose(10));
    })
    .join()
    .expect("the asking thread");
    assert_eq!(outer.wakes(), before + 1, "the first request woke it");
    assert!(outer.poll(&mut connection).is_pending());
    let pto = probe_timeout(
        &sakuya_recovery_v1::rtt::RttEstimate::initial(sakuya_recovery_v1::rtt::INITIAL_RTT),
        ms(1),
        PacketNumberSpaceKind::ApplicationData,
        ms(25),
        0,
    );
    let end = ms(20) + pto * 3;
    assert_eq!(
        take_log(),
        [
            "recovery ended".to_owned(),
            format!("Closing({end:?}), NotValidated, credit Some(0)"),
        ]
    );
    advance_to(end);
    assert!(
        outer.poll(&mut connection).is_ready(),
        "the connection ends with its last link path"
    );
    assert_eq!(
        take_log(),
        [
            "link path ended: Some(Local(Application(AppClose(9))))",
            "entry ended"
        ]
    );
}

#[test]
fn a_close_asked_for_once_another_reason_is_written_is_dropped() {
    reset();
    CLOSER.with(|c| c.borrow_mut().push_back((ms(20), probe::CloserStep::Close)));
    let mut connection = connection!(Mine, AddressValidation::NotValidated, link());
    let outer = Outer::new();
    assert!(outer.poll(&mut connection).is_pending());
    advance_to(ms(20));
    assert!(outer.poll(&mut connection).is_pending());
    take_log();
    close_request().request(common::AppClose(9));
    assert!(outer.poll(&mut connection).is_pending());
    assert!(take_log().is_empty(), "nothing follows from the request");
    drop(connection);
    assert_eq!(
        take_log(),
        [
            "link path ended: Some(Local(Application(AppClose(7))))",
            "entry ended"
        ]
    );
}

#[test]
fn a_close_asked_for_before_the_first_flight_is_received_is_taken_in_first() {
    reset();
    let first = link();
    FIRST_DATAGRAMS.with(|f| {
        f.borrow_mut().push(ReceivedDatagram::new(
            client_initial(0),
            ArrivalFacts::new(TestLink(first.clone()), ms(0), None),
        ));
    });
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first.clone());
    take_strategy_events();
    close_request().request(common::AppClose(9));
    let _ = settle(&mut connection, 0..=0);
    // the receiving call of the first poll receives the first flight in
    // `Closing`: it acknowledges nothing, and its first Initial packet gives
    // the client's connection ID the close packet is sealed with
    let sent = common::take_sent();
    assert_eq!(sent.len(), 1, "the close packet alone: {sent:?}");
    let (kind, initial) = open_long_sent(&sent[0].1, &server_keys());
    assert_eq!(kind, INITIAL);
    assert_eq!(initial.dcid, CLIENT_SCID);
    assert_eq!(initial.number, 0, "nothing was sent before");
    assert_eq!(initial.payload, [0x1c, 0x0c, 0x00, 0x00]);
    // the first flight came before the close packet was sealed
    assert_eq!(resend_events(), ["path 0: close 0"]);
}

/// The steps of a client's packet feeder: the server's connection ID
/// becomes known at 3 ms, and the server's first Initial packet, which
/// elicits an acknowledgment, arrives at 5 ms.
fn client_answering_at_5_ms(first: &LinkId<(), ()>) {
    use probe::PacketStep::{HandshakeConnectionId, Receive};
    feed_packets([
        (ms(3), HandshakeConnectionId(server_cid())),
        (
            ms(5),
            Receive(received(
                long_packet_from(
                    first_byte(INITIAL),
                    &SERVER_CID,
                    &[],
                    &server_keys(),
                    0,
                    &ping(),
                ),
                first,
                ms(5),
            )),
        ),
    ]);
}

#[test]
fn a_client_whose_link_accepted_no_datagram_ends_at_once_with_nothing_sent() {
    reset();
    let first = link();
    client_answering_at_5_ms(&first);
    let mut connection = connection!(ClientMine, AddressValidation::Validated, first.clone());
    // the ACK is sealed and handed over, but the link holds it
    common::plan_sends([common::SendOutcome::Hold(usize::MAX)]);
    let _ = settle(&mut connection, 3..=5);
    assert_eq!(common::take_batch_sizes(), [1]);
    take_log();
    close_request().request(common::AppClose(9));
    let outer = Outer::new();
    assert!(outer.poll(&mut connection).is_ready(), "it ends at once");
    common::release_held_send();
    assert_eq!(common::take_sent(), [], "nothing goes out");
    assert_eq!(
        lines_of(take_log(), &["link path ended"]),
        ["link path ended: Some(Local(Application(AppClose(9))))"]
    );
}

#[test]
fn the_connection_handle_gives_the_close_of_a_client_that_ended_at_once() {
    reset();
    let (mut connection, handle) =
        handled_connection!(ClientMine, AddressValidation::Validated, link());
    handle.close(common::AppClose(9));
    let outer = Outer::new();
    assert!(outer.poll(&mut connection).is_ready(), "it ends at once");
    let application_close = |reason: &CloseReason<CloseCauseOf<ClientMine, Parts>>| {
        matches!(
            reason,
            CloseReason::Local(cause)
                if matches!(**cause, LocalCloseCause::Application(common::AppClose(9)))
        )
    };
    let closed = poll_now(handle.closed());
    assert!(
        matches!(&closed, core::task::Poll::Ready(reason) if application_close(reason)),
        "{closed:?}"
    );
    assert!(matches!(
        poll_now(handle.handshake_completed()),
        core::task::Poll::Ready(Err(error)) if application_close(error.reason())
    ));
}

#[test]
fn a_client_whose_link_accepted_a_datagram_closes_and_sends_its_close_packet() {
    reset();
    let first = link();
    client_answering_at_5_ms(&first);
    let mut connection = connection!(ClientMine, AddressValidation::Validated, first.clone());
    let _ = settle(&mut connection, 3..=5);
    assert_eq!(common::take_sent().len(), 1, "the ACK");
    close_request().request(common::AppClose(9));
    let _ = settle(&mut connection, 6..=6);
    let sent = common::take_sent();
    assert_eq!(sent.len(), 1, "{sent:?}");
    let packet = open_initial(&sent[0].1, &client_keys());
    assert_eq!(packet.dcid, SERVER_CID);
    // an application close goes as APPLICATION_ERROR in an Initial packet
    assert_eq!(packet.payload[..4], [0x1c, 0x0c, 0x00, 0x00]);
    assert!(
        packet.payload[4..].iter().all(|&byte| byte == 0),
        "padding after it"
    );
}

// ---- the retirement of the Initial and Handshake spaces ----

#[test]
fn discarding_the_handshake_keys_retires_the_space_once_and_the_probe_timeout_restarts() {
    use probe::PacketStep::TakeRecords;
    use probe::Step::{Confirm, Discard, Sample, Sent};
    reset();
    feed([
        // an RTT of 10 ms: a probe timeout of 30 ms, 55 ms in the
        // Application Data space with the peer's default max_ack_delay
        (ms(10), Sample(ms(0))),
        (
            ms(12),
            Sent {
                space: PacketNumberSpaceKind::Handshake,
                count: 1,
            },
        ),
        (
            ms(140),
            Sent {
                space: PacketNumberSpaceKind::ApplicationData,
                count: 2,
            },
        ),
        // the confirmation discards the Handshake keys (RFC 9001 §4.9.2)
        (ms(150), Confirm),
        (ms(160), Discard(PacketNumberSpaceKind::Handshake)),
        (ms(170), Discard(PacketNumberSpaceKind::Initial)),
    ]);
    feed_packets([
        (ms(196), TakeRecords(PacketNumberSpaceKind::Handshake)),
        (ms(197), TakeRecords(PacketNumberSpaceKind::ApplicationData)),
    ]);
    let mut connection = connection!(SpyMine, AddressValidation::Validated, link());
    take_log();
    // the Handshake space expires at 42 ms and 102 ms; at 140 ms its
    // timeout, at 222 ms, comes before the Application Data space's, at
    // 140 + 4 × 55 ms
    let log = run(&mut connection, 10..=149);
    assert_eq!(
        lines_of(log, &["in flight", "congestion"]),
        [
            "in flight 1200, outstanding 1, lost [], permits 0, backoff 0",
            "in flight 1200, outstanding 1, lost [], permits 2, backoff 1",
            "in flight 1200, outstanding 1, lost [], permits 4, backoff 2",
            "in flight 3600, outstanding 3, lost [], permits 4, backoff 2",
        ]
    );
    // the Handshake packet leaves the bytes in flight without a signal, and
    // the backoff is reset; the Application Data space's timeout, from its
    // last packet, is now the earliest
    let log = run(&mut connection, 150..=194);
    assert_eq!(
        lines_of(log, &["in flight", "congestion"]),
        [
            "congestion: removed 1200 bytes, 2400 in flight",
            "in flight 2400, outstanding 2, lost [], permits 4, backoff 0",
        ]
    );
    let log = run(&mut connection, 195..=197);
    assert_eq!(
        lines_of(
            log,
            &["in flight", "congestion", "records", "lost", "delivered"]
        ),
        [
            // the probe timeout of the Application Data space hands the
            // content of its two oldest packets, one for each probe
            // datagram, back to their frame sources as lost; the packets
            // stay in flight and count no loss
            "lost ApplicationData 0",
            "lost ApplicationData 1",
            "in flight 2400, outstanding 2, lost [], permits 6, backoff 1",
            // the Handshake space's records are gone, and its frame
            // sources heard nothing; the Application Data space stays
            "records ApplicationData: [(0, \"Sent(140ms)\"), (1, \"Sent(140ms)\")]",
        ]
    );
}

#[test]
fn an_initial_ack_after_the_initial_space_retired_settles_nothing() {
    use probe::PacketStep::{InstallHandshakeKeys, Receive};
    reset();
    let first = link();
    feed([(
        ms(10),
        probe::Step::Sent {
            space: PacketNumberSpaceKind::Initial,
            count: 2,
        },
    )]);
    feed_packets([
        (ms(49), InstallHandshakeKeys),
        (
            ms(50),
            Receive(received(long_packet(HANDSHAKE, 0, &ping()), &first, ms(50))),
        ),
        (ms(51), ack_received(1, &[(0, 1)], &first, ms(51))),
    ]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first);
    take_log();
    let log = run(&mut connection, 10..=51);
    assert_eq!(
        lines_of(
            log,
            &["in flight", "delivered", "lost", "processed", "dropped"]
        ),
        [
            "in flight 2400, outstanding 2, lost [], permits 0, backoff 0",
            // a server discards the Initial keys once it processed a
            // Handshake packet, and the space retires with them
            "processed: highest numbered true, non-probing true",
            "in flight 0, outstanding 0, lost [], permits 0, backoff 0",
            "dropped: no Initial keys",
        ]
    );
}

#[test]
fn an_initial_packet_the_link_accepts_after_the_space_retired_leaves_the_bytes_in_flight() {
    use probe::PacketStep::{InstallHandshakeKeys, Receive, TakeRecords};
    reset();
    let first = link();
    let mut connection = with_the_ack_and_two_probes_at_1005_ms(
        &first,
        [
            (ms(1049), InstallHandshakeKeys),
            (
                ms(1050),
                Receive(received(
                    client_long_packet(HANDSHAKE, 0, &ping()),
                    &first,
                    ms(1050),
                )),
            ),
            (ms(1062), TakeRecords(PacketNumberSpaceKind::Initial)),
        ],
    );
    common::plan_sends([common::SendOutcome::Hold(2)]);
    let log = run(&mut connection, 1005..=1006);
    // the ACK and the expiry's two PING datagrams
    assert_eq!(common::take_batch_sizes(), [3]);
    let sealed = last_in_flight(log);
    // the Initial keys go with the first Handshake packet processed, while
    // the link keeps the batch with the PING's datagram: the Initial packet
    // accepted before leaves the bytes in flight then
    let log = run(&mut connection, 1049..=1050);
    assert_eq!(sealed - last_in_flight(log), MIN_DATAGRAM_SIZE);
    advance_to(ms(1060));
    common::release_held_send();
    let log = run(&mut connection, 1060..=1061);
    let sent = common::take_sent();
    assert_eq!(sent.len(), 3, "{sent:?}");
    assert_eq!(sent[1].1[0] & 0xf0, 0xc0, "the PING's Initial packet");
    assert_eq!(sent[2].1[0] & 0xf0, 0xe0, "the ACK of the Handshake packet");
    // the link accepts the first PING, which the space's records no longer
    // have: it leaves the bytes in flight at once; the second PING (the
    // expiry's second probe datagram), which the hold left out of what was
    // accepted, is left out of the next batch and leaves them as well
    assert_eq!(sealed - last_in_flight(log), 3 * MIN_DATAGRAM_SIZE);
    let log = run(&mut connection, 1062..=1062);
    assert_eq!(lines_of(log, &["records"]), [] as [String; 0]);
}

// ---- connection migration ----

/// A PATH_CHALLENGE frame, then PADDING: a probing packet's payload (RFC
/// 9000 §9.1).
fn path_challenge() -> Vec<u8> {
    [&[0x1a][..], &[7; 8], &[0; 20]].concat()
}

/// A server connection over `first`, of `validation`, with its 1-RTT keys
/// installed at 5 ms; what it logged until then is taken.
fn migrating_server(
    first: &LinkId<(), ()>,
    validation: AddressValidation,
    steps: impl IntoIterator<Item = (Duration, probe::PacketStep)>,
) -> impl Future<Output = ()> + Unpin {
    use probe::PacketStep::InstallOneRttKeys;
    common::strategy::plan_nothing();
    feed_packets(core::iter::once((ms(5), InstallOneRttKeys)).chain(steps));
    let mut connection = connection!(Mine, validation, first.clone());
    run(&mut connection, 0..=5);
    take_log();
    connection
}

#[test]
fn a_packet_from_a_new_link_builds_a_candidate_whose_entry_counts_the_datagram_once() {
    // nothing was received on the active link path: the peer is taken to
    // have switched connection IDs
    use probe::PacketStep::InspectCredit;
    reset();
    let (first, second) = (link(), link());
    let mut connection = migrating_server(
        &first,
        AddressValidation::Validated,
        [
            (ms(8), InspectCredit(second.clone())),
            (ms(11), InspectCredit(second.clone())),
        ],
    );
    let one = one_rtt_packet_of(0, 3, &path_challenge());
    let one_len = one.len();
    deliver(one, &second, ms(6));
    let mut log = run(&mut connection, 6..=8);
    // a later datagram from the same link finds the link path, and asks
    // for nothing
    let two = one_rtt_packet_of(0, 4, &path_challenge());
    let two_len = two.len();
    deliver(two, &second, ms(9));
    log.extend(run(&mut connection, 9..=11));
    // the factor of the tests is 2
    assert_eq!(
        log,
        [
            "admit at 6ms: [\"Active validated\"], peer switched true, migration disabled false"
                .to_owned(),
            "Candidate, NotValidated, credit Some(0)".to_owned(),
            format!("credit Some(Some({}))", 2 * one_len),
            format!("credit Some(Some({}))", 2 * (one_len + two_len)),
        ]
    );
}

#[test]
fn a_dropped_admission_builds_records_and_counts_nothing() {
    use probe::PacketStep::{InspectCredit, InspectLargest};
    reset();
    common::set_migration(
        common::TestAdmission::Drop,
        v1::migration::SwitchTiming::Now,
    );
    let (first, second) = (link(), link());
    let mut connection = migrating_server(
        &first,
        AddressValidation::Validated,
        [
            (ms(7), InspectCredit(second.clone())),
            (ms(8), InspectLargest),
            (ms(10), InspectLargest),
        ],
    );
    deliver(one_rtt_packet_of(0, 3, &ping()), &second, ms(6));
    let mut log = run(&mut connection, 6..=8);
    // the packet was not recorded: the same one over the first link is no
    // duplicate
    deliver(one_rtt_packet_of(0, 3, &ping()), &first, ms(9));
    log.extend(run(&mut connection, 9..=10));
    assert_eq!(
        log,
        [
            "admit at 6ms: [\"Active validated\"], peer switched true, migration disabled false",
            "credit None",
            "largest Application Data None",
            "largest Application Data Some(3)",
        ]
    );
}

#[test]
fn an_admission_ends_what_it_names_but_the_active_link_path() {
    reset();
    common::set_migration(
        common::TestAdmission::AcceptEndingAll,
        v1::migration::SwitchTiming::Now,
    );
    let (first, second, third) = (link(), link(), link());
    let mut connection = migrating_server(&first, AddressValidation::Validated, []);
    deliver(one_rtt_packet_of(0, 3, &path_challenge()), &second, ms(6));
    let mut log = run(&mut connection, 6..=7);
    deliver(one_rtt_packet_of(0, 4, &path_challenge()), &third, ms(8));
    log.extend(run(&mut connection, 8..=10));
    assert_eq!(
        log,
        [
            "admit at 6ms: [\"Active validated\"], peer switched true, migration disabled false",
            "Candidate, NotValidated, credit Some(0)",
            "admit at 8ms: [\"Active validated\", \"Candidate\"], peer switched true, \
             migration disabled false",
            // the new one is built first, then the candidate ends, not the
            // active one
            "Candidate, NotValidated, credit Some(0)",
            "link path ended: None",
            "entry ended",
        ]
    );
}

#[test]
fn a_client_drops_a_packet_from_an_unknown_server_address() {
    use probe::PacketStep::InstallOneRttKeys;
    reset();
    common::strategy::plan_nothing();
    let (first, second) = (link(), link());
    feed_packets([(ms(5), InstallOneRttKeys)]);
    let mut connection = connection!(ClientMine, AddressValidation::Validated, first.clone());
    run(&mut connection, 0..=5);
    take_log();
    deliver(one_rtt_packet_of(0, 3, &ping()), &second, ms(6));
    assert_eq!(run(&mut connection, 6..=8), [] as [&str; 0]);
}

#[test]
fn a_non_probing_packet_switches_at_once_with_a_new_layer_and_the_active_one_settles() {
    reset();
    let (first, second) = (link(), link());
    let mut connection = migrating_server(&first, AddressValidation::Validated, []);
    deliver(one_rtt_packet_of(0, 3, &ping()), &first, ms(6));
    let mut log = run(&mut connection, 6..=7);
    deliver(one_rtt_packet_of(0, 4, &ping()), &second, ms(8));
    log.extend(run(&mut connection, 8..=10));
    // the candidate is built for the packet, which it receives next: its
    // recovery layer is new and the active one settles for three of its
    // probe timeouts, from the packet's arrival
    assert_eq!(
        log,
        [
            "admit at 8ms: [\"Active validated\"], peer switched false, migration disabled false",
            "Candidate, NotValidated, credit Some(0)",
            "peer moved at 8ms, peer switched false: Now",
            "settling for 3 × 1.024s",
            "recovery built, initial RTT None",
            "Settling(3.08s), Validated, credit None",
            // held by the factor 2 of the tests until it is validated
            "Active, NotValidated, credit Some(100)",
        ]
    );
}

#[test]
fn a_packet_on_the_validated_settling_link_path_switches_back_without_asking() {
    reset();
    let (first, second) = (link(), link());
    let mut connection = migrating_server(&first, AddressValidation::Validated, []);
    deliver(one_rtt_packet_of(0, 3, &ping()), &first, ms(6));
    run(&mut connection, 6..=7);
    deliver(one_rtt_packet_of(0, 4, &ping()), &second, ms(8));
    run(&mut connection, 8..=10);
    // older, or probing only: no switch
    deliver(one_rtt_packet_of(0, 2, &ping()), &first, ms(11));
    let mut log = run(&mut connection, 11..=12);
    deliver(one_rtt_packet_of(0, 5, &path_challenge()), &first, ms(13));
    log.extend(run(&mut connection, 13..=14));
    assert_eq!(log, [] as [&str; 0]);
    // the active link path is not validated: back to the settling one,
    // with the layer it kept, and the new one settles
    deliver(one_rtt_packet_of(0, 6, &ping()), &first, ms(15));
    assert_eq!(
        run(&mut connection, 15..=17),
        [
            "settling for 3 × 1.024s",
            "Active, Validated, credit None",
            "Settling(3.087s), NotValidated, credit Some(100)",
        ]
    );
}

#[test]
fn the_local_strategy_hears_only_of_a_switch_of_connection_ids() {
    reset();
    ROUTE_SERVER_CID.with(|r| r.set(true));
    let (first, second, third) = (link(), link(), link());
    let mut connection = migrating_server(&first, AddressValidation::Validated, []);
    let mut used = Vec::new();
    for (number, dcid, over) in [
        (3, CLIENT_DCID, &first),
        (4, CLIENT_DCID, &first),
        (5, SERVER_CID, &first),
        (6, SERVER_CID, &first),
    ] {
        deliver(
            one_rtt_packet_to(dcid, 0, number, &path_challenge()),
            over,
            ms(number + 3),
        );
        run(&mut connection, number + 3..=number + 3);
        used.push(common::take_used_by_peer());
    }
    assert_eq!(
        used,
        [
            vec![CLIENT_DCID.to_vec()],
            vec![],
            vec![SERVER_CID.to_vec()],
            vec![]
        ]
    );
    take_log();
    // a new link path's first packet is compared with the active one
    deliver(
        one_rtt_packet_to(SERVER_CID, 0, 7, &path_challenge()),
        &second,
        ms(10),
    );
    let mut log = run(&mut connection, 10..=11);
    assert_eq!(common::take_used_by_peer(), [] as [Vec<u8>; 0]);
    deliver(
        one_rtt_packet_to(CLIENT_DCID, 0, 8, &path_challenge()),
        &second,
        ms(12),
    );
    log.extend(run(&mut connection, 12..=13));
    assert_eq!(common::take_used_by_peer(), [CLIENT_DCID.to_vec()]);
    deliver(
        one_rtt_packet_to(CLIENT_DCID, 0, 9, &path_challenge()),
        &third,
        ms(14),
    );
    log.extend(run(&mut connection, 14..=15));
    assert_eq!(common::take_used_by_peer(), [CLIENT_DCID.to_vec()]);
    let admitted: Vec<_> = log
        .into_iter()
        .filter(|line| line.starts_with("admit"))
        .collect();
    assert_eq!(
        admitted,
        [
            "admit at 10ms: [\"Active validated\"], peer switched false, migration disabled false",
            "admit at 14ms: [\"Active validated\", \"Candidate\"], peer switched true, \
             migration disabled false",
        ]
    );
}

#[test]
fn a_moved_recovery_layer_keeps_the_datagram_size_probe_that_awaits_its_result() {
    use probe::Step::{InspectPmtu, SealPmtuProbe};
    reset();
    let (first, second) = (link(), link());
    ADD.with(|a| a.set(Some((ms(5), second.clone()))));
    MOVE.with(|m| m.set(Some((ms(10), first.clone(), second.clone()))));
    feed([
        (ms(6), SealPmtuProbe(1350)),
        (ms(8), InspectPmtu(first.clone())),
        (ms(12), InspectPmtu(second.clone())),
    ]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    take_log();
    // the layer moves without the factory: nothing is built or ended
    assert_eq!(
        run(&mut connection, 5..=12),
        [
            "Candidate, NotValidated, credit Some(0)",
            "probe awaited Some(1350), over the link given true",
            "probe awaited Some(1350), over the link given true",
        ]
    );
}

#[test]
fn a_moved_recovery_layer_keeps_its_ecn_state() {
    use probe::Step::{InspectEcn, LoseEcnTest, MarkEcn};
    reset();
    let (first, second) = (link(), link());
    ADD.with(|a| a.set(Some((ms(5), second.clone()))));
    MOVE.with(|m| m.set(Some((ms(10), first.clone(), second.clone()))));
    feed([
        (ms(6), InspectEcn(first.clone())),
        (ms(7), LoseEcnTest),
        (ms(8), MarkEcn),
        (ms(9), InspectEcn(first.clone())),
        (ms(12), InspectEcn(second.clone())),
    ]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    take_log();
    // a layer built anew is unvalidated; the one moved goes on as it was
    assert_eq!(
        run(&mut connection, 5..=12),
        [
            "Candidate, NotValidated, credit Some(0)",
            "ECN Unvalidated, marked outstanding 0, over the link given true",
            "ECN Failed, marked outstanding 1, over the link given true",
            "ECN Failed, marked outstanding 1, over the link given true",
        ]
    );
}

// ---- path validation ----

/// The data of the PATH_CHALLENGE frame in `payload`, if it has one.
fn challenge_data(payload: &[u8]) -> Option<[u8; 8]> {
    // the frames before it in these packets are an ACK frame and a
    // PATH_RESPONSE, neither of which has a byte 0x1a where a frame starts
    // in the tests
    payload
        .windows(9)
        .position(|w| w[0] == 0x1a)
        .map(|at| payload[at + 1..at + 9].try_into().unwrap())
}

/// The 1-RTT datagrams the test links accepted since the last call,
/// opened: the size of each and its payload.
fn sent_payloads() -> Vec<(usize, Vec<u8>)> {
    common::take_sent()
        .into_iter()
        .filter(|(_, datagram)| datagram[0] & 0x80 == 0)
        .map(|(_, datagram)| (datagram.len(), open_sent_one_rtt(&datagram).2))
        .collect()
}

/// A server connection over `first` that received the client's Initial
/// packet at 5 ms, its 1-RTT keys at 6 ms and a second connection ID of the
/// client's at 7 ms, and plans as the ranked strategy does; what it logged
/// and sent until then is taken. `steps` follow.
fn validating_server(
    first: &LinkId<(), ()>,
    steps: impl IntoIterator<Item = (Duration, probe::PacketStep)>,
) -> impl Future<Output = ()> + Unpin {
    validating_server_of(first, AddressValidation::Validated, steps)
}

/// A server connection as [`validating_server`] makes it, the address of
/// whose first link is of `validation`.
fn validating_server_of(
    first: &LinkId<(), ()>,
    validation: AddressValidation,
    steps: impl IntoIterator<Item = (Duration, probe::PacketStep)>,
) -> impl Future<Output = ()> + Unpin {
    use probe::PacketStep::{InstallOneRttKeys, Receive};
    feed_packets(
        [
            (
                ms(5),
                Receive(received(initial_from(&[0xaa; 8], 0, &ping()), first, ms(5))),
            ),
            (ms(6), InstallOneRttKeys),
            (
                ms(7),
                Receive(received(
                    one_rtt_packet_of(0, 0, &new_connection_id(1)),
                    first,
                    ms(7),
                )),
            ),
        ]
        .into_iter()
        .chain(steps),
    );
    let mut connection = connection!(Mine, validation, first.clone());
    run(&mut connection, 5..=9);
    take_log();
    common::take_sent();
    connection
}

#[test]
fn a_candidate_answers_and_challenges_in_a_probe_the_anti_amplification_limit_holds() {
    reset();
    let (first, second) = (link(), link());
    let mut connection = validating_server(&first, []);
    let probe = one_rtt_packet_of(0, 3, &path_challenge());
    let len = probe.len();
    deliver(probe, &second, ms(10));
    run(&mut connection, 10..=12);
    let response = [&[0x1b][..], &[7; 8][..]].concat();
    let sent: Vec<_> = sent_payloads()
        .into_iter()
        .filter(|(_, payload)| payload.windows(9).any(|w| w == response))
        .collect();
    // one datagram, with the response and the candidate's own challenge,
    // padded as far as the factor 2 of the tests lets it
    assert_eq!(sent.len(), 1, "{sent:?}");
    let (size, payload) = &sent[0];
    assert_eq!(*size, 2 * len);
    assert!(challenge_data(payload).is_some(), "{payload:?}");
    // a candidate's response is not followed by a PING
    assert!(
        !payload
            .windows(10)
            .any(|w| w[..9] == response[..] && w[9] == 0x01),
        "{payload:?}"
    );
}

#[test]
fn the_active_link_path_follows_its_response_with_a_ping() {
    reset();
    let first = link();
    let mut connection = validating_server(&first, []);
    deliver(one_rtt_packet_of(0, 3, &path_challenge()), &first, ms(10));
    run(&mut connection, 10..=12);
    let answer = [&[0x1b][..], &[7; 8][..], &[0x01]].concat();
    assert!(
        sent_payloads()
            .iter()
            .any(|(_, payload)| payload.windows(10).any(|w| w == answer)),
        "a PATH_RESPONSE, then a PING"
    );
}

#[test]
fn a_response_over_another_link_path_validates_the_candidate_and_lifts_the_limit() {
    reset();
    let (first, second) = (link(), link());
    let mut connection = validating_server(&first, []);
    deliver(one_rtt_packet_of(0, 3, &path_challenge()), &second, ms(10));
    run(&mut connection, 10..=11);
    let data = sent_payloads()
        .iter()
        .find_map(|(_, payload)| challenge_data(payload))
        .expect("the candidate challenges");
    // the response comes back over the first link
    let response = [&[0x1b][..], &data[..], &[0; 20]].concat();
    deliver(one_rtt_packet_of(0, 4, &response), &first, ms(12));
    run(&mut connection, 12..=13);
    // the candidate's address is validated: its second challenge, for the
    // 1200 bytes, is no longer held by the limit
    let again: Vec<_> = sent_payloads()
        .iter()
        .filter_map(|(size, payload)| challenge_data(payload).map(|_| *size))
        .collect();
    assert_eq!(again, [MIN_DATAGRAM_SIZE]);
}

/// The tokens of the NEW_TOKEN frames in `payload`, a 1-RTT payload of
/// the tests' server, read until a frame the tests do not read.
fn new_tokens_in(payload: &[u8]) -> Vec<Vec<u8>> {
    let mut tokens = Vec::new();
    // the tests' tokens are `token-n`, shorter than 64 bytes: a frame is
    // 0x07, a one-byte length and the token
    let mut at = 0;
    while let Some(start) = payload[at..].windows(2).position(|w| w == [0x07, 7]) {
        let token = &payload[at + start + 2..];
        if token.starts_with(b"token-") {
            tokens.push(token[..7].to_vec());
        }
        at += start + 1;
    }
    tokens
}

#[test]
fn a_server_gives_a_token_for_each_later_link_path_once_it_is_validated() {
    reset();
    let (first, second) = (link(), link());
    let mut connection = validating_server(&first, []);
    deliver(one_rtt_packet_of(0, 3, &path_challenge()), &second, ms(10));
    run(&mut connection, 10..=11);
    let data = sent_payloads()
        .iter()
        .find_map(|(_, payload)| challenge_data(payload))
        .expect("the candidate challenges");
    assert_eq!(
        common::new_tokens_issued(),
        Vec::<bytes::Bytes>::new(),
        "nothing before the new link path is validated"
    );
    let response = [&[0x1b][..], &data[..], &[0; 20]].concat();
    deliver(one_rtt_packet_of(0, 4, &response), &first, ms(12));
    run(&mut connection, 12..=13);
    assert_eq!(
        common::new_tokens_issued(),
        [bytes::Bytes::from_static(b"token-1")]
    );
    let sent: Vec<_> = sent_payloads()
        .iter()
        .flat_map(|(_, payload)| new_tokens_in(payload))
        .collect();
    assert_eq!(
        sent,
        [b"token-1".to_vec()],
        "the token goes on the active link path"
    );
}

#[test]
fn a_server_whose_issuer_gives_no_token_for_a_validated_link_path_sends_none() {
    reset();
    common::set_new_token_issuing(false);
    let (first, second) = (link(), link());
    let mut connection = validating_server(&first, []);
    deliver(one_rtt_packet_of(0, 3, &path_challenge()), &second, ms(10));
    run(&mut connection, 10..=11);
    let data = sent_payloads()
        .iter()
        .find_map(|(_, payload)| challenge_data(payload))
        .expect("the candidate challenges");
    let response = [&[0x1b][..], &data[..], &[0; 20]].concat();
    deliver(one_rtt_packet_of(0, 4, &response), &first, ms(12));
    run(&mut connection, 12..=13);
    let sent: Vec<_> = sent_payloads()
        .iter()
        .flat_map(|(_, payload)| new_tokens_in(payload))
        .collect();
    assert_eq!(sent, Vec::<Vec<u8>>::new());
}

#[test]
fn a_challenge_the_limit_held_is_followed_by_one_of_1200_bytes_once_answered() {
    reset();
    let (first, second) = (link(), link());
    let mut connection = validating_server(&first, []);
    deliver(one_rtt_packet_of(0, 3, &path_challenge()), &second, ms(10));
    run(&mut connection, 10..=11);
    let (size, data) = sent_payloads()
        .iter()
        .find_map(|(size, payload)| challenge_data(payload).map(|data| (*size, data)))
        .expect("the candidate challenges");
    assert!(size < MIN_DATAGRAM_SIZE, "{size}");
    let response = [&[0x1b][..], &data[..], &[0; 20]].concat();
    deliver(one_rtt_packet_of(0, 4, &response), &second, ms(12));
    run(&mut connection, 12..=13);
    // the address is validated, the path's 1200 bytes not yet: a second
    // challenge goes, expanded now that the limit lifted
    let again: Vec<_> = sent_payloads()
        .iter()
        .filter_map(|(size, payload)| challenge_data(payload).map(|data| (*size, data)))
        .collect();
    assert_eq!(again.len(), 1, "{again:?}");
    assert_eq!(again[0].0, MIN_DATAGRAM_SIZE);
    assert_ne!(again[0].1, data);
}

#[test]
fn a_challenge_goes_again_after_the_probe_timeout_and_the_candidate_ends_when_it_gives_up() {
    reset();
    let (first, second) = (link(), link());
    let mut connection = validating_server(&first, []);
    // credit enough for a few challenges
    let probe = padded(
        &[],
        |payload| one_rtt_packet_of(0, 3, payload),
        &path_challenge(),
    );
    deliver(probe, &second, ms(10));
    run(&mut connection, 10..=11);
    let challenges = |sent: Vec<(usize, Vec<u8>)>| {
        sent.iter()
            .filter(|(_, payload)| challenge_data(payload).is_some())
            .count()
    };
    assert_eq!(challenges(sent_payloads()), 1);
    // the test policy waits the probe timeout of a new path, about a
    // second, and the fixed part no less
    run(&mut connection, 12..=1000);
    assert_eq!(challenges(sent_payloads()), 0);
    run(&mut connection, 1001..=1100);
    assert_eq!(challenges(sent_payloads()), 1);
    take_log();
    // three times the probe timeout of a new path after the first: it
    // gives up, and the candidate ends
    let log = run(&mut connection, 1101..=3200);
    assert!(
        log.iter().any(|line| line == "link path ended: None"),
        "{log:?}"
    );
}

/// The challenges of the 1-RTT datagrams the test links accepted since the
/// last call: the size of each datagram that carries one and its data.
fn sent_challenges() -> Vec<(usize, [u8; 8])> {
    sent_payloads()
        .iter()
        .filter_map(|(size, payload)| challenge_data(payload).map(|data| (*size, data)))
        .collect()
}

/// A PATH_RESPONSE with `data`, then PADDING.
fn path_response(data: [u8; 8]) -> Vec<u8> {
    [&[0x1b][..], &data[..], &[0; 20]].concat()
}

#[test]
fn a_switch_to_an_address_not_validated_challenges_both_link_paths() {
    reset();
    let (first, second) = (link(), link());
    let mut connection = validating_server(&first, []);
    deliver(one_rtt_packet_of(0, 3, &ping()), &second, ms(10));
    let log = run(&mut connection, 10..=12);
    assert!(
        log.iter().any(|line| line.starts_with("Settling")),
        "{log:?}"
    );
    // the new active link path's, held by the limit, and the settling one's,
    // which its own congestion control lets go (RFC 9000 §9.3.3)
    let mut sizes: Vec<_> = sent_challenges().iter().map(|(size, _)| *size).collect();
    sizes.sort_unstable();
    assert_eq!(sizes.len(), 2, "{sizes:?}");
    assert!(sizes[0] < MIN_DATAGRAM_SIZE);
    assert_eq!(sizes[1], MIN_DATAGRAM_SIZE);
}

/// The markings of the datagrams the test links accepted since the last
/// call, those over `link` apart from the others.
fn markings_over(link: &LinkId<(), ()>) -> (Vec<EcnMarking>, Vec<EcnMarking>) {
    let (over, others): (Vec<_>, Vec<_>) = common::take_sent_markings()
        .into_iter()
        .partition(|(each, _)| each == link);
    (
        over.into_iter().map(|(_, marking)| marking).collect(),
        others.into_iter().map(|(_, marking)| marking).collect(),
    )
}

#[test]
fn the_active_link_path_marks_and_a_candidates_probes_do_not() {
    reset();
    common::set_links_mark_ecn(true);
    let (first, second) = (link(), link());
    let mut connection = validating_server(&first, []);
    let (active, _) = markings_over(&first);
    assert!(!active.is_empty());
    assert!(
        active.iter().all(|marking| *marking == EcnMarking::Ect0),
        "{active:?}"
    );
    // a probe from elsewhere: the candidate answers and challenges
    deliver(one_rtt_packet_of(0, 3, &path_challenge()), &second, ms(10));
    run(&mut connection, 10..=11);
    let (candidate, _) = markings_over(&second);
    assert!(!candidate.is_empty());
    assert!(
        candidate
            .iter()
            .all(|marking| *marking == EcnMarking::NotEct),
        "{candidate:?}"
    );
}

#[test]
fn a_link_that_cannot_mark_sends_not_ect() {
    reset();
    let first = link();
    let _connection = validating_server(&first, []);
    let (sent, _) = markings_over(&first);
    assert!(!sent.is_empty());
    assert!(
        sent.iter().all(|marking| *marking == EcnMarking::NotEct),
        "{sent:?}"
    );
}

#[test]
fn after_a_switch_the_new_active_link_path_holds_and_the_settling_one_marks_nothing() {
    reset();
    common::set_links_mark_ecn(true);
    let (first, second) = (link(), link());
    let mut connection = validating_server(&first, []);
    let (marked, _) = markings_over(&first);
    assert!(marked.contains(&EcnMarking::Ect0), "{marked:?}");
    // the client's address changes while marked packets of the first link
    // path are outstanding: the second is active with a new layer, the
    // first settles
    deliver(one_rtt_packet_of(0, 3, &ping()), &second, ms(10));
    let log = run(&mut connection, 10..=12);
    assert!(
        log.iter().any(|line| line.starts_with("Settling")),
        "{log:?}"
    );
    let (settling, active) = markings_over(&first);
    assert!(!settling.is_empty() && !active.is_empty());
    assert!(
        settling
            .iter()
            .all(|marking| *marking == EcnMarking::NotEct),
        "{settling:?}"
    );
    assert!(
        active.iter().all(|marking| *marking == EcnMarking::NotEct),
        "held: {active:?}"
    );
}

#[test]
fn once_the_marked_packets_of_the_old_link_path_are_acknowledged_the_new_active_one_marks_again() {
    use probe::PacketStep::{InstallOneRttKeys, Receive};
    // the new active link path holds while the old one has marked packets
    // outstanding, and marks again once those are acknowledged
    reset();
    common::set_links_mark_ecn(true);
    let (first, second) = (link(), link());
    feed_packets([
        (
            ms(5),
            Receive(received(
                initial_from(&[0xaa; 8], 0, &ping()),
                &first,
                ms(5),
            )),
        ),
        (ms(6), InstallOneRttKeys),
        (
            ms(7),
            Receive(received(
                one_rtt_packet_of(0, 0, &new_connection_id(1)),
                &first,
                ms(7),
            )),
        ),
        // the client's ACK of the server's marked Initial packet
        (
            ms(60),
            Receive(received(
                initial_from(&[0xaa; 8], 2, &{
                    let mut frame = ack_of(&[(0, 0)], true);
                    frame[5] = 1;
                    frame
                }),
                &first,
                ms(60),
            )),
        ),
    ]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    run(&mut connection, 5..=46);
    // the marked 1-RTT packets sent so far
    let sent = common::take_sent();
    let markings = common::take_sent_markings();
    assert_eq!(sent.len(), markings.len());
    let (mut largest, mut marked) = (None, 0);
    for ((_, datagram), (_, marking)) in sent.iter().zip(&markings) {
        if short_header(datagram) {
            largest = Some(open_sent_one_rtt(datagram).1);
            marked += u64::from(*marking == EcnMarking::Ect0);
        }
    }
    let largest = u8::try_from(largest.expect("1-RTT packets were sent")).unwrap();
    assert!(marked > 0);
    // the client's address changes: the second link path is active and
    // holds while marked packets of the first are outstanding
    deliver(one_rtt_packet_of(0, 3, &ping()), &second, ms(50));
    run(&mut connection, 50..=52);
    let (_, held) = markings_over(&first);
    assert!(!held.is_empty());
    assert!(
        held.iter().all(|marking| *marking == EcnMarking::NotEct),
        "held: {held:?}"
    );
    // over the second link path, the client acknowledges every 1-RTT packet
    // sent so far, its ECT(0) count (the byte after the first range) as
    // many as were marked; with the Initial one acknowledged at 60 ms too,
    // no marked packet of the first is outstanding
    let mut frame = ack_of(&[(0, largest)], true);
    frame[5] = u8::try_from(marked).unwrap();
    deliver(one_rtt_packet_of(0, 4, &frame), &second, ms(60));
    // the hold is lifted: the ACK of the client's ping, within the 25 ms of
    // its delay, is marked
    deliver(one_rtt_packet_of(0, 5, &ping()), &second, ms(70));
    run(&mut connection, 60..=100);
    let (_, over_second) = markings_over(&first);
    assert!(over_second.contains(&EcnMarking::Ect0), "{over_second:?}");
}

#[test]
fn the_marked_packets_of_a_link_path_that_ends_after_its_recovery_layer_moved_are_outstanding_no_more()
 {
    use probe::Step::InspectEcn;
    // the first link path's marked packets go with its recovery layer to
    // the second; when the first ends, its packets are handed back as lost,
    // and the layer they went with counts them outstanding no more
    reset();
    common::set_links_mark_ecn(true);
    let (first, second) = (link(), link());
    ADD.with(|a| a.set(Some((ms(10), second.clone()))));
    MOVE.with(|m| m.set(Some((ms(11), first.clone(), second.clone()))));
    feed([
        (ms(12), InspectEcn(second.clone())),
        (ms(14), InspectEcn(second.clone())),
    ]);
    let mut connection = validating_server(&first, []);
    let (marked, _) = markings_over(&first);
    assert!(marked.contains(&EcnMarking::Ect0), "{marked:?}");
    let mut log = run(&mut connection, 10..=12);
    common::end_link(&first);
    log.extend(run(&mut connection, 13..=14));
    assert!(
        log.iter().any(|line| line == "link path ended: None"),
        "{log:?}"
    );
    let ecn: Vec<_> = log
        .into_iter()
        .filter(|line| line.starts_with("ECN"))
        .collect();
    assert_eq!(ecn.len(), 2, "{ecn:?}");
    assert!(
        !ecn[0].contains("marked outstanding 0,"),
        "the moved layer counts the first link path's marked packets: {ecn:?}"
    );
    assert_eq!(
        ecn[1],
        "ECN Unvalidated, marked outstanding 0, over the link given true"
    );
}

/// A marking server over its first link that received the client's Initial
/// packet at 5 ms, its 1-RTT keys at 6 ms and a second connection ID of the
/// client's at 7 ms, whose ACK goes within the 25 ms of its delay, then
/// at 50 ms an ACK frame that acknowledges every 1-RTT packet it sent and
/// reports the ECT(0) count `ect0` gives from how many of those were
/// marked, and `ce` CE. What its first recovery layer logged before and
/// after: its ECN state, then its window.
fn ecn_acknowledged(ect0: impl FnOnce(u64) -> u64, ce: u64) -> Vec<String> {
    use probe::PacketStep::{InstallOneRttKeys, Receive};
    use probe::Step::{Inspect, InspectEcn};
    reset();
    common::set_links_mark_ecn(true);
    let first = link();
    feed([
        (ms(47), InspectEcn(first.clone())),
        (ms(48), Inspect),
        (ms(51), InspectEcn(first.clone())),
        (ms(52), Inspect),
    ]);
    feed_packets([
        (
            ms(5),
            Receive(received(
                initial_from(&[0xaa; 8], 0, &ping()),
                &first,
                ms(5),
            )),
        ),
        (ms(6), InstallOneRttKeys),
        (
            ms(7),
            Receive(received(
                one_rtt_packet_of(0, 0, &new_connection_id(1)),
                &first,
                ms(7),
            )),
        ),
    ]);
    let mut connection = connection!(Mine, AddressValidation::Validated, first.clone());
    run(&mut connection, 5..=46);
    // the 1-RTT packets sent, and how many were marked
    let sent = common::take_sent();
    let markings = common::take_sent_markings();
    assert_eq!(sent.len(), markings.len());
    let mut largest = None;
    let mut marked = 0;
    for ((_, datagram), (_, marking)) in sent.iter().zip(&markings) {
        if short_header(datagram) {
            largest = Some(open_sent_one_rtt(datagram).1);
            marked += u64::from(*marking == EcnMarking::Ect0);
        }
    }
    let largest = u8::try_from(largest.expect("1-RTT packets were sent")).unwrap();
    assert!(marked > 0);
    take_log();
    let mut frame = ack_of(&[(0, largest)], true);
    // the counts follow the one range
    frame[5] = u8::try_from(ect0(marked)).unwrap();
    frame[7] = u8::try_from(ce).unwrap();
    let log = run(&mut connection, 47..=48);
    deliver(one_rtt_packet_of(0, 1, &frame), &first, ms(50));
    let after = run(&mut connection, 50..=52);
    log.into_iter()
        .chain(after)
        .filter(|line| line.starts_with("ECN") || line.starts_with("rtt"))
        .collect()
}

/// The window of an `Inspect` line.
fn window_of(line: &str) -> usize {
    let (_, rest) = line.split_once("window ").unwrap();
    rest.split(',').next().unwrap().parse().unwrap()
}

#[test]
fn counts_that_cover_the_marked_packets_an_ack_frame_acknowledges_make_the_link_path_capable() {
    let log = ecn_acknowledged(|marked| marked, 0);
    assert_eq!(log.len(), 4, "{log:?}");
    // its Initial packet is marked too, and not acknowledged
    assert_eq!(
        log[0],
        "ECN Unvalidated, marked outstanding 2, over the link given true"
    );
    assert_eq!(
        log[2],
        "ECN Capable, marked outstanding 1, over the link given true"
    );
}

#[test]
fn counts_short_of_the_marked_packets_an_ack_frame_acknowledges_fail_the_validation() {
    let log = ecn_acknowledged(|_| 0, 0);
    assert_eq!(
        log[2], "ECN Failed, marked outstanding 1, over the link given true",
        "{log:?}"
    );
}

#[test]
fn every_marked_packet_an_ack_frame_acknowledges_reported_ce_fails_an_unvalidated_link_path() {
    let log = ecn_acknowledged(|marked| marked - 1, 1);
    assert_eq!(
        log[2], "ECN Failed, marked outstanding 1, over the link given true",
        "{log:?}"
    );
}

#[test]
fn an_increase_of_the_ce_count_is_a_congestion_event_of_the_marking_link_path() {
    let without = ecn_acknowledged(|marked| marked, 0);
    // one more counted CE than newly acknowledged: an ACK frame before was
    // lost, and the counts may exceed what this one acknowledges
    let with = ecn_acknowledged(|marked| marked, 1);
    assert_eq!(
        with[2], "ECN Capable, marked outstanding 1, over the link given true",
        "{with:?}"
    );
    assert!(
        window_of(&with[3]) < window_of(&without[3]),
        "{with:?} {without:?}"
    );
}

#[test]
fn a_validation_of_the_active_link_path_that_gives_up_reverts_to_the_settling_fallback() {
    reset();
    let (first, second) = (link(), link());
    let mut connection = validating_server(&first, []);
    // a copy of the client's packet arrives from elsewhere first
    deliver(one_rtt_packet_of(0, 3, &ping()), &second, ms(10));
    run(&mut connection, 10..=12);
    // the client, still where it was, answers the challenge of its old path
    let settling = sent_challenges()
        .into_iter()
        .find(|(size, _)| *size == MIN_DATAGRAM_SIZE)
        .expect("the settling link path challenges")
        .1;
    deliver(
        one_rtt_packet_of(0, 4, &path_response(settling)),
        &first,
        ms(13),
    );
    run(&mut connection, 13..=14);
    take_log();
    // nothing answers the new link path's: it gives up three probe
    // timeouts of a new path after its first challenge, and the settling
    // link path, validated, is active again
    let log = run(&mut connection, 15..=3200);
    assert!(
        log.iter()
            .any(|line| line == "Active, Validated, credit None"),
        "{log:?}"
    );
    assert!(
        log.iter().any(|line| line == "link path ended: None"),
        "{log:?}"
    );
    assert!(
        !log.iter().any(|line| line.starts_with("recovery built")),
        "the fallback keeps its recovery layer: {log:?}"
    );
}

/// A server whose client moved to `second` with a non-probing packet at 10
/// ms, which answers the challenge of the new link path, held below 1200
/// bytes by the anti-amplification limit, at 13 ms, and the old one's too
/// when `answer_old`: the new address is validated, its ability to carry
/// 1200 bytes is not yet. What it logged since is taken.
fn moved_and_validated_short(
    first: &LinkId<(), ()>,
    second: &LinkId<(), ()>,
    answer_old: bool,
) -> impl Future<Output = ()> + Unpin {
    let mut connection = validating_server(first, []);
    deliver(one_rtt_packet_of(0, 3, &ping()), second, ms(10));
    run(&mut connection, 10..=12);
    let challenges = sent_challenges();
    let new = challenges
        .iter()
        .find(|(size, _)| *size < MIN_DATAGRAM_SIZE)
        .expect("the new link path's challenge is held by the limit")
        .1;
    deliver(one_rtt_packet_of(0, 4, &path_response(new)), second, ms(13));
    if answer_old {
        let old = challenges
            .iter()
            .find(|(size, _)| *size == MIN_DATAGRAM_SIZE)
            .expect("the settling link path challenges")
            .1;
        deliver(one_rtt_packet_of(0, 5, &path_response(old)), first, ms(13));
    }
    run(&mut connection, 13..=14);
    // the second validation of the new link path expands its challenge
    assert!(
        sent_challenges()
            .iter()
            .any(|(size, _)| *size >= MIN_DATAGRAM_SIZE),
        "the new link path validates its ability to carry 1200 bytes"
    );
    take_log();
    connection
}

#[test]
fn a_new_link_path_that_cannot_carry_1200_bytes_reverts_to_the_fallback() {
    reset();
    let (first, second) = (link(), link());
    let mut connection = moved_and_validated_short(&first, &second, true);
    // nothing answers the expanded challenge: the path is unusable, and the
    // validated link path it moved from is active again (RFC 9000 §14)
    let log = run(&mut connection, 15..=4000);
    assert!(
        log.iter()
            .any(|line| line == "Active, Validated, credit None"),
        "{log:?}"
    );
    assert!(
        log.iter().any(|line| line == "link path ended: None"),
        "{log:?}"
    );
    assert!(
        !log.iter()
            .any(|line| line.contains("PathValidationFailed") || line.contains("NoViablePath")),
        "{log:?}"
    );
}

#[test]
fn a_new_link_path_that_cannot_carry_1200_bytes_with_no_fallback_closes_with_no_viable_path() {
    reset();
    let (first, second) = (link(), link());
    // the client does not answer at its old address either: that link path
    // ends when its own validation gives up, and nothing is left to revert
    // to
    let mut connection = moved_and_validated_short(&first, &second, false);
    // the connection closes, sending its close, and ends once it closed
    // for three probe timeouts
    let outer = Outer::new();
    let ended = (15..=10_000).find(|at| {
        advance_to(ms(*at));
        outer.poll(&mut connection).is_ready()
    });
    assert!(ended.is_some(), "the connection ends");
    let log = take_log();
    assert!(
        log.iter().any(|line| line.starts_with("Closing")),
        "a close is sent: {log:?}"
    );
    assert!(
        log.iter().any(|line| line.contains("NoViablePath")),
        "{log:?}"
    );
    assert!(
        !log.iter().any(|line| line.contains("PathValidationFailed")),
        "the connection does not close silently: {log:?}"
    );
}

#[test]
fn a_validation_given_up_with_a_late_timer_still_finds_its_fallback() {
    reset();
    let (first, second) = (link(), link());
    let mut connection = validating_server(&first, []);
    deliver(one_rtt_packet_of(0, 3, &ping()), &second, ms(10));
    run(&mut connection, 10..=12);
    let settling = sent_challenges()
        .into_iter()
        .find(|(size, _)| *size == MIN_DATAGRAM_SIZE)
        .expect("the settling link path challenges")
        .1;
    deliver(
        one_rtt_packet_of(0, 4, &path_response(settling)),
        &first,
        ms(13),
    );
    run(&mut connection, 13..=2500);
    take_log();
    // the driver wakes well past the instant the new link path's validation
    // gives up at, and past the one granularity the fallback was held for:
    // both come due in one turn, and the fallback is still there to revert
    // to (RFC 9000 §9.3.2)
    let log = run(&mut connection, 3300..=3301);
    assert!(
        log.iter()
            .any(|line| line == "Active, Validated, credit None"),
        "{log:?}"
    );
    assert!(
        !log.iter().any(|line| line.contains("PathValidationFailed")),
        "{log:?}"
    );
}

#[test]
fn a_validation_of_the_active_link_path_that_gives_up_with_no_fallback_closes_silently() {
    reset();
    let (first, second) = (link(), link());
    // the first address was never validated: once the peer moves, there is
    // no validated address to return to
    let mut connection = validating_server_of(&first, AddressValidation::NotValidated, []);
    deliver(one_rtt_packet_of(0, 3, &ping()), &second, ms(10));
    let log = run(&mut connection, 10..=12);
    assert!(
        log.iter().any(|line| line.starts_with("Settling")),
        "{log:?}"
    );
    // nothing answers either challenge: the active link path's validation
    // gives up three probe timeouts of a new path after its first
    // challenge, and the connection ends there and then
    let outer = Outer::new();
    let ended = (13..=5000).find(|at| {
        advance_to(ms(*at));
        outer.poll(&mut connection).is_ready()
    });
    let ended = ended.expect("the connection ends");
    assert!(ended > 3000, "{ended}");
    let log = take_log();
    let aborted = "link path ended: Some(Aborted(PathValidationFailed))";
    assert!(log.iter().any(|line| line == aborted), "{log:?}");
    assert!(
        !log.iter().any(|line| line.starts_with("Closing")),
        "no close is sent: {log:?}"
    );
    // what was sent until then challenged, and nothing closed
    let sent = sent_payloads();
    assert!(
        sent.iter()
            .all(|(_, payload)| challenge_data(payload).is_some()),
        "only challenges: {sent:?}"
    );
}

#[test]
fn a_switch_that_waits_for_validation_starts_with_the_rtt_of_the_challenge() {
    reset();
    common::set_migration(
        common::TestAdmission::Accept,
        v1::migration::SwitchTiming::AfterValidation,
    );
    let (first, second) = (link(), link());
    let mut connection = validating_server(&first, []);
    deliver(one_rtt_packet_of(0, 3, &ping()), &second, ms(10));
    run(&mut connection, 10..=13);
    // the candidate's, accepted at 11 ms, and the active link path's (RFC
    // 9000 §9.3.3)
    let challenges = sent_challenges();
    assert_eq!(challenges.len(), 2, "{challenges:?}");
    let candidate = challenges
        .iter()
        .find(|(size, _)| *size < MIN_DATAGRAM_SIZE)
        .expect("the candidate's is held by the limit")
        .1;
    take_log();
    // answered over the candidate 4 ms after it was sent
    deliver(
        one_rtt_packet_of(0, 4, &path_response(candidate)),
        &second,
        ms(15),
    );
    let log = run(&mut connection, 15..=17);
    assert!(
        log.iter()
            .any(|line| line == "recovery built, initial RTT Some(4ms)"),
        "{log:?}"
    );
    assert!(
        log.iter().any(|line| line.starts_with("Settling")),
        "{log:?}"
    );
}

#[test]
fn a_switch_that_waits_for_validation_waits_no_more_once_the_peer_comes_back() {
    reset();
    common::set_migration(
        common::TestAdmission::Accept,
        v1::migration::SwitchTiming::AfterValidation,
    );
    let (first, second) = (link(), link());
    let mut connection = validating_server(&first, []);
    deliver(one_rtt_packet_of(0, 3, &ping()), &second, ms(10));
    run(&mut connection, 10..=13);
    let challenges = sent_challenges();
    let candidate = challenges
        .iter()
        .find(|(size, _)| *size < MIN_DATAGRAM_SIZE)
        .expect("the candidate's is held by the limit")
        .1;
    // the peer's non-probing packet of the largest number comes over the
    // active link path again (RFC 9000 §9.3)
    deliver(one_rtt_packet_of(0, 4, &ping()), &first, ms(14));
    run(&mut connection, 14..=14);
    take_log();
    // the candidate's validation still goes through, and nothing switches
    deliver(
        one_rtt_packet_of(0, 5, &path_response(candidate)),
        &second,
        ms(15),
    );
    let log = run(&mut connection, 15..=17);
    assert!(
        !log.iter()
            .any(|line| line.starts_with("Settling") || line.starts_with("recovery built")),
        "{log:?}"
    );
    // a later non-probing packet of a new largest number over the
    // validated candidate switches to it as any does, challenging nothing
    sent_challenges();
    deliver(one_rtt_packet_of(0, 6, &ping()), &second, ms(18));
    let log = run(&mut connection, 18..=20);
    assert!(
        log.iter().any(|line| line.starts_with("Settling")),
        "{log:?}"
    );
    assert_eq!(sent_challenges(), []);
}

/// A server whose migration policy switches after validation, and gives a
/// new path 6 s to answer: the client's non-probing packet from `second` at
/// 10 ms makes a candidate there wait for its validation, and the active
/// link path over `first` is challenged too (RFC 9000 §9.3.3). Nobody
/// answers the active one's: its validation gives up about 3 s later, the
/// candidate's still under way. The candidate's challenge data is
/// returned; what was logged until 3500 ms is taken.
fn awaiting_while_the_active_fails(
    first: &LinkId<(), ()>,
    second: &LinkId<(), ()>,
) -> (impl Future<Output = ()> + Unpin, [u8; 8]) {
    common::set_migration(
        common::TestAdmission::Accept,
        v1::migration::SwitchTiming::AfterValidation,
    );
    common::set_new_path_abandon(Some(ms(6000)));
    let mut connection = validating_server(first, []);
    deliver(one_rtt_packet_of(0, 3, &ping()), second, ms(10));
    run(&mut connection, 10..=13);
    let candidate = sent_challenges()
        .iter()
        .find(|(size, _)| *size < MIN_DATAGRAM_SIZE)
        .expect("the candidate's is held by the limit")
        .1;
    let log = run(&mut connection, 14..=3500);
    assert!(
        !log.iter().any(|line| line.contains("PathValidationFailed")),
        "the active link path failing closes nothing while the candidate is validated: {log:?}"
    );
    (connection, candidate)
}

#[test]
fn an_active_link_path_that_fails_while_a_switch_waits_gives_way_to_the_candidate_validated() {
    reset();
    let (first, second) = (link(), link());
    let (mut connection, candidate) = awaiting_while_the_active_fails(&first, &second);
    deliver(
        one_rtt_packet_of(0, 4, &path_response(candidate)),
        &second,
        ms(3501),
    );
    let log = run(&mut connection, 3501..=3503);
    assert!(
        log.iter().any(|line| line.starts_with("recovery built")),
        "the switch is made: {log:?}"
    );
    // the active link path failed: it is not the fallback, and nothing ends
    // the connection
    let log = run(&mut connection, 3504..=9000);
    assert!(
        !log.iter().any(|line| line.contains("PathValidationFailed")),
        "{log:?}"
    );
}

#[test]
fn a_switch_that_waits_past_the_active_link_paths_failure_waits_on_when_the_peer_comes_back() {
    reset();
    let (first, second) = (link(), link());
    let (mut connection, candidate) = awaiting_while_the_active_fails(&first, &second);
    // the peer's non-probing packet of the largest number over the failed
    // active link path: the switch still decides whether the connection
    // goes on, and keeps waiting
    deliver(one_rtt_packet_of(0, 4, &ping()), &first, ms(3501));
    run(&mut connection, 3501..=3502);
    deliver(
        one_rtt_packet_of(0, 5, &path_response(candidate)),
        &second,
        ms(3503),
    );
    let log = run(&mut connection, 3503..=3505);
    assert!(
        log.iter().any(|line| line.starts_with("recovery built")),
        "the switch is made: {log:?}"
    );
}

#[test]
fn an_active_link_path_that_fails_while_a_switch_waits_closes_silently_once_the_candidate_fails_too()
 {
    reset();
    let (first, second) = (link(), link());
    let (mut connection, _) = awaiting_while_the_active_fails(&first, &second);
    // nobody answers the candidate either: it gives up 6 s after its
    // challenge, and no validated address is left (RFC 9000 §9.3.2)
    let outer = Outer::new();
    let ended = (3501..=10_000).find(|at| {
        advance_to(ms(*at));
        outer.poll(&mut connection).is_ready()
    });
    let ended = ended.expect("the connection ends");
    assert!(ended > 6000, "{ended}");
    let log = take_log();
    let aborted = "link path ended: Some(Aborted(PathValidationFailed))";
    assert!(log.iter().any(|line| line == aborted), "{log:?}");
}

#[test]
fn a_challenge_counts_as_sent_when_the_link_accepted_it() {
    reset();
    common::set_migration(
        common::TestAdmission::Accept,
        v1::migration::SwitchTiming::AfterValidation,
    );
    // the links accept 2 ms past the instant the driver's turn read
    common::set_accepted_after(ms(2));
    let (first, second) = (link(), link());
    let mut connection = validating_server(&first, []);
    deliver(one_rtt_packet_of(0, 3, &ping()), &second, ms(10));
    run(&mut connection, 10..=13);
    let candidate = sent_challenges()
        .iter()
        .find(|(size, _)| *size < MIN_DATAGRAM_SIZE)
        .expect("the candidate's is held by the limit")
        .1;
    take_log();
    // sent in the turn at 11 ms, accepted at 13 ms, answered 4 ms later
    deliver(
        one_rtt_packet_of(0, 4, &path_response(candidate)),
        &second,
        ms(17),
    );
    let log = run(&mut connection, 17..=19);
    assert!(
        log.iter()
            .any(|line| line == "recovery built, initial RTT Some(4ms)"),
        "{log:?}"
    );
}

#[test]
fn a_challenge_goes_again_no_sooner_than_the_probe_timeout_whatever_the_policy_says() {
    reset();
    common::set_challenge_resend(Some(ms(1)));
    let (first, second) = (link(), link());
    let mut connection = validating_server(&first, []);
    let probe = padded(
        &[],
        |payload| one_rtt_packet_of(0, 3, payload),
        &path_challenge(),
    );
    deliver(probe, &second, ms(10));
    run(&mut connection, 10..=11);
    assert_eq!(sent_challenges().len(), 1);
    // the probe timeout of a new path, about a second, holds the next
    run(&mut connection, 12..=1000);
    assert_eq!(sent_challenges().len(), 0);
}
