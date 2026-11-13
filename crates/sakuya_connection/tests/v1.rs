//! Version 1's components on the tree: what the connection is made with,
//! the entries of its logical links and the roles of its link paths.
#![feature(impl_trait_in_assoc_type, yield_expr)]

mod common;

use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    fmt::Debug,
    num::NonZeroUsize,
    sync::Arc,
    time::Duration,
};

use bytes::BytesMut;
use common::{Mine, Outer, TestClock, TestLink, TestReceiver, advance_to, log, ms, take_log};
use frunk_core::coproduct::CoproductSelector;
use frunk_core::hlist_pat;
use sakuya_connection::{
    call::CallBundle,
    clock::{ConnectionChoices, InstantOf},
    component::{ArgsOf, Build, DataComponent, LineageOf, ParentsOf, ReadSet, RequestOf},
    dispatch::{DispatchFacts, FrameDispatch, FrameSetDispatch},
    driver::ConnectionDriver,
    error::ConnectionErrorsOf,
    feedback::{FeedbackSummaryPart, SendFeedback},
    layer::{self, EstablishedArgs, LinkPathArgs, LogicalPathArgs, NodeKey},
    others::OtherNodes,
    request::StructureRequest,
    share::{
        FlatMut, FlatRef, LayerShare, LineageLists, LineagePartList, LinkPathIdentifierOf,
        LogicalPathKeyShare, LogicalPathKeys, NodeData, PartList, SoleLogicalPath,
    },
    take::{GetAt, Lineage, Take, TakeEach},
    v1::{
        self, CloseCauseOf,
        aead_usage::AeadUsage,
        amplification::{AddressValidation, AntiAmplification, AntiAmplificationFactor},
        close::{CloseReasonRecord, LocalCloseCause},
        confirmation::HandshakeConfirmation,
        crypto::{CryptoReceiveCapacities, CryptoReceiver, FragmentedCryptoReceiveBuffer},
        feedback::AckSummary,
        first_flight::{
            FirstFlight, FirstFlightReadState, ReadFirstFlightError, read_first_flight,
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
        role::LinkPathRole,
        spaces::{AckObligationsOf, SendJournalsOf},
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
        router::DatagramRouter,
    },
};
use sakuya_link::{ArrivalFacts, BindingId, LinkId, MIN_DATAGRAM_SIZE, ReceivedDatagram};
use sakuya_packet_protection::{
    backend::{AeadAlgorithm, KdfAlgorithm, ring::RingBackend},
    header_protection::HeaderProtectionKey,
    initial::{INITIAL_AEAD, InitialSecrets},
    secret::TrafficSecret,
};
use sakuya_recovery::{
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
use sakuya_stream::connection::CloseReason;
use sakuya_tls::{engine::CryptoLevel, message::MessageLimits};
use sakuya_wire::{
    connection_id::{ConnectionId, ConnectionIdLength, NonEmptyCid},
    parameters::ParametersPart,
    parts::{CNil, CoprodInjector, CoprodUninjector, Coproduct, HList, HNil, PartsError, Selector},
    v1::frame::{
        FrameType,
        set::{FrameSet, FrameSetPart, FrameTypeValues},
    },
    v1::packet_number::PacketNumber,
    v1::protected_packet::{Packet, into_packets},
    v1::transport_parameters::{
        TransportParameterSlots, TransportParameterSpace, TransportParameters,
        integer::MaxIdleTimeout,
    },
    var_int::VarInt,
    version::Version,
};

const PATH: SoleLogicalPath = SoleLogicalPath;

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
    /// What the packet feeder of the next server connection's logical path
    /// does, and when.
    static PACKETS: RefCell<VecDeque<(Duration, probe::PacketStep)>> = const { RefCell::new(VecDeque::new()) };
    /// How many ACK ranges the receive journals of the next connection keep.
    static MAX_ACK_RANGES: Cell<MaxAckRanges> = const { Cell::new(MaxAckRanges::DEFAULT) };
    /// How many inputs the receiving call of the next connection handles in
    /// one poll.
    static MAX_PER_POLL: Cell<usize> = const { Cell::new(16) };
    /// How many inputs a logical path of the next connection holds.
    static MAX_HELD: Cell<usize> = const { Cell::new(16) };
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
}

/// The parts of the tests' connections.
type Parts = HList![v1::Part, probe::Part];

fn link() -> LinkId<(), ()> {
    LinkId::new::<()>((), (), &BindingId::new())
}

fn reset() {
    take_log();
    advance_to(ms(0));
    ADD.with(|a| a.set(None));
    CLOSE_AT.with(|c| c.set(None));
    DRAIN.with(|d| d.set(false));
    PEER_AT.with(|p| p.set(None));
    LEND_AT.with(|p| p.set(None));
    FEED.with(|f| f.borrow_mut().clear());
    CLOSER.with(|c| c.borrow_mut().clear());
    CRYPTO_AT.with(|c| c.set(None));
    PACKETS.with(|p| p.borrow_mut().clear());
    MAX_ACK_RANGES.with(|m| m.set(MaxAckRanges::DEFAULT));
    MAX_PER_POLL.with(|m| m.set(16));
    MAX_HELD.with(|m| m.set(16));
    FIRST_DATAGRAMS.with(|f| f.borrow_mut().clear());
    FIRST_READ.with(|f| f.set(false));
    READ_STATE.with(|r| r.borrow_mut().take());
    RIVAL.with(|r| r.set(false));
    ROUTING.with(|r| r.borrow_mut().take());
}

/// A datagram of the tests, as it arrived.
type Datagram = ReceivedDatagram<BytesMut, TestLink>;
/// What routing gives a deliverer of the tests.
type Delivery =
    DatagramDelivery<Datagram, (), sakuya_datagram_routing::claim::finish::ReleaseUnclaimed>;
/// The deliverers of the tests' routing domain.
type Target = dyn ErasedDatagramDeliverer<Datagram, ()>;

/// A deliverer that posts to a connection's receiver.
struct Posting(DatagramDeliveryPoster<Delivery>);
impl DatagramDeliverer<Datagram, ()> for Posting {
    fn deliver(&self, delivery: Delivery) {
        self.0.post(delivery);
    }
}

/// A routing domain with one route entry, the client's first Destination
/// Connection ID, for every packet form; it reads short headers with
/// 8-byte connection IDs.
struct TestRouting {
    router: DatagramRouter<BytesMut, TestLink, Target, ConnectionIdLengths>,
    _registration: RouteEntryRegistration<Target, ()>,
    /// When there is a rival: its entry for the same connection ID, and
    /// its receiver, which keeps every candidate it is given and never
    /// judges one.
    _rival: Option<(RouteEntryRegistration<Target, ()>, TestReceiver)>,
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
    let queue = DatagramDeliveryQueue::new(NonZeroUsize::new(64).expect("not zero"))
        .expect("a capacity a queue can have");
    let index = RouteIndex::<Target, ()>::new();
    let registration = index.register(
        RouteMatcher::new(
            MatchAssociation::LocalCid(NonEmptyCid::new(client_dcid()).expect("not empty")),
            PacketForms::ALL,
            Version::V1,
        ),
        Arc::new(Posting(queue.poster())) as Arc<Target>,
    );
    let rival = RIVAL.with(Cell::get).then(|| {
        let queue = DatagramDeliveryQueue::new(NonZeroUsize::new(64).expect("not zero"))
            .expect("a capacity a queue can have");
        let registration = index.register(
            RouteMatcher::new(
                MatchAssociation::LocalCid(NonEmptyCid::new(client_dcid()).expect("not empty")),
                PacketForms::ALL,
                Version::V1,
            ),
            Arc::new(Posting(queue.poster())) as Arc<Target>,
        );
        (registration, queue)
    });
    let router = DatagramRouter::new(
        index,
        ConnectionIdLengths::new([ConnectionIdLength::new(8).expect("a length")]),
    );
    ROUTING.with(|r| {
        *r.borrow_mut() = Some(TestRouting {
            router,
            _registration: registration,
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
impl v1::Choices for ClientMine {
    type Crypto = RingBackend;
    type Side = v1::Client;
    type CryptoReceiveBuffer = FragmentedCryptoReceiveBuffer;
    type Recovery<V: Clone + Eq + Debug + 'static> =
        sakuya_recovery::factory::NewRenoRecoveryFactory<V>;
    type AckObligation = sakuya_recovery::ack_obligation::Rfc9000AckObligation<Duration>;
    type SendJournals<S: 'static, P: Clone + Eq + Debug + 'static> =
        sakuya_recovery::send_journals::DequeSendJournals<Duration, S, P>;
    type ApplicationError = common::AppClose;
    type HandshakeFailure = core::convert::Infallible;
    type Receiver = TestReceiver;
}

/// The choices of a server whose recovery factory logs the other link
/// paths it is shown when it lends.
struct SpyMine;
impl ConnectionChoices for SpyMine {
    type Clock = TestClock;
    type Link = TestLink;
}
impl v1::Choices for SpyMine {
    type Crypto = RingBackend;
    type Side = v1::Server;
    type CryptoReceiveBuffer = FragmentedCryptoReceiveBuffer;
    type Recovery<V: Clone + Eq + Debug + 'static> = spy::SpyFactory<V>;
    type AckObligation = sakuya_recovery::ack_obligation::Rfc9000AckObligation<Duration>;
    type SendJournals<S: 'static, P: Clone + Eq + Debug + 'static> =
        sakuya_recovery::send_journals::DequeSendJournals<Duration, S, P>;
    type ApplicationError = common::AppClose;
    type HandshakeFailure = core::convert::Infallible;
    type Receiver = TestReceiver;
}

/// A recovery factory that makes what sakuya's makes and logs, when it
/// lends, the other link paths it sees.
mod spy {
    use super::*;
    use sakuya_connection::v1::recovery::OtherCongestionParts;
    use sakuya_link::EcnMarking;
    use sakuya_recovery::{
        congestion::{
            CongestionContext, CongestionController, InFlightPacket, RemovedPacket,
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
        fn on_packet_sealed(&mut self, bytes: usize, app_limited: bool, now: Duration) {
            self.0.on_packet_sealed(bytes, app_limited, now);
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
            self.0.on_removed(packets, context);
        }
        fn on_max_datagram_size_changed(
            &mut self,
            new: usize,
            handshake_confirmed: bool,
            context: &CongestionContext<Duration>,
        ) {
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
        fn refill(&mut self, at: Duration, input: PacingInput) {
            self.0.refill(at, input);
        }
        fn on_charged(&mut self, bytes: usize) {
            self.0.on_charged(bytes);
        }
    }
    impl PtoPolicy<Duration> for Logged<'_> {
        fn on_pto_expired(&mut self, expiry: &PtoExpiry<Duration>) -> PtoAction {
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
    impl sakuya_connection::error::ConnectionErrorPart for Part {
        type ConnectionError = core::convert::Infallible;
    }
    impl ParametersPart<TransportParameterSpace> for Part {
        type Parameters = HNil;
    }

    /// The summary of a frame the probe writes, as the tests number it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Summary(pub u64);
    impl FeedbackSummaryPart for Part {
        type FeedbackSummary<I> = Summary;
    }
    /// The probe logs what comes back of its summaries.
    impl<T: ConnectionChoices, L: PartList<T>, V> SendFeedback<T, L, V, ()> for Part {
        fn delivered<B: CallBundle>(
            _: &mut Lineage<'_, V>,
            _: &mut OtherNodes<'_, T, L, B>,
            space: PacketNumberSpaceKind,
            summary: Summary,
        ) {
            log(format!("delivered {space:?} {}", summary.0));
        }
        fn lost<B: CallBundle>(
            _: &mut Lineage<'_, V>,
            _: &mut OtherNodes<'_, T, L, B>,
            space: PacketNumberSpaceKind,
            summary: &Summary,
        ) {
            log(format!("lost {space:?} {}", summary.0));
        }
    }

    const NO_FRAME_TYPES: FrameTypeValues = FrameTypeValues::new(&[]);

    /// The probe claims no frames.
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
        fn reads(reads: &mut ReadSet) {
            reads.add::<InitialKeys<RingBackend>>();
        }
        fn deadline<'v>(lineage: &LineageOf<'v, T, L, layer::Connection>) -> Option<Duration> {
            lineage.get::<Adder, I>().0.as_ref().map(|(at, _)| *at)
        }
        fn expire<'v, B: CallBundle>(
            lineage: LineageOf<'v, T, L, layer::Connection>,
            _: &mut OtherNodes<'v, T, L, B>,
            _: Duration,
        ) -> Option<RequestOf<T, L>> {
            let (hlist_pat![adder], _) = Take::<HList![Adder], K>::take(lineage);
            let (_, second) = adder.0.take()?;
            Some(StructureRequest::AddLinkPath {
                args: LinkPathArgs {
                    path: PATH,
                    link: TestLink(second),
                },
            })
        }
        fn reread<'v, B: CallBundle>(
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
            let (hlist_pat![setter, peer, idle], _) = Take::<
                HList![
                    PeerSetter,
                    PeerTransportParameters<TransportParameterSlots<Parts>>,
                    IdleTimeout<Duration>
                ],
                K,
            >::take(lineage);
            setter.0 = None;
            let mut slots =
                TransportParameters::<Vec<u8>, HList![sakuya_wire::v1::Part]>::new().known;
            *slots.get_mut::<Option<MaxIdleTimeout>, _>() =
                Some(MaxIdleTimeout::new(VarInt::from_u32(10_000)));
            peer.set_known(slots);
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
            let (hlist_pat![feeder, receiver], _) = Take::<
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
        /// Log the CRYPTO data ready at the level being read; the largest
        /// packet number, the ranges and the ACK obligation of the Initial
        /// space; the idle timeout's deadline; and the reason for closing.
        Inspect,
        /// Log how many inputs the logical path holds, and the largest
        /// packet number processed in the Handshake space.
        InspectHeld,
        /// Log the credit of the anti-amplification limit of the logical
        /// link, as if its address were not validated.
        InspectCredit(LinkId<(), ()>),
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
    impl<T, L, I, Ii, Ih, Io, Ij, Im, Ia, It, Iu, Ikp, Ir, Ie, Ik, Hd, Ic, Icr, Ip, Ian>
        DataComponent<
            T,
            L,
            layer::LogicalPath,
            (
                I,
                (Ii, Ih, Io),
                (Ij, Im, Ia, It, Iu, Ikp),
                (Ir, Ie, Ik, Hd),
                (Ic, Icr),
                (Ip, Ian),
            ),
        > for PacketFeeder
    where
        T: v1::Choices<
                Clock = TestClock,
                Link = TestLink,
                Crypto = RingBackend,
                CryptoReceiveBuffer = FragmentedCryptoReceiveBuffer,
            >,
        L: LineagePartList<T> + FrameSetDispatch<T, L, Hd>,
        CloseCauseOf<T, L>: Debug,
        <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<v1::error::ConnectionError, Ie>
            + CoprodUninjector<v1::error::ConnectionError, Ie>,
        <L as FrameSet>::Kind: CoproductSelector<FrameType, Ik>,
        for<'v> <L as LineageLists<'v, T>>::LogicalPath: GetAt<PacketFeeder, I>
            + GetAt<InitialKeys<RingBackend>, Ii>
            + GetAt<HandshakeKeys<RingBackend>, Ih>
            + GetAt<OneRttKeys<RingBackend, Duration>, Io>
            + GetAt<PacketNumberSpaces<ReceiveJournals<Duration>>, Ij>
            + GetAt<MaxAckRanges, Im>
            + GetAt<AckObligationsOf<T>, Ia>
            + GetAt<IdleTimeout<Duration>, It>
            + GetAt<AeadUsage, Iu>
            + GetAt<KeyPhaseNumbers, Ikp>
            + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>
            + GetAt<CryptoReceiver<FragmentedCryptoReceiveBuffer>, Icr>
            + GetAt<LogicalPathInput<TestLink, T::Receiver>, Ip>,
        for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
        for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
            GetAt<LinkPathRole<Duration>, Ir>,
        for<'s> NodeData<T, L, layer::LinkEntry>: FlatMut<'s>,
        for<'s> <NodeData<T, L, layer::LinkEntry> as FlatMut<'s>>::Out:
            TakeEach<'s, HList![AntiAmplification], Ian>,
    {
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
                    >(&mut lineage, others, packet);
                    log(describe::<L, Ie>(outcome));
                }
                PacketStep::InstallHandshakeKeys => {
                    let secrets = InitialSecrets::derive(&RingBackend, &client_dcid());
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
                }
                PacketStep::InstallOneRttSendKeys => {
                    let secrets = InitialSecrets::derive(&RingBackend, &client_dcid());
                    lineage
                        .get_mut::<OneRttKeys<RingBackend, Duration>, Io>()
                        .install_send(RingBackend, INITIAL_AEAD, secrets.server);
                }
                PacketStep::InstallOneRttKeys => {
                    lineage
                        .get_mut::<OneRttKeys<RingBackend, Duration>, Io>()
                        .install(RingBackend, ONE_RTT_AEAD, server_secret(), client_secret());
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
        L::ConnectionErrors: CoprodUninjector<v1::error::ConnectionError, Ie>,
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
            Ok(PacketOutcome::Dropped(reason)) => format!(
                "dropped: {}",
                match reason {
                    DropReason::NoLinkPath => "no link path".into(),
                    DropReason::Draining => "draining".into(),
                    DropReason::TokenFromServer => "token from the server".into(),
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
            let (hlist_pat![closer, record], _) = Take::<
                HList![Closer, CloseReasonRecord<CloseCauseOf<Mine, Parts>>],
                K,
            >::take(lineage);
            let (_, step) = closer.0.pop_front()?;
            match step {
                CloserStep::Establish => Some(StructureRequest::AddEstablished {
                    args: EstablishedArgs::default(),
                }),
                CloserStep::Close => {
                    record.record(CloseReason::Local(Arc::new(LocalCloseCause::Application(
                        common::AppClose(7),
                    ))));
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
            let (hlist_pat![lender, factory], _) =
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
                let hlist_pat![role] =
                    others.link_path::<HList![LinkPathRole<Duration>], Kl>(&PATH, &second)?;
                *role = LinkPathRole::Active;
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
            others.with_recovery_at::<HList![CongestionPartOf<SpyMine, Parts>], Ir, _>(
                &PATH,
                &first,
                |hlist_pat![part], rest| {
                    lend_congestion::<SpyMine, Parts, B, Ji, Jr, _>(
                        factory,
                        part,
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
        fn reads(reads: &mut ReadSet) {
            reads.add::<LinkPathRole<Duration>>();
        }
        fn deadline<'v>(lineage: &LineageOf<'v, T, L, layer::LinkPath>) -> Option<Duration> {
            lineage.get::<Watcher, I>().0
        }
        fn expire<'v, B: CallBundle>(
            lineage: LineageOf<'v, T, L, layer::LinkPath>,
            _: &mut OtherNodes<'v, T, L, B>,
            now: Duration,
        ) -> Option<RequestOf<T, L>> {
            let (hlist_pat![watcher, role], _) =
                Take::<HList![Watcher, LinkPathRole<Duration>], N>::take(lineage);
            watcher.0 = None;
            if DRAIN.with(Cell::get) {
                role.drain(now + ms(30));
            } else {
                role.close(now + ms(30));
            }
            None
        }
        fn reread<'v, B: CallBundle>(
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
        /// take: a reread sees only what it left.
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
        ProbeTimeout<Duration>
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
        impl<I, Ith, K, Jd, Js, Jp>
            DataComponent<$t, Parts, layer::Recovery, (I, Ith, K, (Jd, Js, Jp))> for Feeder
        where
            for<'v> <Parts as LineageLists<'v, $t>>::Recovery: GetAt<Feeder, I>
                + GetAt<LossThresholds, Ith>
                + GetAt<LossDetectionOf<$t, Parts>, Jd>
                + GetAt<LinkPathCongestionState<Duration>, Js>
                + GetAt<ProbeTimeout<Duration>, Jp>
                + TakeEach<'v, Fed<$t>, K>,
        {
            fn reads(reads: &mut ReadSet) {
                reads
                    .add::<LossDetectionOf<$t, Parts>>()
                    .add::<LinkPathCongestionState<Duration>>()
                    .add::<ProbeTimeout<Duration>>();
            }
            fn deadline<'v>(lineage: &LineageOf<'v, $t, Parts, layer::Recovery>) -> Option<Duration> {
                lineage.get::<Feeder, I>().0.front().map(|(at, _)| *at)
            }
            fn expire<'v, B: CallBundle>(
                lineage: LineageOf<'v, $t, Parts, layer::Recovery>,
                others: &mut OtherNodes<'v, $t, Parts, B>,
                now: Duration,
            ) -> Option<RequestOf<$t, Parts>> {
                let thresholds = *lineage.get::<LossThresholds, Ith>();
                let (
                    hlist_pat![
                        feeder,
                        spaces,
                        state,
                        numbers,
                        confirmation,
                        rtt,
                        journals,
                        obligations,
                        received,
                        part,
                        pto
                    ],
                    _,
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
                                sent_state: (),
                            };
                            let number = PacketNumber::new(number).ok()?;
                            detection.accept(number, now, true, Some(charge));
                            state.add_in_flight(1200);
                        }
                        let acked = PacketNumber::new(acked?).ok()?;
                        numbers.get_mut(space)?.on_ack(acked, acked);
                        for packet in detection.take_acknowledged(&(acked..=acked)) {
                            if let Some(charge) = packet.in_flight {
                                state.remove_in_flight(charge.bytes);
                            }
                        }
                        let delay = loss_delay(&RttEstimator::<Duration>::estimate(rtt), &thresholds);
                        let lost = detection
                            .detect_lost(now, acked, delay, thresholds.packet_threshold())
                            .count();
                        assert_eq!(lost, 0, "nothing is lost when the ACK arrives");
                    }
                    Step::Confirm => *confirmation = HandshakeConfirmation::Confirmed,
                    Step::Sample(sent_at) => {
                        let sample =
                            RttSample::new(sent_at, now, Duration::ZERO, Duration::MAX, link())?;
                        rtt.on_sample(sample);
                    }
                    Step::Sent { space, count } => {
                        let journals = journals.get_mut(space)?;
                        let detection = spaces.get_mut(space)?;
                        for _ in 0..count {
                            let mut attempt = journals.start_attempt(here.clone());
                            let number = attempt.packet_number();
                            attempt.record_frame(
                                Coproduct::inject(Summary(number.get())),
                                true,
                                true,
                            );
                            let sealed = attempt.seal(1200, false)?;
                            journals.sent(sealed, now);
                            let charge = InFlightCharge {
                                bytes: 1200,
                                app_limited: false,
                                sent_state: (),
                            };
                            detection.accept(number, now, true, Some(charge));
                            state.add_in_flight(1200);
                        }
                    }
                    Step::SentAck(space) => {
                        let received = received.get_mut(space)?;
                        let (largest, _) = received.largest()?;
                        let before = obligations.get_mut(space)?.ack_written(largest);
                        received.on_ack_written();
                        let journals = journals.get_mut(space)?;
                        let mut attempt = journals.start_attempt(here.clone());
                        let number = attempt.packet_number();
                        let summary = v1::feedback::FeedbackSummary::Ack(AckSummary {
                            largest,
                            before,
                        });
                        attempt.record_frame(Coproduct::inject(summary), false, false);
                        let sealed = attempt.seal(50, false)?;
                        journals.sent(sealed, now);
                        spaces.get_mut(space)?.accept(number, now, false, None);
                    }
                    Step::Inspect => {
                        let estimate = RttEstimator::<Duration>::estimate(rtt);
                        log(format!(
                            "rtt latest {:?}, smoothed {:?}, window {}, in flight {}, permits {}, \
                             backoff {}, first sample {:?}",
                            estimate.latest,
                            estimate.smoothed,
                            CongestionController::<Duration>::window(part),
                            state.bytes_in_flight(),
                            state.probe_permits(),
                            pto.backoff(),
                            state.first_rtt_sample_at(),
                        ));
                    }
                }
                None
            }
            fn reread<'v, B: CallBundle>(
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
                log(format!(
                    "in flight {}, outstanding {outstanding}, lost {lost:?}, permits {}, backoff {}",
                    state.bytes_in_flight(),
                    state.probe_permits(),
                    lineage.get::<ProbeTimeout<Duration>, Jp>().backoff(),
                ));
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
        type Data = HList![Adder, PeerSetter, Closer, CryptoFeeder];
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

/// Version 1's facts for a connection whose first logical link is
/// `validation`.
fn args<T>(validation: AddressValidation) -> v1::ConnectionArgs<T, Parts>
where
    T: v1::Choices<Crypto = RingBackend, Link = TestLink, Receiver = TestReceiver>,
    T::Side: SideCapacities,
    T::Recovery<LinkId<(), ()>>: RecoveryFactory<TestLink, Config = NewRenoRecoveryFactoryConfig>,
{
    let mut parameters = TransportParameters::<Vec<u8>>::new();
    parameters.set(MaxIdleTimeout::new(VarInt::from_u32(30_000)));
    v1::ConnectionArgs {
        crypto: RingBackend,
        client_dcid: client_dcid(),
        anti_amplification: AntiAmplificationFactor::new(2).expect("2 is a factor"),
        transport_parameters: parameters.known,
        first_link: LinkFacts { validation },
        recovery: NewRenoRecoveryFactoryConfig::recommended(ms(1)),
        loss_thresholds: sakuya_recovery::loss::LossThresholds::recommended(ms(1))
            .expect("the test clock's timers fire to the millisecond"),
        max_ack_ranges: MAX_ACK_RANGES.with(Cell::get),
        crypto_receive: <T::Side as SideCapacities>::crypto_receive(),
        first_flight: first_flight::<T>(),
        initial_receiver: initial_receiver(),
        max_datagrams_per_poll: NonZeroUsize::new(MAX_PER_POLL.with(Cell::get))
            .expect("the tests handle at least one input per poll"),
        max_held_inputs: MAX_HELD.with(Cell::get),
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
trait SideCapacities: Sized {
    fn crypto_receive() -> CryptoReceiveCapacities;
    fn read_state<T>() -> FirstFlightReadState<T>
    where
        T: v1::Choices<Crypto = RingBackend, Side = Self>;
}
impl SideCapacities for v1::Server {
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
impl SideCapacities for v1::Client {
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
    ($t:ty, $validation:expr, $first:expr) => {
        ConnectionDriver::<$t, Parts, _, _, _>::new(
            TestClock,
            frunk_core::hlist![args::<$t>($validation), HNil],
            LogicalPathArgs { path: PATH },
            LinkPathArgs {
                path: PATH,
                link: TestLink($first),
            },
        )
    };
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
        &sakuya_recovery::rtt::RttEstimate::initial(sakuya_recovery::rtt::INITIAL_RTT),
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

#[test]
fn a_connection_dropped_with_no_reason_recorded_ends_aborted() {
    reset();
    let mut connection = connection!(Mine, AddressValidation::NotValidated, link());
    let outer = Outer::new();
    assert!(outer.poll(&mut connection).is_pending());
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
    // the factory sees the other layer only, read only, with its estimate
    assert_eq!(log.len(), 1, "{log:?}");
    assert!(
        log[0].starts_with("lent beside Recovery(SoleLogicalPath, ")
            && log[0].ends_with("smoothed 333ms"),
        "{log:?}"
    );
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

/// The lines the feeder logged since the last call.
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
    reset();
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
    let mut packet = vec![first];
    packet.extend_from_slice(&1u32.to_be_bytes());
    packet.push(8);
    packet.extend_from_slice(&CLIENT_DCID);
    packet.push(0);
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
    TrafficSecret::new(KdfAlgorithm::HkdfSha256, &[0xc1; 32]).unwrap()
}

/// The traffic secret the server sends 1-RTT packets with.
fn server_secret() -> TrafficSecret {
    TrafficSecret::new(KdfAlgorithm::HkdfSha256, &[0x5e; 32]).unwrap()
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
    let keys = client_generation(generation);
    let header = HeaderProtectionKey::derive(&RingBackend, ONE_RTT_AEAD, &client_secret());
    let key_phase = if generation % 2 == 1 { 0x04 } else { 0 };
    let mut packet = vec![0x43 | key_phase];
    packet.extend_from_slice(&CLIENT_DCID);
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

/// A CRYPTO frame of "hello" at offset 0, then PADDING.
fn crypto_hello() -> Vec<u8> {
    [&[0x06, 0x00, 0x05][..], b"hello", &[0; 20]].concat()
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
    let payload = [&[0x06, 0x00, 0x05][..], b"hello", &[0x1e], &[0; 20]].concat();
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
    assert!(
        inspect.contains("largest Some((0, 5ms))") && inspect.contains("reason Some(\"Peer("),
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
    let first = link();
    feed_packets([(ms(6), Inspect), (ms(7), InspectCredit(first.clone()))]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first.clone());
    take_log();
    // the last packet is protected with the server's keys, which the server
    // does not open with
    let datagram = padded(
        &[
            long_packet(INITIAL, 0, &crypto_at(0, b"hel")),
            long_packet(INITIAL, 1, &crypto_at(3, b"lo")),
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
    let first = link();
    feed_packets([(ms(6), Inspect), (ms(7), InspectCredit(first.clone()))]);
    let datagram = padded(
        &[],
        |payload| long_packet(INITIAL, 0, payload),
        &crypto_at(0, b"hel"),
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
        &crypto_at(3, b"lo"),
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
        &crypto_at(0, b"hello"),
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
        &<v1::Server as SideCapacities>::crypto_receive(),
        MaxAckRanges::DEFAULT,
        MAX_HELD.with(Cell::get),
    );
    let result = {
        let reading = core::pin::pin!(read_first_flight::<Mine, Parts, _, _, _>(
            &mut state,
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
    MAX_PER_POLL.with(|m| m.set(1));
    let first = link();
    feed_packets([(ms(5), Inspect), (ms(6), Inspect)]);
    let mut connection = connection!(Mine, AddressValidation::NotValidated, first.clone());
    take_log();
    deliver(
        padded(
            &[],
            |payload| long_packet(INITIAL, 0, payload),
            &crypto_at(0, b"hel"),
        ),
        &first,
        ms(5),
    );
    deliver(
        padded(
            &[],
            |payload| long_packet(INITIAL, 1, payload),
            &crypto_at(3, b"lo"),
        ),
        &first,
        ms(5),
    );
    let outer = Outer::new();
    advance_to(ms(5));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(outer.wakes(), 1, "the receiving call woke itself");
    assert_eq!(
        take_log(),
        [
            "read \"hel\", largest Some((0, 5ms)), ranges [(0, 0)], due Some(Now), \
          idle Some(30.005s), reason None"
        ]
    );
    advance_to(ms(6));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(
        take_log(),
        [
            "read \"lo\", largest Some((1, 5ms)), ranges [(0, 1)], due Some(Now), \
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
            // what the inspection took is read again
            "in flight 0, outstanding 0, lost [], permits 0, backoff 0",
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
    assert_eq!(
        at(200).as_deref(),
        Some("in flight 1200, outstanding 1, lost [], permits 2, backoff 1")
    );
    assert_eq!(
        at(210).as_deref(),
        Some("in flight 0, outstanding 0, lost [], permits 0, backoff 0")
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
