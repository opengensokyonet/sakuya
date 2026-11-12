//! Version 1's components on the tree: what the connection is made with,
//! the entries of its logical links and the roles of its link paths.
#![feature(impl_trait_in_assoc_type, yield_expr)]

mod common;

use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    fmt::Debug,
    sync::Arc,
    time::Duration,
};

use common::{Mine, Outer, TestClock, TestLink, advance_to, log, ms, take_log};
use frunk_core::hlist_pat;
use sakuya_connection::{
    call::CallBundle,
    clock::{ConnectionChoices, InstantOf},
    component::{ArgsOf, Build, DataComponent, LineageOf, ParentsOf, ReadSet, RequestOf},
    driver::ConnectionDriver,
    error::ConnectionErrorsOf,
    layer::{self, EstablishedArgs, LinkPathArgs, LogicalPathArgs, NodeKey},
    others::OtherNodes,
    request::StructureRequest,
    share::{
        FlatMut, FlatRef, LayerShare, LineageLists, LogicalPathKeyShare, LogicalPathKeys, NodeData,
        SoleLogicalPath,
    },
    take::{GetAt, Take, TakeEach},
    v1::{
        self, CloseCauseOf,
        amplification::{AddressValidation, AntiAmplification, AntiAmplificationFactor},
        close::{CloseReasonRecord, LocalCloseCause},
        confirmation::HandshakeConfirmation,
        crypto::{CryptoReceiveCapacities, CryptoReceiver, FragmentedCryptoReceiveBuffer},
        idle::IdleTimeout,
        keys::InitialKeys,
        link::LinkFacts,
        loss_detection::LossDetectionOf,
        parameters::PeerTransportParameters,
        pto::ProbeTimeout,
        recovery::{
            CongestionPartOf, LinkPathCongestionState, RecoveryFactoryOf, RttOf, lend_congestion,
        },
        role::LinkPathRole,
    },
};
use sakuya_link::{BindingId, LinkId};
use sakuya_packet_protection::backend::ring::RingBackend;
use sakuya_recovery::{
    congestion::CongestionController,
    factory::{NewRenoRecoveryFactory, NewRenoRecoveryFactoryConfig, RecoveryFactory},
    loss::{LossThresholds, loss_delay},
    loss_detection::InFlightCharge,
    pacing::{Pacer, PacingInput},
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaceState, PacketNumberSpaces},
    pto::probe_timeout,
    rtt::{RttEstimator, RttSample},
};
use sakuya_stream::connection::CloseReason;
use sakuya_tls::{engine::CryptoLevel, message::MessageLimits};
use sakuya_wire::{
    connection_id::ConnectionId,
    parameters::ParametersPart,
    parts::{HList, HNil, Selector},
    v1::packet_number::PacketNumber,
    v1::transport_parameters::{
        TransportParameterSlots, TransportParameterSpace, TransportParameters,
        integer::MaxIdleTimeout,
    },
    var_int::VarInt,
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
    type ApplicationError = common::AppClose;
    type HandshakeFailure = core::convert::Infallible;
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
    type ApplicationError = common::AppClose;
    type HandshakeFailure = core::convert::Infallible;
}

/// A recovery factory that makes what sakuya's makes and logs, when it
/// lends, the other link paths it sees.
mod spy {
    use super::*;
    use sakuya_connection::v1::recovery::OtherCongestionParts;
    use sakuya_recovery::{
        congestion::CongestionController,
        factory::{LendCongestion, PacedNewReno, RecoveryFactory},
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
            = &'a mut PacedNewReno<Duration>
        where
            Self: 'a,
            's: 'a;
        fn lend<'a>(
            &'a mut self,
            this: &'a mut PacedNewReno<Duration>,
            others: &'a OtherCongestionParts<'s, K, LinkId<(), ()>, PacedNewReno<Duration>>,
        ) -> &'a mut PacedNewReno<Duration> {
            others.each(|key, _, rtt| {
                log(format!("lent beside {key:?}, smoothed {:?}", rtt.smoothed))
            });
            this
        }
        fn next_deadline(&self, this: &PacedNewReno<Duration>) -> Option<Duration> {
            LendCongestion::<Duration, ()>::next_deadline(&self.0, this)
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
                    lend_congestion::<SpyMine, Parts, B, Ji, Jr, _>(factory, part, rest, |access| {
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
                    })
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
        RttOf<T, Parts>
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
                _: &mut OtherNodes<'v, $t, Parts, B>,
                now: Duration,
            ) -> Option<RequestOf<$t, Parts>> {
                let thresholds = *lineage.get::<LossThresholds, Ith>();
                let (hlist_pat![feeder, spaces, state, numbers, confirmation, rtt], _) =
                    Take::<Fed<$t>, K>::take(lineage);
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
        type Data = HList![LayerWatch];
        type Calls = HNil;
    }
    impl LayerShare<ClientMine, Parts, layer::Recovery> for Part {
        type Data = HList![LayerWatch, Feeder];
        type Calls = HNil;
    }
    none!(LogicalPath, Established);
}

/// Version 1's facts for a connection whose first logical link is
/// `validation`.
fn args<T>(validation: AddressValidation) -> v1::ConnectionArgs<T, Parts>
where
    T: v1::Choices<Crypto = RingBackend, Link = TestLink>,
    T::Side: SideCapacities,
    T::Recovery<LinkId<(), ()>>: RecoveryFactory<TestLink, Config = NewRenoRecoveryFactoryConfig>,
{
    let mut parameters = TransportParameters::<Vec<u8>>::new();
    parameters.set(MaxIdleTimeout::new(VarInt::from_u32(30_000)));
    v1::ConnectionArgs {
        crypto: RingBackend,
        // invariant: eight bytes is a valid connection ID length
        client_dcid: ConnectionId::new(&[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08])
            .expect("eight bytes"),
        anti_amplification: AntiAmplificationFactor::new(2).expect("2 is a factor"),
        transport_parameters: parameters.known,
        first_link: LinkFacts { validation },
        recovery: NewRenoRecoveryFactoryConfig::recommended(ms(1)),
        loss_thresholds: sakuya_recovery::loss::LossThresholds::recommended(ms(1))
            .expect("the test clock's timers fire to the millisecond"),
        max_ack_ranges: sakuya_recovery::receive_journals::MaxAckRanges::DEFAULT,
        crypto_receive: <T::Side as SideCapacities>::crypto_receive(),
    }
}

/// The CRYPTO capacities of a side: the least the default message limits
/// allow at each level.
trait SideCapacities {
    fn crypto_receive() -> CryptoReceiveCapacities;
}
impl SideCapacities for v1::Server {
    fn crypto_receive() -> CryptoReceiveCapacities {
        // ClientHello at Initial; only Finished at Handshake
        CryptoReceiveCapacities::server(MessageLimits::default(), false, 16 * 1024 + 4, 4096)
            .expect("the least capacities the limits allow")
    }
}
impl SideCapacities for v1::Client {
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
