//! Version 1's components on the tree: what the connection is made with,
//! the entries of its logical links and the roles of its link paths.
#![feature(impl_trait_in_assoc_type, yield_expr)]

mod common;

use std::{cell::Cell, fmt::Debug, time::Duration};

use common::{Mine, Outer, TestClock, TestLink, advance_to, log, ms, take_log};
use frunk_core::hlist_pat;
use sakuya_connection::{
    call::CallBundle,
    clock::{ConnectionChoices, InstantOf},
    component::{ArgsOf, Build, DataComponent, LineageOf, ParentsOf, ReadSet, RequestOf},
    driver::ConnectionDriver,
    layer::{self, LinkPathArgs, LogicalPathArgs},
    others::OtherNodes,
    request::StructureRequest,
    share::{LayerShare, LineageLists, LogicalPathKeyShare, SoleLogicalPath},
    take::{GetAt, Take, TakeEach},
    v1::{
        self,
        amplification::{AddressValidation, AntiAmplification, AntiAmplificationFactor},
        idle::IdleTimeout,
        keys::InitialKeys,
        link::LinkFacts,
        parameters::PeerTransportParameters,
        role::LinkPathRole,
    },
};
use sakuya_link::{BindingId, LinkId};
use sakuya_packet_protection::backend::ring::RingBackend;
use sakuya_wire::{
    connection_id::ConnectionId,
    parameters::ParametersPart,
    parts::{HList, HNil},
    v1::transport_parameters::{
        TransportParameterSlots, TransportParameterSpace, TransportParameters,
        integer::MaxIdleTimeout,
    },
    var_int::VarInt,
};

const PATH: SoleLogicalPath = SoleLogicalPath;

thread_local! {
    /// When the probe asks for a link path over a second logical link.
    static ADD: Cell<Option<(Duration, LinkId)>> = const { Cell::new(None) };
    /// When the probe of each link path built from now on closes its role.
    static CLOSE_AT: Cell<Option<Duration>> = const { Cell::new(None) };
    /// When the probe sets the peer's maximum idle timeout to 10 s and
    /// processes a packet, as the calls will.
    static PEER_AT: Cell<Option<Duration>> = const { Cell::new(None) };
}

/// The parts of the tests' connections.
type Parts = HList![v1::Part, probe::Part];

fn link() -> LinkId {
    LinkId::new::<()>(BindingId::new::<()>())
}

fn reset() {
    take_log();
    advance_to(ms(0));
    ADD.with(|a| a.set(None));
    CLOSE_AT.with(|c| c.set(None));
    PEER_AT.with(|p| p.set(None));
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
}

/// A probe part: it logs what version 1 built and changes what a test
/// needs changed.
mod probe {
    use super::*;

    pub struct Part;
    impl LogicalPathKeyShare for Part {
        type Fields = HNil;
    }
    impl ParametersPart<TransportParameterSpace> for Part {
        type Parameters = HNil;
    }

    /// In the connection: asks for a second link path at its deadline, and
    /// logs whether the Initial keys are live.
    #[derive(Debug)]
    pub struct Adder(Option<(Duration, LinkId)>);
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
        fn end<'v>(self, _: &mut ParentsOf<'v, T, L, layer::LinkEntry>) {
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
    impl<T: v1::Choices, L> Build<T, L, layer::LinkPath, ()> for Watcher
    where
        for<'v> L: LineageLists<'v, T>,
    {
        fn build<'v>(
            _: &mut ParentsOf<'v, T, L, layer::LinkPath>,
            _: &mut ArgsOf<T, L, layer::LinkPath>,
        ) -> Self {
            Watcher(CLOSE_AT.with(Cell::get))
        }
        fn end<'v>(self, _: &mut ParentsOf<'v, T, L, layer::LinkPath>) {
            log("link path ended");
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
            role.close(now + ms(30));
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

    impl LayerShare<Mine, Parts, layer::Connection> for Part {
        type Data = HList![Adder, PeerSetter];
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
    none!(LogicalPath, Established, Recovery);
}

/// Version 1's facts for a connection whose first logical link is
/// `validation`.
fn args<T: v1::Choices<Crypto = RingBackend>>(
    validation: AddressValidation,
) -> v1::ConnectionArgs<T> {
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
            "Active, NotValidated, credit Some(0)",
        ]
    );
}

#[test]
fn a_later_link_path_is_a_candidate_over_an_entry_the_side_starts() {
    reset();
    ADD.with(|a| a.set(Some((ms(10), link()))));
    let mut server = connection!(Mine, AddressValidation::Validated, link());
    assert_eq!(take_log()[1], "Active, Validated, credit None");
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
            "Closing(50ms), NotValidated, credit Some(0)",
            "Closing(50ms), NotValidated, credit Some(0)",
        ]
    );
    advance_to(ms(50));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(
        take_log(),
        [
            "link path ended",
            "entry ended",
            "link path ended",
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
    assert_eq!(take_log(), ["link path ended", "entry ended"]);
}
