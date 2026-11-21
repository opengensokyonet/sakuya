//! Loom explores the claim core of `sakuya_datagram_routing_v1` under two
//! candidates on two threads: its participation count, its commit flag, the
//! reference count that drops it, and the lock the candidates judge under,
//! with every interleaving and the weak memory orderings loom models.
//!
//! The candidates are real: they come out of a real router, over the index of
//! one thread of the routing crate, whose candidates compete under a lock of
//! loom instead of the lock of a cell ([`LoomClaimLock`]). The index is only
//! used before the threads start.

use std::convert::Infallible;
use std::future::Pending;
use std::hash::RandomState;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use loom::sync::atomic::{AtomicUsize, Ordering};
use loom::thread;
use sakuya_datagram_routing_v1::claim::candidate::{
    DatagramClaimAccess, DatagramClaimAttempt, DatagramClaimOutcome,
};
use sakuya_datagram_routing_v1::claim::deliverer::DatagramDeliverer;
use sakuya_datagram_routing_v1::claim::delivery::{DatagramDelivery, ExclusiveDatagram};
use sakuya_datagram_routing_v1::claim::erased::SendDatagramDeliverer;
use sakuya_datagram_routing_v1::claim::lock::DatagramClaimLock;
use sakuya_datagram_routing_v1::route::acceptance::{
    InitialAcceptance, InitialDatagramReceiver, InitialReceiverFactory, PreparedReceiver,
    ReflowHandoff, ReflowProvider, UnclaimedWork,
};
use sakuya_datagram_routing_v1::route::association::{MatchAssociation, PacketForms, RouteMatcher};
use sakuya_datagram_routing_v1::route::index::{
    HashMapRouteEntryRegistration, HashMapRouteIndex, NonEmptyCidRouteBucket, RouteIndex,
    ZeroCidRouteBucket,
};
use sakuya_datagram_routing_v1::route::interpretation::RecognizedInitial;
use sakuya_datagram_routing_v1::route::recognizer::ConnectionIdLengths;
use sakuya_datagram_routing_v1::route::router::DatagramRouter;
use sakuya_link::{
    ArrivalFacts, BindingId, Link, LinkId, MIN_DATAGRAM_SIZE, OutgoingDatagram, ReceivedDatagram,
    SendAcceptance,
};
use sakuya_wire_v1::connection_id::{ConnectionIdLength, NonEmptyCid};
use sakuya_wire_v1::header::VERSION;

type Local = u32;
type Peer = u32;
type Datagram = ReceivedDatagram<Vec<u8>, TestLink>;
type Work = UnclaimedWork<Vec<u8>, TestLink>;
type Handoff = ReflowHandoff<Collect, Local>;
type Target = dyn SendDatagramDeliverer<Datagram, Local, Handoff, LoomClaimLock>;
type Delivery = DatagramDelivery<Datagram, Local, Handoff, LoomClaimLock>;
type Router = DatagramRouter<
    Vec<u8>,
    TestLink,
    LoomIndex,
    ConnectionIdLengths,
    (),
    (),
    InitialAcceptance<NoFactory, Collect>,
>;

/// The claim lock of these models: a mutex of loom, which an attempt waits
/// for by blocking its thread, as loom models a blocked thread.
enum LoomClaimLock {}

impl DatagramClaimLock for LoomClaimLock {
    type Lock<T> = loom::sync::Mutex<T>;

    fn new<T>(value: T) -> loom::sync::Mutex<T> {
        loom::sync::Mutex::new(value)
    }

    async fn with<T, R>(lock: &loom::sync::Mutex<T>, op: impl FnOnce(&mut T) -> R) -> R {
        op(&mut lock.lock().unwrap())
    }

    fn try_with<T, R>(lock: &loom::sync::Mutex<T>, op: impl FnOnce(&mut T) -> R) -> Option<R> {
        let mut value = lock.try_lock().ok()?;
        Some(op(&mut value))
    }

    fn get_mut<T>(lock: &mut loom::sync::Mutex<T>) -> &mut T {
        lock.get_mut().unwrap()
    }
}

type InnerIndex = HashMapRouteIndex<Target, Local, RandomState>;

/// The index of one thread of the routing crate, whose candidates compete
/// under [`LoomClaimLock`].
#[derive(Clone)]
struct LoomIndex(InnerIndex);

impl RouteIndex<Local> for LoomIndex {
    type Target = Target;
    type Registration = HashMapRouteEntryRegistration<Target, Local, RandomState>;
    type ClaimLock = LoomClaimLock;

    fn new() -> Self {
        Self(InnerIndex::new())
    }

    fn registration_count(&self) -> usize {
        self.0.registration_count()
    }

    fn poll_empty(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.0.poll_empty(cx)
    }

    fn count_published(&self) {
        self.0.count_published();
    }

    fn count_revoked(&self) {
        self.0.count_revoked();
    }

    fn read_nonzero<R>(
        &self,
        cid: &NonEmptyCid,
        read: impl FnOnce(&NonEmptyCidRouteBucket<Target, Local>) -> R,
    ) -> Option<R> {
        self.0.read_nonzero(cid, read)
    }

    fn update_nonzero<R>(
        &self,
        cid: &NonEmptyCid,
        update: impl FnOnce(&mut NonEmptyCidRouteBucket<Target, Local>) -> R,
    ) -> R {
        self.0.update_nonzero(cid, update)
    }

    fn read_zero<R>(
        &self,
        local: &Local,
        read: impl FnOnce(&ZeroCidRouteBucket<Target, Local>) -> R,
    ) -> Option<R> {
        self.0.read_zero(local, read)
    }

    fn update_zero<R>(
        &self,
        local: &Local,
        update: impl FnOnce(&mut ZeroCidRouteBucket<Target, Local>) -> R,
    ) -> R {
        self.0.update_zero(local, update)
    }

    fn hold(
        &self,
        entry: Arc<sakuya_datagram_routing_v1::route::index::DatagramRouteEntry<Target, Local>>,
    ) -> Self::Registration {
        self.0.hold(entry)
    }
}

/// A link of these models: only its identity takes part in routing.
#[derive(Clone, Debug)]
struct TestLink(LinkId<Local, Peer>);

impl Link for TestLink {
    type Local = Local;
    type Peer = Peer;
    type Payload = Vec<u8>;
    type Instant = Duration;
    type MaxDatagramSizeError = Infallible;
    type SendError = Infallible;
    type RecvError = Infallible;
    type Recv<'a>
        = Pending<Result<ReceivedDatagram<Vec<u8>, Self>, Infallible>>
    where
        Self: 'a;
    type Ended = Pending<Infallible>;
    type Send<'a> = Pending<Result<SendAcceptance<Duration>, Infallible>>;
    type MaxDatagramSizeChanged = Pending<()>;

    fn id(&self) -> &LinkId<Local, Peer> {
        &self.0
    }

    fn may_mark_ecn(&self) -> bool {
        false
    }

    fn max_datagram_size(&self) -> Result<usize, Infallible> {
        Ok(MIN_DATAGRAM_SIZE)
    }

    fn recv(&self) -> Self::Recv<'_> {
        std::future::pending()
    }

    fn ended(&self) -> Self::Ended {
        std::future::pending()
    }

    fn send<'a>(&self, _batch: &'a [OutgoingDatagram]) -> Self::Send<'a> {
        std::future::pending()
    }

    fn max_datagram_size_changed(&self) -> Pending<()> {
        std::future::pending()
    }
}

/// Counts hand-offs with an atomic of loom, and checks the datagram is
/// intact.
struct Collect {
    handed_off: loom::sync::Arc<AtomicUsize>,
}

impl ReflowProvider<Vec<u8>, TestLink> for Collect {
    fn hand_off(&self, work: Work) {
        assert_eq!(work.datagram().payload(), &initial_packet());
        self.handed_off.fetch_add(1, Ordering::SeqCst);
    }
}

/// Never receives: its factory prepares nothing.
struct Nothing;

impl InitialDatagramReceiver<Vec<u8>, TestLink, LoomIndex> for Nothing {
    fn receive_first(
        self,
        _: HashMapRouteEntryRegistration<Target, Local, RandomState>,
        _: ExclusiveDatagram<Datagram>,
        _: RecognizedInitial<Local>,
    ) {
    }
}

/// Admits the Initial or not, which decides whether every candidate exiting
/// hands the datagram off or releases it; prepares nothing.
struct NoFactory {
    admits: bool,
}

impl InitialReceiverFactory<Vec<u8>, TestLink, LoomIndex> for NoFactory {
    type Receiver = Nothing;

    fn admits(&self, _: &RecognizedInitial<Local>, _: &Datagram) -> bool {
        self.admits
    }

    fn prepare(&self, _: &RecognizedInitial<Local>) -> Option<PreparedReceiver<Target, Nothing>> {
        None
    }
}

/// Keeps its deliveries in a mutex of std, used only before the threads
/// start.
#[derive(Default)]
struct Keeper {
    kept: Mutex<Vec<Delivery>>,
}

impl DatagramDeliverer<Datagram, Local> for Keeper {
    type Handoff = Handoff;
    type ClaimLock = LoomClaimLock;

    fn deliver(&self, delivery: Delivery) {
        self.kept.lock().unwrap().push(delivery);
    }
}

/// A version 1 Initial with an eight-byte Destination Connection ID of
/// ones, no Source Connection ID and no token.
fn initial_packet() -> Vec<u8> {
    let mut packet = vec![0xc1];
    packet.extend(VERSION.to_be_bytes());
    packet.push(8);
    packet.extend([1; 8]);
    packet.push(0);
    packet.push(0);
    packet.push(12);
    packet.extend([0xa5; 12]);
    packet
}

/// Routes one Initial to two keepers registered under its Destination
/// Connection ID; returns their deliveries, which compete.
fn two_candidates(admits: bool, handed_off: &loom::sync::Arc<AtomicUsize>) -> [Delivery; 2] {
    let router: Router = DatagramRouter::new(
        LoomIndex::new(),
        ConnectionIdLengths::new([ConnectionIdLength::new(8).unwrap()]),
    )
    .with_initial_acceptance(InitialAcceptance::new(
        NoFactory { admits },
        Arc::new(Collect {
            handed_off: handed_off.clone(),
        }),
    ));
    let cid: NonEmptyCid = [1u8; 8].as_slice().try_into().unwrap();
    let keepers = [Arc::new(Keeper::default()), Arc::new(Keeper::default())];
    let registrations: Vec<_> = keepers
        .iter()
        .map(|keeper| {
            router.index().register(
                RouteMatcher::new(
                    MatchAssociation::InitialDcid(cid),
                    PacketForms::ALL,
                    VERSION,
                ),
                Arc::clone(keeper) as Arc<Target>,
            )
        })
        .collect();
    let link = TestLink(LinkId::new::<TestLink>(1, 2, &BindingId::new()));
    router.route(ReceivedDatagram::new(
        initial_packet(),
        ArrivalFacts::new(link, Duration::ZERO, None),
    ));
    drop(registrations);
    keepers.map(|keeper| {
        let delivery = keeper.kept.lock().unwrap().pop().unwrap();
        assert!(
            matches!(delivery, DatagramDelivery::Competing(_)),
            "two candidates compete"
        );
        delivery
    })
}

/// The judgment of an attempt: take the datagram, or leave it.
fn judge(
    accept: bool,
    access: DatagramClaimAccess<'_, Datagram>,
) -> DatagramClaimOutcome<'_, (), (), Datagram> {
    if accept {
        DatagramClaimOutcome::Claimed(access.into_exclusive(), ())
    } else {
        DatagramClaimOutcome::Unclaimed(access)
    }
}

/// Attempts `delivery` once with the judgment `accept`, and drops what is
/// left of the candidate; true when it ended up owning the datagram.
fn attempt(delivery: Delivery, accept: bool) -> bool {
    let DatagramDelivery::Competing(candidate) = delivery else {
        panic!("two candidates compete");
    };
    match loom::future::block_on(candidate.try_exclusive(move |access, _| judge(accept, access))) {
        DatagramClaimAttempt::Claimed(exclusive, ())
        | DatagramClaimAttempt::Exclusive(exclusive) => {
            drop(exclusive.consume());
            true
        }
        DatagramClaimAttempt::Unclaimed(candidate) => {
            drop(candidate);
            false
        }
        DatagramClaimAttempt::Abandoned(()) | DatagramClaimAttempt::ClaimedElsewhere => false,
    }
}

#[test]
fn concurrent_exits_hand_off_once() {
    loom::model(|| {
        let handed_off = loom::sync::Arc::new(AtomicUsize::new(0));
        let [one, two] = two_candidates(true, &handed_off);
        let exit = thread::spawn(move || drop(one));
        drop(two);
        exit.join().unwrap();
        assert_eq!(handed_off.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn an_exit_racing_an_unclaimed_attempt_hands_off_once() {
    loom::model(|| {
        let handed_off = loom::sync::Arc::new(AtomicUsize::new(0));
        let [one, two] = two_candidates(true, &handed_off);
        let exit = thread::spawn(move || drop(one));
        assert!(!attempt(two, false));
        exit.join().unwrap();
        assert_eq!(handed_off.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn a_winner_racing_an_exit_suppresses_the_hand_off() {
    loom::model(|| {
        let handed_off = loom::sync::Arc::new(AtomicUsize::new(0));
        let [one, two] = two_candidates(true, &handed_off);
        let winner = thread::spawn(move || attempt(one, true));
        drop(two);
        assert!(winner.join().unwrap(), "the only accepting candidate wins");
        assert_eq!(handed_off.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn one_of_two_accepting_attempts_wins() {
    loom::model(|| {
        let handed_off = loom::sync::Arc::new(AtomicUsize::new(0));
        let [one, two] = two_candidates(true, &handed_off);
        let other = thread::spawn(move || attempt(one, true));
        let won = attempt(two, true);
        let other_won = other.join().unwrap();
        assert!(won != other_won, "exactly one attempt wins");
        assert_eq!(handed_off.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn the_last_taker_takes_or_the_datagram_is_released() {
    loom::model(|| {
        let handed_off = loom::sync::Arc::new(AtomicUsize::new(0));
        let [one, two] = two_candidates(false, &handed_off);
        let exit = thread::spawn(move || drop(one));
        // A leaving judgment ends up with the datagram only as the sole
        // remaining participant, which takes it without judging; both
        // outcomes are legal, and nothing is handed off when the last
        // participant takes.
        let _ = attempt(two, false);
        exit.join().unwrap();
        assert_eq!(handed_off.load(Ordering::SeqCst), 0);
    });
}
