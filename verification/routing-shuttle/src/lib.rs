//! Fixtures of the Shuttle tests: a link, packets, a recording deliverer, a
//! receiver factory and a routing domain made of the tables, the claim lock
//! and the reflow queue of `sakuya_sync_std`, all through the public
//! interfaces of the routing crate.

use std::convert::Infallible;
use std::future::Pending;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::time::Duration;

use sakuya_datagram_routing_v1::claim::candidate::{
    DatagramClaimAccess, DatagramClaimAttempt, DatagramClaimOutcome,
};
use sakuya_datagram_routing_v1::claim::deliverer::DatagramDeliverer;
use sakuya_datagram_routing_v1::claim::delivery::{DatagramDelivery, ExclusiveDatagram};
use sakuya_datagram_routing_v1::claim::erased::SendDatagramDeliverer;
use sakuya_datagram_routing_v1::claim::queue::DatagramDeliveryQueue;
use sakuya_datagram_routing_v1::route::acceptance::{
    InitialAcceptance, InitialDatagramReceiver, InitialReceiverFactory, PreparedReceiver,
    ReflowHandoff, UnclaimedWork,
};
use sakuya_datagram_routing_v1::route::association::{MatchAssociation, PacketForms, RouteMatcher};
use sakuya_datagram_routing_v1::route::index::RouteIndex;
use sakuya_datagram_routing_v1::route::interpretation::RecognizedInitial;
use sakuya_datagram_routing_v1::route::recognizer::ConnectionIdLengths;
use sakuya_datagram_routing_v1::route::router::DatagramRouter;
use sakuya_link::{
    ArrivalFacts, BindingId, Link, LinkId, MIN_DATAGRAM_SIZE, OutgoingDatagram, ReceivedDatagram,
    SendAcceptance,
};
use sakuya_sync_std::claim::TokioMutexDatagramClaimLock;
use sakuya_sync_std::queue::{MutexDatagramDeliveryPoster, MutexDatagramDeliveryQueue};
use sakuya_sync_std::route::{DashMapRouteEntryRegistration, DashMapRouteIndex};
use sakuya_wire_v1::connection_id::{ConnectionIdLength, NonEmptyCid};
use sakuya_wire_v1::header::VERSION;
use shuttle::sync::Mutex;

/// This side's end of a test link.
pub type Local = u32;
/// The peer's end of a test link.
pub type Peer = u32;
pub type Datagram = ReceivedDatagram<Vec<u8>, TestLink>;
pub type Work = UnclaimedWork<Vec<u8>, TestLink>;
pub type Reflow = MutexDatagramDeliveryPoster<Work>;
pub type Handoff = ReflowHandoff<Reflow, Local>;
pub type Lock = TokioMutexDatagramClaimLock;
pub type Delivery = DatagramDelivery<Datagram, Local, Handoff, Lock>;
pub type Target = dyn SendDatagramDeliverer<Datagram, Local, Handoff, Lock>;
pub type Index = DashMapRouteIndex<Target, Local>;
pub type Registration = DashMapRouteEntryRegistration<Target, Local>;
pub type Router = DatagramRouter<
    Vec<u8>,
    TestLink,
    Index,
    ConnectionIdLengths,
    (),
    (),
    InitialAcceptance<Factory, Reflow>,
>;

/// A link of the tests: only its identity takes part in routing. It never
/// receives, and its sends never complete.
#[derive(Clone, Debug)]
pub struct TestLink(LinkId<Local, Peer>);

impl Link for TestLink {
    type Local = Local;
    type Peer = Peer;
    type Payload = Vec<u8>;
    type Instant = Duration;
    type MaxDatagramSizeError = Infallible;
    type SendError = Infallible;
    type RecvError = Infallible;
    type Recv<'a>
        = Pending<Result<ReceivedDatagram<Self::Payload, Self>, Infallible>>
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

static NEXT_END: AtomicU32 = AtomicU32::new(1);

/// A new link with local and peer ends no other link of this function has.
pub fn link() -> TestLink {
    let local = NEXT_END.fetch_add(1, Ordering::Relaxed);
    let peer = NEXT_END.fetch_add(1, Ordering::Relaxed);
    TestLink(LinkId::new::<TestLink>(local, peer, &BindingId::new()))
}

/// The eight-byte connection ID made of `label`.
pub fn key(label: u8) -> NonEmptyCid {
    NonEmptyCid::try_from(&[label; 8][..]).unwrap()
}

/// The source connection ID of every packet of the tests.
const SCID: [u8; 8] = [0x5c; 8];

/// A version 1 long header packet of the type `type_bits`, with the
/// connection IDs `dcid` and `scid`, a two-byte packet number and `payload`
/// protected bytes after it.
fn long(type_bits: u8, dcid: &[u8], scid: &[u8], payload: u16) -> Vec<u8> {
    let mut packet = vec![0x80 | 0x40 | (type_bits << 4) | 0x01];
    packet.extend(VERSION.to_be_bytes());
    packet.push(u8::try_from(dcid.len()).unwrap());
    packet.extend(dcid);
    packet.push(u8::try_from(scid.len()).unwrap());
    packet.extend(scid);
    if type_bits == 0b00 {
        // an empty token
        packet.push(0);
    }
    let length = 2 + payload;
    assert!(length < 1 << 14, "the length fits two bytes");
    // a two-byte variable-length integer
    packet.extend((0x4000 | length).to_be_bytes());
    packet.extend(std::iter::repeat_n(0xa5, usize::from(length)));
    packet
}

/// A version 1 Initial to the connection ID made of `label`, padded to the
/// 1200 bytes a server requires.
pub fn initial(label: u8) -> Vec<u8> {
    let header = 1 + 4 + 1 + 8 + 1 + SCID.len() + 1 + 2;
    let payload = u16::try_from(1200 - header - 2).unwrap();
    let packet = long(0b00, &[label; 8], &SCID, payload);
    debug_assert_eq!(packet.len(), 1200);
    packet
}

/// A version 1 0-RTT packet to the connection ID made of `label`, shorter
/// than an Initial a server accepts.
pub fn zero_rtt(label: u8) -> Vec<u8> {
    long(0b01, &[label; 8], &SCID, 20)
}

/// How a holder of a competing candidate judges it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Judging {
    Reject,
    Accept,
}

/// The judgment of a receiver that judges with `judging`. It runs while the
/// claim lock is held, and yields there first, so that other candidates of
/// the same datagram may try to take the lock meanwhile.
fn judge(
    access: DatagramClaimAccess<'_, Datagram>,
    judging: Judging,
) -> DatagramClaimOutcome<'_, (), (), Datagram> {
    shuttle::thread::yield_now();
    match judging {
        Judging::Reject => DatagramClaimOutcome::Unclaimed(access),
        Judging::Accept => DatagramClaimOutcome::Claimed(access.into_exclusive(), ()),
    }
}

/// Attempts `delivery` once with a judgment that judges with `judging`, and
/// drops what the attempt leaves; whether the datagram ended in this
/// holder's hands.
///
/// An unclaimed candidate is dropped, so that it exits.
pub fn settle(delivery: Delivery, judging: Judging) -> bool {
    let exclusive = match delivery {
        DatagramDelivery::Exclusive(exclusive) => exclusive,
        DatagramDelivery::Competing(candidate) => {
            let attempt = candidate.try_exclusive(|access, _route| judge(access, judging));
            match shuttle::future::block_on(attempt) {
                DatagramClaimAttempt::Claimed(exclusive, ())
                | DatagramClaimAttempt::Exclusive(exclusive) => exclusive,
                DatagramClaimAttempt::Unclaimed(candidate) => {
                    drop(candidate);
                    return false;
                }
                DatagramClaimAttempt::Abandoned(()) | DatagramClaimAttempt::ClaimedElsewhere => {
                    return false;
                }
            }
        }
    };
    drop(exclusive.consume());
    true
}

/// A deliverer that keeps every delivery for the test to settle, and counts
/// them.
pub struct Recorder {
    judging: Judging,
    deliveries: Mutex<Vec<Delivery>>,
    delivered: AtomicUsize,
}

impl Recorder {
    /// A recorder whose receiver judges with `judging`.
    pub fn new(judging: Judging) -> Arc<Self> {
        Arc::new(Self {
            judging,
            deliveries: Mutex::new(Vec::new()),
            delivered: AtomicUsize::new(0),
        })
    }

    pub fn judging(&self) -> Judging {
        self.judging
    }

    /// How many deliveries it received in all.
    pub fn delivered(&self) -> usize {
        self.delivered.load(Ordering::SeqCst)
    }

    /// Takes the deliveries it holds.
    pub fn take(&self) -> Vec<Delivery> {
        std::mem::take(&mut self.deliveries.lock().unwrap())
    }

    /// Settles every delivery it holds with its own judging; how many ended
    /// in its receiver's hands.
    pub fn settle_all(&self) -> usize {
        self.take()
            .into_iter()
            .map(|delivery| usize::from(settle(delivery, self.judging)))
            .sum()
    }
}

impl DatagramDeliverer<Datagram, Local> for Recorder {
    type Handoff = Handoff;
    type ClaimLock = Lock;

    fn deliver(&self, delivery: Delivery) {
        self.delivered.fetch_add(1, Ordering::SeqCst);
        self.deliveries.lock().unwrap().push(delivery);
    }
}

/// Registers `recorder` under `association` for every form of version 1.
pub fn register(
    index: &Index,
    association: MatchAssociation<Local>,
    recorder: &Arc<Recorder>,
) -> Registration {
    index.register(
        RouteMatcher::new(association, PacketForms::ALL, VERSION),
        Arc::clone(recorder) as Arc<Target>,
    )
}

/// What a newly published receiver received.
pub struct Published {
    pub registration: Registration,
    pub datagram: ExclusiveDatagram<Datagram>,
    pub deliverer: Arc<Recorder>,
}

/// The receiver of a newly published Initial entry: it records what it
/// received.
pub struct Receiver {
    deliverer: Arc<Recorder>,
    published: Arc<Mutex<Vec<Published>>>,
}

impl InitialDatagramReceiver<Vec<u8>, TestLink, Index> for Receiver {
    fn receive_first(
        self,
        registration: Registration,
        datagram: ExclusiveDatagram<Datagram>,
        _initial: RecognizedInitial<Local>,
    ) {
        self.published.lock().unwrap().push(Published {
            registration,
            datagram,
            deliverer: self.deliverer,
        });
    }
}

/// Prepares a [`Recorder`] per resumed Initial; it admits the Initials of
/// the 1200 bytes a server requires.
pub struct Factory {
    judging: Judging,
    published: Arc<Mutex<Vec<Published>>>,
}

impl InitialReceiverFactory<Vec<u8>, TestLink, Index> for Factory {
    type Receiver = Receiver;

    fn admits(&self, _initial: &RecognizedInitial<Local>, datagram: &Datagram) -> bool {
        datagram.payload().len() >= 1200
    }

    fn prepare(
        &self,
        _initial: &RecognizedInitial<Local>,
    ) -> Option<PreparedReceiver<Target, Receiver>> {
        let deliverer = Recorder::new(self.judging);
        let receiver = Receiver {
            deliverer: Arc::clone(&deliverer),
            published: Arc::clone(&self.published),
        };
        Some(PreparedReceiver::new(deliverer as Arc<Target>, receiver))
    }
}

/// A routing domain shared between threads, which accepts new Initials and
/// queues its reflow work for the test to resume.
pub struct Domain {
    pub router: Arc<Router>,
    reflow: MutexDatagramDeliveryQueue<Work>,
    published: Arc<Mutex<Vec<Published>>>,
    link: TestLink,
}

impl Domain {
    /// A domain whose new receivers judge with `judging`.
    pub fn new(judging: Judging) -> Self {
        let reflow = MutexDatagramDeliveryQueue::new(NonZeroUsize::new(16).unwrap()).unwrap();
        let published = Arc::new(Mutex::new(Vec::new()));
        let factory = Factory {
            judging,
            published: Arc::clone(&published),
        };
        let lengths = ConnectionIdLengths::new([ConnectionIdLength::new(8).unwrap()]);
        let router = DatagramRouter::new(Index::new(), lengths)
            .with_initial_acceptance(InitialAcceptance::new(factory, Arc::new(reflow.poster())));
        Self {
            router: Arc::new(router),
            reflow,
            published,
            link: link(),
        }
    }

    pub fn index(&self) -> &Index {
        self.router.index()
    }

    /// Routes `bytes` as they arrived on the domain's link.
    pub fn route(&self, bytes: Vec<u8>) {
        self.router.route(ReceivedDatagram::new(
            bytes,
            ArrivalFacts::new(self.link.clone(), Duration::ZERO, None),
        ));
    }

    /// Takes every queued reflow work.
    pub fn reflow(&mut self) -> Vec<Work> {
        std::iter::from_fn(|| self.reflow.try_recv()).collect()
    }

    /// Takes the receivers published so far.
    pub fn published(&self) -> Vec<Published> {
        std::mem::take(&mut self.published.lock().unwrap())
    }
}
