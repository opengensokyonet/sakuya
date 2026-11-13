//! A clock, an outer waker and a log for the tests, all on the test's thread.
#![allow(dead_code)]
use std::{
    cell::{Cell, RefCell},
    future::Future,
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
    time::Duration,
};

use sakuya_connection::clock::{ConnectionChoices, MonotonicClock};
use sakuya_link::{Link, LinkId, OutgoingDatagram, SendAcceptance};

pub mod parts;
pub mod strategy;

thread_local! {
    static NOW: Cell<Duration> = const { Cell::new(Duration::ZERO) };
    static SLEEPERS: RefCell<Vec<(Duration, Waker)>> = const { RefCell::new(Vec::new()) };
    static LOG: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// The test's clock: time moves only when the test says so.
#[derive(Clone, Debug, Default)]
pub struct TestClock;

/// A sleep of the test's clock.
pub struct TestSleep(Duration);

impl Future for TestSleep {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if now() >= self.0 {
            Poll::Ready(())
        } else {
            SLEEPERS.with(|s| s.borrow_mut().push((self.0, cx.waker().clone())));
            Poll::Pending
        }
    }
}

impl MonotonicClock for TestClock {
    type Instant = Duration;
    type Sleep = TestSleep;
    fn now(&self) -> Duration {
        now()
    }
    fn sleep_until(&self, at: Duration) -> TestSleep {
        TestSleep(at)
    }
    fn timer_granularity(&self) -> Duration {
        Duration::from_millis(1)
    }
}

/// A link of the tests: an identity and nothing else; its two ends are
/// `()`, and a datagram's payload is a `BytesMut`.
#[derive(Clone, Debug)]
pub struct TestLink(pub TestLinkId);

/// The identity of a [`TestLink`].
pub type TestLinkId = LinkId<(), ()>;

impl Link for TestLink {
    type Local = ();
    type Peer = ();
    type Payload = bytes::BytesMut;
    type Instant = Duration;
    type MaxDatagramSizeError = ();
    type SendError = ();
    type Send<'a> = core::future::Ready<Result<SendAcceptance<Duration>, ()>>;
    type MaxDatagramSizeChanged = core::future::Pending<()>;
    fn id(&self) -> &TestLinkId {
        &self.0
    }
    fn may_mark_ecn(&self) -> bool {
        false
    }
    fn max_datagram_size(&self) -> Result<usize, ()> {
        Ok(sakuya_link::MIN_DATAGRAM_SIZE)
    }
    fn send<'a>(&self, batch: &'a [OutgoingDatagram]) -> Self::Send<'a> {
        let count = NonZeroUsize::new(batch.len()).expect("a batch is not empty");
        core::future::ready(Ok(SendAcceptance { count, at: now() }))
    }
    fn max_datagram_size_changed(&self) -> Self::MaxDatagramSizeChanged {
        core::future::pending()
    }
}

/// The choices of the tests' compositions.
pub struct Mine;
impl ConnectionChoices for Mine {
    type Clock = TestClock;
    type Link = TestLink;
}
impl sakuya_connection::v1::Choices for Mine {
    type Crypto = sakuya_packet_protection::backend::ring::RingBackend;
    type Side = sakuya_connection::v1::Server;
    type CryptoReceiveBuffer = sakuya_connection::v1::crypto::FragmentedCryptoReceiveBuffer;
    type Recovery<V: Clone + Eq + core::fmt::Debug + 'static> =
        sakuya_recovery::factory::NewRenoRecoveryFactory<V>;
    type AckObligation = sakuya_recovery::ack_obligation::Rfc9000AckObligation<Duration>;
    type SendJournals<S: 'static, P: Clone + Eq + core::fmt::Debug + 'static> =
        sakuya_recovery::send_journals::DequeSendJournals<Duration, S, P>;
    type ApplicationError = AppClose;
    type HandshakeFailure = core::convert::Infallible;
    type Receiver = TestReceiver;
    type SendStrategy<I: sakuya_connection::send_strategy::SendStrategyTypes> =
        strategy::EventLoggingSendStrategy<I>;
    type DestinationConnectionIds = TestDestinationConnectionIds;
    type ResetTokenRegistry = TestResetTokenRegistry;
}

/// The destination connection ID strategy of the tests' compositions.
pub type TestDestinationConnectionIds =
    sakuya_connection::connection_id::sequence_map::SequenceMapDestinationConnectionIdStrategy<
        LinkId<(), ()>,
        sakuya_connection::connection_id::reset_token::PeerGroupedResetTokenRegistrar<
            (),
            std::sync::Arc<sakuya_connection::v1::stateless_reset::StatelessResetSignal>,
        >,
    >;

/// What the tests' connections register reset tokens in.
pub type TestResetTokenRegistry = std::sync::Arc<
    sakuya_datagram_routing::route::reset::StatelessResetTokens<
        (),
        std::sync::Arc<sakuya_connection::v1::stateless_reset::StatelessResetSignal>,
    >,
>;

/// The datagram receiver of the tests' logical paths: a delivery queue that
/// a routing domain of the test posts to.
pub type TestReceiver = sakuya_datagram_routing::claim::queue::DatagramDeliveryQueue<
    sakuya_datagram_routing::claim::delivery::DatagramDelivery<
        sakuya_link::ReceivedDatagram<bytes::BytesMut, TestLink>,
        (),
        sakuya_datagram_routing::claim::finish::ReleaseUnclaimed,
    >,
>;

/// The application's error type for closing, in the tests: an application
/// error code.
#[derive(Debug, PartialEq, Eq)]
pub struct AppClose(pub u32);
impl core::fmt::Display for AppClose {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "the application closed with {}", self.0)
    }
}
impl std::error::Error for AppClose {}
impl sakuya_connection::v1::close::ApplicationClose for AppClose {
    fn code(&self) -> sakuya_wire::v1::application_error::ApplicationErrorCode {
        sakuya_wire::v1::application_error::ApplicationErrorCode::new(
            sakuya_wire::var_int::VarInt::from_u32(self.0),
        )
    }
}

/// What the part `P`, which declares nothing the connection node needs, is
/// given: one per part, so a composition's facts are written by its parts.
#[allow(clippy::extra_unused_type_parameters)] // the part names the slot
pub fn nothing<P>() -> sakuya_wire::parts::HNil {
    sakuya_wire::parts::HNil
}

pub fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

pub fn now() -> Duration {
    NOW.with(Cell::get)
}

/// Move the clock to `at` and wake the sleeps that ended.
pub fn advance_to(at: Duration) {
    NOW.with(|n| n.set(at));
    let due: Vec<Waker> = SLEEPERS.with(|s| {
        let mut sleepers = s.borrow_mut();
        let (due, waiting) = std::mem::take(&mut *sleepers)
            .into_iter()
            .partition(|(end, _)| *end <= at);
        *sleepers = waiting;
        due.into_iter().map(|(_, waker)| waker).collect()
    });
    for waker in due {
        waker.wake();
    }
}

pub fn log(line: impl Into<String>) {
    LOG.with(|l| l.borrow_mut().push(line.into()));
}

pub fn take_log() -> Vec<String> {
    LOG.with(|l| std::mem::take(&mut *l.borrow_mut()))
}

/// An outer waker that counts its wakes.
#[derive(Default)]
pub struct Counter(AtomicUsize);
impl Wake for Counter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

pub struct Outer {
    counter: Arc<Counter>,
    waker: Waker,
}

impl Outer {
    pub fn new() -> Self {
        let counter = Arc::new(Counter::default());
        Self {
            waker: Waker::from(counter.clone()),
            counter,
        }
    }
    pub fn wakes(&self) -> usize {
        self.counter.0.load(Ordering::SeqCst)
    }
    pub fn poll<F: Future + Unpin>(&self, future: &mut F) -> Poll<F::Output> {
        Pin::new(future).poll(&mut Context::from_waker(&self.waker))
    }
}
