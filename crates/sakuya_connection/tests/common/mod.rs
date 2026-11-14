//! A clock, an outer waker and a log for the tests, all on the test's thread.
#![allow(dead_code)]
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
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

use bytes::Bytes;
use sakuya_connection::clock::{ConnectionChoices, MonotonicClock};
use sakuya_link::{Link, LinkId, MIN_DATAGRAM_SIZE, OutgoingDatagram, SendAcceptance};

pub mod parts;
pub mod strategy;

thread_local! {
    static NOW: Cell<Duration> = const { Cell::new(Duration::ZERO) };
    static SLEEPERS: RefCell<Vec<(Duration, Waker)>> = const { RefCell::new(Vec::new()) };
    static LOG: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    static LINK_CEILING: Cell<usize> = const { Cell::new(MIN_DATAGRAM_SIZE) };
    static SEND_OUTCOMES: RefCell<VecDeque<SendOutcome>> = const { RefCell::new(VecDeque::new()) };
    static SENT: RefCell<Vec<(Duration, Bytes)>> = const { RefCell::new(Vec::new()) };
    static GIVEN_UP: RefCell<Vec<Bytes>> = const { RefCell::new(Vec::new()) };
    static HELD: RefCell<Option<Waker>> = const { RefCell::new(None) };
    static RELEASED: Cell<bool> = const { Cell::new(false) };
    static BATCHES: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
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
///
/// What it does with a batch is what the test planned with
/// [`plan_sends`], and accepting all of it otherwise; what it accepted and
/// gave up is kept for [`take_sent`] and [`take_given_up`]. The largest
/// datagram it takes is 1200 bytes unless [`set_link_ceiling`] says
/// otherwise.
#[derive(Clone, Debug)]
pub struct TestLink(pub TestLinkId);

/// What a test link does with the next batch handed to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    /// Accept the first datagrams, at most this many, and leave the rest.
    Accept(usize),
    /// Give the first datagram up.
    GiveUp,
    /// Keep the sender waiting until [`release_held_send`], then accept
    /// the first datagrams, at most this many.
    Hold(usize),
}

/// What the test links do with the next batches, in order; past these
/// they accept every datagram.
pub fn plan_sends(outcomes: impl IntoIterator<Item = SendOutcome>) {
    SEND_OUTCOMES.with(|o| o.borrow_mut().extend(outcomes));
}

/// The datagrams the test links accepted since the last call, with the
/// instant they accepted them, in order.
pub fn take_sent() -> Vec<(Duration, Bytes)> {
    SENT.with(|s| std::mem::take(&mut *s.borrow_mut()))
}

/// How many datagrams each batch handed to the test links since the last
/// call held, in order.
pub fn take_batch_sizes() -> Vec<usize> {
    BATCHES.with(|b| std::mem::take(&mut *b.borrow_mut()))
}

/// The datagrams the test links gave up since the last call, in order.
pub fn take_given_up() -> Vec<Bytes> {
    GIVEN_UP.with(|g| std::mem::take(&mut *g.borrow_mut()))
}

/// Let the batch a test link keeps the sender waiting on be accepted.
pub fn release_held_send() {
    RELEASED.with(|r| r.set(true));
    if let Some(waker) = HELD.with(|h| h.borrow_mut().take()) {
        waker.wake();
    }
}

/// The largest datagram the test links take from now on: below 1200
/// bytes, a link path over them sends nothing.
pub fn set_link_ceiling(size: usize) {
    LINK_CEILING.with(|c| c.set(size));
}

/// Forget what the test links were told to do and what they did.
pub fn reset_links() {
    LINK_CEILING.with(|c| c.set(MIN_DATAGRAM_SIZE));
    SEND_OUTCOMES.with(|o| o.borrow_mut().clear());
    SENT.with(|s| s.borrow_mut().clear());
    GIVEN_UP.with(|g| g.borrow_mut().clear());
    HELD.with(|h| h.borrow_mut().take());
    RELEASED.with(|r| r.set(false));
    BATCHES.with(|b| b.borrow_mut().clear());
}

/// One send of a test link: what it does is decided when it is first
/// polled.
pub struct TestSend<'a> {
    batch: &'a [OutgoingDatagram],
    outcome: Option<SendOutcome>,
}

impl Future for TestSend<'_> {
    type Output = Result<SendAcceptance<Duration>, ()>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let outcome = *self.outcome.get_or_insert_with(|| {
            SEND_OUTCOMES
                .with(|o| o.borrow_mut().pop_front())
                .unwrap_or(SendOutcome::Accept(usize::MAX))
        });
        let count = match outcome {
            SendOutcome::Accept(count) => count.min(self.batch.len()),
            SendOutcome::GiveUp => {
                GIVEN_UP.with(|g| g.borrow_mut().push(self.batch[0].payload.clone()));
                return Poll::Ready(Err(()));
            }
            SendOutcome::Hold(count) => {
                if !RELEASED.with(|r| r.replace(false)) {
                    HELD.with(|h| *h.borrow_mut() = Some(cx.waker().clone()));
                    return Poll::Pending;
                }
                count.min(self.batch.len())
            }
        };
        let at = now();
        SENT.with(|s| {
            s.borrow_mut().extend(
                self.batch[..count]
                    .iter()
                    .map(|datagram| (at, datagram.payload.clone())),
            )
        });
        let count = NonZeroUsize::new(count).expect("a test accepts at least one datagram");
        Poll::Ready(Ok(SendAcceptance { count, at }))
    }
}

/// The identity of a [`TestLink`].
pub type TestLinkId = LinkId<(), ()>;

impl Link for TestLink {
    type Local = ();
    type Peer = ();
    type Payload = bytes::BytesMut;
    type Instant = Duration;
    type MaxDatagramSizeError = ();
    type SendError = ();
    type Send<'a> = TestSend<'a>;
    type MaxDatagramSizeChanged = core::future::Pending<()>;
    fn id(&self) -> &TestLinkId {
        &self.0
    }
    fn may_mark_ecn(&self) -> bool {
        false
    }
    fn max_datagram_size(&self) -> Result<usize, ()> {
        Ok(LINK_CEILING.with(Cell::get))
    }
    fn send<'a>(&self, batch: &'a [OutgoingDatagram]) -> Self::Send<'a> {
        assert!(!batch.is_empty(), "a batch is not empty");
        BATCHES.with(|b| b.borrow_mut().push(batch.len()));
        TestSend {
            batch,
            outcome: None,
        }
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
