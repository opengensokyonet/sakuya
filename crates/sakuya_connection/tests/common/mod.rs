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
use nitori_call::LentAccess;
use nitori_crypto_aws_lc::AwsLcBackend;
use nitori_tls::{
    client::engine::{
        ClientHandshakeCapability, ClientHandshakeCompleted, ClientHandshakeSteps, ClientTransport,
        EarlyDataOffered, ServerHelloRead,
    },
    engine::HandshakeError,
    schedule::OneRttSendTrafficSecret,
    server::engine::{
        FirstClientHello, ReadFirstClientHelloError, ServerHandshakeCapability,
        ServerHandshakeCompleted, ServerHandshakeSteps, ServerHelloWritten, ServerTransport,
    },
};
use sakuya_connection::clock::{ConnectionChoices, MonotonicClock};
use sakuya_link::{EcnMarking, Link, LinkId, MIN_DATAGRAM_SIZE, OutgoingDatagram, SendAcceptance};

pub mod ending;
pub mod events;
pub mod parts;
pub mod strategy;

thread_local! {
    static NOW: Cell<Duration> = const { Cell::new(Duration::ZERO) };
    static SLEEPERS: RefCell<Vec<(Duration, Waker)>> = const { RefCell::new(Vec::new()) };
    static LOG: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    static LINK_CEILING: Cell<usize> = const { Cell::new(MIN_DATAGRAM_SIZE) };
    static SEND_OUTCOMES: RefCell<VecDeque<SendOutcome>> = const { RefCell::new(VecDeque::new()) };
    static SENT: RefCell<Vec<(Duration, Bytes)>> = const { RefCell::new(Vec::new()) };
    static SENT_MARKINGS: RefCell<Vec<(TestLinkId, EcnMarking)>> = const { RefCell::new(Vec::new()) };
    static MARKS_ECN: Cell<bool> = const { Cell::new(false) };
    static GIVEN_UP: RefCell<Vec<Bytes>> = const { RefCell::new(Vec::new()) };
    static HELD: RefCell<Option<Waker>> = const { RefCell::new(None) };
    static RELEASED: Cell<bool> = const { Cell::new(false) };
    static BATCHES: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
    static CEILINGS: RefCell<Vec<(TestLinkId, LinkCeiling)>> = const { RefCell::new(Vec::new()) };
    static ENDS: RefCell<Vec<(TestLinkId, LinkEnd)>> = const { RefCell::new(Vec::new()) };
    static CLOSE_PHRASE: RefCell<Option<Bytes>> = const { RefCell::new(None) };
    static ADJUSTED: RefCell<Vec<sakuya_wire_v1::encryption_level::EncryptionLevel>> = const { RefCell::new(Vec::new()) };
    static USED_BY_PEER: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
    static ADMISSION: Cell<TestAdmission> = const { Cell::new(TestAdmission::Accept) };
    static SWITCH: Cell<sakuya_connection::v1::migration::SwitchTiming> =
        const { Cell::new(sakuya_connection::v1::migration::SwitchTiming::Now) };
    static RESEND_AFTER: Cell<Option<Duration>> = const { Cell::new(None) };
    static NEW_PATH_ABANDON_AFTER: Cell<Option<Duration>> = const { Cell::new(None) };
    static ACCEPTED_AFTER: Cell<Duration> = const { Cell::new(Duration::ZERO) };
    static ISSUES_NEW_TOKENS: Cell<bool> = const { Cell::new(true) };
    static NEW_TOKENS_ISSUED: RefCell<Vec<Bytes>> = const { RefCell::new(Vec::new()) };
    static TOKENS_KEPT: RefCell<Vec<Bytes>> = const { RefCell::new(Vec::new()) };
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
/// gave up is kept for [`take_sent`] and [`take_given_up`]. Its datagram size
/// limit is 1200 bytes unless [`set_link_ceilings`] or, for that link,
/// [`set_link_ceiling`] says otherwise, and it reports a change only when
/// [`report_link_ceiling_changed`] says so. It ends only when [`end_link`]
/// says so, and may mark ECN only when [`set_links_mark_ecn`] says so; the
/// marking of what it accepted is kept for [`take_sent_markings`].
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

/// The link and the ECN marking of each datagram the test links accepted
/// since the last call, in order.
pub fn take_sent_markings() -> Vec<(TestLinkId, EcnMarking)> {
    SENT_MARKINGS.with(|s| std::mem::take(&mut *s.borrow_mut()))
}

/// Whether the test links may mark ECN; they may not unless a test says
/// so.
pub fn set_links_mark_ecn(marks: bool) {
    MARKS_ECN.with(|m| m.set(marks));
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

/// The largest datagram the test links take from now on, unless one is set
/// for the link: below 1200 bytes, a link path over them sends nothing.
pub fn set_link_ceilings(size: usize) {
    LINK_CEILING.with(|c| c.set(size));
}

/// Forget what the test links were told to do and what they did.
pub fn reset_links() {
    LINK_CEILING.with(|c| c.set(MIN_DATAGRAM_SIZE));
    CEILINGS.with(|ceilings| ceilings.borrow_mut().clear());
    ENDS.with(|ends| ends.borrow_mut().clear());
    SEND_OUTCOMES.with(|o| o.borrow_mut().clear());
    SENT.with(|s| s.borrow_mut().clear());
    SENT_MARKINGS.with(|s| s.borrow_mut().clear());
    MARKS_ECN.with(|m| m.set(false));
    GIVEN_UP.with(|g| g.borrow_mut().clear());
    HELD.with(|h| h.borrow_mut().take());
    RELEASED.with(|r| r.set(false));
    BATCHES.with(|b| b.borrow_mut().clear());
    NEW_TOKENS_ISSUED.with(|i| i.borrow_mut().clear());
    TOKENS_KEPT.with(|k| k.borrow_mut().clear());
}

/// The issuer of the NEW_TOKEN tokens of the tests' servers: the n-th
/// token it issues is `token-n`, counted from 1, whatever the peer, unless
/// [`set_new_token_issuing`] said it issues none.
#[derive(Debug, Default)]
pub struct TestNewTokenIssuer;

impl<P> sakuya_connection::v1::address_token::ConnectionNewTokenIssuer<P> for TestNewTokenIssuer {
    fn issue(&self, _: &P) -> Option<Bytes> {
        if !ISSUES_NEW_TOKENS.with(Cell::get) {
            return None;
        }
        NEW_TOKENS_ISSUED.with(|issued| {
            let mut issued = issued.borrow_mut();
            let token = Bytes::from(format!("token-{}", issued.len() + 1));
            issued.push(token.clone());
            Some(token)
        })
    }
}

/// Whether the tests' issuer issues tokens from now on; it does until told
/// otherwise, and making the links afresh ([`reset_links`]) does not change
/// it.
pub fn set_new_token_issuing(issues: bool) {
    ISSUES_NEW_TOKENS.with(|i| i.set(issues));
}

/// The tokens the tests' issuer issued, in order.
pub fn new_tokens_issued() -> Vec<Bytes> {
    NEW_TOKENS_ISSUED.with(|i| i.borrow().clone())
}

/// Where the tests' clients put the tokens their servers give.
#[derive(Debug, Default)]
pub struct TestTokenSink;

impl sakuya_connection::v1::address_token::AddressTokenSink for TestTokenSink {
    fn keep(&self, token: Bytes) {
        TOKENS_KEPT.with(|k| k.borrow_mut().push(token));
    }
}

/// The tokens the tests' clients kept, in order.
pub fn tokens_kept() -> Vec<Bytes> {
    TOKENS_KEPT.with(|k| k.borrow().clone())
}

/// One send of a test link: what it does is decided when it is first
/// polled.
pub struct TestSend<'a> {
    link: TestLinkId,
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
        let at = now() + ACCEPTED_AFTER.with(Cell::get);
        SENT_MARKINGS.with(|s| {
            s.borrow_mut().extend(
                self.batch[..count]
                    .iter()
                    .map(|datagram| (self.link.clone(), datagram.ecn)),
            )
        });
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
    type RecvError = ();
    type Recv<'a> =
        core::future::Pending<Result<sakuya_link::ReceivedDatagram<Self::Payload, Self>, ()>>;
    type Ended = TestLinkEnded;
    type Send<'a> = TestSend<'a>;
    type MaxDatagramSizeChanged = LinkCeilingChanged;
    fn id(&self) -> &TestLinkId {
        &self.0
    }
    fn may_mark_ecn(&self) -> bool {
        MARKS_ECN.with(Cell::get)
    }
    fn max_datagram_size(&self) -> Result<usize, ()> {
        let set = with_ceiling(&self.0, |ceiling| ceiling.size);
        Ok(set.unwrap_or_else(|| LINK_CEILING.with(Cell::get)))
    }
    fn recv(&self) -> Self::Recv<'_> {
        core::future::pending()
    }
    fn ended(&self) -> Self::Ended {
        TestLinkEnded(self.0.clone())
    }
    fn send<'a>(&self, batch: &'a [OutgoingDatagram]) -> Self::Send<'a> {
        assert!(!batch.is_empty(), "a batch is not empty");
        BATCHES.with(|b| b.borrow_mut().push(batch.len()));
        TestSend {
            link: self.0.clone(),
            batch,
            outcome: None,
        }
    }
    fn max_datagram_size_changed(&self) -> Self::MaxDatagramSizeChanged {
        LinkCeilingChanged {
            link: self.0.clone(),
            since: with_ceiling(&self.0, |ceiling| ceiling.reports),
        }
    }
}

/// The datagram size limit of one of the tests' links, if set for it, how
/// many changes it has reported and who waits for the next.
struct LinkCeiling {
    size: Option<usize>,
    reports: u64,
    waiting: Vec<Waker>,
}

fn with_ceiling<R>(link: &TestLinkId, f: impl FnOnce(&mut LinkCeiling) -> R) -> R {
    CEILINGS.with(|ceilings| {
        let mut ceilings = ceilings.borrow_mut();
        let at = match ceilings.iter().position(|(id, _)| id == link) {
            Some(at) => at,
            None => {
                ceilings.push((
                    link.clone(),
                    LinkCeiling {
                        size: None,
                        reports: 0,
                        waiting: Vec::new(),
                    },
                ));
                ceilings.len() - 1
            }
        };
        f(&mut ceilings[at].1)
    })
}

/// Make the datagram size limit of the test link `link` `size`, without
/// reporting the change.
pub fn set_link_ceiling(link: &TestLinkId, size: usize) {
    with_ceiling(link, |ceiling| ceiling.size = Some(size));
}

/// Report a change of the datagram size limit of the test link `link`: the
/// futures made before are ready.
pub fn report_link_ceiling_changed(link: &TestLinkId) {
    let waiting = with_ceiling(link, |ceiling| {
        ceiling.reports += 1;
        std::mem::take(&mut ceiling.waiting)
    });
    for waker in waiting {
        waker.wake();
    }
}

/// Ready once the test link has reported a change of its limit since the
/// future was made.
pub struct LinkCeilingChanged {
    link: TestLinkId,
    since: u64,
}

impl Future for LinkCeilingChanged {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        with_ceiling(&self.link, |ceiling| {
            if ceiling.reports > self.since {
                Poll::Ready(())
            } else {
                ceiling.waiting.push(cx.waker().clone());
                Poll::Pending
            }
        })
    }
}

/// Whether one of the tests' links ended, and who waits for its end.
#[derive(Default)]
struct LinkEnd {
    ended: bool,
    waiting: Vec<Waker>,
}

fn with_end<R>(link: &TestLinkId, f: impl FnOnce(&mut LinkEnd) -> R) -> R {
    ENDS.with(|ends| {
        let mut ends = ends.borrow_mut();
        let at = match ends.iter().position(|(id, _)| id == link) {
            Some(at) => at,
            None => {
                ends.push((link.clone(), LinkEnd::default()));
                ends.len() - 1
            }
        };
        f(&mut ends[at].1)
    })
}

/// End the test link `link`: the futures of its end are ready, with `()`
/// as its reason.
pub fn end_link(link: &TestLinkId) {
    let waiting = with_end(link, |end| {
        end.ended = true;
        std::mem::take(&mut end.waiting)
    });
    for waker in waiting {
        waker.wake();
    }
}

/// Ready once [`end_link`] ended the test link.
pub struct TestLinkEnded(TestLinkId);

impl Future for TestLinkEnded {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        with_end(&self.0, |end| {
            if end.ended {
                Poll::Ready(())
            } else {
                end.waiting.push(cx.waker().clone());
                Poll::Pending
            }
        })
    }
}

/// The start state of a server's handshake engine that never gets past
/// its first step: every step waits forever.
pub struct PendingServerEngine;

impl ServerHandshakeSteps for PendingServerEngine {
    type Crypto = AwsLcBackend;
    type Target = ();
    type AlertError = ReadFirstClientHelloError;
    type ServerHelloWrittenState = ();
    type ServerFinishedWrittenState = ();
    type ServerHandshakeCompletedState = ();

    async fn write_server_hello<W: ServerHandshakeCapability<()>>(
        self,
        _: FirstClientHello,
        _: &mut impl LentAccess<Family = W>,
    ) -> Result<
        (ServerHelloWritten<()>, ()),
        HandshakeError<ReadFirstClientHelloError, <W as ServerTransport<()>>::Error>,
    > {
        core::future::pending().await
    }

    async fn write_server_finished<W: ServerHandshakeCapability<()>>(
        (): (),
        _: &mut impl LentAccess<Family = W>,
    ) -> Result<
        (OneRttSendTrafficSecret, ()),
        HandshakeError<ReadFirstClientHelloError, <W as ServerTransport<()>>::Error>,
    > {
        core::future::pending().await
    }

    async fn read_client_finished<W: ServerHandshakeCapability<()>>(
        (): (),
        _: &mut impl LentAccess<Family = W>,
    ) -> Result<
        (ServerHandshakeCompleted<AwsLcBackend, ()>, ()),
        HandshakeError<ReadFirstClientHelloError, <W as ServerTransport<()>>::Error>,
    > {
        core::future::pending().await
    }

    async fn write_tickets<W: ServerHandshakeCapability<()>>(
        (): (),
        _: &mut impl LentAccess<Family = W>,
    ) -> Result<(), HandshakeError<ReadFirstClientHelloError, <W as ServerTransport<()>>::Error>>
    {
        core::future::pending().await
    }
}

/// The start state of a client's handshake engine that never gets past
/// its first step: every step waits forever.
pub struct PendingClientEngine;

impl ClientHandshakeSteps for PendingClientEngine {
    type Crypto = AwsLcBackend;
    type AlertError = core::convert::Infallible;
    type ClientHelloWrittenState = ();
    type ServerHelloReadState = ();
    type ClientHandshakeCompletedState = ();

    async fn write_client_hello<W: ClientHandshakeCapability>(
        self,
        _: &mut impl LentAccess<Family = W>,
    ) -> Result<
        (Option<EarlyDataOffered>, ()),
        HandshakeError<core::convert::Infallible, <W as ClientTransport>::Error>,
    > {
        core::future::pending().await
    }

    async fn read_server_hello<W: ClientHandshakeCapability>(
        (): (),
        _: &mut impl LentAccess<Family = W>,
    ) -> Result<
        (ServerHelloRead, ()),
        HandshakeError<core::convert::Infallible, <W as ClientTransport>::Error>,
    > {
        core::future::pending().await
    }

    async fn read_server_finished<W: ClientHandshakeCapability>(
        (): (),
        _: &mut impl LentAccess<Family = W>,
    ) -> Result<
        (ClientHandshakeCompleted<AwsLcBackend>, ()),
        HandshakeError<core::convert::Infallible, <W as ClientTransport>::Error>,
    > {
        core::future::pending().await
    }

    async fn read_tickets<W: ClientHandshakeCapability>(
        (): (),
        _: &mut impl LentAccess<Family = W>,
    ) -> Result<
        core::convert::Infallible,
        HandshakeError<core::convert::Infallible, <W as ClientTransport>::Error>,
    > {
        core::future::pending().await
    }
}

/// The choices of the tests' compositions.
pub struct Mine;
impl ConnectionChoices for Mine {
    type Clock = TestClock;
    type Link = TestLink;
}
impl sakuya_connection::v1::MakerChoices for Mine {
    type Crypto = sakuya_packet_protection::backend::ring::RingBackend;
    type Side = sakuya_connection::v1::Server<PendingServerEngine, TestNewTokenIssuer>;
    type Receiver = TestReceiver;
    type ResetTokenRegistry = TestResetTokenRegistry;
    type ConnectionIdIssuer = TestConnectionIdIssuer;
}
impl sakuya_connection::v1::Choices for Mine {
    type Host = Self;
}
impl sakuya_connection::v1::HostChoices<Mine> for Mine {
    type ApplicationError = AppClose;
    type SendStrategy<I: sakuya_connection::send_strategy::SendStrategyTypes> =
        strategy::EventLoggingSendStrategy<I>;
    type DestinationConnectionIds = TestDestinationConnectionIds;
    type LocalConnectionIds = TestLocalConnectionIds;
    type ImmediateClosePolicy = TestImmediateClosePolicy;
    type MigrationPolicy = TestMigrationPolicy;
    // every event is recorded, so each test also runs what records them
    type Events<L> = events::RecordingEvents;
}

/// The close policy of the tests' compositions: it notes the level of each
/// close it adjusts, and gives the close the reason phrase
/// [`set_close_phrase`] set, if any.
#[derive(Debug, Clone, Copy, Default)]
pub struct TestImmediateClosePolicy;

impl<C> sakuya_connection::v1::close::ImmediateClosePolicy<C> for TestImmediateClosePolicy {
    fn adjust(
        &mut self,
        _: &C,
        level: sakuya_wire_v1::encryption_level::EncryptionLevel,
        mut close: sakuya_stream::connection::ImmediateClose,
    ) -> sakuya_stream::connection::ImmediateClose {
        use sakuya_stream::connection::ImmediateClose;
        ADJUSTED.with(|adjusted| adjusted.borrow_mut().push(level));
        if let Some(phrase) = CLOSE_PHRASE.with(|phrase| phrase.borrow().clone()) {
            match &mut close {
                ImmediateClose::Transport(close) => close.reason_phrase = phrase,
                ImmediateClose::Application(close) => close.reason_phrase = phrase,
            }
        }
        close
    }
}

/// The reason phrase the tests' close policy gives every close from now
/// on; `None` leaves the one the error gives.
pub fn set_close_phrase(phrase: Option<Bytes>) {
    CLOSE_PHRASE.with(|p| *p.borrow_mut() = phrase);
}

/// The levels the tests' close policy adjusted a close for since the last
/// call, in order.
pub fn take_adjusted_levels() -> Vec<sakuya_wire_v1::encryption_level::EncryptionLevel> {
    ADJUSTED.with(|adjusted| std::mem::take(&mut *adjusted.borrow_mut()))
}

/// Forget what the tests' close policy was told and noted.
pub fn reset_close_policy() {
    set_close_phrase(None);
    take_adjusted_levels();
}

/// The destination connection ID strategy of the tests' compositions.
pub type TestDestinationConnectionIds =
    sakuya_connection::connection_id::sequence_map::SequenceMapDestinationConnectionIdStrategy<
        LinkId<(), ()>,
        TestResetTokenRegistrar,
    >;

/// What registers the reset tokens of the peer's connection IDs for each
/// link path of the tests' compositions.
pub type TestResetTokenRegistrar =
    sakuya_connection::connection_id::reset_token::PeerGroupedResetTokenRegistrar<
        TestResetTokenRegistry,
        (),
        std::sync::Arc<sakuya_connection::v1::stateless_reset::StatelessResetSignal>,
    >;

/// What issues the tests' connections' connection IDs after the first:
/// `[0xc0 + n; 8]` for the n-th, with the token `[0xd0 + n; 16]`. Nothing
/// routes them: a registration is nothing.
#[derive(Debug, Default)]
pub struct TestConnectionIdIssuer(u8);

impl sakuya_connection::connection_id::local::ConnectionIdIssuer for TestConnectionIdIssuer {
    type Registration = ();

    fn issue(&mut self) -> sakuya_connection::connection_id::local::IssuedConnectionId<()> {
        self.0 += 1;
        let id = sakuya_wire::connection_id::ConnectionId::new(&[0xc0 + self.0; 8])
            .expect("eight bytes");
        sakuya_connection::connection_id::local::IssuedConnectionId {
            id: sakuya_wire::connection_id::NonEmptyCid::new(id).expect("not empty"),
            token: sakuya_wire::connection_id::StatelessResetToken::new([0xd0 + self.0; 16]),
            registration: (),
        }
    }
}

/// The local connection ID strategy of the tests' compositions.
#[derive(Debug)]
pub struct TestLocalConnectionIds(
    sakuya_connection::connection_id::local::SequenceMapLocalConnectionIdStrategy<(), Duration>,
);

/// sakuya's strategy, which notes each connection ID the peer switched to
/// for [`take_used_by_peer`].
impl<Id> sakuya_connection::connection_id::local::LocalConnectionIdStrategy<Id, Duration, ()>
    for TestLocalConnectionIds
{
    fn new(
        first: Option<sakuya_connection::connection_id::local::IssuedConnectionId<()>>,
        preferred: Option<sakuya_connection::connection_id::local::IssuedConnectionId<()>>,
    ) -> Self {
        Self(
            <sakuya_connection::connection_id::local::SequenceMapLocalConnectionIdStrategy<
                (),
                Duration,
            > as sakuya_connection::connection_id::local::LocalConnectionIdStrategy<
                Id,
                Duration,
                (),
            >>::new(first, preferred),
        )
    }
    fn on_issuable<C>(&mut self, issuer: &mut C, peer_limit: u64) -> bool
    where
        C: sakuya_connection::connection_id::local::ConnectionIdIssuer<Registration = ()>,
    {
        sakuya_connection::connection_id::local::LocalConnectionIdStrategy::<Id, Duration, ()>::on_issuable(
            &mut self.0, issuer, peer_limit,
        )
    }
    fn on_handshake_confirmed<C>(&mut self, issuer: &mut C) -> bool
    where
        C: sakuya_connection::connection_id::local::ConnectionIdIssuer<Registration = ()>,
    {
        sakuya_connection::connection_id::local::LocalConnectionIdStrategy::<Id, Duration, ()>::on_handshake_confirmed(
            &mut self.0, issuer,
        )
    }
    fn on_zero_rtt_rejected<C>(&mut self, issuer: &mut C, peer_limit: u64) -> bool
    where
        C: sakuya_connection::connection_id::local::ConnectionIdIssuer<Registration = ()>,
    {
        sakuya_connection::connection_id::local::LocalConnectionIdStrategy::<Id, Duration, ()>::on_zero_rtt_rejected(
            &mut self.0, issuer, peer_limit,
        )
    }
    fn on_retired_by_peer<C>(
        &mut self,
        issuer: &mut C,
        sequence: u64,
        packet_destination: &sakuya_wire::connection_id::ConnectionId,
        now: Duration,
        pto: Duration,
    ) -> Result<bool, sakuya_connection::connection_id::local::RetiredByPeerViolationError>
    where
        C: sakuya_connection::connection_id::local::ConnectionIdIssuer<Registration = ()>,
    {
        sakuya_connection::connection_id::local::LocalConnectionIdStrategy::<Id, Duration, ()>::on_retired_by_peer(
            &mut self.0, issuer, sequence, packet_destination, now, pto,
        )
    }
    fn on_used_by_peer<C>(
        &mut self,
        issuer: &mut C,
        id: &sakuya_wire::connection_id::ConnectionId,
        link_path: &Id,
    ) -> bool
    where
        C: sakuya_connection::connection_id::local::ConnectionIdIssuer<Registration = ()>,
    {
        USED_BY_PEER.with(|used| used.borrow_mut().push(id.as_bytes().to_vec()));
        sakuya_connection::connection_id::local::LocalConnectionIdStrategy::<Id, Duration, ()>::on_used_by_peer(
            &mut self.0, issuer, id, link_path,
        )
    }
    fn next_deadline(&self) -> Option<Duration> {
        sakuya_connection::connection_id::local::LocalConnectionIdStrategy::<Id, Duration, ()>::next_deadline(
            &self.0,
        )
    }
    fn on_deadline<C>(&mut self, issuer: &mut C, now: Duration) -> bool
    where
        C: sakuya_connection::connection_id::local::ConnectionIdIssuer<Registration = ()>,
    {
        sakuya_connection::connection_id::local::LocalConnectionIdStrategy::<Id, Duration, ()>::on_deadline(
            &mut self.0, issuer, now,
        )
    }
    fn waiting_disclosures(
        &self,
    ) -> impl Iterator<Item = sakuya_connection::connection_id::local::NewConnectionIdIntent> + '_
    {
        sakuya_connection::connection_id::local::LocalConnectionIdStrategy::<Id, Duration, ()>::waiting_disclosures(
            &self.0,
        )
    }
}

impl sakuya_connection::frame_source::FrameSource for TestLocalConnectionIds {
    type Summary = sakuya_connection::connection_id::local::NewConnectionIdSummary;
    type Class = sakuya_wire_v1::frame::write::InFlightClass;
    type Item<'a> = u64;

    fn supply<W, P, Idx>(
        &mut self,
        item: u64,
        packet: sakuya_connection::write::OpenPacket<W, Self::Class, P>,
    ) -> sakuya_connection::write::Supplied<W, Self::Class, P>
    where
        W: sakuya_connection::write::PacketWriting,
        sakuya_connection::write::SummaryOf<W>:
            sakuya_connection::feedback::InjectSummary<Self::Summary, Idx>,
        P: sakuya_connection::write::PacketPosition,
    {
        self.0.supply::<W, P, Idx>(item, packet)
    }
    fn delivered(
        &mut self,
        space: sakuya_recovery::packet_number_space::PacketNumberSpaceKind,
        summary: Self::Summary,
    ) {
        self.0.delivered(space, summary);
    }
    fn lost(
        &mut self,
        space: sakuya_recovery::packet_number_space::PacketNumberSpaceKind,
        summary: &Self::Summary,
    ) {
        self.0.lost(space, summary);
    }
    fn unfulfilled(
        &mut self,
        item: u64,
        cause: sakuya_stream::send_options::destination::Unfulfilled,
    ) {
        self.0.unfulfilled(item, cause);
    }
}

impl TestLocalConnectionIds {
    /// sakuya's strategy, which this one notes the switches of.
    pub fn inner(
        &self,
    ) -> &sakuya_connection::connection_id::local::SequenceMapLocalConnectionIdStrategy<(), Duration>
    {
        &self.0
    }
}

/// The connection IDs the peer switched to that the tests' local
/// connection ID strategies were told of since the last call, in order.
pub fn take_used_by_peer() -> Vec<Vec<u8>> {
    USED_BY_PEER.with(|used| std::mem::take(&mut *used.borrow_mut()))
}

/// The issuer of a test connection whose first local connection ID is
/// `first`, with the registration of an issued one.
pub fn local_connection_id_issuer(
    first: &sakuya_connection::v1::connection_ids::FirstLocalConnectionId,
) -> sakuya_connection::v1::connection_ids::LocalConnectionIdIssuer<TestConnectionIdIssuer> {
    use sakuya_connection::v1::connection_ids::FirstLocalConnectionId;
    let registration = match first {
        FirstLocalConnectionId::Issued { .. } => Some(()),
        FirstLocalConnectionId::ZeroLength => None,
    };
    sakuya_connection::v1::connection_ids::LocalConnectionIdIssuer::new(
        TestConnectionIdIssuer::default(),
        registration,
    )
}

/// What the tests' connections register reset tokens in.
pub type TestResetTokenRegistry =
    sakuya_datagram_routing::route::reset::HashMapStatelessResetTokens<
        (),
        std::sync::Arc<sakuya_connection::v1::stateless_reset::StatelessResetSignal>,
        std::hash::RandomState,
    >;

/// The datagram receiver of the tests' logical paths: a delivery queue that
/// a routing domain of the test posts to.
pub type TestReceiver = sakuya_datagram_routing::claim::queue::RefCellDatagramDeliveryQueue<
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
    fn code(&self) -> sakuya_wire_v1::application_error::ApplicationErrorCode {
        sakuya_wire_v1::application_error::ApplicationErrorCode::new(
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

/// What the tests' migration policy answers for a packet from a new
/// logical link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestAdmission {
    /// Build the link path, ending nothing first.
    Accept,
    /// Build the link path, after ending every link path there is, which
    /// the fixed part keeps the active one and the fallback of.
    AcceptEndingAll,
    /// Drop the datagram's packets.
    Drop,
}

/// What the tests' migration policy answers from now on: `admission` for a
/// packet from a new logical link, `switch` for a peer that moved.
pub fn set_migration(
    admission: TestAdmission,
    switch: sakuya_connection::v1::migration::SwitchTiming,
) {
    ADMISSION.with(|a| a.set(admission));
    SWITCH.with(|s| s.set(switch));
}

/// The migration policy of the tests' compositions: it logs each question
/// it is asked, and answers as [`set_migration`] says, accepting and
/// switching at once unless told otherwise. The ends of the tests' links are
/// `()`, which state no network address: it always gets a new recovery
/// layer. A PATH_CHALLENGE goes again after the link path's probe timeout,
/// unless [`set_challenge_resend`] says otherwise, and validation gives up
/// after three probe timeouts of a new path. A `Settling` link path keeps
/// for three probe timeouts.
#[derive(Debug, Default)]
pub struct TestMigrationPolicy;

impl<Lo: Clone, P: Clone, I: Copy + core::fmt::Debug>
    sakuya_connection::v1::migration::MigrationPolicy<Lo, P, I> for TestMigrationPolicy
{
    fn admit(
        &mut self,
        cx: &sakuya_connection::v1::migration::LinkPathAdmissionContext<'_, Lo, P, I>,
    ) -> sakuya_connection::v1::migration::LinkPathAdmission<Lo, P> {
        use sakuya_connection::v1::migration::LinkPathAdmission;
        let roles: Vec<_> = cx
            .link_paths
            .iter()
            .map(|facts| {
                format!(
                    "{:?}{}{}",
                    facts.role,
                    match facts.validation {
                        sakuya_connection::v1::amplification::AddressValidation::Validated => {
                            " validated"
                        }
                        sakuya_connection::v1::amplification::AddressValidation::NotValidated => "",
                    },
                    if facts.fallback { " fallback" } else { "" }
                )
            })
            .collect();
        log(format!(
            "admit at {:?}: {roles:?}, peer switched {}, migration disabled {}",
            cx.now, cx.peer_switched_local_id, cx.local_disabled_active_migration
        ));
        match ADMISSION.with(Cell::get) {
            TestAdmission::Accept => LinkPathAdmission::Accept { end: Vec::new() },
            TestAdmission::AcceptEndingAll => LinkPathAdmission::Accept {
                end: cx
                    .link_paths
                    .iter()
                    .map(|facts| facts.link.clone())
                    .collect(),
            },
            TestAdmission::Drop => LinkPathAdmission::Drop,
        }
    }

    fn on_peer_moved(
        &mut self,
        cx: &sakuya_connection::v1::migration::PeerMovedContext<'_, Lo, P, I>,
    ) -> sakuya_connection::v1::migration::MigrationDecision<Lo, P> {
        let timing = SWITCH.with(Cell::get);
        log(format!(
            "peer moved at {:?}, peer switched {}: {timing:?}",
            cx.now, cx.peer_switched_local_id
        ));
        sakuya_connection::v1::migration::MigrationDecision {
            timing,
            recovery: sakuya_connection::v1::migration::SwitchRecovery::New,
        }
    }

    fn challenge_timing(
        &self,
        cx: &sakuya_connection::v1::migration::PathChallengeContext,
    ) -> sakuya_connection::v1::migration::PathChallengeTiming {
        sakuya_connection::v1::migration::PathChallengeTiming {
            resend_after: RESEND_AFTER
                .with(Cell::get)
                .unwrap_or_else(|| cx.path_pto.unwrap_or(cx.initial_pto)),
            abandon_after: match (cx.path_pto, NEW_PATH_ABANDON_AFTER.with(Cell::get)) {
                (None, Some(after)) => after,
                _ => cx.initial_pto.saturating_mul(3),
            },
        }
    }

    fn settling_for(&self, cx: &sakuya_connection::v1::migration::SettlingContext) -> Duration {
        log(format!("settling for 3 × {:?}", cx.pto));
        cx.pto.saturating_mul(3)
    }

    /// As version 1's default does; the answers do not depend on the ends
    /// of the links.
    fn choose_preferred_address(
        &mut self,
        cx: &sakuya_connection::v1::migration::PreferredAddressContext<'_>,
    ) -> Option<std::net::SocketAddr> {
        let chosen = <sakuya_connection::v1::migration::Rfc9000MigrationPolicy as sakuya_connection::v1::migration::MigrationPolicy<(), std::net::SocketAddr, Duration>>::choose_preferred_address(
            &mut sakuya_connection::v1::migration::Rfc9000MigrationPolicy,
            cx,
        );
        log(format!(
            "preferred address {chosen:?}, failed {:?}",
            cx.failed
        ));
        chosen
    }

    fn on_old_local_address(
        &mut self,
        cx: &sakuya_connection::v1::migration::OldLocalAddressContext,
    ) -> sakuya_connection::v1::migration::OldLocalAddressPacketHandling {
        let handling = <sakuya_connection::v1::migration::Rfc9000MigrationPolicy as sakuya_connection::v1::migration::MigrationPolicy<(), std::net::SocketAddr, Duration>>::on_old_local_address(
            &mut sakuya_connection::v1::migration::Rfc9000MigrationPolicy,
            cx,
        );
        log(format!(
            "old local address, newer {}: {handling:?}",
            cx.newer
        ));
        handling
    }
}

/// The time to the next PATH_CHALLENGE the tests' migration policy answers
/// from now on: `after`, or the link path's probe timeout when `None`.
pub fn set_challenge_resend(after: Option<Duration>) {
    RESEND_AFTER.with(|r| r.set(after));
}

/// The time the validation of a link path without a recovery layer of its
/// own gives up after, as the tests' migration policy answers from now on:
/// `after`, or three probe timeouts of a new path when `None`.
pub fn set_new_path_abandon(after: Option<Duration>) {
    NEW_PATH_ABANDON_AFTER.with(|a| a.set(after));
}

/// How long after the connection's instant the test links report that
/// they accepted a batch, from now on, as a link whose send completes later
/// in the driver's turn does: `after`, zero by default.
pub fn set_accepted_after(after: Duration) {
    ACCEPTED_AFTER.with(|a| a.set(after));
}

/// Forget what the tests' migration policy was told to answer.
pub fn reset_migration() {
    set_challenge_resend(None);
    set_new_path_abandon(None);
    set_migration(
        TestAdmission::Accept,
        sakuya_connection::v1::migration::SwitchTiming::Now,
    );
}
