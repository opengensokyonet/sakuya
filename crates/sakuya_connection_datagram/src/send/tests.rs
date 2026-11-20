use core::{cell::RefCell, future::Future, pin::pin};
use sakuya_wire_v1::frame::write::FlightClass;
use std::rc::Rc;

use frunk_core::indices::Here;

use sakuya_wire::parts::{CNil, Coproduct};
use sakuya_wire_v1::packet_number::PacketNumber;

use super::*;
use bytes::BytesMut;
use sakuya_connection::{
    send_strategy::{
        FrameSourceSet, InHead, IntentState, SendStrategyTypes, ranked::RankedSendStrategy,
    },
    v1::send_planning::HostSendStrategyTypes,
    write::{Last, NotLast, sealed},
};
use sakuya_stream::send_options::destination::AnyActiveLinkPath;

/// The side of the queues' tests: it reads the bytes, which come in 1-RTT
/// packets.
#[derive(Debug)]
pub(crate) enum TestSide {}

impl DatagramSide for TestSide {
    type Received = Bytes;

    fn received(level: sakuya_wire_v1::encryption_level::EncryptionLevel, data: Bytes) -> Bytes {
        assert_eq!(
            level,
            sakuya_wire_v1::encryption_level::EncryptionLevel::OneRtt
        );
        data
    }
}

/// The summaries of a composition of the extension alone.
pub(crate) type Summary = Coproduct<Coproduct<DatagramSummary, CNil>, CNil>;

// ---- the strategy types of the extension alone ----

/// The sum of intents of a composition of the extension alone.
pub(crate) type Intents = Coproduct<Coproduct<DatagramIntent<Urgency>, CNil>, CNil>;

pub(crate) fn inner(intent: &Intents) -> &DatagramIntent<Urgency> {
    match intent {
        Coproduct::Inl(Coproduct::Inl(intent)) => intent,
        Coproduct::Inl(Coproduct::Inr(never)) | Coproduct::Inr(never) => match *never {},
    }
}

/// Every kind of packet carries the datagrams.
#[derive(Debug)]
pub(crate) enum TestSources {}

impl FrameSourceSet for TestSources {
    type Intents = Intents;
    type FrameSourceId = super::FrameSourceId;
    type Item<'a> = &'a DatagramIntent<Urgency>;

    fn item(intent: &Intents) -> Option<&DatagramIntent<Urgency>> {
        Some(inner(intent))
    }

    fn source(_: &&DatagramIntent<Urgency>) -> super::FrameSourceId {
        super::FrameSourceId::Datagram
    }
}

/// The strategy types of a composition of the extension alone, run by the
/// ranked strategy.
#[derive(Debug)]
pub(crate) enum TestTypes {}

impl SendStrategyTypes for TestTypes {
    type SendIntents = Intents;
    type FrameSourceId = super::FrameSourceId;
    type LinkPathIdentifier = u8;
    type CloseCause = ();
    type InitialFrameSources = TestSources;
    type HandshakeFrameSources = TestSources;
    type ZeroRttFrameSources = TestSources;
    type OneRttFrameSources = TestSources;
    type ProbeFrameSources = TestSources;
    type SettlingFrameSources = TestSources;

    fn frame_source(intent: &Intents) -> super::FrameSourceId {
        inner(intent).frame_source()
    }

    fn min_lengths(intent: &Intents) -> MinimumLengths {
        inner(intent).min_lengths()
    }

    fn flight_class(_: &Intents) -> FlightClass {
        FlightClass::InFlight
    }
}

impl HostSendStrategyTypes for TestTypes {
    type Strategy = RankedSendStrategy<TestTypes>;
}

/// What a [`SummaryWriter`] wrote: its bytes, once it is dropped, and the
/// frames' summaries.
#[derive(Debug, Default)]
pub(crate) struct Written {
    pub(crate) bytes: Vec<u8>,
    pub(crate) summaries: Vec<Summary>,
}

/// A packet writer with `room` bytes, that keeps what it wrote in `out`.
#[derive(Debug)]
pub(crate) struct SummaryWriter {
    buffer: BytesMut,
    room: usize,
    out: Rc<RefCell<Written>>,
}

impl SummaryWriter {
    pub(crate) fn new(room: usize, out: &Rc<RefCell<Written>>) -> Self {
        Self {
            buffer: BytesMut::new(),
            room,
            out: Rc::clone(out),
        }
    }
}

impl Drop for SummaryWriter {
    fn drop(&mut self) {
        self.out.borrow_mut().bytes = self.buffer.to_vec();
    }
}

impl sealed::Writing for SummaryWriter {}

impl PacketWriting for SummaryWriter {
    type Attempt = NoAttempt;

    fn room(&self, _: sakuya_wire_v1::frame::write::FlightClass) -> usize {
        self.room - self.buffer.len()
    }

    fn buffer(&mut self) -> &mut BytesMut {
        &mut self.buffer
    }

    fn buffer_len(&self) -> usize {
        self.buffer.len()
    }

    fn frame_written(&mut self, summary: Summary, _: bool, _: bool, _: bool) {
        self.out.borrow_mut().summaries.push(summary);
    }

    fn close(&mut self) {}

    fn conclude(&mut self, _: bool) {}
}

/// The send attempt of [`SummaryWriter`]: nothing makes one.
#[derive(Debug)]
pub(crate) enum NoAttempt {}

impl sakuya_recovery::send_journals::PacketSendAttempt for NoAttempt {
    type Summary = Summary;
    type Sealed = ();

    fn packet_number(&self) -> PacketNumber {
        match *self {}
    }

    fn record_frame(&mut self, _: Summary, _: bool, _: bool) {
        match *self {}
    }

    fn seal(self, _: usize, _: bool, _: sakuya_link::EcnMarking) -> Option<()> {
        match self {}
    }
}

/// The datagram summary of `summary`.
pub(crate) fn datagram_summary(summary: Summary) -> DatagramSummary {
    match summary {
        Coproduct::Inl(Coproduct::Inl(summary)) => summary,
        Coproduct::Inl(Coproduct::Inr(never)) | Coproduct::Inr(never) => match never {},
    }
}

fn intent(len: usize) -> DatagramIntent<Urgency> {
    DatagramIntent::new(DatagramKey::FIRST, len, Urgency::default())
}

/// What writing `payload` into an open packet of `room` bytes in position
/// `P` leaves, when `start` lets it: what the packet holds afterwards,
/// whether it closed, and whether the frame was written.
fn write<P: PacketPosition>(
    payload: &'static [u8],
    room: usize,
    start: bool,
) -> (Written, bool, bool) {
    let out = Rc::default();
    let packet = OpenPacket::<_, InFlightClass, P>::new(SummaryWriter::new(room, &out));
    let (supplied, written) = write_datagram::<_, _, InHead<Here>>(
        Bytes::from_static(payload),
        packet,
        DatagramSummary {
            key: DatagramKey::FIRST.next(),
        },
        || start,
    );
    let closed = matches!(supplied, Supplied::Closed(_));
    drop(supplied);
    (
        Rc::into_inner(out)
            .expect("the packet is dropped")
            .into_inner(),
        closed,
        written,
    )
}

pub(crate) fn poll_now<F: Future>(future: F) -> Poll<F::Output> {
    pin!(future).poll(&mut Context::from_waker(Waker::noop()))
}

/// A frame with a Length field writes as type `0x31`, one without as
/// `0x30`, each in the length it states.
#[test]
fn both_kinds_of_datagram_frames_write_their_encoded_length() {
    let with = DatagramFrame::with_length(VarIntWidth::One, Bytes::from_static(b"hi")).unwrap();
    let mut buffer = BytesMut::new();
    let len = DelimitedFrame::encoded_len(&with);
    DelimitedFrame::write_to(with, &mut buffer);
    assert_eq!(&buffer[..], [0x31, 0x02, b'h', b'i']);
    assert_eq!(len, buffer.len());
    let without = DatagramFrame::without_length(Bytes::from_static(b"hi"));
    let mut buffer = BytesMut::new();
    let len = ToPacketEndFrame::encoded_len(&without);
    ToPacketEndFrame::write_to(without, &mut buffer);
    assert_eq!(&buffer[..], [0x30, b'h', b'i']);
    assert_eq!(len, buffer.len());
}

/// The intent needs its whole frame: with the shortest Length field, or
/// none as the last frame; it carries the key and the length, not the
/// payload.
#[test]
fn a_datagram_intent_needs_its_whole_frame() {
    let short = intent(63);
    assert_eq!(
        short.min_lengths(),
        MinimumLengths {
            with_length: 65,
            as_last: 64
        }
    );
    assert_eq!((short.key(), short.len()), (DatagramKey::FIRST, 63));
    let longer = intent(64);
    assert_eq!(longer.min_lengths().with_length, 67);
    // the queues order writing and withdrawing; the strategy consumes the
    // intent once it was written
    assert!(!longer.stays_after_writing());
    assert_eq!(longer.rank().priority, SendPriority::ApplicationData);
}

/// In the last position the frame leaves the Length field out and closes
/// the packet; in any other it has one, and the summary is the key.
#[test]
fn the_last_frame_leaves_the_length_out() {
    let (writer, closed, written) = write::<Last>(b"last", 100, true);
    assert!(closed && written);
    assert_eq!(&writer.bytes[..], [0x30, b'l', b'a', b's', b't']);
    let (writer, closed, written) = write::<NotLast>(b"more", 100, true);
    assert!(!closed && written);
    assert_eq!(&writer.bytes[..], [0x31, 0x04, b'm', b'o', b'r', b'e']);
    assert_eq!(
        writer
            .summaries
            .into_iter()
            .map(datagram_summary)
            .collect::<Vec<_>>(),
        [DatagramSummary {
            key: DatagramKey::FIRST.next()
        }]
    );
}

/// A frame that does not fit is not written, nor one its queue does not
/// let start; a Length of two bytes is counted.
#[test]
fn a_datagram_that_does_not_fit_or_may_not_start_is_not_written() {
    let (writer, _, written) = write::<NotLast>(b"large", 6, true);
    assert!(writer.bytes.is_empty() && !written);
    let (writer, _, written) = write::<NotLast>(b"large", 7, true);
    assert_eq!((writer.bytes.len(), written), (7, true));
    let (writer, _, written) = write::<NotLast>(b"gone", 100, false);
    assert!(writer.bytes.is_empty() && !written);
    let (writer, _, written) = write::<Last>(b"gone", 100, false);
    assert!(writer.bytes.is_empty() && !written);
    let (writer, _, written) = write::<NotLast>(&[0; 64], 66, true);
    assert!(writer.bytes.is_empty() && !written, "a Length of two bytes");
}

/// The progress orders writing and withdrawing, and a late acknowledgment
/// of a lost datagram counts.
#[test]
fn the_progress_settles_once_written() {
    let mut progress = ProgressState::new();
    assert!(progress.start_writing());
    assert!(!progress.start_writing(), "written once only");
    assert_eq!(
        progress.withdraw(Withdrawal::Holder),
        WithdrawReport::Consumed
    );
    progress.settle(false);
    assert_eq!(progress.state(false), Some(DatagramState::Lost));
    progress.settle(true);
    assert_eq!(progress.state(false), Some(DatagramState::Acknowledged));
    let mut withdrawn = ProgressState::new();
    assert_eq!(
        withdrawn.withdraw(Withdrawal::Holder),
        WithdrawReport::Withdrawn
    );
    assert!(!withdrawn.start_writing());
    assert_eq!(withdrawn.state(false), None);
    // once the driver panicked, what waits is withdrawn and what is in
    // flight lost
    assert_eq!(
        ProgressState::new().state(true),
        Some(DatagramState::Withdrawn(DatagramWithdrawCause::LayerEnded))
    );
    let mut sent = ProgressState::new();
    sent.start_writing();
    assert_eq!(sent.state(true), Some(DatagramState::Lost));
}

/// A strategy's ticket that records whether it was withdrawn, and tells
/// whether its intent waits as too large.
#[derive(Debug, Default)]
struct RecordingTicket {
    withdrawn: Arc<Mutex<bool>>,
    too_large: Arc<Mutex<bool>>,
}

impl IntentTicketWithdraw for RecordingTicket {
    type Report = IntentState<()>;

    fn withdraw(self) -> IntentState<()> {
        *lock(&self.withdrawn) = true;
        IntentState::Withdrawn
    }
}

impl IntentTicketState for RecordingTicket {
    type End = ();

    fn state(&self) -> IntentState<()> {
        if *lock(&self.too_large) {
            IntentState::WaitingTooLarge
        } else {
            IntentState::Waiting
        }
    }
}

/// A ticket of the recording strategy, its datagram's cell, and whether
/// the strategy's ticket was withdrawn.
type Recorded<D = AnyActiveLinkPath> = (
    DatagramTicket<RecordingTicket, D, Urgency>,
    Arc<DatagramCell<RecordingTicket, D, Urgency>>,
    Arc<Mutex<bool>>,
);

fn ticket_to<D>(payload: &'static [u8], destination: D) -> Recorded<D> {
    let ticket = RecordingTicket::default();
    let withdrawn = Arc::clone(&ticket.withdrawn);
    let cell = DatagramCell::new(
        DatagramKey::FIRST,
        Bytes::from_static(payload),
        Urgency::default(),
        ticket,
        destination,
        Arc::default(),
    );
    (DatagramTicket::new(Arc::clone(&cell)), cell, withdrawn)
}

fn ticket_of(payload: &'static [u8]) -> Recorded {
    ticket_to(payload, AnyActiveLinkPath)
}

/// Withdrawing before the datagram is written withdraws it, and the
/// strategy's intent; after, it reports the datagram consumed.
#[test]
fn withdrawing_reports_whether_the_datagram_was_written() {
    let (ticket, cell, strategy) = ticket_of(b"early");
    assert_eq!(ticket.state(), DatagramState::Waiting);
    assert_eq!(ticket.withdraw(), WithdrawReport::Withdrawn);
    assert!(*lock(&strategy));
    assert!(!cell.start_writing(), "a withdrawn datagram is not written");

    let (ticket, cell, strategy) = ticket_of(b"late");
    assert!(cell.start_writing());
    assert_eq!(ticket.state(), DatagramState::Sent);
    assert_eq!(ticket.withdraw(), WithdrawReport::Consumed);
    assert!(!*lock(&strategy));
}

/// Dropping the ticket withdraws the datagram; releasing it does not.
#[test]
fn dropping_the_ticket_withdraws_and_releasing_it_does_not() {
    let (ticket, cell, strategy) = ticket_of(b"dropped");
    drop(ticket);
    assert!(*lock(&strategy));
    assert!(!cell.is_waiting());
    let (ticket, cell, strategy) = ticket_of(b"released");
    ticket.release();
    assert!(!*lock(&strategy));
    assert!(cell.start_writing(), "a released datagram is still sent");
}

/// `settled` waits until the datagram is acknowledged, then gives that at
/// once.
#[test]
fn settled_waits_for_the_acknowledgment() {
    let (mut ticket, cell, _) = ticket_of(b"waited");
    assert!(poll_now(ticket.settled()).is_pending());
    assert!(cell.start_writing());
    assert!(
        poll_now(ticket.settled()).is_pending(),
        "sent is not settled"
    );
    cell.settle(true);
    assert_eq!(
        poll_now(ticket.settled()),
        Poll::Ready(DatagramSettlement::Acknowledged)
    );
    assert_eq!(ticket.state(), DatagramState::Acknowledged);
    ticket.release();
}

/// The strategy's ticket tells when a datagram that waits is too large for
/// now; the wait for a settlement goes on, and the datagram waits again
/// once a link path can carry it.
#[test]
fn a_ticket_reads_a_datagram_too_large_for_now() {
    let (mut ticket, cell, _) = ticket_of(b"large");
    let too_large = Arc::clone(&lock(&cell.route).ticket.as_ref().unwrap().too_large);
    *lock(&too_large) = true;
    assert_eq!(ticket.state(), DatagramState::WaitingTooLarge);
    assert!(poll_now(ticket.settled()).is_pending());
    *lock(&too_large) = false;
    assert_eq!(ticket.state(), DatagramState::Waiting);
    ticket.release();
}

/// A handle that publishes to the recorded strategy, counting.
#[derive(Debug, Clone, Default)]
struct CountingHandle(Arc<Mutex<usize>>);

impl SendIntentHandle<DatagramIntent<Urgency>, AnyActiveLinkPath> for CountingHandle {
    type Outcome = RecordingTicket;

    fn publish_to(&self, _: DatagramIntent<Urgency>, _: AnyActiveLinkPath) -> RecordingTicket {
        *lock(&self.0) += 1;
        RecordingTicket::default()
    }
}

/// A destination that has nothing to fall back to.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Nowhere;

impl SendDestination for Nowhere {
    type Current = AnyActiveLinkPath;

    fn current(&self) -> AnyActiveLinkPath {
        AnyActiveLinkPath
    }

    fn on_unfulfilled(&mut self, _: Unfulfilled) -> DestinationFallback {
        DestinationFallback::Exhausted
    }
}

/// An intent that was not fulfilled is published again while its
/// destination degrades, with the same ticket; withdrawn once its
/// destination has nothing left.
#[test]
fn an_unfulfilled_datagram_falls_back_as_its_destination_says() {
    let publish = CountingHandle::default();
    let (ticket, cell, _) = ticket_of(b"again");
    cell.resolve_unfulfilled(Unfulfilled::Ended, &publish);
    assert_eq!(*lock(&publish.0), 1, "published again");
    assert_eq!(ticket.state(), DatagramState::Waiting);
    assert!(cell.start_writing());
    cell.resolve_unfulfilled(Unfulfilled::Ended, &publish);
    assert_eq!(*lock(&publish.0), 1, "nothing for a datagram written");
    ticket.release();

    let (mut ticket, cell, strategy) = ticket_to(b"exhausted", Nowhere);
    cell.resolve_unfulfilled(Unfulfilled::Rejected, &publish);
    assert_eq!(*lock(&publish.0), 1, "not published again");
    assert!(*lock(&strategy));
    assert_eq!(
        ticket.state(),
        DatagramState::Withdrawn(DatagramWithdrawCause::DestinationExhausted)
    );
    assert_eq!(
        poll_now(ticket.settled()),
        Poll::Ready(DatagramSettlement::Withdrawn(
            DatagramWithdrawCause::DestinationExhausted
        ))
    );
    assert_eq!(ticket.withdraw(), WithdrawReport::Withdrawn);
}
