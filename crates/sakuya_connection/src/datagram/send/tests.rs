use core::{cell::RefCell, future::Future, pin::pin};
use std::rc::Rc;

use frunk_core::indices::Here;

use sakuya_wire::{
    parts::{CNil, Coproduct},
    v1::packet_number::PacketNumber,
};

use super::*;
use crate::{
    send_strategy::{
        FrameSourceSet, InHead, IntentState, SendStrategyTypes, ranked::RankedSendStrategy,
    },
    v1::send_planning::{HostSendStrategyTypes, SendStrategyPublisher},
    write::{FlightClass, Last, NotLast, sealed},
};
use sakuya_stream::send_options::destination::AnyActiveLinkPath;

/// The summaries of a composition of the extension alone.
type Summary = Coproduct<Coproduct<DatagramSummary, CNil>, CNil>;

// ---- the strategy types of the extension alone ----

/// The sum of intents of a composition of the extension alone.
pub(in crate::datagram) type Intents = Coproduct<Coproduct<DatagramIntent<Urgency>, CNil>, CNil>;

pub(in crate::datagram) fn inner(intent: &Intents) -> &DatagramIntent<Urgency> {
    match intent {
        Coproduct::Inl(Coproduct::Inl(intent)) => intent,
        Coproduct::Inl(Coproduct::Inr(never)) | Coproduct::Inr(never) => match *never {},
    }
}

/// Every kind of packet carries the datagrams.
#[derive(Debug)]
pub(in crate::datagram) enum TestSources {}

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
pub(in crate::datagram) enum TestTypes {}

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
pub(in crate::datagram) struct Written {
    pub(in crate::datagram) bytes: Vec<u8>,
    pub(in crate::datagram) summaries: Vec<Summary>,
}

/// A packet writer with `room` bytes, that keeps what it wrote in `out`.
#[derive(Debug)]
pub(in crate::datagram) struct SummaryWriter {
    buffer: BytesMut,
    room: usize,
    out: Rc<RefCell<Written>>,
}

impl SummaryWriter {
    pub(in crate::datagram) fn new(room: usize, out: &Rc<RefCell<Written>>) -> Self {
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

    fn room(&self, _: crate::write::FlightClass) -> usize {
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
pub(in crate::datagram) enum NoAttempt {}

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
pub(in crate::datagram) fn datagram_summary(summary: Summary) -> DatagramSummary {
    match summary {
        Coproduct::Inl(Coproduct::Inl(summary)) => summary,
        Coproduct::Inl(Coproduct::Inr(never)) | Coproduct::Inr(never) => match never {},
    }
}

fn intent(payload: &'static [u8]) -> DatagramIntent<Urgency> {
    DatagramIntent::new(
        Bytes::from_static(payload),
        Urgency::default(),
        DatagramProgress::new(),
    )
}

/// Supply `intent` into an open packet of `room` bytes in position `P`;
/// what the packet holds afterwards and whether it closed.
fn supply<P: PacketPosition>(intent: &DatagramIntent<Urgency>, room: usize) -> (Written, bool) {
    let out = Rc::default();
    let packet = OpenPacket::<_, InFlightClass, P>::new(SummaryWriter::new(room, &out));
    let closed = matches!(
        DatagramFrameSource.supply::<_, _, InHead<Here>>(intent, packet),
        Supplied::Closed(_)
    );
    (
        Rc::into_inner(out)
            .expect("the packet is dropped")
            .into_inner(),
        closed,
    )
}

fn poll_now<F: Future>(future: F) -> Poll<F::Output> {
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
/// none as the last frame.
#[test]
fn a_datagram_intent_needs_its_whole_frame() {
    let short = intent(&[0; 63]);
    assert_eq!(
        short.min_lengths(),
        MinimumLengths {
            with_length: 65,
            as_last: 64
        }
    );
    let longer = intent(&[0; 64]);
    assert_eq!(longer.min_lengths().with_length, 67);
    // the progress of the datagram orders writing and withdrawing; the
    // strategy consumes the intent once it was written
    assert!(!longer.stays_after_writing());
    assert_eq!(longer.rank().priority, SendPriority::ApplicationData);
}

/// In the last position the frame leaves the Length field out and closes
/// the packet; in any other it has one. Either way the datagram is sent.
#[test]
fn the_last_frame_leaves_the_length_out() {
    let last = intent(b"last");
    let (writer, closed) = supply::<Last>(&last, 100);
    assert!(closed);
    assert_eq!(&writer.bytes[..], [0x30, b'l', b'a', b's', b't']);
    assert_eq!(
        last.progress.state(&DriverPanicFlag::default()),
        Some(DatagramState::Sent)
    );
    let not_last = intent(b"more");
    let (writer, closed) = supply::<NotLast>(&not_last, 100);
    assert!(!closed);
    assert_eq!(&writer.bytes[..], [0x31, 0x04, b'm', b'o', b'r', b'e']);
    assert_eq!(writer.summaries.len(), 1);
}

/// A datagram withdrawn before, or whose frame does not fit, is not
/// written, and a datagram is written once only.
#[test]
fn a_datagram_withdrawn_or_too_large_is_not_written() {
    let withdrawn = intent(b"gone");
    withdrawn.progress.withdraw(Withdrawal::Holder);
    let (writer, _) = supply::<NotLast>(&withdrawn, 100);
    assert!(writer.bytes.is_empty());
    let large = intent(b"large");
    let (writer, _) = supply::<NotLast>(&large, 6);
    assert!(writer.bytes.is_empty());
    assert_eq!(
        large.progress.state(&DriverPanicFlag::default()),
        Some(DatagramState::Waiting)
    );
    let (writer, _) = supply::<NotLast>(&large, 7);
    assert_eq!(writer.bytes.len(), 7);
    let (writer, _) = supply::<NotLast>(&large, 7);
    assert!(writer.bytes.is_empty(), "written once only");
}

/// The summary takes the acknowledgment or the loss to the datagram's
/// progress; a late acknowledgment of a lost packet counts; a lost
/// datagram is not published again.
#[test]
fn the_summary_settles_the_datagram() {
    for delivered in [true, false] {
        let sent = intent(b"data");
        let (mut writer, _) = supply::<NotLast>(&sent, 100);
        let summary = datagram_summary(writer.summaries.remove(0));
        if delivered {
            DatagramFrameSource.delivered(PacketNumberSpaceKind::ApplicationData, summary);
            assert_eq!(
                sent.progress.state(&DriverPanicFlag::default()),
                Some(DatagramState::Acknowledged)
            );
        } else {
            DatagramFrameSource.lost(PacketNumberSpaceKind::ApplicationData, &summary);
            assert_eq!(
                sent.progress.state(&DriverPanicFlag::default()),
                Some(DatagramState::Lost)
            );
            DatagramFrameSource.delivered(PacketNumberSpaceKind::ApplicationData, summary);
            assert_eq!(
                sent.progress.state(&DriverPanicFlag::default()),
                Some(DatagramState::Acknowledged)
            );
        }
    }
}

/// A strategy's ticket that records whether it was withdrawn.
#[derive(Debug, Default)]
struct RecordingTicket(Arc<Mutex<bool>>);

impl IntentTicketWithdraw for RecordingTicket {
    type Report = IntentState<()>;

    fn withdraw(self) -> IntentState<()> {
        *lock(&self.0) = true;
        IntentState::Withdrawn
    }
}

/// A ticket of the recording strategy, its datagram's intent, and whether
/// the strategy's ticket was withdrawn.
type Recorded = (
    DatagramTicket<RecordingTicket, AnyActiveLinkPath, Urgency>,
    DatagramIntent<Urgency>,
    Arc<Mutex<bool>>,
);

fn ticket_of(payload: &'static [u8]) -> Recorded {
    let intent = intent(payload);
    let withdrawn = Arc::default();
    let cell = DatagramCell::new(
        intent.clone(),
        RecordingTicket(Arc::clone(&withdrawn)),
        AnyActiveLinkPath,
        Arc::default(),
    );
    (DatagramTicket::new(cell), intent, withdrawn)
}

/// Withdrawing before the datagram is written withdraws it, and the
/// strategy's intent; after, it reports the datagram consumed.
#[test]
fn withdrawing_reports_whether_the_datagram_was_written() {
    let (ticket, intent, strategy) = ticket_of(b"early");
    assert_eq!(ticket.state(), DatagramState::Waiting);
    assert_eq!(ticket.withdraw(), WithdrawReport::Withdrawn);
    assert!(*lock(&strategy));
    let (writer, _) = supply::<NotLast>(&intent, 100);
    assert!(
        writer.bytes.is_empty(),
        "a withdrawn datagram is not written"
    );

    let (ticket, intent, strategy) = ticket_of(b"late");
    let _ = supply::<NotLast>(&intent, 100);
    assert_eq!(ticket.state(), DatagramState::Sent);
    assert_eq!(ticket.withdraw(), WithdrawReport::Consumed);
    assert!(!*lock(&strategy));
}

/// Dropping the ticket withdraws the datagram; releasing it does not.
#[test]
fn dropping_the_ticket_withdraws_and_releasing_it_does_not() {
    let (ticket, intent, strategy) = ticket_of(b"dropped");
    drop(ticket);
    assert!(*lock(&strategy));
    assert!(!intent.progress.is_waiting());
    let (ticket, intent, strategy) = ticket_of(b"released");
    ticket.release();
    assert!(!*lock(&strategy));
    let (writer, _) = supply::<NotLast>(&intent, 100);
    assert!(
        !writer.bytes.is_empty(),
        "a released datagram is still sent"
    );
}

/// `settled` waits until the datagram is acknowledged, then gives that at
/// once.
#[test]
fn settled_waits_for_the_acknowledgment() {
    let (mut ticket, intent, _) = ticket_of(b"waited");
    assert!(poll_now(ticket.settled()).is_pending());
    let (mut writer, _) = supply::<NotLast>(&intent, 100);
    assert!(
        poll_now(ticket.settled()).is_pending(),
        "sent is not settled"
    );
    let summary = datagram_summary(writer.summaries.remove(0));
    DatagramFrameSource.delivered(PacketNumberSpaceKind::ApplicationData, summary);
    assert_eq!(
        poll_now(ticket.settled()),
        Poll::Ready(DatagramSettlement::Acknowledged)
    );
    assert_eq!(ticket.state(), DatagramState::Acknowledged);
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
struct Nowhere;

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
    let (ticket, intent, _) = ticket_of(b"again");
    DatagramFrameSource.unfulfilled(&intent, Unfulfilled::Ended);
    assert_eq!(ticket.state(), DatagramState::Waiting);
    ticket.cell.resolve_unfulfilled(&publish);
    assert_eq!(*lock(&publish.0), 1, "published again");
    assert_eq!(ticket.state(), DatagramState::Waiting);
    ticket.cell.resolve_unfulfilled(&publish);
    assert_eq!(*lock(&publish.0), 1, "nothing more without another failure");

    let intent = super::DatagramIntent::new(
        Bytes::from_static(b"exhausted"),
        Urgency::default(),
        DatagramProgress::new(),
    );
    let strategy = Arc::default();
    let cell = DatagramCell::new(
        intent.clone(),
        RecordingTicket(Arc::clone(&strategy)),
        Nowhere,
        Arc::default(),
    );
    let mut ticket = DatagramTicket::new(cell);
    DatagramFrameSource.unfulfilled(&intent, Unfulfilled::Rejected);
    ticket.cell.resolve_unfulfilled(&publish);
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

/// Queues of the established layer whose datagrams have nothing to fall
/// back to: what [`LineageDatagramFrameSource`] finds appended to its
/// lineage.
struct ExhaustedQueues {
    cells: Vec<Arc<DatagramCell<RecordingTicket, Nowhere, Urgency>>>,
    /// What they publish through, apart from the publisher they are lent.
    publish: CountingHandle,
}

/// The share of [`ExhaustedQueues`]: no handle takes it.
#[derive(Clone)]
struct NoShare;

impl DatagramQueues<(), TestTypes> for ExhaustedQueues {
    type Config = ();
    type Handle = NoShare;
    type Events = crate::v1::events::NoEvents;
    type Remains = ();
    type Intake = CountingHandle;

    fn new(
        _: super::super::DatagramQueuesFacts,
        (): (),
        _: crate::v1::events::NoEvents,
        publish: CountingHandle,
    ) -> Self {
        Self {
            cells: Vec::new(),
            publish,
        }
    }

    fn handle(&self) -> NoShare {
        NoShare
    }

    fn on_datagram_frame(
        &mut self,
        _: sakuya_wire::v1::encryption_level::EncryptionLevel,
        _: DatagramFrame<Bytes>,
    ) {
    }

    fn layer_ended(&mut self, _: sakuya_stream::connection::LayerEnd<()>) {}

    /// No handle takes the queues, so no wait is on them.
    fn driver_panicked(&mut self, _: sakuya_stream::connection::LayerEnd<()>) {}

    fn remains(&mut self) {}

    fn resolve_unfulfilled<Ij>(&mut self, _: &mut StrategyPublisherOf<TestTypes>)
    where
        StrategyPublisherOf<TestTypes>: StrategyPublisherFor<DatagramIntent<Urgency>, Ij>,
    {
        let publish = &self.publish;
        self.cells.retain(|cell| {
            cell.resolve_unfulfilled(publish);
            cell.is_waiting()
        });
    }
}

/// The source found in a lineage resolves an intent not fulfilled at once,
/// through the queues appended to the lineage: a datagram whose destination
/// has nothing left is withdrawn before anything is sent again, and leaves
/// its queue; without the queues the progress only keeps the cause.
#[test]
fn an_unfulfilled_datagram_is_resolved_at_once_through_the_lineage() {
    let publish = CountingHandle::default();
    let intent = super::DatagramIntent::new(
        Bytes::from_static(b"exhausted"),
        Urgency::default(),
        DatagramProgress::new(),
    );
    let strategy = Arc::default();
    let cell = DatagramCell::new(
        intent.clone(),
        RecordingTicket(Arc::clone(&strategy)),
        Nowhere,
        Arc::default(),
    );
    let mut ticket = DatagramTicket::new(Arc::clone(&cell));
    let mut queues = ExhaustedQueues {
        cells: vec![cell],
        publish: publish.clone(),
    };
    let mut publisher = SendStrategyPublisher::new(StrategyPublisherOf::<TestTypes>::default());
    let taken = crate::take::TakenPositions::default();
    {
        let mut lineage = Lineage::new(
            frunk_core::hlist![
                &mut publisher,
                Some(crate::take::ComponentMut::new(
                    &mut queues,
                    crate::take::Sink::Nowhere,
                    1
                ))
            ],
            &taken,
        );
        let mut source =
            LineageDatagramFrameSource::<_, ExhaustedQueues, (), TestTypes, _, _, _>::new(
                &mut lineage,
            );
        source.unfulfilled(&intent, Unfulfilled::Rejected);
    }
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
    assert!(*lock(&strategy), "the strategy's ticket is withdrawn");
    assert_eq!(*lock(&publish.0), 0, "not published again");
    assert!(queues.cells.is_empty(), "it leaves its queue");

    // without the established layer the cause is only kept
    let (ticket, intent, strategy) = ticket_of(b"no layer");
    let mut lineage = Lineage::new(
        frunk_core::hlist![
            &mut publisher,
            None::<crate::take::ComponentMut<'_, ExhaustedQueues>>
        ],
        &taken,
    );
    LineageDatagramFrameSource::<_, ExhaustedQueues, (), TestTypes, _, _, _>::new(&mut lineage)
        .unfulfilled(&intent, Unfulfilled::Ended);
    assert_eq!(ticket.state(), DatagramState::Waiting);
    assert!(!*lock(&strategy));
    assert_eq!(*lock(&publish.0), 0);
    ticket.release();
}
