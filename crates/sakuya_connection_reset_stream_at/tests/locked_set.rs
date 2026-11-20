//! The locked stream set with the reliable stream reset extension, through
//! the set's own entries: the frames it takes, the operations on the
//! credential of a stream's writer, the frames it writes into a packet,
//! and the acknowledgment of those frames.

use core::{
    cell::RefCell,
    marker::PhantomData,
    task::{Context, Poll, Waker},
};
use std::rc::Rc;

use bytes::{Bytes, BytesMut};
use frunk_core::Coprod;
use sakuya_connection::{
    send_strategy::{
        AnyActiveLinkPath, FrameSourceSet, IntentPublisher, IntentTicketResize,
        IntentTicketWithdraw, MinimumLengths, SendIntent as _, SendStrategyTypes,
        ranked::{RankedSendPublisher, RankedSendStrategy},
    },
    v1::{
        application_handles::stream::AllAcknowledgedError,
        events::NoEvents,
        send::FrameSourceId,
        send_planning::HostSendStrategyTypes,
        streams::{
            FlowControlParameters, StreamSet, StreamSetFacts, StreamSetFrameError,
            StreamWriterCredential,
            locked::{LockedStreamSet, LockedStreamSetConfig, LockedStreamSetHandle},
            send::{
                ResetStreamSummary, StreamIntent, StreamIntentKey, StreamSetFrameSummary,
                StreamSummary,
            },
        },
    },
    write::{NotLast, OpenPacket, PacketWriting, sealed},
};
use sakuya_connection_reset_stream_at::{ReliableStreamResets, ResetStreamAtRequest};
use sakuya_stream::{send_options::urgency::Urgency, stream_end::ResetCodeChangeError};
use sakuya_stream_reset_stream_at::{receive::OnResetStreamError, send::PeerResetStreamAtSupport};
use sakuya_wire::{
    parts::{CNil, Coproduct, HList},
    v1::{
        self,
        application_error::ApplicationErrorCode,
        encryption_level::EncryptionLevel,
        frame::{
            FrameRun,
            reset_stream::ResetStreamFrame,
            set::Frames,
            stream::StreamFrame,
            write::{FlightClass, InFlightClass},
        },
        packet_number::PacketNumber,
        role::Role,
        stream_count::StreamCount,
        stream_id::{Directionality, StreamId},
        transport_error::TransportErrorCode,
        transport_parameters::integer::{
            InitialMaxData, InitialMaxStreamDataBidiLocal, InitialMaxStreamDataBidiRemote,
            InitialMaxStreamDataUni, InitialMaxStreamsBidi, InitialMaxStreamsUni,
        },
    },
    var_int::{VarInt, VarIntField},
};
use sakuya_wire_reset_stream_at::{ResetStreamAt, ResetStreamAtFrame};

// ---- the strategy types the set is lent the publisher of ----

/// The sum of intents of the tests: the stream intents alone.
type TestIntents = Coproduct<Coproduct<StreamIntent<Urgency>, CNil>, CNil>;

fn inner(intent: &TestIntents) -> &StreamIntent<Urgency> {
    match intent {
        Coproduct::Inl(Coproduct::Inl(intent)) => intent,
        Coproduct::Inl(Coproduct::Inr(never)) | Coproduct::Inr(never) => match *never {},
    }
}

/// Every kind of packet carries the stream intents.
#[derive(Debug)]
enum TestSources {}

impl FrameSourceSet for TestSources {
    type Intents = TestIntents;
    type FrameSourceId = FrameSourceId;
    type Item<'a> = &'a StreamIntent<Urgency>;

    fn item(intent: &TestIntents) -> Option<&StreamIntent<Urgency>> {
        Some(inner(intent))
    }

    fn source(item: &&StreamIntent<Urgency>) -> FrameSourceId {
        item.frame_source()
    }
}

/// The strategy types the set is made over: the ranked strategy's, whose
/// publisher the set is lent.
#[derive(Debug)]
enum TestTypes {}

impl SendStrategyTypes for TestTypes {
    type SendIntents = TestIntents;
    type FrameSourceId = FrameSourceId;
    type LinkPathIdentifier = u8;
    type CloseCause = ();
    type InitialFrameSources = TestSources;
    type HandshakeFrameSources = TestSources;
    type ZeroRttFrameSources = TestSources;
    type OneRttFrameSources = TestSources;
    type ProbeFrameSources = TestSources;
    type SettlingFrameSources = TestSources;

    fn frame_source(intent: &TestIntents) -> FrameSourceId {
        inner(intent).frame_source()
    }

    fn min_lengths(intent: &TestIntents) -> MinimumLengths {
        inner(intent).min_lengths()
    }

    fn flight_class(_: &TestIntents) -> FlightClass {
        FlightClass::InFlight
    }
}

impl HostSendStrategyTypes for TestTypes {
    type Strategy = RankedSendStrategy<TestTypes>;
}

/// The publisher the set is lent.
type TestPublisher = RankedSendPublisher<TestTypes>;

/// A publisher for one call.
fn publisher() -> TestPublisher {
    TestPublisher::default()
}

/// The ticket of what the set publishes through its own handle.
#[derive(Debug)]
struct TestTicket;

impl IntentTicketResize for TestTicket {
    fn resize(&mut self, _: MinimumLengths) {}
}

impl IntentTicketWithdraw for TestTicket {
    type Report = ();

    fn withdraw(self) {}
}

/// The handle of the strategy's intake the set publishes through.
#[derive(Debug, Clone)]
struct TestPublish;

impl IntentPublisher<StreamIntent<Urgency>, AnyActiveLinkPath> for TestPublish {
    type Ticket = TestTicket;

    fn publish_to(&mut self, _: StreamIntent<Urgency>, _: AnyActiveLinkPath) -> TestTicket {
        TestTicket
    }

    fn resize(&mut self, ticket: &mut TestTicket, min: MinimumLengths) {
        ticket.resize(min);
    }

    fn withdraw(&mut self, ticket: TestTicket) {
        ticket.withdraw();
    }

    fn release_written(&mut self, _: TestTicket) {}

    fn waits_too_large(&self, _: &TestTicket) -> bool {
        false
    }
}

// ---- the set ----

type ReliableSet = LockedStreamSet<(), TestTicket, TestPublish, ReliableStreamResets>;

/// The set `set` as the driver lends it: a stream set over the test
/// strategy types, so that its methods know them.
fn lent(
    set: &mut ReliableSet,
) -> &mut impl StreamSet<
    (),
    TestTypes,
    ReliableStreamResets,
    SendParameters = Urgency,
    Handle = LockedStreamSetHandle<(), TestTicket, TestPublish, ReliableStreamResets>,
> {
    set
}

fn v(value: u32) -> VarInt {
    VarInt::from_u32(value)
}

fn count(value: u64) -> StreamCount {
    StreamCount::new(value).expect("a small count")
}

fn id(value: u32) -> StreamId {
    StreamId::from(v(value))
}

fn field(stream: u32) -> VarIntField<StreamId> {
    VarIntField::shortest(id(stream))
}

/// The set of a client whose peer, a server, opens the streams 1, 5, 9, …
/// (bidirectional); each side grants the other three streams of each type,
/// 100 bytes of each stream and 1000 bytes of the connection. The peer
/// allows RESET_STREAM_AT if `peer_allows`.
fn reliable_client_set(peer_allows: bool) -> ReliableSet {
    let flow = FlowControlParameters {
        initial_max_data: InitialMaxData::new(v(1000)),
        initial_max_stream_data_bidi_local: InitialMaxStreamDataBidiLocal::new(v(100)),
        initial_max_stream_data_bidi_remote: InitialMaxStreamDataBidiRemote::new(v(100)),
        initial_max_stream_data_uni: InitialMaxStreamDataUni::new(v(100)),
        initial_max_streams_bidi: InitialMaxStreamsBidi::new(count(3)),
        initial_max_streams_uni: InitialMaxStreamsUni::new(count(3)),
    };
    <ReliableSet as StreamSet<(), TestTypes, ReliableStreamResets>>::new(
        StreamSetFacts {
            role: Role::Client,
            granted_to_peer: flow,
            granted_by_peer: flow,
            peer_reset_support: peer_allows
                .then(|| PeerResetStreamAtSupport::from_peer_parameter(ResetStreamAt)),
        },
        LockedStreamSetConfig::default(),
        NoEvents,
        TestPublish,
    )
}

/// A STREAM frame of `stream` with `len` bytes at offset 0.
fn stream_frame(stream: u32, len: usize, fin: bool) -> StreamFrame<Bytes> {
    StreamFrame::new(field(stream), None, Bytes::from(vec![7; len]), fin)
        .expect("a short frame")
        .into_without_length()
        .into()
}

fn reset_stream_at(stream: u32, code: u32, final_size: u32, reliable: u32) -> ResetStreamAtFrame {
    ResetStreamAtFrame::new(
        field(stream),
        VarIntField::shortest(ApplicationErrorCode::new(v(code))),
        VarIntField::shortest(v(final_size)),
        VarIntField::shortest(v(reliable)),
    )
    .expect("the reliable size is within the final size")
}

fn reset_stream_with_code(stream: u32, code: u32, final_size: u32) -> ResetStreamFrame {
    ResetStreamFrame::new(
        field(stream),
        VarIntField::shortest(ApplicationErrorCode::new(v(code))),
        VarIntField::shortest(v(final_size)),
    )
}

fn context() -> Context<'static> {
    Context::from_waker(Waker::noop())
}

// ---- what the set writes ----

/// The summaries of the frames the tests have the set write.
type Summary = Coproduct<Coprod![StreamSummary, ResetStreamSummary], CNil>;

/// What a [`SummaryWriter`] wrote: its bytes, once it is dropped, and the
/// frames' summaries.
#[derive(Debug, Default)]
struct Written {
    bytes: Vec<u8>,
    summaries: Vec<Summary>,
}

/// A packet writer with `room` bytes, that keeps what it wrote in `out`.
#[derive(Debug)]
struct SummaryWriter {
    buffer: BytesMut,
    room: usize,
    out: Rc<RefCell<Written>>,
}

impl Drop for SummaryWriter {
    fn drop(&mut self) {
        self.out.borrow_mut().bytes = self.buffer.to_vec();
    }
}

impl sealed::Writing for SummaryWriter {}

impl PacketWriting for SummaryWriter {
    type Attempt = NoAttempt;

    fn room(&self, _: FlightClass) -> usize {
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
enum NoAttempt {}

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

/// A frame as the peer reads it from a packet the set wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Read {
    Stream {
        stream: StreamId,
        offset: VarInt,
        len: usize,
        fin: bool,
    },
    ResetStreamAt {
        stream: StreamId,
        final_size: VarInt,
        reliable_size: VarInt,
    },
}

/// What the peer reads of the packet of `room` bytes, not the last of its
/// datagram, that the item `key` of `set` is written into; the summaries of the frames are those of what
/// was read.
fn written(set: &mut ReliableSet, key: StreamIntentKey, room: usize) -> Vec<Read> {
    let out = Rc::default();
    {
        let packet = OpenPacket::<_, InFlightClass, NotLast>::new(SummaryWriter {
            buffer: BytesMut::new(),
            room,
            out: Rc::clone(&out),
        });
        let supplied = match key {
            StreamIntentKey::Stream(stream) => {
                lent(set).supply_stream(&mut publisher(), stream, Urgency::default(), packet)
            }
            StreamIntentKey::ResetStream(stream) => {
                lent(set).supply_reset_stream(&mut publisher(), stream, packet)
            }
            other => panic!("the tests write no {other:?}"),
        };
        drop(supplied);
    }
    let Written { bytes, summaries } = Rc::into_inner(out)
        .expect("the packet is dropped")
        .into_inner();
    let mut summaries = summaries.into_iter();
    let mut read = Vec::new();
    for run in Frames::new(
        &bytes[..],
        PhantomData::<HList![v1::Part, sakuya_wire_reset_stream_at::Part]>,
    ) {
        let run = run.expect("the set writes frames that read");
        let summary = summaries.next().expect("a summary for each frame");
        read.push(match run.uninject::<FrameRun<&[u8]>, _>() {
            Ok(FrameRun::Stream(frame)) => {
                let read = Read::Stream {
                    stream: frame.stream_id().get(),
                    offset: frame.data_offset(),
                    len: frame.data().len(),
                    fin: frame.fin(),
                };
                assert_eq!(
                    summary,
                    Coproduct::Inl(Coproduct::Inl(StreamSummary {
                        stream_id: frame.stream_id().get(),
                        offset: frame.data_offset(),
                        len: frame.data().len(),
                        fin: frame.fin(),
                    }))
                );
                read
            }
            Ok(other) => panic!("the tests write no {other:?}"),
            Err(other) => {
                let frame: ResetStreamAtFrame = other.extract();
                assert_eq!(
                    summary,
                    Coproduct::Inl(Coproduct::Inr(Coproduct::Inl(ResetStreamSummary {
                        stream_id: frame.stream_id().get(),
                        final_size: frame.final_size().get(),
                        reliable_size: frame.reliable_size().get(),
                    })))
                );
                Read::ResetStreamAt {
                    stream: frame.stream_id().get(),
                    final_size: frame.final_size().get(),
                    reliable_size: frame.reliable_size().get(),
                }
            }
        });
    }
    assert!(summaries.next().is_none());
    read
}

// ---- the tests ----

/// RESET_STREAM_AT with code 1, then RESET_STREAM with code 2, on the
/// peer's stream: the second changes the error code, which the extension
/// makes a STREAM_STATE_ERROR (draft §5.2).
#[test]
fn a_reset_that_changes_the_code_of_a_reset_stream_at_is_a_stream_state_error() {
    let mut set = reliable_client_set(true);
    lent(&mut set)
        .on_reset_frame(&mut publisher(), reset_stream_at(1, 1, 10, 4))
        .expect("the first reset of stream 1");
    let error = lent(&mut set)
        .on_reset_stream(&mut publisher(), reset_stream_with_code(1, 2, 10))
        .expect_err("another code");
    assert!(matches!(
        error,
        StreamSetFrameError::ResetStream {
            source: OnResetStreamError::ResetCodeChanged {
                source: ResetCodeChangeError { .. }
            }
        }
    ));
    assert_eq!(
        error.transport_error_code(),
        TransportErrorCode::STREAM_STATE_ERROR
    );
    // the same code lowers the reliable size to zero, and is taken
    lent(&mut set)
        .on_reset_stream(&mut publisher(), reset_stream_with_code(1, 1, 10))
        .expect("the same code");
}

/// Accept the peer's stream 1 for a holder of its writer and write `len`
/// bytes into its sending part: the credential of the writer.
fn written_peer_stream(set: &mut ReliableSet, len: usize) -> StreamWriterCredential {
    lent(set)
        .on_stream_frame(
            &mut publisher(),
            EncryptionLevel::OneRtt,
            stream_frame(1, 1, false),
        )
        .expect("stream 1");
    let accepted = lent(set).poll_accept_held(&mut context(), Directionality::Bidirectional);
    assert_eq!(accepted, Poll::Ready(Ok(id(1))));
    let writer = StreamWriterCredential::new(id(1));
    let wrote = lent(set).poll_write(
        &mut publisher(),
        &writer,
        &mut context(),
        &mut Bytes::from(vec![9; len]),
        &Urgency::default(),
        &AnyActiveLinkPath,
    );
    assert!(matches!(wrote, Poll::Ready(Ok(_))));
    writer
}

/// A reset at a reliable size writes RESET_STREAM_AT; its acknowledgment
/// and that of the data below the reliable size end the sending part in
/// "Data Recvd" (draft §5.3), and a later frame with a lower reliable size
/// has to be acknowledged in its turn.
#[test]
fn a_reset_at_a_reliable_size_ends_once_its_frame_and_prefix_are_acknowledged() {
    let mut set = reliable_client_set(true);
    let writer = written_peer_stream(&mut set, 10);
    let reset_at = |set: &mut ReliableSet, reliable: u32| {
        lent(set).reset_with(
            &mut publisher(),
            &writer,
            ResetStreamAtRequest {
                code: ApplicationErrorCode::new(v(3)),
                reliable_size: v(reliable),
            },
        )
    };
    reset_at(&mut set, 6).expect("not done");
    let reset = StreamIntentKey::ResetStream(id(1));
    let data = StreamIntentKey::Stream(id(1));
    assert_eq!(
        written(&mut set, data, 100),
        [Read::Stream {
            stream: id(1),
            offset: v(0),
            len: 6,
            fin: false,
        }]
    );
    assert_eq!(
        written(&mut set, reset, 100),
        [Read::ResetStreamAt {
            stream: id(1),
            final_size: v(6),
            reliable_size: v(6),
        }]
    );
    // the reliable size is lowered before anything is acknowledged: its
    // frame is due again
    reset_at(&mut set, 2).expect("lower");
    let summary = |reliable: u32| {
        StreamSetFrameSummary::ResetStream(ResetStreamSummary {
            stream_id: id(1),
            final_size: v(6),
            reliable_size: v(reliable),
        })
    };
    lent(&mut set).on_frame_delivered(
        &mut publisher(),
        StreamSetFrameSummary::Stream(StreamSummary {
            stream_id: id(1),
            offset: v(0),
            len: 6,
            fin: false,
        }),
    );
    // the frame of the earlier, larger reliable size is not the one in
    // effect: the sending part has not ended, and is reset
    lent(&mut set).on_frame_delivered(&mut publisher(), summary(6));
    assert!(matches!(
        lent(&mut set).poll_all_acknowledged(&writer, &mut context()),
        Poll::Ready(Err(AllAcknowledgedError::Reset { .. }))
    ));
    assert_eq!(
        written(&mut set, reset, 100),
        [Read::ResetStreamAt {
            stream: id(1),
            final_size: v(6),
            reliable_size: v(2),
        }]
    );
    lent(&mut set).on_frame_delivered(&mut publisher(), summary(2));
    // "Data Recvd": everything the reliable size keeps was acknowledged
    assert_eq!(
        lent(&mut set).poll_all_acknowledged(&writer, &mut context()),
        Poll::Ready(Ok(()))
    );
}
