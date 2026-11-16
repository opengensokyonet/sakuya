use bytes::Bytes;
use sakuya_stream::{
    connection::{CloseReason, LayerEnd},
    send::write::FlushError,
};

use crate::{
    send_strategy::{MinimumLengths, SendIntentHandle},
    v1::streams::{StreamSetFrameError, resets::Rfc9000StreamResets},
};
use sakuya_wire::{
    v1::{
        application_error::ApplicationErrorCode,
        encryption_level::EncryptionLevel,
        frame::{
            max_stream_data::MaxStreamDataFrame, max_streams::MaxStreamsFrame,
            reset_stream::ResetStreamFrame, stop_sending::StopSendingFrame, stream::StreamFrame,
        },
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

use super::*;

/// The set the tests use: no close cause, the test ticket.
type TestSet = LockedStreamSet<(), TestTicket, Rfc9000StreamResets>;

/// What happened to the intents the set published.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Published(StreamIntent<Urgency>),
    Resized(StreamIntentKey, MinimumLengths),
    Withdrawn(StreamIntentKey),
}

thread_local! {
    static EVENTS: std::cell::RefCell<Vec<Event>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// The events since the last call, of this thread.
fn events() -> Vec<Event> {
    EVENTS.with(|events| core::mem::take(&mut *events.borrow_mut()))
}

fn record(event: Event) {
    EVENTS.with(|events| events.borrow_mut().push(event));
}

/// A ticket that records what is done with it.
#[derive(Debug)]
struct TestTicket {
    key: StreamIntentKey,
}

impl IntentTicketResize for TestTicket {
    fn resize(&mut self, min: MinimumLengths) {
        record(Event::Resized(self.key, min));
    }
}

impl IntentTicketWithdraw for TestTicket {
    type Report = ();

    fn withdraw(self) {
        record(Event::Withdrawn(self.key));
    }
}

/// A handle that records what it publishes.
#[derive(Debug, Clone)]
struct TestPublish;

impl SendIntentHandle<StreamIntent<Urgency>, AnyActiveLinkPath> for TestPublish {
    type Outcome = TestTicket;

    fn publish_to(&self, intent: StreamIntent<Urgency>, _: AnyActiveLinkPath) -> TestTicket {
        let key = intent.key();
        record(Event::Published(intent));
        TestTicket { key }
    }
}

fn publish() -> TestPublish {
    TestPublish
}

/// The set of a client: the peer, a server, opens the streams 1, 5, 9, …
/// (bidirectional) and 3, 7, … (unidirectional). The client grants the
/// server three streams of each type, 100 bytes of each bidirectional
/// stream the server opens, 60 of each unidirectional one, and 1000 bytes
/// of the connection; the server grants each bidirectional stream it opens
/// 50 bytes.
fn client_set() -> TestSet {
    client_set_with_connection_limit(1000)
}

fn client_set_with_connection_limit(initial_max_data: u32) -> TestSet {
    let granted_to_peer = FlowControlParameters {
        initial_max_data: InitialMaxData::new(v(initial_max_data)),
        initial_max_stream_data_bidi_local: InitialMaxStreamDataBidiLocal::new(v(70)),
        initial_max_stream_data_bidi_remote: InitialMaxStreamDataBidiRemote::new(v(100)),
        initial_max_stream_data_uni: InitialMaxStreamDataUni::new(v(60)),
        initial_max_streams_bidi: InitialMaxStreamsBidi::new(count(3)),
        initial_max_streams_uni: InitialMaxStreamsUni::new(count(3)),
    };
    let granted_by_peer = FlowControlParameters {
        initial_max_data: InitialMaxData::new(v(500)),
        initial_max_stream_data_bidi_local: InitialMaxStreamDataBidiLocal::new(v(50)),
        initial_max_stream_data_bidi_remote: InitialMaxStreamDataBidiRemote::new(v(40)),
        initial_max_stream_data_uni: InitialMaxStreamDataUni::new(v(30)),
        initial_max_streams_bidi: InitialMaxStreamsBidi::new(count(2)),
        initial_max_streams_uni: InitialMaxStreamsUni::new(count(2)),
    };
    LockedStreamSet::new(
        StreamSetFacts {
            role: Role::Client,
            granted_to_peer,
            granted_by_peer,
        },
        LockedStreamSetConfig::default(),
    )
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

/// A STREAM frame of `stream` with `len` bytes at offset 0.
fn stream_frame(stream: u32, len: usize, fin: bool) -> StreamFrame<Bytes> {
    StreamFrame::new(field(stream), None, Bytes::from(vec![7; len]), fin)
        .expect("a short frame")
        .into_without_length()
        .into()
}

fn stop_sending(stream: u32) -> StopSendingFrame {
    StopSendingFrame::new(
        field(stream),
        VarIntField::shortest(ApplicationErrorCode::new(v(4))),
    )
}

fn max_stream_data(stream: u32, maximum: u32) -> MaxStreamDataFrame {
    MaxStreamDataFrame::new(field(stream), VarIntField::shortest(v(maximum)))
}

fn reset_stream(stream: u32, final_size: u32) -> ResetStreamFrame {
    ResetStreamFrame::new(
        field(stream),
        VarIntField::shortest(ApplicationErrorCode::new(v(2))),
        VarIntField::shortest(v(final_size)),
    )
}

/// The streams of `directionality` waiting to be accepted, in order.
fn to_accept(set: &TestSet, directionality: Directionality) -> Vec<StreamId> {
    let state = lock(&set.shared.set);
    let queue = match directionality {
        Directionality::Bidirectional => &state.accept_bidirectional,
        Directionality::Unidirectional => &state.accept_unidirectional,
    };
    queue.iter().copied().collect()
}

fn receiver(
    set: &TestSet,
    stream: u32,
) -> Option<ReceivingPart<(), TestTicket, Rfc9000StreamResets, Urgency>> {
    lock(&set.shared.set).receivers.get(&id(stream)).cloned()
}

fn sender(
    set: &TestSet,
    stream: u32,
) -> Option<SendingPart<(), TestTicket, Rfc9000StreamResets, Urgency>> {
    lock(&set.shared.set).senders.get(&id(stream)).cloned()
}

/// What reclaiming the state of a stream does: the ledger records it, and
/// its parts leave the tables.
fn reclaim(set: &TestSet, stream: u32) {
    let mut state = lock(&set.shared.set);
    state.ledger.reclaim(id(stream)).expect("a created stream");
    state.receivers.remove(&id(stream));
    state.senders.remove(&id(stream));
}

/// The scenario of stream-events «流进连接»: the first frame of the peer's
/// stream 9 opens 1 and 5 as well, but only 9 gets its parts and waits to
/// be accepted; 1 gets them, and its place in the queue, with its own first
/// frame.
#[test]
fn a_peer_stream_opens_the_lower_ones_but_only_it_is_built() {
    let mut set = client_set();
    set.on_stream_frame(
        &publish(),
        EncryptionLevel::OneRtt,
        stream_frame(9, 4, false),
    )
    .expect("stream 9 is within the limit");
    assert!(receiver(&set, 9).is_some());
    assert!(
        sender(&set, 9).is_some(),
        "a bidirectional stream sends too"
    );
    assert!(receiver(&set, 1).is_none());
    assert!(receiver(&set, 5).is_none());
    assert_eq!(to_accept(&set, Directionality::Bidirectional), [id(9)]);

    set.on_stream_frame(
        &publish(),
        EncryptionLevel::OneRtt,
        stream_frame(1, 2, false),
    )
    .expect("stream 1 was opened with 9");
    assert!(receiver(&set, 1).is_some());
    assert_eq!(
        to_accept(&set, Directionality::Bidirectional),
        [id(9), id(1)]
    );
    // a later frame of 9 does not queue it again
    set.on_stream_frame(
        &publish(),
        EncryptionLevel::OneRtt,
        stream_frame(9, 6, false),
    )
    .expect("more data of 9");
    assert_eq!(
        to_accept(&set, Directionality::Bidirectional),
        [id(9), id(1)]
    );
    assert!(to_accept(&set, Directionality::Unidirectional).is_empty());
}

/// The parts of the peer's streams start with the limits RFC 9000 §18.2
/// gives them: a bidirectional stream receives up to this side's
/// `initial_max_stream_data_bidi_remote` and sends up to the peer's
/// `initial_max_stream_data_bidi_local`; a unidirectional one receives up
/// to this side's `initial_max_stream_data_uni` and does not send.
#[test]
fn the_parts_of_peer_streams_start_with_their_limits() {
    let mut set = client_set();
    set.on_stream_frame(
        &publish(),
        EncryptionLevel::OneRtt,
        stream_frame(1, 1, false),
    )
    .expect("a bidirectional stream");
    set.on_stream_frame(
        &publish(),
        EncryptionLevel::OneRtt,
        stream_frame(3, 1, false),
    )
    .expect("a unidirectional stream");
    let bidirectional = receiver(&set, 1).expect("built");
    assert_eq!(bidirectional.lock().receiver.opened_limit(), v(100));
    let sending = sender(&set, 1).expect("built");
    assert_eq!(sending.lock().sender.peer_stream_limit(), v(50));
    let unidirectional = receiver(&set, 3).expect("built");
    assert_eq!(unidirectional.lock().receiver.opened_limit(), v(60));
    assert!(sender(&set, 3).is_none());
    assert_eq!(to_accept(&set, Directionality::Unidirectional), [id(3)]);
}

#[test]
fn a_late_frame_of_a_reclaimed_stream_is_ignored() {
    let mut set = client_set();
    set.on_stream_frame(
        &publish(),
        EncryptionLevel::OneRtt,
        stream_frame(1, 4, true),
    )
    .expect("stream 1");
    reclaim(&set, 1);
    set.on_stream_frame(
        &publish(),
        EncryptionLevel::OneRtt,
        stream_frame(1, 4, true),
    )
    .expect("ignored");
    set.on_reset_stream(&publish(), reset_stream(1, 4))
        .expect("ignored");
    set.on_max_stream_data(&publish(), max_stream_data(1, 90))
        .expect("ignored");
    assert!(receiver(&set, 1).is_none());
    assert!(sender(&set, 1).is_none());
    assert_eq!(to_accept(&set, Directionality::Bidirectional), [id(1)]);
}

#[test]
fn a_frame_of_a_stream_this_side_has_not_opened_is_a_stream_state_error() {
    let mut set = client_set();
    let error = set
        .on_stream_frame(
            &publish(),
            EncryptionLevel::OneRtt,
            stream_frame(0, 1, false),
        )
        .expect_err("stream 0 is the client's, not opened");
    assert!(matches!(
        error,
        StreamSetFrameError::ReceivingPartFrame { .. }
    ));
    assert_eq!(
        error.transport_error_code(),
        TransportErrorCode::STREAM_STATE_ERROR
    );
    let error = set
        .on_stop_sending(&publish(), stop_sending(4))
        .expect_err("stream 4 is the client's, not opened");
    assert!(matches!(
        error,
        StreamSetFrameError::SendingPartFrame { .. }
    ));
    assert_eq!(
        error.transport_error_code(),
        TransportErrorCode::STREAM_STATE_ERROR
    );
}

#[test]
fn a_sending_part_frame_of_a_peer_unidirectional_stream_is_a_stream_state_error() {
    let mut set = client_set();
    let error = set
        .on_max_stream_data(&publish(), max_stream_data(3, 10))
        .expect_err("stream 3 only receives here");
    assert_eq!(
        error.transport_error_code(),
        TransportErrorCode::STREAM_STATE_ERROR
    );
}

#[test]
fn a_stream_beyond_the_limit_granted_to_the_peer_is_a_stream_limit_error() {
    let mut set = client_set();
    // index 3 of the server's bidirectional streams: the fourth, of three
    let error = set
        .on_stream_frame(
            &publish(),
            EncryptionLevel::OneRtt,
            stream_frame(13, 1, false),
        )
        .expect_err("beyond the limit");
    assert_eq!(
        error.transport_error_code(),
        TransportErrorCode::STREAM_LIMIT_ERROR
    );
    assert!(to_accept(&set, Directionality::Bidirectional).is_empty());
}

#[test]
fn data_beyond_the_connection_limit_is_a_flow_control_error() {
    let mut set = client_set_with_connection_limit(10);
    set.on_stream_frame(
        &publish(),
        EncryptionLevel::OneRtt,
        stream_frame(1, 6, false),
    )
    .expect("within the connection's limit");
    let error = set
        .on_stream_frame(
            &publish(),
            EncryptionLevel::OneRtt,
            stream_frame(5, 6, false),
        )
        .expect_err("12 bytes of the connection, beyond 10");
    assert!(matches!(error, StreamSetFrameError::Stream { .. }));
    assert_eq!(
        error.transport_error_code(),
        TransportErrorCode::FLOW_CONTROL_ERROR
    );
}

#[test]
fn max_stream_data_raises_the_limit_of_the_sending_part() {
    let mut set = client_set();
    set.on_stream_frame(
        &publish(),
        EncryptionLevel::OneRtt,
        stream_frame(1, 1, false),
    )
    .expect("stream 1");
    set.on_max_stream_data(&publish(), max_stream_data(1, 80))
        .expect("a sending part");
    let part = sender(&set, 1).expect("built");
    assert_eq!(part.lock().sender.peer_stream_limit(), v(80));
    // a lower limit is ignored
    set.on_max_stream_data(&publish(), max_stream_data(1, 60))
        .expect("a sending part");
    assert_eq!(part.lock().sender.peer_stream_limit(), v(80));
}

/// A frame for the sending part of a bidirectional stream of the peer opens
/// it (RFC 9000 §3.2, §19.5): both its parts are built and it waits to be
/// accepted.
#[test]
fn stop_sending_opens_a_peer_bidirectional_stream() {
    let mut set = client_set();
    set.on_stop_sending(&publish(), stop_sending(5))
        .expect("within the limit");
    assert!(receiver(&set, 5).is_some());
    let part = sender(&set, 5).expect("built");
    assert_eq!(
        part.lock().sender.stop_sending_code(),
        Some(ApplicationErrorCode::new(v(4)))
    );
    assert_eq!(to_accept(&set, Directionality::Bidirectional), [id(5)]);
}

#[test]
fn max_streams_raises_the_limit_on_this_sides_streams() {
    let mut set = client_set();
    let frame = MaxStreamsFrame::new(
        Directionality::Bidirectional,
        VarIntField::shortest(count(5)),
    );
    set.on_max_streams(&publish(), frame)
        .expect("no rule to break");
    let state = lock(&set.shared.set);
    assert_eq!(
        state.ledger.local_limit(Directionality::Bidirectional),
        count(5)
    );
}

#[test]
fn a_stream_frame_in_a_zero_rtt_packet_marks_its_stream() {
    let mut set = client_set();
    set.on_stream_frame(
        &publish(),
        EncryptionLevel::OneRtt,
        stream_frame(1, 1, false),
    )
    .expect("stream 1");
    set.on_stream_frame(
        &publish(),
        EncryptionLevel::OneRtt,
        stream_frame(5, 1, false),
    )
    .expect("stream 5");
    let one = receiver(&set, 1).expect("built");
    assert!(!one.lock().receiver.received_zero_rtt());
    set.on_stream_frame(
        &publish(),
        EncryptionLevel::ZeroRtt,
        stream_frame(1, 3, false),
    )
    .expect("more data of 1");
    assert!(one.lock().receiver.received_zero_rtt());
    let five = receiver(&set, 5).expect("built");
    assert!(!five.lock().receiver.received_zero_rtt());
}

#[test]
fn every_part_hears_the_same_end_of_the_layer() {
    let mut set = client_set();
    set.on_stream_frame(
        &publish(),
        EncryptionLevel::OneRtt,
        stream_frame(1, 1, false),
    )
    .expect("a bidirectional stream");
    set.on_stream_frame(
        &publish(),
        EncryptionLevel::OneRtt,
        stream_frame(3, 1, false),
    )
    .expect("a unidirectional stream");
    let end = LayerEnd::ConnectionClosed(CloseReason::IdleTimeout);
    set.layer_ended(end.clone());
    for stream in [1, 3] {
        let part = receiver(&set, stream).expect("built");
        let part = part.lock();
        let closed = part.receiver.closed().expect("the layer ended");
        assert_eq!(closed.end(), &end);
    }
    let part = sender(&set, 1).expect("built");
    let Err(FlushError::LayerEnded { source }) = part.lock().sender.flush() else {
        panic!("the layer ended");
    };
    assert_eq!(source.end(), &end);
    assert_eq!(lock(&set.shared.set).end.as_ref(), Some(&end));

    // a second end changes nothing, and frames are ignored from now on
    set.layer_ended(LayerEnd::ZeroRttRejected);
    assert_eq!(lock(&set.shared.set).end.as_ref(), Some(&end));
    set.on_stream_frame(
        &publish(),
        EncryptionLevel::OneRtt,
        stream_frame(5, 1, false),
    )
    .expect("ignored");
    assert!(receiver(&set, 5).is_none());
}

// ---- the intents and the frames of the streams ----

/// A frame as the peer reads it from a packet the set wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Read {
    Stream {
        stream: StreamId,
        offset: VarInt,
        len: usize,
        fin: bool,
    },
    ResetStream {
        stream: StreamId,
        final_size: VarInt,
    },
    MaxStreamData {
        stream: StreamId,
        limit: VarInt,
    },
    Other,
}

/// Give the item `key` to `set` with `packet`.
///
/// `I1` to `I9` are the places of the summaries of the nine kinds of frames
/// in the packet's summary; the compiler infers them.
fn supply_key<W, Q, I1, I2, I3, I4, I5, I6, I7, I8, I9>(
    set: &mut TestSet,
    key: StreamIntentKey,
    packet: OpenPacket<W, InFlightClass, Q>,
) -> Supplied<W, InFlightClass, Q>
where
    W: PacketWriting,
    Q: PacketPosition,
    SummaryOf<W>: InjectSummary<StreamSummary, I1>
        + InjectSummary<ResetStreamSummary, I2>
        + InjectSummary<StopSendingSummary, I3>
        + InjectSummary<MaxDataSummary, I4>
        + InjectSummary<MaxStreamDataSummary, I5>
        + InjectSummary<MaxStreamsSummary, I6>
        + InjectSummary<DataBlockedSummary, I7>
        + InjectSummary<StreamDataBlockedSummary, I8>
        + InjectSummary<StreamsBlockedSummary, I9>,
{
    let publish = publish();
    match key {
        StreamIntentKey::Stream(id) => set.supply_stream(&publish, id, packet),
        StreamIntentKey::ResetStream(id) => set.supply_reset_stream(&publish, id, packet),
        StreamIntentKey::StopSending(id) => set.supply_stop_sending(&publish, id, packet),
        StreamIntentKey::MaxData => set.supply_max_data(&publish, packet),
        StreamIntentKey::MaxStreamData(id) => set.supply_max_stream_data(&publish, id, packet),
        StreamIntentKey::MaxStreams(directionality) => {
            set.supply_max_streams(&publish, directionality, packet)
        }
        StreamIntentKey::DataBlocked => set.supply_data_blocked(&publish, packet),
        StreamIntentKey::StreamDataBlocked(id) => {
            set.supply_stream_data_blocked(&publish, id, packet)
        }
        StreamIntentKey::StreamsBlocked(directionality) => {
            set.supply_streams_blocked(&publish, directionality, packet)
        }
    }
}

/// What the peer reads of the 1-RTT packet the item `key` of `set` is
/// written into, with `room` bytes for frames, the last packet of its
/// datagram if `last`.
fn written(set: &mut TestSet, key: StreamIntentKey, room: usize, last: bool) -> Vec<Read> {
    use core::{marker::PhantomData, num::NonZeroUsize};

    use bytes::BytesMut;
    use sakuya_recovery::send_journals::{DequeSendJournals, SendJournals as _};
    use sakuya_wire::{
        parts::{CNil, Coproduct, HList},
        v1::frame::{FrameRun, set::Frames},
    };

    use crate::v1::{
        aead_usage::AeadUsage,
        datagram_batch::tests::{Accounts, Batch, one_rtt_keys},
        feedback::FeedbackSummary,
        receive::open_one_rtt,
    };

    // a 1-RTT packet takes 26 bytes beyond its frames here
    let max_len = 26 + room;
    let (sender, receiver) = one_rtt_keys();
    let mut journals = DequeSendJournals::<u64, Coproduct<FeedbackSummary<u64>, CNil>, ()>::new();
    let mut usage = AeadUsage::new();
    let mut accounts = Accounts::new();
    let mut batch = Batch::new(NonZeroUsize::MIN);
    {
        let mut datagram = accounts.start(&mut batch, Role::Server, max_len, max_len, false);
        let packet = datagram
            .start_one_rtt_packet(
                journals.start_attempt(()),
                sender.send().unwrap(),
                &mut usage,
                None,
            )
            .unwrap();
        let open = packet.open::<InFlightClass>();
        assert_eq!(open.remaining(), room);
        if last {
            let _ = supply_key(set, key, open.make_last());
        } else {
            let _ = supply_key(set, key, open);
        }
    }
    let Some(datagram) = batch.datagrams().next() else {
        return Vec::new();
    };
    let mut packet = BytesMut::from(datagram);
    let (opened, _) =
        open_one_rtt(receiver.receive().unwrap(), None, &mut packet, 9, None).unwrap();
    let payload = &packet[opened.payload.clone()];
    let frames = Frames::new(payload, PhantomData::<HList![sakuya_wire::v1::Part]>);
    let mut read = Vec::new();
    for run in frames {
        read.push(match run.unwrap().extract() {
            FrameRun::Padding(_) => continue,
            FrameRun::Stream(frame) => Read::Stream {
                stream: frame.stream_id().get(),
                offset: frame.data_offset(),
                len: frame.data().len(),
                fin: frame.fin(),
            },
            FrameRun::ResetStream(frame) => Read::ResetStream {
                stream: frame.stream_id().get(),
                final_size: frame.final_size().get(),
            },
            FrameRun::MaxStreamData(frame) => Read::MaxStreamData {
                stream: frame.stream_id().get(),
                limit: frame.maximum_stream_data().get(),
            },
            _ => Read::Other,
        });
    }
    read
}

fn options() -> SendOptions<Urgency, AnyActiveLinkPath> {
    SendOptions::new(Urgency::default(), AnyActiveLinkPath)
}

/// A client set whose peer opened its bidirectional stream 1; the events
/// of that are forgotten.
fn set_with_peer_stream() -> TestSet {
    let mut set = client_set();
    set.on_stream_frame(
        &publish(),
        EncryptionLevel::OneRtt,
        stream_frame(1, 1, false),
    )
    .expect("stream 1");
    events();
    set
}

/// Write `len` bytes into the sending part of `stream`, as the
/// application's writer does, and bring its intents up to date.
fn write(set: &TestSet, stream: u32, len: usize) {
    let part = sender(set, stream).expect("built");
    let mut end = part.lock();
    end.sender
        .write(&mut Bytes::from(vec![9; len]), &options())
        .expect("within the limits");
    end.sync_intents(&publish());
}

/// The scenario of connection-driver «消耗»: data written is published; a
/// supply that writes part of it resizes the intent to what is left, one
/// that writes the rest withdraws it; lost data is published again, and
/// withdrawn once a late acknowledgment of it arrives.
#[test]
fn a_stream_intent_follows_the_data_waiting() {
    let mut set = set_with_peer_stream();
    write(&set, 1, 30);
    assert_eq!(
        events(),
        [Event::Published(StreamIntent::Stream {
            stream_id: id(1),
            parameters: Urgency::default(),
            min: MinimumLengths {
                with_length: 4,
                as_last: 3,
            },
        })]
    );

    // with a Length field, 12 bytes take 9 of the data
    let key = StreamIntentKey::Stream(id(1));
    assert_eq!(
        written(&mut set, key, 12, false),
        [Read::Stream {
            stream: id(1),
            offset: v(0),
            len: 9,
            fin: false,
        }]
    );
    // the next byte is at offset 9: one byte more for the Offset field
    assert_eq!(
        events(),
        [Event::Resized(
            key,
            MinimumLengths {
                with_length: 5,
                as_last: 4,
            }
        )]
    );

    // the rest, as the last frame of its packet
    assert_eq!(
        written(&mut set, key, 100, true),
        [Read::Stream {
            stream: id(1),
            offset: v(9),
            len: 21,
            fin: false,
        }]
    );
    assert_eq!(events(), [Event::Withdrawn(key)]);

    let first = StreamSummary {
        stream_id: id(1),
        offset: v(0),
        len: 9,
        fin: false,
    };
    set.on_frame_lost(&publish(), StreamSetFrameSummary::Stream(first));
    assert_eq!(
        events(),
        [Event::Published(StreamIntent::Stream {
            stream_id: id(1),
            parameters: Urgency::default(),
            min: MinimumLengths {
                with_length: 4,
                as_last: 3,
            },
        })]
    );
    set.on_frame_delivered(&publish(), StreamSetFrameSummary::Stream(first));
    assert_eq!(events(), [Event::Withdrawn(key)]);
}

/// A closed stream sends its FIN alone once its data went; the
/// acknowledgment of the FIN and all data makes the sending part done.
#[test]
fn the_fin_goes_alone_and_its_acknowledgment_ends_the_sending_part() {
    let mut set = set_with_peer_stream();
    write(&set, 1, 5);
    let key = StreamIntentKey::Stream(id(1));
    assert_eq!(
        written(&mut set, key, 100, false),
        [Read::Stream {
            stream: id(1),
            offset: v(0),
            len: 5,
            fin: false,
        }]
    );
    let part = sender(&set, 1).expect("built");
    {
        let mut end = part.lock();
        end.sender.close().expect("open");
        end.sync_intents(&publish());
    }
    events();
    assert_eq!(
        written(&mut set, key, 100, false),
        [Read::Stream {
            stream: id(1),
            offset: v(5),
            len: 0,
            fin: true,
        }]
    );
    assert_eq!(events(), [Event::Withdrawn(key)]);
    let fin = StreamSummary {
        stream_id: id(1),
        offset: v(5),
        len: 0,
        fin: true,
    };
    // the FIN lost is sent again
    set.on_frame_lost(&publish(), StreamSetFrameSummary::Stream(fin));
    assert!(matches!(
        events().as_slice(),
        [Event::Published(StreamIntent::Stream { .. })]
    ));
    set.on_frame_delivered(&publish(), StreamSetFrameSummary::Stream(fin));
    assert_eq!(part.lock().sender.terminal_state(), None);
    set.on_frame_delivered(
        &publish(),
        StreamSetFrameSummary::Stream(StreamSummary {
            stream_id: id(1),
            offset: v(0),
            len: 5,
            fin: false,
        }),
    );
    assert_eq!(
        part.lock().sender.terminal_state(),
        Some(SendTerminalState::DataRecvd)
    );
    assert_eq!(events(), [Event::Withdrawn(key)]);
}

/// A reset withdraws the data and publishes its RESET_STREAM, at the
/// least final size, as nothing was sent; the frame is sent again when lost
/// and ends the sending part once acknowledged.
#[test]
fn a_reset_is_sent_until_acknowledged() {
    let mut set = set_with_peer_stream();
    write(&set, 1, 5);
    events();
    let part = sender(&set, 1).expect("built");
    {
        let mut end = part.lock();
        end.sender
            .reset(ApplicationErrorCode::new(v(6)))
            .expect("not done");
        end.sync_intents(&publish());
    }
    let key = StreamIntentKey::ResetStream(id(1));
    assert_eq!(
        events(),
        [
            Event::Withdrawn(StreamIntentKey::Stream(id(1))),
            Event::Published(StreamIntent::ResetStream {
                stream_id: id(1),
                len: 4,
            }),
        ]
    );
    assert_eq!(
        written(&mut set, key, 100, false),
        [Read::ResetStream {
            stream: id(1),
            final_size: v(0),
        }]
    );
    assert_eq!(events(), [Event::Withdrawn(key)]);
    let summary = ResetStreamSummary {
        stream_id: id(1),
        final_size: v(0),
    };
    set.on_frame_lost(&publish(), StreamSetFrameSummary::ResetStream(summary));
    assert_eq!(
        events(),
        [Event::Published(StreamIntent::ResetStream {
            stream_id: id(1),
            len: 4,
        })]
    );
    set.on_frame_delivered(&publish(), StreamSetFrameSummary::ResetStream(summary));
    assert_eq!(
        part.lock().sender.terminal_state(),
        Some(SendTerminalState::ResetRecvd)
    );
    assert_eq!(events(), [Event::Withdrawn(key)]);
    // lost after it was acknowledged: nothing more
    set.on_frame_lost(&publish(), StreamSetFrameSummary::ResetStream(summary));
    assert_eq!(events(), []);
}

/// A client set whose peer's bidirectional streams get a window of 40.
fn narrow_window_set() -> TestSet {
    let mut granted_to_peer = FlowControlParameters {
        initial_max_data: InitialMaxData::new(v(1000)),
        initial_max_streams_bidi: InitialMaxStreamsBidi::new(count(3)),
        ..FlowControlParameters::default()
    };
    granted_to_peer.initial_max_stream_data_bidi_remote =
        InitialMaxStreamDataBidiRemote::new(v(40));
    LockedStreamSet::new(
        StreamSetFacts {
            role: Role::Client,
            granted_to_peer,
            granted_by_peer: FlowControlParameters::default(),
        },
        LockedStreamSetConfig::default(),
    )
}

/// Read `len` bytes of `stream`, as the application's reader does, and
/// bring its intents up to date.
fn read(set: &TestSet, stream: u32, len: usize) {
    let part = receiver(set, stream).expect("built");
    let mut end = part.lock();
    end.receiver
        .read_chunk(core::num::NonZeroUsize::new(len).unwrap())
        .expect("data to read");
    end.sync_intents(id(stream), &publish());
}

/// The window of 40 slides by what is read: at 20 bytes read the limit 60
/// is advertised, a frame of 3 bytes; at 24 the limit 64 takes one byte
/// more, and the intent is resized. Written, the limit is open; lost, the
/// limit in effect is sent again.
#[test]
fn a_wider_max_stream_data_resizes_its_intent() {
    let mut set = narrow_window_set();
    set.on_stream_frame(
        &publish(),
        EncryptionLevel::OneRtt,
        stream_frame(1, 24, false),
    )
    .expect("within the window");
    events();
    read(&set, 1, 20);
    let key = StreamIntentKey::MaxStreamData(id(1));
    assert_eq!(
        events(),
        [Event::Published(StreamIntent::MaxStreamData {
            stream_id: id(1),
            len: 3,
        })]
    );
    read(&set, 1, 4);
    assert_eq!(
        events(),
        [Event::Resized(
            key,
            MinimumLengths {
                with_length: 4,
                as_last: 4,
            }
        )]
    );
    assert_eq!(
        written(&mut set, key, 100, false),
        [Read::MaxStreamData {
            stream: id(1),
            limit: v(64),
        }]
    );
    assert_eq!(events(), [Event::Withdrawn(key)]);
    let part = receiver(&set, 1).expect("built");
    assert_eq!(part.lock().receiver.opened_limit(), v(64));

    set.on_frame_lost(
        &publish(),
        StreamSetFrameSummary::MaxStreamData(MaxStreamDataSummary {
            stream_id: id(1),
            maximum_stream_data: v(64),
        }),
    );
    assert_eq!(
        events(),
        [Event::Published(StreamIntent::MaxStreamData {
            stream_id: id(1),
            len: 4,
        })]
    );
}

/// Once the layer ended, nothing is written: the frame sources find the
/// streams ended with it.
#[test]
fn nothing_is_written_once_the_layer_ended() {
    let mut set = set_with_peer_stream();
    write(&set, 1, 5);
    events();
    set.layer_ended(LayerEnd::ConnectionClosed(CloseReason::IdleTimeout));
    assert_eq!(
        written(&mut set, StreamIntentKey::Stream(id(1)), 100, false),
        []
    );
}
