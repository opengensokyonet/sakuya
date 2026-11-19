use bytes::Bytes;
use sakuya_stream::{
    connection::{CloseReason, LayerEnd},
    send::write::FlushError,
};

use crate::write::FlightClass;
use crate::{
    send_strategy::{
        FrameSourceSet, IntentTicketResize, MinimumLengths, SendStrategyTypes,
        ranked::{RankedSendPublisher, RankedSendStrategy},
    },
    v1::{
        send::FrameSourceId,
        streams::{StreamSetFrameError, resets::Rfc9000StreamResets},
    },
};
use sakuya_wire::parts::{CNil, Coproduct};
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
use crate::send_strategy::SendIntent;
use crate::v1::streams::FlowControlParameters;
use crate::v1::streams::set_state::max_streams_frame;
use sakuya_stream::{send::SendTerminalState, send_options::SendOptions};

/// The set the tests use: no close cause, the test ticket, publishing
/// through the test handle.
type TestSet = LockedStreamSet<(), TestTicket, TestPublish, Rfc9000StreamResets>;

// ---- the strategy types the set is lent the publisher of ----

/// The sum of intents of the tests: the stream intents alone.
pub(in crate::v1::streams) type TestIntents =
    Coproduct<Coproduct<StreamIntent<Urgency>, CNil>, CNil>;

fn inner(intent: &TestIntents) -> &StreamIntent<Urgency> {
    match intent {
        Coproduct::Inl(Coproduct::Inl(intent)) => intent,
        Coproduct::Inl(Coproduct::Inr(never)) | Coproduct::Inr(never) => match *never {},
    }
}

/// Every kind of packet carries the stream intents.
#[derive(Debug)]
pub(in crate::v1::streams) enum TestSources {}

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
/// publisher the set is lent and ignores.
#[derive(Debug)]
pub(in crate::v1::streams) enum TestTypes {}

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
pub(in crate::v1::streams) type TestPublisher = RankedSendPublisher<TestTypes>;

/// A set of `facts`, publishing through the test handle.
fn new_set<Rs>(
    facts: StreamSetFacts<Rs::PeerSupport>,
    config: LockedStreamSetConfig,
    events: NoEvents,
) -> LockedStreamSet<(), TestTicket, TestPublish, Rs>
where
    Rs: StreamResets,
    LockedStreamSet<(), TestTicket, TestPublish, Rs>: StreamSet<
            (),
            TestTypes,
            Rs,
            Config = LockedStreamSetConfig,
            Events = NoEvents,
            Intake = TestPublish,
        >,
{
    <LockedStreamSet<(), TestTicket, TestPublish, Rs> as StreamSet<(), TestTypes, Rs>>::new(
        facts,
        config,
        events,
        TestPublish,
    )
}

/// The set `set` as the driver lends it: a stream set over the test
/// strategy types, so that its methods know them.
pub(in crate::v1::streams) fn lent<X, Rs>(
    set: &mut X,
) -> &mut impl StreamSet<(), TestTypes, Rs, SendParameters = Urgency, Handle = X::Handle>
where
    X: StreamSet<(), TestTypes, Rs, SendParameters = Urgency>,
    Rs: StreamResets,
{
    set
}

/// A publisher for one call: the set publishes through its own handle.
pub(in crate::v1::streams) fn publisher() -> TestPublisher {
    TestPublisher::default()
}

/// What happened to the intents the set published.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Published(StreamIntent<Urgency>),
    Resized(StreamIntentKey, MinimumLengths),
    Withdrawn(StreamIntentKey),
    /// Let go once its frame was written, not withdrawn.
    Released(StreamIntentKey),
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

/// A handle that records what it publishes, and what is done with its
/// tickets.
#[derive(Debug, Clone)]
struct TestPublish;

impl IntentPublisher<StreamIntent<Urgency>, AnyActiveLinkPath> for TestPublish {
    type Ticket = TestTicket;

    fn publish_to(&mut self, intent: StreamIntent<Urgency>, _: AnyActiveLinkPath) -> TestTicket {
        let key = intent.key();
        record(Event::Published(intent));
        TestTicket { key }
    }

    fn resize(&mut self, ticket: &mut TestTicket, min: MinimumLengths) {
        ticket.resize(min);
    }

    fn withdraw(&mut self, ticket: TestTicket) {
        ticket.withdraw();
    }

    fn release_written(&mut self, ticket: TestTicket) {
        record(Event::Released(ticket.key));
    }

    fn waits_too_large(&self, _: &TestTicket) -> bool {
        false
    }
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
    new_set(
        StreamSetFacts {
            role: Role::Client,
            granted_to_peer,
            granted_by_peer,
            peer_reset_support: (),
        },
        LockedStreamSetConfig::default(),
        NoEvents,
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
    lent(&mut set)
        .on_stream_frame(
            &mut publisher(),
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

    lent(&mut set)
        .on_stream_frame(
            &mut publisher(),
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
    lent(&mut set)
        .on_stream_frame(
            &mut publisher(),
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
    lent(&mut set)
        .on_stream_frame(
            &mut publisher(),
            EncryptionLevel::OneRtt,
            stream_frame(1, 1, false),
        )
        .expect("a bidirectional stream");
    lent(&mut set)
        .on_stream_frame(
            &mut publisher(),
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
    lent(&mut set)
        .on_stream_frame(
            &mut publisher(),
            EncryptionLevel::OneRtt,
            stream_frame(1, 4, true),
        )
        .expect("stream 1");
    reclaim(&set, 1);
    lent(&mut set)
        .on_stream_frame(
            &mut publisher(),
            EncryptionLevel::OneRtt,
            stream_frame(1, 4, true),
        )
        .expect("ignored");
    lent(&mut set)
        .on_reset_stream(&mut publisher(), reset_stream(1, 4))
        .expect("ignored");
    lent(&mut set)
        .on_max_stream_data(&mut publisher(), max_stream_data(1, 90))
        .expect("ignored");
    assert!(receiver(&set, 1).is_none());
    assert!(sender(&set, 1).is_none());
    assert_eq!(to_accept(&set, Directionality::Bidirectional), [id(1)]);
}

#[test]
fn a_frame_of_a_stream_this_side_has_not_opened_is_a_stream_state_error() {
    let mut set = client_set();
    let error = lent(&mut set)
        .on_stream_frame(
            &mut publisher(),
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
    let error = lent(&mut set)
        .on_stop_sending(&mut publisher(), stop_sending(4))
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
    let error = lent(&mut set)
        .on_max_stream_data(&mut publisher(), max_stream_data(3, 10))
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
    let error = lent(&mut set)
        .on_stream_frame(
            &mut publisher(),
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
    lent(&mut set)
        .on_stream_frame(
            &mut publisher(),
            EncryptionLevel::OneRtt,
            stream_frame(1, 6, false),
        )
        .expect("within the connection's limit");
    let error = lent(&mut set)
        .on_stream_frame(
            &mut publisher(),
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
    lent(&mut set)
        .on_stream_frame(
            &mut publisher(),
            EncryptionLevel::OneRtt,
            stream_frame(1, 1, false),
        )
        .expect("stream 1");
    lent(&mut set)
        .on_max_stream_data(&mut publisher(), max_stream_data(1, 80))
        .expect("a sending part");
    let part = sender(&set, 1).expect("built");
    assert_eq!(part.lock().sender.peer_stream_limit(), v(80));
    // a lower limit is ignored
    lent(&mut set)
        .on_max_stream_data(&mut publisher(), max_stream_data(1, 60))
        .expect("a sending part");
    assert_eq!(part.lock().sender.peer_stream_limit(), v(80));
}

/// A frame for the sending part of a bidirectional stream of the peer opens
/// it (RFC 9000 §3.2, §19.5): both its parts are built and it waits to be
/// accepted.
#[test]
fn stop_sending_opens_a_peer_bidirectional_stream() {
    let mut set = client_set();
    lent(&mut set)
        .on_stop_sending(&mut publisher(), stop_sending(5))
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
    lent(&mut set)
        .on_max_streams(&mut publisher(), frame)
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
    lent(&mut set)
        .on_stream_frame(
            &mut publisher(),
            EncryptionLevel::OneRtt,
            stream_frame(1, 1, false),
        )
        .expect("stream 1");
    lent(&mut set)
        .on_stream_frame(
            &mut publisher(),
            EncryptionLevel::OneRtt,
            stream_frame(5, 1, false),
        )
        .expect("stream 5");
    let one = receiver(&set, 1).expect("built");
    assert!(!one.lock().receiver.received_zero_rtt());
    lent(&mut set)
        .on_stream_frame(
            &mut publisher(),
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
    lent(&mut set)
        .on_stream_frame(
            &mut publisher(),
            EncryptionLevel::OneRtt,
            stream_frame(1, 1, false),
        )
        .expect("a bidirectional stream");
    lent(&mut set)
        .on_stream_frame(
            &mut publisher(),
            EncryptionLevel::OneRtt,
            stream_frame(3, 1, false),
        )
        .expect("a unidirectional stream");
    let end = LayerEnd::ConnectionClosed(CloseReason::IdleTimeout);
    lent(&mut set).layer_ended(end.clone());
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
    lent(&mut set).layer_ended(LayerEnd::ZeroRttRejected);
    assert_eq!(lock(&set.shared.set).end.as_ref(), Some(&end));
    lent(&mut set)
        .on_stream_frame(
            &mut publisher(),
            EncryptionLevel::OneRtt,
            stream_frame(5, 1, false),
        )
        .expect("ignored");
    assert!(receiver(&set, 5).is_none());
}

// ---- the intents and the frames of the streams ----

/// A frame as the peer reads it from a packet the set wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::v1::streams) enum Read {
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
    #[cfg(feature = "reset_stream_at")]
    ResetStreamAt {
        stream: StreamId,
        final_size: VarInt,
        reliable_size: VarInt,
    },
    MaxStreamData {
        stream: StreamId,
        limit: VarInt,
    },
    MaxStreams {
        directionality: Directionality,
        limit: StreamCount,
    },
    Other,
}

/// Give the item `key` to `set` with `packet`, lent the publisher
/// `publish`.
///
/// `I1` to `I9` are the places of the summaries of the nine kinds of frames
/// in the packet's summary; the compiler infers them.
#[allow(clippy::too_many_arguments)] // the places of the nine summaries
fn supply_key<X, Rs, W, Q, I1, I2, I3, I4, I5, I6, I7, I8, I9>(
    set: &mut X,
    publish: &mut TestPublisher,
    key: StreamIntentKey,
    packet: OpenPacket<W, InFlightClass, Q>,
) -> Supplied<W, InFlightClass, Q>
where
    X: StreamSet<(), TestTypes, Rs, SendParameters = Urgency>,
    Rs: StreamResets,
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
    match key {
        StreamIntentKey::Stream(id) => set.supply_stream(publish, id, Urgency::default(), packet),
        StreamIntentKey::ResetStream(id) => set.supply_reset_stream(publish, id, packet),
        StreamIntentKey::StopSending(id) => set.supply_stop_sending(publish, id, packet),
        StreamIntentKey::MaxData => set.supply_max_data(publish, packet),
        StreamIntentKey::MaxStreamData(id) => set.supply_max_stream_data(publish, id, packet),
        StreamIntentKey::MaxStreams(directionality) => {
            set.supply_max_streams(publish, directionality, packet)
        }
        StreamIntentKey::DataBlocked => set.supply_data_blocked(publish, packet),
        StreamIntentKey::StreamDataBlocked(id) => {
            set.supply_stream_data_blocked(publish, id, packet)
        }
        StreamIntentKey::StreamsBlocked(directionality) => {
            set.supply_streams_blocked(publish, directionality, packet)
        }
    }
}

/// What the peer reads of the 1-RTT packet the item `key` of `set` is
/// written into, with `room` bytes for frames, the last packet of its
/// datagram if `last`.
pub(in crate::v1::streams) fn written<X, Rs>(
    set: &mut X,
    key: StreamIntentKey,
    room: usize,
    last: bool,
) -> Vec<Read>
where
    X: StreamSet<(), TestTypes, Rs, SendParameters = Urgency>,
    Rs: StreamResets,
{
    written_through(set, &mut publisher(), key, room, last)
}

/// What the peer reads of the packet the item `key` of `set` is written
/// into, as [`written`] has it, lent the publisher `publish`.
pub(in crate::v1::streams) fn written_through<X, Rs>(
    set: &mut X,
    publish: &mut TestPublisher,
    key: StreamIntentKey,
    room: usize,
    last: bool,
) -> Vec<Read>
where
    X: StreamSet<(), TestTypes, Rs, SendParameters = Urgency>,
    Rs: StreamResets,
{
    use core::{marker::PhantomData, num::NonZeroUsize};

    use bytes::BytesMut;
    use sakuya_recovery::send_journals::{DequeSendJournals, SendJournals as _};
    use sakuya_wire::{
        parts::{CNil, Coproduct},
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
            let _ = supply_key(set, publish, key, open.make_last());
        } else {
            let _ = supply_key(set, publish, key, open);
        }
    }
    let summaries: Vec<_> = journals
        .take_link_path(&())
        .flat_map(|record| record.summaries)
        .filter_map(|summary| match summary {
            Coproduct::Inl(summary) => summary.get::<StreamSummary, _>().copied(),
            Coproduct::Inr(never) => match never {},
        })
        .collect();
    let Some(datagram) = batch.datagrams().next() else {
        return Vec::new();
    };
    let mut packet = BytesMut::from(datagram);
    let (opened, _) =
        open_one_rtt(receiver.receive().unwrap(), None, &mut packet, 9, None).unwrap();
    let payload = &packet[opened.payload.clone()];
    let mut frames = Frames::new(payload, PhantomData::<TestFrameSet>).peekable();
    let mut summaries = summaries.iter();
    let mut read = Vec::new();
    while let Some(run) = frames.next() {
        let run = run.unwrap();
        #[cfg(feature = "reset_stream_at")]
        let run = match run.uninject::<FrameRun<&[u8]>, _>() {
            Ok(run) => run,
            Err(other) => {
                let frame: sakuya_wire::reset_stream_at::ResetStreamAtFrame = other.extract();
                read.push(Read::ResetStreamAt {
                    stream: frame.stream_id().get(),
                    final_size: frame.final_size().get(),
                    reliable_size: frame.reliable_size().get(),
                });
                continue;
            }
        };
        #[cfg(not(feature = "reset_stream_at"))]
        let run = run.extract();
        read.push(match run {
            FrameRun::Padding(_) => continue,
            FrameRun::Stream(frame) => {
                assert_eq!(frame.length().is_left(), last && frames.peek().is_none());
                assert_eq!(
                    summaries.next(),
                    Some(&StreamSummary {
                        stream_id: frame.stream_id().get(),
                        offset: frame.data_offset(),
                        len: frame.data().len(),
                        fin: frame.fin(),
                    })
                );
                Read::Stream {
                    stream: frame.stream_id().get(),
                    offset: frame.data_offset(),
                    len: frame.data().len(),
                    fin: frame.fin(),
                }
            }
            FrameRun::ResetStream(frame) => Read::ResetStream {
                stream: frame.stream_id().get(),
                final_size: frame.final_size().get(),
            },
            FrameRun::MaxStreamData(frame) => Read::MaxStreamData {
                stream: frame.stream_id().get(),
                limit: frame.maximum_stream_data().get(),
            },
            FrameRun::MaxStreams(frame) => Read::MaxStreams {
                directionality: frame.directionality(),
                limit: frame.maximum_streams().get(),
            },
            _ => Read::Other,
        });
    }
    assert!(summaries.next().is_none());
    read
}

/// The frame set the tests read what the set wrote with: version 1's, and
/// the reliable stream reset extension's where it is built.
#[cfg(not(feature = "reset_stream_at"))]
type TestFrameSet = sakuya_wire::parts::HList![sakuya_wire::v1::Part];
#[cfg(feature = "reset_stream_at")]
type TestFrameSet =
    sakuya_wire::parts::HList![sakuya_wire::v1::Part, sakuya_wire::reset_stream_at::Part];

fn options() -> SendOptions<Urgency, AnyActiveLinkPath> {
    SendOptions::new(Urgency::default(), AnyActiveLinkPath)
}

/// A client set whose peer opened its bidirectional stream 1; the events
/// of that are forgotten.
fn set_with_peer_stream() -> TestSet {
    let mut set = client_set();
    lent(&mut set)
        .on_stream_frame(
            &mut publisher(),
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
    end.sync_intents(&mut TestPublish);
}

#[test]
fn one_supply_fills_the_packet_from_matching_segments() {
    let key = StreamIntentKey::Stream(id(1));
    let frame = |offset, len, fin| Read::Stream {
        stream: id(1),
        offset: v(offset),
        len,
        fin,
    };
    for (last, tail) in [(true, 3), (false, 2)] {
        let mut set = set_with_peer_stream();
        write(&set, 1, 3);
        write(&set, 1, 5);
        let part = sender(&set, 1).unwrap();
        {
            let mut end = part.lock();
            end.sender.close().unwrap();
            end.sync_intents(&mut TestPublish);
        }
        // The first frame is delimited. Only the last position can spend
        // its Length byte on another byte of the second frame's data.
        assert_eq!(
            written(&mut set, key, 12, last),
            [frame(0, 3, false), frame(3, tail, false)]
        );
        assert_eq!(
            written(&mut set, key, 12, last),
            [frame(3 + tail as u32, 5 - tail, true)]
        );
        // Only the first frame is lost. Its acknowledged neighbor stays
        // out of the retransmission.
        let summary = |offset, len| {
            StreamSetFrameSummary::Stream(StreamSummary {
                stream_id: id(1),
                offset: v(offset),
                len,
                fin: false,
            })
        };
        lent(&mut set).on_frame_delivered(&mut publisher(), summary(3, tail));
        lent(&mut set).on_frame_lost(&mut publisher(), summary(0, 3));
        assert_eq!(written(&mut set, key, 12, last), [frame(0, 3, false)]);
    }
}

#[test]
fn the_next_stream_frame_has_room_for_its_offset_and_one_byte() {
    let key = StreamIntentKey::Stream(id(1));
    // At 64 both the first frame's Length and the next frame's Offset
    // occupy two bytes. The delimited first frame needs 68 bytes; the
    // next needs at least five even in the last position.
    for room in [72, 73] {
        let mut set = set_with_peer_stream();
        lent(&mut set)
            .on_max_stream_data(&mut publisher(), max_stream_data(1, 100))
            .unwrap();
        write(&set, 1, 64);
        write(&set, 1, 5);
        let mut expected = vec![Read::Stream {
            stream: id(1),
            offset: v(0),
            len: 64,
            fin: false,
        }];
        if room == 73 {
            expected.push(Read::Stream {
                stream: id(1),
                offset: v(64),
                len: 1,
                fin: false,
            });
        }
        assert_eq!(written(&mut set, key, room, true), expected);
    }
}

#[test]
fn a_supply_stops_at_a_different_urgency_even_with_room_left() {
    let mut set = set_with_peer_stream();
    let key = StreamIntentKey::Stream(id(1));
    write(&set, 1, 2);
    let part = sender(&set, 1).unwrap();
    let low = SendOptions::new(Urgency::new(7).unwrap(), AnyActiveLinkPath);
    {
        let mut end = part.lock();
        end.sender
            .write(&mut Bytes::from_static(b"later"), &low)
            .unwrap();
        end.sync_intents(&mut TestPublish);
    }
    assert_eq!(
        written(&mut set, key, 32, true),
        [Read::Stream {
            stream: id(1),
            offset: v(0),
            len: 2,
            fin: false,
        }]
    );
    // A cursor still carrying the old urgency cannot take the new head.
    assert!(written(&mut set, key, 32, true).is_empty());
    let end = part.lock();
    let next = end.sender.next_segment(&AnyActiveLinkPath).unwrap();
    assert_eq!(
        (next.offset, next.len, next.marker.parameters()),
        (v(2), 5, low.parameters())
    );
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
    lent(&mut set).on_frame_lost(&mut publisher(), StreamSetFrameSummary::Stream(first));
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
    lent(&mut set).on_frame_delivered(&mut publisher(), StreamSetFrameSummary::Stream(first));
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
        end.sync_intents(&mut TestPublish);
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
    lent(&mut set).on_frame_lost(&mut publisher(), StreamSetFrameSummary::Stream(fin));
    assert!(matches!(
        events().as_slice(),
        [Event::Published(StreamIntent::Stream { .. })]
    ));
    lent(&mut set).on_frame_delivered(&mut publisher(), StreamSetFrameSummary::Stream(fin));
    assert_eq!(part.lock().sender.terminal_state(), None);
    lent(&mut set).on_frame_delivered(
        &mut publisher(),
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
        end.sync_intents(&mut TestPublish);
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
    assert_eq!(events(), [Event::Released(key)]);
    let summary = ResetStreamSummary {
        stream_id: id(1),
        final_size: v(0),
        reliable_size: v(0),
    };
    lent(&mut set).on_frame_lost(
        &mut publisher(),
        StreamSetFrameSummary::ResetStream(summary),
    );
    assert_eq!(
        events(),
        [Event::Published(StreamIntent::ResetStream {
            stream_id: id(1),
            len: 4,
        })]
    );
    lent(&mut set).on_frame_delivered(
        &mut publisher(),
        StreamSetFrameSummary::ResetStream(summary),
    );
    assert_eq!(
        part.lock().sender.terminal_state(),
        Some(SendTerminalState::ResetRecvd)
    );
    assert_eq!(events(), [Event::Withdrawn(key)]);
    // lost after it was acknowledged: nothing more
    lent(&mut set).on_frame_lost(
        &mut publisher(),
        StreamSetFrameSummary::ResetStream(summary),
    );
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
    new_set(
        StreamSetFacts {
            role: Role::Client,
            granted_to_peer,
            granted_by_peer: FlowControlParameters::default(),
            peer_reset_support: (),
        },
        LockedStreamSetConfig::default(),
        NoEvents,
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
    end.sync_intents(id(stream), &mut TestPublish);
}

/// The window of 40 slides by what is read: at 20 bytes read the limit 60
/// is advertised, a frame of 3 bytes; at 24 the limit 64 takes one byte
/// more, and the intent is resized. Written, the limit is open; lost, the
/// limit in effect is sent again.
#[test]
fn a_wider_max_stream_data_resizes_its_intent() {
    let mut set = narrow_window_set();
    lent(&mut set)
        .on_stream_frame(
            &mut publisher(),
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
    assert_eq!(events(), [Event::Released(key)]);
    let part = receiver(&set, 1).expect("built");
    assert_eq!(part.lock().receiver.opened_limit(), v(64));

    lent(&mut set).on_frame_lost(
        &mut publisher(),
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
    lent(&mut set).layer_ended(LayerEnd::ConnectionClosed(CloseReason::IdleTimeout));
    assert_eq!(
        written(&mut set, StreamIntentKey::Stream(id(1)), 100, false),
        []
    );
}

// ---- reclaiming a stream ----

impl<Lc, K, Rs: StreamResets, P> SendingEnd<Lc, K, Rs, P>
where
    K: IntentTicketResize + IntentTicketWithdraw,
    P: Clone + PartialEq + Default + SendUrgency,
{
    /// Send the data waiting and the FIN, if due, as `write_stream` writes
    /// them into packets, but without packets; the summaries of what was
    /// sent, for a test to acknowledge.
    pub(in crate::v1::streams::locked) fn send_all(&mut self) -> Vec<StreamSummary> {
        let stream_id = self.sender.stream_id();
        let mut sent = Vec::new();
        while let Some(selected) = self.sender.select(&AnyActiveLinkPath, usize::MAX) {
            let len = selected.bytes.len();
            let end = VarInt::try_from(selected.offset.get() + len as u64).expect("a short stream");
            let fin = self.fin_due() == Some(end);
            self.sender
                .expose_usage_through(end)
                .expect("selected data is exposed");
            if fin {
                self.fin_exposed();
            }
            sent.push(StreamSummary {
                stream_id,
                offset: selected.offset,
                len,
                fin,
            });
        }
        if let Some(final_size) = self.fin_due() {
            self.fin_exposed();
            sent.push(StreamSummary {
                stream_id,
                offset: final_size,
                len: 0,
                fin: true,
            });
        }
        sent
    }
}

/// Change the receiving part of `stream` as the application's reader does:
/// under the part's lock, bring its intents up to date and mark whether it
/// is done; with the lock let go, reclaim the stream if it is done.
fn as_reader(
    set: &TestSet,
    stream: u32,
    change: impl FnOnce(&mut ReceivingEnd<(), TestTicket, Rfc9000StreamResets, Urgency>),
) {
    let part = receiver(set, stream).expect("built");
    {
        let mut end = part.lock();
        change(&mut end);
        end.sync_intents(id(stream), &mut TestPublish);
        part.note_done(&end);
    }
    set.shared
        .reclaim_if_done(&part, id(stream), &mut TestPublish);
}

/// Change the sending part of `stream` as the application's writer does, as
/// [`as_reader`] the receiving part.
fn as_writer(
    set: &TestSet,
    stream: u32,
    change: impl FnOnce(&mut SendingEnd<(), TestTicket, Rfc9000StreamResets, Urgency>),
) {
    let part = sender(set, stream).expect("built");
    {
        let mut end = part.lock();
        change(&mut end);
        end.sync_intents(&mut TestPublish);
        part.note_done(&end);
    }
    set.shared
        .reclaim_if_done(&part, id(stream), &mut TestPublish);
}

/// Read `stream` to its end, as the application's reader does.
fn read_to_end(set: &TestSet, stream: u32) {
    as_reader(set, stream, |end| {
        loop {
            match end.receiver.read_chunk(core::num::NonZeroUsize::MAX) {
                Ok(sakuya_stream::receive::read::ReadOutcome::Data(_)) => {}
                Ok(sakuya_stream::receive::read::ReadOutcome::End) => break,
                other => panic!("the stream is read to its end: {other:?}"),
            }
        }
    });
}

/// Accept the peer's stream `stream`: it leaves the queue to accept.
fn accept(set: &TestSet, stream: u32) {
    let mut state = lock(&set.shared.set);
    state
        .accept_bidirectional
        .retain(|&queued| queued != id(stream));
    state
        .accept_unidirectional
        .retain(|&queued| queued != id(stream));
}

/// Write `len` bytes into `stream` and close it, as the application's
/// writer does, and send them and the FIN; the summaries of what was sent.
fn answer(set: &TestSet, stream: u32, len: usize) -> Vec<StreamSummary> {
    as_writer(set, stream, |end| {
        end.sender
            .write(&mut Bytes::from(vec![9; len]), &options())
            .expect("within the limits");
        end.sender.close().expect("open");
    });
    let part = sender(set, stream).expect("built");
    let mut end = part.lock();
    let sent = end.send_all();
    end.sync_intents(&mut TestPublish);
    sent
}

/// Acknowledge what `sent` summarizes, as the driver does.
fn acknowledge(set: &mut TestSet, sent: Vec<StreamSummary>) {
    for summary in sent {
        lent(set).on_frame_delivered(&mut publisher(), StreamSetFrameSummary::Stream(summary));
    }
}

fn is_reclaimed(set: &TestSet, stream: u32) -> bool {
    let reclaimed = lock(&set.shared.set).ledger.is_reclaimed(id(stream));
    let in_tables = receiver(set, stream).is_some() || sender(set, stream).is_some();
    assert_eq!(
        reclaimed, !in_tables,
        "stream {stream} leaves the tables when it is reclaimed"
    );
    reclaimed
}

/// The intent of the MAX_STREAMS frame of `directionality` at `limit`.
fn max_streams_intent(directionality: Directionality, limit: u64) -> Event {
    Event::Published(StreamIntent::MaxStreams {
        directionality,
        len: max_streams_frame(directionality, count(limit)).encoded_len(),
    })
}

/// The peer's bidirectional stream 1 carries a request with its end and an
/// answer with its end: once the request is read and the answer
/// acknowledged, the stream is reclaimed, and the peer may open one stream
/// more than the three it was granted (RFC 9000 §4.6). Late frames of the
/// stream are ignored.
#[test]
fn a_peer_stream_is_reclaimed_once_its_request_is_read_and_its_answer_acknowledged() {
    let mut set = client_set();
    lent(&mut set)
        .on_stream_frame(
            &mut publisher(),
            EncryptionLevel::OneRtt,
            stream_frame(1, 4, true),
        )
        .expect("stream 1");
    accept(&set, 1);
    read_to_end(&set, 1);
    assert!(!is_reclaimed(&set, 1), "the answer is not acknowledged");
    let sent = answer(&set, 1, 5);
    events();
    acknowledge(&mut set, sent);
    assert!(is_reclaimed(&set, 1));
    let directionality = Directionality::Bidirectional;
    assert_eq!(events(), [max_streams_intent(directionality, 4)]);
    assert_eq!(
        written(
            &mut set,
            StreamIntentKey::MaxStreams(directionality),
            100,
            false
        ),
        [Read::MaxStreams {
            directionality,
            limit: count(4),
        }]
    );
    events();

    lent(&mut set)
        .on_stream_frame(
            &mut publisher(),
            EncryptionLevel::OneRtt,
            stream_frame(1, 4, true),
        )
        .expect("ignored");
    lent(&mut set)
        .on_stop_sending(&mut publisher(), stop_sending(1))
        .expect("ignored");
    acknowledge(
        &mut set,
        vec![StreamSummary {
            stream_id: id(1),
            offset: v(0),
            len: 5,
            fin: true,
        }],
    );
    assert!(is_reclaimed(&set, 1));
    assert_eq!(events(), []);
    assert!(to_accept(&set, Directionality::Bidirectional).is_empty());
}

/// The other order: the answer is acknowledged first, and the reader's
/// read of the request's end reclaims the stream.
#[test]
fn reading_the_end_after_the_answer_is_acknowledged_reclaims_the_stream() {
    let mut set = client_set();
    lent(&mut set)
        .on_stream_frame(
            &mut publisher(),
            EncryptionLevel::OneRtt,
            stream_frame(1, 4, true),
        )
        .expect("stream 1");
    accept(&set, 1);
    let sent = answer(&set, 1, 5);
    acknowledge(&mut set, sent);
    assert_eq!(
        sender(&set, 1)
            .expect("built")
            .lock()
            .sender
            .terminal_state(),
        Some(SendTerminalState::DataRecvd)
    );
    assert!(
        !is_reclaimed(&set, 1),
        "the request was received but not read"
    );
    events();
    read_to_end(&set, 1);
    assert!(is_reclaimed(&set, 1));
    assert_eq!(
        events(),
        [max_streams_intent(Directionality::Bidirectional, 4)]
    );
}

/// A dropped reader leaves the stream in the tables while its final size
/// is unknown; the frame with the FIN reclaims it.
#[test]
fn a_dropped_reader_waits_for_the_final_size_to_reclaim_the_stream() {
    let mut set = client_set();
    lent(&mut set)
        .on_stream_frame(
            &mut publisher(),
            EncryptionLevel::OneRtt,
            stream_frame(1, 4, false),
        )
        .expect("stream 1");
    accept(&set, 1);
    let sent = answer(&set, 1, 0);
    acknowledge(&mut set, sent);
    as_reader(&set, 1, |end| end.receiver.reader_dropped());
    assert!(
        !is_reclaimed(&set, 1),
        "the peer may still send: the final size is unknown"
    );
    events();
    lent(&mut set)
        .on_stream_frame(
            &mut publisher(),
            EncryptionLevel::OneRtt,
            stream_frame(1, 4, true),
        )
        .expect("the end of stream 1");
    assert!(is_reclaimed(&set, 1));
    assert!(
        events().contains(&max_streams_intent(Directionality::Bidirectional, 4)),
        "the peer may open one more stream"
    );
}

/// A unidirectional stream of the peer has only its receiving part: read
/// to its end, it is reclaimed.
#[test]
fn a_peer_unidirectional_stream_read_to_its_end_is_reclaimed() {
    let mut set = client_set();
    lent(&mut set)
        .on_stream_frame(
            &mut publisher(),
            EncryptionLevel::OneRtt,
            stream_frame(3, 4, true),
        )
        .expect("stream 3");
    accept(&set, 3);
    events();
    read_to_end(&set, 3);
    assert!(is_reclaimed(&set, 3));
    assert_eq!(
        events(),
        [max_streams_intent(Directionality::Unidirectional, 4)]
    );
    assert_eq!(
        lock(&set.shared.set)
            .ledger
            .max_streams(Directionality::Bidirectional),
        None
    );
}

/// The locked set with the reliable stream reset extension.
#[cfg(feature = "reset_stream_at")]
mod reliable {
    use sakuya_stream::{
        reset_stream_at::{receive::OnResetStreamError, send::PeerResetStreamAtSupport},
        stream_end::ResetCodeChangeError,
    };
    use sakuya_wire::reset_stream_at::{ResetStreamAt, ResetStreamAtFrame};

    use super::*;
    use crate::reset_stream_at::{ReliableStreamResets, ResetStreamAtSet};

    type ReliableSet = LockedStreamSet<(), TestTicket, TestPublish, ReliableStreamResets>;

    /// The set `set` as the driver lends it, as [`super::lent`] gives it,
    /// with the extension's frame too.
    fn lent(
        set: &mut ReliableSet,
    ) -> &mut impl ResetStreamAtSet<
        (),
        TestTypes,
        ReliableStreamResets,
        SendParameters = Urgency,
        Handle = LockedStreamSetHandle<(), TestTicket, TestPublish, ReliableStreamResets>,
    > {
        set
    }

    /// A client set as [`client_set`] is, whose peer allows RESET_STREAM_AT
    /// if `peer_allows`.
    fn reliable_client_set(peer_allows: bool) -> ReliableSet {
        let flow = FlowControlParameters {
            initial_max_data: InitialMaxData::new(v(1000)),
            initial_max_stream_data_bidi_local: InitialMaxStreamDataBidiLocal::new(v(100)),
            initial_max_stream_data_bidi_remote: InitialMaxStreamDataBidiRemote::new(v(100)),
            initial_max_stream_data_uni: InitialMaxStreamDataUni::new(v(100)),
            initial_max_streams_bidi: InitialMaxStreamsBidi::new(count(3)),
            initial_max_streams_uni: InitialMaxStreamsUni::new(count(3)),
        };
        new_set(
            StreamSetFacts {
                role: Role::Client,
                granted_to_peer: flow,
                granted_by_peer: flow,
                peer_reset_support: peer_allows
                    .then(|| PeerResetStreamAtSupport::from_peer_parameter(ResetStreamAt)),
            },
            LockedStreamSetConfig::default(),
            NoEvents,
        )
    }

    fn reset_stream_at(
        stream: u32,
        code: u32,
        final_size: u32,
        reliable: u32,
    ) -> ResetStreamAtFrame {
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

    /// RESET_STREAM_AT with code 1, then RESET_STREAM with code 2, on the
    /// peer's stream: the second changes the error code, which the
    /// extension makes a STREAM_STATE_ERROR (draft §5.2).
    #[test]
    fn a_reset_that_changes_the_code_of_a_reset_stream_at_is_a_stream_state_error() {
        let mut set = reliable_client_set(true);
        lent(&mut set)
            .on_reset_stream_at(&mut publisher(), reset_stream_at(1, 1, 10, 4))
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

    /// RESET_STREAM_AT names a stream as RESET_STREAM does: one of this
    /// side's not opened yet is a STREAM_STATE_ERROR.
    #[test]
    fn a_reset_stream_at_of_a_stream_not_opened_is_a_stream_state_error() {
        let mut set = reliable_client_set(true);
        let error = lent(&mut set)
            .on_reset_stream_at(&mut publisher(), reset_stream_at(0, 1, 10, 4))
            .expect_err("stream 0 is not open");
        assert!(matches!(
            error,
            StreamSetFrameError::ReceivingPartFrame { .. }
        ));
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::STREAM_STATE_ERROR
        );
    }

    /// Open the peer's stream 1 and write `len` bytes into its sending
    /// part; the events of that are forgotten.
    fn written_peer_stream(
        set: &mut ReliableSet,
        len: usize,
    ) -> SendingPart<(), TestTicket, ReliableStreamResets, Urgency> {
        lent(set)
            .on_stream_frame(
                &mut publisher(),
                EncryptionLevel::OneRtt,
                stream_frame(1, 1, false),
            )
            .expect("stream 1");
        let part = lock(&set.shared.set)
            .senders
            .get(&id(1))
            .cloned()
            .expect("built");
        {
            let mut end = part.lock();
            end.sender
                .write(&mut Bytes::from(vec![9; len]), &options())
                .expect("within the limits");
            end.sync_intents(&mut TestPublish);
        }
        events();
        part
    }

    /// A reset at a reliable size writes RESET_STREAM_AT; its
    /// acknowledgment and that of the data below the reliable size end the
    /// sending part in "Data Recvd" (draft §5.3), and a later frame with a
    /// lower reliable size has to be acknowledged in its turn.
    #[test]
    fn a_reset_at_a_reliable_size_ends_once_its_frame_and_prefix_are_acknowledged() {
        let mut set = reliable_client_set(true);
        let part = written_peer_stream(&mut set, 10);
        let support = PeerResetStreamAtSupport::from_peer_parameter(ResetStreamAt);
        {
            let mut end = part.lock();
            end.sender
                .reset_at(support, ApplicationErrorCode::new(v(3)), v(6))
                .expect("not done");
            end.sync_intents(&mut TestPublish);
        }
        events();
        let reset = StreamIntentKey::ResetStream(id(1));
        let data = StreamIntentKey::Stream(id(1));
        assert_eq!(
            written(&mut set, data, 100, false),
            [Read::Stream {
                stream: id(1),
                offset: v(0),
                len: 6,
                fin: false,
            }]
        );
        assert_eq!(
            written(&mut set, reset, 100, false),
            [Read::ResetStreamAt {
                stream: id(1),
                final_size: v(6),
                reliable_size: v(6),
            }]
        );
        // the reliable size is lowered before anything is acknowledged:
        // its frame is due again
        {
            let mut end = part.lock();
            end.sender
                .reset_at(support, ApplicationErrorCode::new(v(3)), v(2))
                .expect("lower");
            end.sync_intents(&mut TestPublish);
        }
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
        // the frame of the earlier, larger reliable size is not the one
        // in effect
        lent(&mut set).on_frame_delivered(&mut publisher(), summary(6));
        assert_eq!(part.lock().sender.terminal_state(), None);
        assert_eq!(
            written(&mut set, reset, 100, false),
            [Read::ResetStreamAt {
                stream: id(1),
                final_size: v(6),
                reliable_size: v(2),
            }]
        );
        lent(&mut set).on_frame_delivered(&mut publisher(), summary(2));
        assert_eq!(
            part.lock().sender.terminal_state(),
            Some(SendTerminalState::DataRecvd)
        );
    }
}
