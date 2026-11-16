use std::{
    pin::pin,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    task::Wake,
    thread,
    time::Duration,
};

use bytes::Bytes;
use nitori_io::{ReadChunkHostExt as _, calls::WriteAllHostExt as _};
use sakuya_stream::{connection::CloseReason, send_options::urgency::Urgency};
use sakuya_wire::{
    v1::{
        encryption_level::EncryptionLevel,
        frame::{
            max_data::MaxDataFrame, max_stream_data::MaxStreamDataFrame,
            max_streams::MaxStreamsFrame, stream::StreamFrame,
        },
        role::Role,
        stream_count::StreamCount,
        transport_parameters::integer::{
            InitialMaxData, InitialMaxStreamDataBidiLocal, InitialMaxStreamDataBidiRemote,
            InitialMaxStreamDataUni, InitialMaxStreamsBidi, InitialMaxStreamsUni,
        },
    },
    var_int::VarIntField,
};

use super::*;
use crate::{
    send_strategy::{IntakeSendIntentHandle, MinimumLengths, PublishOutcome, SendIntent},
    v1::streams::{
        FlowControlParameters, StreamSet, StreamSetFacts,
        locked::{LockedStreamSet, LockedStreamSetConfig},
        resets::Rfc9000StreamResets,
        send::StreamIntentKey,
    },
};

// ---- an intake that records what is published ----

/// A ticket that does nothing.
#[derive(Debug)]
struct Ticket;

impl IntentTicketResize for Ticket {
    fn resize(&mut self, _: MinimumLengths) {}
}

impl IntentTicketWithdraw for Ticket {
    type Report = ();

    fn withdraw(self) {}
}

/// An intake that records the keys of the intents published through it, by
/// any thread.
#[derive(Debug, Clone, Default)]
struct Intake {
    published: Arc<Mutex<Vec<StreamIntentKey>>>,
}

impl Intake {
    /// The keys published since the last call.
    fn published(&self) -> Vec<StreamIntentKey> {
        core::mem::take(&mut *self.published.lock().expect("not poisoned"))
    }
}

impl PublishOutcome<StreamIntent<Urgency>, AnyActiveLinkPath> for Intake {
    type Outcome = Ticket;
}

impl SharedPublishTo<StreamIntent<Urgency>, AnyActiveLinkPath, ()> for Intake {
    fn publish_to(&self, intent: StreamIntent<Urgency>, _: AnyActiveLinkPath) -> Ticket {
        self.published
            .lock()
            .expect("not poisoned")
            .push(intent.key());
        Ticket
    }
}

impl SendIntentIntake<AnyActiveLinkPath> for Intake {
    type Handle<J: SendIntent, Idx>
        = IntakeSendIntentHandle<Self, J, Idx>
    where
        Self: SharedPublishTo<J, AnyActiveLinkPath, Idx>;

    fn handle<J: SendIntent, Idx>(&self) -> IntakeSendIntentHandle<Self, J, Idx>
    where
        Self: SharedPublishTo<J, AnyActiveLinkPath, Idx>,
    {
        IntakeSendIntentHandle::new(self.clone())
    }
}

type Set = LockedStreamSet<(), Ticket, Rfc9000StreamResets>;
type Layer = EstablishedLayerHandle<
    LockedStreamSetHandle<(), Ticket, Rfc9000StreamResets, Urgency>,
    Intake,
    (),
    (),
>;
type Publish = IntakeSendIntentHandle<Intake, StreamIntent<Urgency>, ()>;

/// A client's set and the handle of its layer: the server, the peer, grants
/// the client two streams of each type, `stream` bytes of each stream and
/// `connection` bytes of the connection; the client grants the server
/// three streams of each type and 1000 bytes of each stream and of the
/// connection.
fn client(stream: u32, connection: u32) -> (Set, Layer, Intake, Publish) {
    client_receiving(stream, connection, 1000)
}

/// As [`client`], with `receive` bytes the client grants of each stream and
/// of the connection.
fn client_receiving(stream: u32, connection: u32, receive: u32) -> (Set, Layer, Intake, Publish) {
    let granted_to_peer = FlowControlParameters {
        initial_max_data: InitialMaxData::new(v(receive)),
        initial_max_stream_data_bidi_local: InitialMaxStreamDataBidiLocal::new(v(receive)),
        initial_max_stream_data_bidi_remote: InitialMaxStreamDataBidiRemote::new(v(receive)),
        initial_max_stream_data_uni: InitialMaxStreamDataUni::new(v(receive)),
        initial_max_streams_bidi: InitialMaxStreamsBidi::new(count(3)),
        initial_max_streams_uni: InitialMaxStreamsUni::new(count(3)),
    };
    let granted_by_peer = FlowControlParameters {
        initial_max_data: InitialMaxData::new(v(connection)),
        initial_max_stream_data_bidi_local: InitialMaxStreamDataBidiLocal::new(v(stream)),
        initial_max_stream_data_bidi_remote: InitialMaxStreamDataBidiRemote::new(v(stream)),
        initial_max_stream_data_uni: InitialMaxStreamDataUni::new(v(stream)),
        initial_max_streams_bidi: InitialMaxStreamsBidi::new(count(2)),
        initial_max_streams_uni: InitialMaxStreamsUni::new(count(2)),
    };
    let set = Set::new(
        StreamSetFacts {
            role: Role::Client,
            granted_to_peer,
            granted_by_peer,
        },
        LockedStreamSetConfig::default(),
    );
    let intake = Intake::default();
    let layer = EstablishedLayerHandle::new(set.handle(), intake.clone(), ());
    let publish = intake.handle::<StreamIntent<Urgency>, ()>();
    (set, layer, intake, publish)
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

/// A STREAM frame of `stream` with `len` bytes at `offset`.
fn stream_frame(stream: u32, offset: u32, len: usize) -> StreamFrame<Bytes> {
    let offset = (offset > 0).then(|| VarIntField::shortest(v(offset)));
    StreamFrame::new(
        VarIntField::shortest(id(stream)),
        offset,
        Bytes::from(vec![7; len]),
        false,
    )
    .expect("a short frame")
    .into_without_length()
    .into()
}

fn max_streams(directionality: Directionality, maximum: u64) -> MaxStreamsFrame {
    MaxStreamsFrame::new(directionality, VarIntField::shortest(count(maximum)))
}

fn max_stream_data(stream: u32, maximum: u32) -> MaxStreamDataFrame {
    MaxStreamDataFrame::new(
        VarIntField::shortest(id(stream)),
        VarIntField::shortest(v(maximum)),
    )
}

fn max_data(maximum: u32) -> MaxDataFrame {
    MaxDataFrame::new(VarIntField::shortest(v(maximum)))
}

#[derive(Default)]
struct Wakes(AtomicUsize);

impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl Wakes {
    fn count(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

fn counting() -> (Arc<Wakes>, Waker) {
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(Arc::clone(&wakes));
    (wakes, waker)
}

fn poll_once<F: Future>(future: Pin<&mut F>, waker: &Waker) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(waker))
}

/// The output of a future that is ready at once.
fn now<F: Future>(future: F) -> F::Output {
    match poll_once(pin!(future), Waker::noop()) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("not ready"),
    }
}

/// A waker that unparks the thread that made it.
struct Unpark(thread::Thread);

impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

/// Run `future` to its end on this thread.
fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::from(Arc::new(Unpark(thread::current())));
    let mut future = pin!(future);
    loop {
        match poll_once(future.as_mut(), &waker) {
            Poll::Ready(output) => return output,
            Poll::Pending => thread::park_timeout(Duration::from_millis(50)),
        }
    }
}

type Writer = StreamWriter<
    LockedStreamSendShare<(), Ticket, Rfc9000StreamResets, Urgency, Publish>,
    SendOptions<Urgency, AnyActiveLinkPath>,
>;

/// Write `input` once through `writer`, with its own options.
fn poll_write(writer: &mut Writer, input: &mut Bytes, waker: &Waker) -> Poll<usize> {
    let mut cx = Context::from_waker(waker);
    let options = *writer.send_options_mut();
    match writer.poll_write_with(&mut cx, input, options.parameters(), options.destination()) {
        Poll::Ready(Ok(report)) => Poll::Ready(report.new_bytes.get() as usize),
        Poll::Ready(Err(error)) => panic!("the write fails: {error:?}"),
        Poll::Pending => Poll::Pending,
    }
}

fn idle_end() -> LayerEnd<()> {
    LayerEnd::ConnectionClosed(CloseReason::IdleTimeout)
}

// ---- the tests ----

#[test]
fn opening_at_the_limit_waits_and_asks_for_more_until_max_streams() {
    let (mut set, layer, intake, publish) = client(100, 1000);
    let _first = layer.try_open_bi().expect("the first of two");
    let _second = layer.try_open_bi().expect("the second of two");
    intake.published();
    assert!(matches!(
        layer.try_open_bi(),
        Err(TryOpenStreamError::AtLimit)
    ));
    let (wakes, waker) = counting();
    let mut open = pin!(layer.open_bi());
    assert!(poll_once(open.as_mut(), &waker).is_pending());
    assert!(
        intake
            .published()
            .contains(&StreamIntentKey::StreamsBlocked(
                Directionality::Bidirectional
            )),
        "STREAMS_BLOCKED is wanted at the limit"
    );
    set.on_max_streams(&publish, max_streams(Directionality::Unidirectional, 5))
        .expect("taken");
    assert_eq!(wakes.count(), 0, "another type's limit wakes nothing");
    set.on_max_streams(&publish, max_streams(Directionality::Bidirectional, 3))
        .expect("taken");
    assert_eq!(wakes.count(), 1);
    let Poll::Ready(Ok((writer, _reader))) = poll_once(open.as_mut(), &waker) else {
        panic!("the third stream opens");
    };
    assert_eq!(writer.share.part.lock().sender.stream_id(), id(8));
}

#[test]
fn accepting_waits_for_the_first_frame_of_a_stream_of_the_peer() {
    let (mut set, layer, _intake, publish) = client(100, 1000);
    let (wakes, waker) = counting();
    let mut accept = pin!(layer.accept_bi());
    assert!(poll_once(accept.as_mut(), &waker).is_pending());
    set.on_stream_frame(&publish, EncryptionLevel::OneRtt, stream_frame(1, 0, 5))
        .expect("taken");
    assert_eq!(wakes.count(), 1);
    let Poll::Ready(Ok((_writer, mut reader))) = poll_once(accept.as_mut(), &waker) else {
        panic!("the peer's stream is accepted");
    };
    let chunk = now(reader.read_chunk_unpin(NonZeroUsize::new(16).expect("not zero")))
        .expect("read")
        .expect("data");
    assert_eq!(chunk, Bytes::from(vec![7; 5]));
}

#[test]
fn a_write_at_the_stream_limit_waits_for_max_stream_data() {
    let (mut set, layer, intake, publish) = client(40, 1000);
    let (writer, _reader) = layer.try_open_bi().expect("a stream");
    let mut writer = writer.with_send_options(Urgency::default(), AnyActiveLinkPath);
    let (wakes, waker) = counting();
    let mut input = Bytes::from(vec![1; 100]);
    assert_eq!(poll_write(&mut writer, &mut input, &waker), Poll::Ready(40));
    assert!(poll_write(&mut writer, &mut input, &waker).is_pending());
    assert!(
        intake
            .published()
            .contains(&StreamIntentKey::StreamDataBlocked(id(0))),
        "STREAM_DATA_BLOCKED is wanted once the limit held a write back"
    );
    set.on_max_stream_data(&publish, max_stream_data(0, 100))
        .expect("taken");
    assert_eq!(wakes.count(), 1);
    assert_eq!(poll_write(&mut writer, &mut input, &waker), Poll::Ready(60));
}

#[test]
fn a_write_without_connection_credit_waits_for_max_data() {
    let (mut set, layer, intake, publish) = client(1000, 30);
    let (writer, _reader) = layer.try_open_bi().expect("a stream");
    let mut writer = writer.with_send_options(Urgency::default(), AnyActiveLinkPath);
    let (wakes, waker) = counting();
    let mut input = Bytes::from(vec![1; 50]);
    assert_eq!(poll_write(&mut writer, &mut input, &waker), Poll::Ready(30));
    intake.published();
    assert!(poll_write(&mut writer, &mut input, &waker).is_pending());
    assert!(
        intake.published().contains(&StreamIntentKey::DataBlocked),
        "DATA_BLOCKED is wanted at the connection's limit"
    );
    set.on_max_data(&publish, max_data(60)).expect("taken");
    assert_eq!(wakes.count(), 1);
    assert_eq!(poll_write(&mut writer, &mut input, &waker), Poll::Ready(20));
}

#[test]
fn a_read_without_data_waits_for_a_stream_frame() {
    let (mut set, layer, intake, publish) = client(100, 1000);
    let (_writer, mut reader) = layer.try_open_bi().expect("a stream");
    let (wakes, waker) = counting();
    let maximum = NonZeroUsize::new(64).expect("not zero");
    let mut cx = Context::from_waker(&waker);
    assert!(reader.share.poll_read_chunk(&mut cx, maximum).is_pending());
    set.on_stream_frame(&publish, EncryptionLevel::OneRtt, stream_frame(0, 0, 900))
        .expect("taken");
    assert_eq!(wakes.count(), 1);
    intake.published();
    let mut read = 0;
    while let Poll::Ready(chunk) = reader.share.poll_read_chunk(&mut cx, maximum) {
        read += chunk.expect("read").expect("data").len();
    }
    assert_eq!(read, 900);
    let published = intake.published();
    assert!(
        published.contains(&StreamIntentKey::MaxStreamData(id(0)))
            && published.contains(&StreamIntentKey::MaxData),
        "what was read is advertised again: {published:?}"
    );
}

#[test]
fn every_wait_ends_with_the_same_end_of_the_layer() {
    let (mut set, layer, _intake, _publish) = client(10, 1000);
    let (writer, mut reader) = layer.try_open_bi().expect("a stream");
    let mut writer = writer.with_send_options(Urgency::default(), AnyActiveLinkPath);
    let _second = layer.try_open_bi().expect("the second of two");
    let (wakes, waker) = counting();
    let mut open = pin!(layer.open_bi());
    let mut accept = pin!(layer.accept_uni());
    let mut ended = pin!(layer.ended());
    let mut input = Bytes::from(vec![1; 20]);
    assert_eq!(poll_write(&mut writer, &mut input, &waker), Poll::Ready(10));
    assert!(poll_write(&mut writer, &mut input, &waker).is_pending());
    let maximum = NonZeroUsize::new(64).expect("not zero");
    let mut cx = Context::from_waker(&waker);
    assert!(reader.share.poll_read_chunk(&mut cx, maximum).is_pending());
    assert!(poll_once(open.as_mut(), &waker).is_pending());
    assert!(poll_once(accept.as_mut(), &waker).is_pending());
    assert!(poll_once(ended.as_mut(), &waker).is_pending());

    set.layer_ended(idle_end());
    layer.layer.end(idle_end());
    assert_eq!(
        wakes.count(),
        5,
        "the writer, the reader, open, accept, ended"
    );
    let expected = LayerEndedError::new(idle_end());
    assert!(matches!(
        poll_once(open.as_mut(), &waker),
        Poll::Ready(Err(error)) if error == expected
    ));
    assert!(matches!(
        poll_once(accept.as_mut(), &waker),
        Poll::Ready(Err(error)) if error == expected
    ));
    assert_eq!(poll_once(ended.as_mut(), &waker), Poll::Ready(idle_end()));
    let options = *writer.send_options_mut();
    assert!(matches!(
        writer.poll_write_with(&mut cx, &mut input, options.parameters(), options.destination()),
        Poll::Ready(Err(WriteError::LayerEnded { source })) if source == expected
    ));
    assert!(matches!(
        reader.share.poll_read_chunk(&mut cx, maximum),
        Poll::Ready(Err(ReadError::LayerEnded { source })) if source == expected
    ));
    assert!(matches!(
        now(writer.all_acknowledged()),
        Err(AllAcknowledgedError::LayerEnded { source }) if source == expected
    ));
}

#[test]
fn write_all_writes_through_a_borrowed_writer_with_other_options() {
    let (_set, layer, _intake, _publish) = client(1000, 1000);
    let (writer, _reader) = layer.try_open_bi().expect("a stream");
    let mut writer = writer.with_send_options(Urgency::default(), AnyActiveLinkPath);
    {
        let mut borrowed = writer
            .borrow_with_send_options(Urgency::new(1).expect("an urgency"), AnyActiveLinkPath);
        now(borrowed.write_all_unpin(Bytes::from_static(b"head"))).expect("written");
    }
    now(writer.write_all_unpin(Bytes::from_static(b"body"))).expect("written");
    now(writer.flush()).expect("flushed");
    let sender = &writer.share.part.lock().sender;
    assert_eq!(sender.written_end(), v(8));
}

#[test]
fn a_writer_without_options_writes_with_the_defaults() {
    let (_set, layer, _intake, _publish) = client(1000, 1000);
    let mut writer = layer.try_open_uni().expect("a stream");
    now(writer.write_all_unpin(Bytes::from_static(b"data"))).expect("written");
    assert_eq!(writer.share.part.lock().sender.written_end(), v(4));
}

#[test]
fn dropping_the_handles_gives_the_parts_up() {
    let (_set, layer, intake, _publish) = client(1000, 1000);
    let (writer, reader) = layer.try_open_bi().expect("a stream");
    intake.published();
    drop(reader);
    assert!(
        intake
            .published()
            .contains(&StreamIntentKey::StopSending(id(0))),
        "a dropped reader asks the peer to stop"
    );
    drop(writer);
    assert!(
        intake
            .published()
            .contains(&StreamIntentKey::ResetStream(id(0))),
        "an abandoned writer resets the stream"
    );
}

#[test]
fn stop_and_reset_have_their_frames_sent() {
    let (_set, layer, intake, _publish) = client(1000, 1000);
    let (mut writer, mut reader) = layer.try_open_bi().expect("a stream");
    intake.published();
    let code = ApplicationErrorCode::new(v(9));
    reader.stop(code).expect("stopped");
    assert!(
        intake
            .published()
            .contains(&StreamIntentKey::StopSending(id(0)))
    );
    writer.reset(code).expect("reset");
    assert!(
        intake
            .published()
            .contains(&StreamIntentKey::ResetStream(id(0)))
    );
    assert!(matches!(
        now(writer.all_acknowledged()),
        Err(AllAcknowledgedError::Reset { .. })
    ));
}

/// A writer on one stream and a reader on another, each on its own thread,
/// while the driver's side takes frames of a third stream and of the
/// reader's: none waits on the others for good.
#[test]
fn the_application_and_the_driver_take_the_locks_without_deadlock() {
    const ROUNDS: u32 = 200;
    const LEN: usize = 10;
    let (mut set, layer, _intake, publish) = client_receiving(1_000_000, 1_000_000, 1_000_000);
    let (writer, _) = layer.try_open_bi().expect("stream 0");
    let (_, mut reader) = layer.try_open_bi().expect("stream 4");
    let mut writer = writer.with_send_options(Urgency::default(), AnyActiveLinkPath);
    let (done, finished) = mpsc::channel();
    let writing = {
        let done = done.clone();
        thread::spawn(move || {
            for _ in 0..ROUNDS {
                block_on(writer.write_all_unpin(Bytes::from(vec![1; LEN]))).expect("written");
            }
            done.send("writer").expect("the test waits");
        })
    };
    let reading = thread::spawn(move || {
        let mut read = 0;
        while read < ROUNDS as usize * LEN {
            let chunk = block_on(reader.read_chunk_unpin(NonZeroUsize::new(64).expect("not zero")))
                .expect("read")
                .expect("data");
            read += chunk.len();
        }
        done.send("reader").expect("the test waits");
    });
    for round in 0..ROUNDS {
        let offset = round * LEN as u32;
        set.on_stream_frame(
            &publish,
            EncryptionLevel::OneRtt,
            stream_frame(4, offset, LEN),
        )
        .expect("stream 4");
        set.on_stream_frame(
            &publish,
            EncryptionLevel::OneRtt,
            stream_frame(1, offset, LEN),
        )
        .expect("stream 1");
        set.on_max_stream_data(&publish, max_stream_data(0, 1_000_000 + round))
            .expect("stream 0");
    }
    for _ in 0..2 {
        finished
            .recv_timeout(Duration::from_secs(20))
            .expect("both threads finish");
    }
    writing.join().expect("the writer");
    reading.join().expect("the reader");
}

#[test]
fn an_owned_accept_goes_to_another_thread() {
    use crate::v1::application_handles::established_layer::AcceptStreamsOwned as _;
    let (mut set, layer, _intake, publish) = client(100, 1000);
    let accept = layer.accept_uni_owned();
    drop(layer);
    let accepting = thread::spawn(move || block_on(accept).map(|reader| reader.share.stream_id));
    set.on_stream_frame(&publish, EncryptionLevel::OneRtt, stream_frame(3, 0, 4))
        .expect("taken");
    let accepted = accepting.join().expect("the accepting thread");
    assert_eq!(accepted.expect("accepted"), id(3));
}
