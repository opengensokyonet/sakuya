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
use sakuya_stream_v1::resets::Rfc9000StreamResets;
use sakuya_stream_v1::{connection::CloseReason, send_options::urgency::Urgency};
use sakuya_wire::var_int::VarIntField;
use sakuya_wire_v1::{
    encryption_level::EncryptionLevel,
    frame::{
        max_data::MaxDataFrame, max_stream_data::MaxStreamDataFrame, max_streams::MaxStreamsFrame,
        stream::StreamFrame,
    },
    role::Role,
    stream_count::StreamCount,
    transport_parameters::integer::{
        InitialMaxData, InitialMaxStreamDataBidiLocal, InitialMaxStreamDataBidiRemote,
        InitialMaxStreamDataUni, InitialMaxStreamsBidi, InitialMaxStreamsUni,
    },
};

use super::super::tests::{TestPublisher, TestTypes, lent, publisher};
use super::*;
use crate::v1::events::{
    DataLocation, DataMovedAdditionalInfo, StreamDataMoved, StreamStateChange,
};
use crate::{
    send_strategy::{IntentTicketResize, IntentTicketWithdraw, MinimumLengths},
    v1::streams::{
        FlowControlParameters, StreamSet, StreamSetFacts,
        locked::{LockedStreamSet, LockedStreamSetConfig},
        send::{StreamIntentKey, StreamSetFrameSummary, StreamSummary},
    },
};
use sakuya_stream_v1::send::SendStreamState;
use sakuya_stream_v1::{
    receive::{ReceiveStreamState, read::ReadError},
    send::SendTerminalState,
};

// ---- a handle that records what is published ----

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

/// A handle of an intake that records the keys of the intents published
/// through it, by any thread; its clones share the record.
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

impl IntentPublisher<StreamIntent<Urgency>, AnyActiveLinkPath> for Intake {
    type Ticket = Ticket;

    fn publish_to(&mut self, intent: StreamIntent<Urgency>, _: AnyActiveLinkPath) -> Ticket {
        self.published
            .lock()
            .expect("not poisoned")
            .push(intent.key());
        Ticket
    }

    fn resize(&mut self, ticket: &mut Ticket, min: MinimumLengths) {
        ticket.resize(min);
    }

    fn withdraw(&mut self, ticket: Ticket) {
        ticket.withdraw();
    }

    fn release_written(&mut self, _: Ticket) {}

    fn waits_too_large(&self, _: &Ticket) -> bool {
        false
    }
}

/// The set that gives its events through `E`.
type SetOf<E> = LockedStreamSet<(), Ticket, Intake, Rfc9000StreamResets, Urgency, E>;
type Set = SetOf<NoEvents>;
/// What opens and accepts the streams of a set that gives its events
/// through `E`, as the handle of its layer does once it is lent the set:
/// the set's handle, on the side of the selection `A`.
struct LayerWith<A, E> {
    set: LockedStreamSetHandle<(), Ticket, Intake, Rfc9000StreamResets, Urgency, E>,
    side: PhantomData<fn() -> A>,
}
/// What opens and accepts the streams of a set that gives no events.
type LayerOf<A> = LayerWith<A, NoEvents>;
/// A client's.
type Layer = LayerOf<Option<nitori_tls::extension::alpn::ProtocolName<Bytes>>>;
/// A server's.
type ServerLayer = LayerOf<nitori_tls::server::targets::SelectedTarget<()>>;
/// The strategy's publisher the tests lend the sets.
type Publish = TestPublisher;
/// A writer of the tests' sets.
type TestWriter<E> = WriterOf<(), Ticket, Rfc9000StreamResets, Urgency, Intake, E>;
/// A reader of the tests' sets, on the side of the selection `A`.
type TestReader<A, E> =
    ReaderOf<(), Ticket, Rfc9000StreamResets, Urgency, Intake, <A as LayerSelection>::Role, E>;

/// The operations of the capabilities, on the set's handle.
#[allow(clippy::type_complexity)] // a writer and a reader
impl<A: LayerSelection, E: SharedEvents> LayerWith<A, E> {
    fn open_bi(
        &self,
    ) -> impl Future<Output = Result<(TestWriter<E>, TestReader<A, E>), LayerEndedError<()>>> + '_
    {
        poll_fn(move |cx| waited(open_bi_now(&self.set.shared, Some(cx.waker()))))
    }

    fn try_open_bi(&self) -> Result<(TestWriter<E>, TestReader<A, E>), TryOpenStreamError<()>> {
        tried(open_bi_now(&self.set.shared, None))
    }

    fn try_open_uni(&self) -> Result<TestWriter<E>, TryOpenStreamError<()>> {
        tried(open_uni_now::<_, _, _, _, _, A::Role, _>(
            &self.set.shared,
            None,
        ))
    }

    fn accept_bi(
        &self,
    ) -> impl Future<Output = Result<(TestWriter<E>, TestReader<A, E>), LayerEndedError<()>>> + '_
    {
        poll_fn(move |cx| poll_accept_bi(&self.set.shared, cx))
    }

    fn accept_uni(
        &self,
    ) -> impl Future<Output = Result<TestReader<A, E>, LayerEndedError<()>>> + '_ {
        poll_fn(move |cx| poll_accept_uni(&self.set.shared, cx))
    }

    /// As [`accept_uni`](Self::accept_uni), with a future that holds what
    /// it needs.
    fn accept_uni_owned(
        &self,
    ) -> impl Future<Output = Result<TestReader<A, E>, LayerEndedError<()>>> + 'static
    where
        A: 'static,
        E: 'static,
    {
        let set = self.set.clone();
        poll_fn(move |cx| poll_accept_uni(&set.shared, cx))
    }
}

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
    made(Role::Client, None, stream, connection, receive)
}

/// A server's set and the handle of its layer, as [`client`] with the
/// sides swapped.
fn server(stream: u32, connection: u32) -> (Set, ServerLayer, Intake, Publish) {
    let selected = nitori_tls::server::targets::SelectedTarget {
        target: (),
        application_protocol: None,
    };
    made(Role::Server, selected, stream, connection, 1000)
}

/// The set of `role` and the handle of its layer, running with `selection`,
/// as [`client_receiving`] describes them.
fn made<A>(
    role: Role,
    selection: A,
    stream: u32,
    connection: u32,
    receive: u32,
) -> (Set, LayerOf<A>, Intake, Publish) {
    made_with(role, selection, stream, connection, receive, NoEvents)
}

/// As [`made`], with a set that gives its events through `events`.
fn made_with<A, E: SharedEvents + Clone + 'static>(
    role: Role,
    selection: A,
    stream: u32,
    connection: u32,
    receive: u32,
    events: E,
) -> (SetOf<E>, LayerWith<A, E>, Intake, Publish) {
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
    let intake = Intake::default();
    let mut set = <SetOf<E> as StreamSet<(), TestTypes, Rfc9000StreamResets>>::new(
        StreamSetFacts {
            role,
            granted_to_peer,
            granted_by_peer,
            peer_reset_support: (),
        },
        LockedStreamSetConfig::default(),
        events,
        intake.clone(),
    );
    let _ = selection;
    let layer = LayerWith {
        set: lent(&mut set).handle(),
        side: PhantomData,
    };
    (set, layer, intake, publisher())
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
    LockedStreamSendShare<(), Ticket, Rfc9000StreamResets, Urgency, Intake>,
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
    let (mut set, layer, intake, mut publish) = client(100, 1000);
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
    lent(&mut set)
        .on_max_streams(&mut publish, max_streams(Directionality::Unidirectional, 5))
        .expect("taken");
    assert_eq!(wakes.count(), 0, "another type's limit wakes nothing");
    lent(&mut set)
        .on_max_streams(&mut publish, max_streams(Directionality::Bidirectional, 3))
        .expect("taken");
    assert_eq!(wakes.count(), 1);
    let Poll::Ready(Ok((writer, _reader))) = poll_once(open.as_mut(), &waker) else {
        panic!("the third stream opens");
    };
    assert_eq!(writer.share.part.lock().sender.stream_id(), id(8));
}

#[test]
fn accepting_waits_for_the_first_frame_of_a_stream_of_the_peer() {
    let (mut set, layer, _intake, mut publish) = client(100, 1000);
    let (wakes, waker) = counting();
    let mut accept = pin!(layer.accept_bi());
    assert!(poll_once(accept.as_mut(), &waker).is_pending());
    lent(&mut set)
        .on_stream_frame(&mut publish, EncryptionLevel::OneRtt, stream_frame(1, 0, 5))
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
    let (mut set, layer, intake, mut publish) = client(40, 1000);
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
    lent(&mut set)
        .on_max_stream_data(&mut publish, max_stream_data(0, 100))
        .expect("taken");
    assert_eq!(wakes.count(), 1);
    assert_eq!(poll_write(&mut writer, &mut input, &waker), Poll::Ready(60));
}

#[test]
fn a_write_without_connection_credit_waits_for_max_data() {
    let (mut set, layer, intake, mut publish) = client(1000, 30);
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
    lent(&mut set)
        .on_max_data(&mut publish, max_data(60))
        .expect("taken");
    assert_eq!(wakes.count(), 1);
    assert_eq!(poll_write(&mut writer, &mut input, &waker), Poll::Ready(20));
}

/// Two readers of one stream, holders of a shared credential, wait for
/// data at once: the data wakes both, not only the one that waited last.
#[test]
fn every_holder_that_waits_is_woken() {
    let (mut set, layer, _intake, mut publish) = client(100, 1000);
    let (_writer, reader) = layer.try_open_bi().expect("a stream");
    let first = reader.into_shared::<Arc<StreamReaderCredential>>();
    let second = first.clone();
    let maximum = NonZeroUsize::new(64).expect("not zero");
    let (first_wakes, first_waker) = counting();
    let (second_wakes, second_waker) = counting();
    for (reader, waker) in [(&first, &first_waker), (&second, &second_waker)] {
        let mut cx = Context::from_waker(waker);
        assert!(
            reader
                .share
                .access()
                .poll_read_chunk(&mut cx, maximum)
                .is_pending()
        );
    }
    lent(&mut set)
        .on_stream_frame(
            &mut publish,
            EncryptionLevel::OneRtt,
            stream_frame(0, 0, 10),
        )
        .expect("taken");
    assert_eq!((first_wakes.count(), second_wakes.count()), (1, 1));
}

#[test]
fn a_read_without_data_waits_for_a_stream_frame() {
    let (mut set, layer, intake, mut publish) = client(100, 1000);
    let (_writer, reader) = layer.try_open_bi().expect("a stream");
    let (wakes, waker) = counting();
    let maximum = NonZeroUsize::new(64).expect("not zero");
    let mut cx = Context::from_waker(&waker);
    assert!(
        reader
            .share
            .access()
            .poll_read_chunk(&mut cx, maximum)
            .is_pending()
    );
    lent(&mut set)
        .on_stream_frame(
            &mut publish,
            EncryptionLevel::OneRtt,
            stream_frame(0, 0, 900),
        )
        .expect("taken");
    assert_eq!(wakes.count(), 1);
    intake.published();
    let mut read = 0;
    while let Poll::Ready(chunk) = reader.share.access().poll_read_chunk(&mut cx, maximum) {
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
    let (writer, reader) = layer.try_open_bi().expect("a stream");
    let mut writer = writer.with_send_options(Urgency::default(), AnyActiveLinkPath);
    let _second = layer.try_open_bi().expect("the second of two");
    let (wakes, waker) = counting();
    let mut open = pin!(layer.open_bi());
    let mut accept = pin!(layer.accept_uni());
    let mut input = Bytes::from(vec![1; 20]);
    assert_eq!(poll_write(&mut writer, &mut input, &waker), Poll::Ready(10));
    assert!(poll_write(&mut writer, &mut input, &waker).is_pending());
    let maximum = NonZeroUsize::new(64).expect("not zero");
    let mut cx = Context::from_waker(&waker);
    assert!(
        reader
            .share
            .access()
            .poll_read_chunk(&mut cx, maximum)
            .is_pending()
    );
    assert!(poll_once(open.as_mut(), &waker).is_pending());
    assert!(poll_once(accept.as_mut(), &waker).is_pending());

    lent(&mut set).layer_ended(&mut publisher(), idle_end());
    assert_eq!(wakes.count(), 4, "the writer, the reader, open, accept");
    let expected = LayerEndedError::new(idle_end());
    assert!(matches!(
        poll_once(open.as_mut(), &waker),
        Poll::Ready(Err(error)) if error == expected
    ));
    assert!(matches!(
        poll_once(accept.as_mut(), &waker),
        Poll::Ready(Err(error)) if error == expected
    ));
    let options = *writer.send_options_mut();
    assert!(matches!(
        writer.poll_write_with(&mut cx, &mut input, options.parameters(), options.destination()),
        Poll::Ready(Err(WriteError::LayerEnded { source })) if source == expected
    ));
    assert!(matches!(
        reader.share.access().poll_read_chunk(&mut cx, maximum),
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
    let (mut set, layer, _intake, mut publish) = client_receiving(1_000_000, 1_000_000, 1_000_000);
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
        lent(&mut set)
            .on_stream_frame(
                &mut publish,
                EncryptionLevel::OneRtt,
                stream_frame(4, offset, LEN),
            )
            .expect("stream 4");
        lent(&mut set)
            .on_stream_frame(
                &mut publish,
                EncryptionLevel::OneRtt,
                stream_frame(1, offset, LEN),
            )
            .expect("stream 1");
        lent(&mut set)
            .on_max_stream_data(&mut publish, max_stream_data(0, 1_000_000 + round))
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
    let (mut set, layer, _intake, mut publish) = client(100, 1000);
    let accept = layer.accept_uni_owned();
    drop(layer);
    let accepting = thread::spawn(move || block_on(accept).map(|reader| reader.share.stream_id));
    lent(&mut set)
        .on_stream_frame(&mut publish, EncryptionLevel::OneRtt, stream_frame(3, 0, 4))
        .expect("taken");
    let accepted = accepting.join().expect("the accepting thread");
    assert_eq!(accepted.expect("accepted"), id(3));
}

/// A server's reader tells whether its stream had data in 0-RTT packets,
/// by the encryption level of the packets its STREAM frames came in
/// (application-handles «0-RTT 里到的数据怎样标出»): stream 0 had its first
/// bytes in 1-RTT and later ones in 0-RTT, which arrived late, and is
/// marked; stream 4 had all of its data in 1-RTT, and is not. The mark
/// stays.
#[test]
fn a_servers_reader_tells_whether_its_stream_had_data_in_zero_rtt_packets() {
    let (mut set, layer, _intake, mut publish) = server(100, 1000);
    lent(&mut set)
        .on_stream_frame(&mut publish, EncryptionLevel::OneRtt, stream_frame(0, 5, 5))
        .expect("taken");
    lent(&mut set)
        .on_stream_frame(&mut publish, EncryptionLevel::OneRtt, stream_frame(4, 0, 5))
        .expect("taken");
    let (_writer, mut zero_rtt) = now(layer.accept_bi()).expect("stream 0");
    let (_writer, one_rtt) = now(layer.accept_bi()).expect("stream 4");
    assert_eq!(zero_rtt.share.stream_id, id(0));
    assert!(
        !zero_rtt.received_zero_rtt(),
        "nothing came in 0-RTT packets yet"
    );
    lent(&mut set)
        .on_stream_frame(
            &mut publish,
            EncryptionLevel::ZeroRtt,
            stream_frame(0, 0, 5),
        )
        .expect("taken");
    assert!(zero_rtt.received_zero_rtt());
    assert!(!one_rtt.received_zero_rtt());
    let chunk = now(zero_rtt.read_chunk_unpin(NonZeroUsize::new(16).expect("not zero")))
        .expect("read")
        .expect("data");
    assert_eq!(chunk, Bytes::from(vec![7; 5]), "the first frame's data");
    assert!(zero_rtt.received_zero_rtt(), "the mark stays");
}

#[test]
fn the_drivers_panic_ends_every_wait_and_changes_no_stream() {
    // each stream may take 10 bytes, the connection 15
    let (mut set, layer, intake, _publish) = client(10, 15);
    let (writer, mut reader) = layer.try_open_bi().expect("a stream");
    let mut writer = writer.with_send_options(Urgency::default(), AnyActiveLinkPath);
    let (second, _second_reader) = layer.try_open_bi().expect("the second of two");
    let mut second = second.with_send_options(Urgency::default(), AnyActiveLinkPath);
    let (wakes, waker) = counting();
    let mut open = pin!(layer.open_bi());
    let mut accept = pin!(layer.accept_uni());
    let mut input = Bytes::from(vec![1; 20]);
    assert_eq!(poll_write(&mut writer, &mut input, &waker), Poll::Ready(10));
    assert!(
        poll_write(&mut writer, &mut input, &waker).is_pending(),
        "the stream's limit holds it"
    );
    let mut other = Bytes::from(vec![2; 20]);
    assert_eq!(poll_write(&mut second, &mut other, &waker), Poll::Ready(5));
    assert!(
        poll_write(&mut second, &mut other, &waker).is_pending(),
        "the connection's credit holds it"
    );
    let maximum = NonZeroUsize::new(64).expect("not zero");
    let mut cx = Context::from_waker(&waker);
    assert!(
        reader
            .share
            .access()
            .poll_read_chunk(&mut cx, maximum)
            .is_pending()
    );
    assert!(poll_once(open.as_mut(), &waker).is_pending());
    assert!(poll_once(accept.as_mut(), &waker).is_pending());
    intake.published();

    lent(&mut set).driver_panicked(idle_end());
    assert_eq!(
        wakes.count(),
        5,
        "both writers, the reader, open and accept"
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
    for writer in [&mut writer, &mut second] {
        let options = *writer.send_options_mut();
        assert!(matches!(
            writer.poll_write_with(&mut cx, &mut input, options.parameters(), options.destination()),
            Poll::Ready(Err(WriteError::LayerEnded { source })) if source == expected
        ));
    }
    assert!(matches!(
        reader.share.access().poll_read_chunk(&mut cx, maximum),
        Poll::Ready(Err(ReadError::LayerEnded { source })) if source == expected
    ));
    assert!(matches!(
        now(writer.all_acknowledged()),
        Err(AllAcknowledgedError::LayerEnded { source }) if source == expected
    ));
    assert!(matches!(
        now(writer.flush()),
        Err(FlushError::LayerEnded { source }) if source == expected
    ));
    assert!(matches!(
        writer.close(),
        Err(CloseError::LayerEnded { source }) if source == expected
    ));
    assert!(matches!(
        writer.reset(ApplicationErrorCode::new(v(1))),
        Err(ResetError::LayerEnded { source }) if source == expected
    ));
    assert!(matches!(
        reader.stop(ApplicationErrorCode::new(v(1))),
        Err(StopError::LayerEnded { source }) if source == expected
    ));
    assert!(matches!(
        layer.try_open_uni(),
        Err(TryOpenStreamError::LayerEnded { source }) if source == expected
    ));

    // the mark changed no state machine: the parts did not hear of the
    // layer's end, the set did not end, and nothing was published
    {
        let end = writer.share.part.lock();
        assert!(!end.sender.is_connection_closed());
        assert!(matches!(
            end.sender.end_state(),
            sakuya_stream_v1::send::SendEndState::Open
        ));
        assert_eq!(end.sender.written_end(), v(10));
    }
    assert!(lock(&set.shared.set).end.is_none());
    assert!(!lock(&set.shared.connection_receive).ended);
    drop((writer, reader));
    assert_eq!(
        intake.published(),
        [],
        "neither the operations nor dropping the handles published"
    );
    // a second panic's mark keeps the first end
    lent(&mut set).driver_panicked(LayerEnd::ZeroRttRejected);
    assert_eq!(set.shared.panic_end(), Some(&idle_end()));
}

// ---- reclaiming a stream ----

/// A STREAM frame of `stream` with `len` bytes at `offset` and the FIN.
fn fin_frame(stream: u32, offset: u32, len: usize) -> StreamFrame<Bytes> {
    let offset = (offset > 0).then(|| VarIntField::shortest(v(offset)));
    StreamFrame::new(
        VarIntField::shortest(id(stream)),
        offset,
        Bytes::from(vec![7; len]),
        true,
    )
    .expect("a short frame")
    .into_without_length()
    .into()
}

/// Send what `writer` wrote and its FIN, and acknowledge it all, as the
/// driver does.
fn send_and_acknowledge<O>(
    set: &mut Set,
    publish: &mut Publish,
    writer: &StreamWriter<
        LockedStreamSendShare<(), Ticket, Rfc9000StreamResets, Urgency, Intake>,
        O,
    >,
) {
    let sent = writer.share.part.lock().send_all();
    for summary in sent {
        lent(set).on_frame_delivered(publish, StreamSetFrameSummary::Stream(summary));
    }
}

/// Whether `stream` was reclaimed: the ledger records it, and its parts
/// left the tables.
fn is_reclaimed<E>(set: &SetOf<E>, stream: u32) -> bool {
    let state = lock(&set.shared.set);
    let reclaimed = state.ledger.is_reclaimed(id(stream));
    let in_tables =
        state.senders.contains_key(&id(stream)) || state.receivers.contains_key(&id(stream));
    assert_eq!(
        reclaimed, !in_tables,
        "stream {stream} leaves the tables when it is reclaimed"
    );
    reclaimed
}

/// The client's bidirectional stream 0: its request is acknowledged, and
/// the reader's read of the answer's end reclaims it while the application
/// still holds both handles. The reader then returns the same end again,
/// and a write reports that the stream was closed. A stream of this side
/// lets the peer open no more streams.
#[test]
fn a_reclaimed_stream_leaves_its_handles_with_their_last_results() {
    let (mut set, layer, intake, mut publish) = client(100, 1000);
    let (mut writer, mut reader) = layer.try_open_bi().expect("a stream");
    now(writer.write_all_unpin(Bytes::from_static(b"ping"))).expect("written");
    writer.close().expect("open");
    send_and_acknowledge(&mut set, &mut publish, &writer);
    assert_eq!(
        writer.share.part.lock().sender.terminal_state(),
        Some(SendTerminalState::DataRecvd)
    );
    assert!(!is_reclaimed(&set, 0), "the answer was not read");
    lent(&mut set)
        .on_stream_frame(&mut publish, EncryptionLevel::OneRtt, fin_frame(0, 0, 4))
        .expect("the answer");
    intake.published();
    let maximum = NonZeroUsize::new(64).expect("not zero");
    let chunk = now(reader.read_chunk_unpin(maximum))
        .expect("read")
        .expect("data");
    assert_eq!(chunk, Bytes::from(vec![7; 4]));
    assert!(!is_reclaimed(&set, 0), "the end was not read");
    assert_eq!(now(reader.read_chunk_unpin(maximum)).expect("read"), None);
    assert!(is_reclaimed(&set, 0));
    assert!(
        !intake
            .published()
            .iter()
            .any(|key| matches!(key, StreamIntentKey::MaxStreams(_))),
        "a stream of this side gives the peer no more streams"
    );

    // what the handles hold is only the last result
    assert_eq!(now(reader.read_chunk_unpin(maximum)).expect("read"), None);
    let mut writer = writer.with_send_options(Urgency::default(), AnyActiveLinkPath);
    let options = *writer.send_options_mut();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        writer.poll_write_with(
            &mut cx,
            &mut Bytes::from_static(b"more"),
            options.parameters(),
            options.destination()
        ),
        Poll::Ready(Err(WriteError::Closed))
    ));
    assert!(matches!(now(writer.all_acknowledged()), Ok(())));
    // a late frame of the stream is ignored
    lent(&mut set)
        .on_stream_frame(&mut publish, EncryptionLevel::OneRtt, fin_frame(0, 0, 4))
        .expect("ignored");
    assert!(is_reclaimed(&set, 0));
    drop((writer, reader));
    assert!(is_reclaimed(&set, 0));
    assert_eq!(intake.published(), []);
}

/// A unidirectional stream of this side has only its sending part: once
/// its data and FIN are acknowledged, it is reclaimed, and the peer gets no
/// more streams for it.
#[test]
fn a_unidirectional_stream_of_this_side_is_reclaimed_once_acknowledged() {
    let (mut set, layer, intake, mut publish) = client(100, 1000);
    let mut writer = layer.try_open_uni().expect("a stream");
    now(writer.write_all_unpin(Bytes::from_static(b"data"))).expect("written");
    writer.close().expect("open");
    intake.published();
    send_and_acknowledge(&mut set, &mut publish, &writer);
    assert!(is_reclaimed(&set, 2));
    for directionality in [
        Directionality::Bidirectional,
        Directionality::Unidirectional,
    ] {
        assert_eq!(
            lock(&set.shared.set).ledger.max_streams(directionality),
            None
        );
    }
    assert!(
        !intake
            .published()
            .iter()
            .any(|key| matches!(key, StreamIntentKey::MaxStreams(_)))
    );
}

/// The peer's stream 1 with its final size known and the answer
/// acknowledged: dropping the reader without reading reclaims it, and the
/// peer may open one more stream.
#[test]
fn dropping_the_reader_of_a_received_stream_reclaims_it() {
    let (mut set, layer, intake, mut publish) = client(100, 1000);
    lent(&mut set)
        .on_stream_frame(&mut publish, EncryptionLevel::OneRtt, fin_frame(1, 0, 5))
        .expect("taken");
    let (mut writer, reader) = now(layer.accept_bi()).expect("stream 1");
    writer.close().expect("open");
    send_and_acknowledge(&mut set, &mut publish, &writer);
    assert!(!is_reclaimed(&set, 1), "the reader is still there");
    intake.published();
    drop(reader);
    assert!(is_reclaimed(&set, 1));
    assert_eq!(
        intake.published(),
        [StreamIntentKey::MaxStreams(Directionality::Bidirectional)]
    );
    assert_eq!(
        lock(&set.shared.set)
            .ledger
            .max_streams(Directionality::Bidirectional),
        Some(count(4))
    );
    drop(writer);
    assert_eq!(intake.published(), [], "the done writer gives nothing up");
}

// ---- the events of the streams ----

/// One event of the streams, as [`Recording`] keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum StreamEvent {
    State(StreamId, StreamStateChange, EventInitiator),
    Moved(StreamDataMoved),
}

/// A handle that records the events of the streams; its clones share the
/// record.
#[derive(Debug, Clone, Default)]
struct Recording(Arc<Mutex<Vec<StreamEvent>>>);

impl Recording {
    /// The events since the last call.
    fn taken(&self) -> Vec<StreamEvent> {
        core::mem::take(&mut *self.0.lock().expect("not poisoned"))
    }

    fn push(&self, event: StreamEvent) {
        self.0.lock().expect("not poisoned").push(event);
    }
}

impl SharedEvents for Recording {
    const ENABLED: bool = true;
    fn enabled(&self) -> bool {
        true
    }
    fn stream_state(
        &self,
        stream_id: StreamId,
        change: StreamStateChange,
        trigger: EventInitiator,
    ) {
        self.push(StreamEvent::State(stream_id, change, trigger));
    }
    fn stream_data_moved(&self, moved: &StreamDataMoved) {
        self.push(StreamEvent::Moved(*moved));
    }
    type PartEvents = crate::v1::events::NoPartEvents;
    fn part_event(&self, event: Self::PartEvents) {
        match event {}
    }
}

fn sending(
    stream: u32,
    old: Option<SendStreamState>,
    new: Option<SendStreamState>,
    trigger: EventInitiator,
) -> StreamEvent {
    StreamEvent::State(id(stream), StreamStateChange::Sending { old, new }, trigger)
}

fn receiving(
    stream: u32,
    old: Option<ReceiveStreamState>,
    new: Option<ReceiveStreamState>,
    trigger: EventInitiator,
) -> StreamEvent {
    StreamEvent::State(
        id(stream),
        StreamStateChange::Receiving { old, new },
        trigger,
    )
}

/// `length` bytes of `stream` at `offset` moved from `from` to `to`, with
/// `additional_info`.
fn moved(
    stream: u32,
    offset: u64,
    length: u64,
    from: DataLocation,
    additional_info: Option<DataMovedAdditionalInfo>,
) -> StreamEvent {
    let to = match from {
        DataLocation::Application => DataLocation::Transport,
        DataLocation::Transport | DataLocation::Network => DataLocation::Application,
    };
    StreamEvent::Moved(StreamDataMoved {
        stream_id: id(stream),
        offset,
        length,
        from,
        to,
        additional_info,
    })
}

/// What the driver writes of `stream`'s data and FIN into one packet, as
/// the summaries of its acknowledgment.
fn supplied<E: SharedEvents>(set: &mut SetOf<E>, stream: u32) -> Vec<StreamSummary> {
    let read = super::super::tests::written(set, StreamIntentKey::Stream(id(stream)), 100, false);
    read.into_iter()
        .map(|read| match read {
            super::super::tests::Read::Stream {
                stream,
                offset,
                len,
                fin,
            } => StreamSummary {
                stream_id: stream,
                offset,
                len,
                fin,
            },
            other => panic!("a STREAM frame is written: {other:?}"),
        })
        .collect()
}

/// The client's stream 0, from its opening to its reclaim: each part leaves
/// idle as this side's; the write and the close move the data and the end
/// to the transport; the first supply sends the data, the second the FIN,
/// and the acknowledgment of the FIN, the peer's, receives it all. The
/// peer's answer and its FIN arrive at once; the read of the data moves it
/// to the application, the read of the end reads the part, and the stream
/// is reclaimed with both parts' last states.
#[test]
fn a_stream_of_this_side_gives_each_change_of_its_parts_and_its_data() {
    use DataLocation::{Application, Transport};
    use EventInitiator::{Local, Remote};
    use ReceiveStreamState as R;
    use SendStreamState as S;

    let events = Recording::default();
    let (mut set, layer, _intake, mut publish) = made_with(
        Role::Client,
        None::<nitori_tls::extension::alpn::ProtocolName<Bytes>>,
        100,
        1000,
        1000,
        events.clone(),
    );
    let (mut writer, mut reader) = layer.try_open_bi().expect("a stream");
    assert_eq!(
        events.taken(),
        [
            sending(0, None, Some(S::Ready), Local),
            receiving(0, None, Some(R::Recv), Local),
        ]
    );
    now(writer.write_all_unpin(Bytes::from_static(b"ping"))).expect("written");
    assert_eq!(events.taken(), [moved(0, 0, 4, Application, None)]);

    let data = supplied(&mut set, 0);
    assert_eq!(
        events.taken(),
        [sending(0, Some(S::Ready), Some(S::Send), Local)]
    );
    writer.close().expect("open");
    assert_eq!(
        events.taken(),
        [moved(
            0,
            4,
            0,
            Application,
            Some(DataMovedAdditionalInfo::FinSet)
        )]
    );
    writer.close().expect("closed already");
    assert_eq!(events.taken(), [], "a second close moves nothing");
    let fin = supplied(&mut set, 0);
    assert_eq!(fin.len(), 1);
    assert!(fin[0].fin);
    assert_eq!(
        events.taken(),
        [sending(0, Some(S::Send), Some(S::DataSent), Local)]
    );
    for summary in data.into_iter().chain(fin) {
        lent(&mut set).on_frame_delivered(&mut publish, StreamSetFrameSummary::Stream(summary));
    }
    assert_eq!(
        events.taken(),
        [sending(0, Some(S::DataSent), Some(S::DataRecvd), Remote)]
    );

    lent(&mut set)
        .on_stream_frame(&mut publish, EncryptionLevel::OneRtt, fin_frame(0, 0, 3))
        .expect("the answer");
    assert_eq!(
        events.taken(),
        [receiving(0, Some(R::Recv), Some(R::DataRecvd), Remote)]
    );
    let maximum = NonZeroUsize::new(64).expect("not zero");
    now(reader.read_chunk_unpin(maximum))
        .expect("read")
        .expect("data");
    assert_eq!(events.taken(), [moved(0, 0, 3, Transport, None)]);
    assert_eq!(now(reader.read_chunk_unpin(maximum)).expect("read"), None);
    assert_eq!(
        events.taken(),
        [
            receiving(0, Some(R::DataRecvd), Some(R::DataRead), Local),
            sending(0, Some(S::DataRecvd), None, Local),
            receiving(0, Some(R::DataRead), None, Local),
        ],
        "the read of the end gives no move, and reclaims the stream"
    );
    assert!(is_reclaimed(&set, 0));
    drop(writer);
    assert_eq!(events.taken(), [], "the done writer gives nothing up");
    drop(reader);
}

/// The peer's stream 1: its first frame makes both parts as the peer's;
/// reads move the data from where the earlier ones ended; the peer's reset
/// moves to the application with the read that first gives it, and a read
/// that gives it again moves nothing.
#[test]
fn a_stream_of_the_peer_gives_its_parts_as_the_peers_and_its_reset_once() {
    use DataLocation::Transport;
    use EventInitiator::{Local, Remote};
    use ReceiveStreamState as R;
    use SendStreamState as S;

    let events = Recording::default();
    let (mut set, layer, _intake, mut publish) = made_with(
        Role::Client,
        None::<nitori_tls::extension::alpn::ProtocolName<Bytes>>,
        100,
        1000,
        1000,
        events.clone(),
    );
    lent(&mut set)
        .on_stream_frame(&mut publish, EncryptionLevel::OneRtt, stream_frame(1, 0, 6))
        .expect("taken");
    assert_eq!(
        events.taken(),
        [
            receiving(1, None, Some(R::Recv), Remote),
            sending(1, None, Some(S::Ready), Remote),
        ]
    );
    let (_writer, mut reader) = now(layer.accept_bi()).expect("stream 1");
    let four = NonZeroUsize::new(4).expect("not zero");
    now(reader.read_chunk_unpin(four))
        .expect("read")
        .expect("data");
    now(reader.read_chunk_unpin(four))
        .expect("read")
        .expect("data");
    assert_eq!(
        events.taken(),
        [
            moved(1, 0, 4, Transport, None),
            moved(1, 4, 2, Transport, None)
        ]
    );

    let reset = sakuya_wire_v1::frame::reset_stream::ResetStreamFrame::new(
        VarIntField::shortest(id(1)),
        VarIntField::shortest(ApplicationErrorCode::new(v(2))),
        VarIntField::shortest(v(10)),
    );
    lent(&mut set)
        .on_reset_stream(&mut publish, reset)
        .expect("taken");
    assert_eq!(
        events.taken(),
        [receiving(1, Some(R::Recv), Some(R::ResetRecvd), Remote)]
    );
    let maximum = NonZeroUsize::new(64).expect("not zero");
    assert!(matches!(
        now(reader.read_chunk_unpin(maximum)),
        Err(ReadError::Reset { .. })
    ));
    assert_eq!(
        events.taken(),
        [
            moved(
                1,
                6,
                0,
                Transport,
                Some(DataMovedAdditionalInfo::StreamReset)
            ),
            receiving(1, Some(R::ResetRecvd), Some(R::ResetRead), Local),
        ]
    );
    assert!(matches!(
        now(reader.read_chunk_unpin(maximum)),
        Err(ReadError::Reset { .. })
    ));
    assert_eq!(events.taken(), [], "the same reset again moves nothing");
}

/// With the default handle, which records nothing, the set gives nothing
/// and works as it does with one that records.
#[test]
fn a_set_without_events_reclaims_as_one_with_them() {
    let (mut set, layer, _intake, mut publish) = client(100, 1000);
    let mut writer = layer.try_open_uni().expect("a stream");
    now(writer.write_all_unpin(Bytes::from_static(b"data"))).expect("written");
    writer.close().expect("open");
    for summary in supplied(&mut set, 2) {
        lent(&mut set).on_frame_delivered(&mut publish, StreamSetFrameSummary::Stream(summary));
    }
    assert!(is_reclaimed(&set, 2));
}
