use alloc::{collections::BTreeMap, sync::Arc};
use core::{
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll, Waker},
};

use alloc::task::Wake;
use bytes::Bytes;
use sakuya_stream_v1::{
    receive::read::ReadError, send::write::WriteError, send_options::urgency::Urgency,
};
use sakuya_wire::{
    parts::Coproduct,
    var_int::{VarInt, VarIntField},
};
use sakuya_wire_v1::{
    application_error::ApplicationErrorCode,
    encryption_level::EncryptionLevel,
    frame::{max_data::MaxDataFrame, max_stream_data::MaxStreamDataFrame, stream::StreamFrame},
    role::Role,
    stream_count::StreamCount,
    stream_id::{Directionality, StreamId},
    transport_error::TransportErrorCode,
    transport_parameters::integer::{
        InitialMaxData, InitialMaxStreamDataBidiLocal, InitialMaxStreamDataBidiRemote,
        InitialMaxStreamDataUni, InitialMaxStreamsBidi, InitialMaxStreamsUni,
    },
};

use super::*;
use crate::{
    send_strategy::ranked::{KeyIntentTicket, PublisherChange},
    v1::streams::{
        FlowControlParameters, StreamSetFrameError,
        locked::tests::{Read, TestPublisher, TestTypes, lent, publisher, written_through},
        resets::Rfc9000StreamResets,
        send::shortest_stream_frame,
    },
};

/// The set the tests use: no close cause, the ranked publisher's tickets.
type TestSet = OwnedStreamSet<(), KeyIntentTicket, Rfc9000StreamResets>;

/// The set of a client, as the locked set's tests make theirs: the peer, a
/// server, opens 1, 5, 9, … (bidirectional) and 3, 7, … (unidirectional),
/// three of each, with 100 bytes of each bidirectional stream and 1000
/// bytes of the connection; the server grants each bidirectional stream
/// this side opens 40 bytes, and the connection `send_credit` bytes.
fn client_set(send_credit: u32, receive_credit: u32) -> TestSet {
    let granted_to_peer = FlowControlParameters {
        initial_max_data: InitialMaxData::new(v(receive_credit)),
        initial_max_stream_data_bidi_local: InitialMaxStreamDataBidiLocal::new(v(70)),
        initial_max_stream_data_bidi_remote: InitialMaxStreamDataBidiRemote::new(v(100)),
        initial_max_stream_data_uni: InitialMaxStreamDataUni::new(v(60)),
        initial_max_streams_bidi: InitialMaxStreamsBidi::new(count(3)),
        initial_max_streams_uni: InitialMaxStreamsUni::new(count(3)),
    };
    let granted_by_peer = FlowControlParameters {
        initial_max_data: InitialMaxData::new(v(send_credit)),
        initial_max_stream_data_bidi_local: InitialMaxStreamDataBidiLocal::new(v(50)),
        initial_max_stream_data_bidi_remote: InitialMaxStreamDataBidiRemote::new(v(40)),
        initial_max_stream_data_uni: InitialMaxStreamDataUni::new(v(30)),
        initial_max_streams_bidi: InitialMaxStreamsBidi::new(count(2)),
        initial_max_streams_uni: InitialMaxStreamsUni::new(count(2)),
    };
    <TestSet as StreamSet<(), TestTypes, Rfc9000StreamResets>>::new(
        StreamSetFacts {
            role: Role::Client,
            granted_to_peer,
            granted_by_peer,
            peer_reset_support: (),
        },
        OwnedStreamSetConfig::default(),
        NoEvents,
        (),
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

fn code(value: u32) -> ApplicationErrorCode {
    ApplicationErrorCode::new(v(value))
}

/// A STREAM frame of `stream` with `len` bytes at offset 0.
fn stream_frame(stream: u32, len: usize, fin: bool) -> StreamFrame<Bytes> {
    StreamFrame::new(
        VarIntField::shortest(id(stream)),
        None,
        Bytes::from(vec![7; len]),
        fin,
    )
    .expect("a short frame")
    .into_without_length()
    .into()
}

/// What the publisher took, with the key of each intent.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    Published(StreamIntent<Urgency>),
    Resized(StreamIntentKey),
    Withdrawn(StreamIntentKey),
}

/// The publisher the set is lent, kept across calls as the connection keeps
/// it, with the keys of the intents published through it.
struct Watched {
    publisher: TestPublisher,
    keys: BTreeMap<u64, StreamIntentKey>,
}

impl Watched {
    fn new() -> Self {
        Self {
            publisher: publisher(),
            keys: BTreeMap::new(),
        }
    }

    /// What the publisher took since the last call.
    fn seen(&mut self) -> Vec<Seen> {
        let mut seen = Vec::new();
        for change in self.publisher.take_changes() {
            seen.push(match change {
                PublisherChange::Published { key, intent } => {
                    let intent = match intent {
                        Coproduct::Inl(Coproduct::Inl(intent)) => intent,
                        Coproduct::Inl(Coproduct::Inr(never)) | Coproduct::Inr(never) => {
                            match never {}
                        }
                    };
                    self.keys.insert(key, intent.key());
                    Seen::Published(intent)
                }
                PublisherChange::Resized { key, .. } => Seen::Resized(self.keys[&key]),
                PublisherChange::Withdrawn { key } => Seen::Withdrawn(self.keys[&key]),
            });
        }
        seen
    }
}

/// A waker that counts how often it is woken.
#[derive(Default)]
struct Wakes(AtomicUsize);

impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn counting() -> (Arc<Wakes>, Waker) {
    let wakes = Arc::new(Wakes::default());
    (Arc::clone(&wakes), Waker::from(Arc::clone(&wakes)))
}

/// Write `len` bytes into the stream of `held` once; how many it took.
fn write(
    set: &mut TestSet,
    watched: &mut Watched,
    held: &StreamWriterCredential,
    len: usize,
    waker: &Waker,
) -> Poll<usize> {
    let mut input = Bytes::from(vec![1; len]);
    match lent(set).poll_write(
        &mut watched.publisher,
        held,
        &mut Context::from_waker(waker),
        &mut input,
        &Urgency::default(),
        &AnyActiveLinkPath,
    ) {
        Poll::Ready(Ok(report)) => Poll::Ready(report.new_bytes.get() as usize),
        Poll::Ready(Err(_)) => panic!("the write fails"),
        Poll::Pending => Poll::Pending,
    }
}

/// Read the stream of `held` into `into` once; how many bytes it read.
fn read(
    set: &mut TestSet,
    watched: &mut Watched,
    held: &StreamReaderCredential,
    into: &mut Vec<u8>,
) -> Poll<usize> {
    match lent(set).poll_read_into(
        &mut watched.publisher,
        held,
        &mut Context::from_waker(Waker::noop()),
        into,
    ) {
        Poll::Ready(Ok(read)) => Poll::Ready(read),
        Poll::Ready(Err(_)) => panic!("the read fails"),
        Poll::Pending => Poll::Pending,
    }
}

#[test]
fn a_stream_frame_of_the_peer_is_accepted_and_read_through_the_set() {
    let mut set = client_set(500, 1000);
    let mut watched = Watched::new();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(
        lent(&mut set)
            .poll_accept_held(&mut cx, Directionality::Bidirectional)
            .is_pending()
    );
    lent(&mut set)
        .on_stream_frame(
            &mut watched.publisher,
            EncryptionLevel::OneRtt,
            stream_frame(1, 10, true),
        )
        .expect("within the limits");
    assert!(matches!(
        lent(&mut set).poll_accept_held(&mut cx, Directionality::Bidirectional),
        Poll::Ready(Ok(accepted)) if accepted == id(1)
    ));
    let held = &StreamReaderCredential::new(id(1));
    let mut into = Vec::new();
    assert_eq!(
        read(&mut set, &mut watched, held, &mut into),
        Poll::Ready(10)
    );
    assert_eq!(into, vec![7; 10]);
    assert_eq!(
        read(&mut set, &mut watched, held, &mut into),
        Poll::Ready(0)
    );
    assert!(!lent(&mut set).received_zero_rtt(held));
}

#[test]
fn data_beyond_the_connection_limit_is_a_flow_control_error() {
    let mut set = client_set(500, 10);
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
fn a_write_publishes_its_intent_and_a_partial_frame_resizes_it() {
    let mut set = client_set(500, 1000);
    let mut watched = Watched::new();
    let opened = lent(&mut set)
        .open_held(&mut watched.publisher, Directionality::Bidirectional, None)
        .expect("the peer allows two");
    assert_eq!(opened, id(0));
    assert!(watched.seen().is_empty());
    let held = &StreamWriterCredential::new(opened);
    assert_eq!(
        write(&mut set, &mut watched, held, 30, Waker::noop()),
        Poll::Ready(30)
    );
    assert_eq!(
        watched.seen(),
        [Seen::Published(StreamIntent::Stream {
            stream_id: opened,
            parameters: Urgency::default(),
            min: shortest_stream_frame(opened, VarInt::ZERO, true),
        })]
    );
    let read = written_through(
        &mut set,
        &mut watched.publisher,
        StreamIntentKey::Stream(opened),
        20,
        false,
    );
    let [Read::Stream { offset, len, .. }] = read[..] else {
        panic!("one STREAM frame is written: {read:?}");
    };
    assert_eq!(offset, VarInt::ZERO);
    assert!(len > 0 && len < 30, "a part of the data fits: {len}");
    assert_eq!(
        watched.seen(),
        [Seen::Resized(StreamIntentKey::Stream(opened))],
        "the rest needs room for its offset"
    );
}

#[test]
fn a_reset_withdraws_the_data_intent_and_publishes_its_frame() {
    let mut set = client_set(500, 1000);
    let mut watched = Watched::new();
    let opened = lent(&mut set)
        .open_held(&mut watched.publisher, Directionality::Unidirectional, None)
        .expect("the peer allows two");
    let held = &StreamWriterCredential::new(opened);
    assert_eq!(
        write(&mut set, &mut watched, held, 10, Waker::noop()),
        Poll::Ready(10)
    );
    watched.seen();
    lent(&mut set)
        .reset(&mut watched.publisher, held, code(3))
        .expect("open");
    let seen = watched.seen();
    assert!(seen.contains(&Seen::Withdrawn(StreamIntentKey::Stream(opened))));
    assert!(seen.iter().any(|seen| matches!(
        seen,
        Seen::Published(intent) if intent.key() == StreamIntentKey::ResetStream(opened)
    )));
}

#[test]
fn a_stop_sending_written_is_let_go_and_not_withdrawn() {
    let mut set = client_set(500, 1000);
    let mut watched = Watched::new();
    lent(&mut set)
        .on_stream_frame(
            &mut watched.publisher,
            EncryptionLevel::OneRtt,
            stream_frame(1, 5, false),
        )
        .expect("within the limits");
    watched.seen();
    lent(&mut set)
        .stop(
            &mut watched.publisher,
            &StreamReaderCredential::new(id(1)),
            code(4),
        )
        .expect("open");
    assert!(matches!(
        &watched.seen()[..],
        [Seen::Published(intent)] if intent.key() == StreamIntentKey::StopSending(id(1))
    ));
    let read = written_through(
        &mut set,
        &mut watched.publisher,
        StreamIntentKey::StopSending(id(1)),
        100,
        false,
    );
    assert_eq!(read, [Read::Other]);
    assert!(
        watched.seen().is_empty(),
        "the written intent goes with its packet, and nothing is due again"
    );
}

#[test]
fn a_write_at_the_stream_limit_waits_for_max_stream_data() {
    let mut set = client_set(500, 1000);
    let mut watched = Watched::new();
    let opened = lent(&mut set)
        .open_held(&mut watched.publisher, Directionality::Bidirectional, None)
        .expect("the peer allows two");
    let held = &StreamWriterCredential::new(opened);
    let (wakes, waker) = counting();
    assert_eq!(
        write(&mut set, &mut watched, held, 100, &waker),
        Poll::Ready(40)
    );
    assert!(write(&mut set, &mut watched, held, 60, &waker).is_pending());
    assert!(watched.seen().iter().any(|seen| matches!(
        seen,
        Seen::Published(intent)
            if intent.key() == StreamIntentKey::StreamDataBlocked(opened)
    )));
    lent(&mut set)
        .on_max_stream_data(
            &mut watched.publisher,
            MaxStreamDataFrame::new(VarIntField::shortest(opened), VarIntField::shortest(v(100))),
        )
        .expect("taken");
    assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
    assert_eq!(
        write(&mut set, &mut watched, held, 60, &waker),
        Poll::Ready(60)
    );
}

#[test]
fn a_write_without_connection_credit_waits_for_max_data() {
    let mut set = client_set(30, 1000);
    let mut watched = Watched::new();
    let opened = lent(&mut set)
        .open_held(&mut watched.publisher, Directionality::Bidirectional, None)
        .expect("the peer allows two");
    let held = &StreamWriterCredential::new(opened);
    let (wakes, waker) = counting();
    assert_eq!(
        write(&mut set, &mut watched, held, 50, &waker),
        Poll::Ready(30)
    );
    watched.seen();
    assert!(write(&mut set, &mut watched, held, 20, &waker).is_pending());
    assert!(watched.seen().iter().any(|seen| matches!(
        seen,
        Seen::Published(intent) if intent.key() == StreamIntentKey::DataBlocked
    )));
    lent(&mut set)
        .on_max_data(
            &mut watched.publisher,
            MaxDataFrame::new(VarIntField::shortest(v(60))),
        )
        .expect("taken");
    assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
    assert_eq!(
        write(&mut set, &mut watched, held, 20, &waker),
        Poll::Ready(10),
        "the stream's own limit of 40 holds the rest back"
    );
}

/// The peer's stream 1 is read to its end and answered, and the answer
/// acknowledged: the stream is reclaimed, but its reader and writer keep
/// their last results until their credentials come back.
fn reclaimed_peer_stream(set: &mut TestSet, watched: &mut Watched) {
    lent(set)
        .on_stream_frame(
            &mut watched.publisher,
            EncryptionLevel::OneRtt,
            stream_frame(1, 4, true),
        )
        .expect("within the limits");
    let mut into = Vec::new();
    let receive = &StreamReaderCredential::new(id(1));
    assert_eq!(read(set, watched, receive, &mut into), Poll::Ready(4));
    assert_eq!(read(set, watched, receive, &mut into), Poll::Ready(0));
    let send = &StreamWriterCredential::new(id(1));
    assert_eq!(write(set, watched, send, 3, Waker::noop()), Poll::Ready(3));
    lent(set).close(&mut watched.publisher, send).expect("open");
    let read = written_through(
        set,
        &mut watched.publisher,
        StreamIntentKey::Stream(id(1)),
        100,
        false,
    );
    assert_eq!(
        read,
        [Read::Stream {
            stream: id(1),
            offset: VarInt::ZERO,
            len: 3,
            fin: true
        }]
    );
    lent(set).on_frame_delivered(
        &mut watched.publisher,
        StreamSetFrameSummary::Stream(StreamSummary {
            stream_id: id(1),
            offset: VarInt::ZERO,
            len: 3,
            fin: true,
        }),
    );
    assert!(set.set.ledger.is_reclaimed(id(1)));
    assert!(set.set.senders.is_empty() && set.set.receivers.is_empty());
}

#[test]
fn a_reclaimed_stream_keeps_its_last_results_for_its_holders() {
    let mut set = client_set(500, 1000);
    let mut watched = Watched::new();
    reclaimed_peer_stream(&mut set, &mut watched);
    let mut into = Vec::new();
    assert_eq!(
        read(
            &mut set,
            &mut watched,
            &StreamReaderCredential::new(id(1)),
            &mut into
        ),
        Poll::Ready(0),
        "the reader reads the end again"
    );
    assert!(matches!(
        lent(&mut set).poll_write(
            &mut watched.publisher,
            &StreamWriterCredential::new(id(1)),
            &mut Context::from_waker(Waker::noop()),
            &mut Bytes::from_static(b"late"),
            &Urgency::default(),
            &AnyActiveLinkPath,
        ),
        Poll::Ready(Err(WriteError::Closed))
    ));
    assert!(matches!(
        lent(&mut set).poll_all_acknowledged(
            &StreamWriterCredential::new(id(1)),
            &mut Context::from_waker(Waker::noop()),
        ),
        Poll::Ready(Ok(()))
    ));
}

#[test]
#[cfg_attr(debug_assertions, should_panic(expected = "is gone"))]
fn once_its_credential_is_back_a_part_is_forgotten() {
    let mut set = client_set(500, 1000);
    let mut watched = Watched::new();
    reclaimed_peer_stream(&mut set, &mut watched);
    lent(&mut set).reclaim_writer(&mut watched.publisher, StreamWriterCredential::new(id(1)));
    lent(&mut set).reclaim_reader(&mut watched.publisher, StreamReaderCredential::new(id(1)));
    assert!(set.set.held_senders.is_empty() && set.set.held_receivers.is_empty());
    // a capability cannot name it any more; a borrowed credential made here
    // stands for one that would
    let read = lent(&mut set).poll_read_into(
        &mut watched.publisher,
        &StreamReaderCredential::new(id(1)),
        &mut Context::from_waker(Waker::noop()),
        &mut Vec::new(),
    );
    assert!(matches!(
        read,
        Poll::Ready(Err(ReadError::LayerEnded { .. }))
    ));
}

#[test]
fn a_stream_whose_credentials_came_back_before_it_was_done_is_not_kept() {
    let mut set = client_set(500, 1000);
    let mut watched = Watched::new();
    let opened = lent(&mut set)
        .open_held(&mut watched.publisher, Directionality::Unidirectional, None)
        .expect("the peer allows two");
    lent(&mut set)
        .close(&mut watched.publisher, &StreamWriterCredential::new(opened))
        .expect("open");
    lent(&mut set).reclaim_writer(&mut watched.publisher, StreamWriterCredential::new(opened));
    let read = written_through(
        &mut set,
        &mut watched.publisher,
        StreamIntentKey::Stream(opened),
        100,
        false,
    );
    assert_eq!(read.len(), 1, "the FIN is still sent: {read:?}");
    lent(&mut set).on_frame_delivered(
        &mut watched.publisher,
        StreamSetFrameSummary::Stream(StreamSummary {
            stream_id: opened,
            offset: VarInt::ZERO,
            len: 0,
            fin: true,
        }),
    );
    assert!(set.set.ledger.is_reclaimed(opened));
    assert!(set.set.senders.is_empty() && set.set.held_senders.is_empty());
}

#[test]
fn the_end_of_the_layer_ends_every_wait_and_withdraws_nothing_more() {
    let mut set = client_set(500, 1000);
    let mut watched = Watched::new();
    let opened = lent(&mut set)
        .open_held(&mut watched.publisher, Directionality::Bidirectional, None)
        .expect("the peer allows two");
    let (wakes, waker) = counting();
    let mut into = Vec::new();
    assert!(
        lent(&mut set)
            .poll_read_into(
                &mut watched.publisher,
                &StreamReaderCredential::new(opened),
                &mut Context::from_waker(&waker),
                &mut into,
            )
            .is_pending()
    );
    let end = LayerEnd::ConnectionClosed(sakuya_stream_v1::connection::CloseReason::Aborted(
        sakuya_stream_v1::connection::AbortCause::DriverDropped,
    ));
    lent(&mut set).layer_ended(&mut watched.publisher, end);
    assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
    assert!(matches!(
        lent(&mut set).poll_read_into(
            &mut watched.publisher,
            &StreamReaderCredential::new(opened),
            &mut Context::from_waker(&waker),
            &mut into,
        ),
        Poll::Ready(Err(ReadError::LayerEnded { .. }))
    ));
    assert!(matches!(
        lent(&mut set).open_held(&mut watched.publisher, Directionality::Bidirectional, None),
        Err(TryOpenStreamError::LayerEnded { .. })
    ));
}

/// The end of the layer withdraws every intent of the set, as when the
/// server rejected 0-RTT and the connection goes on: the data of a stream
/// and the STREAMS_BLOCKED of the limit reached.
#[test]
fn the_end_of_the_layer_withdraws_the_intents_of_the_set() {
    let mut set = client_set(500, 1000);
    let mut watched = Watched::new();
    let first = lent(&mut set)
        .open_held(&mut watched.publisher, Directionality::Bidirectional, None)
        .expect("the peer allows two");
    lent(&mut set)
        .open_held(&mut watched.publisher, Directionality::Bidirectional, None)
        .expect("the peer allows two");
    assert!(matches!(
        lent(&mut set).open_held(&mut watched.publisher, Directionality::Bidirectional, None),
        Err(TryOpenStreamError::AtLimit)
    ));
    assert_eq!(
        write(
            &mut set,
            &mut watched,
            &StreamWriterCredential::new(first),
            10,
            Waker::noop()
        ),
        Poll::Ready(10)
    );
    watched.seen();
    lent(&mut set).layer_ended(&mut watched.publisher, LayerEnd::ZeroRttRejected);
    let seen = watched.seen();
    assert!(
        seen.contains(&Seen::Withdrawn(StreamIntentKey::Stream(first))),
        "{seen:?}"
    );
    assert!(
        seen.contains(&Seen::Withdrawn(StreamIntentKey::StreamsBlocked(
            Directionality::Bidirectional
        ))),
        "{seen:?}"
    );
    assert!(
        seen.iter().all(|seen| matches!(seen, Seen::Withdrawn(_))),
        "{seen:?}"
    );
}

/// The peer's transport parameters of this handshake, in place of the
/// remembered ones the set was made on, raise the connection's send
/// credit, the limit of a stream opened and the limit on the streams this
/// side opens; a stream opened after gets its limit from them.
#[test]
fn the_peers_parameters_of_this_handshake_raise_the_limits() {
    let mut set = client_set(30, 1000);
    let mut watched = Watched::new();
    let first = lent(&mut set)
        .open_held(&mut watched.publisher, Directionality::Bidirectional, None)
        .expect("the peer allows two");
    lent(&mut set)
        .open_held(&mut watched.publisher, Directionality::Bidirectional, None)
        .expect("the peer allows two");
    assert!(matches!(
        lent(&mut set).open_held(&mut watched.publisher, Directionality::Bidirectional, None),
        Err(TryOpenStreamError::AtLimit)
    ));
    let held = &StreamWriterCredential::new(first);
    let (wakes, waker) = counting();
    assert_eq!(
        write(&mut set, &mut watched, held, 50, &waker),
        Poll::Ready(30)
    );
    assert!(write(&mut set, &mut watched, held, 20, &waker).is_pending());
    watched.seen();
    lent(&mut set).peer_transport_parameters_known(
        &mut watched.publisher,
        FlowControlParameters {
            initial_max_data: InitialMaxData::new(v(500)),
            initial_max_stream_data_bidi_local: InitialMaxStreamDataBidiLocal::new(v(50)),
            initial_max_stream_data_bidi_remote: InitialMaxStreamDataBidiRemote::new(v(100)),
            initial_max_stream_data_uni: InitialMaxStreamDataUni::new(v(30)),
            initial_max_streams_bidi: InitialMaxStreamsBidi::new(count(3)),
            initial_max_streams_uni: InitialMaxStreamsUni::new(count(2)),
        },
        (),
    );
    assert!(wakes.0.load(Ordering::Relaxed) >= 1, "the writer is woken");
    let seen = watched.seen();
    assert!(
        seen.contains(&Seen::Withdrawn(StreamIntentKey::StreamsBlocked(
            Directionality::Bidirectional
        ))),
        "{seen:?}"
    );
    assert_eq!(
        write(&mut set, &mut watched, held, 80, &waker),
        Poll::Ready(70),
        "the stream's new limit of 100 holds the rest back"
    );
    let third = lent(&mut set)
        .open_held(&mut watched.publisher, Directionality::Bidirectional, None)
        .expect("the peer allows three now");
    assert_eq!(
        write(
            &mut set,
            &mut watched,
            &StreamWriterCredential::new(third),
            150,
            &waker
        ),
        Poll::Ready(100),
        "a stream opened after gets the new limit"
    );
}

#[test]
fn an_intent_the_strategy_ends_is_withdrawn_and_published_again() {
    let mut set = client_set(500, 1000);
    let mut watched = Watched::new();
    let opened = lent(&mut set)
        .open_held(&mut watched.publisher, Directionality::Bidirectional, None)
        .expect("the peer allows two");
    assert_eq!(
        write(
            &mut set,
            &mut watched,
            &StreamWriterCredential::new(opened),
            10,
            Waker::noop()
        ),
        Poll::Ready(10)
    );
    watched.seen();
    lent(&mut set).on_intent_unfulfilled(
        &mut watched.publisher,
        StreamIntentKey::Stream(opened),
        Unfulfilled::Ended,
    );
    let seen = watched.seen();
    assert_eq!(
        seen.first(),
        Some(&Seen::Withdrawn(StreamIntentKey::Stream(opened))),
        "what the strategy ended is withdrawn, which changes nothing there: {seen:?}"
    );
    assert!(
        seen.iter().any(|seen| matches!(
            seen,
            Seen::Published(intent) if intent.key() == StreamIntentKey::Stream(opened)
        )),
        "the data's intent is published again: {seen:?}"
    );
}

/// The owned set with a reset kind that stands for an extension's.
mod extension_resets {
    use super::*;
    use crate::v1::streams::resets::test_resets::{
        ExtensionTestResets, TestResetError, TestResetRequest,
    };

    type ExtensionSet = OwnedStreamSet<(), KeyIntentTicket, ExtensionTestResets>;

    /// The set `set` as the driver lends it, with the kind's resets.
    fn lent(
        set: &mut ExtensionSet,
    ) -> &mut impl StreamSet<(), TestTypes, ExtensionTestResets, SendParameters = Urgency> {
        set
    }

    /// A set made on parameters that do not allow the kind's resets, as a
    /// client's early layer on remembered ones, refuses a reset the kind's
    /// request asks for until the server's parameters of this handshake
    /// allow it; from then on its writers reset so.
    #[test]
    fn the_peers_parameters_of_this_handshake_allow_the_kinds_reset() {
        let flow = FlowControlParameters {
            initial_max_data: InitialMaxData::new(v(1000)),
            initial_max_stream_data_bidi_local: InitialMaxStreamDataBidiLocal::new(v(100)),
            initial_max_stream_data_bidi_remote: InitialMaxStreamDataBidiRemote::new(v(100)),
            initial_max_stream_data_uni: InitialMaxStreamDataUni::new(v(100)),
            initial_max_streams_bidi: InitialMaxStreamsBidi::new(count(3)),
            initial_max_streams_uni: InitialMaxStreamsUni::new(count(3)),
        };
        let mut set = <ExtensionSet as StreamSet<(), TestTypes, ExtensionTestResets>>::new(
            StreamSetFacts {
                role: Role::Client,
                granted_to_peer: flow,
                granted_by_peer: flow,
                peer_reset_support: false,
            },
            OwnedStreamSetConfig::default(),
            NoEvents,
            (),
        );
        let mut watched = Watched::new();
        let opened = lent(&mut set)
            .open_held(&mut watched.publisher, Directionality::Bidirectional, None)
            .expect("the peer allows three");
        let reset = |set: &mut ExtensionSet, watched: &mut Watched| {
            lent(set).reset_with(
                &mut watched.publisher,
                &StreamWriterCredential::new(opened),
                TestResetRequest { code: code(3) },
            )
        };
        assert!(matches!(
            reset(&mut set, &mut watched),
            Err(TestResetError::NotSupportedByPeer)
        ));
        lent(&mut set).peer_transport_parameters_known(&mut watched.publisher, flow, true);
        reset(&mut set, &mut watched).expect("the peer allows it now");
        let seen = watched.seen();
        assert!(
            seen.iter().any(|seen| matches!(
                seen,
                Seen::Published(StreamIntent::ResetStream { stream_id, .. }) if *stream_id == opened
            )),
            "the reset is due: {seen:?}"
        );
    }
}
