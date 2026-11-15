use bytes::Bytes;
use sakuya_stream::{
    connection::{CloseReason, LayerEnd},
    send::write::FlushError,
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

/// The set of a client: the peer, a server, opens the streams 1, 5, 9, …
/// (bidirectional) and 3, 7, … (unidirectional). The client grants the
/// server three streams of each type, 100 bytes of each bidirectional
/// stream the server opens, 60 of each unidirectional one, and 1000 bytes
/// of the connection; the server grants each bidirectional stream it opens
/// 50 bytes.
fn client_set() -> LockedStreamSet<()> {
    client_set_with_connection_limit(1000)
}

fn client_set_with_connection_limit(initial_max_data: u32) -> LockedStreamSet<()> {
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
fn to_accept(set: &LockedStreamSet<()>, directionality: Directionality) -> Vec<StreamId> {
    let state = lock(&set.shared.set);
    let queue = match directionality {
        Directionality::Bidirectional => &state.accept_bidirectional,
        Directionality::Unidirectional => &state.accept_unidirectional,
    };
    queue.iter().copied().collect()
}

fn receiver(set: &LockedStreamSet<()>, stream: u32) -> Option<ReceivingPart<()>> {
    lock(&set.shared.set).receivers.get(&id(stream)).cloned()
}

fn sender(
    set: &LockedStreamSet<()>,
    stream: u32,
) -> Option<SendingPart<(), SendOptions<Urgency, AnyActiveLinkPath>>> {
    lock(&set.shared.set).senders.get(&id(stream)).cloned()
}

/// What reclaiming the state of a stream does: the ledger records it, and
/// its parts leave the tables.
fn reclaim(set: &LockedStreamSet<()>, stream: u32) {
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
    set.on_stream_frame(EncryptionLevel::OneRtt, stream_frame(9, 4, false))
        .expect("stream 9 is within the limit");
    assert!(receiver(&set, 9).is_some());
    assert!(
        sender(&set, 9).is_some(),
        "a bidirectional stream sends too"
    );
    assert!(receiver(&set, 1).is_none());
    assert!(receiver(&set, 5).is_none());
    assert_eq!(to_accept(&set, Directionality::Bidirectional), [id(9)]);

    set.on_stream_frame(EncryptionLevel::OneRtt, stream_frame(1, 2, false))
        .expect("stream 1 was opened with 9");
    assert!(receiver(&set, 1).is_some());
    assert_eq!(
        to_accept(&set, Directionality::Bidirectional),
        [id(9), id(1)]
    );
    // a later frame of 9 does not queue it again
    set.on_stream_frame(EncryptionLevel::OneRtt, stream_frame(9, 6, false))
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
    set.on_stream_frame(EncryptionLevel::OneRtt, stream_frame(1, 1, false))
        .expect("a bidirectional stream");
    set.on_stream_frame(EncryptionLevel::OneRtt, stream_frame(3, 1, false))
        .expect("a unidirectional stream");
    let bidirectional = receiver(&set, 1).expect("built");
    assert_eq!(bidirectional.lock().opened_limit(), v(100));
    let sending = sender(&set, 1).expect("built");
    assert_eq!(sending.lock().peer_stream_limit(), v(50));
    let unidirectional = receiver(&set, 3).expect("built");
    assert_eq!(unidirectional.lock().opened_limit(), v(60));
    assert!(sender(&set, 3).is_none());
    assert_eq!(to_accept(&set, Directionality::Unidirectional), [id(3)]);
}

#[test]
fn a_late_frame_of_a_reclaimed_stream_is_ignored() {
    let mut set = client_set();
    set.on_stream_frame(EncryptionLevel::OneRtt, stream_frame(1, 4, true))
        .expect("stream 1");
    reclaim(&set, 1);
    set.on_stream_frame(EncryptionLevel::OneRtt, stream_frame(1, 4, true))
        .expect("ignored");
    set.on_reset_stream(reset_stream(1, 4)).expect("ignored");
    set.on_max_stream_data(max_stream_data(1, 90))
        .expect("ignored");
    assert!(receiver(&set, 1).is_none());
    assert!(sender(&set, 1).is_none());
    assert_eq!(to_accept(&set, Directionality::Bidirectional), [id(1)]);
}

#[test]
fn a_frame_of_a_stream_this_side_has_not_opened_is_a_stream_state_error() {
    let mut set = client_set();
    let error = set
        .on_stream_frame(EncryptionLevel::OneRtt, stream_frame(0, 1, false))
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
        .on_stop_sending(stop_sending(4))
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
        .on_max_stream_data(max_stream_data(3, 10))
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
        .on_stream_frame(EncryptionLevel::OneRtt, stream_frame(13, 1, false))
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
    set.on_stream_frame(EncryptionLevel::OneRtt, stream_frame(1, 6, false))
        .expect("within the connection's limit");
    let error = set
        .on_stream_frame(EncryptionLevel::OneRtt, stream_frame(5, 6, false))
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
    set.on_stream_frame(EncryptionLevel::OneRtt, stream_frame(1, 1, false))
        .expect("stream 1");
    set.on_max_stream_data(max_stream_data(1, 80))
        .expect("a sending part");
    let part = sender(&set, 1).expect("built");
    assert_eq!(part.lock().peer_stream_limit(), v(80));
    // a lower limit is ignored
    set.on_max_stream_data(max_stream_data(1, 60))
        .expect("a sending part");
    assert_eq!(part.lock().peer_stream_limit(), v(80));
}

/// A frame for the sending part of a bidirectional stream of the peer opens
/// it (RFC 9000 §3.2, §19.5): both its parts are built and it waits to be
/// accepted.
#[test]
fn stop_sending_opens_a_peer_bidirectional_stream() {
    let mut set = client_set();
    set.on_stop_sending(stop_sending(5))
        .expect("within the limit");
    assert!(receiver(&set, 5).is_some());
    let part = sender(&set, 5).expect("built");
    assert_eq!(
        part.lock().stop_sending_code(),
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
    set.on_max_streams(frame).expect("no rule to break");
    let state = lock(&set.shared.set);
    assert_eq!(
        state.ledger.local_limit(Directionality::Bidirectional),
        count(5)
    );
}

#[test]
fn a_stream_frame_in_a_zero_rtt_packet_marks_its_stream() {
    let mut set = client_set();
    set.on_stream_frame(EncryptionLevel::OneRtt, stream_frame(1, 1, false))
        .expect("stream 1");
    set.on_stream_frame(EncryptionLevel::OneRtt, stream_frame(5, 1, false))
        .expect("stream 5");
    let one = receiver(&set, 1).expect("built");
    assert!(!one.lock().received_zero_rtt());
    set.on_stream_frame(EncryptionLevel::ZeroRtt, stream_frame(1, 3, false))
        .expect("more data of 1");
    assert!(one.lock().received_zero_rtt());
    let five = receiver(&set, 5).expect("built");
    assert!(!five.lock().received_zero_rtt());
}

#[test]
fn every_part_hears_the_same_end_of_the_layer() {
    let mut set = client_set();
    set.on_stream_frame(EncryptionLevel::OneRtt, stream_frame(1, 1, false))
        .expect("a bidirectional stream");
    set.on_stream_frame(EncryptionLevel::OneRtt, stream_frame(3, 1, false))
        .expect("a unidirectional stream");
    let end = LayerEnd::ConnectionClosed(CloseReason::IdleTimeout);
    set.layer_ended(end.clone());
    for stream in [1, 3] {
        let part = receiver(&set, stream).expect("built");
        let part = part.lock();
        let closed = part.closed().expect("the layer ended");
        assert_eq!(closed.end(), &end);
    }
    let part = sender(&set, 1).expect("built");
    let Err(FlushError::LayerEnded { source }) = part.lock().flush() else {
        panic!("the layer ended");
    };
    assert_eq!(source.end(), &end);
    assert_eq!(lock(&set.shared.set).end.as_ref(), Some(&end));

    // a second end changes nothing, and frames are ignored from now on
    set.layer_ended(LayerEnd::ZeroRttRejected);
    assert_eq!(lock(&set.shared.set).end.as_ref(), Some(&end));
    set.on_stream_frame(EncryptionLevel::OneRtt, stream_frame(5, 1, false))
        .expect("ignored");
    assert!(receiver(&set, 5).is_none());
}
