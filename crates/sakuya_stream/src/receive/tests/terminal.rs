//! When the receive direction is terminal: the protocol owes nothing more
//! and the application has its last result or dropped the reader.
use super::*;
use crate::connection::LayerEnd;

#[test]
fn reading_the_end_of_a_received_stream_is_terminal() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 50, false), &mut connection)
        .unwrap();
    assert!(!receiver.is_terminal());
    receiver
        .on_stream_frame(stream(50, 50, true), &mut connection)
        .unwrap();
    assert!(
        !receiver.is_terminal(),
        "all data was received, but the application has not read its end"
    );
    let (read, outcome) = read_all(&mut receiver);
    assert_eq!(read.len(), 100);
    assert_eq!(outcome, Ok(ReadOutcome::End));
    assert!(receiver.is_terminal());
    // a repeated read returns the same end and stays terminal
    assert_eq!(receiver.read_chunk(NonZeroUsize::MAX), Ok(ReadOutcome::End));
    assert!(receiver.is_terminal());
}

#[test]
fn a_gap_below_the_final_size_keeps_the_stream_from_being_terminal() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(50, 50, true), &mut connection)
        .unwrap();
    receiver.reader_dropped();
    assert!(!receiver.is_terminal(), "[0, 50) is still owed");
    receiver
        .on_stream_frame(stream(0, 50, false), &mut connection)
        .unwrap();
    assert!(receiver.is_terminal());
}

#[test]
fn reading_the_reset_of_the_peer_is_terminal() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 50, false), &mut connection)
        .unwrap();
    receiver
        .on_reset_stream(reset(3, 200), &mut connection)
        .unwrap();
    assert!(
        !receiver.is_terminal(),
        "the reset arrived, but the application has not read it"
    );
    let (_, outcome) = read_all(&mut receiver);
    assert!(
        matches!(outcome, Err(ReadError::Reset { .. })),
        "{outcome:?}"
    );
    assert!(receiver.is_terminal());
}

#[test]
fn a_dropped_reader_is_terminal_once_the_final_size_is_known_and_received() {
    let (mut receiver, mut connection) = new_receiver(FollowingTermination::new(c(9)));
    receiver
        .on_stream_frame(stream(0, 50, false), &mut connection)
        .unwrap();
    receiver.reader_dropped();
    assert!(
        !receiver.is_terminal(),
        "the final size is not known: the peer may still send"
    );
    receiver
        .on_stream_frame(stream(50, 50, true), &mut connection)
        .unwrap();
    assert!(receiver.is_terminal());
}

#[test]
fn a_dropped_reader_is_terminal_once_the_peer_reset_the_stream() {
    let (mut receiver, mut connection) = new_receiver(FollowingTermination::new(c(9)));
    receiver
        .on_stream_frame(stream(0, 50, false), &mut connection)
        .unwrap();
    receiver.reader_dropped();
    assert!(!receiver.is_terminal());
    // the peer answers the STOP request with a reset
    receiver
        .on_reset_stream(reset(9, 80), &mut connection)
        .unwrap();
    assert!(receiver.is_terminal());
}

#[test]
fn the_end_of_the_layer_does_not_make_the_stream_terminal() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 50, true), &mut connection)
        .unwrap();
    receiver.layer_ended(LayerEnd::ConnectionClosed(close_reason()));
    assert!(
        receiver.read_chunk(NonZeroUsize::MAX).is_err(),
        "a read reports the end of the layer"
    );
    assert!(!receiver.is_terminal());
}
