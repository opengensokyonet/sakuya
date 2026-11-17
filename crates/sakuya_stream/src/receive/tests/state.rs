//! The state of the receive direction (RFC 9000 §3.2), transition by
//! transition.
use super::*;
use crate::connection::LayerEnd;
use crate::receive::ReceiveStreamState as State;

#[test]
fn data_reaches_size_known_data_recvd_and_data_read() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    assert_eq!(receiver.receive_state(), State::Recv);
    receiver
        .on_stream_frame(stream(0, 50, false), &mut connection)
        .unwrap();
    assert_eq!(receiver.receive_state(), State::Recv);
    receiver
        .on_stream_frame(stream(80, 20, true), &mut connection)
        .unwrap();
    assert_eq!(receiver.receive_state(), State::SizeKnown);
    receiver
        .on_stream_frame(stream(50, 30, false), &mut connection)
        .unwrap();
    assert_eq!(receiver.receive_state(), State::DataRecvd);
    let (read, outcome) = read_all(&mut receiver);
    assert_eq!(read.len(), 100);
    assert_eq!(outcome, Ok(ReadOutcome::End));
    assert_eq!(receiver.receive_state(), State::DataRead);
}

#[test]
fn a_reset_reaches_reset_recvd_and_reset_read() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 50, false), &mut connection)
        .unwrap();
    receiver
        .on_reset_stream(reset(3, 200), &mut connection)
        .unwrap();
    assert_eq!(receiver.receive_state(), State::ResetRecvd);
    let (_, outcome) = read_all(&mut receiver);
    assert!(
        matches!(outcome, Err(ReadError::Reset { .. })),
        "{outcome:?}"
    );
    assert_eq!(receiver.receive_state(), State::ResetRead);
}

#[test]
fn a_reset_in_size_known_reaches_reset_recvd() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(50, 50, true), &mut connection)
        .unwrap();
    assert_eq!(receiver.receive_state(), State::SizeKnown);
    receiver
        .on_reset_stream(reset(3, 100), &mut connection)
        .unwrap();
    assert_eq!(receiver.receive_state(), State::ResetRecvd);
}

/// All data and then a reset: the reset is reported by default, and a
/// policy that suppresses it keeps the stream in Data Recvd.
#[test]
fn a_reset_after_all_data_follows_the_reset_presentation() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 100, true), &mut connection)
        .unwrap();
    assert_eq!(receiver.receive_state(), State::DataRecvd);
    receiver
        .on_reset_stream(reset(3, 100), &mut connection)
        .unwrap();
    assert_eq!(receiver.receive_state(), State::ResetRecvd);

    let (mut receiver, mut connection) = new_receiver(scripted(|_, _| {
        TerminationDecision::keep().with_reset_presentation(ResetPresentation::Suppress)
    }));
    receiver
        .on_stream_frame(stream(0, 100, true), &mut connection)
        .unwrap();
    receiver
        .on_reset_stream(reset(3, 100), &mut connection)
        .unwrap();
    assert_eq!(receiver.receive_state(), State::DataRecvd);
    let (read, outcome) = read_all(&mut receiver);
    assert_eq!(read.len(), 100);
    assert_eq!(outcome, Ok(ReadOutcome::End));
    assert_eq!(receiver.receive_state(), State::DataRead);
}

/// What only this side decides leaves the state where the peer's frames
/// put it.
#[test]
fn local_decisions_are_no_state() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 50, false), &mut connection)
        .unwrap();
    receiver.reader_dropped();
    assert_eq!(receiver.receive_state(), State::Recv);
    receiver
        .on_stream_frame(stream(50, 50, true), &mut connection)
        .unwrap();
    assert_eq!(receiver.receive_state(), State::DataRecvd);

    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 50, true), &mut connection)
        .unwrap();
    receiver.layer_ended(LayerEnd::ConnectionClosed(close_reason()));
    assert_eq!(receiver.receive_state(), State::DataRecvd);
}
