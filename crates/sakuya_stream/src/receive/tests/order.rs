//! Remote end facts in every order of observation.
use super::*;

/// Plain RESET, then STREAM: in-flight data received before the error is
/// delivered can still complete the readable range.
#[test]
fn reset_then_stream_before_the_error_is_read() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 100, false), &mut connection)
        .unwrap();
    receiver
        .on_reset_stream(reset(4, 200), &mut connection)
        .unwrap();
    receiver
        .on_stream_frame(stream(100, 100, false), &mut connection)
        .unwrap();
    let (read, end) = read_all(&mut receiver);
    assert_eq!(read, data(0, 200));
    assert_eq!(end, reset_error(4, 200, true));
}

/// Plain RESET, then STREAM after the error was delivered: the late data is
/// checked and accounted but does not reopen delivery.
#[test]
fn reset_then_stream_after_the_error_is_read() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 100, false), &mut connection)
        .unwrap();
    receiver
        .on_reset_stream(reset(4, 300), &mut connection)
        .unwrap();
    let (read, end) = read_all(&mut receiver);
    assert_eq!(read, data(0, 100));
    assert_eq!(end, reset_error(4, 300, false));
    assert!(receiver.parts().buffer.is_destroyed());
    receiver
        .on_stream_frame(stream(100, 200, false), &mut connection)
        .unwrap();
    assert_eq!(receiver.parts().buffer.held_len(), 0);
    assert_eq!(receiver.read_chunk().map(|_| ()), end.map(|_| ()));
    // Late data is still checked against the final size.
    assert!(
        receiver
            .on_stream_frame(stream(300, 1, false), &mut connection)
            .is_err()
    );
}

/// STOP sent, then any reset: the facts are taken, the local choice stays.
#[test]
fn stop_sent_then_plain_reset() {
    let (mut receiver, mut connection) = new_receiver(scripted(|event, _| match event {
        TerminationEvent::StopSent => restrict(
            BoundaryUpdate::Fix(VarInt::ZERO),
            BoundaryUpdate::Keep,
            "stop",
        ),
        _ => TerminationDecision::keep(),
    }));
    receiver
        .on_stream_frame(stream(0, 100, false), &mut connection)
        .unwrap();
    receiver.stop(c(7)).unwrap();
    receiver.on_stop_sent().unwrap();
    receiver
        .on_reset_stream(reset(4, 500), &mut connection)
        .unwrap();
    assert_eq!(
        receiver.acceptance_limit(),
        BoundaryMode::Fixed(VarInt::ZERO)
    );
    let (read, end) = read_all(&mut receiver);
    assert_eq!(read, data(0, 100));
    assert_eq!(end, reset_error(4, 500, false));
}

/// A plain RESET arrives, then the late feedback that the STOP request was
/// sent: the policy decides on the current state, and nothing is restored.
#[test]
fn late_stop_feedback_after_a_reset() {
    let (mut receiver, mut connection) = new_receiver(scripted(|event, view| match event {
        TerminationEvent::StopSent => {
            assert!(view.reset.is_some());
            assert!(view.destroyed && view.read_result_committed);
            TerminationDecision::keep()
        }
        _ => TerminationDecision::keep(),
    }));
    receiver
        .on_stream_frame(stream(0, 100, false), &mut connection)
        .unwrap();
    receiver.stop(c(5)).unwrap();
    receiver
        .on_reset_stream(reset(4, 200), &mut connection)
        .unwrap();
    assert_eq!(receiver.pending_stop(), None);
    let (_, end) = read_all(&mut receiver);
    assert_eq!(end, reset_error(4, 200, false));
    receiver.on_stop_sent().unwrap();
    assert_eq!(receiver.parts().count(TerminationEvent::StopSent), 1);
    assert_eq!(receiver.read_chunk(), end);
}
