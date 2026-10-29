//! Remote end facts in every order of observation, and the reliable prefix.
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
    assert_eq!(end, reset_error(4, 200, 0, true));
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
    assert_eq!(end, reset_error(4, 300, 0, false));
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

/// RESET_STREAM_AT(800), then RESET_STREAM_AT(400): the effective prefix
/// drops to 400 and a read waiting for the gap at 500 ends.
#[test]
fn lower_reliable_size_releases_a_waiting_read() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_reset_stream_at(reset_at(4, 1000, 800), &mut connection)
        .unwrap();
    receiver
        .on_stream_frame(stream(0, 500, false), &mut connection)
        .unwrap();
    let (read, outcome) = read_all(&mut receiver);
    assert_eq!(read.len(), 500);
    assert_eq!(outcome, Ok(ReadOutcome::Wait));
    receiver
        .on_reset_stream_at(reset_at(4, 1000, 400), &mut connection)
        .unwrap();
    assert_eq!(receiver.remote_reset().unwrap().reliable_size, v(400));
    assert_eq!(
        receiver
            .parts()
            .count(TerminationEvent::ReliablePrefixLowered),
        1
    );
    assert_eq!(receiver.read_chunk(), reset_error(4, 1000, 400, false));
}

/// RESET_STREAM_AT(400), then RESET_STREAM_AT(800): out of order; the
/// prefix stays 400 and nothing new happens.
#[test]
fn higher_reliable_size_is_ignored() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_reset_stream_at(reset_at(4, 1000, 400), &mut connection)
        .unwrap();
    receiver
        .on_reset_stream_at(reset_at(4, 1000, 800), &mut connection)
        .unwrap();
    assert_eq!(receiver.remote_reset().unwrap().reliable_size, v(400));
    assert_eq!(
        receiver.parts().event_kinds(),
        vec![TerminationEvent::RemoteReset]
    );
}

/// RESET_STREAM_AT, then plain RESET: the prefix drops to zero, but held
/// contiguous data stays readable.
#[test]
fn plain_reset_after_reset_at_keeps_readable_data() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 300, false), &mut connection)
        .unwrap();
    receiver
        .on_reset_stream_at(reset_at(4, 1000, 800), &mut connection)
        .unwrap();
    receiver
        .on_reset_stream(reset(4, 1000), &mut connection)
        .unwrap();
    assert_eq!(receiver.remote_reset().unwrap().reliable_size, VarInt::ZERO);
    let (read, end) = read_all(&mut receiver);
    assert_eq!(read, data(0, 300));
    assert_eq!(end, reset_error(4, 1000, 0, false));
}

/// Plain RESET, then RESET_STREAM_AT: an extension frame sent earlier and
/// delivered late; the prefix stays zero.
#[test]
fn reset_at_after_plain_reset_keeps_zero() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_reset_stream(reset(4, 1000), &mut connection)
        .unwrap();
    receiver
        .on_reset_stream_at(reset_at(4, 1000, 800), &mut connection)
        .unwrap();
    assert_eq!(receiver.remote_reset().unwrap().reliable_size, VarInt::ZERO);
    assert_eq!(receiver.read_chunk(), reset_error(4, 1000, 0, false));
}

/// FIN and RESET_STREAM_AT in both orders agree on the final size, and FIN
/// does not restore a lowered prefix.
#[test]
fn fin_and_reset_at_in_either_order() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(900, 100, true), &mut connection)
        .unwrap();
    receiver
        .on_reset_stream_at(reset_at(4, 1000, 400), &mut connection)
        .unwrap();
    assert_eq!(receiver.remote_reset().unwrap().final_size, v(1000));

    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_reset_stream_at(reset_at(4, 1000, 800), &mut connection)
        .unwrap();
    receiver
        .on_reset_stream_at(reset_at(4, 1000, 400), &mut connection)
        .unwrap();
    receiver
        .on_stream_frame(stream(900, 100, true), &mut connection)
        .unwrap();
    assert_eq!(receiver.parts().final_size(), Some(v(1000)));
    assert_eq!(receiver.remote_reset().unwrap().reliable_size, v(400));
}

/// A RESET_STREAM_AT that arrives before any data does not wipe the
/// reliable prefix: the read waits for it.
#[test]
fn reset_at_before_data_keeps_the_prefix() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_reset_stream_at(reset_at(4, 1000, 800), &mut connection)
        .unwrap();
    assert_eq!(receiver.read_chunk(), Ok(ReadOutcome::Wait));
    assert_eq!(receiver.acceptance_limit(), BoundaryMode::Following);
    receiver
        .on_stream_frame(stream(0, 800, false), &mut connection)
        .unwrap();
    let (read, end) = read_all(&mut receiver);
    assert_eq!(read, data(0, 800));
    assert_eq!(end, reset_error(4, 1000, 800, false));
}

/// Data beyond the reliable prefix is delivered when it is there.
#[test]
fn data_beyond_the_prefix_is_delivered() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 600, false), &mut connection)
        .unwrap();
    receiver
        .on_reset_stream_at(reset_at(4, 1000, 400), &mut connection)
        .unwrap();
    let (read, end) = read_all(&mut receiver);
    assert_eq!(read.len(), 600);
    assert_eq!(end, reset_error(4, 1000, 400, false));
}

/// The STOP request was sent and the policy truncated delivery at 300; a
/// later RESET_STREAM_AT promising 800 does not lift the truncation, and the
/// read ends at 300 with the local reason and the remote facts.
#[test]
fn stop_truncation_survives_a_larger_reliable_size() {
    let (mut receiver, mut connection) = new_receiver(scripted(|event, _| match event {
        TerminationEvent::StopSent => fix_both(300, "stop"),
        _ => TerminationDecision::keep(),
    }));
    receiver
        .on_stream_frame(stream(0, 200, false), &mut connection)
        .unwrap();
    receiver.stop(v(7)).unwrap();
    receiver.on_stop_sent();
    assert_eq!(receiver.delivery_limit(), BoundaryMode::Fixed(v(300)));
    receiver
        .on_stream_frame(stream(200, 600, false), &mut connection)
        .unwrap();
    // Only [200, 300) of the frame is kept; all of it is accounted.
    assert_eq!(receiver.parts().buffer.held_len(), 300);
    assert_eq!(connection.used(), v(800));
    receiver
        .on_reset_stream_at(reset_at(4, 1000, 800), &mut connection)
        .unwrap();
    assert_eq!(receiver.delivery_limit(), BoundaryMode::Fixed(v(300)));
    let (read, end) = read_all(&mut receiver);
    assert_eq!(read, data(0, 300));
    assert_eq!(
        end,
        Err(ReadError::LocalTermination {
            reason: "stop",
            trigger: TerminationEvent::StopSent,
            remote: Some(RemoteReset {
                code: v(4),
                final_size: v(1000),
                reliable_size: v(800),
            }),
        })
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
    receiver.stop(v(7)).unwrap();
    receiver.on_stop_sent();
    receiver
        .on_reset_stream(reset(4, 500), &mut connection)
        .unwrap();
    assert_eq!(
        receiver.acceptance_limit(),
        BoundaryMode::Fixed(VarInt::ZERO)
    );
    let (read, end) = read_all(&mut receiver);
    assert_eq!(read, data(0, 100));
    assert_eq!(end, reset_error(4, 500, 0, false));
}

/// RESET_STREAM_AT whose prefix is not yet received, then a local STOP
/// request: still allowed.
#[test]
fn stop_is_allowed_while_the_prefix_is_missing() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 500, false), &mut connection)
        .unwrap();
    receiver
        .on_reset_stream_at(reset_at(4, 1000, 800), &mut connection)
        .unwrap();
    assert_eq!(receiver.stop(v(5)), Ok(()));
    assert_eq!(receiver.pending_stop(), Some(v(5)));
    // Once the prefix arrives, the pending request lapses.
    receiver
        .on_stream_frame(stream(500, 300, false), &mut connection)
        .unwrap();
    assert_eq!(receiver.pending_stop(), None);
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
    receiver.stop(v(5)).unwrap();
    receiver
        .on_reset_stream(reset(4, 200), &mut connection)
        .unwrap();
    assert_eq!(receiver.pending_stop(), None);
    let (_, end) = read_all(&mut receiver);
    assert_eq!(end, reset_error(4, 200, 0, false));
    receiver.on_stop_sent();
    assert_eq!(receiver.parts().count(TerminationEvent::StopSent), 1);
    assert_eq!(receiver.read_chunk(), end);
}
