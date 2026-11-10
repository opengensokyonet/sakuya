//! The local STOP request, row by row of its checks.
use super::*;
use crate::connection::ConnectionClosedError;
use crate::receive::stop::{NoStopRequestError, StopError, StopNotNeededReason};

#[test]
fn connection_closed_fails_the_request() {
    let (mut receiver, _connection) = new_receiver(keep_all());
    receiver.connection_closed(close_reason());
    assert_eq!(
        receiver.stop(c(1)),
        Err(StopError::ConnectionClosed {
            source: ConnectionClosedError::new(close_reason())
        })
    );
    assert_eq!(receiver.pending_stop(), None);
}

#[test]
fn same_code_is_idempotent() {
    let (mut receiver, _connection) = new_receiver(keep_all());
    assert_eq!(receiver.stop(c(1)), Ok(()));
    assert_eq!(receiver.stop(c(1)), Ok(()));
    assert_eq!(receiver.parts().count(TerminationEvent::StopRequested), 1);
    assert_eq!(receiver.pending_stop(), Some(c(1)));
}

#[test]
fn other_code_conflicts_and_keeps_the_request() {
    let (mut receiver, _connection) = new_receiver(keep_all());
    receiver.stop(c(1)).unwrap();
    assert_eq!(
        receiver.stop(c(2)),
        Err(StopError::StopConflict {
            installed: c(1),
            requested: c(2),
        })
    );
    assert_eq!(receiver.pending_stop(), Some(c(1)));
}

#[test]
fn complete_reception_needs_no_request() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 100, true), &mut connection)
        .unwrap();
    let not_needed = Err(StopError::StopNotNeeded {
        reason: StopNotNeededReason::DataComplete,
    });
    assert_eq!(receiver.stop(c(1)), not_needed);
    // Also after the normal end was read.
    let (_, end) = read_all(&mut receiver);
    assert_eq!(end, Ok(ReadOutcome::End));
    assert_eq!(receiver.stop(c(1)), not_needed);
}

#[test]
fn plain_reset_needs_no_request() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_reset_stream(reset(4, 100), &mut connection)
        .unwrap();
    assert_eq!(
        receiver.stop(c(1)),
        Err(StopError::StopNotNeeded {
            reason: StopNotNeededReason::PeerReset,
        })
    );
}

/// An allowed request is installed; it neither sends anything nor ends
/// reading.
#[test]
fn allowed_request_is_installed_without_ending_reads() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 100, false), &mut connection)
        .unwrap();
    assert_eq!(receiver.stop(c(1)), Ok(()));
    assert_eq!(receiver.pending_stop(), Some(c(1)));
    assert_eq!(receiver.read_chunk(), Ok(ReadOutcome::Data(data(0, 100))));
    receiver
        .on_stream_frame(stream(100, 100, true), &mut connection)
        .unwrap();
    let (read, end) = read_all(&mut receiver);
    assert_eq!(read, data(100, 100));
    assert_eq!(end, Ok(ReadOutcome::End));
    assert_eq!(receiver.delivery_limit(), BoundaryMode::Following);
}

/// A request installed before the stream completed lapses, but repeating it
/// still confirms the original request instead of failing.
#[test]
fn installed_request_outlives_completion_for_retries() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver.stop(c(1)).unwrap();
    receiver
        .on_stream_frame(stream(0, 100, true), &mut connection)
        .unwrap();
    assert_eq!(receiver.pending_stop(), None);
    assert_eq!(receiver.stop(c(1)), Ok(()));
    assert_eq!(receiver.parts().count(TerminationEvent::StopRequested), 1);
}

/// Ending delivery locally does not end the request: repeating it after the
/// local termination still confirms it.
#[test]
fn request_after_local_termination() {
    let (mut receiver, _connection) = new_receiver(scripted(|event, _| match event {
        TerminationEvent::StopSent => destroy("stopped"),
        _ => TerminationDecision::keep(),
    }));
    receiver.stop(c(1)).unwrap();
    receiver.on_stop_sent().unwrap();
    assert_eq!(
        receiver.read_chunk(),
        Err(ReadError::BufferDestroyed {
            reason: SharedTerminationReason::new("stopped"),
            trigger: TerminationEvent::StopSent,
            remote: None,
        })
    );
    // The same request is confirmed again; the duty to send is done.
    assert_eq!(receiver.stop(c(1)), Ok(()));
    assert_eq!(receiver.pending_stop(), None);
}

#[test]
fn request_is_observed_but_cannot_be_vetoed() {
    let (mut receiver, _connection) = new_receiver(scripted(|event, view| {
        if event == TerminationEvent::StopRequested {
            assert_eq!(view.stop_code, Some(c(1)));
            assert!(!view.stop_sent);
        }
        TerminationDecision::keep()
    }));
    receiver.stop(c(1)).unwrap();
    assert_eq!(
        receiver.parts().event_kinds(),
        vec![TerminationEvent::StopRequested]
    );
    receiver.on_stop_sent().unwrap();
    receiver.on_stop_sent().unwrap();
    assert_eq!(receiver.parts().count(TerminationEvent::StopSent), 1);
    assert_eq!(receiver.pending_stop(), None);
}

#[test]
fn stop_sent_without_a_request_fails() {
    let (mut receiver, _connection) = new_receiver(keep_all());
    assert_eq!(receiver.on_stop_sent(), Err(NoStopRequestError));
    assert!(receiver.parts().events.is_empty());
    receiver.stop(c(1)).unwrap();
    receiver.on_stop_sent().unwrap();
    // A repeated report changes nothing.
    receiver.on_stop_sent().unwrap();
    assert_eq!(receiver.parts().count(TerminationEvent::StopSent), 1);
}

#[test]
fn stop_error_display() {
    let error = StopError::StopNotNeeded {
        reason: StopNotNeededReason::DataComplete,
    };
    assert_eq!(
        error.to_string(),
        "no STOP request is needed: all stream data has been received"
    );
}
