//! Read results and their priorities.
use super::*;
use crate::connection::ConnectionClosedError;
use core::num::NonZeroUsize;

fn nz(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).unwrap()
}

#[test]
fn connection_failure_is_not_hidden_by_held_data() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 100, false), &mut connection)
        .unwrap();
    receiver.connection_closed();
    let closed = Err(ReadError::Connection {
        source: ConnectionFailureError::Closed {
            source: ConnectionClosedError::new(),
        },
    });
    assert_eq!(receiver.read_chunk(), closed);
    // Not by an empty target either.
    let mut empty = [0u8; 0];
    assert_eq!(
        receiver.read_into(&mut &mut empty[..]),
        Err(ReadError::Connection {
            source: ConnectionFailureError::Closed {
                source: ConnectionClosedError::new()
            },
        })
    );
    assert!(receiver.parts().buffer.is_destroyed());
}

#[test]
fn connection_failure_overrides_a_committed_result() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 10, true), &mut connection)
        .unwrap();
    let (_, end) = read_all(&mut receiver);
    assert_eq!(end, Ok(ReadOutcome::End));
    receiver.connection_closed();
    assert_eq!(
        receiver.read_chunk(),
        Err(ReadError::Connection {
            source: ConnectionFailureError::Closed {
                source: ConnectionClosedError::new()
            },
        })
    );
}

/// An empty target makes no progress and commits nothing, even when the end
/// or a reset is already known.
#[test]
fn empty_target_commits_nothing() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 100, false), &mut connection)
        .unwrap();
    receiver
        .on_reset_stream(reset(4, 200), &mut connection)
        .unwrap();
    let mut out = Vec::new();
    assert_eq!(receiver.read_into(&mut out), Ok(ReadOutcome::Data(nz(100))));
    let mut empty = [0u8; 0];
    assert_eq!(
        receiver.read_into(&mut &mut empty[..]),
        Ok(ReadOutcome::NoProgress)
    );
    assert_eq!(
        receiver
            .parts()
            .count(TerminationEvent::ReadResultCommitted),
        0
    );
    // The gap can still be filled, and the stream completes.
    receiver
        .on_stream_frame(stream(100, 100, false), &mut connection)
        .unwrap();
    let (read, end) = read_all(&mut receiver);
    assert_eq!(read, data(100, 100));
    assert_eq!(end, reset_error(4, 200, 0, true));
}

#[test]
fn empty_target_does_not_report_the_end() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 0, true), &mut connection)
        .unwrap();
    let mut empty = [0u8; 0];
    assert_eq!(
        receiver.read_into(&mut &mut empty[..]),
        Ok(ReadOutcome::NoProgress)
    );
    assert_eq!(receiver.read_chunk(), Ok(ReadOutcome::End));
    // A committed end is returned before the empty-target shortcut.
    assert_eq!(
        receiver.read_into(&mut &mut empty[..]),
        Ok(ReadOutcome::End)
    );
}

/// Data and the end are never returned by the same call.
#[test]
fn data_then_end_in_separate_calls() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 10, true), &mut connection)
        .unwrap();
    let mut out = Vec::new();
    assert_eq!(receiver.read_into(&mut out), Ok(ReadOutcome::Data(nz(10))));
    assert_eq!(out, data(0, 10));
    assert_eq!(receiver.read_into(&mut out), Ok(ReadOutcome::End));
    assert_eq!(receiver.read_into(&mut out), Ok(ReadOutcome::End));
    assert_eq!(receiver.read_chunk(), Ok(ReadOutcome::End));
}

#[test]
fn both_ways_of_reading_share_one_position() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 100, true), &mut connection)
        .unwrap();
    let mut first = [0u8; 30];
    assert_eq!(
        receiver.read_into(&mut &mut first[..]),
        Ok(ReadOutcome::Data(nz(30)))
    );
    assert_eq!(receiver.read_chunk(), Ok(ReadOutcome::Data(data(30, 70))));
    assert_eq!(receiver.read_chunk(), Ok(ReadOutcome::End));
}

/// After a terminal error, reads keep returning it, and late frames do not
/// change it.
#[test]
fn terminal_error_is_stable() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_reset_stream(reset(4, 100), &mut connection)
        .unwrap();
    let error = reset_error(4, 100, 0, false);
    assert_eq!(receiver.read_chunk(), error);
    receiver
        .on_stream_frame(stream(0, 100, true), &mut connection)
        .unwrap();
    assert_eq!(receiver.read_chunk(), error);
    let mut out = Vec::new();
    assert_eq!(receiver.read_into(&mut out).map(|_| ()), error.map(|_| ()));
    assert_eq!(
        receiver
            .parts()
            .count(TerminationEvent::ReadResultCommitted),
        1
    );
}

/// A normal end is not rewritten by a later reset.
#[test]
fn committed_end_is_not_rewritten_by_a_reset() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 10, true), &mut connection)
        .unwrap();
    let (_, end) = read_all(&mut receiver);
    assert_eq!(end, Ok(ReadOutcome::End));
    receiver
        .on_reset_stream(reset(4, 10), &mut connection)
        .unwrap();
    assert_eq!(receiver.read_chunk(), Ok(ReadOutcome::End));
}

/// A completely delivered stream that was reset reports the reset with
/// completeness, unless the policy suppresses it.
#[test]
fn complete_but_reset_presentation() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 100, false), &mut connection)
        .unwrap();
    receiver
        .on_reset_stream(reset(4, 100), &mut connection)
        .unwrap();
    let (read, end) = read_all(&mut receiver);
    assert_eq!(read.len(), 100);
    assert_eq!(end, reset_error(4, 100, 0, true));

    let (mut receiver, mut connection) = new_receiver(scripted(|event, _| match event {
        TerminationEvent::RemoteReset => {
            TerminationDecision::keep().with_reset_presentation(ResetPresentation::Suppress)
        }
        _ => TerminationDecision::keep(),
    }));
    receiver
        .on_stream_frame(stream(0, 100, false), &mut connection)
        .unwrap();
    receiver
        .on_reset_stream(reset(4, 100), &mut connection)
        .unwrap();
    let (read, end) = read_all(&mut receiver);
    assert_eq!(read.len(), 100);
    assert_eq!(end, Ok(ReadOutcome::End));
}

/// Waiting happens only while missing data is still expected.
#[test]
fn waits_for_expected_data_only() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    assert_eq!(receiver.read_chunk(), Ok(ReadOutcome::Wait));
    receiver
        .on_stream_frame(stream(10, 10, false), &mut connection)
        .unwrap();
    assert_eq!(receiver.read_chunk(), Ok(ReadOutcome::Wait));
    receiver
        .on_stream_frame(stream(0, 10, false), &mut connection)
        .unwrap();
    let (read, outcome) = read_all(&mut receiver);
    assert_eq!(read, data(0, 20));
    assert_eq!(outcome, Ok(ReadOutcome::Wait));
}

#[test]
fn read_error_reports_its_layer() {
    let error: ReadError<&str> = ReadError::Connection {
        source: ConnectionFailureError::Closed {
            source: ConnectionClosedError::new(),
        },
    };
    assert_eq!(error.to_string(), "connection failed");
    let report = snafu::Report::from_error(error).to_string();
    assert!(report.contains("the connection is closed"), "{report}");
}
