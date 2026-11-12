//! The violations of the frame methods, the absence of any trace they leave,
//! and the stream between a violation and the connection's closure.
use super::*;
use crate::connection::ConnectionClosedError;
use crate::connection_receive_flow::RecordUsageError;
use crate::receive::stop::StopError;
use crate::receive::violation::{
    FinalSizeBelowReceivedError, OnRemoteResetError, OnResetStreamError, OnStreamFrameError,
    StreamLimitExceededError,
};
use crate::stream_end::{BeyondFinalSizeError, FinalSizeChangeError};
use core::fmt::Debug;

/// Everything about a receiver and its connection that an observer can see
/// without reading.
#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    accounted_end: VarInt,
    final_size: Option<VarInt>,
    delivered_end: VarInt,
    held_len: usize,
    destroyed: bool,
    reset: Option<RemoteReset>,
    pending_stop: Option<ApplicationErrorCode>,
    acceptance: BoundaryMode,
    delivery: BoundaryMode,
    advertisement: Option<VarInt>,
    flow_events: Vec<ReceiveFlowEvent>,
    termination_events: Vec<TerminationEvent>,
    used: VarInt,
    released: VarInt,
}

fn snapshot<T: ReceiveTerminationPolicy>(
    receiver: &Receiver<T>,
    connection: &ConnectionReceiveFlowController,
) -> Snapshot {
    let parts = receiver.parts();
    Snapshot {
        accounted_end: parts.accounted_end(),
        final_size: parts.final_size(),
        delivered_end: parts.delivered_end(),
        held_len: parts.buffer.held_len(),
        destroyed: parts.buffer.is_destroyed(),
        reset: receiver.remote_reset(),
        pending_stop: receiver.pending_stop(),
        acceptance: receiver.acceptance_limit(),
        delivery: receiver.delivery_limit(),
        advertisement: receiver.advertisement(),
        flow_events: parts.flow_events.clone(),
        termination_events: parts.event_kinds(),
        used: connection.used(),
        released: connection.released(),
    }
}

/// Runs a frame that is expected to violate the protocol, checks that the
/// receiver and the connection are as before it, and returns the violation.
fn violation<T, E>(
    receiver: &mut Receiver<T>,
    connection: &mut ConnectionReceiveFlowController,
    frame: impl FnOnce(&mut Receiver<T>, &mut ConnectionReceiveFlowController) -> Result<(), E>,
) -> E
where
    T: ReceiveTerminationPolicy,
    E: Debug,
{
    let before = snapshot(receiver, connection);
    let error = frame(receiver, connection).expect_err("the frame violates the protocol");
    assert_eq!(snapshot(receiver, connection), before, "{error:?}");
    error
}

fn stream_violation<T: ReceiveTerminationPolicy>(
    receiver: &mut Receiver<T>,
    connection: &mut ConnectionReceiveFlowController,
    frame: StreamFrame,
) -> OnStreamFrameError {
    violation(receiver, connection, |receiver, connection| {
        receiver.on_stream_frame(frame, connection)
    })
}

fn reset_violation<T: ReceiveTerminationPolicy>(
    receiver: &mut Receiver<T>,
    connection: &mut ConnectionReceiveFlowController,
    frame: ResetStreamFrame,
) -> OnResetStreamError {
    violation(receiver, connection, |receiver, connection| {
        receiver.on_reset_stream(frame, connection)
    })
}

fn closed() -> ReadError<&'static str, TestCloseCause> {
    ReadError::ConnectionClosed {
        source: ConnectionClosedError::new(close_reason()),
    }
}

mod stream_frame {
    use super::*;

    #[test]
    fn final_size_changed() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_stream_frame(stream(0, 100, true), &mut connection)
            .unwrap();
        let error = stream_violation(&mut receiver, &mut connection, stream(0, 200, true));
        assert_eq!(
            error,
            OnStreamFrameError::FinalSizeChanged {
                source: FinalSizeChangeError::check(v(100), v(200)).unwrap_err(),
            }
        );
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::FINAL_SIZE_ERROR
        );
    }

    #[test]
    fn beyond_final_size() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_stream_frame(stream(0, 100, true), &mut connection)
            .unwrap();
        let error = stream_violation(&mut receiver, &mut connection, stream(90, 20, false));
        assert_eq!(
            error,
            OnStreamFrameError::BeyondFinalSize {
                source: BeyondFinalSizeError::check(v(100), v(110)).unwrap_err(),
            }
        );
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::FINAL_SIZE_ERROR
        );
    }

    #[test]
    fn final_size_below_received() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_stream_frame(stream(0, 100, false), &mut connection)
            .unwrap();
        let error = stream_violation(&mut receiver, &mut connection, stream(0, 50, true));
        assert_eq!(
            error,
            OnStreamFrameError::FinalSizeBelowReceived {
                source: FinalSizeBelowReceivedError::check(v(50), v(100)).unwrap_err(),
            }
        );
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::FINAL_SIZE_ERROR
        );
    }

    #[test]
    fn data_within_the_final_size_and_a_repeated_fin_are_fine() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_stream_frame(stream(50, 50, true), &mut connection)
            .unwrap();
        receiver
            .on_stream_frame(stream(0, 100, true), &mut connection)
            .unwrap();
        receiver
            .on_stream_frame(stream(10, 10, false), &mut connection)
            .unwrap();
    }

    #[test]
    fn stream_limit_exceeded() {
        let (mut receiver, mut connection) = receiver_with(keep_all(), 1000, 1 << 20);
        receiver
            .on_stream_frame(stream(0, 900, false), &mut connection)
            .unwrap();
        let error = stream_violation(&mut receiver, &mut connection, stream(900, 101, false));
        assert_eq!(
            error,
            OnStreamFrameError::StreamLimitExceeded {
                source: StreamLimitExceededError::check(v(1001), v(1000)).unwrap_err(),
            }
        );
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::FLOW_CONTROL_ERROR
        );
        // The connection usage was not charged for the rejected frame.
        assert_eq!(connection.used(), v(900));
    }

    #[test]
    fn connection_limit_exceeded() {
        let (mut receiver, mut connection) = receiver_with(keep_all(), 1000, 100);
        let error = stream_violation(&mut receiver, &mut connection, stream(0, 101, false));
        assert_eq!(
            error,
            OnStreamFrameError::ConnectionLimitExceeded {
                source: RecordUsageError {
                    used: VarInt::ZERO,
                    increase: v(101),
                    limit: v(100),
                },
            }
        );
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::FLOW_CONTROL_ERROR
        );
        assert_eq!(connection.used(), VarInt::ZERO);
    }

    #[test]
    fn offset_overflow() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        let frame = StreamFrame {
            offset: VarInt::MAX,
            data: Bytes::from_static(b"x"),
            fin: false,
        };
        let error = stream_violation(&mut receiver, &mut connection, frame);
        assert_eq!(
            error,
            OnStreamFrameError::OffsetOverflow {
                offset: VarInt::MAX,
                len: 1,
            }
        );
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::FRAME_ENCODING_ERROR
        );
    }

    /// The violating frame carries payload the buffer would keep, and a FIN
    /// the policies would observe.
    #[test]
    fn violating_payload_is_not_kept() {
        let (mut receiver, mut connection) = receiver_with(keep_all(), 1000, 1 << 20);
        receiver
            .on_stream_frame(stream(0, 100, false), &mut connection)
            .unwrap();
        stream_violation(&mut receiver, &mut connection, stream(500, 600, true));
        assert_eq!(receiver.parts().buffer.held_len(), 100);
        assert_eq!(receiver.parts().final_size(), None);
    }
}

mod reset_stream {
    use super::*;

    #[test]
    fn final_size_changed() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_stream_frame(stream(0, 100, true), &mut connection)
            .unwrap();
        let error = reset_violation(&mut receiver, &mut connection, reset(1, 200));
        assert_eq!(
            error,
            OnResetStreamError::FinalSizeChanged {
                source: FinalSizeChangeError::check(v(100), v(200)).unwrap_err(),
            }
        );
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::FINAL_SIZE_ERROR
        );
    }

    #[test]
    fn final_size_below_received() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_stream_frame(stream(0, 100, false), &mut connection)
            .unwrap();
        let error = reset_violation(&mut receiver, &mut connection, reset(1, 50));
        assert_eq!(
            error,
            OnResetStreamError::FinalSizeBelowReceived {
                source: FinalSizeBelowReceivedError::check(v(50), v(100)).unwrap_err(),
            }
        );
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::FINAL_SIZE_ERROR
        );
    }

    /// A later `RESET_STREAM` with another error code is no violation: the
    /// first code is kept and nothing else happens.
    #[test]
    fn a_later_error_code_is_ignored() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_stream_frame(stream(0, 40, false), &mut connection)
            .unwrap();
        receiver
            .on_reset_stream(reset(1, 100), &mut connection)
            .unwrap();
        let before = snapshot(&receiver, &connection);
        assert_eq!(
            receiver.on_reset_stream(reset(2, 100), &mut connection),
            Ok(())
        );
        // Only the flow control policy observes that a frame came in.
        let mut after = snapshot(&receiver, &connection);
        assert_eq!(after.flow_events.pop(), Some(ReceiveFlowEvent::Received));
        assert_eq!(after, before);
        assert_eq!(
            receiver.remote_reset(),
            Some(RemoteReset {
                code: c(1),
                final_size: v(100),
            })
        );
        let (read, end) = read_all(&mut receiver);
        assert_eq!(read, data(0, 40));
        assert_eq!(end, reset_error(1, 100, false));
        // The connection is not closing: frames are still taken.
        receiver
            .on_stream_frame(stream(40, 60, false), &mut connection)
            .unwrap();
        assert_eq!(connection.used(), v(100));
    }

    /// A later reset with another error code and another final size still
    /// violates the final size.
    #[test]
    fn a_later_error_code_does_not_excuse_the_final_size() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_reset_stream(reset(1, 100), &mut connection)
            .unwrap();
        let error = reset_violation(&mut receiver, &mut connection, reset(2, 200));
        assert_eq!(
            error,
            OnResetStreamError::FinalSizeChanged {
                source: FinalSizeChangeError::check(v(100), v(200)).unwrap_err(),
            }
        );
    }

    /// The entry point every kind of reset shares reports the same
    /// violations, wrapped.
    #[test]
    fn the_shared_entry_point_wraps_the_violation() {
        let (mut receiver, mut connection) = receiver_with(keep_all(), 1000, 1 << 20);
        let error = violation(&mut receiver, &mut connection, |receiver, connection| {
            receiver.on_remote_reset(reset(1, 1001), connection)
        });
        assert_eq!(
            error,
            OnRemoteResetError::Violation {
                source: OnResetStreamError::StreamLimitExceeded {
                    source: StreamLimitExceededError::check(v(1001), v(1000)).unwrap_err(),
                },
            }
        );
        receiver.connection_closed(close_reason());
        assert_eq!(receiver.read_chunk(), Err(closed()));
    }

    #[test]
    fn stream_limit_exceeded() {
        let (mut receiver, mut connection) = receiver_with(keep_all(), 1000, 1 << 20);
        let error = reset_violation(&mut receiver, &mut connection, reset(1, 1001));
        assert_eq!(
            error,
            OnResetStreamError::StreamLimitExceeded {
                source: StreamLimitExceededError::check(v(1001), v(1000)).unwrap_err(),
            }
        );
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::FLOW_CONTROL_ERROR
        );
    }

    #[test]
    fn connection_limit_exceeded() {
        let (mut receiver, mut connection) = receiver_with(keep_all(), 1000, 100);
        let error = reset_violation(&mut receiver, &mut connection, reset(1, 101));
        assert_eq!(
            error,
            OnResetStreamError::ConnectionLimitExceeded {
                source: RecordUsageError {
                    used: VarInt::ZERO,
                    increase: v(101),
                    limit: v(100),
                },
            }
        );
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::FLOW_CONTROL_ERROR
        );
    }

    /// A reset that agrees with everything known is not a violation, also
    /// when it repeats the code of an earlier reset.
    #[test]
    fn agreeing_resets_are_fine() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_stream_frame(stream(0, 100, true), &mut connection)
            .unwrap();
        receiver
            .on_reset_stream(reset(1, 100), &mut connection)
            .unwrap();
        receiver
            .on_reset_stream(reset(1, 100), &mut connection)
            .unwrap();
    }
}

/// The stream between a violation and the connection's closure.
mod awaiting_the_close {
    use super::*;

    /// A receiver holding 100 readable bytes whose next frame violates the
    /// protocol, with the violation already returned.
    fn violated() -> (
        Receiver<impl ReceiveTerminationPolicy<Reason = &'static str>>,
        ConnectionReceiveFlowController,
    ) {
        let (mut receiver, mut connection) = receiver_with(keep_all(), 1000, 1 << 20);
        receiver
            .on_stream_frame(stream(0, 100, false), &mut connection)
            .unwrap();
        stream_violation(&mut receiver, &mut connection, stream(900, 101, false));
        (receiver, connection)
    }

    #[test]
    fn a_read_does_not_complete() {
        let (mut receiver, _connection) = violated();
        // Held data is not delivered, and an empty target does not report
        // that it makes no progress.
        assert_eq!(receiver.read_chunk(), Ok(ReadOutcome::Wait));
        assert_eq!(receiver.read_into(&mut Vec::new()), Ok(ReadOutcome::Wait));
        let mut empty = [0u8; 0];
        assert_eq!(
            receiver.read_into(&mut &mut empty[..]),
            Ok(ReadOutcome::Wait)
        );
        assert_eq!(receiver.parts().delivered_end(), VarInt::ZERO);
        assert!(!receiver.parts().buffer.is_destroyed());
    }

    #[test]
    fn a_read_does_not_judge_a_terminal_result() {
        // A policy that destroyed the buffer on the reset would make the
        // next read commit a local termination.
        let (mut receiver, mut connection) = new_receiver(scripted(|event, _| match event {
            TerminationEvent::RemoteReset => destroy("reset"),
            _ => TerminationDecision::keep(),
        }));
        receiver
            .on_reset_stream(reset(1, 100), &mut connection)
            .unwrap();
        stream_violation(&mut receiver, &mut connection, stream(0, 200, false));
        assert_eq!(receiver.read_chunk(), Ok(ReadOutcome::Wait));
        receiver.connection_closed(close_reason());
        assert_eq!(receiver.read_chunk(), Err(closed()));
    }

    #[test]
    fn a_committed_result_is_repeated() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_stream_frame(stream(0, 10, true), &mut connection)
            .unwrap();
        let (_, end) = read_all(&mut receiver);
        assert_eq!(end, Ok(ReadOutcome::End));
        stream_violation(&mut receiver, &mut connection, stream(0, 5, true));
        assert_eq!(receiver.read_chunk(), Ok(ReadOutcome::End));
        receiver.connection_closed(close_reason());
        assert_eq!(receiver.read_chunk(), Err(closed()));
    }

    #[test]
    fn a_dropped_reader_stays_dropped() {
        let (mut receiver, _connection) = violated();
        receiver.reader_dropped();
        assert_eq!(receiver.read_chunk(), Err(ReadError::ReaderDropped));
        receiver.connection_closed(close_reason());
        assert_eq!(receiver.read_chunk(), Err(ReadError::ReaderDropped));
    }

    #[test]
    fn frames_are_ignored() {
        let (mut receiver, mut connection) = violated();
        let before = snapshot(&receiver, &connection);
        assert_eq!(
            receiver.on_stream_frame(stream(100, 100, true), &mut connection),
            Ok(())
        );
        assert_eq!(
            receiver.on_stream_frame(stream(0, 200, true), &mut connection),
            Ok(())
        );
        assert_eq!(
            receiver.on_reset_stream(reset(1, 300), &mut connection),
            Ok(())
        );
        receiver.on_stream_data_blocked(v(77));
        assert_eq!(snapshot(&receiver, &connection), before);
    }

    #[test]
    fn closing_reports_the_reason() {
        let (mut receiver, mut connection) = violated();
        receiver.connection_closed(close_reason());
        receiver.connection_closed(CloseReason::StatelessReset);
        assert_eq!(receiver.read_chunk(), Err(closed()));
        assert_eq!(
            receiver.closed().map(ConnectionClosedError::reason),
            Some(&close_reason())
        );
        assert!(receiver.parts().buffer.is_destroyed());
        assert_eq!(
            receiver.parts().count(TerminationEvent::ConnectionClosed),
            1
        );
        assert_eq!(
            receiver.stop(c(1)),
            Err(StopError::ConnectionClosed {
                source: ConnectionClosedError::new(close_reason()),
            })
        );
        // Frames stay ignored.
        assert_eq!(
            receiver.on_stream_frame(stream(0, 10, false), &mut connection),
            Ok(())
        );
    }

    #[test]
    fn a_stop_request_is_checked_as_usual() {
        let (mut receiver, _connection) = violated();
        assert_eq!(receiver.stop(c(1)), Ok(()));
        assert_eq!(
            receiver.stop(c(2)),
            Err(StopError::StopConflict {
                installed: c(1),
                requested: c(2),
            })
        );
    }

    #[test]
    fn the_policy_does_not_observe_a_blocked_peer() {
        let (mut receiver, _connection) = violated();
        receiver.on_stream_data_blocked(v(77));
        assert!(
            !receiver
                .parts()
                .flow_events
                .contains(&ReceiveFlowEvent::PeerBlocked { limit: v(77) })
        );
    }
}

mod after_the_close {
    use super::*;

    #[test]
    fn frames_are_ignored() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_stream_frame(stream(0, 100, false), &mut connection)
            .unwrap();
        receiver.connection_closed(close_reason());
        let before = snapshot(&receiver, &connection);
        assert_eq!(
            receiver.on_stream_frame(stream(100, 100, true), &mut connection),
            Ok(())
        );
        assert_eq!(
            receiver.on_reset_stream(reset(1, 300), &mut connection),
            Ok(())
        );
        receiver.on_stream_data_blocked(v(77));
        assert_eq!(snapshot(&receiver, &connection), before);
        assert_eq!(receiver.read_chunk(), Err(closed()));
    }
}
