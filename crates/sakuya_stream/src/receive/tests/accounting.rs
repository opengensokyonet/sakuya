//! Acceptance, accounting and the protocol errors it detects.
use super::*;
use crate::stream_end::{BeyondFinalSizeError, FinalSizeChangeError, ResetCodeChangeError};
use sakuya_wire::frame::reset_stream_at::ReliableSizeError;

/// [100, 200) with FIN, then [0, 100): data is contiguous only after the
/// second frame, and the end of stream comes after reading to 200.
#[test]
fn out_of_order_fin_then_fill() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(100, 100, true), &mut connection)
        .unwrap();
    assert_eq!(receiver.read_chunk(), Ok(ReadOutcome::Wait));
    receiver
        .on_stream_frame(stream(0, 100, false), &mut connection)
        .unwrap();
    let (read, end) = read_all(&mut receiver);
    assert_eq!(read, data(0, 200));
    assert_eq!(end, Ok(ReadOutcome::End));
    assert_eq!(receiver.read_chunk(), Ok(ReadOutcome::End));
}

/// The examples of the before-and-after accounting: [100, 200) accounts up
/// to 200, filling [0, 100) adds nothing, and a reset with final size 300
/// adds 100 without adding readable data.
#[test]
fn accounting_follows_the_highest_end() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(100, 100, false), &mut connection)
        .unwrap();
    assert_eq!(connection.used(), v(200));
    receiver
        .on_stream_frame(stream(0, 100, false), &mut connection)
        .unwrap();
    assert_eq!(connection.used(), v(200));
    receiver
        .on_reset_stream(reset(1, 300), &mut connection)
        .unwrap();
    assert_eq!(connection.used(), v(300));
    let (read, end) = read_all(&mut receiver);
    assert_eq!(read, data(0, 200));
    assert_eq!(end, reset_error(1, 300, 0, false));
}

#[test]
fn small_frame_accounts_up_to_its_end() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(100, 10, false), &mut connection)
        .unwrap();
    assert_eq!(connection.used(), v(110));
    receiver
        .on_stream_frame(stream(0, 100, false), &mut connection)
        .unwrap();
    assert_eq!(connection.used(), v(110));
    // Duplicates add nothing either.
    receiver
        .on_stream_frame(stream(0, 110, false), &mut connection)
        .unwrap();
    assert_eq!(connection.used(), v(110));
    assert!(
        receiver
            .parts()
            .flow_events
            .iter()
            .filter(|event| **event == ReceiveFlowEvent::Received)
            .count()
            == 3
    );
}

/// Data accepted up to 768 and a reset with final size 1024: accounting
/// reaches 1024 while data still ends at 768.
#[test]
fn reset_extends_accounting_beyond_the_data() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 768, false), &mut connection)
        .unwrap();
    receiver
        .on_reset_stream(reset(1, 1024), &mut connection)
        .unwrap();
    assert_eq!(receiver.parts().accounted_end(), v(1024));
    assert_eq!(connection.used(), v(1024));
    let (read, _) = read_all(&mut receiver);
    assert_eq!(read.len(), 768);
}

#[test]
fn exceeding_the_stream_limit_is_a_protocol_error() {
    let (mut receiver, mut connection) = receiver_with(keep_all(), 1000, 1 << 20);
    receiver
        .on_stream_frame(stream(0, 900, false), &mut connection)
        .unwrap();
    let failure = receiver
        .on_stream_frame(stream(900, 101, false), &mut connection)
        .unwrap_err();
    let error = protocol(failure.clone());
    assert_eq!(
        error,
        ProtocolError::StreamLimitExceeded {
            accounted_end: v(1001),
            limit: v(1000),
        }
    );
    assert_eq!(
        error.transport_error_code(),
        TransportErrorCode::FLOW_CONTROL_ERROR
    );
    // The connection usage was not charged for the rejected frame.
    assert_eq!(connection.used(), v(900));
    // The failure persists: later input and reads report it first, and the
    // data held before is not readable.
    assert_eq!(
        receiver.on_stream_frame(stream(0, 10, false), &mut connection),
        Err(failure.clone())
    );
    assert_eq!(
        receiver.read_chunk(),
        Err(ReadError::Connection {
            source: failure.clone()
        })
    );
    assert_eq!(receiver.failure(), Some(failure));
    assert!(
        receiver
            .parts()
            .event_kinds()
            .contains(&TerminationEvent::ConnectionClosed)
    );
}

#[test]
fn reset_beyond_the_stream_limit_is_a_protocol_error() {
    let (mut receiver, mut connection) = receiver_with(keep_all(), 1000, 1 << 20);
    let failure = receiver
        .on_reset_stream(reset(1, 1001), &mut connection)
        .unwrap_err();
    assert!(matches!(
        protocol(failure),
        ProtocolError::StreamLimitExceeded { .. }
    ));
}

#[test]
fn exceeding_the_connection_limit_is_a_protocol_error() {
    let (mut receiver, mut connection) = receiver_with(keep_all(), 1000, 100);
    let failure = receiver
        .on_stream_frame(stream(0, 101, false), &mut connection)
        .unwrap_err();
    let error = protocol(failure);
    assert!(matches!(
        error,
        ProtocolError::ConnectionLimitExceeded { .. }
    ));
    assert_eq!(
        error.transport_error_code(),
        TransportErrorCode::FLOW_CONTROL_ERROR
    );
    assert_eq!(connection.used(), VarInt::ZERO);
}

#[test]
fn opened_limit_admits_more_and_only_grows() {
    let (mut receiver, mut connection) = receiver_with(keep_all(), 1000, 1 << 20);
    receiver.open_limit(v(2000));
    receiver.open_limit(v(1500));
    assert_eq!(receiver.opened_limit(), v(2000));
    receiver
        .on_stream_frame(stream(0, 2000, false), &mut connection)
        .unwrap();
    assert_eq!(
        receiver
            .parts()
            .flow_events
            .iter()
            .filter(|event| **event == ReceiveFlowEvent::LimitOpened)
            .count(),
        1
    );
}

/// The intent is replaced freely, and the opened limit is kept apart from
/// it.
#[test]
fn advertisement_intent_is_replaceable() {
    let (mut receiver, mut connection) = receiver_with(keep_all(), 4096, 1 << 20);
    let intent = receiver.parts().intent.clone();
    assert_eq!(receiver.advertisement(), None);
    intent.set(AdvertisementIntent::Advertise {
        target_limit: v(8192),
    });
    assert_eq!(receiver.advertisement(), Some(v(8192)));
    intent.set(AdvertisementIntent::Advertise {
        target_limit: v(12288),
    });
    assert_eq!(receiver.advertisement(), Some(v(12288)));
    intent.set(AdvertisementIntent::Withhold);
    assert_eq!(receiver.advertisement(), None);
    assert_eq!(receiver.opened_limit(), v(4096));

    // Once 8192 may be visible, withdrawing the intent keeps it open.
    receiver.open_limit(v(8192));
    assert_eq!(receiver.opened_limit(), v(8192));
    intent.set(AdvertisementIntent::Advertise {
        target_limit: v(6000),
    });
    assert_eq!(receiver.advertisement(), None);
    receiver
        .on_stream_frame(stream(0, 8192, false), &mut connection)
        .unwrap();

    // A known final size needs no further increase.
    intent.set(AdvertisementIntent::Advertise {
        target_limit: v(20000),
    });
    assert_eq!(receiver.advertisement(), Some(v(20000)));
    receiver
        .on_stream_frame(stream(8192, 0, true), &mut connection)
        .unwrap();
    assert_eq!(receiver.advertisement(), None);
}

#[test]
fn peer_blocked_reaches_the_flow_control_policy() {
    let (mut receiver, _connection) = new_receiver(keep_all());
    receiver.on_stream_data_blocked(v(77));
    assert_eq!(
        receiver.parts().flow_events,
        vec![ReceiveFlowEvent::PeerBlocked { limit: v(77) }]
    );
}

#[test]
fn final_size_errors() {
    fn fails<T: ReceiveTerminationPolicy>(
        receiver: &mut Receiver<T>,
        connection: &mut ConnectionReceiveFlowController,
        frame: StreamFrame,
    ) -> ProtocolError {
        protocol(receiver.on_stream_frame(frame, connection).unwrap_err())
    }

    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 100, true), &mut connection)
        .unwrap();
    let error = fails(&mut receiver, &mut connection, stream(0, 200, true));
    assert_eq!(
        error,
        ProtocolError::FinalSizeChanged {
            source: FinalSizeChangeError::check(v(100), v(200)).unwrap_err(),
        }
    );
    assert_eq!(
        error.transport_error_code(),
        TransportErrorCode::FINAL_SIZE_ERROR
    );

    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 100, true), &mut connection)
        .unwrap();
    assert_eq!(
        fails(&mut receiver, &mut connection, stream(90, 20, false)),
        ProtocolError::BeyondFinalSize {
            source: BeyondFinalSizeError::check(v(100), v(110)).unwrap_err(),
        }
    );

    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 100, false), &mut connection)
        .unwrap();
    assert_eq!(
        fails(&mut receiver, &mut connection, stream(0, 50, true)),
        ProtocolError::FinalSizeBelowReceived {
            final_size: v(50),
            accounted_end: v(100),
        }
    );

    // Data within the final size, and FIN repeated, are fine.
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
fn reset_errors() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 100, true), &mut connection)
        .unwrap();
    let failure = receiver
        .on_reset_stream(reset(1, 200), &mut connection)
        .unwrap_err();
    assert!(matches!(
        protocol(failure),
        ProtocolError::FinalSizeChanged { .. }
    ));

    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 100, false), &mut connection)
        .unwrap();
    let failure = receiver
        .on_reset_stream(reset(1, 50), &mut connection)
        .unwrap_err();
    assert!(matches!(
        protocol(failure),
        ProtocolError::FinalSizeBelowReceived { .. }
    ));

    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_reset_stream_at(reset_at(1, 100, 50), &mut connection)
        .unwrap();
    let error = protocol(
        receiver
            .on_reset_stream(reset(2, 100), &mut connection)
            .unwrap_err(),
    );
    assert_eq!(
        error,
        ProtocolError::ResetCodeChanged {
            source: ResetCodeChangeError::check(c(1), c(2)).unwrap_err(),
        }
    );
    assert_eq!(
        error.transport_error_code(),
        TransportErrorCode::STREAM_STATE_ERROR
    );

    let (mut receiver, mut connection) = new_receiver(keep_all());
    let error = protocol(
        receiver
            .on_reset_stream_at(reset_at(1, 100, 101), &mut connection)
            .unwrap_err(),
    );
    assert_eq!(
        error,
        ProtocolError::ReliableSizeExceedsFinalSize {
            source: ReliableSizeError::check(v(100), v(101)).unwrap_err(),
        }
    );
    assert_eq!(
        error.transport_error_code(),
        TransportErrorCode::FRAME_ENCODING_ERROR
    );
}

#[test]
fn offset_overflow_is_a_frame_encoding_error() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    let frame = StreamFrame {
        offset: VarInt::MAX,
        data: Bytes::from_static(b"x"),
        fin: false,
    };
    let error = protocol(
        receiver
            .on_stream_frame(frame, &mut connection)
            .unwrap_err(),
    );
    assert!(matches!(error, ProtocolError::OffsetOverflow { .. }));
    assert_eq!(
        error.transport_error_code(),
        TransportErrorCode::FRAME_ENCODING_ERROR
    );
}

/// A STREAM frame crossing the acceptance limit hands only the part below it
/// to the buffer, but the whole frame is accounted.
#[test]
fn frame_across_the_acceptance_limit() {
    let (mut receiver, mut connection) = new_receiver(scripted(|event, _| match event {
        TerminationEvent::StopSent => {
            restrict(BoundaryUpdate::Fix(v(150)), BoundaryUpdate::Keep, "stop")
        }
        _ => TerminationDecision::keep(),
    }));
    receiver.stop(c(1)).unwrap();
    receiver.on_stop_sent().unwrap();
    receiver
        .on_stream_frame(stream(100, 200, false), &mut connection)
        .unwrap();
    assert_eq!(receiver.parts().buffer.held_len(), 50);
    assert_eq!(connection.used(), v(300));
    receiver
        .on_stream_frame(stream(300, 0, true), &mut connection)
        .unwrap();
    assert_eq!(receiver.parts().final_size(), Some(v(300)));
}

#[test]
fn released_progress_reaches_the_connection() {
    let (mut receiver, mut connection) = new_receiver(scripted(|event, _| match event {
        TerminationEvent::RemoteReset => fix_both(150, "reset"),
        _ => TerminationDecision::keep(),
    }));
    receiver
        .on_stream_frame(stream(0, 200, false), &mut connection)
        .unwrap();
    assert_eq!(connection.released(), VarInt::ZERO);
    let mut target = vec![0; 0];
    let mut limited = (&mut target).limit(50);
    receiver.read_into(&mut limited).unwrap();
    receiver.report_release(&mut connection).unwrap();
    assert_eq!(connection.released(), v(50));
    // The reset fixes delivery at 150: [150, 300) no longer needs holding.
    receiver
        .on_reset_stream(reset(1, 300), &mut connection)
        .unwrap();
    assert_eq!(connection.released(), v(200));
    let (read, _) = read_all(&mut receiver);
    assert_eq!(read, data(50, 100));
    receiver.report_release(&mut connection).unwrap();
    assert_eq!(connection.released(), v(300));
}

/// A release reported to a controller that never recorded the usage fails
/// and stays due for the controller that did.
#[test]
fn release_to_another_controller_fails_and_stays_due() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 100, false), &mut connection)
        .unwrap();
    let (read, _) = read_all(&mut receiver);
    assert_eq!(read.len(), 100);
    let mut other = ConnectionReceiveFlowController::new(v(1 << 20));
    assert_eq!(
        receiver.report_release(&mut other),
        Err(crate::connection_receive_flow::RecordReleaseError {
            released: VarInt::ZERO,
            increase: v(100),
            used: VarInt::ZERO,
        })
    );
    receiver.report_release(&mut connection).unwrap();
    assert_eq!(connection.released(), v(100));
}
