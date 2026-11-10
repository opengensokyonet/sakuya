//! Reception completes from the ranges the frames stated, whatever became of
//! the payload.
use super::*;
use crate::receive::stop::{StopError, StopNotNeededReason};

fn completed<T: ReceiveTerminationPolicy>(receiver: &Receiver<T>) -> usize {
    receiver.parts().count(TerminationEvent::DataComplete)
}

/// The reader is gone and the buffer destroyed before the rest arrives, so
/// the destroyed buffer never sees the data that completes the stream.
#[test]
fn data_arriving_after_destruction_completes_the_stream() {
    let (mut receiver, mut connection) = new_receiver(FollowingTermination::new(c(9)));
    receiver
        .on_stream_frame(stream(0, 50, false), &mut connection)
        .unwrap();
    receiver.reader_dropped();
    assert!(receiver.parts().buffer.is_destroyed());
    assert_eq!(receiver.pending_stop(), Some(c(9)));
    assert_eq!(completed(&receiver), 0);
    receiver
        .on_stream_frame(stream(50, 50, true), &mut connection)
        .unwrap();
    assert_eq!(receiver.parts().buffer.held_len(), 0);
    assert_eq!(completed(&receiver), 1);
    assert_eq!(receiver.pending_stop(), None);
}

#[test]
fn a_gap_filled_after_destruction_completes_the_stream() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(50, 50, true), &mut connection)
        .unwrap();
    receiver.reader_dropped();
    assert_eq!(completed(&receiver), 0);
    receiver.stop(c(1)).unwrap();
    receiver
        .on_stream_frame(stream(0, 50, false), &mut connection)
        .unwrap();
    assert_eq!(completed(&receiver), 1);
    assert_eq!(receiver.pending_stop(), None);
}

#[test]
fn complete_data_after_destruction_needs_no_request() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 50, false), &mut connection)
        .unwrap();
    receiver.reader_dropped();
    receiver
        .on_stream_frame(stream(50, 50, true), &mut connection)
        .unwrap();
    assert_eq!(
        receiver.stop(c(1)),
        Err(StopError::StopNotNeeded {
            reason: StopNotNeededReason::DataComplete,
        })
    );
}

/// The acceptance limit cuts every later payload, yet the frames still state
/// the ranges that complete the stream.
#[test]
fn data_cut_at_the_acceptance_limit_still_counts() {
    let (mut receiver, mut connection) = new_receiver(scripted(|event, _| match event {
        TerminationEvent::StopSent => {
            restrict(BoundaryUpdate::Fix(v(100)), BoundaryUpdate::Keep, "cut")
        }
        _ => TerminationDecision::keep(),
    }));
    receiver
        .on_stream_frame(stream(0, 100, false), &mut connection)
        .unwrap();
    receiver.stop(c(1)).unwrap();
    receiver.on_stop_sent().unwrap();
    receiver
        .on_stream_frame(stream(200, 100, true), &mut connection)
        .unwrap();
    assert_eq!(completed(&receiver), 0);
    receiver
        .on_stream_frame(stream(100, 100, false), &mut connection)
        .unwrap();
    assert_eq!(receiver.parts().buffer.held_len(), 100);
    assert_eq!(completed(&receiver), 1);
}

/// Releasing the held tail leaves the ranges recorded.
#[test]
fn data_released_by_a_delivery_limit_still_counts() {
    let (mut receiver, mut connection) = new_receiver(scripted(|event, _| match event {
        TerminationEvent::StopSent => restrict(
            BoundaryUpdate::Keep,
            BoundaryUpdate::Fix(v(200)),
            "released",
        ),
        _ => TerminationDecision::keep(),
    }));
    receiver
        .on_stream_frame(stream(0, 500, false), &mut connection)
        .unwrap();
    receiver.stop(c(1)).unwrap();
    receiver.on_stop_sent().unwrap();
    assert_eq!(receiver.parts().buffer.held_len(), 200);
    receiver
        .on_stream_frame(stream(500, 100, true), &mut connection)
        .unwrap();
    assert_eq!(receiver.parts().buffer.held_len(), 200);
    assert_eq!(completed(&receiver), 1);
}

/// Delivered bytes are received bytes.
#[test]
fn delivered_data_counts() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 100, false), &mut connection)
        .unwrap();
    let (read, _) = read_all(&mut receiver);
    assert_eq!(read, data(0, 100));
    receiver
        .on_stream_frame(stream(100, 100, true), &mut connection)
        .unwrap();
    assert_eq!(completed(&receiver), 1);
}

/// Out of order, overlapping and repeated frames merge into the ranges that
/// complete the stream exactly when the last gap closes.
#[test]
fn out_of_order_overlapping_and_repeated_frames_merge() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    let frames = [
        stream(300, 50, true),
        stream(0, 100, false),
        stream(200, 100, false),
        stream(50, 100, false),
        stream(0, 100, false),
        stream(300, 50, true),
        stream(50, 100, false),
        stream(190, 20, false),
    ];
    for frame in frames {
        receiver.on_stream_frame(frame, &mut connection).unwrap();
        assert_eq!(completed(&receiver), 0, "[150, 190) is still missing");
    }
    // Adjacent to both neighbours on each side.
    receiver
        .on_stream_frame(stream(150, 40, false), &mut connection)
        .unwrap();
    assert_eq!(completed(&receiver), 1);
}

#[test]
fn a_gap_of_one_byte_keeps_the_stream_incomplete() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 99, false), &mut connection)
        .unwrap();
    receiver
        .on_stream_frame(stream(100, 100, true), &mut connection)
        .unwrap();
    assert_eq!(completed(&receiver), 0);
    receiver
        .on_stream_frame(stream(99, 1, false), &mut connection)
        .unwrap();
    assert_eq!(completed(&receiver), 1);
}

/// A frame that violates the protocol records no range: had its range been
/// kept, the stream below would be complete when the connection closes.
#[test]
fn a_violating_frame_records_no_range() {
    let violating = [
        // Beyond the final size of 100.
        stream(0, 150, false),
        // Changes the final size.
        stream(0, 60, true),
    ];
    for frame in violating {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_stream_frame(stream(50, 50, true), &mut connection)
            .unwrap();
        assert!(receiver.on_stream_frame(frame, &mut connection).is_err());
        receiver.connection_closed(close_reason());
        let (event, view) = receiver.parts().events.last().unwrap();
        assert_eq!(*event, TerminationEvent::ConnectionClosed);
        assert!(!view.fully_received);
        assert_eq!(completed(&receiver), 0);
    }
}
