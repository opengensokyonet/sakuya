use super::*;
use sakuya_wire::stream_id::StreamId;

fn v(value: u32) -> VarInt {
    VarInt::from_u32(value)
}

fn stream() -> StreamId {
    StreamId::from(VarInt::ZERO)
}

/// Appends `length` bytes, each holding the low byte of its offset.
fn append(
    buffer: &mut BasicSendBuffer,
    connection: &mut ConnectionSendFlowController,
    length: u32,
) -> Bytes {
    let start = buffer.written_end().get();
    let bytes: Bytes = (start..start + u64::from(length))
        .map(|offset| offset as u8)
        .collect();
    let reservation = connection.reserve(stream(), v(length)).unwrap();
    buffer.append(bytes.clone(), reservation);
    bytes
}

fn retained_ranges(buffer: &BasicSendBuffer) -> Vec<(u64, usize)> {
    buffer
        .retained()
        .map(|(offset, bytes)| (offset.get(), bytes.len()))
        .collect()
}

#[test]
fn append_moves_bytes_without_copying() {
    let mut connection = ConnectionSendFlowController::new(v(1000));
    let mut buffer = BasicSendBuffer::new();
    let first = append(&mut buffer, &mut connection, 100);
    let second = append(&mut buffer, &mut connection, 50);
    assert_eq!(buffer.written_end(), v(150));
    let stored: Vec<_> = buffer.retained().collect();
    assert_eq!(stored[0].1.as_ptr(), first.as_ptr());
    assert_eq!(stored[1].1.as_ptr(), second.as_ptr());
    assert_eq!(stored[1].0, v(100));
    // Appending reserves nothing more and commits nothing.
    assert_eq!(connection.reserved(), v(150));
    assert_eq!(connection.committed(), VarInt::ZERO);
}

#[test]
#[should_panic(expected = "cover exactly the appended data")]
fn append_rejects_a_mismatched_reservation() {
    let mut connection = ConnectionSendFlowController::new(v(1000));
    let mut buffer = BasicSendBuffer::new();
    let reservation = connection.reserve(stream(), v(9)).unwrap();
    buffer.append(Bytes::from_static(b"ten bytes!"), reservation);
}

/// `send-side.md`: with 1000 unexposed bytes, `apply_reset(final_size = 800,
/// reliable_size = 600)` keeps the data below 600, keeps the reservations
/// below 800 and cancels the 200 beyond; lowering the reliable size to 200
/// afterwards keeps the coverage of 800.
#[test]
fn reset_retention_keeps_coverage_up_to_the_final_size() {
    let mut connection = ConnectionSendFlowController::new(v(2000));
    let mut buffer = BasicSendBuffer::new();
    for _ in 0..4 {
        append(&mut buffer, &mut connection, 250);
    }
    assert_eq!(connection.reserved(), v(1000));

    let retention = ResetRetention {
        final_size: v(800),
        reliable_size: v(600),
    };
    buffer.apply_reset(retention);
    assert_eq!(retained_ranges(&buffer), [(0, 250), (250, 250), (500, 100)]);
    assert_eq!(connection.reserved(), v(800));
    assert_eq!(buffer.written_end(), v(1000));

    // Repeating the same target releases nothing twice.
    buffer.apply_reset(retention);
    assert_eq!(connection.reserved(), v(800));

    buffer.apply_reset(ResetRetention {
        final_size: v(800),
        reliable_size: v(200),
    });
    assert_eq!(retained_ranges(&buffer), [(0, 200)]);
    assert_eq!(connection.reserved(), v(800));
    assert_eq!(connection.committed(), VarInt::ZERO);
}

#[test]
fn reset_slices_the_straddling_entry_without_copying() {
    let mut connection = ConnectionSendFlowController::new(v(1000));
    let mut buffer = BasicSendBuffer::new();
    let bytes = append(&mut buffer, &mut connection, 100);
    buffer.apply_reset(ResetRetention {
        final_size: v(100),
        reliable_size: v(30),
    });
    let (offset, kept) = buffer.retained().next().unwrap();
    assert_eq!((offset, kept.len()), (VarInt::ZERO, 30));
    assert_eq!(kept.as_ptr(), bytes.as_ptr());
    assert_eq!(kept[..], bytes[..30]);
}

#[test]
#[should_panic(expected = "no data after a reset")]
fn append_after_reset_panics() {
    let mut connection = ConnectionSendFlowController::new(v(1000));
    let mut buffer = BasicSendBuffer::new();
    append(&mut buffer, &mut connection, 10);
    buffer.apply_reset(ResetRetention {
        final_size: v(10),
        reliable_size: v(0),
    });
    append(&mut buffer, &mut connection, 10);
}

/// The settlement commits `max(E, usage_end) − E` and keeps `E` monotone;
/// a high-offset exposure commits the offsets it spans.
#[test]
fn exposure_commits_new_usage_once() {
    let mut connection = ConnectionSendFlowController::new(v(1000));
    let mut buffer = BasicSendBuffer::new();
    append(&mut buffer, &mut connection, 500);

    let exposed = buffer
        .expose_usage_through(v(300), ExposedEnd::Data, &mut connection)
        .unwrap();
    assert_eq!(exposed, v(300));
    assert_eq!(buffer.exposure_end(), v(300));
    assert_eq!(
        (connection.reserved(), connection.committed()),
        (v(200), v(300))
    );

    // A retransmission or an earlier range commits nothing again.
    let exposed = buffer
        .expose_usage_through(v(100), ExposedEnd::Data, &mut connection)
        .unwrap();
    assert_eq!(exposed, VarInt::ZERO);
    assert_eq!(buffer.exposure_end(), v(300));

    let exposed = buffer
        .expose_usage_through(v(450), ExposedEnd::Data, &mut connection)
        .unwrap();
    assert_eq!(exposed, v(150));
    assert_eq!(
        (connection.reserved(), connection.committed()),
        (v(50), v(450))
    );
    assert_eq!(connection.available(), v(500));
}

#[test]
fn exposure_rejects_usage_beyond_the_written_end() {
    let mut connection = ConnectionSendFlowController::new(v(1000));
    let mut buffer = BasicSendBuffer::new();
    append(&mut buffer, &mut connection, 100);
    let error = buffer
        .expose_usage_through(v(101), ExposedEnd::Data, &mut connection)
        .unwrap_err();
    assert_eq!(
        error,
        ExposeUsageError::BeyondWrittenEnd {
            usage_end: v(101),
            written_end: v(100),
        }
    );
    assert_eq!(connection.committed(), VarInt::ZERO);
}

#[test]
fn exposed_final_size_constrains_later_exposures() {
    let mut connection = ConnectionSendFlowController::new(v(1000));
    let mut buffer = BasicSendBuffer::new();
    append(&mut buffer, &mut connection, 100);
    buffer
        .expose_usage_through(v(60), ExposedEnd::Data, &mut connection)
        .unwrap();

    let error = buffer
        .expose_usage_through(v(50), ExposedEnd::FinalSize, &mut connection)
        .unwrap_err();
    assert_eq!(
        error,
        ExposeUsageError::FinalSizeBelowExposure {
            final_size: v(50),
            exposure_end: v(60),
        }
    );

    // A FIN at 80 fixes the exposed final size and commits up to it.
    let exposed = buffer
        .expose_usage_through(v(80), ExposedEnd::FinalSize, &mut connection)
        .unwrap();
    assert_eq!(exposed, v(20));
    assert_eq!(buffer.visibility().exposed_final_size(), Some(v(80)));

    let error = buffer
        .expose_usage_through(v(90), ExposedEnd::Data, &mut connection)
        .unwrap_err();
    assert_eq!(
        error,
        ExposeUsageError::BeyondFinalSize {
            usage_end: v(90),
            final_size: v(80),
        }
    );
    let error = buffer
        .expose_usage_through(v(100), ExposedEnd::FinalSize, &mut connection)
        .unwrap_err();
    assert_eq!(
        error,
        ExposeUsageError::FinalSizeMismatch {
            final_size: v(100),
            established: v(80),
        }
    );
    // Exposing the same final size again commits nothing.
    let exposed = buffer
        .expose_usage_through(v(80), ExposedEnd::FinalSize, &mut connection)
        .unwrap();
    assert_eq!(exposed, VarInt::ZERO);
    assert_eq!(connection.committed(), v(80));
}

/// A reset with reliable size zero still exposes its final size, though no
/// data remains to send.
#[test]
fn reset_final_size_is_exposed_without_data() {
    let mut connection = ConnectionSendFlowController::new(v(1000));
    let mut buffer = BasicSendBuffer::new();
    append(&mut buffer, &mut connection, 100);
    buffer.apply_reset(ResetRetention {
        final_size: v(70),
        reliable_size: VarInt::ZERO,
    });
    assert_eq!(retained_ranges(&buffer), []);
    assert_eq!(connection.reserved(), v(70));

    let error = buffer
        .expose_usage_through(v(80), ExposedEnd::Data, &mut connection)
        .unwrap_err();
    assert!(matches!(error, ExposeUsageError::BeyondFinalSize { .. }));
    let exposed = buffer
        .expose_usage_through(v(70), ExposedEnd::FinalSize, &mut connection)
        .unwrap();
    assert_eq!(exposed, v(70));
    assert_eq!(
        (connection.reserved(), connection.committed()),
        (v(0), v(70))
    );
}
