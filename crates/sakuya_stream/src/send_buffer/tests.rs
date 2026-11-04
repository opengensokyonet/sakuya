use super::covered_bytes::{CoveredBytes, CoveredBytesError};
use super::offset_map::OffsetMapStreamSendBuffer;
use super::visibility::{
    CoverError, FinalSizeBelowExposureError, FixFinalSizeError, UsageBeyondCoverageError,
    VisibilitySettlement,
};
use super::*;
use crate::connection_send_credit::{
    AtomicConnectionCreditReservation, AtomicConnectionSendFlowController,
    ConnectionCreditReservation, ConnectionSendFlowController,
};
use crate::stream_end::{BeyondFinalSizeError, FinalSizeChangeError};
use sakuya_wire::frame::reset_stream_at::ReliableSizeError;
use sakuya_wire::stream_id::StreamId;

type Buffer = OffsetMapStreamSendBuffer<AtomicConnectionCreditReservation>;
type Covered = CoveredBytes<AtomicConnectionCreditReservation>;

fn v(value: u32) -> VarInt {
    VarInt::from_u32(value)
}

fn stream() -> StreamId {
    StreamId::from(VarInt::ZERO)
}

/// Appends `length` bytes, each holding the low byte of its offset.
fn append(
    buffer: &mut Buffer,
    connection: &AtomicConnectionSendFlowController,
    length: u32,
) -> Bytes {
    let start = buffer.written_end().get();
    let bytes: Bytes = (start..start + u64::from(length))
        .map(|offset| offset as u8)
        .collect();
    let reservation = connection.reserve(stream(), v(length)).unwrap();
    buffer
        .append(CoveredBytes::new(bytes.clone(), reservation).unwrap())
        .unwrap();
    bytes
}

fn covered(connection: &AtomicConnectionSendFlowController, bytes: &'static [u8]) -> Covered {
    let length = VarInt::try_from(bytes.len()).unwrap();
    let reservation = connection.reserve(stream(), length).unwrap();
    CoveredBytes::new(Bytes::from_static(bytes), reservation).unwrap()
}

fn retention(final_size: u32, reliable_size: u32) -> ResetRetention {
    ResetRetention {
        final_size: v(final_size),
        reliable_size: v(reliable_size),
    }
}

fn retained_ranges(buffer: &Buffer) -> Vec<(u64, usize)> {
    buffer
        .retained()
        .map(|(offset, bytes)| (offset.get(), bytes.len()))
        .collect()
}

#[test]
fn append_moves_bytes_without_copying() {
    let connection = AtomicConnectionSendFlowController::new(v(1000));
    let mut buffer = OffsetMapStreamSendBuffer::new();
    let first = append(&mut buffer, &connection, 100);
    let second = append(&mut buffer, &connection, 50);
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
fn covered_bytes_reject_a_mismatched_reservation_and_return_both() {
    let connection = AtomicConnectionSendFlowController::new(v(1000));
    let reservation = connection.reserve(stream(), v(9)).unwrap();
    let data = Bytes::from_static(b"ten bytes!");
    let error = CoveredBytes::new(data.clone(), reservation).unwrap_err();
    assert!(matches!(error, CoveredBytesError::AmountMismatch { len, .. } if len == v(10)));
    let (bytes, reservation) = error.into_parts();
    assert_eq!(bytes, data);
    assert_eq!(reservation.amount(), v(9));
    assert_eq!(connection.reserved(), v(9));
}

#[test]
fn covered_bytes_report_their_parts() {
    let connection = AtomicConnectionSendFlowController::new(v(1000));
    let data = covered(&connection, b"abc");
    assert_eq!(data.len(), v(3));
    assert!(!data.is_empty());
    assert_eq!(data.bytes()[..], b"abc"[..]);
    assert_eq!(data.reservation().amount(), v(3));
    let (bytes, reservation): (Bytes, AtomicConnectionCreditReservation) = data.into_parts();
    assert_eq!((bytes.len(), reservation.amount()), (3, v(3)));
}

/// With 1000 unexposed bytes, `apply_reset(final_size = 800, reliable_size
/// = 600)` keeps the data below 600, keeps the reservations below 800 and
/// cancels the 200 beyond; lowering the reliable size to 200 afterwards
/// keeps the coverage of 800.
#[test]
fn reset_retention_keeps_coverage_up_to_the_final_size() {
    let connection = AtomicConnectionSendFlowController::new(v(2000));
    let mut buffer = OffsetMapStreamSendBuffer::new();
    for _ in 0..4 {
        append(&mut buffer, &connection, 250);
    }
    assert_eq!(connection.reserved(), v(1000));

    let retention = retention(800, 600);
    buffer.apply_reset(retention).unwrap();
    assert_eq!(retained_ranges(&buffer), [(0, 250), (250, 250), (500, 100)]);
    assert_eq!(connection.reserved(), v(800));
    assert_eq!(buffer.written_end(), v(1000));

    // Repeating the same target releases nothing twice.
    buffer.apply_reset(retention).unwrap();
    assert_eq!(connection.reserved(), v(800));

    buffer.apply_reset(self::retention(800, 200)).unwrap();
    assert_eq!(retained_ranges(&buffer), [(0, 200)]);
    assert_eq!(connection.reserved(), v(800));
    assert_eq!(connection.committed(), VarInt::ZERO);
}

#[test]
fn reset_slices_the_straddling_entry_without_copying() {
    let connection = AtomicConnectionSendFlowController::new(v(1000));
    let mut buffer = OffsetMapStreamSendBuffer::new();
    let bytes = append(&mut buffer, &connection, 100);
    buffer.apply_reset(retention(100, 30)).unwrap();
    let (offset, kept) = buffer.retained().next().unwrap();
    assert_eq!((offset, kept.len()), (VarInt::ZERO, 30));
    assert_eq!(kept.as_ptr(), bytes.as_ptr());
    assert_eq!(kept[..], bytes[..30]);
}

#[test]
fn append_after_reset_fails_and_returns_the_data() {
    let connection = AtomicConnectionSendFlowController::new(v(1000));
    let mut buffer = OffsetMapStreamSendBuffer::new();
    append(&mut buffer, &connection, 10);
    buffer.apply_reset(retention(10, 0)).unwrap();
    let error = buffer.append(covered(&connection, b"more")).unwrap_err();
    assert!(matches!(error, AppendError::AfterReset { .. }));
    assert_eq!(error.into_data().len(), v(4));
    assert_eq!(buffer.written_end(), v(10));
}

#[test]
fn append_after_an_exposed_fin_fails() {
    let connection = AtomicConnectionSendFlowController::new(v(1000));
    let mut buffer = OffsetMapStreamSendBuffer::new();
    append(&mut buffer, &connection, 10);
    buffer
        .expose_usage_through(v(10), ExposedContent::FinalSize)
        .unwrap();
    let error = buffer.append(covered(&connection, b"late")).unwrap_err();
    assert!(
        matches!(&error, AppendError::AfterFinalSize { source, .. } if source.final_size() == v(10))
    );
    drop(error.into_data());
    assert_eq!(buffer.written_end(), v(10));
    assert_eq!(connection.reserved(), VarInt::ZERO);
}

#[test]
fn reset_retention_is_checked_before_anything_changes() {
    let connection = AtomicConnectionSendFlowController::new(v(1000));
    let mut buffer = OffsetMapStreamSendBuffer::new();
    append(&mut buffer, &connection, 100);
    assert_eq!(
        buffer.apply_reset(retention(50, 60)),
        Err(ApplyResetError::ReliableSizeBeyondFinalSize {
            source: ReliableSizeError::check(v(50), v(60)).unwrap_err(),
        })
    );
    assert_eq!(
        buffer.apply_reset(retention(101, 0)),
        Err(ApplyResetError::FinalSizeBeyondWrittenEnd {
            source: FinalSizeBeyondWrittenEndError::check(v(101), v(100)).unwrap_err(),
        })
    );
    buffer
        .expose_usage_through(v(40), ExposedContent::Data)
        .unwrap();
    assert_eq!(
        buffer.apply_reset(retention(30, 0)),
        Err(ApplyResetError::FixFinalSize {
            source: FixFinalSizeError::BelowExposure {
                source: FinalSizeBelowExposureError::check(v(30), v(40)).unwrap_err(),
            },
        })
    );
    buffer.apply_reset(retention(70, 0)).unwrap();
    assert_eq!(
        buffer.apply_reset(retention(80, 0)),
        Err(ApplyResetError::FixFinalSize {
            source: FixFinalSizeError::Mismatch {
                source: FinalSizeChangeError::check(v(70), v(80)).unwrap_err(),
            },
        })
    );
    assert_eq!(buffer.retention(), Some(retention(70, 0)));
    assert_eq!(connection.reserved(), v(30));
}

#[test]
fn settlement_coverage_must_be_contiguous() {
    let connection = AtomicConnectionSendFlowController::new(v(1000));
    let mut settlement = VisibilitySettlement::new();
    settlement
        .cover(VarInt::ZERO, covered(&connection, b"abcd"))
        .unwrap();
    assert_eq!(settlement.coverage_end(), v(4));
    let error = settlement
        .cover(v(5), covered(&connection, b"ef"))
        .unwrap_err();
    assert!(matches!(
        error,
        CoverError::NotContiguous { offset, coverage_end, .. }
            if offset == v(5) && coverage_end == v(4)
    ));
    drop(error.into_data());
    settlement.fix_final_size(v(4)).unwrap();
    let error = settlement
        .cover(v(4), covered(&connection, b"gh"))
        .unwrap_err();
    assert!(
        matches!(&error, CoverError::FinalSizeEstablished { source, .. } if source.final_size() == v(4))
    );
    drop(error.into_data());
    assert_eq!(settlement.final_size(), Some(v(4)));
    assert_eq!(settlement.exposed_final_size(), None);
    assert_eq!(connection.reserved(), v(4));
}

#[test]
fn settlement_exposure_needs_coverage() {
    let connection = AtomicConnectionSendFlowController::new(v(1000));
    let mut settlement = VisibilitySettlement::new();
    settlement
        .cover(VarInt::ZERO, covered(&connection, b"abcd"))
        .unwrap();
    assert_eq!(
        settlement.expose_usage_through(v(6), ExposedContent::Data, v(10)),
        Err(ExposeUsageError::BeyondCoverage {
            source: UsageBeyondCoverageError::check(v(6), v(4)).unwrap_err(),
        })
    );
    assert_eq!(settlement.covered(), v(4));
}

/// The settlement commits `max(E, usage_end) − E` and keeps `E` monotone;
/// a high-offset exposure commits the offsets it spans.
#[test]
fn exposure_commits_new_usage_once() {
    let connection = AtomicConnectionSendFlowController::new(v(1000));
    let mut buffer = OffsetMapStreamSendBuffer::new();
    append(&mut buffer, &connection, 500);

    let exposed = buffer
        .expose_usage_through(v(300), ExposedContent::Data)
        .unwrap();
    assert_eq!(exposed, v(300));
    assert_eq!(buffer.exposure_end(), v(300));
    assert_eq!(
        (connection.reserved(), connection.committed()),
        (v(200), v(300))
    );

    // A retransmission or an earlier range commits nothing again.
    let exposed = buffer
        .expose_usage_through(v(100), ExposedContent::Data)
        .unwrap();
    assert_eq!(exposed, VarInt::ZERO);
    assert_eq!(buffer.exposure_end(), v(300));

    let exposed = buffer
        .expose_usage_through(v(450), ExposedContent::Data)
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
    let connection = AtomicConnectionSendFlowController::new(v(1000));
    let mut buffer = OffsetMapStreamSendBuffer::new();
    append(&mut buffer, &connection, 100);
    let error = buffer
        .expose_usage_through(v(101), ExposedContent::Data)
        .unwrap_err();
    assert_eq!(
        error,
        ExposeUsageError::BeyondWrittenEnd {
            source: UsageBeyondWrittenEndError::check(v(101), v(100)).unwrap_err(),
        }
    );
    assert_eq!(connection.committed(), VarInt::ZERO);
}

#[test]
fn exposed_final_size_constrains_later_exposures() {
    let connection = AtomicConnectionSendFlowController::new(v(1000));
    let mut buffer = OffsetMapStreamSendBuffer::new();
    append(&mut buffer, &connection, 100);
    buffer
        .expose_usage_through(v(60), ExposedContent::Data)
        .unwrap();

    let error = buffer
        .expose_usage_through(v(50), ExposedContent::FinalSize)
        .unwrap_err();
    assert_eq!(
        error,
        ExposeUsageError::FinalSizeBelowExposure {
            source: FinalSizeBelowExposureError::check(v(50), v(60)).unwrap_err(),
        }
    );

    // A FIN at 80 fixes the exposed final size and commits up to it.
    let exposed = buffer
        .expose_usage_through(v(80), ExposedContent::FinalSize)
        .unwrap();
    assert_eq!(exposed, v(20));
    assert_eq!(buffer.visibility().exposed_final_size(), Some(v(80)));

    let error = buffer
        .expose_usage_through(v(90), ExposedContent::Data)
        .unwrap_err();
    assert_eq!(
        error,
        ExposeUsageError::BeyondFinalSize {
            source: BeyondFinalSizeError::check(v(80), v(90)).unwrap_err(),
        }
    );
    let error = buffer
        .expose_usage_through(v(100), ExposedContent::FinalSize)
        .unwrap_err();
    assert_eq!(
        error,
        ExposeUsageError::FinalSizeMismatch {
            source: FinalSizeChangeError::check(v(80), v(100)).unwrap_err(),
        }
    );
    // Exposing the same final size again, by any end frame, commits nothing.
    let exposed = buffer
        .expose_usage_through(v(80), ExposedContent::FinalSize)
        .unwrap();
    assert_eq!(exposed, VarInt::ZERO);
    assert_eq!(connection.committed(), v(80));
}

/// A reset with reliable size zero still exposes its final size, though no
/// data remains to send.
#[test]
fn reset_final_size_is_exposed_without_data() {
    let connection = AtomicConnectionSendFlowController::new(v(1000));
    let mut buffer = OffsetMapStreamSendBuffer::new();
    append(&mut buffer, &connection, 100);
    buffer.apply_reset(retention(70, 0)).unwrap();
    assert_eq!(retained_ranges(&buffer), []);
    assert_eq!(connection.reserved(), v(70));

    let error = buffer
        .expose_usage_through(v(80), ExposedContent::Data)
        .unwrap_err();
    assert!(matches!(error, ExposeUsageError::BeyondFinalSize { .. }));
    let exposed = buffer
        .expose_usage_through(v(70), ExposedContent::FinalSize)
        .unwrap();
    assert_eq!(exposed, v(70));
    assert_eq!(
        (connection.reserved(), connection.committed()),
        (v(0), v(70))
    );
}

/// A FIN exposes the final size while input is still open in the buffer; a
/// later reset must keep it, and fixing it cancels the coverage beyond.
#[test]
fn fixing_an_exposed_final_size_keeps_it() {
    let connection = AtomicConnectionSendFlowController::new(v(1000));
    let mut buffer = OffsetMapStreamSendBuffer::new();
    append(&mut buffer, &connection, 100);
    buffer
        .expose_usage_through(v(80), ExposedContent::FinalSize)
        .unwrap();
    assert_eq!(buffer.visibility().exposed_final_size(), Some(v(80)));
    assert_eq!(
        buffer.apply_reset(retention(90, 0)),
        Err(ApplyResetError::FixFinalSize {
            source: FixFinalSizeError::Mismatch {
                source: FinalSizeChangeError::check(v(80), v(90)).unwrap_err(),
            },
        })
    );
    assert_eq!(connection.reserved(), v(20));
    buffer.apply_reset(retention(80, 0)).unwrap();
    assert_eq!(connection.reserved(), VarInt::ZERO);
    assert_eq!(buffer.visibility().exposed_final_size(), Some(v(80)));
    assert_eq!(buffer.visibility().covered(), VarInt::ZERO);
}
