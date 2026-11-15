//! Selection and feedback of [`OffsetMapStreamSendBuffer`]: grouping by
//! destination, the order within one, partial selection, acknowledgement,
//! loss, unfulfilled intents and the interplay with a reset.
use super::*;
use crate::send_buffer::{DestinationChanges, NextSegment};

/// The offset and length of the next segment for `path`, and its urgency
/// and current destination.
fn next_of(buffer: &Buffer, path: Path) -> Option<(u64, usize, u8, Path)> {
    buffer.next(&path).map(
        |NextSegment {
             offset,
             len,
             marker,
         }| {
            (
                offset.get(),
                len,
                marker.parameters().get(),
                marker.destination().current(),
            )
        },
    )
}

/// The offset and length of a selection.
fn select(buffer: &mut Buffer, path: Path, max_len: usize) -> Option<(u64, usize)> {
    buffer
        .select(&path, max_len)
        .map(|selected| (selected.offset.get(), selected.bytes.len()))
}

fn range(start: u32, end: u32) -> Range<VarInt> {
    v(start)..v(end)
}

fn changes(pending_changed: Vec<Path>, exhausted: Vec<Range<VarInt>>) -> DestinationChanges<Path> {
    DestinationChanges {
        pending_changed,
        exhausted,
    }
}

/// [0, 1000) at urgency 3 only direct, falling back to any active link
/// path, then [1000, 1500) at urgency 1 to any active link path.
fn two_destinations(connection: &AtomicConnectionSendFlowController) -> Buffer {
    let mut buffer = Buffer::new();
    append_with(
        &mut buffer,
        connection,
        1000,
        SendOptions::new(urgency(3), Route::DIRECT_THEN_ANY),
    );
    append_with(
        &mut buffer,
        connection,
        500,
        SendOptions::new(urgency(1), Route::ANY),
    );
    buffer
}

#[test]
fn waiting_data_is_grouped_by_destination() {
    let connection = AtomicConnectionSendFlowController::new(v(2000));
    let buffer = two_destinations(&connection);
    assert_eq!(buffer.destinations(), [Path::Direct, Path::Any]);
    assert_eq!(
        next_of(&buffer, Path::Direct),
        Some((0, 1000, 3, Path::Direct))
    );
    assert_eq!(next_of(&buffer, Path::Any), Some((1000, 500, 1, Path::Any)));
}

/// Within a destination, the smaller urgency goes first, then the smaller
/// offset.
#[test]
fn a_destination_orders_by_urgency_then_offset() {
    let connection = AtomicConnectionSendFlowController::new(v(1000));
    let mut buffer = Buffer::new();
    append_with(&mut buffer, &connection, 100, any());
    append_with(
        &mut buffer,
        &connection,
        50,
        SendOptions::new(urgency(1), Route::ANY),
    );
    append_with(&mut buffer, &connection, 50, any());
    let order: Vec<_> = core::iter::from_fn(|| select(&mut buffer, Path::Any, 1000)).collect();
    assert_eq!(order, [(100, 50), (0, 100), (150, 50)]);
    assert!(buffer.destinations().is_empty());
    assert_eq!(next_of(&buffer, Path::Any), None);
}

/// A selection takes at most what it is asked for, without copying; the
/// rest keeps its place.
#[test]
fn selection_takes_a_prefix_and_keeps_the_rest_waiting() {
    let connection = AtomicConnectionSendFlowController::new(v(1000));
    let mut buffer = Buffer::new();
    let bytes = append(&mut buffer, &connection, 100);
    assert_eq!(buffer.select(&Path::Any, 0).map(|s| s.offset), None);
    let first = buffer.select(&Path::Any, 30).unwrap();
    assert_eq!((first.offset, first.bytes.len()), (v(0), 30));
    assert_eq!(first.bytes.as_ptr(), bytes.as_ptr());
    assert_eq!(next_of(&buffer, Path::Any), Some((30, 70, 3, Path::Any)));
    let rest = buffer.select(&Path::Any, 1000).unwrap();
    assert_eq!((rest.offset, &rest.bytes[..]), (v(30), &bytes[30..]));
    assert_eq!(next_of(&buffer, Path::Any), None);
    // Selected data is kept for retransmission.
    assert_eq!(retained_ranges(&buffer), [(0, 30), (30, 70)]);
    assert_eq!(buffer.written_end(), v(100));
    assert_eq!(connection.reserved(), v(100));
}

/// Acknowledged data is released, whether it was selected or waits again;
/// the written end stays.
#[test]
fn acknowledgement_releases_data() {
    let connection = AtomicConnectionSendFlowController::new(v(1000));
    let mut buffer = Buffer::new();
    append(&mut buffer, &connection, 100);
    select(&mut buffer, Path::Any, 60);
    assert!(buffer.on_acknowledged(range(0, 20)).is_empty());
    assert_eq!(retained_ranges(&buffer), [(20, 40), (60, 40)]);
    // [60, 100) still waits; acknowledging part of it changes its group.
    assert_eq!(buffer.on_acknowledged(range(50, 70)), [Path::Any]);
    assert_eq!(retained_ranges(&buffer), [(20, 30), (70, 30)]);
    assert_eq!(next_of(&buffer, Path::Any), Some((70, 30, 3, Path::Any)));
    assert_eq!(buffer.written_end(), v(100));
    // Ranges not kept are ignored.
    assert!(buffer.on_acknowledged(range(0, 20)).is_empty());
    assert!(buffer.on_acknowledged(range(200, 300)).is_empty());
}

/// The example of the design: [200, 400) of the direct data is lost and
/// falls back to any active link path, where it waits behind the urgency 1
/// data.
#[test]
fn loss_falls_back_and_regroups() {
    let connection = AtomicConnectionSendFlowController::new(v(2000));
    let mut buffer = two_destinations(&connection);
    assert_eq!(select(&mut buffer, Path::Direct, 1000), Some((0, 1000)));
    assert_eq!(buffer.destinations(), [Path::Any]);

    assert_eq!(
        buffer.on_lost(range(200, 400)),
        changes(vec![Path::Any], vec![])
    );
    assert_eq!(buffer.destinations(), [Path::Any]);
    assert_eq!(next_of(&buffer, Path::Any), Some((1000, 500, 1, Path::Any)));
    assert_eq!(select(&mut buffer, Path::Any, 500), Some((1000, 500)));
    assert_eq!(next_of(&buffer, Path::Any), Some((200, 200, 3, Path::Any)));
    // The rest of the direct data stays selected; a repeated loss of the
    // range already waiting changes nothing.
    assert_eq!(buffer.on_lost(range(200, 400)), changes(vec![], vec![]));
    assert_eq!(select(&mut buffer, Path::Any, 1000), Some((200, 200)));
    assert_eq!(next_of(&buffer, Path::Any), None);
    // Committed credit is neither returned nor committed again.
    assert_eq!(connection.reserved(), v(1500));
}

/// A destination with nothing to fall back to reports the lost range.
#[test]
fn loss_without_fallback_is_exhausted() {
    let connection = AtomicConnectionSendFlowController::new(v(2000));
    let mut buffer = Buffer::new();
    append_with(
        &mut buffer,
        &connection,
        1000,
        SendOptions::new(urgency(3), Route::DIRECT_ONLY),
    );
    select(&mut buffer, Path::Direct, 1000);
    assert_eq!(
        buffer.on_lost(range(200, 400)),
        changes(vec![], vec![range(200, 400)])
    );
    assert!(buffer.destinations().is_empty());
    assert_eq!(next_of(&buffer, Path::Direct), None);
    // The exhausted data is kept, and a later loss of it is not reported
    // again.
    assert_eq!(retained_ranges(&buffer), [(0, 200), (200, 200), (400, 600)]);
    assert_eq!(
        buffer.on_lost(range(0, 1000)).exhausted,
        [range(0, 200), range(400, 1000)]
    );
}

/// An unfulfilled intent lets every piece waiting for that destination fall
/// back.
#[test]
fn unfulfilled_intents_fall_back_or_are_exhausted() {
    let connection = AtomicConnectionSendFlowController::new(v(2000));
    let mut buffer = Buffer::new();
    append_with(
        &mut buffer,
        &connection,
        100,
        SendOptions::new(urgency(3), Route::DIRECT_THEN_ANY),
    );
    append_with(
        &mut buffer,
        &connection,
        50,
        SendOptions::new(urgency(2), Route::DIRECT_ONLY),
    );
    assert_eq!(buffer.destinations(), [Path::Direct]);
    assert_eq!(
        buffer.on_unfulfilled(&Path::Direct, Unfulfilled::Rejected),
        changes(vec![Path::Direct, Path::Any], vec![range(100, 150)])
    );
    assert_eq!(buffer.destinations(), [Path::Any]);
    assert_eq!(next_of(&buffer, Path::Any), Some((0, 100, 3, Path::Any)));
    // Any active link path stays where it is.
    assert_eq!(
        buffer.on_unfulfilled(&Path::Any, Unfulfilled::Ended),
        changes(vec![Path::Any], vec![])
    );
    assert_eq!(next_of(&buffer, Path::Any), Some((0, 100, 3, Path::Any)));
    // A destination nothing waits for changes nothing.
    assert_eq!(
        buffer.on_unfulfilled(&Path::Direct, Unfulfilled::Rejected),
        changes(vec![], vec![])
    );
}

/// Data a reset abandoned does not come back when its loss is reported.
#[test]
fn loss_after_a_reset_does_not_revive_abandoned_data() {
    let connection = AtomicConnectionSendFlowController::new(v(1000));
    let mut buffer = Buffer::new();
    append(&mut buffer, &connection, 100);
    select(&mut buffer, Path::Any, 100);
    buffer.apply_reset(retention(100, 30)).unwrap();
    assert_eq!(retained_ranges(&buffer), [(0, 30)]);
    assert_eq!(
        buffer.on_lost(range(0, 100)),
        changes(vec![Path::Any], vec![])
    );
    assert_eq!(next_of(&buffer, Path::Any), Some((0, 30, 3, Path::Any)));
    // Waiting data beyond a lowered reliable size is abandoned too.
    buffer.apply_reset(retention(100, 10)).unwrap();
    assert_eq!(next_of(&buffer, Path::Any), Some((0, 10, 3, Path::Any)));
    buffer.apply_reset(retention(100, 0)).unwrap();
    assert!(buffer.destinations().is_empty());
    assert_eq!(buffer.on_lost(range(0, 100)), changes(vec![], vec![]));
}

/// An acknowledgement of one transmission is not undone by the late loss of
/// another.
#[test]
fn late_loss_does_not_undo_an_acknowledgement() {
    let connection = AtomicConnectionSendFlowController::new(v(1000));
    let mut buffer = Buffer::new();
    append(&mut buffer, &connection, 100);
    select(&mut buffer, Path::Any, 100);
    // The first transmission is declared lost and sent again.
    buffer.on_lost(range(0, 100));
    assert_eq!(select(&mut buffer, Path::Any, 100), Some((0, 100)));
    // The first transmission is acknowledged after all, in part.
    buffer.on_acknowledged(range(0, 50));
    // The second is lost: only what was not acknowledged waits again.
    buffer.on_lost(range(0, 100));
    assert_eq!(next_of(&buffer, Path::Any), Some((50, 50, 3, Path::Any)));
    // Acknowledged while waiting: gone, and a later loss finds nothing.
    assert_eq!(buffer.on_acknowledged(range(0, 100)), [Path::Any]);
    assert_eq!(buffer.on_lost(range(0, 100)), changes(vec![], vec![]));
    assert!(buffer.destinations().is_empty());
    assert_eq!(retained_ranges(&buffer), []);
    assert_eq!(buffer.written_end(), v(100));
}
