use super::*;

fn v(value: u32) -> VarInt {
    VarInt::from_u32(value)
}

fn stream(index: u64) -> StreamId {
    use sakuya_wire::stream_id::{Directionality, Initiator};
    StreamId::new(Initiator::Client, Directionality::Bidirectional, index).unwrap()
}

fn assert_ledger(controller: &AtomicConnectionSendFlowController, reserved: u32, committed: u32) {
    assert_eq!(controller.reserved(), v(reserved), "reserved");
    assert_eq!(controller.committed(), v(committed), "committed");
}

/// L = 100: reserving 80 leaves 20, committing 30 of it still leaves 20, and
/// discarding the other 50 at a reset leaves 70.
#[test]
fn reserve_commit_and_discard_example() {
    let controller = AtomicConnectionSendFlowController::new(v(100));
    let mut reservation = controller.reserve(stream(0), v(80)).unwrap();
    assert_ledger(&controller, 80, 0);
    assert_eq!(controller.available(), v(20));

    let exposed = reservation.split_off(v(30)).unwrap();
    assert_eq!(exposed.commit(), v(30));
    assert_ledger(&controller, 50, 30);
    assert_eq!(controller.available(), v(20));

    drop(reservation);
    assert_ledger(&controller, 0, 30);
    assert_eq!(controller.available(), v(70));
}

#[test]
fn explicit_release_matches_drop() {
    let controller = AtomicConnectionSendFlowController::new(v(100));
    let reservation = controller.reserve(stream(0), v(40)).unwrap();
    assert_eq!(reservation.release(), v(40));
    assert_ledger(&controller, 0, 0);
    assert_eq!(controller.available(), v(100));
}

#[test]
fn splitting_and_merging_conserve_the_amount() {
    let controller = AtomicConnectionSendFlowController::new(v(100));
    let mut first = controller.reserve(stream(0), v(60)).unwrap();
    let second = first.split_off(v(25)).unwrap();
    assert_eq!((first.amount(), second.amount()), (v(35), v(25)));
    assert_ledger(&controller, 60, 0);

    first.absorb(second).unwrap();
    assert_eq!(first.amount(), v(60));
    assert_ledger(&controller, 60, 0);

    let empty = first.split_off(VarInt::ZERO).unwrap();
    drop(empty);
    assert_ledger(&controller, 60, 0);
}

#[test]
fn reserving_more_than_available_fails_without_effect() {
    let controller = AtomicConnectionSendFlowController::new(v(100));
    let _held = controller.reserve(stream(0), v(70)).unwrap();
    let error = controller.reserve(stream(4), v(31)).unwrap_err();
    assert_eq!(
        error,
        InsufficientConnectionCreditError {
            requested: v(31),
            available: v(30),
        }
    );
    assert_ledger(&controller, 70, 0);
}

#[test]
fn reserve_up_to_takes_what_is_available() {
    let controller = AtomicConnectionSendFlowController::new(v(100));
    let first = controller.reserve_up_to(stream(0), v(60)).unwrap();
    assert_eq!(first.amount(), v(60));
    let second = controller.reserve_up_to(stream(4), v(60)).unwrap();
    assert_eq!(second.amount(), v(40));
    assert!(controller.reserve_up_to(stream(8), v(1)).is_none());
    drop(second);
    assert!(controller.reserve_up_to(stream(8), VarInt::ZERO).is_none());
}

#[test]
fn max_data_only_raises_the_limit() {
    let controller = AtomicConnectionSendFlowController::new(v(100));
    assert!(!controller.on_max_data(v(80)));
    assert!(!controller.on_max_data(v(100)));
    assert_eq!(controller.limit(), v(100));
    assert!(controller.on_max_data(v(150)));
    assert_eq!(controller.limit(), v(150));
}

#[test]
fn committed_credit_survives_the_stream() {
    let controller = AtomicConnectionSendFlowController::new(v(100));
    let reservation = controller.reserve(stream(0), v(50)).unwrap();
    reservation.commit();
    // Nothing of the stream remains, but its usage stays committed.
    assert_ledger(&controller, 0, 50);
    assert_eq!(controller.available(), v(50));
}

#[test]
fn dropping_an_uncommitted_reservation_releases_it() {
    let controller = AtomicConnectionSendFlowController::new(v(100));
    let reservation = controller.reserve(stream(0), v(40)).unwrap();
    assert_ledger(&controller, 40, 0);
    drop(reservation);
    assert_ledger(&controller, 0, 0);
    assert_eq!(controller.available(), v(100));

    // A committed reservation is not released by being dropped afterwards:
    // commit consumes it.
    let reservation = controller.reserve(stream(0), v(40)).unwrap();
    assert_eq!(reservation.commit(), v(40));
    assert_ledger(&controller, 0, 40);
    assert_eq!(controller.available(), v(60));
}

#[test]
fn reservations_of_one_controller_commit_into_it_whatever_handle_holds_them() {
    let first = AtomicConnectionSendFlowController::new(v(100));
    let second = AtomicConnectionSendFlowController::new(v(100));
    let reservation = first.reserve(stream(0), v(10)).unwrap();
    // The reservation carries its own controller's counters.
    assert_eq!(reservation.commit(), v(10));
    assert_ledger(&first, 0, 10);
    assert_ledger(&second, 0, 0);
}

#[test]
fn merging_reservations_of_different_streams_fails_and_returns_them() {
    let controller = AtomicConnectionSendFlowController::new(v(100));
    let mut first = controller.reserve(stream(0), v(10)).unwrap();
    let second = controller.reserve(stream(4), v(15)).unwrap();
    let error = first.absorb(second).unwrap_err();
    assert!(
        matches!(error, AbsorbError::DifferentStream { stream_id, .. } if stream_id == stream(0))
    );
    let second = error.into_other();
    assert_eq!((first.amount(), second.amount()), (v(10), v(15)));
    assert_ledger(&controller, 25, 0);
}

#[test]
fn merging_reservations_of_different_controllers_fails() {
    let controller = AtomicConnectionSendFlowController::new(v(100));
    let other = AtomicConnectionSendFlowController::new(v(100));
    let mut first = controller.reserve(stream(0), v(10)).unwrap();
    let foreign = other.reserve(stream(0), v(5)).unwrap();
    let error = first.absorb(foreign).unwrap_err();
    assert!(matches!(error, AbsorbError::ForeignController { .. }));
    drop(error);
    assert_ledger(&other, 0, 0);
    assert_eq!(first.amount(), v(10));
}

#[test]
fn splitting_more_than_owned_fails_without_effect() {
    let controller = AtomicConnectionSendFlowController::new(v(100));
    let mut reservation = controller.reserve(stream(0), v(10)).unwrap();
    assert_eq!(
        reservation.split_off(v(11)).unwrap_err(),
        SplitOffError {
            requested: v(11),
            owned: v(10),
        }
    );
    assert_eq!(reservation.amount(), v(10));
    assert_ledger(&controller, 10, 0);
}
