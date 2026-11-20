use super::{ConnectionReceiveFlowController, RecordReleaseError, RecordUsageError};
use sakuya_wire::var_int::VarInt;

fn v(value: u32) -> VarInt {
    VarInt::from_u32(value)
}

#[test]
fn usage_up_to_the_limit_is_accepted() {
    let mut controller = ConnectionReceiveFlowController::new(v(100));
    controller.record_usage(v(60)).unwrap();
    controller.record_usage(v(40)).unwrap();
    assert_eq!(controller.used(), v(100));
}

#[test]
fn usage_beyond_the_limit_is_an_error_and_changes_nothing() {
    let mut controller = ConnectionReceiveFlowController::new(v(100));
    controller.record_usage(v(60)).unwrap();
    assert_eq!(
        controller.record_usage(v(41)),
        Err(RecordUsageError {
            used: v(60),
            increase: v(41),
            limit: v(100),
        })
    );
    assert_eq!(controller.used(), v(60));
    assert!(controller.record_usage(VarInt::MAX).is_err());
}

#[test]
fn limit_only_grows() {
    let mut controller = ConnectionReceiveFlowController::new(v(100));
    assert!(controller.raise_limit(v(200)));
    assert!(!controller.raise_limit(v(150)));
    assert!(!controller.raise_limit(v(200)));
    assert_eq!(controller.limit(), v(200));
    controller.record_usage(v(200)).unwrap();
}

#[test]
fn release_is_tracked_apart_from_usage() {
    let mut controller = ConnectionReceiveFlowController::new(v(100));
    controller.record_usage(v(50)).unwrap();
    controller.record_release(v(30)).unwrap();
    assert_eq!(controller.released(), v(30));
    assert_eq!(controller.used(), v(50));
}

#[test]
fn release_beyond_usage_is_an_error_and_changes_nothing() {
    let mut controller = ConnectionReceiveFlowController::new(v(100));
    controller.record_usage(v(10)).unwrap();
    controller.record_release(v(4)).unwrap();
    assert_eq!(
        controller.record_release(v(7)),
        Err(RecordReleaseError {
            released: v(4),
            increase: v(7),
            used: v(10),
        })
    );
    assert_eq!(controller.released(), v(4));
    assert!(controller.record_release(VarInt::MAX).is_err());
}

const KIB: u32 = 1024;

/// W = 64 KiB, the initial limit: releasing 20 KiB makes a target of 84 KiB,
/// which is withheld; releasing 32 KiB makes one of 96 KiB, which is
/// advertised until it is recorded as visible.
#[test]
fn max_data_slides_with_released_progress() {
    let mut controller = ConnectionReceiveFlowController::new(v(64 * KIB));
    assert_eq!(controller.window(), v(64 * KIB));
    assert_eq!(controller.advertisement(), None);
    controller.record_usage(v(64 * KIB)).unwrap();
    controller.record_release(v(20 * KIB)).unwrap();
    assert_eq!(controller.advertisement(), None);
    controller.record_release(v(12 * KIB)).unwrap();
    assert_eq!(controller.advertisement(), Some(v(96 * KIB)));
    // Querying again changes nothing.
    assert_eq!(controller.advertisement(), Some(v(96 * KIB)));
    assert!(controller.raise_limit(v(96 * KIB)));
    assert_eq!(controller.advertisement(), None);
    controller.record_usage(v(32 * KIB)).unwrap();
    controller.record_release(v(32 * KIB)).unwrap();
    assert_eq!(controller.advertisement(), Some(v(128 * KIB)));
}

/// Usage does not move the target; only released progress does.
#[test]
fn usage_alone_advertises_nothing() {
    let mut controller = ConnectionReceiveFlowController::new(v(100));
    controller.record_usage(v(100)).unwrap();
    assert_eq!(controller.advertisement(), None);
    controller.record_release(v(49)).unwrap();
    assert_eq!(controller.advertisement(), None);
    controller.record_release(v(1)).unwrap();
    assert_eq!(controller.advertisement(), Some(v(150)));
}

/// A zero initial limit is a zero window: nothing is ever advertised.
#[test]
fn zero_window_advertises_nothing() {
    let controller = ConnectionReceiveFlowController::new(VarInt::ZERO);
    assert_eq!(controller.advertisement(), None);
}
