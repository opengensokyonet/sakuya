use super::{ConnectionReceiveFlowController, RecordUsageError};
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
    controller.record_release(v(30));
    assert_eq!(controller.released(), v(30));
    assert_eq!(controller.used(), v(50));
}

#[test]
#[should_panic(expected = "released progress exceeds connection usage")]
fn release_beyond_usage_panics() {
    let mut controller = ConnectionReceiveFlowController::new(v(100));
    controller.record_usage(v(10)).unwrap();
    controller.record_release(v(11));
}
