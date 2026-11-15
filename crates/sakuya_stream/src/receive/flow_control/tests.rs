use super::{
    AdvertisementIntent, ReceiveFlowControlPolicy, ReceiveFlowEvent, ReceiveFlowView,
    SlidingWindowAdvertisement,
};
use crate::receive::BoundaryMode;
use sakuya_wire::var_int::VarInt;

const KIB: u32 = 1024;

fn v(value: u32) -> VarInt {
    VarInt::from_u32(value)
}

fn view(opened_limit: VarInt, delivered_end: VarInt) -> ReceiveFlowView {
    ReceiveFlowView {
        opened_limit,
        accounted_end: delivered_end,
        delivered_end,
        final_size: None,
        acceptance: BoundaryMode::Following,
        delivery: BoundaryMode::Following,
        destroyed: false,
        reader_dropped: false,
    }
}

fn intent_after(
    policy: &mut SlidingWindowAdvertisement,
    opened_limit: VarInt,
    delivered_end: VarInt,
) -> AdvertisementIntent {
    policy.on_receive_flow_event(
        ReceiveFlowEvent::Delivered,
        &view(opened_limit, delivered_end),
    );
    policy.advertisement_intent()
}

fn advertise(target_limit: VarInt) -> AdvertisementIntent {
    AdvertisementIntent::Advertise { target_limit }
}

/// The example of the design: W = 64 KiB, 64 KiB opened; 20 KiB delivered
/// withholds the 84 KiB target, 32 KiB delivered advertises 96 KiB.
#[test]
fn half_a_window_of_delivery_advertises() {
    let mut policy = SlidingWindowAdvertisement::new(v(64 * KIB));
    assert_eq!(policy.advertisement_intent(), AdvertisementIntent::Withhold);
    assert_eq!(
        intent_after(&mut policy, v(64 * KIB), v(20 * KIB)),
        AdvertisementIntent::Withhold
    );
    assert_eq!(
        intent_after(&mut policy, v(64 * KIB), v(32 * KIB)),
        advertise(v(96 * KIB))
    );
}

/// The target follows delivery and is absolute: more delivery moves it on,
/// repeated events do not add to it, and opening it withdraws it.
#[test]
fn target_is_absolute_and_opening_it_withdraws_it() {
    let mut policy = SlidingWindowAdvertisement::new(v(64 * KIB));
    assert_eq!(
        intent_after(&mut policy, v(64 * KIB), v(40 * KIB)),
        advertise(v(104 * KIB))
    );
    assert_eq!(
        intent_after(&mut policy, v(64 * KIB), v(40 * KIB)),
        advertise(v(104 * KIB))
    );
    assert_eq!(
        intent_after(&mut policy, v(64 * KIB), v(50 * KIB)),
        advertise(v(114 * KIB))
    );
    let opened = view(v(114 * KIB), v(50 * KIB));
    policy.on_receive_flow_event(ReceiveFlowEvent::LimitOpened, &opened);
    assert_eq!(policy.advertisement_intent(), AdvertisementIntent::Withhold);
}

/// The threshold is `W / 2` rounded down, and a target never passes the
/// largest offset.
#[test]
fn threshold_rounds_down_and_target_saturates() {
    let mut policy = SlidingWindowAdvertisement::new(v(5));
    assert_eq!(
        intent_after(&mut policy, v(5), v(1)),
        AdvertisementIntent::Withhold
    );
    assert_eq!(intent_after(&mut policy, v(5), v(2)), advertise(v(7)));

    let mut policy = SlidingWindowAdvertisement::new(v(1));
    assert_eq!(
        intent_after(&mut policy, v(1), v(0)),
        AdvertisementIntent::Withhold
    );
    assert_eq!(intent_after(&mut policy, v(1), v(1)), advertise(v(2)));

    let mut policy = SlidingWindowAdvertisement::new(VarInt::MAX);
    assert_eq!(
        intent_after(&mut policy, v(10), v(10)),
        advertise(VarInt::MAX)
    );
    assert_eq!(
        intent_after(&mut policy, VarInt::MAX, VarInt::MAX),
        AdvertisementIntent::Withhold
    );
}

/// A zero window never advertises.
#[test]
fn zero_window_never_advertises() {
    let mut policy = SlidingWindowAdvertisement::new(VarInt::ZERO);
    assert_eq!(
        intent_after(&mut policy, v(0), v(0)),
        AdvertisementIntent::Withhold
    );
    assert_eq!(
        intent_after(&mut policy, v(10), v(10)),
        AdvertisementIntent::Withhold
    );
}
