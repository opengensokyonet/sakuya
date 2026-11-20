use super::{
    GranularityBelowClockError, LossThresholds, PacketThreshold, PacketThresholdBelowThreeError,
    RECOMMENDED_TIME_THRESHOLD, loss_delay,
};
use crate::rtt::RttEstimate;
use core::time::Duration;

fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}

fn estimate(latest: u64, smoothed: u64) -> RttEstimate {
    RttEstimate {
        latest: ms(latest),
        min: ms(latest),
        smoothed: ms(smoothed),
        variation: ms(smoothed / 2),
    }
}

#[test]
fn a_packet_threshold_below_three_is_rejected() {
    assert_eq!(
        PacketThreshold::new(2),
        Err(PacketThresholdBelowThreeError { threshold: 2 })
    );
    assert_eq!(PacketThreshold::new(3), Ok(PacketThreshold::RECOMMENDED));
}

#[test]
fn a_granularity_below_the_clock_is_rejected() {
    assert_eq!(
        LossThresholds::recommended(ms(10)),
        Err(GranularityBelowClockError {
            granularity: ms(1),
            clock_granularity: ms(10),
        })
    );
    let thresholds = LossThresholds::new(
        PacketThreshold::RECOMMENDED,
        RECOMMENDED_TIME_THRESHOLD,
        ms(10),
        ms(10),
    )
    .unwrap();
    assert_eq!(thresholds.granularity(), ms(10));
}

#[test]
fn the_loss_delay_takes_the_larger_rtt() {
    let thresholds = LossThresholds::recommended(ms(1)).unwrap();
    // 9/8 × max(40, 32) = 45.
    assert_eq!(loss_delay(&estimate(40, 32), &thresholds), ms(45));
    // 9/8 × max(32, 40) = 45.
    assert_eq!(loss_delay(&estimate(32, 40), &thresholds), ms(45));
}

#[test]
fn the_loss_delay_is_at_least_the_granularity() {
    let thresholds = LossThresholds::recommended(Duration::ZERO).unwrap();
    let tiny = RttEstimate {
        latest: Duration::from_micros(200),
        min: Duration::from_micros(200),
        smoothed: Duration::from_micros(200),
        variation: Duration::from_micros(100),
    };
    assert_eq!(loss_delay(&tiny, &thresholds), ms(1));
}

#[test]
fn before_a_sample_the_loss_delay_uses_the_initial_rtt() {
    let thresholds = LossThresholds::recommended(ms(1)).unwrap();
    let initial = RttEstimate::initial(ms(333));
    assert_eq!(
        loss_delay(&initial, &thresholds),
        Duration::from_micros(374_625)
    );
}
