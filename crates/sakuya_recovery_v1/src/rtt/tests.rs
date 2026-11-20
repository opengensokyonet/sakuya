use super::{
    INITIAL_RTT, Rfc9002RttEstimator, RttEstimate, RttEstimator, RttSample, effective_ack_delay,
};
use crate::packet_number_space::PacketNumberSpaceKind;
use core::time::Duration;

fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}

fn micros(value: u64) -> Duration {
    Duration::from_micros(value)
}

/// A sample with instants as durations since some start.
fn sample(sent: u64, arrived: u64, ack_delay: u64, min_rtt: Duration) -> RttSample<Duration, ()> {
    RttSample::new(ms(sent), ms(arrived), ms(ack_delay), min_rtt, ()).unwrap()
}

fn estimator() -> Rfc9002RttEstimator<()> {
    Rfc9002RttEstimator::new(INITIAL_RTT)
}

fn take(estimator: &mut Rfc9002RttEstimator<()>, sample: RttSample<Duration, ()>) {
    RttEstimator::<Duration>::on_sample(estimator, sample);
}

fn estimate(estimator: &Rfc9002RttEstimator<()>) -> RttEstimate {
    RttEstimator::<Duration>::estimate(estimator)
}

#[test]
fn before_the_first_sample_the_estimate_is_the_initial_rtt() {
    assert_eq!(
        estimate(&estimator()),
        RttEstimate {
            latest: Duration::ZERO,
            min: Duration::ZERO,
            smoothed: ms(333),
            variation: micros(166_500),
        }
    );
}

#[test]
fn the_first_sample_ignores_the_ack_delay() {
    let mut estimator = estimator();
    take(&mut estimator, sample(0, 100, 10, Duration::ZERO));
    assert_eq!(
        estimate(&estimator),
        RttEstimate {
            latest: ms(100),
            min: ms(100),
            smoothed: ms(100),
            variation: ms(50),
        }
    );
}

#[test]
fn later_samples_follow_appendix_a7() {
    let mut estimator = estimator();
    take(&mut estimator, sample(0, 100, 10, Duration::ZERO));

    // 80 ms with 10 ms of delay would be 70 ms, below the minimum of 80 ms
    // this sample sets: the delay is not taken off.
    let second = sample(120, 200, 10, estimate(&estimator).min);
    assert_eq!(second.adjusted(), ms(80));
    take(&mut estimator, second);
    // variation = 3/4 × 50 + 1/4 × |100 − 80|, measured against the smoothed
    // RTT before this sample; smoothed = 7/8 × 100 + 1/8 × 80.
    assert_eq!(
        estimate(&estimator),
        RttEstimate {
            latest: ms(80),
            min: ms(80),
            smoothed: micros(97_500),
            variation: micros(42_500),
        }
    );

    // 120 ms with 30 ms of delay is 90 ms, above the minimum: taken off.
    let third = sample(300, 420, 30, estimate(&estimator).min);
    assert_eq!(third.adjusted(), ms(90));
    take(&mut estimator, third);
    let estimate = estimate(&estimator);
    assert_eq!(estimate.latest, ms(120));
    assert_eq!(estimate.min, ms(80));
    // 7/8 × 97.5 + 1/8 × 90 = 96.5625.
    assert_eq!(estimate.smoothed, Duration::from_nanos(96_562_500));
}

#[test]
fn a_sample_sent_after_its_ack_arrived_is_dropped() {
    let sample = RttSample::new(ms(100), ms(99), Duration::ZERO, Duration::ZERO, ());
    assert_eq!(sample, None);
}

#[test]
fn a_sample_keeps_where_the_ack_arrived() {
    let sample = RttSample::new(ms(10), ms(50), Duration::ZERO, Duration::ZERO, 7u8).unwrap();
    assert_eq!(*sample.at(), ms(50));
    assert_eq!(*sample.ack_via(), 7);
    assert_eq!(sample.latest(), ms(40));
}

#[test]
fn persistent_congestion_makes_the_latest_sample_the_minimum() {
    let mut estimator = estimator();
    take(&mut estimator, sample(0, 50, 0, Duration::ZERO));
    take(&mut estimator, sample(100, 190, 0, ms(50)));
    assert_eq!(estimate(&estimator).min, ms(50));
    RttEstimator::<Duration>::on_persistent_congestion(&mut estimator);
    assert_eq!(estimate(&estimator).min, ms(90));
}

#[test]
fn persistent_congestion_before_a_sample_changes_nothing() {
    let mut estimator = estimator();
    RttEstimator::<Duration>::on_persistent_congestion(&mut estimator);
    assert_eq!(estimate(&estimator), RttEstimate::initial(INITIAL_RTT));
}

#[test]
fn the_ack_delay_follows_the_space_and_the_handshake() {
    use PacketNumberSpaceKind::{ApplicationData, Handshake, Initial};
    let reported = ms(40);
    let peer = ms(25);
    assert_eq!(
        effective_ack_delay(Initial, reported, true, peer),
        Duration::ZERO
    );
    assert_eq!(
        effective_ack_delay(Handshake, reported, false, peer),
        ms(40)
    );
    assert_eq!(
        effective_ack_delay(ApplicationData, reported, false, peer),
        ms(40)
    );
    assert_eq!(
        effective_ack_delay(ApplicationData, reported, true, peer),
        ms(25)
    );
}
