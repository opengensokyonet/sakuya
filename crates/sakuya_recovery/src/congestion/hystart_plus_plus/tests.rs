use super::{CSS_GROWTH_DIVISOR, CSS_ROUNDS, HyStartPlusPlus, Phase, RTT_SAMPLES};
use core::time::Duration;

fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}

/// Seals `packets` packets, then acknowledges them one by one with an RTT
/// sample of `rtt` each; whether one of the acknowledgments started
/// congestion avoidance.
fn round(hystart: &mut HyStartPlusPlus, packets: u32, rtt: Duration) -> bool {
    let sequences: Vec<_> = (0..packets).map(|_| hystart.on_sealed()).collect();
    sequences
        .into_iter()
        .any(|sequence| hystart.on_ack(Some(sequence), Some(rtt)))
}

#[test]
fn off_it_is_finished() {
    let mut hystart = HyStartPlusPlus::new(false);
    assert_eq!(hystart.phase(), Phase::Finished);
    assert!(!round(&mut hystart, 10, ms(40)));
    assert_eq!(hystart.growth_divisor(), 1);
}

#[test]
fn a_delay_increase_moves_to_conservative_slow_start() {
    let mut hystart = HyStartPlusPlus::new(true);
    // The first acknowledgment starts the first round; its minimum is
    // 40 ms.
    hystart.on_ack(None, None);
    round(&mut hystart, RTT_SAMPLES, ms(40));
    assert_eq!(hystart.phase(), Phase::SlowStart);
    // The next round's minimum is 45 ms: 40 + max(4, min(40 / 8, 16)).
    round(&mut hystart, RTT_SAMPLES, ms(45));
    assert_eq!(
        hystart.phase(),
        Phase::Conservative {
            baseline_min_rtt: ms(45),
            rounds: 0,
        }
    );
    assert_eq!(hystart.growth_divisor(), CSS_GROWTH_DIVISOR);
}

#[test]
fn a_smaller_increase_stays_in_slow_start() {
    let mut hystart = HyStartPlusPlus::new(true);
    hystart.on_ack(None, None);
    round(&mut hystart, RTT_SAMPLES, ms(40));
    round(&mut hystart, RTT_SAMPLES, ms(44));
    assert_eq!(hystart.phase(), Phase::SlowStart);
}

#[test]
fn the_threshold_is_at_most_16_ms() {
    let mut hystart = HyStartPlusPlus::new(true);
    hystart.on_ack(None, None);
    round(&mut hystart, RTT_SAMPLES, ms(200));
    // 200 / 8 = 25 ms is above 16 ms.
    round(&mut hystart, RTT_SAMPLES, ms(216));
    assert!(matches!(hystart.phase(), Phase::Conservative { .. }));
}

#[test]
fn too_few_samples_change_nothing() {
    let mut hystart = HyStartPlusPlus::new(true);
    hystart.on_ack(None, None);
    round(&mut hystart, RTT_SAMPLES, ms(40));
    round(&mut hystart, RTT_SAMPLES - 1, ms(100));
    assert_eq!(hystart.phase(), Phase::SlowStart);
}

#[test]
fn a_minimum_below_the_baseline_resumes_slow_start() {
    let mut hystart = HyStartPlusPlus::new(true);
    hystart.on_ack(None, None);
    round(&mut hystart, RTT_SAMPLES, ms(40));
    round(&mut hystart, RTT_SAMPLES, ms(50));
    assert!(matches!(hystart.phase(), Phase::Conservative { .. }));
    round(&mut hystart, RTT_SAMPLES, ms(42));
    assert_eq!(hystart.phase(), Phase::SlowStart);
}

#[test]
fn congestion_avoidance_starts_after_the_rounds_of_conservative_slow_start() {
    let mut hystart = HyStartPlusPlus::new(true);
    hystart.on_ack(None, None);
    round(&mut hystart, RTT_SAMPLES, ms(40));
    round(&mut hystart, RTT_SAMPLES, ms(50));
    // The partial round CSS started in counts (§4.2): it ends with the
    // first acknowledgment of the next.
    for _ in 1..CSS_ROUNDS {
        assert!(!round(&mut hystart, RTT_SAMPLES, ms(50)));
    }
    assert!(round(&mut hystart, RTT_SAMPLES, ms(50)));
    assert_eq!(hystart.phase(), Phase::Finished);
}

#[test]
fn a_congestion_event_finishes_it() {
    let mut hystart = HyStartPlusPlus::new(true);
    hystart.finish();
    assert_eq!(hystart.phase(), Phase::Finished);
}
