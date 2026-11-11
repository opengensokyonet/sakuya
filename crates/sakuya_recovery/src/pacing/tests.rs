use super::{
    PacedCongestionController, Pacer, PacingInput, TokenBucketPacer, TokenBucketPacerConfig,
    TokenBucketPacerConfigError,
};
use crate::{
    congestion::{CongestionController, InitialWindow, new_reno::NewReno, new_reno::NewRenoConfig},
    ratio::Ratio,
};
use core::{num::NonZeroUsize, time::Duration};

fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}

fn micros(value: u64) -> Duration {
    Duration::from_micros(value)
}

/// Window 12000, smoothed RTT 40 ms: 1.25 × 12000 / 40 ms = 375 bytes/ms.
fn input() -> PacingInput {
    PacingInput {
        window: 12000,
        smoothed_rtt: ms(40),
        max_datagram_size: 1200,
    }
}

fn pacer() -> TokenBucketPacer<Duration> {
    TokenBucketPacer::new(TokenBucketPacerConfig::recommended(ms(1)))
}

#[test]
fn the_first_refill_fills_the_bucket() {
    let mut pacer = pacer();
    pacer.refill(ms(0), input());
    // The rate gives 750 bytes in 2 ms; the burst is at least the initial
    // window.
    assert_eq!(pacer.allowance(), 12000);
    assert_eq!(pacer.next_release(), None);
}

#[test]
fn an_empty_bucket_releases_when_a_datagram_is_earned() {
    let mut pacer = pacer();
    pacer.refill(ms(0), input());
    pacer.on_charged(12000);
    assert_eq!(pacer.allowance(), 0);
    // 1200 bytes at 375 bytes/ms: 3.2 ms.
    assert_eq!(pacer.next_release(), Some(micros(3200)));
    pacer.refill(ms(1), input());
    assert_eq!(pacer.allowance(), 375);
    // 825 more bytes from 1 ms: 2.2 ms.
    assert_eq!(pacer.next_release(), Some(micros(3200)));
    pacer.refill(micros(3200), input());
    assert_eq!(pacer.allowance(), 1200);
    assert_eq!(pacer.next_release(), None);
}

#[test]
fn a_fraction_of_a_byte_is_carried_over() {
    let mut pacer = pacer();
    pacer.refill(ms(0), input());
    pacer.on_charged(12000);
    // 0.375 bytes in 1 µs: none yet.
    pacer.refill(micros(1), input());
    assert_eq!(pacer.allowance(), 0);
    // 1.125 bytes in 3 µs since the last refill that earned.
    pacer.refill(micros(3), input());
    assert_eq!(pacer.allowance(), 1);
}

#[test]
fn an_earlier_instant_earns_nothing() {
    let mut pacer = pacer();
    pacer.refill(ms(10), input());
    pacer.on_charged(12000);
    pacer.refill(ms(5), input());
    assert_eq!(pacer.allowance(), 0);
    pacer.refill(ms(11), input());
    assert_eq!(pacer.allowance(), 375);
}

#[test]
fn overcharging_empties_the_bucket() {
    let mut pacer = pacer();
    pacer.refill(ms(0), input());
    pacer.on_charged(13200);
    assert_eq!(pacer.allowance(), 0);
}

#[test]
fn the_burst_follows_the_rate_up_to_the_limit() {
    let mut pacer = pacer();
    // Smoothed RTT 0.1 ms: 15000 bytes per 0.1 ms, 300000 in 2 ms.
    let fast = PacingInput {
        smoothed_rtt: micros(100),
        ..input()
    };
    pacer.refill(ms(0), fast);
    assert_eq!(pacer.allowance(), 300_000);
    // Smoothed RTT 0.01 ms: 3 MB in 2 ms, limited to 256 datagrams.
    let faster = PacingInput {
        smoothed_rtt: micros(10),
        ..input()
    };
    let mut pacer = self::pacer();
    pacer.refill(ms(0), faster);
    assert_eq!(pacer.allowance(), 256 * 1200);
}

#[test]
fn a_zero_rtt_does_not_hold_anything_back() {
    let mut pacer = pacer();
    let instant = PacingInput {
        smoothed_rtt: Duration::ZERO,
        ..input()
    };
    pacer.refill(ms(0), instant);
    pacer.on_charged(1_000_000);
    pacer.refill(ms(0), instant);
    assert_eq!(pacer.allowance(), 256 * 1200);
    assert_eq!(pacer.next_release(), None);
}

#[test]
fn the_configuration_is_checked() {
    let burst = NonZeroUsize::new(256).unwrap();
    assert_eq!(
        TokenBucketPacerConfig::new(
            ms(1),
            InitialWindow::RECOMMENDED,
            burst,
            Ratio::literal(3, 4)
        ),
        Err(TokenBucketPacerConfigError::GainBelowOne {
            gain: Ratio::literal(3, 4)
        })
    );
    let small = NonZeroUsize::new(9).unwrap();
    assert_eq!(
        TokenBucketPacerConfig::new(
            ms(1),
            InitialWindow::RECOMMENDED,
            small,
            Ratio::literal(5, 4)
        ),
        Err(TokenBucketPacerConfigError::MaxBurstBelowInitialWindow {
            max_burst_datagrams: small,
            initial_window_datagrams: 10,
        })
    );
    assert_eq!(
        TokenBucketPacerConfig::new(
            ms(1),
            InitialWindow::RECOMMENDED,
            burst,
            Ratio::literal(5, 4)
        ),
        Ok(TokenBucketPacerConfig::recommended(ms(1)))
    );
}

#[test]
fn a_paced_controller_answers_for_both() {
    let mut paced = PacedCongestionController::new(
        NewReno::<Duration>::new(NewRenoConfig::RECOMMENDED, 1200),
        pacer(),
    );
    assert_eq!(CongestionController::<Duration>::window(&paced), 12000);
    paced.refill(ms(0), input());
    paced.on_charged(1200);
    assert_eq!(Pacer::<Duration>::allowance(&paced), 10800);
}
