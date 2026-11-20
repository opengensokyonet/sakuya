use super::{Cubic, CubicConfig, CubicConfigError, CubicCongestionEvent, CubicSendSequence};
use crate::{
    congestion::{
        CongestionContext, CongestionController, CongestionWindowConfig,
        CongestionWindowConfigError, InFlightPacket, InitialWindow, SealedPacket,
        SpuriouslyLostPacket,
    },
    pto::PtoPolicy,
    ratio::Ratio,
    rtt::RttEstimate,
};
use core::time::Duration;

fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}

/// An event at `now` ms, with a smoothed RTT of 40 ms and something still
/// in flight.
fn context(now: u64) -> CongestionContext<Duration> {
    CongestionContext {
        now: ms(now),
        bytes_in_flight: 1200,
        rtt: RttEstimate::initial(ms(40)),
        rtt_sampled: true,
        max_datagram_size: 1200,
    }
}

fn drained(now: u64) -> CongestionContext<Duration> {
    CongestionContext {
        bytes_in_flight: 0,
        ..context(now)
    }
}

fn packet(sent: u64, bytes: usize) -> InFlightPacket<Duration, CubicSendSequence> {
    InFlightPacket {
        bytes,
        sent_at: ms(sent),
        app_limited: false,
        sent_state: CubicSendSequence(0),
    }
}

fn sealed(bytes: usize, now: Duration) -> SealedPacket<Duration> {
    SealedPacket {
        bytes,
        app_limited: false,
        bytes_in_flight: bytes,
        now,
    }
}

fn spurious(sent: u64) -> SpuriouslyLostPacket<Duration> {
    SpuriouslyLostPacket {
        bytes: 1200,
        sent_at: ms(sent),
    }
}

fn controller() -> Cubic<Duration> {
    Cubic::new(CubicConfig::RECOMMENDED, 1200)
}

/// A controller after a loss at 100 ms of a packet sent at 50 ms: window
/// 8400, `W_max` 12000, `K` = ∛(3600 / (0.4 × 1200)) = ∛7.5 s.
fn after_one_loss() -> Cubic<Duration> {
    let mut cubic = controller();
    cubic.on_lost([packet(50, 1200)].into_iter(), &context(100));
    cubic
}

#[test]
fn the_configuration_is_checked() {
    let window = CongestionWindowConfig::RECOMMENDED;
    for beta in [Ratio::literal(0, 10), Ratio::literal(10, 10)] {
        assert_eq!(
            CubicConfig::new(window, beta, Ratio::literal(2, 5), true, true),
            Err(CubicConfigError::BetaOutOfRange { beta })
        );
    }
    assert_eq!(
        CubicConfig::new(
            window,
            Ratio::literal(7, 10),
            Ratio::literal(0, 5),
            true,
            true
        ),
        Err(CubicConfigError::ZeroAggressiveness)
    );
    assert_eq!(
        CubicConfig::new(
            window,
            Ratio::literal(7, 10),
            Ratio::literal(2, 5),
            true,
            true
        ),
        Ok(CubicConfig::RECOMMENDED)
    );
    assert_eq!(
        CongestionWindowConfig::new(InitialWindow::RECOMMENDED, 0),
        Err(CongestionWindowConfigError::ZeroMinimumWindow)
    );
    assert_eq!(
        CongestionWindowConfig::new(InitialWindow::new(1, 14720), 2),
        Err(CongestionWindowConfigError::InitialWindowBelowMinimum {
            initial_window_datagrams: 1,
            minimum_window_datagrams: 2,
        })
    );
}

#[test]
fn alpha_follows_section_4_3() {
    // 3 × (1 − 0.7) / (1 + 0.7)
    assert!((CubicConfig::RECOMMENDED.alpha() - 0.9 / 1.7).abs() < 1e-12);
}

#[test]
fn slow_start_grows_by_the_bytes_acknowledged() {
    let mut cubic = controller();
    assert_eq!(cubic.window(), 12000);
    cubic.on_acked([packet(0, 1200), packet(1, 1200)].into_iter(), &context(40));
    assert_eq!(cubic.window(), 14400);
}

#[test]
fn a_loss_multiplies_the_window_by_beta_once_per_recovery_period() {
    let mut cubic = after_one_loss();
    // Figure 5: ssthresh = cwnd × 0.7, cwnd = ssthresh.
    assert_eq!(cubic.window(), 8400);
    assert_eq!(cubic.slow_start_threshold(), 8400);
    assert_eq!(cubic.window_max(), 12000);
    assert_eq!(cubic.window_prior, 12000);
    let stage = cubic.stage.expect("a stage starts at the event");
    assert_eq!(stage.start, ms(100));
    assert!((stage.k - 7.5f64.cbrt()).abs() < 1e-9);
    assert!(cubic.wants_recovery_send());
    assert!(!cubic.wants_recovery_send());

    // A packet sent before the recovery period started: no second
    // reduction, no growth.
    cubic.on_lost([packet(60, 1200)].into_iter(), &context(120));
    assert_eq!(cubic.window(), 8400);
    assert!(!cubic.wants_recovery_send());
    cubic.on_acked([packet(90, 1200)].into_iter(), &context(130));
    assert_eq!(cubic.window(), 8400);
}

#[test]
fn fast_convergence_reduces_w_max_below_the_window() {
    let mut cubic = after_one_loss();
    // A second event while the window (8400) is below W_max (12000):
    // W_max = 8400 × (1 + 0.7) / 2 (§4.7).
    cubic.on_lost([packet(150, 1200)].into_iter(), &context(200));
    assert_eq!(cubic.window_max(), 7140);
    assert_eq!(cubic.window(), 5880);

    let config = CubicConfig::new(
        CongestionWindowConfig::RECOMMENDED,
        Ratio::literal(7, 10),
        Ratio::literal(2, 5),
        false,
        true,
    )
    .unwrap();
    let mut cubic = Cubic::<Duration>::new(config, 1200);
    cubic.on_lost([packet(50, 1200)].into_iter(), &context(100));
    cubic.on_lost([packet(150, 1200)].into_iter(), &context(200));
    assert_eq!(cubic.window_max(), 8400);
}

#[test]
fn the_concave_region_grows_towards_the_target() {
    let mut cubic = after_one_loss();
    // 500 ms into the stage: W_cubic(0.5) ≈ 10514 is above W_est ≈ 8491;
    // target = W_cubic(0.54) ≈ 10633, and cwnd grows by
    // (target − cwnd) / cwnd per datagram: ≈ 319 bytes (§4.4).
    cubic.on_acked([packet(110, 1200)].into_iter(), &context(600));
    assert_eq!(cubic.window(), 8719);
}

#[test]
fn the_convex_region_grows_away_from_w_max() {
    let mut cubic = after_one_loss();
    cubic.window = 12100;
    // 3 s into the stage, past K: target = W_cubic(3.04) ≈ 12609, and cwnd
    // grows by ≈ 50 bytes (§4.5).
    cubic.on_acked([packet(110, 1200)].into_iter(), &context(3100));
    assert_eq!(cubic.window(), 12150);
}

#[test]
fn the_target_is_at_most_one_and_a_half_windows() {
    let mut cubic = after_one_loss();
    // W_cubic(3.04) ≈ 12609 is above 1.5 × 8400: the target is 12600, and
    // cwnd grows by half a datagram.
    cubic.on_acked([packet(110, 1200)].into_iter(), &context(3100));
    assert_eq!(cubic.window(), 9000);
}

#[test]
fn the_reno_friendly_region_follows_w_est() {
    let mut cubic = after_one_loss();
    // 1 ms into the stage W_cubic is ≈ 8405.5, below
    // W_est = 8400 + α × 1200 × 1200 / 8400 ≈ 8490.8 (Figure 4).
    cubic.on_acked([packet(101, 1200)].into_iter(), &context(101));
    assert_eq!(cubic.window(), 8490);
}

#[test]
fn alpha_is_one_once_w_est_reaches_the_window_before_the_event() {
    let mut cubic = after_one_loss();
    let stage = cubic.stage.as_mut().unwrap();
    stage.reno_estimate = 12000.0;
    cubic.window = 12000;
    // W_est grows by 1 × 1200 × 1200 / 12000 = 120.
    cubic.on_acked([packet(101, 1200)].into_iter(), &context(101));
    assert_eq!(cubic.window(), 12120);
}

#[test]
fn the_time_with_nothing_in_flight_is_left_out() {
    let mut cubic = after_one_loss();
    cubic.on_acked([packet(110, 1200)].into_iter(), &drained(200));
    // Idle from 200 ms to 5200 ms: the stage starts 5 s later.
    cubic.on_packet_sealed(&sealed(1200, ms(5200)));
    assert_eq!(cubic.stage.unwrap().start, ms(5100));
    // Only the first packet after the idle period moves it.
    cubic.on_packet_sealed(&sealed(1200, ms(5300)));
    assert_eq!(cubic.stage.unwrap().start, ms(5100));
}

#[test]
fn the_time_acknowledging_only_application_limited_packets_is_left_out() {
    let mut cubic = after_one_loss();
    cubic.on_acked([packet(110, 1200)].into_iter(), &context(200));
    let window = cubic.window();
    let mut limited = packet(150, 1200);
    limited.app_limited = true;
    cubic.on_acked([limited].into_iter(), &context(300));
    // No growth, and the 100 ms since the last ACK do not count.
    assert_eq!(cubic.window(), window);
    assert_eq!(cubic.stage.unwrap().start, ms(200));
}

#[test]
fn a_spurious_event_is_undone_once_all_its_losses_arrive() {
    let mut cubic = controller();
    let event = cubic.on_lost(
        [packet(40, 1200), packet(50, 1200)].into_iter(),
        &context(100),
    );
    assert_eq!(cubic.window(), 8400);
    // One of the two arrived: the other may still be lost.
    cubic.on_spurious_loss(event, [spurious(40)].into_iter(), &context(110));
    assert_eq!(cubic.window(), 8400);
    // Both arrived: back to the state before the event (§4.9.2).
    cubic.on_spurious_loss(event, [spurious(50)].into_iter(), &context(120));
    assert_eq!(cubic.window(), 12000);
    assert_eq!(cubic.slow_start_threshold(), usize::MAX);
    assert!(cubic.stage.is_none());
    assert!(cubic.recovery_start.is_none());
}

#[test]
fn losses_in_the_recovery_period_join_the_event_to_undo() {
    let mut cubic = controller();
    let event = cubic.on_lost([packet(50, 1200)].into_iter(), &context(100));
    let joined = cubic.on_lost([packet(60, 1200)].into_iter(), &context(110));
    assert_eq!(joined, event);
    cubic.on_spurious_loss(event, [spurious(50)].into_iter(), &context(120));
    assert_eq!(cubic.window(), 8400);
    cubic.on_spurious_loss(event, [spurious(60)].into_iter(), &context(130));
    assert_eq!(cubic.window(), 12000);
}

#[test]
fn only_the_latest_event_is_undone() {
    let mut cubic = controller();
    let first = cubic.on_lost([packet(50, 1200)].into_iter(), &context(100));
    let second = cubic.on_lost([packet(150, 1200)].into_iter(), &context(200));
    assert_ne!(first, second);
    cubic.on_spurious_loss(first, [spurious(50)].into_iter(), &context(210));
    assert_eq!(cubic.window(), 5880);
    cubic.on_spurious_loss(second, [spurious(150)].into_iter(), &context(220));
    assert_eq!(cubic.window(), 8400);
}

#[test]
fn an_event_is_not_undone_once_the_window_is_back_above_the_prior() {
    let mut cubic = after_one_loss();
    let event = CubicCongestionEvent(cubic.events);
    cubic.window = 12500;
    cubic.on_spurious_loss(event, [spurious(50)].into_iter(), &context(5000));
    assert_eq!(cubic.window(), 12500);
    assert_eq!(cubic.slow_start_threshold(), 8400);
}

#[test]
fn a_ce_increase_is_an_event_that_cannot_be_undone() {
    let mut cubic = controller();
    let event = cubic.on_lost([packet(50, 1200)].into_iter(), &context(100));
    cubic.on_ce(1, ms(150), &context(200));
    assert_eq!(cubic.window(), 5880);
    assert!(cubic.wants_recovery_send());
    cubic.on_spurious_loss(event, [spurious(50)].into_iter(), &context(210));
    assert_eq!(cubic.window(), 5880);
}

#[test]
fn the_window_does_not_go_below_the_minimum() {
    let mut cubic = controller();
    for round in 0..20 {
        let at = 100 * (round + 1);
        cubic.on_lost([packet(at - 1, 1200)].into_iter(), &context(at));
        cubic.on_ce(1, ms(at + 1), &context(at + 50));
    }
    assert_eq!(cubic.window(), 2400);
}

#[test]
fn after_persistent_congestion_the_next_stage_starts_with_k_zero() {
    let mut cubic = after_one_loss();
    cubic.on_persistent_congestion(&context(100));
    assert_eq!(cubic.window(), 2400);
    assert!(cubic.stage.is_none());
    // Slow start up to the threshold of 8400 (§4.8 keeps β's).
    let packets = (0..5).map(|index| packet(110 + index, 1200));
    cubic.on_acked(packets, &context(200));
    assert_eq!(cubic.window(), 8400);
    // The first growth in congestion avoidance starts the stage there.
    cubic.on_acked([packet(120, 1200)].into_iter(), &context(300));
    let stage = cubic.stage.unwrap();
    assert_eq!(stage.start, ms(300));
    assert_eq!(stage.k, 0.0);
    assert_eq!(stage.window_max, 8400.0);
}

#[test]
fn a_larger_datagram_size_replaces_the_initial_window() {
    let mut cubic = controller();
    cubic.on_max_datagram_size_changed(1452, true, &context(150));
    assert_eq!(cubic.window(), 14520);
    assert_eq!(cubic.minimum_window(), 2904);
}

#[test]
fn shrinking_before_the_handshake_is_confirmed_sets_the_initial_window() {
    let mut cubic = Cubic::<Duration>::new(CubicConfig::RECOMMENDED, 1400);
    cubic.on_acked([packet(0, 1400)].into_iter(), &context(40));
    cubic.on_max_datagram_size_changed(1200, false, &context(50));
    assert_eq!(cubic.window(), 12000);
}

#[test]
fn only_the_first_duplicate_initial_crypto_is_answered() {
    let mut cubic = controller();
    assert!(cubic.on_duplicate_initial_crypto());
    assert!(!cubic.on_duplicate_initial_crypto());
}

/// Drives a controller through two rounds of HyStart++ whose minimum RTT
/// rises from 40 ms to 50 ms: it is then in Conservative Slow Start.
fn in_conservative_slow_start() -> Cubic<Duration> {
    let mut cubic = controller();
    let mut now = 0;
    for rtt in [40, 50] {
        let sealed: Vec<_> = (0..8)
            .map(|_| cubic.on_packet_sealed(&sealed(100, ms(now))))
            .collect();
        for sent_state in sealed {
            now += 1;
            let mut context = context(now);
            context.rtt.latest = ms(rtt);
            let packet = InFlightPacket {
                sent_state,
                ..packet(now - 1, 100)
            };
            cubic.on_acked([packet].into_iter(), &context);
        }
    }
    cubic
}

#[test]
fn conservative_slow_start_grows_a_quarter_as_fast() {
    let mut cubic = in_conservative_slow_start();
    let window = cubic.window();
    let sent_state = cubic.on_packet_sealed(&sealed(1200, ms(100)));
    let packet = InFlightPacket {
        sent_state,
        ..packet(100, 1200)
    };
    cubic.on_acked([packet].into_iter(), &context(140));
    assert_eq!(cubic.window(), window + 300);
}

#[test]
fn hystart_plus_plus_ends_the_initial_slow_start_with_k_zero() {
    let mut cubic = in_conservative_slow_start();
    let mut now = 100;
    // Five rounds of Conservative Slow Start, the partial one included.
    for _ in 0..5 {
        let sent_state = cubic.on_packet_sealed(&sealed(100, ms(now)));
        now += 50;
        let packet = InFlightPacket {
            sent_state,
            ..packet(now - 50, 100)
        };
        cubic.on_acked([packet].into_iter(), &context(now));
    }
    let window = cubic.window();
    assert_eq!(cubic.slow_start_threshold(), window);
    assert_eq!(cubic.window_prior, window);
    let stage = cubic.stage.expect("congestion avoidance started");
    assert_eq!(stage.k, 0.0);
    assert_eq!(stage.start, ms(now));
}

#[test]
fn without_hystart_plus_plus_slow_start_ignores_the_delay() {
    let config = CubicConfig::new(
        CongestionWindowConfig::RECOMMENDED,
        Ratio::literal(7, 10),
        Ratio::literal(2, 5),
        true,
        false,
    )
    .unwrap();
    let mut cubic = Cubic::<Duration>::new(config, 1200);
    let mut now = 0;
    for rtt in [40, 50, 60, 70, 80, 90, 100] {
        for _ in 0..8 {
            let sent_state = cubic.on_packet_sealed(&sealed(100, ms(now)));
            now += 1;
            let mut context = context(now);
            context.rtt.latest = ms(rtt);
            let packet = InFlightPacket {
                sent_state,
                ..packet(now - 1, 100)
            };
            cubic.on_acked([packet].into_iter(), &context);
        }
    }
    assert_eq!(cubic.window(), 12000 + 56 * 100);
    assert_eq!(cubic.slow_start_threshold(), usize::MAX);
}
