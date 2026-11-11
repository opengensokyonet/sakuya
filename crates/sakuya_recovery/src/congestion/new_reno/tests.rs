use super::{NewReno, NewRenoConfig, NewRenoConfigError};
use crate::{
    congestion::{CongestionContext, CongestionController, InFlightPacket, InitialWindow},
    pto::PtoPolicy,
    ratio::Ratio,
    rtt::RttEstimate,
};
use core::time::Duration;

fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}

fn context(now: u64) -> CongestionContext<Duration> {
    CongestionContext {
        now: ms(now),
        bytes_in_flight: 0,
        rtt: RttEstimate::initial(ms(40)),
        rtt_sampled: true,
        max_datagram_size: 1200,
    }
}

fn packet(sent: u64, bytes: usize) -> InFlightPacket<Duration, ()> {
    InFlightPacket {
        bytes,
        sent_at: ms(sent),
        app_limited: false,
        sent_state: (),
    }
}

fn controller() -> NewReno<Duration> {
    NewReno::new(NewRenoConfig::RECOMMENDED, 1200)
}

#[test]
fn the_configuration_is_checked() {
    assert_eq!(
        NewRenoConfig::new(InitialWindow::RECOMMENDED, 0, Ratio::literal(1, 2)),
        Err(NewRenoConfigError::ZeroMinimumWindow)
    );
    assert_eq!(
        NewRenoConfig::new(InitialWindow::new(1, 14720), 2, Ratio::literal(1, 2)),
        Err(NewRenoConfigError::InitialWindowBelowMinimum {
            initial_window_datagrams: 1,
            minimum_window_datagrams: 2,
        })
    );
    for loss_reduction in [Ratio::literal(0, 2), Ratio::literal(1, 1)] {
        assert_eq!(
            NewRenoConfig::new(InitialWindow::RECOMMENDED, 2, loss_reduction),
            Err(NewRenoConfigError::LossReductionOutOfRange { loss_reduction })
        );
    }
    assert_eq!(
        NewRenoConfig::new(InitialWindow::RECOMMENDED, 2, Ratio::literal(1, 2)),
        Ok(NewRenoConfig::RECOMMENDED)
    );
}

#[test]
fn slow_start_grows_by_the_bytes_acknowledged() {
    let mut reno = controller();
    assert_eq!(reno.window(), 12000);
    reno.on_acked([packet(0, 1200), packet(1, 1200)].into_iter(), &context(40));
    assert_eq!(reno.window(), 14400);
}

#[test]
fn packets_sealed_while_application_limited_do_not_grow_the_window() {
    let mut reno = controller();
    let mut limited = packet(0, 1200);
    limited.app_limited = true;
    reno.on_acked([limited].into_iter(), &context(40));
    assert_eq!(reno.window(), 12000);
}

#[test]
fn a_loss_halves_the_window_once_per_recovery_period() {
    let mut reno = controller();
    reno.on_lost(
        [packet(10, 1200), packet(20, 1200)].into_iter(),
        &context(100),
    );
    assert_eq!(reno.window(), 6000);
    assert_eq!(reno.slow_start_threshold(), 6000);
    assert!(reno.wants_recovery_send());
    assert!(!reno.wants_recovery_send());

    // A packet sent before the recovery period started: no second
    // reduction.
    reno.on_lost([packet(50, 1200)].into_iter(), &context(120));
    assert_eq!(reno.window(), 6000);
    assert!(!reno.wants_recovery_send());

    // No growth for packets of the recovery period either.
    reno.on_acked([packet(90, 1200)].into_iter(), &context(130));
    assert_eq!(reno.window(), 6000);

    // A packet sent after it ends the period: congestion avoidance adds
    // 1200 × 1200 / 6000 = 240.
    reno.on_acked([packet(110, 1200)].into_iter(), &context(150));
    assert_eq!(reno.window(), 6240);

    // A loss of a packet sent after the period started: a new event.
    reno.on_lost([packet(140, 1200)].into_iter(), &context(200));
    assert_eq!(reno.window(), 3120);
}

#[test]
fn congestion_avoidance_carries_the_fraction_over() {
    let mut reno = controller();
    reno.on_lost([packet(0, 1200)].into_iter(), &context(10));
    assert_eq!(reno.window(), 6000);
    // Each packet of 100 bytes adds 1200 × 100 / window: 20 at first, less
    // as the window grows. Rounded down one by one they would add 905;
    // with the fractions carried over they add 929.
    let small = (0..50).map(|index| packet(20 + index, 100));
    reno.on_acked(small, &context(100));
    assert_eq!(reno.window(), 6929);
}

#[test]
fn the_window_does_not_go_below_the_minimum() {
    let mut reno = controller();
    for round in 0..10 {
        let at = 100 * (round + 1);
        reno.on_lost([packet(at - 1, 1200)].into_iter(), &context(at));
        reno.on_acked([packet(at, 1200)].into_iter(), &context(at + 1));
    }
    assert_eq!(reno.window(), 2400);
}

#[test]
fn a_ce_increase_is_a_congestion_event() {
    let mut reno = controller();
    reno.on_ce(1, ms(30), &context(60));
    assert_eq!(reno.window(), 6000);
    assert!(reno.wants_recovery_send());
}

#[test]
fn persistent_congestion_goes_to_the_minimum_window() {
    let mut reno = controller();
    reno.on_lost([packet(0, 1200)].into_iter(), &context(500));
    reno.on_persistent_congestion(&context(500));
    assert_eq!(reno.window(), 2400);
    // The recovery period is over: the next loss is a new event.
    reno.on_lost([packet(10, 1200)].into_iter(), &context(510));
    assert_eq!(reno.slow_start_threshold(), 1200);
    assert_eq!(reno.window(), 2400);
}

#[test]
fn a_larger_datagram_size_replaces_the_initial_window() {
    let mut reno = controller();
    reno.on_max_datagram_size_changed(1452, true, &context(150));
    assert_eq!(reno.window(), 14520);
    assert_eq!(reno.minimum_window(), 2904);
}

#[test]
fn a_grown_window_only_keeps_the_new_minimum() {
    let mut reno = controller();
    reno.on_acked([packet(0, 1200)].into_iter(), &context(40));
    reno.on_max_datagram_size_changed(1452, true, &context(150));
    assert_eq!(reno.window(), 13200);
}

#[test]
fn shrinking_before_the_handshake_is_confirmed_sets_the_initial_window() {
    let mut reno = NewReno::<Duration>::new(NewRenoConfig::RECOMMENDED, 1400);
    reno.on_acked([packet(0, 1400)].into_iter(), &context(40));
    reno.on_max_datagram_size_changed(1200, false, &context(50));
    assert_eq!(reno.window(), 12000);
}

#[test]
fn only_the_first_duplicate_initial_crypto_is_answered() {
    let mut reno = controller();
    assert!(reno.on_duplicate_initial_crypto());
    assert!(!reno.on_duplicate_initial_crypto());
}
