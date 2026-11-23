//! Congestion signals whose size or timing the peer decides.

use super::{bbr, context, ms, seal};
use crate::congestion::CongestionController;

#[test]
fn a_huge_ce_increase_counts_at_most_the_datagrams_in_flight() {
    let mut bbr = bbr();
    let _packets: Vec<_> = (1..=3)
        .map(|n| seal(&mut bbr, 0, 1200 * n, false))
        .collect();
    // A peer can report any CE count; three datagrams are in flight.
    bbr.on_ce(1 << 60, ms(0), &context(30, 3600));
    assert_eq!(bbr.rate_sampler.lost(), 3600);
    assert_eq!(bbr.loss_events_in_round, 3);
    // Later losses still count, so loss rates stay meaningful.
    let later = seal(&mut bbr, 40, 4800, false);
    let _ = bbr.on_lost([later].into_iter(), &context(80, 3600));
    assert_eq!(bbr.rate_sampler.lost(), 4800);
}

#[test]
fn a_ce_increase_counts_at_least_one_datagram() {
    let mut bbr = bbr();
    bbr.on_ce(5, ms(0), &context(30, 0));
    assert_eq!(bbr.rate_sampler.lost(), 1200);
    assert_eq!(bbr.loss_events_in_round, 1);
}

#[test]
fn persistent_congestion_within_a_recovery_is_not_undone_by_the_same_ack() {
    let mut bbr = bbr();
    let mut packets: Vec<_> = (1..=5)
        .map(|n| seal(&mut bbr, 0, 1200 * n, false))
        .collect();
    let rest = packets.split_off(1);
    // A loss starts a recovery at 100 ms.
    let _ = bbr.on_lost(packets.into_iter(), &context(100, 4800));
    assert_eq!(bbr.recovery_start, Some(ms(100)));
    let probe = seal(&mut bbr, 500, 6000, false);
    // One ACK at 1000 ms: the rest is lost and establishes persistent
    // congestion, and the probe sent within the recovery is acknowledged.
    let _ = bbr.on_lost(rest.into_iter(), &context(1000, 1200));
    bbr.on_persistent_congestion(&context(1000, 1200));
    assert_eq!(bbr.window(), 2400);
    bbr.on_acked([probe].into_iter(), &context(1000, 0));
    // RFC 9002 §7.6.2: the window stays reduced, raised only to
    // MinPipeCwnd (§5.6.4.6), and the recovery goes on.
    assert!(bbr.window() <= 4800, "window {}", bbr.window());
    assert_eq!(bbr.recovery_start, Some(ms(1000)));
    // The ACK of a packet sent after persistent congestion ends it.
    let after = seal(&mut bbr, 1010, 1200, false);
    bbr.on_acked([after].into_iter(), &context(1050, 0));
    assert!(bbr.recovery_start.is_none());
}
