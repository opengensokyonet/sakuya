use super::{ProbeCount, PtoAction, PtoExpiry, PtoPolicy, probe_timeout};
use crate::{
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaceSet},
    rtt::RttEstimate,
};
use core::time::Duration;

fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}

fn rtt(smoothed: u64, variation: u64) -> RttEstimate {
    RttEstimate {
        latest: ms(smoothed),
        min: ms(smoothed),
        smoothed: ms(smoothed),
        variation: ms(variation),
    }
}

#[test]
fn the_application_data_space_adds_the_peer_max_ack_delay() {
    // 40 + max(4 × 5, 1) = 60; plus 25 in Application Data.
    let rtt = rtt(40, 5);
    let pto = |space| probe_timeout(&rtt, ms(1), space, ms(25), 0);
    assert_eq!(pto(PacketNumberSpaceKind::Initial), ms(60));
    assert_eq!(pto(PacketNumberSpaceKind::Handshake), ms(60));
    assert_eq!(pto(PacketNumberSpaceKind::ApplicationData), ms(85));
}

#[test]
fn the_variation_term_is_at_least_the_granularity() {
    let rtt = rtt(1, 0);
    assert_eq!(
        probe_timeout(&rtt, ms(1), PacketNumberSpaceKind::Initial, ms(25), 0),
        ms(2)
    );
}

#[test]
fn the_backoff_doubles_and_saturates() {
    let rtt = rtt(40, 5);
    let pto = |backoff| {
        probe_timeout(
            &rtt,
            ms(1),
            PacketNumberSpaceKind::ApplicationData,
            ms(25),
            backoff,
        )
    };
    assert_eq!(pto(1), ms(170));
    assert_eq!(pto(3), ms(680));
    assert_eq!(pto(40), Duration::MAX);
    assert_eq!(pto(u32::MAX), Duration::MAX);
}

struct Defaults;

impl PtoPolicy<Duration> for Defaults {
    fn on_duplicate_initial_crypto(&mut self) -> bool {
        false
    }
}

#[test]
fn the_default_probes_twice_in_every_space_in_flight() {
    let spaces = PacketNumberSpaceSet::EMPTY
        .with(PacketNumberSpaceKind::Initial)
        .with(PacketNumberSpaceKind::Handshake);
    let expiry = PtoExpiry {
        at: ms(500),
        expired_space: PacketNumberSpaceKind::Initial,
        in_flight_spaces: spaces,
        backoff: 1,
        rtt: rtt(40, 5),
    };
    assert_eq!(
        Defaults.on_pto_expired(&expiry),
        PtoAction::Probe {
            datagrams: ProbeCount::Two,
            spaces,
        }
    );
    assert_eq!(ProbeCount::Two.get(), 2);
}
