use super::{LostPacket, establishes_persistent_congestion, persistent_congestion_duration};
use crate::rtt::RttEstimate;
use core::time::Duration;

fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}

/// Link path B: smoothed RTT 50 ms, variation 10 ms, the peer's
/// `max_ack_delay` 25 ms; the duration is (50 + 40 + 25) × 3 = 345 ms.
fn rtt() -> RttEstimate {
    RttEstimate {
        latest: ms(50),
        min: ms(50),
        smoothed: ms(50),
        variation: ms(10),
    }
}

/// Sequence numbers 20 to 27, ack-eliciting, sent every 50 ms from 1000 ms.
fn batch() -> Vec<LostPacket<Duration>> {
    (0..8)
        .map(|index| LostPacket {
            seq: 20 + index,
            sent_at: ms(1000 + 50 * index),
            ack_eliciting: true,
        })
        .collect()
}

#[test]
fn the_duration_includes_the_peer_max_ack_delay() {
    assert_eq!(
        persistent_congestion_duration(&rtt(), ms(1), Some(ms(25))),
        ms(345)
    );
    // Unknown: 25 ms.
    assert_eq!(persistent_congestion_duration(&rtt(), ms(1), None), ms(345));
    assert_eq!(
        persistent_congestion_duration(&rtt(), ms(1), Some(ms(0))),
        ms(270)
    );
}

#[test]
fn a_segment_spanning_more_than_the_duration_is_persistent() {
    // 1000 to 1350 ms is 350 ms > 345 ms; the first sample at 100 ms.
    assert!(establishes_persistent_congestion(
        batch(),
        ms(345),
        Some(ms(100))
    ));
}

#[test]
fn a_gap_splits_the_segment() {
    // Sequence 23 was acknowledged earlier: segments of 100 and 150 ms.
    let lost = batch().into_iter().filter(|packet| packet.seq != 23);
    assert!(!establishes_persistent_congestion(
        lost,
        ms(345),
        Some(ms(100))
    ));
}

#[test]
fn a_packet_that_is_not_ack_eliciting_splits_the_segment() {
    let mut lost = batch();
    lost[3].ack_eliciting = false;
    assert!(!establishes_persistent_congestion(
        lost,
        ms(345),
        Some(ms(100))
    ));
}

#[test]
fn no_rtt_sample_means_no_persistent_congestion() {
    assert!(!establishes_persistent_congestion(batch(), ms(345), None));
}

#[test]
fn packets_sent_before_the_first_sample_do_not_take_part() {
    // The first sample at 1100 ms: the segment starts at 1150 ms and spans
    // 200 ms.
    assert!(!establishes_persistent_congestion(
        batch(),
        ms(345),
        Some(ms(1100))
    ));
}

#[test]
fn exactly_the_duration_is_not_enough() {
    assert!(!establishes_persistent_congestion(
        batch(),
        ms(350),
        Some(ms(100))
    ));
}
