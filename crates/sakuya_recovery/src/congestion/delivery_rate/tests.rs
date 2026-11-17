use super::{DeliveryRateSampler, RateSampleBuilder};
use core::time::Duration;

fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}

#[test]
fn the_first_packet_starts_the_interval_at_its_sending() {
    let mut sampler = DeliveryRateSampler::new();
    let snapshot = sampler.on_sent(1200, 1200, ms(10));
    // OnPacketSent with nothing in flight (§4.1.2.2).
    assert_eq!(snapshot.first_send_time, ms(10));
    assert_eq!(snapshot.delivered_time, ms(10));
    assert_eq!(snapshot.delivered, 0);
    assert_eq!(snapshot.tx_in_flight, 1200);
    let later = sampler.on_sent(1200, 2400, ms(12));
    assert_eq!(later.first_send_time, ms(10));
    assert_eq!(later.send_time, ms(12));
    assert_eq!(later.packet_id, snapshot.packet_id + 1);
}

#[test]
fn the_rate_is_the_lower_of_the_send_and_ack_rates() {
    let mut sampler = DeliveryRateSampler::new();
    // Ten packets sent over 40 ms, all acknowledged at 60 ms.
    let snapshots: Vec<_> = (0..10)
        .map(|i| sampler.on_sent(1200, 1200 * (i + 1), ms(4 * i as u64)))
        .collect();
    let mut sample = RateSampleBuilder::new();
    for snapshot in &snapshots {
        sampler.on_acked(&mut sample, snapshot, 1200, ms(60));
    }
    let rs = sampler.generate(sample, ms(60), ms(20)).unwrap();
    // send_elapsed = 36 ms, ack_elapsed = 60 ms: 12000 bytes / 60 ms
    // (§4.1.1.2.4).
    assert_eq!(rs.delivered, 12000);
    assert!((rs.delivery_rate - 200_000.0).abs() < 1e-6);
    assert_eq!(rs.tx_in_flight, 12000);
    assert_eq!(rs.newly_acked, 12000);

    // The next flight is sent over 50 ms from 60 ms, with nothing in
    // flight before it, and acknowledged together at 140 ms.
    let snapshots: Vec<_> = (0..10)
        .map(|i| sampler.on_sent(1200, 1200 * (i + 1), ms(60 + 50 * i as u64 / 9)))
        .collect();
    let mut sample = RateSampleBuilder::new();
    for snapshot in &snapshots {
        sampler.on_acked(&mut sample, snapshot, 1200, ms(140));
    }
    let rs = sampler.generate(sample, ms(140), ms(20)).unwrap();
    // Sent with nothing in flight: send_elapsed = 50 ms from the first,
    // ack_elapsed = 140 − 60 = 80 ms.
    assert!((rs.delivery_rate - 12000.0 / 0.080).abs() < 1e-6);
}

#[test]
fn an_ack_compressed_flight_is_capped_by_the_send_rate() {
    let mut sampler = DeliveryRateSampler::new();
    let a = sampler.on_sent(1200, 1200, ms(0));
    let _b = sampler.on_sent(1200, 2400, ms(100));
    let mut sample = RateSampleBuilder::new();
    sampler.on_acked(&mut sample, &a, 1200, ms(150));
    sampler.generate(sample, ms(150), ms(0)).unwrap();
    // Sent with b in flight: it starts from the ACK of a at 150 ms and from
    // a's sending at 0 ms.
    let c = sampler.on_sent(1200, 2400, ms(160));
    assert_eq!(c.delivered_time, ms(150));
    assert_eq!(c.first_send_time, ms(0));
    let mut sample = RateSampleBuilder::new();
    sampler.on_acked(&mut sample, &c, 1200, ms(170));
    let rs = sampler.generate(sample, ms(170), ms(0)).unwrap();
    // ack_elapsed = 20 ms would give 60000 bytes/s; send_elapsed = 160 ms
    // caps it at 7500 (§4.1.1.2.4).
    assert_eq!(rs.delivered, 1200);
    assert!((rs.delivery_rate - 7500.0).abs() < 1e-6);
}

#[test]
fn an_interval_below_the_minimum_rtt_gives_no_rate() {
    let mut sampler = DeliveryRateSampler::new();
    let snapshot = sampler.on_sent(1200, 1200, ms(0));
    let mut sample = RateSampleBuilder::new();
    sampler.on_acked(&mut sample, &snapshot, 1200, ms(10));
    let rs = sampler.generate(sample, ms(10), ms(20)).unwrap();
    assert_eq!(rs.delivery_rate, 0.0);
    assert_eq!(rs.delivered, 1200);
}

#[test]
fn an_ack_without_packets_gives_no_sample() {
    let mut sampler = DeliveryRateSampler::<Duration>::new();
    assert_eq!(
        sampler.generate(RateSampleBuilder::new(), ms(10), ms(0)),
        None
    );
}

#[test]
fn the_bubble_ends_once_the_data_in_flight_at_marking_is_delivered() {
    let mut sampler = DeliveryRateSampler::new();
    let a = sampler.on_sent(1200, 1200, ms(0));
    // MarkConnectionAppLimited with 1200 in flight: C.app_limited =
    // 0 + 1200 (§4.1.2.4).
    sampler.mark_app_limited(1200);
    let b = sampler.on_sent(1200, 2400, ms(1));
    assert!(!a.is_app_limited);
    assert!(b.is_app_limited);
    let mut sample = RateSampleBuilder::new();
    sampler.on_acked(&mut sample, &a, 1200, ms(30));
    sampler.generate(sample, ms(30), ms(0));
    // C.delivered = 1200 is not above the bubble.
    assert!(sampler.is_app_limited());
    let mut sample = RateSampleBuilder::new();
    sampler.on_acked(&mut sample, &b, 1200, ms(31));
    let rs = sampler.generate(sample, ms(31), ms(0)).unwrap();
    assert!(rs.is_app_limited);
    assert!(!sampler.is_app_limited());
}

#[test]
fn the_newest_packet_gives_the_sample() {
    let mut sampler = DeliveryRateSampler::new();
    let a = sampler.on_sent(1200, 1200, ms(0));
    let b = sampler.on_sent(1200, 2400, ms(5));
    sampler.on_lost(1200);
    let c = sampler.on_sent(1200, 2400, ms(5));
    let mut sample = RateSampleBuilder::new();
    // Out of order: c, then a, then b.
    sampler.on_acked(&mut sample, &c, 1200, ms(40));
    sampler.on_acked(&mut sample, &a, 1200, ms(40));
    sampler.on_acked(&mut sample, &b, 1200, ms(40));
    let rs = sampler.generate(sample, ms(40), ms(0)).unwrap();
    // c and b share a send time; c was sealed later (IsNewestPacket).
    assert_eq!(rs.tx_in_flight, c.tx_in_flight);
    assert_eq!(rs.lost, 0);
    assert_eq!(rs.prior_delivered, 0);
    assert_eq!(rs.delivered, 3600);
    // RS.lost counts the loss after b's sending, before c's.
    assert_eq!(c.lost, 1200);
    assert_eq!(b.lost, 0);
}
