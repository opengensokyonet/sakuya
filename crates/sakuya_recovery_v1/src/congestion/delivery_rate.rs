//! Delivery rate sampling (draft-ietf-ccwg-bbr-07 §4.1).
//!
//! The sampler keeps the connection state of §4.1.2.1.1 for one link path
//! (`C.delivered`, `C.delivered_time`, `C.first_send_time`, `C.lost` and
//! the application-limited bubble `C.app_limited`) and gives each packet
//! sealed a [`DeliverySnapshot`], the per-packet state of §4.1.2.1.2. The
//! packets an ACK newly acknowledges go through a [`RateSampleBuilder`]
//! (UpdateRateSample, §4.1.2.3), which becomes one [`RateSample`]
//! (GenerateRateSample).
//!
//! Lifetime totals are `u64`; volumes, such as the bytes in flight, are
//! `usize` as in the rest of the crate.
use crate::checked_duration_since;
use core::{ops::Sub, time::Duration};

/// `bytes` as a lifetime total.
pub(crate) fn total(bytes: usize) -> u64 {
    u64::try_from(bytes).unwrap_or(u64::MAX)
}

/// A difference of lifetime totals as a volume, saturating.
pub(crate) fn volume(bytes: u64) -> usize {
    usize::try_from(bytes).unwrap_or(usize::MAX)
}

/// The connection state of the delivery rate sampling of one link path.
#[derive(Clone, Debug)]
pub(crate) struct DeliveryRateSampler<I> {
    /// `C.delivered`.
    delivered: u64,
    /// `C.delivered_time`; `None` before the first packet.
    delivered_time: Option<I>,
    /// `C.first_send_time`; `None` before the first packet.
    first_send_time: Option<I>,
    /// `C.app_limited`: the delivered total that ends the bubble; `None`
    /// when the link path is not limited by the application.
    app_limited_until: Option<u64>,
    /// `C.lost`.
    lost: u64,
    /// The identifier the next packet gets (`P.packet_id`): the order the
    /// sampler saw packets sealed.
    next_packet_id: u64,
}

/// What a packet sealed keeps of the connection state (§4.1.2.1.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DeliverySnapshot<I> {
    /// `P.delivered`.
    pub(crate) delivered: u64,
    /// `P.delivered_time`.
    pub(crate) delivered_time: I,
    /// `P.first_send_time`.
    pub(crate) first_send_time: I,
    /// `P.send_time`: the instant of the poll it was sealed in.
    pub(crate) send_time: I,
    /// `P.is_app_limited`.
    pub(crate) is_app_limited: bool,
    /// `P.tx_in_flight`: the bytes in flight once it was sealed.
    pub(crate) tx_in_flight: usize,
    /// `P.lost`.
    pub(crate) lost: u64,
    /// `P.packet_id`.
    pub(crate) packet_id: u64,
}

/// The rate sample of one ACK while its packets are taken in
/// (InitRateSample and UpdateRateSample, §4.1.2.3).
#[derive(Clone, Copy, Debug)]
pub(crate) struct RateSampleBuilder<I> {
    /// The newest packet delivered so far, with the delivered time at its
    /// acknowledgment (`RS.ack_elapsed` is computed from it); `None` while
    /// `RS.has_data` is false.
    newest: Option<DeliverySnapshot<I>>,
    /// `RS.newly_acked`.
    newly_acked: usize,
}

impl<I> RateSampleBuilder<I> {
    /// InitRateSample.
    pub(crate) const fn new() -> Self {
        Self {
            newest: None,
            newly_acked: 0,
        }
    }
}

/// The rate sample of one ACK (§4.1.2.1.3, with `RS.newly_acked`,
/// `RS.tx_in_flight` and `RS.lost` of §2.3).
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct RateSample {
    /// `RS.delivery_rate`, in bytes per second; zero without a reliable
    /// sample.
    pub(crate) delivery_rate: f64,
    /// `RS.is_app_limited`.
    pub(crate) is_app_limited: bool,
    /// `RS.delivered`.
    pub(crate) delivered: usize,
    /// `RS.prior_delivered`.
    pub(crate) prior_delivered: u64,
    /// `RS.tx_in_flight` of the newest packet delivered.
    pub(crate) tx_in_flight: usize,
    /// `RS.lost`: the bytes declared lost between the sending and the
    /// acknowledgment of the newest packet delivered.
    pub(crate) lost: usize,
    /// `RS.newly_acked`.
    pub(crate) newly_acked: usize,
}

impl<I> DeliveryRateSampler<I> {
    /// The state of a link path that has sent nothing.
    pub(crate) const fn new() -> Self {
        Self {
            delivered: 0,
            delivered_time: None,
            first_send_time: None,
            app_limited_until: None,
            lost: 0,
            next_packet_id: 0,
        }
    }

    /// `C.delivered`.
    pub(crate) const fn delivered(&self) -> u64 {
        self.delivered
    }

    /// `C.lost`.
    pub(crate) const fn lost(&self) -> u64 {
        self.lost
    }

    /// Whether `C.app_limited` is set.
    pub(crate) const fn is_app_limited(&self) -> bool {
        self.app_limited_until.is_some()
    }

    /// MarkConnectionAppLimited (§4.1.2.4) with `bytes_in_flight` as
    /// `C.inflight`.
    pub(crate) fn mark_app_limited(&mut self, bytes_in_flight: usize) {
        let until = self.delivered.saturating_add(total(bytes_in_flight));
        self.app_limited_until = Some(until.max(1));
    }

    /// Bytes declared lost: `C.lost` grows.
    pub(crate) fn on_lost(&mut self, bytes: usize) {
        self.lost = self.lost.saturating_add(total(bytes));
    }
}

impl<I: Ord + Copy + Sub<Output = Duration>> DeliveryRateSampler<I> {
    /// OnPacketSent (§4.1.2.2) for a packet of `bytes` sealed at `now`,
    /// leaving `bytes_in_flight` in flight with it.
    pub(crate) fn on_sent(
        &mut self,
        bytes: usize,
        bytes_in_flight: usize,
        now: I,
    ) -> DeliverySnapshot<I> {
        let (first_send_time, delivered_time) = match (self.first_send_time, self.delivered_time) {
            (Some(first_send_time), Some(delivered_time)) if bytes_in_flight > bytes => {
                (first_send_time, delivered_time)
            }
            // nothing was in flight before it
            _ => (now, now),
        };
        self.first_send_time = Some(first_send_time);
        self.delivered_time = Some(delivered_time);
        let packet_id = self.next_packet_id;
        self.next_packet_id = self.next_packet_id.wrapping_add(1);
        DeliverySnapshot {
            delivered: self.delivered,
            delivered_time,
            first_send_time,
            send_time: now,
            is_app_limited: self.is_app_limited(),
            tx_in_flight: bytes_in_flight,
            lost: self.lost,
            packet_id,
        }
    }

    /// Bytes declared lost earlier were acknowledged at `now` after all:
    /// they count as delivered (§2.2, SHOULD), without a rate sample.
    pub(crate) fn on_spuriously_lost(&mut self, bytes: usize, now: I) {
        self.delivered = self.delivered.saturating_add(total(bytes));
        self.delivered_time = Some(now);
    }

    /// UpdateRateSample: the packet of `snapshot` with `bytes` was newly
    /// acknowledged at `now`.
    pub(crate) fn on_acked(
        &mut self,
        sample: &mut RateSampleBuilder<I>,
        snapshot: &DeliverySnapshot<I>,
        bytes: usize,
        now: I,
    ) {
        self.delivered = self.delivered.saturating_add(total(bytes));
        self.delivered_time = Some(now);
        sample.newly_acked = sample.newly_acked.saturating_add(bytes);
        let newest = match (sample.newest, self.first_send_time) {
            (None, _) | (_, None) => true,
            (Some(newest), Some(first_send_time)) => {
                snapshot.send_time > first_send_time
                    || (snapshot.send_time == first_send_time
                        && snapshot.packet_id > newest.packet_id)
            }
        };
        if newest {
            sample.newest = Some(*snapshot);
            self.first_send_time = Some(snapshot.send_time);
        }
    }

    /// GenerateRateSample at `now`, the instant of the ACK; `min_rtt` is
    /// `C.min_rtt`. `None` if the ACK delivered nothing.
    pub(crate) fn generate(
        &mut self,
        sample: RateSampleBuilder<I>,
        now: I,
        min_rtt: Duration,
    ) -> Option<RateSample> {
        // the bubble is acknowledged and gone
        if self
            .app_limited_until
            .is_some_and(|until| self.delivered > until)
        {
            self.app_limited_until = None;
        }
        let newest = sample.newest?;
        let send_elapsed = checked_duration_since(newest.send_time, newest.first_send_time)
            .unwrap_or(Duration::ZERO);
        let ack_elapsed =
            checked_duration_since(now, newest.delivered_time).unwrap_or(Duration::ZERO);
        let interval = send_elapsed.max(ack_elapsed);
        let delivered = volume(self.delivered.saturating_sub(newest.delivered));
        let delivery_rate = if interval < min_rtt || interval.is_zero() {
            // no reliable rate sample
            0.0
        } else {
            delivered as f64 / interval.as_secs_f64()
        };
        Some(RateSample {
            delivery_rate,
            is_app_limited: newest.is_app_limited,
            delivered,
            prior_delivered: newest.delivered,
            tx_in_flight: newest.tx_in_flight,
            lost: volume(self.lost.saturating_sub(newest.lost)),
            newly_acked: sample.newly_acked,
        })
    }
}

#[cfg(test)]
mod tests;
