//! The test for persistent congestion ([RFC 9002 §7.6] and Appendix B.8).
//!
//! It runs on one batch of packets just declared lost, of one link path in
//! one packet number space, by an ACK or by the time threshold. It looks
//! for a segment of the batch whose consecutive sequence numbers follow one
//! another and whose packets are all ack-eliciting and all sent after the
//! link path's first RTT sample; persistent congestion is established when
//! the send times of the first and the last of such a segment are further
//! apart than [`persistent_congestion_duration`].
//!
//! A gap in the sequence numbers may be an acknowledged packet or one
//! declared lost earlier; either way it ends the segment, which can miss
//! persistent congestion but never declares it wrongly. Each packet number
//! space is looked at on its own, which §7.6.2 allows: it can declare
//! persistent congestion that looking across spaces would not, and never
//! misses it. Losses that do not count for congestion (§7.4, and datagram
//! size probes) are left out of the batch by the caller.
//!
//! [RFC 9002 §7.6]: https://www.rfc-editor.org/rfc/rfc9002.html#section-7.6
use crate::{checked_duration_since, pto::probe_timeout_base, rtt::RttEstimate};
use core::{ops::Sub, time::Duration};

/// The multiple of the probe timeout without backoff that makes congestion
/// persistent (`kPersistentCongestionThreshold`, RFC 9002 §7.6.1): 3.
pub const PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;

/// The peer's `max_ack_delay` while it is not known yet: 25 ms, the default
/// of the transport parameter (RFC 9000 §18.2).
pub const DEFAULT_PEER_MAX_ACK_DELAY: Duration = Duration::from_millis(25);

/// The persistent congestion duration of a link path:
/// `(smoothed_rtt + max(4 × rttvar, granularity) + max_ack_delay) × 3`
/// (RFC 9002 §7.6.1).
///
/// `peer_max_ack_delay` is `None` while the peer's transport parameters are
/// not known, and 25 ms is used. Unlike the probe timeout it includes the
/// peer's `max_ack_delay` in every packet number space and has no backoff.
/// It saturates at [`Duration::MAX`].
pub fn persistent_congestion_duration(
    rtt: &RttEstimate,
    granularity: Duration,
    peer_max_ack_delay: Option<Duration>,
) -> Duration {
    probe_timeout_base(rtt, granularity)
        .saturating_add(peer_max_ack_delay.unwrap_or(DEFAULT_PEER_MAX_ACK_DELAY))
        .saturating_mul(PERSISTENT_CONGESTION_THRESHOLD)
}

/// A packet just declared lost, as far as the test needs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LostPacket<I> {
    /// Its consecutive sequence number on its link path, in its packet
    /// number space.
    pub seq: u64,
    /// When the link accepted it.
    pub sent_at: I,
    /// Whether it was ack-eliciting.
    pub ack_eliciting: bool,
}

/// Whether the batch `lost` establishes persistent congestion.
///
/// `lost` is in ascending sequence order. `duration` is the
/// [`persistent_congestion_duration`] of the link path, and
/// `first_rtt_sample_at` when the link path's first RTT sample arrived:
/// without one there is no persistent congestion, and a packet sent at or
/// before it ends a segment.
pub fn establishes_persistent_congestion<I>(
    lost: impl IntoIterator<Item = LostPacket<I>>,
    duration: Duration,
    first_rtt_sample_at: Option<I>,
) -> bool
where
    I: Ord + Copy + Sub<Output = Duration>,
{
    let Some(first_rtt_sample_at) = first_rtt_sample_at else {
        return false;
    };
    // The first packet of the current segment, and the last sequence number.
    let mut segment: Option<(I, u64)> = None;
    for packet in lost {
        if !packet.ack_eliciting || packet.sent_at <= first_rtt_sample_at {
            segment = None;
            continue;
        }
        let start = match segment {
            Some((start, last)) if last.checked_add(1) == Some(packet.seq) => start,
            _ => packet.sent_at,
        };
        segment = Some((start, packet.seq));
        if checked_duration_since(packet.sent_at, start).is_some_and(|span| span > duration) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests;
