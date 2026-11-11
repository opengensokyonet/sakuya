//! The probe timeout ([RFC 9002 §6.2]).
//!
//! When and how often the probe timeout expires is fixed by the protocol:
//! [`probe_timeout`] computes its duration, and the caller sets and resets
//! the deadline. What to send when it expires is replaceable: the
//! [`PtoPolicy`] of the link path, which is the same value as its
//! congestion controller and pacer.
//!
//! [RFC 9002 §6.2]: https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2
use crate::{
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaceSet},
    rtt::RttEstimate,
};
use core::time::Duration;

/// `smoothed_rtt + max(4 × rttvar, granularity)`, saturating.
pub(crate) fn probe_timeout_base(rtt: &RttEstimate, granularity: Duration) -> Duration {
    rtt.smoothed
        .saturating_add(rtt.variation.saturating_mul(4).max(granularity))
}

/// The probe timeout of a link path in `space`, after `backoff` expiries
/// without an acknowledgment: `(smoothed_rtt + max(4 × rttvar,
/// granularity) + max_ack_delay) × 2^backoff` (RFC 9002 §6.2.1).
///
/// `max_ack_delay` is the peer's in the Application Data space and zero in
/// the Initial and Handshake spaces. With `backoff` zero it is the probe
/// timeout without backoff, which the idle timeout and the ECN test read.
/// It is at least `granularity`, and saturates at [`Duration::MAX`]: the
/// backoff has no upper bound.
pub fn probe_timeout(
    rtt: &RttEstimate,
    granularity: Duration,
    space: PacketNumberSpaceKind,
    peer_max_ack_delay: Duration,
    backoff: u32,
) -> Duration {
    let base = probe_timeout_base(rtt, granularity);
    let duration = match space {
        PacketNumberSpaceKind::Initial | PacketNumberSpaceKind::Handshake => base,
        PacketNumberSpaceKind::ApplicationData => base.saturating_add(peer_max_ack_delay),
    };
    match 1u32.checked_shl(backoff) {
        Some(factor) => duration.saturating_mul(factor),
        None if duration.is_zero() => Duration::ZERO,
        None => Duration::MAX,
    }
}

/// What to do when the probe timeout of a link path expires.
///
/// It is implemented by the same value as the link path's congestion
/// controller and pacer, so that the choice can depend on the congestion
/// state. When the deadline is and how the backoff grows are fixed and not
/// part of this trait.
pub trait PtoPolicy<I> {
    /// The probe timeout expired; `expiry.backoff` already counts this
    /// expiry.
    ///
    /// Whatever the answer, the caller probes in
    /// [`expired_space`](PtoExpiry::expired_space) even if
    /// [`Probe::spaces`](PtoAction::Probe) leaves it out (RFC 9002 §6.2.4,
    /// MUST), and every probe datagram is ack-eliciting.
    ///
    /// By default it sends two datagrams, so that one lost probe does not
    /// cost another doubled timeout, in every space with ack-eliciting
    /// packets in flight (§6.2.4, SHOULD); it does not declare the packets
    /// in flight lost instead, which would reduce the window for nothing.
    fn on_pto_expired(&mut self, expiry: &PtoExpiry<I>) -> PtoAction {
        PtoAction::Probe {
            datagrams: ProbeCount::Two,
            spaces: expiry.in_flight_spaces,
        }
    }

    /// A server received an Initial whose CRYPTO data it had all received
    /// before: the client likely lost the server's Initial. `true` resends
    /// the server's unacknowledged Initial CRYPTO data now, without waiting
    /// for the probe timeout (RFC 9002 §6.2.3, MAY).
    fn on_duplicate_initial_crypto(&mut self) -> bool;
}

impl<I, T: PtoPolicy<I> + ?Sized> PtoPolicy<I> for &mut T {
    fn on_pto_expired(&mut self, expiry: &PtoExpiry<I>) -> PtoAction {
        (**self).on_pto_expired(expiry)
    }

    fn on_duplicate_initial_crypto(&mut self) -> bool {
        (**self).on_duplicate_initial_crypto()
    }
}

/// The facts of one expiry of a probe timeout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PtoExpiry<I> {
    /// When it expired: the instant of the poll.
    pub at: I,
    /// The space whose timeout expired, the earliest of the link path.
    pub expired_space: PacketNumberSpaceKind,
    /// The spaces with ack-eliciting packets in flight on this link path.
    pub in_flight_spaces: PacketNumberSpaceSet,
    /// The backoff count, this expiry included.
    pub backoff: u32,
    /// The RTT estimate of this link path.
    pub rtt: RttEstimate,
}

/// What to do at an expiry of the probe timeout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PtoAction {
    /// Send probe datagrams that may exceed the congestion window, with a
    /// PING in each of `spaces`.
    Probe {
        /// How many datagrams.
        datagrams: ProbeCount,
        /// The spaces to probe in, besides the expired one.
        spaces: PacketNumberSpaceSet,
    },
    /// Send nothing and declare the packets in flight lost (RFC 9002
    /// §6.2.4, MAY).
    MarkInFlightLost,
}

/// How many probe datagrams to send: at most two (RFC 9002 §6.2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProbeCount {
    /// One datagram.
    One,
    /// Two datagrams.
    Two,
}

impl ProbeCount {
    /// The number of datagrams.
    pub const fn get(self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => 2,
        }
    }
}

#[cfg(test)]
mod tests;
