//! RTT estimation ([RFC 9002 §5]).
//!
//! Each link path keeps one [`RttEstimator`]. When an ACK newly
//! acknowledges its largest acknowledged packet and at least one newly
//! acknowledged packet is ack-eliciting, the link path where that largest
//! packet was sent gets one [`RttSample`]; the other link paths of the ACK
//! get none. The time threshold of loss detection, the probe timeout and
//! the congestion controller read the [`RttEstimate`].
//!
//! The rules the protocol fixes are applied before the estimator sees a
//! sample, by [`effective_ack_delay`] and [`RttSample::new`]: an estimator
//! cannot break them. How the samples become an estimate is the
//! estimator's; [`Rfc9002RttEstimator`] computes it as RFC 9002 does.
//!
//! [RFC 9002 §5]: https://www.rfc-editor.org/rfc/rfc9002.html#section-5
use crate::{checked_duration_since, packet_number_space::PacketNumberSpaceKind};
use core::{marker::PhantomData, ops::Sub, time::Duration};

/// The RTT assumed before anything better is known, 333 ms
/// (`kInitialRtt`, RFC 9002 §6.2.2 and Appendix A.2).
pub const INITIAL_RTT: Duration = Duration::from_millis(333);

/// The RTT estimate of one link path.
///
/// `I` is the type of instants. Each implementation fixes the type of
/// [`Via`](Self::Via), where the acknowledgments came back from.
pub trait RttEstimator<I> {
    /// Where an acknowledgment came back from: the logical link identity
    /// when a connection supports QUIC version 1 alone.
    type Via;

    /// Takes the sample of an ACK whose largest acknowledged packet was
    /// sent on this link path. It runs once per such ACK, before loss
    /// detection.
    fn on_sample(&mut self, sample: RttSample<I, Self::Via>);

    /// Persistent congestion was established on this link path. RFC 9002
    /// §5.2 says the minimum RTT SHOULD then become the latest sample.
    fn on_persistent_congestion(&mut self);

    /// The current estimate.
    fn estimate(&self) -> RttEstimate;
}

/// The four values of an RTT estimate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RttEstimate {
    /// The latest sample; zero before the first.
    pub latest: Duration,
    /// The minimum RTT; zero before the first sample.
    pub min: Duration,
    /// The smoothed RTT; the initial RTT before the first sample.
    pub smoothed: Duration,
    /// The RTT variation; half the initial RTT before the first sample.
    pub variation: Duration,
}

impl RttEstimate {
    /// The estimate before the first sample: the smoothed RTT is
    /// `initial_rtt` and the variation half of it; the latest sample and
    /// the minimum are zero (RFC 9002 Appendix A.4).
    pub fn initial(initial_rtt: Duration) -> Self {
        Self {
            latest: Duration::ZERO,
            min: Duration::ZERO,
            smoothed: initial_rtt,
            variation: initial_rtt / 2,
        }
    }
}

/// One RTT sample, already put through the rules the protocol fixes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RttSample<I, Via> {
    at: I,
    latest: Duration,
    adjusted: Duration,
    ack_via: Via,
}

impl<I, Via> RttSample<I, Via> {
    /// The sample of an ACK whose largest acknowledged packet was sent at
    /// `sent_at`, carried by a datagram that arrived at `arrived_at` over
    /// `ack_via`.
    ///
    /// `ack_delay` is what to take off, from [`effective_ack_delay`], and
    /// `min_rtt` the minimum of the estimate before this sample. As in RFC
    /// 9002 Appendix A.7, the sample first lowers that minimum if it is
    /// smaller; the delay is taken off only where the result stays at or
    /// above it (§5.3, MUST NOT go below).
    ///
    /// `None` if the packet was sent after the ACK arrived: such a sample
    /// is dropped and leaves the estimate as it was. Instants a link
    /// reports for an accepted send are not guaranteed to come before the
    /// datagram leaves, so an honest connection can see a sample slightly
    /// below zero.
    pub fn new(
        sent_at: I,
        arrived_at: I,
        ack_delay: Duration,
        min_rtt: Duration,
        ack_via: Via,
    ) -> Option<Self>
    where
        I: Ord + Copy + Sub<Output = Duration>,
    {
        let latest = checked_duration_since(arrived_at, sent_at)?;
        let min_rtt = min_rtt.min(latest);
        let adjusted = latest
            .checked_sub(ack_delay)
            .filter(|adjusted| *adjusted >= min_rtt)
            .unwrap_or(latest);
        Some(Self {
            at: arrived_at,
            latest,
            adjusted,
            ack_via,
        })
    }

    /// When the datagram that carried the ACK arrived.
    pub fn at(&self) -> &I {
        &self.at
    }

    /// The sample without the acknowledgment delay taken off.
    pub const fn latest(&self) -> Duration {
        self.latest
    }

    /// The sample with the acknowledgment delay taken off, where that stays
    /// at or above the minimum RTT; otherwise the same as
    /// [`latest`](Self::latest).
    pub const fn adjusted(&self) -> Duration {
        self.adjusted
    }

    /// Where the ACK came back from.
    pub fn ack_via(&self) -> &Via {
        &self.ack_via
    }
}

/// The acknowledgment delay to take off a sample, from the delay the peer
/// reported (RFC 9002 §5.3).
///
/// In the Initial space it is zero: a peer has no reason to delay those
/// acknowledgments. Before the handshake is confirmed the reported delay
/// stands, since the peer may have waited for keys; once it is confirmed,
/// the delay is at most the peer's `max_ack_delay`. A server's handshake is
/// confirmed when it completes (RFC 9001 §4.1.2).
pub fn effective_ack_delay(
    space: PacketNumberSpaceKind,
    reported: Duration,
    handshake_confirmed: bool,
    peer_max_ack_delay: Duration,
) -> Duration {
    match space {
        PacketNumberSpaceKind::Initial => Duration::ZERO,
        PacketNumberSpaceKind::Handshake | PacketNumberSpaceKind::ApplicationData
            if handshake_confirmed =>
        {
            reported.min(peer_max_ack_delay)
        }
        PacketNumberSpaceKind::Handshake | PacketNumberSpaceKind::ApplicationData => reported,
    }
}

/// The RTT estimate RFC 9002 §5 and Appendix A.7 compute.
///
/// The first sample sets the minimum and the smoothed RTT to itself and the
/// variation to half of it. Each later sample lowers the minimum to itself
/// if smaller, without the acknowledgment delay taken off, and moves the
/// smoothed RTT an eighth and the variation a quarter of the way toward the
/// adjusted sample; the variation is measured against the smoothed RTT
/// before this sample (Appendix A.7 and RFC 6298).
///
/// It ignores where acknowledgments came back from; `Via` only fixes the
/// type its samples carry.
#[derive(Debug)]
pub struct Rfc9002RttEstimator<Via> {
    estimate: RttEstimate,
    sampled: bool,
    via: PhantomData<fn(Via)>,
}

impl<Via> Rfc9002RttEstimator<Via> {
    /// An estimator with no sample yet, starting from `initial_rtt`.
    ///
    /// The initial RTT sets the smoothed RTT and the variation only; it is
    /// not a sample and does not set the minimum.
    pub fn new(initial_rtt: Duration) -> Self {
        Self {
            estimate: RttEstimate::initial(initial_rtt),
            sampled: false,
            via: PhantomData,
        }
    }
}

impl<Via> Clone for Rfc9002RttEstimator<Via> {
    fn clone(&self) -> Self {
        Self {
            estimate: self.estimate,
            sampled: self.sampled,
            via: PhantomData,
        }
    }
}

impl<I, Via> RttEstimator<I> for Rfc9002RttEstimator<Via> {
    type Via = Via;

    fn on_sample(&mut self, sample: RttSample<I, Via>) {
        let estimate = &mut self.estimate;
        estimate.latest = sample.latest;
        if !self.sampled {
            self.sampled = true;
            estimate.min = sample.latest;
            estimate.smoothed = sample.latest;
            estimate.variation = sample.latest / 2;
            return;
        }
        estimate.min = estimate.min.min(sample.latest);
        estimate.variation = weighted_average(
            estimate.variation,
            estimate.smoothed.abs_diff(sample.adjusted),
            4,
        );
        estimate.smoothed = weighted_average(estimate.smoothed, sample.adjusted, 8);
    }

    fn on_persistent_congestion(&mut self) {
        if self.sampled {
            self.estimate.min = self.estimate.latest;
        }
    }

    fn estimate(&self) -> RttEstimate {
        self.estimate
    }
}

/// `(parts − 1) / parts` of `average` plus `1 / parts` of `sample`.
fn weighted_average(average: Duration, sample: Duration, parts: u32) -> Duration {
    crate::ratio::duration_from_nanos(
        (average.as_nanos() * u128::from(parts - 1) + sample.as_nanos()) / u128::from(parts),
    )
}

#[cfg(test)]
mod tests;
