//! The thresholds that declare a packet lost ([RFC 9002 §6.1]).
//!
//! A packet sent before an acknowledged packet of its packet number space
//! is lost when a later packet of its link path is acknowledged and at
//! least [`PacketThreshold`] packets of that link path lie between them, or
//! when it has been outstanding for [`loss_delay`]. The thresholds are
//! endpoint configuration, checked when they are built
//! ([`LossThresholds::new`]).
//!
//! [RFC 9002 §6.1]: https://www.rfc-editor.org/rfc/rfc9002.html#section-6.1
use crate::{ratio::Ratio, rtt::RttEstimate};
use core::time::Duration;
use snafu::{Snafu, ensure};

/// The packet reordering threshold, at least 3 (`kPacketThreshold`, RFC
/// 9002 §6.1.1: SHOULD NOT be less than 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PacketThreshold(u64);

impl PacketThreshold {
    /// 3, the value RFC 9002 recommends and the smallest allowed.
    pub const RECOMMENDED: Self = Self(3);

    /// The threshold `threshold`, in packets.
    ///
    /// # Errors
    ///
    /// [`PacketThresholdBelowThreeError`] if `threshold` is below 3.
    pub const fn new(threshold: u64) -> Result<Self, PacketThresholdBelowThreeError> {
        if threshold < Self::RECOMMENDED.0 {
            return Err(PacketThresholdBelowThreeError { threshold });
        }
        Ok(Self(threshold))
    }

    /// The number of packets.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A packet threshold is below 3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("packet threshold {threshold} is below 3"))]
pub struct PacketThresholdBelowThreeError {
    threshold: u64,
}

impl PacketThresholdBelowThreeError {
    /// The rejected threshold, below 3.
    pub const fn threshold(&self) -> u64 {
        self.threshold
    }
}

/// The time threshold RFC 9002 recommends, as a multiple of the RTT
/// (`kTimeThreshold`, §6.1.2): 9/8.
pub const RECOMMENDED_TIME_THRESHOLD: Ratio = Ratio::literal(9, 8);

/// The timer granularity RFC 9002 recommends (`kGranularity`, §6.1.2):
/// 1 ms.
pub const RECOMMENDED_GRANULARITY: Duration = Duration::from_millis(1);

/// The configured thresholds of loss detection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LossThresholds {
    packet_threshold: PacketThreshold,
    time_threshold: Ratio,
    granularity: Duration,
}

impl LossThresholds {
    /// The thresholds given, for a clock whose timers fire with a precision
    /// of `clock_granularity`.
    ///
    /// `granularity` is the timer granularity of loss detection and of the
    /// probe timeout.
    ///
    /// # Errors
    ///
    /// [`GranularityBelowClockError`] if `granularity` is below
    /// `clock_granularity`: RFC 9002 §6.1.2 says the time threshold MUST
    /// NOT be below the actual granularity of the timer. A configured value
    /// is not raised silently, so what the configuration says is what is
    /// used.
    pub fn new(
        packet_threshold: PacketThreshold,
        time_threshold: Ratio,
        granularity: Duration,
        clock_granularity: Duration,
    ) -> Result<Self, GranularityBelowClockError> {
        ensure!(
            granularity >= clock_granularity,
            GranularityBelowClockSnafu {
                granularity,
                clock_granularity,
            }
        );
        Ok(Self {
            packet_threshold,
            time_threshold,
            granularity,
        })
    }

    /// The values RFC 9002 recommends, for a clock whose timers fire with a
    /// precision of `clock_granularity`.
    ///
    /// # Errors
    ///
    /// [`GranularityBelowClockError`] if the clock is coarser than 1 ms.
    pub fn recommended(clock_granularity: Duration) -> Result<Self, GranularityBelowClockError> {
        Self::new(
            PacketThreshold::RECOMMENDED,
            RECOMMENDED_TIME_THRESHOLD,
            RECOMMENDED_GRANULARITY,
            clock_granularity,
        )
    }

    /// The packet reordering threshold.
    pub const fn packet_threshold(&self) -> PacketThreshold {
        self.packet_threshold
    }

    /// The time threshold, as a multiple of the RTT.
    pub const fn time_threshold(&self) -> Ratio {
        self.time_threshold
    }

    /// The timer granularity.
    pub const fn granularity(&self) -> Duration {
        self.granularity
    }
}

/// The configured timer granularity is finer than the clock's timers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("timer granularity {granularity:?} is below the clock's {clock_granularity:?}"))]
pub struct GranularityBelowClockError {
    granularity: Duration,
    clock_granularity: Duration,
}

impl GranularityBelowClockError {
    /// The configured granularity.
    pub const fn granularity(&self) -> Duration {
        self.granularity
    }

    /// The precision of the clock's timers, above the configured
    /// granularity.
    pub const fn clock_granularity(&self) -> Duration {
        self.clock_granularity
    }
}

/// How long a packet may be outstanding before the time threshold declares
/// it lost: `max(time_threshold × max(latest_rtt, smoothed_rtt),
/// granularity)` (RFC 9002 §6.1.2 and Appendix A.10).
///
/// Before the first sample the latest RTT is zero and the smoothed RTT is
/// the initial RTT.
pub fn loss_delay(rtt: &RttEstimate, thresholds: &LossThresholds) -> Duration {
    thresholds
        .time_threshold
        .of_duration(rtt.latest.max(rtt.smoothed))
        .max(thresholds.granularity)
}

#[cfg(test)]
mod tests;
