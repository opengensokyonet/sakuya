//! Exact ratios of two integers, for the constants RFC 9002 states as
//! fractions: 9/8, 5/4, 1/2.
use core::time::Duration;
use snafu::Snafu;

/// A ratio `numerator / denominator` with a denominator above zero.
///
/// Applying a ratio multiplies before it divides, so that no precision is
/// lost to an intermediate rounding. Results round down and saturate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ratio {
    numerator: u32,
    denominator: u32,
}

impl Ratio {
    /// The ratio `numerator / denominator`.
    ///
    /// # Errors
    ///
    /// [`ZeroDenominatorError`] if `denominator` is zero.
    pub const fn new(numerator: u32, denominator: u32) -> Result<Self, ZeroDenominatorError> {
        if denominator == 0 {
            return Err(ZeroDenominatorError { numerator });
        }
        Ok(Self {
            numerator,
            denominator,
        })
    }

    /// A ratio of two constants.
    pub(crate) const fn literal(numerator: u32, denominator: u32) -> Self {
        match Self::new(numerator, denominator) {
            Ok(ratio) => ratio,
            Err(_) => panic!("a ratio constant has a zero denominator"),
        }
    }

    /// The numerator.
    pub const fn numerator(self) -> u32 {
        self.numerator
    }

    /// The denominator, above zero.
    pub const fn denominator(self) -> u32 {
        self.denominator
    }

    /// Whether the ratio is below 1.
    pub const fn is_below_one(self) -> bool {
        self.numerator < self.denominator
    }

    /// This ratio of `duration`, saturating at [`Duration::MAX`].
    pub fn of_duration(self, duration: Duration) -> Duration {
        duration_from_nanos(
            duration.as_nanos() * u128::from(self.numerator) / u128::from(self.denominator),
        )
    }

    /// This ratio of `bytes`, saturating at [`usize::MAX`].
    pub fn of_bytes(self, bytes: usize) -> usize {
        let scaled = bytes as u128 * u128::from(self.numerator) / u128::from(self.denominator);
        usize::try_from(scaled).unwrap_or(usize::MAX)
    }
}

/// The denominator of a [`Ratio`] is zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("ratio {numerator}/0 has a zero denominator"))]
pub struct ZeroDenominatorError {
    numerator: u32,
}

impl ZeroDenominatorError {
    /// The numerator of the rejected ratio.
    pub const fn numerator(&self) -> u32 {
        self.numerator
    }
}

const NANOS_PER_SECOND: u128 = 1_000_000_000;

/// The duration of `nanos` nanoseconds, saturating at [`Duration::MAX`].
pub(crate) fn duration_from_nanos(nanos: u128) -> Duration {
    // invariant: the remainder of a division by 10^9 fits in a `u32`.
    let subsec_nanos = (nanos % NANOS_PER_SECOND) as u32;
    u64::try_from(nanos / NANOS_PER_SECOND).map_or(Duration::MAX, |seconds| {
        Duration::new(seconds, subsec_nanos)
    })
}

#[cfg(test)]
mod tests;
