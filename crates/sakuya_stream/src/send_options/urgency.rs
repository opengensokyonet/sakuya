//! The default send parameter: the urgency of [RFC 9218 §4.1]
//! ([`Urgency`]), and what a send strategy that orders by it asks of the
//! parameters ([`SendUrgency`]).
//!
//! [RFC 9218 §4.1]: https://www.rfc-editor.org/rfc/rfc9218.html#section-4.1
use snafu::{Snafu, ensure};

/// The urgency of [RFC 9218 §4.1] (`Urgency`): `0` to `7`, `3` by default;
/// a smaller value is sent first.
///
/// The order of the type follows the value, so `a < b` means that `a` goes
/// before `b`. It ranks application data only: STREAM and DATAGRAM data by
/// the same measure, never the connection's own frames. The `incremental`
/// parameter of RFC 9218 is not part of it.
///
/// [RFC 9218 §4.1]: https://www.rfc-editor.org/rfc/rfc9218.html#section-4.1
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Urgency(u8);

impl Urgency {
    /// The largest value, the urgency sent last.
    const LOWEST: u8 = 7;

    /// The urgency `value`.
    ///
    /// # Errors
    ///
    /// [`UrgencyOutOfRangeError`] if `value` exceeds `7`.
    pub fn new(value: u8) -> Result<Self, UrgencyOutOfRangeError> {
        ensure!(value <= Self::LOWEST, UrgencyOutOfRangeSnafu { value });
        Ok(Self(value))
    }

    /// The value, `0` to `7`.
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// `3`, the urgency of RFC 9218 when none is given.
impl Default for Urgency {
    fn default() -> Self {
        Self(3)
    }
}

impl TryFrom<u8> for Urgency {
    type Error = UrgencyOutOfRangeError;

    fn try_from(value: u8) -> Result<Self, UrgencyOutOfRangeError> {
        Self::new(value)
    }
}

impl From<Urgency> for u8 {
    fn from(urgency: Urgency) -> Self {
        urgency.get()
    }
}

/// An urgency above `7`, beyond the range of RFC 9218.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("urgency {value} lies beyond the range 0 to 7"))]
pub struct UrgencyOutOfRangeError {
    value: u8,
}

impl UrgencyOutOfRangeError {
    /// The rejected value, above `7`.
    pub const fn value(self) -> u8 {
        self.value
    }
}

/// Send parameters that give an [`Urgency`] (`SendUrgency`): what the
/// default send strategy and the default send buffer order data by.
pub trait SendUrgency {
    /// The urgency of the data these parameters were written with.
    fn urgency(&self) -> Urgency;
}

/// An urgency is the simplest send parameter: it gives itself.
impl SendUrgency for Urgency {
    fn urgency(&self) -> Urgency {
        *self
    }
}
