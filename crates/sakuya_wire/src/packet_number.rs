//! Packet numbers ([RFC 9000 §12.3]).
//!
//! A [`PacketNumber`] is an integer from 0 to 2<sup>62</sup> − 1 that
//! identifies a packet within its packet number space. Packet headers carry
//! it truncated and protected; ACK frames carry it whole as variable-length
//! integers, so every [`VarInt`] is a packet number.
//!
//! [RFC 9000 §12.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.3
use crate::var_int::VarInt;
use core::fmt;
use snafu::Snafu;

/// A QUIC packet number: 0 to 2<sup>62</sup> − 1.
///
/// Equality, ordering and hashing are those of the numeric value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PacketNumber(VarInt);

impl PacketNumber {
    /// Packet number zero, the first of every packet number space.
    pub const ZERO: Self = Self(VarInt::ZERO);

    /// The largest packet number, 2<sup>62</sup> − 1.
    pub const MAX: Self = Self(VarInt::MAX);

    /// Returns the packet number `value`.
    ///
    /// This is the `const` form of `PacketNumber::try_from(value)`.
    ///
    /// # Errors
    ///
    /// [`OutOfRangeError`] if `value` exceeds [`PacketNumber::MAX`].
    pub const fn new(value: u64) -> Result<Self, OutOfRangeError> {
        match VarInt::new(value) {
            Ok(value) => Ok(Self(value)),
            Err(_) => Err(OutOfRangeError { value }),
        }
    }

    /// The packet number a variable-length integer states.
    pub const fn from_var_int(value: VarInt) -> Self {
        Self(value)
    }

    /// The numeric value.
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// The packet number as a variable-length integer.
    pub const fn to_var_int(self) -> VarInt {
        self.0
    }

    /// Adds `count`, returning `None` past [`PacketNumber::MAX`].
    pub const fn checked_add(self, count: u64) -> Option<Self> {
        match self.get().checked_add(count) {
            Some(value) => match Self::new(value) {
                Ok(number) => Some(number),
                Err(_) => None,
            },
            None => None,
        }
    }

    /// Subtracts `count`, returning `None` below zero.
    pub const fn checked_sub(self, count: u64) -> Option<Self> {
        match self.get().checked_sub(count) {
            Some(value) => match Self::new(value) {
                Ok(number) => Some(number),
                Err(_) => None,
            },
            None => None,
        }
    }
}

impl From<VarInt> for PacketNumber {
    fn from(value: VarInt) -> Self {
        Self(value)
    }
}

impl From<PacketNumber> for VarInt {
    fn from(number: PacketNumber) -> Self {
        number.0
    }
}

impl TryFrom<u64> for PacketNumber {
    type Error = OutOfRangeError;

    /// Accepts values up to [`PacketNumber::MAX`].
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<PacketNumber> for u64 {
    fn from(number: PacketNumber) -> Self {
        number.get()
    }
}

/// Formats the numeric value.
impl fmt::Display for PacketNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// A value exceeds [`PacketNumber::MAX`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("{value} exceeds the largest packet number 2^62 - 1"))]
pub struct OutOfRangeError {
    /// The rejected value.
    pub value: u64,
}

#[cfg(test)]
mod tests {
    use super::{OutOfRangeError, PacketNumber};
    use crate::var_int::VarInt;

    #[test]
    fn range_and_arithmetic() {
        assert_eq!(PacketNumber::MAX.get(), (1 << 62) - 1);
        assert_eq!(
            PacketNumber::new(1 << 62),
            Err(OutOfRangeError { value: 1 << 62 })
        );
        assert_eq!(PacketNumber::try_from(7u64).map(u64::from), Ok(7));
        assert_eq!(PacketNumber::MAX.checked_add(1), None);
        assert_eq!(PacketNumber::ZERO.checked_sub(1), None);
        assert_eq!(
            PacketNumber::ZERO
                .checked_add(5)
                .and_then(|pn| pn.checked_sub(2)),
            PacketNumber::new(3).ok()
        );
        assert_eq!(PacketNumber::from(VarInt::MAX), PacketNumber::MAX);
        assert_eq!(VarInt::from(PacketNumber::ZERO), VarInt::ZERO);
        assert_eq!(PacketNumber::new(42).unwrap().to_string(), "42");
    }
}
