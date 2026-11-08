//! Packet numbers ([RFC 9000 §12.3]).
//!
//! A [`PacketNumber`] is an integer from 0 to 2<sup>62</sup> − 1 that
//! identifies a packet within its packet number space. Packet headers carry
//! it truncated and protected; ACK frames carry it whole as variable-length
//! integers, so every [`VarInt`] is a packet number. The length of the Packet
//! Number field of a header is a [`PacketNumberLength`].
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
///
/// Only [`PacketNumber::new`] and the conversions into [`PacketNumber`]
/// construct it, so the value it holds always exceeds 2<sup>62</sup> − 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("{value} exceeds the largest packet number 2^62 - 1"))]
pub struct OutOfRangeError {
    value: u64,
}

impl OutOfRangeError {
    /// The rejected value, above 2<sup>62</sup> − 1.
    pub const fn value(self) -> u64 {
        self.value
    }
}

/// The length of a Packet Number field, 1 to 4 bytes ([RFC 9000 §17.1]).
///
/// The two Packet Number Length bits of the unprotected first header byte
/// hold the length minus one.
///
/// [RFC 9000 §17.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.1
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PacketNumberLength {
    /// A 1-byte field.
    One,
    /// A 2-byte field.
    Two,
    /// A 3-byte field.
    Three,
    /// A 4-byte field.
    Four,
}

impl PacketNumberLength {
    /// The field length of `len` bytes.
    ///
    /// # Errors
    ///
    /// Fails when `len` is not 1 to 4.
    pub const fn new(len: usize) -> Result<Self, PacketNumberLengthError> {
        match len {
            1 => Ok(Self::One),
            2 => Ok(Self::Two),
            3 => Ok(Self::Three),
            4 => Ok(Self::Four),
            _ => Err(PacketNumberLengthError { length: len }),
        }
    }

    /// The field length that the Packet Number Length bits of an unprotected
    /// first header byte encode; the other bits are ignored.
    pub const fn from_first_byte(first_byte: u8) -> Self {
        match first_byte & 0x03 {
            0 => Self::One,
            1 => Self::Two,
            2 => Self::Three,
            _ => Self::Four,
        }
    }

    /// The length in bytes, 1 to 4.
    pub const fn get(self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Three => 3,
            Self::Four => 4,
        }
    }

    /// The value of the Packet Number Length bits for this length, the
    /// length minus one, which occupies the two least significant bits of
    /// the first header byte.
    pub const fn first_byte_bits(self) -> u8 {
        match self {
            Self::One => 0,
            Self::Two => 1,
            Self::Three => 2,
            Self::Four => 3,
        }
    }
}

/// The error returned by [`PacketNumberLength::new`]: the length is not 1 to
/// 4 bytes.
///
/// Only [`PacketNumberLength::new`] constructs it, for a length it refuses.
#[derive(Debug, Snafu)]
#[snafu(display("packet number field of {length} bytes is not 1 to 4 bytes long"))]
pub struct PacketNumberLengthError {
    length: usize,
}

impl PacketNumberLengthError {
    /// The length given, which is zero or above four.
    pub const fn length(&self) -> usize {
        self.length
    }
}

#[cfg(test)]
mod tests {
    use super::{PacketNumber, PacketNumberLength};
    use crate::var_int::VarInt;

    #[test]
    fn range_and_arithmetic() {
        assert_eq!(PacketNumber::MAX.get(), (1 << 62) - 1);
        assert_eq!(PacketNumber::new(1 << 62).unwrap_err().value(), 1 << 62);
        assert_eq!(PacketNumber::new(u64::MAX).unwrap_err().value(), u64::MAX);
        assert_eq!(
            PacketNumber::new(1 << 62).unwrap_err().to_string(),
            "4611686018427387904 exceeds the largest packet number 2^62 - 1"
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

    #[test]
    fn packet_number_length_bounds() {
        assert_eq!(PacketNumberLength::new(0).unwrap_err().length(), 0);
        assert_eq!(PacketNumberLength::new(5).unwrap_err().length(), 5);
        for (bytes, expected) in [
            (1, PacketNumberLength::One),
            (2, PacketNumberLength::Two),
            (3, PacketNumberLength::Three),
            (4, PacketNumberLength::Four),
        ] {
            let length = PacketNumberLength::new(bytes).unwrap();
            assert_eq!(length, expected);
            assert_eq!(length.get(), bytes);
            assert_eq!(usize::from(length.first_byte_bits()), bytes - 1);
            assert_eq!(
                PacketNumberLength::from_first_byte(length.first_byte_bits()),
                length
            );
        }
    }

    #[test]
    fn packet_number_length_from_first_byte_ignores_other_bits() {
        assert_eq!(
            PacketNumberLength::from_first_byte(0xfc),
            PacketNumberLength::One
        );
        assert_eq!(
            PacketNumberLength::from_first_byte(0xc1),
            PacketNumberLength::Two
        );
        assert_eq!(
            PacketNumberLength::from_first_byte(0x42),
            PacketNumberLength::Three
        );
        assert_eq!(
            PacketNumberLength::from_first_byte(0xff),
            PacketNumberLength::Four
        );
    }
}
