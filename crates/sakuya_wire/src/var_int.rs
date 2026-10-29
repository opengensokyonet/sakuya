//! Variable-length integers ([RFC 9000 §16]).
//!
//! A [`VarInt`] holds a value below 2<sup>62</sup>. Its encoding takes 1, 2, 4
//! or 8 bytes: the two most significant bits of the first byte give the
//! encoded length, and the remaining bits hold the value in network byte
//! order.
//!
//! [`codec::read_var_int`] and [`codec::write_var_int`] read and write the
//! encoding as `nitori_call` operations, on sources and sinks that may wait
//! between bytes as well as on byte slices, through the `sync_` host methods.
//!
//! [RFC 9000 §16]: https://www.rfc-editor.org/rfc/rfc9000.html#section-16
use core::fmt;
use snafu::Snafu;

pub mod codec;

/// A QUIC variable-length integer: an unsigned value of at most 62 bits.
///
/// Every value of this type is at most [`VarInt::MAX`]; the constructors
/// enforce that bound. Ordering, equality and hashing are those of the
/// numeric value. [`codec::write_var_int`] always writes the shortest
/// encoding; [`codec::read_var_int`] also accepts longer encodings, as
/// RFC 9000 §16 permits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VarInt(u64);

impl VarInt {
    /// The value zero.
    pub const ZERO: Self = Self(0);

    /// The largest representable value, 2<sup>62</sup> − 1.
    pub const MAX: Self = Self((1 << 62) - 1);

    /// The largest number of bytes an encoding takes.
    pub const MAX_ENCODED_LEN: usize = 8;

    /// Returns the value if it is at most [`VarInt::MAX`].
    ///
    /// This is the `const` form of `VarInt::try_from(value)`.
    ///
    /// # Errors
    ///
    /// [`OutOfRangeError`] if `value` exceeds [`VarInt::MAX`].
    pub const fn new(value: u64) -> Result<Self, OutOfRangeError> {
        if value <= Self::MAX.0 {
            Ok(Self(value))
        } else {
            Err(OutOfRangeError { value })
        }
    }

    /// Converts a `u32`, which always fits.
    pub const fn from_u32(value: u32) -> Self {
        Self(value as u64)
    }

    /// Returns the numeric value.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the number of bytes of the shortest encoding: 1, 2, 4 or 8.
    pub const fn encoded_len(self) -> usize {
        if self.0 < 1 << 6 {
            1
        } else if self.0 < 1 << 14 {
            2
        } else if self.0 < 1 << 30 {
            4
        } else {
            8
        }
    }

    /// Returns the encoded length that a first byte announces: 1, 2, 4 or 8.
    ///
    /// Every byte value announces a length; whether the encoding is complete
    /// depends on the bytes that follow.
    pub const fn encoded_len_of(first_byte: u8) -> usize {
        1 << (first_byte >> 6)
    }

    /// Adds, returning `None` if the sum exceeds [`VarInt::MAX`].
    pub const fn checked_add(self, rhs: Self) -> Option<Self> {
        // Both operands are below 2^62, so the `u64` sum cannot overflow.
        match Self::new(self.0 + rhs.0) {
            Ok(value) => Some(value),
            Err(_) => None,
        }
    }

    /// Subtracts, returning `None` if the difference would be negative.
    pub const fn checked_sub(self, rhs: Self) -> Option<Self> {
        match self.0.checked_sub(rhs.0) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Multiplies, returning `None` if the product exceeds [`VarInt::MAX`].
    pub const fn checked_mul(self, rhs: Self) -> Option<Self> {
        match self.0.checked_mul(rhs.0) {
            Some(value) => match Self::new(value) {
                Ok(value) => Some(value),
                Err(_) => None,
            },
            None => None,
        }
    }

    /// Adds, returning [`VarInt::MAX`] if the sum exceeds it.
    pub const fn saturating_add(self, rhs: Self) -> Self {
        match self.checked_add(rhs) {
            Some(value) => value,
            None => Self::MAX,
        }
    }

    /// Subtracts, returning zero if the difference would be negative.
    pub const fn saturating_sub(self, rhs: Self) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }

    /// Decodes an encoding from its first byte and the bytes that follow it.
    ///
    /// Only the low six bits of `first` are value bits; `rest` holds the
    /// remaining bytes of the encoding, at most seven, so the value stays
    /// below 2<sup>62</sup>.
    pub(crate) const fn from_encoding(first: u8, rest: &[u8]) -> Self {
        let mut value = (first & 0x3f) as u64;
        let mut index = 0;
        while index < rest.len() {
            value = (value << 8) | rest[index] as u64;
            index += 1;
        }
        Self(value)
    }

    /// The shortest encoding, left-aligned in an array, and its length.
    pub(crate) const fn to_encoding(self) -> ([u8; Self::MAX_ENCODED_LEN], usize) {
        let encoded_len = self.encoded_len();
        // The two-bit length prefix is log2 of the encoded length; it occupies
        // the top bits of the encoding, which then moves to the array's start.
        let prefix = (encoded_len.trailing_zeros() as u64) << (8 * encoded_len - 2);
        let shift = 8 * (Self::MAX_ENCODED_LEN - encoded_len);
        (((prefix | self.0) << shift).to_be_bytes(), encoded_len)
    }
}

impl fmt::Display for VarInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl From<u8> for VarInt {
    fn from(value: u8) -> Self {
        Self(value.into())
    }
}

impl From<u16> for VarInt {
    fn from(value: u16) -> Self {
        Self(value.into())
    }
}

impl From<u32> for VarInt {
    fn from(value: u32) -> Self {
        Self::from_u32(value)
    }
}

impl TryFrom<u64> for VarInt {
    type Error = OutOfRangeError;

    /// Accepts values up to [`VarInt::MAX`].
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<usize> for VarInt {
    type Error = OutOfRangeError;

    /// Accepts values up to [`VarInt::MAX`].
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        // `usize` is at most 64 bits wide on every target Rust supports.
        Self::try_from(value as u64)
    }
}

impl From<VarInt> for u64 {
    fn from(value: VarInt) -> Self {
        value.0
    }
}

/// A value exceeds [`VarInt::MAX`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("{value} exceeds the variable-length integer maximum 2^62 - 1"))]
pub struct OutOfRangeError {
    /// The rejected value.
    pub value: u64,
}

#[cfg(test)]
mod tests;
