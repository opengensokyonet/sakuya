//! Variable-length integers ([RFC 9000 §16]).
//!
//! A [`VarInt`] holds a value below 2<sup>62</sup>. Its encoding takes 1, 2, 4
//! or 8 bytes: the two most significant bits of the first byte give the
//! encoded length, and the remaining bits hold the value in network byte
//! order.
//!
//! Two entry points read and write the encoding:
//!
//! - [`VarInt::decode`] and [`VarInt::encode`] work on byte slices and
//!   [`BufMut`] buffers that already hold or can take the whole encoding.
//! - [`calls::read_var_int`] and [`calls::write_var_int`] are `nitori_call`
//!   operations over `nitori_io` capabilities, for sources and sinks that may
//!   wait between bytes.
//!
//! [RFC 9000 §16]: https://www.rfc-editor.org/rfc/rfc9000.html#section-16
use bytes::BufMut;
use core::fmt;
use snafu::Snafu;

pub mod calls;

/// A QUIC variable-length integer: an unsigned value of at most 62 bits.
///
/// Every value of this type is at most [`VarInt::MAX`]; the constructors
/// enforce that bound. Ordering, equality and hashing are those of the
/// numeric value. The encoding chosen by [`VarInt::encode`] is always the
/// shortest one; [`VarInt::decode`] also accepts longer encodings, as
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
    pub const fn new(value: u64) -> Option<Self> {
        if value <= Self::MAX.0 {
            Some(Self(value))
        } else {
            None
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
        Self::new(self.0 + rhs.0)
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
            Some(value) => Self::new(value),
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

    /// Decodes one variable-length integer from the start of `bytes`.
    ///
    /// Returns the value and the number of bytes its encoding took; bytes
    /// after the encoding are not examined. Encodings longer than necessary
    /// are accepted.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Empty`] if `bytes` is empty, and
    /// [`DecodeError::Truncated`] if it is shorter than the length its first
    /// byte announces.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), DecodeError> {
        let Some(&first) = bytes.first() else {
            return Err(DecodeError::Empty);
        };
        let encoded_len = Self::encoded_len_of(first);
        let Some(encoding) = bytes.get(..encoded_len) else {
            return Err(DecodeError::Truncated {
                encoded_len,
                available: bytes.len(),
            });
        };
        Ok((Self::from_encoding(encoding), encoded_len))
    }

    /// Appends the shortest encoding of this value to `buffer`.
    ///
    /// Nothing is written unless the whole encoding fits.
    ///
    /// # Errors
    ///
    /// [`EncodeError`] if `buffer.remaining_mut()` is below
    /// [`VarInt::encoded_len`].
    pub fn encode<B: BufMut + ?Sized>(self, buffer: &mut B) -> Result<(), EncodeError> {
        let (bytes, encoded_len) = self.to_encoding();
        let available = buffer.remaining_mut();
        if available < encoded_len {
            return Err(EncodeError {
                required: encoded_len,
                available,
            });
        }
        buffer.put_slice(&bytes[..encoded_len]);
        Ok(())
    }

    /// Decodes a complete encoding whose length matches its first byte.
    fn from_encoding(encoding: &[u8]) -> Self {
        debug_assert_eq!(encoding.len(), Self::encoded_len_of(encoding[0]));
        let value = encoding[1..]
            .iter()
            .fold(u64::from(encoding[0] & 0x3f), |value, &byte| {
                (value << 8) | u64::from(byte)
            });
        Self(value)
    }

    /// The shortest encoding, left-aligned in an array, and its length.
    fn to_encoding(self) -> ([u8; Self::MAX_ENCODED_LEN], usize) {
        let encoded_len = self.encoded_len();
        // The two-bit length prefix is log2 of the encoded length; it occupies
        // the top bits of the encoding, which then moves to the array's start.
        let prefix = u64::from(encoded_len.trailing_zeros()) << (8 * encoded_len - 2);
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
        Self::new(value).ok_or(OutOfRangeError { value })
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

/// Failures of [`VarInt::decode`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(decode_error), visibility(pub(crate)))]
pub enum DecodeError {
    /// The input has no bytes.
    #[snafu(display("no bytes for a variable-length integer"))]
    Empty,
    /// The input ends before the length its first byte announces.
    #[snafu(display(
        "variable-length integer needs {encoded_len} bytes, but only {available} remain"
    ))]
    Truncated {
        /// The length announced by the first byte.
        encoded_len: usize,
        /// The bytes that were available, including the first.
        available: usize,
    },
}

/// The buffer passed to [`VarInt::encode`] cannot take the whole encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "variable-length integer needs {required} bytes, but the buffer has room for {available}"
))]
pub struct EncodeError {
    /// The length of the encoding.
    pub required: usize,
    /// The room the buffer reported.
    pub available: usize,
}

#[cfg(test)]
mod tests;
