//! Variable-length integers ([RFC 9000 §16]).
//!
//! A [`VarInt`] holds a value below 2<sup>62</sup>. Its encoding takes 1, 2, 4
//! or 8 bytes, its [`VarIntWidth`]: the two most significant bits of the
//! first byte give the width, and the remaining bits hold the value in
//! network byte order. A value has an encoding of every width that can hold
//! it; RFC 9000 permits encodings longer than necessary.
//!
//! [`codec::read_var_int`] and [`codec::write_var_int`] read and write the
//! encoding as `nitori_call` operations, on sources and sinks that may wait
//! between bytes as well as on byte slices, through the `sync_` host methods.
//! They read a value of any width and write the shortest encoding.
//!
//! A [`VarIntField`] is a field of a wire format that holds a variable-length
//! integer: a value together with the width of its encoding.
//! [`codec::read_var_int_field`] keeps the width it reads, and
//! [`codec::write_var_int_field`] writes that width, so a field reads back as
//! it was written and writes back the bytes it was read from.
//!
//! [RFC 9000 §16]: https://www.rfc-editor.org/rfc/rfc9000.html#section-16
use core::fmt;
use snafu::Snafu;

pub mod codec;

/// A QUIC variable-length integer: an unsigned value of at most 62 bits.
///
/// Every value of this type is at most [`VarInt::MAX`]; the constructors
/// enforce that bound. Ordering, equality and hashing are those of the
/// numeric value. A `VarInt` has no width: [`codec::write_var_int`] always
/// writes the shortest encoding, and [`codec::read_var_int`] also accepts
/// longer encodings, as RFC 9000 §16 permits. [`VarIntField`] keeps the
/// width.
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
    ///
    /// This is the length of [`VarIntWidth::shortest`].
    pub const fn encoded_len(self) -> usize {
        VarIntWidth::shortest(self).encoded_len()
    }

    /// Returns the encoded length that a first byte announces: 1, 2, 4 or 8.
    ///
    /// Every byte value announces a length; whether the encoding is complete
    /// depends on the bytes that follow. This is the length of
    /// [`VarIntWidth::of_first_byte`].
    pub const fn encoded_len_of(first_byte: u8) -> usize {
        VarIntWidth::of_first_byte(first_byte).encoded_len()
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
        self.to_encoding_of(VarIntWidth::shortest(self))
    }

    /// The encoding of `width`, left-aligned in an array, and its length.
    ///
    /// The value must fit `width`; callers check it with
    /// [`VarIntWidth::fits`] first.
    pub(crate) const fn to_encoding_of(
        self,
        width: VarIntWidth,
    ) -> ([u8; Self::MAX_ENCODED_LEN], usize) {
        debug_assert!(width.fits(self));
        let encoded_len = width.encoded_len();
        // The two-bit length prefix is log2 of the encoded length; it occupies
        // the top bits of the encoding, which then moves to the array's start.
        let prefix = (width as u64) << (8 * encoded_len - 2);
        let value = self.0 & width.max_value().0;
        let shift = 8 * (Self::MAX_ENCODED_LEN - encoded_len);
        (((prefix | value) << shift).to_be_bytes(), encoded_len)
    }
}

/// The number of bytes a variable-length integer encoding takes: 1, 2, 4 or
/// 8.
///
/// A width holds the values up to [`VarIntWidth::max_value`]. Widths are
/// ordered by their length.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VarIntWidth {
    /// One byte, for values up to 2<sup>6</sup> − 1.
    One = 0,
    /// Two bytes, for values up to 2<sup>14</sup> − 1.
    Two = 1,
    /// Four bytes, for values up to 2<sup>30</sup> − 1.
    Four = 2,
    /// Eight bytes, for values up to 2<sup>62</sup> − 1.
    Eight = 3,
}

impl VarIntWidth {
    /// Every width, shortest first.
    pub const ALL: [Self; 4] = [Self::One, Self::Two, Self::Four, Self::Eight];

    /// The shortest width that holds `value`.
    pub const fn shortest(value: VarInt) -> Self {
        if value.0 < 1 << 6 {
            Self::One
        } else if value.0 < 1 << 14 {
            Self::Two
        } else if value.0 < 1 << 30 {
            Self::Four
        } else {
            Self::Eight
        }
    }

    /// The width that the two most significant bits of a first byte
    /// announce.
    pub const fn of_first_byte(first_byte: u8) -> Self {
        match first_byte >> 6 {
            0 => Self::One,
            1 => Self::Two,
            2 => Self::Four,
            _ => Self::Eight,
        }
    }

    /// The number of bytes of the encoding: 1, 2, 4 or 8.
    pub const fn encoded_len(self) -> usize {
        1 << self as u32
    }

    /// The largest value an encoding of this width holds.
    pub const fn max_value(self) -> VarInt {
        VarInt((1 << (8 * self.encoded_len() - 2)) - 1)
    }

    /// Whether an encoding of this width holds `value`.
    pub const fn fits(self, value: VarInt) -> bool {
        value.0 <= self.max_value().0
    }
}

/// A field of a wire format that holds a variable-length integer: a value of
/// type `T` and the [`VarIntWidth`] of its encoding.
///
/// The value always fits the width. [`VarIntField::shortest`] chooses the
/// shortest width, as a sender normally does; [`VarIntField::new`] takes any
/// width that holds the value, as an encoding read from the wire may use.
/// Equality and hashing cover both the value and the width, so two fields
/// with the same value and different widths are different fields.
///
/// `T` is the type the field carries, such as [`VarInt`] itself or a domain
/// type like a stream ID. It converts into a `VarInt` for writing and from
/// one for reading: the constructors and the codec require
/// `T: Into<VarInt> + TryFrom<VarInt>`. These conversions must agree, so
/// that a field reads back as the value it was written from: for every value
/// `x` of `T`, `T::try_from(VarInt::from(x))` is `Ok(x)`. A conversion from
/// `VarInt` may still fail for values outside the range of `T`; reading then
/// reports the error of `T`.
///
/// ```
/// use sakuya_wire::var_int::{VarInt, VarIntField, VarIntWidth};
///
/// let shortest = VarIntField::shortest(VarInt::from(37u8));
/// assert_eq!(shortest.width(), VarIntWidth::One);
///
/// let long = VarIntField::new(VarInt::from(37u8), VarIntWidth::Two).unwrap();
/// assert_eq!(long.get(), VarInt::from(37u8));
/// assert_ne!(long, shortest);
///
/// // 64 needs two bytes.
/// assert!(VarIntField::new(VarInt::from(64u8), VarIntWidth::One).is_err());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VarIntField<T> {
    value: T,
    width: VarIntWidth,
}

impl<T> VarIntField<T> {
    /// The width of the encoding.
    pub const fn width(&self) -> VarIntWidth {
        self.width
    }

    /// The number of bytes of the encoding: the length of its width.
    pub const fn encoded_len(&self) -> usize {
        self.width.encoded_len()
    }

    /// Takes the value.
    pub fn into_inner(self) -> T {
        self.value
    }
}

impl<T: Copy> VarIntField<T> {
    /// The value.
    pub const fn get(&self) -> T {
        self.value
    }
}

impl<T: Copy + Into<VarInt> + TryFrom<VarInt>> VarIntField<T> {
    /// The field holding `value` in its shortest encoding.
    pub fn shortest(value: T) -> Self {
        Self {
            value,
            width: VarIntWidth::shortest(value.into()),
        }
    }

    /// The field holding `value` in an encoding of `width`.
    ///
    /// # Errors
    ///
    /// [`VarIntWidthError`] if `value` does not fit `width`.
    pub fn new(value: T, width: VarIntWidth) -> Result<Self, VarIntWidthError> {
        let var_int = value.into();
        if !width.fits(var_int) {
            return Err(VarIntWidthError {
                value: var_int,
                width,
            });
        }
        Ok(Self { value, width })
    }

    /// The value as a variable-length integer.
    pub fn to_var_int(&self) -> VarInt {
        self.value.into()
    }
}

/// A value does not fit the width chosen for its encoding.
///
/// Only [`VarIntField::new`] constructs it, when the value does not fit, so
/// the width is never 8 bytes and the value always exceeds what the width
/// holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "{value} does not fit a {}-byte variable-length integer encoding",
    width.encoded_len()
))]
pub struct VarIntWidthError {
    value: VarInt,
    width: VarIntWidth,
}

impl VarIntWidthError {
    /// The value, which exceeds what [`width`](Self::width) holds.
    pub const fn value(self) -> VarInt {
        self.value
    }

    /// The width that cannot hold the value; never 8 bytes.
    pub const fn width(self) -> VarIntWidth {
        self.width
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
