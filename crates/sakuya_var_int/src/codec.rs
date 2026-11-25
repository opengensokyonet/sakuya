//! Reading and writing [`VarInt`] and [`VarIntField`] in memory.
//!
//! [`read_var_int`] reads from a [`Buf`] and [`write_var_int`] writes to a
//! [`BufMut`]; a source that ends within the encoding is an
//! [`IncompleteError`]. [`read_var_int_field`] and [`write_var_int_field`]
//! keep the width of the encoding. For sources and sinks that may wait
//! between bytes, such as a stream, the types decode and encode the same
//! encoding with `nitori_codec`; see [`stream`](super::stream).
//!
//! ```
//! use sakuya_var_int::{
//!     VarInt,
//!     codec::{read_var_int, write_var_int},
//! };
//!
//! let mut output = Vec::new();
//! write_var_int(&mut output, VarInt::from(15293u16));
//! assert_eq!(output, [0x7b, 0xbd]);
//!
//! let mut input = &[0x7b, 0xbd, 0x25][..];
//! assert_eq!(read_var_int(&mut input).unwrap(), VarInt::from(15293u16));
//! assert_eq!(input, [0x25]); // The next integer has not been read.
//!
//! // Encodings longer than necessary are accepted.
//! let mut input = &[0x40, 0x25][..];
//! assert_eq!(read_var_int(&mut input).unwrap(), VarInt::from(37u8));
//!
//! // A source that ends within the encoding is incomplete.
//! let mut input = &[0x9d, 0x7f][..];
//! let error = read_var_int(&mut input).unwrap_err();
//! assert_eq!((error.completed(), error.expected()), (2, 4));
//! ```
//!
//! A field keeps the width it was read with and writes it back:
//!
//! ```
//! use sakuya_var_int::{
//!     VarInt, VarIntField, VarIntWidth,
//!     codec::{read_var_int_field, write_var_int_field},
//! };
//!
//! let mut input = &[0x40, 0x25][..];
//! let field: VarIntField<VarInt> = read_var_int_field(&mut input).unwrap();
//! assert_eq!((field.get(), field.width()), (VarInt::from(37u8), VarIntWidth::Two));
//!
//! let mut output = Vec::new();
//! write_var_int_field(&mut output, field);
//! assert_eq!(output, [0x40, 0x25]);
//! ```
use super::{VarInt, VarIntField, VarIntWidth};
use bytes::{Buf, BufMut};
use core::convert::Infallible;
use nitori_io::error::IncompleteError;
use snafu::{ResultExt, Snafu};

/// Reads one variable-length integer.
///
/// Reads the first byte, then exactly the remaining bytes of the length it
/// announces, and nothing after them. Encodings longer than necessary are
/// accepted.
///
/// # Errors
///
/// [`IncompleteError`] if the source ends before the encoding is complete:
/// it expects the encoded length once the first byte has been read, and 1
/// if the source is empty. The bytes that were there stay consumed.
pub fn read_var_int(src: &mut impl Buf) -> Result<VarInt, IncompleteError> {
    read_var_int_with_width(src).map(|(value, _)| value)
}

/// Reads one variable-length integer as [`read_var_int`] does, and returns
/// it with the width of its encoding.
pub(crate) fn read_var_int_with_width(
    src: &mut impl Buf,
) -> Result<(VarInt, VarIntWidth), IncompleteError> {
    if !src.has_remaining() {
        return Err(incomplete(src, 1, 0));
    }
    let first = src.get_u8();
    let width = VarIntWidth::of_first_byte(first);
    let rest = width.encoded_len() - 1;
    if src.remaining() < rest {
        return Err(incomplete(src, width.encoded_len(), 1));
    }
    let mut encoding = [0; VarInt::MAX_ENCODED_LEN - 1];
    src.copy_to_slice(&mut encoding[..rest]);
    Ok((VarInt::from_encoding(first, &encoding[..rest]), width))
}

/// Writes the shortest encoding of `value`.
///
/// # Panics
///
/// If `dst` has no room for the encoding, as [`BufMut::put_slice`] does;
/// a `Vec` or `BytesMut` grows instead.
pub fn write_var_int(dst: &mut impl BufMut, value: VarInt) {
    let (encoding, encoded_len) = value.to_encoding();
    dst.put_slice(&encoding[..encoded_len]);
}

/// Reads one variable-length integer field: its value as a `T`, and the
/// width of its encoding.
///
/// Reads exactly one encoding, of any width, as [`read_var_int`] does, then
/// converts the value with `T::try_from`.
///
/// # Errors
///
/// [`ReadVarIntFieldError::VarInt`] if the encoding cannot be read, and
/// [`ReadVarIntFieldError::Value`] if `T` rejects the value; the encoding
/// stays consumed.
pub fn read_var_int_field<T>(
    src: &mut impl Buf,
) -> Result<VarIntField<T>, ReadVarIntFieldError<<T as TryFrom<VarInt>>::Error>>
where
    T: Copy + Into<VarInt> + TryFrom<VarInt>,
{
    let (value, width) = read_var_int_with_width(src)?;
    let value = T::try_from(value).context(read_var_int_field_error::ValueSnafu { value })?;
    // The encoding of `width` holds the value, and `T` converts back to it.
    Ok(VarIntField { value, width })
}

/// Failures that [`read_var_int_field`] can produce.
///
/// `V` is the error of converting the value into the field's type. For a
/// type that every value converts into, it is [`Infallible`], and the
/// failure converts into an [`IncompleteError`].
#[derive(Debug, Snafu)]
#[snafu(module(read_var_int_field_error), visibility(pub(crate)))]
pub enum ReadVarIntFieldError<V> {
    /// The encoding could not be read.
    #[snafu(transparent)]
    VarInt {
        /// The shortfall, counted over the encoding.
        source: IncompleteError,
    },
    /// The field's type rejects the value.
    #[snafu(display("variable-length integer {value} is outside the range of the field"))]
    Value {
        /// The value that was read.
        value: VarInt,
        /// The conversion error.
        source: V,
    },
}

impl From<ReadVarIntFieldError<Infallible>> for IncompleteError {
    fn from(error: ReadVarIntFieldError<Infallible>) -> Self {
        match error {
            ReadVarIntFieldError::VarInt { source } => source,
            ReadVarIntFieldError::Value { source, .. } => match source {},
        }
    }
}

/// Writes the encoding of `field` at its width.
///
/// # Panics
///
/// If `dst` has no room for the encoding, as [`BufMut::put_slice`] does.
pub fn write_var_int_field<T>(dst: &mut impl BufMut, field: VarIntField<T>)
where
    T: Copy + Into<VarInt> + TryFrom<VarInt>,
{
    let (encoding, encoded_len) = field.to_encoding();
    dst.put_slice(&encoding[..encoded_len]);
}

/// The error of a source that ends after `offset` of the `expected` bytes of
/// an encoding, consuming what is left of it.
///
/// It is the same as `sakuya_wire::source::incomplete`, copied because this
/// package does not depend on `sakuya_wire`; a change to one is checked
/// against the other.
///
/// # Panics
///
/// If `offset` plus the bytes left is not below `expected`.
fn incomplete(src: &mut impl Buf, expected: usize, offset: usize) -> IncompleteError {
    let completed = offset + src.remaining();
    src.advance(src.remaining());
    // invariant: every caller has found fewer than `expected - offset` bytes
    // left, so `completed` is below `expected`.
    IncompleteError::new(expected, completed).expect("fewer bytes are left than the field needs")
}
