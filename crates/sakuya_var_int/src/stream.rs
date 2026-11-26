//! Decoding and encoding [`VarInt`] and [`VarIntField`] on the sources and
//! sinks of `nitori_io`, for formats on byte streams.
//!
//! A format on a byte stream, such as the type and length of an HTTP/3
//! frame, can arrive in pieces, so reading it may wait between bytes. Both
//! types implement `nitori_codec`'s [`DecodeFrom`] and [`EncodeInto`] for
//! every source and sink that lends an access ([`AsAccess`]), and
//! [`EncodedLen`]. The formats that are read and written whole in memory use
//! [`codec`](super::codec) instead; the two read and write the same
//! encoding.
//!
//! A `VarInt` decodes from an encoding of any width and encodes the shortest
//! one; a `VarIntField` keeps the width it decodes and encodes at its width,
//! so that a field writes back the bytes it was read from.
//!
//! Both are base values: they read their own bytes, so they decode only from
//! sources without metadata (`Metadata = ()`). On a source with metadata,
//! decode `nitori_io::calls::ReadValue<VarInt, M>`, which holds the merged
//! metadata of the bytes the integer was read from. Encoding returns the
//! sink's reports of the bytes written, merged.
//!
//! Inside an operation, `io.decode::<VarInt>()` and `io.encode(value)` decode
//! and encode on an access; on a call executor, `nitori_codec::host` runs
//! them as the whole call, with `sync_` versions for receivers that never
//! wait. On those, a source that ends early is a
//! [`ReadVarIntError::Incomplete`] failure.
//!
//! ```
//! use nitori_codec::prelude::*;
//! use sakuya_var_int::{VarInt, VarIntField, VarIntWidth};
//!
//! let mut output = Vec::new();
//! output.sync_encode_unpin(VarInt::from(15293u16)).unwrap();
//! assert_eq!(output, [0x7b, 0xbd]);
//!
//! let mut input = &[0x7b, 0xbd, 0x25][..];
//! assert_eq!(input.sync_decode_unpin::<VarInt>().unwrap(), VarInt::from(15293u16));
//! assert_eq!(input, [0x25]);
//!
//! let mut input = &[0x40, 0x25][..];
//! let field = input.sync_decode_unpin::<VarIntField<VarInt>>().unwrap();
//! assert_eq!(field.width(), VarIntWidth::Two);
//!
//! let mut input = &[0x9d, 0x7f][..];
//! let error = input.sync_decode_unpin::<VarInt>().unwrap_err();
//! assert_eq!(error.completed(), 2);
//! ```
//!
//! A source with metadata needs `ReadValue`, for a `VarInt`:
//!
//! ```compile_fail,E0271
//! use nitori_call::AsAccess;
//! use nitori_codec::DecodeFrom;
//! use nitori_io::Read;
//! use sakuya_var_int::VarInt;
//!
//! fn decodes<S: AsAccess<Family: Read<Metadata = u8>>>(source: S) {
//!     let _ = VarInt::decode_from(source);
//! }
//! ```
//!
//! and for a `VarIntField`:
//!
//! ```compile_fail,E0271
//! use nitori_call::AsAccess;
//! use nitori_codec::DecodeFrom;
//! use nitori_io::Read;
//! use sakuya_var_int::{VarInt, VarIntField};
//!
//! fn decodes<S: AsAccess<Family: Read<Metadata = u8>>>(source: S) {
//!     let _ = VarIntField::<VarInt>::decode_from(source);
//! }
//! ```
use super::{VarInt, VarIntField, VarIntWidth};
use core::fmt;
use nitori_call::{AsAccess, ReceiverAccess};
use nitori_codec::{DecodeFrom, EncodeInto, EncodedLen};
use nitori_io::{
    Combine, Read, Write,
    calls::{ReadArrayError, ReadArrayExt as _, WriteAllError, WriteAllExt as _},
    error::{IncompleteError, WriteZeroError},
};
use snafu::{IntoError, Snafu};

/// Reads one encoding of any width, then exactly the remaining bytes of the
/// length its first byte announces, and nothing after them. Encodings
/// longer than necessary are accepted.
///
/// Bytes read before a failure stay consumed;
/// [`ReadVarIntError::completed`] reports how many there were.
impl<S> DecodeFrom<S> for VarInt
where
    S: AsAccess<Family: Read<Metadata = ()>>,
{
    type Error = ReadVarIntError<<S::Family as Read>::Error>;
    async fn decode_from(mut source: S) -> Result<Self, Self::Error> {
        let (value, _) = read_with_width(source.access()).await?;
        Ok(value)
    }
}

/// Reads one encoding as a `VarInt` does, as a field of type `T`, and keeps
/// the width of its encoding.
///
/// `T` takes every value, such as `VarInt` itself or a type that wraps it;
/// for a type that rejects some values, decode a `VarIntField<VarInt>` and
/// convert it, as [`codec::read_var_int_field`](super::codec::read_var_int_field)
/// does in memory.
impl<S, T> DecodeFrom<S> for VarIntField<T>
where
    S: AsAccess<Family: Read<Metadata = ()>>,
    T: Copy + Into<VarInt> + From<VarInt>,
{
    type Error = ReadVarIntError<<S::Family as Read>::Error>;
    async fn decode_from(mut source: S) -> Result<Self, Self::Error> {
        let (value, width) = read_with_width(source.access()).await?;
        // The encoding of `width` holds the value it was read with, and `T`
        // converts back to it.
        Ok(VarIntField {
            value: T::from(value),
            width,
        })
    }
}

/// Writes the shortest encoding completely and returns the merged report.
///
/// Acceptance by the receiver does not imply flushing or delivery. Bytes
/// accepted before a failure stay written; [`WriteVarIntError::completed`]
/// reports how many there were.
impl<S> EncodeInto<S> for VarInt
where
    S: AsAccess<Family: Write<Report: Combine>>,
{
    type Output = <S::Family as Write>::Report;
    type Error = WriteVarIntError<<S::Family as Write>::Error>;
    async fn encode_into(self, mut sink: S) -> Result<Self::Output, Self::Error> {
        let (encoding, encoded_len) = self.to_encoding();
        Ok(sink.access().write_all(&encoding[..encoded_len]).await?)
    }
}

/// Writes the encoding at the field's width completely, as
/// [`codec::write_var_int_field`](super::codec::write_var_int_field) does in
/// memory, and returns the merged report; a field decoded from a source
/// writes back the bytes it was read from.
///
/// As for a `VarInt`, bytes accepted before a failure stay written.
impl<S, T> EncodeInto<S> for VarIntField<T>
where
    S: AsAccess<Family: Write<Report: Combine>>,
    T: Copy + Into<VarInt> + TryFrom<VarInt>,
{
    type Output = <S::Family as Write>::Report;
    type Error = WriteVarIntError<<S::Family as Write>::Error>;
    async fn encode_into(self, mut sink: S) -> Result<Self::Output, Self::Error> {
        let (encoding, encoded_len) = self.to_encoding();
        Ok(sink.access().write_all(&encoding[..encoded_len]).await?)
    }
}

/// The length of the shortest encoding.
impl EncodedLen for VarInt {
    type LengthError = !;
    async fn encoded_len(&mut self) -> Result<u64, !> {
        Ok(encoded_length(VarInt::encoded_len(*self)))
    }
}

/// The length of the field's width.
impl<T> EncodedLen for VarIntField<T> {
    type LengthError = !;
    async fn encoded_len(&mut self) -> Result<u64, !> {
        Ok(encoded_length(self.width.encoded_len()))
    }
}

/// The length of an encoding, at most 8, as a `u64`.
fn encoded_length(len: usize) -> u64 {
    // invariant: an encoding has at most 8 bytes.
    u64::try_from(len).expect("an encoding has at most 8 bytes")
}

/// Reads one variable-length integer with the width of its encoding.
async fn read_with_width<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> Result<(VarInt, VarIntWidth), ReadVarIntError<F::Error>> {
    let [first] = io
        .read_array::<1>()
        .await
        .map_err(|error| ReadVarIntError::after(error, 0, 1))?
        .value;
    let width = VarIntWidth::of_first_byte(first);
    let encoded_len = width.encoded_len();
    let value = match width {
        VarIntWidth::One => VarInt::from_encoding(first, &[]),
        VarIntWidth::Two => {
            VarInt::from_encoding(first, &read_rest::<1, F, A>(io, encoded_len).await?)
        }
        VarIntWidth::Four => {
            VarInt::from_encoding(first, &read_rest::<3, F, A>(io, encoded_len).await?)
        }
        VarIntWidth::Eight => {
            VarInt::from_encoding(first, &read_rest::<7, F, A>(io, encoded_len).await?)
        }
    };
    Ok((value, width))
}

/// Reads the `LENGTH` bytes that follow the first byte of an encoding.
async fn read_rest<const LENGTH: usize, F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    encoded_len: usize,
) -> Result<[u8; LENGTH], ReadVarIntError<F::Error>> {
    Ok(io
        .read_array::<LENGTH>()
        .await
        .map_err(|error| ReadVarIntError::after(error, 1, encoded_len))?
        .value)
}

/// Failures of decoding a [`VarInt`] or a [`VarIntField`].
#[derive(Debug, Snafu)]
#[snafu(module(read_var_int_error), visibility(pub(crate)))]
pub enum ReadVarIntError<E> {
    /// The source ended before the encoding was complete.
    ///
    /// `expected` is the encoded length once the first byte has been read,
    /// and 1 if the source ended before it.
    #[snafu(transparent)]
    Incomplete {
        /// The shortfall, counted over the whole encoding.
        source: IncompleteError,
    },
    /// The receiver failed.
    #[snafu(display("variable-length integer read failed after {completed} bytes"))]
    Receiver {
        /// The receiver's error.
        source: E,
        /// Bytes of the encoding read before the failure.
        completed: VarIntCompleted,
    },
}

impl<E> ReadVarIntError<E> {
    /// Whether the source ended before the encoding was complete.
    pub fn is_incomplete(&self) -> bool {
        matches!(self, Self::Incomplete { .. })
    }

    /// Bytes of the encoding read before the failure.
    pub fn completed(&self) -> usize {
        match self {
            Self::Incomplete { source } => source.completed(),
            Self::Receiver { completed, .. } => completed.get(),
        }
    }

    /// The receiver's error, if the failure came from the receiver.
    pub fn host_error(&self) -> Option<&E> {
        match self {
            Self::Receiver { source, .. } => Some(source),
            Self::Incomplete { .. } => None,
        }
    }

    /// Restates a failure of reading part of an encoding that starts `offset`
    /// bytes into it, counting progress over the whole encoding.
    fn after(error: ReadArrayError<E>, offset: usize, encoded_len: usize) -> Self {
        match error {
            ReadArrayError::Incomplete { source } => Self::Incomplete {
                // invariant: every caller reads the rest of the encoding, so
                // `source.expected()` is `encoded_len - offset` and the bytes
                // read before the failure, `source.completed()`, are below it;
                // hence `offset + source.completed()` is below `encoded_len`.
                source: IncompleteError::new(encoded_len, offset + source.completed())
                    .expect("the bytes read are below the encoding length"),
            },
            ReadArrayError::Receiver { source, completed } => read_var_int_error::ReceiverSnafu {
                completed: VarIntCompleted::of_failure(offset + completed),
            }
            .into_error(source),
        }
    }
}

/// The number of bytes of a variable-length integer encoding read or
/// accepted before the receiver failed: 0 to 7.
///
/// An encoding has at most 8 bytes, and a failure leaves at least one of
/// them unread or unwritten.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VarIntCompleted(usize);

impl VarIntCompleted {
    /// `count` bytes, or `None` if `count` is 8 or more.
    pub const fn new(count: usize) -> Option<Self> {
        if count < 8 { Some(Self(count)) } else { None }
    }

    /// The number of bytes, below 8.
    pub const fn get(self) -> usize {
        self.0
    }

    /// The bytes completed before a failure within an encoding of at most 8
    /// bytes.
    fn of_failure(count: usize) -> Self {
        // invariant: `nitori_io` reports a failure only while bytes of the
        // requested encoding remain, so fewer than 8 have been completed.
        Self::new(count).expect("a failure within an encoding leaves fewer than 8 bytes completed")
    }
}

/// Formats the number of bytes.
impl fmt::Display for VarIntCompleted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Failures of encoding a [`VarInt`] or a [`VarIntField`].
#[derive(Debug, Snafu)]
#[snafu(module(write_var_int_error), visibility(pub(crate)))]
pub enum WriteVarIntError<E> {
    /// The receiver accepted nothing from a nonempty remainder.
    #[snafu(transparent)]
    WriteZero {
        /// The bytes accepted before the receiver stopped accepting.
        source: WriteZeroError,
    },
    /// The receiver failed.
    #[snafu(display("variable-length integer write failed after {completed} bytes"))]
    Receiver {
        /// The receiver's error.
        source: E,
        /// Bytes of the encoding accepted before the failure.
        completed: VarIntCompleted,
    },
}

impl<E> WriteVarIntError<E> {
    /// Bytes of the encoding accepted before the failure.
    pub fn completed(&self) -> usize {
        match self {
            Self::WriteZero { source } => source.completed,
            Self::Receiver { completed, .. } => completed.get(),
        }
    }

    /// The receiver's error, if the failure came from the receiver.
    pub fn host_error(&self) -> Option<&E> {
        match self {
            Self::Receiver { source, .. } => Some(source),
            Self::WriteZero { .. } => None,
        }
    }
}

impl<E> From<WriteAllError<E>> for WriteVarIntError<E> {
    fn from(error: WriteAllError<E>) -> Self {
        match error {
            WriteAllError::WriteZero { source } => source.into(),
            WriteAllError::Receiver { source, completed } => write_var_int_error::ReceiverSnafu {
                completed: VarIntCompleted::of_failure(completed),
            }
            .into_error(source),
        }
    }
}
