//! Failures shared by the length-prefixed fields of TLS messages.
//!
//! TLS writes a variable-length field as a length of one, two or three bytes
//! followed by that many bytes (RFC 9846 §3.4). [`ReadVectorError`] is the
//! failure of reading such a field, [`ReadBoundedVectorError`] that of a
//! field whose length has a narrower range than its length field allows,
//! with [`LengthOutOfRangeError`] for the range. [`ExcessBytesError`] reports bytes
//! left over once a structure of known length has been read.

use crate::{
    alert::AlertDescription,
    code_point::{ByteCodePoint, ByteCodePointList, CodePoint, CodePointList},
    message::{HandshakeType, MessageSource},
    width::Width,
};
use bytes::Buf;
use core::{convert::Infallible, num::NonZeroUsize, ops::RangeInclusive};
use nitori_call::ReceiverAccess;
use nitori_io::{
    ReadChunkExt as _, Write,
    calls::{ReadArrayError, ReadArrayExt as _, WriteAllError, WriteAllExt as _},
    error::{Incomplete, WriteZero},
};
use snafu::{ResultExt, Snafu};

/// A length lies outside the range its field allows.
///
/// It is constructed only when the check fails, so the length is always
/// outside [`min`](Self::min)`..=`[`max`](Self::max).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("length {len} is outside {min}..={max}"))]
pub struct LengthOutOfRangeError {
    len: usize,
    min: usize,
    max: usize,
}

impl LengthOutOfRangeError {
    /// The length.
    pub const fn length(self) -> usize {
        self.len
    }

    /// The smallest length allowed.
    pub const fn min(self) -> usize {
        self.min
    }

    /// The largest length allowed.
    pub const fn max(self) -> usize {
        self.max
    }

    /// Checks that `len` lies in `range`.
    pub(crate) fn check(len: usize, range: RangeInclusive<usize>) -> Result<(), Self> {
        if !range.contains(&len) {
            return Err(Self {
                len,
                min: *range.start(),
                max: *range.end(),
            });
        }
        Ok(())
    }
}

/// A structure of known length ends before its bytes do.
///
/// It is constructed only when bytes are left, so the excess is never zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("{excess} bytes follow the last field"))]
pub struct ExcessBytesError {
    excess: NonZeroUsize,
}

impl ExcessBytesError {
    /// The number of bytes left over.
    pub const fn excess(self) -> NonZeroUsize {
        self.excess
    }

    /// Checks that no bytes are left of a structure, with `left` left.
    pub(crate) fn check(left: usize) -> Result<(), Self> {
        match NonZeroUsize::new(left) {
            Some(excess) => Err(Self { excess }),
            None => Ok(()),
        }
    }
}

/// Failures of reading a variable-length field whose length may be any
/// value of its length field.
#[derive(Debug, Snafu)]
#[snafu(module(read_vector_error), visibility(pub(crate)))]
pub enum ReadVectorError {
    /// The length field could not be read.
    #[snafu(display("vector length read failed"))]
    Length {
        /// The shortfall.
        source: Incomplete,
    },
    /// The bytes the length field states are not all there.
    #[snafu(display("vector read failed"))]
    Bytes {
        /// The shortfall.
        source: Incomplete,
    },
}

impl ReadVectorError {
    /// The alert the failure calls for: always decode_error.
    pub fn alert(&self) -> AlertDescription {
        AlertDescription::DECODE_ERROR
    }
}

/// Failures of reading a variable-length field whose length has a range
/// narrower than its length field.
#[derive(Debug, Snafu)]
#[snafu(module(read_bounded_vector_error), visibility(pub(crate)))]
pub enum ReadBoundedVectorError {
    /// The length field could not be read.
    #[snafu(display("vector length read failed"))]
    Length {
        /// The shortfall.
        source: Incomplete,
    },
    /// The length lies outside the range of the field.
    #[snafu(transparent)]
    Range {
        /// The broken range.
        source: LengthOutOfRangeError,
    },
    /// The bytes the length field states are not all there.
    #[snafu(display("vector read failed"))]
    Bytes {
        /// The shortfall.
        source: Incomplete,
    },
}

impl ReadBoundedVectorError {
    /// The alert the failure calls for: always decode_error.
    pub fn alert(&self) -> AlertDescription {
        AlertDescription::DECODE_ERROR
    }
}

/// The shortfall of a fixed-size read from a source that cannot fail.
fn incomplete(error: ReadArrayError<Infallible>) -> Incomplete {
    match error {
        ReadArrayError::Incomplete { source } => source,
        ReadArrayError::Receiver { source, .. } => match source {},
    }
}

/// Reads `N` bytes.
pub(crate) async fn read_array<const N: usize, F, A>(io: &mut A) -> Result<[u8; N], Incomplete>
where
    F: MessageSource,
    A: ReceiverAccess<Family = F>,
{
    io.read_array::<N>().await.map_err(incomplete)
}

/// Reads one byte.
pub(crate) async fn read_u8<F: MessageSource, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> Result<u8, Incomplete> {
    let [byte] = read_array(io).await?;
    Ok(byte)
}

/// Reads a two-byte integer.
pub(crate) async fn read_u16<F: MessageSource, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> Result<u16, Incomplete> {
    Ok(u16::from_be_bytes(read_array(io).await?))
}

/// Reads a three-byte integer.
pub(crate) async fn read_u24<F: MessageSource, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> Result<u32, Incomplete> {
    let [a, b, c] = read_array(io).await?;
    Ok(u32::from_be_bytes([0, a, b, c]))
}

/// Reads a four-byte integer.
pub(crate) async fn read_u32<F: MessageSource, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> Result<u32, Incomplete> {
    Ok(u32::from_be_bytes(read_array(io).await?))
}

/// Reads a length field of `width`.
pub(crate) async fn read_length<F: MessageSource, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    width: Width,
) -> Result<usize, Incomplete> {
    Ok(match width {
        Width::U8 => usize::from(read_u8(io).await?),
        Width::U16 => usize::from(read_u16(io).await?),
        Width::U24 => read_u24(io).await? as usize,
    })
}

/// Reads `len` bytes as one chunk of the source.
pub(crate) async fn read_bytes<F: MessageSource, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    len: usize,
) -> Result<F::Bytes, Incomplete> {
    let Some(maximum) = NonZeroUsize::new(len) else {
        return Ok(F::Bytes::default());
    };
    let chunk = match io.read_chunk(maximum).await {
        Ok(chunk) => chunk,
        Err(error) => match error {},
    };
    // A message source hands out what is left of its bytes, up to the
    // maximum, in one chunk; a shorter chunk means the bytes end.
    let completed = chunk.as_ref().map_or(0, Buf::remaining);
    match chunk {
        Some(chunk) if completed == len => Ok(chunk),
        _ => Err(Incomplete {
            expected: len,
            completed,
        }),
    }
}

/// Reads a length field of `width` and that many bytes.
pub(crate) async fn read_vector<F: MessageSource, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    width: Width,
) -> Result<F::Bytes, ReadVectorError> {
    let len = read_length(io, width)
        .await
        .context(read_vector_error::LengthSnafu)?;
    read_bytes(io, len)
        .await
        .context(read_vector_error::BytesSnafu)
}

/// Reads a length field of `width`, checks that the length lies in `range`
/// and reads that many bytes.
pub(crate) async fn read_bounded_vector<F: MessageSource, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    width: Width,
    range: RangeInclusive<usize>,
) -> Result<F::Bytes, ReadBoundedVectorError> {
    let len = read_length(io, width)
        .await
        .context(read_bounded_vector_error::LengthSnafu)?;
    LengthOutOfRangeError::check(len, range)?;
    read_bytes(io, len)
        .await
        .context(read_bounded_vector_error::BytesSnafu)
}

/// A sink that counts the bytes it accepted over a whole encoding, so that a
/// failure reports them.
pub(crate) struct Out<'a, A> {
    io: &'a mut A,
    written: usize,
}

impl<'a, F: Write, A: ReceiverAccess<Family = F>> Out<'a, A> {
    pub(crate) fn new(io: &'a mut A) -> Self {
        Self { io, written: 0 }
    }

    /// Writes `bytes` completely.
    pub(crate) async fn put(&mut self, bytes: impl Buf) -> Result<(), WriteAllError<F::Error>> {
        let len = bytes.remaining();
        let before = self.written;
        match self.io.write_all(bytes).await {
            Ok(()) => {
                self.written += len;
                Ok(())
            }
            Err(WriteAllError::WriteZero { source }) => Err(WriteAllError::WriteZero {
                source: WriteZero {
                    completed: before + source.completed,
                },
            }),
            Err(WriteAllError::Receiver { source, completed }) => Err(WriteAllError::Receiver {
                source,
                completed: before + completed,
            }),
        }
    }

    pub(crate) async fn u8(&mut self, value: u8) -> Result<(), WriteAllError<F::Error>> {
        self.put(&[value][..]).await
    }

    pub(crate) async fn u16(&mut self, value: u16) -> Result<(), WriteAllError<F::Error>> {
        self.put(&value.to_be_bytes()[..]).await
    }

    pub(crate) async fn u32(&mut self, value: u32) -> Result<(), WriteAllError<F::Error>> {
        self.put(&value.to_be_bytes()[..]).await
    }

    /// Writes a length field of `width`.
    ///
    /// The caller has checked that `len` fits the width.
    pub(crate) async fn length(
        &mut self,
        width: Width,
        len: usize,
    ) -> Result<(), WriteAllError<F::Error>> {
        debug_assert!(len <= width.max());
        let bytes = (len as u32).to_be_bytes();
        self.put(&bytes[4 - width.len()..]).await
    }

    /// Writes a length field of `width` and `bytes`.
    pub(crate) async fn vector(
        &mut self,
        width: Width,
        bytes: &[u8],
    ) -> Result<(), WriteAllError<F::Error>> {
        self.length(width, bytes.len()).await?;
        self.put(bytes).await
    }

    /// Writes the header of a handshake message whose body is `body_len`
    /// bytes long.
    pub(crate) async fn header(
        &mut self,
        message: HandshakeType,
        body_len: usize,
    ) -> Result<(), WriteAllError<F::Error>> {
        self.u8(message.get()).await?;
        self.length(Width::U24, body_len).await
    }

    /// Writes a list of two-byte code points with its length field.
    pub(crate) async fn code_point_list<T: CodePoint>(
        &mut self,
        list: &CodePointList<T>,
    ) -> Result<(), WriteAllError<F::Error>> {
        let items = list.as_slice();
        self.length(T::LIST_LENGTH, 2 * items.len()).await?;
        for item in items {
            self.u16(item.value()).await?;
        }
        Ok(())
    }

    /// Writes a list of one-byte code points with its length field.
    pub(crate) async fn byte_code_point_list<T: ByteCodePoint>(
        &mut self,
        list: &ByteCodePointList<T>,
    ) -> Result<(), WriteAllError<F::Error>> {
        let items = list.as_slice();
        self.length(Width::U8, items.len()).await?;
        for item in items {
            self.u8(item.value()).await?;
        }
        Ok(())
    }
}
