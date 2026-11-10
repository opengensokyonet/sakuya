//! What the frames of every part share: the encoding of their fields.
//!
//! The frames of version 1 and of each extension are defined in their own
//! modules, and the frame sets that compose them are in
//! [`v1::frame::set`](crate::v1::frame::set). This module holds what those
//! frames have in common: the Length field of STREAM and DATAGRAM frames and
//! the errors of the limits that tie a payload to its length and offset.
//!
//! # Length fields
//!
//! Whether a STREAM or DATAGRAM frame has a Length field is stated by the
//! type parameter `L` of the frame, a [`LengthKind`] of one of four types:
//! [`VarIntWidth`], for a frame with a Length field of that width;
//! [`NoLength`], for a frame without one, whose data extends to the end of
//! the packet; and [`Either<NoLength, VarIntWidth>`](Either) and
//! [`Either<VarIntWidth, NoLength>`](Either), of the `either` crate, for
//! either of the two. A STREAM frame whose Length field is not decided yet
//! is of the type [`UndecidedLength`], which has no write operation.
use crate::var_int::{
    VarInt, VarIntField, VarIntWidth,
    codec::{ReadVarIntError, read_var_int_field},
};
use core::convert::Infallible;
use either::Either;
use nitori_call::ReceiverAccess;
use nitori_io::Read;
use snafu::Snafu;

/// A Frame Type value below 2<sup>6</sup> as a variable-length integer.
pub(crate) const fn type_var_int(value: u64) -> VarInt {
    VarInt::from_u32(value as u32)
}

/// The absence of a Length field in a STREAM or DATAGRAM frame: the data
/// extends to the end of the packet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct NoLength;

/// A STREAM frame whose Length field is not decided yet, as the type
/// parameter `L` of [`StreamFrame`](crate::v1::frame::stream::StreamFrame).
///
/// It is not a [`LengthKind`]: a frame of this kind has no write operation, so
/// the types stop a frame from being written before its Length field is
/// decided. [`StreamFrame::into_with_length`](crate::v1::frame::stream::StreamFrame::into_with_length)
/// and [`StreamFrame::into_without_length`](crate::v1::frame::stream::StreamFrame::into_without_length)
/// decide it. Reading never gives this kind.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct UndecidedLength;

mod sealed {
    use crate::var_int::VarIntWidth;

    /// Restricts [`LengthKind`](super::LengthKind) to the types of this
    /// crate.
    pub trait Sealed: Copy {
        /// The width of the Length field, or `None` without one.
        fn length_width(self) -> Option<VarIntWidth>;
    }
}

/// What a STREAM or DATAGRAM frame states about its Length field, as the
/// type parameter `L` of [`StreamFrame`](crate::v1::frame::stream::StreamFrame)
/// and of `DatagramFrame` in the `datagram` extension.
///
/// It is implemented by exactly four types:
///
/// - [`VarIntWidth`]: the frame has a Length field, of this width;
/// - [`NoLength`]: the frame has no Length field, and its data extends to
///   the end of the packet;
/// - [`Either<NoLength, VarIntWidth>`](Either): either of the two, as a frame
///   that was read states it. This is the default, so `StreamFrame<D>` and
///   `DatagramFrame<D>` are frames as they are read;
/// - [`Either<VarIntWidth, NoLength>`](Either): either of the two, in the
///   other order.
///
/// The two single kinds convert into each `Either` kind with `From`. A frame
/// of an `Either` kind converts with `From` into an `Either` of frames of
/// its two kinds, in the same order, such as
/// `Either<StreamFrame<D, NoLength>, StreamFrame<D, VarIntWidth>>` for `StreamFrame<D>`,
/// and back; and into a frame of the other `Either` kind, with the sides
/// swapped.
pub trait LengthKind: sealed::Sealed {}

impl sealed::Sealed for VarIntWidth {
    fn length_width(self) -> Option<VarIntWidth> {
        Some(self)
    }
}

impl LengthKind for VarIntWidth {}

impl sealed::Sealed for NoLength {
    fn length_width(self) -> Option<VarIntWidth> {
        None
    }
}

impl LengthKind for NoLength {}

impl sealed::Sealed for Either<NoLength, VarIntWidth> {
    fn length_width(self) -> Option<VarIntWidth> {
        match self {
            Either::Left(NoLength) => None,
            Either::Right(width) => Some(width),
        }
    }
}

impl LengthKind for Either<NoLength, VarIntWidth> {}

impl sealed::Sealed for Either<VarIntWidth, NoLength> {
    fn length_width(self) -> Option<VarIntWidth> {
        match self {
            Either::Left(width) => Some(width),
            Either::Right(NoLength) => None,
        }
    }
}

impl LengthKind for Either<VarIntWidth, NoLength> {}

/// The width of the Length field that `length` states, or `None` without
/// one.
pub(crate) fn length_width<L: LengthKind>(length: L) -> Option<VarIntWidth> {
    sealed::Sealed::length_width(length)
}

/// The data of a STREAM or CRYPTO frame ends beyond 2<sup>62</sup> − 1.
///
/// It is constructed only when the check fails, so its offset plus its
/// length always exceeds 2<sup>62</sup> − 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("data at offset {offset} of length {length} ends beyond 2^62 - 1"))]
pub struct DataEndError {
    offset: VarInt,
    length: u64,
}

impl DataEndError {
    /// The Offset field.
    pub const fn offset(self) -> VarInt {
        self.offset
    }

    /// The length of the data, which ends beyond 2<sup>62</sup> − 1 after
    /// [`offset`](Self::offset).
    pub const fn length(self) -> u64 {
        self.length
    }

    /// Checks that `length` bytes of data at `offset` end at most at
    /// 2<sup>62</sup> − 1.
    pub(crate) fn check(offset: VarInt, length: u64) -> Result<(), Self> {
        if length > VarInt::MAX.get() - offset.get() {
            return Err(Self { offset, length });
        }
        Ok(())
    }

    /// The largest data length permitted after `offset`, capped to `usize`.
    pub(crate) fn limit(offset: VarInt) -> usize {
        usize::try_from(VarInt::MAX.get() - offset.get()).unwrap_or(usize::MAX)
    }
}

/// A payload field is longer than its Length field can state at the
/// field's width.
///
/// It is constructed only when the check fails, so the length always
/// exceeds what the width holds: for an 8-byte width, 2<sup>62</sup> − 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "field of {length} bytes is longer than a {}-byte Length field can state",
    width.encoded_len()
))]
pub struct LengthError {
    length: usize,
    width: VarIntWidth,
}

impl LengthError {
    /// The length of the payload field, which exceeds what
    /// [`width`](Self::width) holds.
    pub const fn length(self) -> usize {
        self.length
    }

    /// The width of the Length field.
    pub const fn width(self) -> VarIntWidth {
        self.width
    }

    /// The value of a Length field of `width` for a payload of `length`
    /// bytes.
    pub(crate) fn check(length: usize, width: VarIntWidth) -> Result<VarInt, Self> {
        match VarInt::try_from(length) {
            Ok(value) if width.fits(value) => Ok(value),
            _ => Err(Self { length, width }),
        }
    }
}

/// The data of a STREAM or CRYPTO frame breaks a limit of the encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
pub enum InvalidDataError {
    /// The data ends beyond 2<sup>62</sup> − 1.
    #[snafu(transparent)]
    DataEnd {
        /// The broken limit.
        source: DataEndError,
    },
    /// The Length field is too narrow for the length of the data.
    #[snafu(transparent)]
    Length {
        /// The broken limit.
        source: LengthError,
    },
}

/// The encoded length of the shortest Length field for `length` bytes; a
/// length above 2<sup>62</sup> − 1 counts as the longest encoding.
pub(crate) fn length_field_len(length: usize) -> usize {
    VarInt::try_from(length).map_or(VarInt::MAX_ENCODED_LEN, VarInt::encoded_len)
}

/// Reads a variable-length integer field of a type that every value
/// converts into.
pub(crate) async fn read_field<T, F, A>(
    io: &mut A,
) -> Result<VarIntField<T>, ReadVarIntError<F::Error>>
where
    T: Copy + Into<VarInt> + TryFrom<VarInt, Error = Infallible>,
    F: Read,
    A: ReceiverAccess<Family = F>,
{
    read_var_int_field(io).await.map_err(ReadVarIntError::from)
}

/// The largest `n` with `fixed + len(n) + n <= room` and `n <= limit`, where
/// `len(n)` is the length of the Length field.
pub(crate) fn max_len_with_length_field(fixed: usize, limit: usize, room: usize) -> Option<usize> {
    const CLASSES: [(usize, u64); 4] = [
        (1, (1 << 6) - 1),
        (2, (1 << 14) - 1),
        (4, (1 << 30) - 1),
        (8, (1 << 62) - 1),
    ];
    CLASSES
        .iter()
        .filter_map(|&(field_len, class_max)| {
            let left = room.checked_sub(fixed + field_len)?;
            let class_max = usize::try_from(class_max).unwrap_or(usize::MAX);
            Some(left.min(class_max).min(limit))
        })
        .max()
}

/// The fields of a frame before its payload, encoded for one write.
///
/// `N` is the longest encoding of those fields for the frame type.
pub(crate) struct Head<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> Head<N> {
    /// A head starting with the Frame Type `frame_type`.
    pub(crate) fn new(frame_type: VarInt) -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
        .var_int(frame_type)
    }

    /// Appends the shortest encoding of `value`.
    pub(crate) fn var_int(self, value: VarInt) -> Self {
        self.var_int_of(value, VarIntWidth::shortest(value))
    }

    /// Appends the encoding of `value` of `width`, which holds the value.
    pub(crate) fn var_int_of(self, value: VarInt, width: VarIntWidth) -> Self {
        let (encoding, encoded_len) = value.to_encoding_of(width);
        self.bytes(&encoding[..encoded_len])
    }

    /// Appends the encoding of `field` at its width.
    pub(crate) fn field<T>(self, field: VarIntField<T>) -> Self
    where
        T: Copy + Into<VarInt> + TryFrom<VarInt>,
    {
        self.var_int_of(field.to_var_int(), field.width())
    }

    /// Appends `bytes`.
    pub(crate) fn bytes(mut self, bytes: &[u8]) -> Self {
        // invariant: every frame type sizes `N` for the longest encoding of
        // its fields, so the bytes fit.
        self.bytes[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        self
    }

    /// The encoded fields.
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// The length of the encoded fields.
    pub(crate) fn len(&self) -> usize {
        self.len
    }
}
