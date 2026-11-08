//! Frame sets composed of parts, and what the frames of every part share.
//!
//! The payload of a QUIC packet, once packet protection is removed, is a
//! sequence of frames, each starting with a Frame Type field. A frame never
//! extends past the end of its packet ([RFC 9000 §12.4]), so frames are read
//! from a source that holds the complete payload of one packet: a frame that
//! the payload cuts short is a terminal incomplete failure, not a reason to
//! wait for more bytes.
//!
//! # Frame sets
//!
//! QUIC version 1 and each extension define their own frames, and nothing
//! else: a *part* of a frame set. A part is a marker type that implements
//! [`FrameSetPart`]: [`v1::Part`](crate::v1::Part) for the frames of
//! [RFC 9000], and one in the module of each extension that this crate
//! implements behind a feature of the same name, `reset_stream_at` and
//! `datagram`. A part states its frames, the kinds of its frames
//! ([`FrameKind`]), the failures of reading their fields, and the Frame Type
//! values it claims ([`FrameTypeValues`]).
//!
//! The frame set of a connection is the parts it uses, composed by
//! [`PartSum`], which is itself a part: each part keeps one place in the sum,
//! for its frames, kinds and failures. A set of version 1 alone is
//! [`v1::Part`](crate::v1::Part), without a sum. Reading a frame
//! ([`codec::read_frame`]) reads its Frame Type, checks that it uses its
//! shortest encoding, asks the set which part claims it, and lets that part
//! read the other fields. A Frame Type value that no part of the set claims
//! is unknown, including the values of an extension that is not in the set:
//! a FRAME_ENCODING_ERROR ([RFC 9000 §12.4]).
//!
//! The parts of a set must claim disjoint Frame Type values, or the frames of
//! one would be read as those of another. Two checks reject a set that breaks
//! this at compile time: [`assert_frame_types_disjoint!`](crate::assert_frame_types_disjoint),
//! which whoever composes a set writes for it and which `cargo check` already
//! evaluates, and an assertion in the sum's [`FrameSetPart::kind_of`], which
//! fails when the code that reads with the set is built.
//!
//! ```compile_fail
//! use sakuya_wire::{assert_frame_types_disjoint, frame::PartSum, v1};
//!
//! // Version 1 twice claims every value twice.
//! assert_frame_types_disjoint!(PartSum<v1::Part, v1::Part>);
//! ```
//!
//! ```compile_fail
//! use core::marker::PhantomData;
//! use sakuya_wire::{frame::{PartSum, codec::ReadFrameHostExt as _}, v1};
//!
//! let mut input = &[0x01][..];
//! let _ = input.sync_read_frame_unpin(PhantomData::<PartSum<v1::Part, v1::Part>>);
//! ```
//!
//! [`Frames`] walks a packet payload held by a byte slice or `Bytes`, frame
//! by frame, without collecting the frames first, and reports a run of
//! PADDING frames as one frame. Payload fields are chunks of the source, of
//! the type parameter `D` of the frames: subslices of a byte slice and `Bytes`
//! that share the storage of a `Bytes` source, so reading copies no payload.
//!
//! ```
//! use core::marker::PhantomData;
//! use sakuya_wire::{
//!     frame::Frames,
//!     v1::{self, frame::Frame},
//! };
//!
//! // PING, then three PADDING frames.
//! let payload = [0x01, 0x00, 0x00, 0x00];
//! let mut frames = Frames::new(&payload[..], PhantomData::<v1::Part>);
//! assert!(matches!(frames.next(), Some(Ok(Frame::Ping(_)))));
//! let Some(Ok(Frame::Padding(padding))) = frames.next() else { panic!() };
//! assert_eq!(padding.len().get(), 3);
//! assert!(frames.next().is_none());
//!
//! // DATAGRAM is not a frame of version 1.
//! let mut frames = Frames::new(&[0x30, 0x01][..], PhantomData::<v1::Part>);
//! assert!(frames.next().unwrap().is_err());
//! ```
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
//!
//! [RFC 9000]: https://www.rfc-editor.org/rfc/rfc9000.html
//! [RFC 9000 §12.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4
use crate::{
    v1::{encryption_level::EncryptionLevel, role::Role, transport_error::TransportErrorCode},
    var_int::{
        VarInt, VarIntField, VarIntWidth,
        codec::{ReadVarIntError, read_var_int_field},
    },
};
use bytes::Buf;
use core::{
    convert::Infallible, error::Error, fmt, future::Future, iter::FusedIterator,
    marker::PhantomData, ops::RangeInclusive,
};
use either::Either;
use nitori_call::{Direct, Receiver, ReceiverAccess};
use nitori_io::{Read, ReadChunk};
use snafu::Snafu;

pub mod codec;

#[cfg(test)]
mod tests;

/// The kind of a frame, as its Frame Type field announces it, and what the
/// kind alone determines.
///
/// The kinds of each part implement it, and so do those of a [`PartSum`],
/// which answer for the part they belong to.
pub trait FrameKind: Copy + Eq {
    /// Whether a frame of this kind can appear in a packet protected at
    /// `level` ([RFC 9000 §12.4], Table 3).
    ///
    /// [RFC 9000 §12.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4
    fn can_appear_in(self, level: EncryptionLevel) -> bool;

    /// Whether a packet containing a frame of this kind is ack-eliciting
    /// ([RFC 9002 §2]).
    ///
    /// [RFC 9002 §2]: https://www.rfc-editor.org/rfc/rfc9002.html#section-2
    fn is_ack_eliciting(self) -> bool;

    /// Whether a packet containing a frame of this kind counts as in flight
    /// ([RFC 9002 §2]).
    ///
    /// [RFC 9002 §2]: https://www.rfc-editor.org/rfc/rfc9002.html#section-2
    fn counts_in_flight(self) -> bool;

    /// Whether this is a probing frame ([RFC 9000 §9.1]): a packet that
    /// contains only probing frames is a probing packet.
    ///
    /// [RFC 9000 §9.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-9.1
    fn is_probing(self) -> bool;

    /// Whether an endpoint of `role` can receive a frame of this kind.
    fn receivable_by(self, role: Role) -> bool;
}

/// A part of a frame set: the frames that version 1 or one extension
/// defines, or a [`PartSum`] of parts.
///
/// [`codec::read_frame`] reads a frame of a set: it looks the Frame Type up
/// with [`kind_of`](Self::kind_of) and reads the other fields with
/// [`read_fields`](Self::read_fields).
pub trait FrameSetPart {
    /// A frame of this part; `D` is the type of its payload fields.
    type Frame<D>;

    /// The kinds of the frames of this part.
    type Kind: FrameKind;

    /// The failures of reading the fields after the Frame Type; each states
    /// the transport error it corresponds to ([`FrameFieldsError`]).
    type FieldsError<E>;

    /// The Frame Type values this part claims.
    const FRAME_TYPE_VALUES: &'static FrameTypeValues;

    /// Whether the parts this part is composed of claim disjoint Frame Type
    /// values: always for a single part, which has no others to compare
    /// with; a [`PartSum`] compares its two sides.
    const PARTS_DISJOINT: bool = true;

    /// The kind that the Frame Type value `value` announces, or `None` for a
    /// value this part does not claim.
    fn kind_of(value: VarInt) -> Option<Self::Kind>;

    /// Reads the fields that follow the Frame Type `value`, of the kind
    /// [`kind_of`](Self::kind_of) gave for it.
    ///
    /// The source is the rest of a packet payload; payload fields are chunks
    /// of it.
    fn read_fields<F, A>(
        io: &mut A,
        kind: Self::Kind,
        value: VarInt,
    ) -> impl Future<Output = Result<Self::Frame<F::Chunk>, Self::FieldsError<F::Error>>>
    where
        F: ReadChunk<Chunk: Default>,
        A: ReceiverAccess<Family = F>;
}

/// A failure of reading the fields of a frame after its Frame Type, as a
/// [`FrameSetPart::FieldsError`] reports it.
pub trait FrameFieldsError {
    /// The Frame Type of the frame.
    fn frame_type(&self) -> VarInt;

    /// Whether the source ended within the frame.
    fn is_incomplete(&self) -> bool;

    /// The transport error the failure corresponds to.
    fn transport_error_code(&self) -> TransportErrorCode;
}

/// A frame that [`Frames`] reads, which merges a run of PADDING frames into
/// one.
///
/// PADDING is a frame of version 1; the frames of other parts keep the
/// default, which does nothing.
pub trait MergePadding {
    /// If this is a PADDING frame, consumes the PADDING frames at the start
    /// of `rest`, the rest of the payload, into it.
    fn merge_padding(&mut self, rest: &mut impl Buf) {
        let _ = rest;
    }
}

/// The sum of two parts of a frame set, itself a part; and the sum of the
/// frames, kinds and failures of those two parts.
///
/// A set of several parts nests sums, such as
/// `PartSum<v1::Part, PartSum<reset_stream_at::Part, datagram::Part>>`. A
/// frame, kind or failure of the set is one of the first part, in
/// [`First`](Self::First), or one of the rest, in [`Rest`](Self::Rest).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PartSum<H, T> {
    /// Of the first part.
    First(H),
    /// Of the rest of the parts.
    Rest(T),
}

impl<H: FrameKind, T: FrameKind> FrameKind for PartSum<H, T> {
    fn can_appear_in(self, level: EncryptionLevel) -> bool {
        match self {
            Self::First(kind) => kind.can_appear_in(level),
            Self::Rest(kind) => kind.can_appear_in(level),
        }
    }

    fn is_ack_eliciting(self) -> bool {
        match self {
            Self::First(kind) => kind.is_ack_eliciting(),
            Self::Rest(kind) => kind.is_ack_eliciting(),
        }
    }

    fn counts_in_flight(self) -> bool {
        match self {
            Self::First(kind) => kind.counts_in_flight(),
            Self::Rest(kind) => kind.counts_in_flight(),
        }
    }

    fn is_probing(self) -> bool {
        match self {
            Self::First(kind) => kind.is_probing(),
            Self::Rest(kind) => kind.is_probing(),
        }
    }

    fn receivable_by(self, role: Role) -> bool {
        match self {
            Self::First(kind) => kind.receivable_by(role),
            Self::Rest(kind) => kind.receivable_by(role),
        }
    }
}

impl<H: FrameSetPart, T: FrameSetPart> FrameSetPart for PartSum<H, T> {
    type Frame<D> = PartSum<H::Frame<D>, T::Frame<D>>;
    type Kind = PartSum<H::Kind, T::Kind>;
    type FieldsError<E> = PartSum<H::FieldsError<E>, T::FieldsError<E>>;

    const FRAME_TYPE_VALUES: &'static FrameTypeValues =
        &FrameTypeValues::join(H::FRAME_TYPE_VALUES, T::FRAME_TYPE_VALUES);

    const PARTS_DISJOINT: bool = H::PARTS_DISJOINT
        && T::PARTS_DISJOINT
        && H::FRAME_TYPE_VALUES.is_disjoint(T::FRAME_TYPE_VALUES);

    fn kind_of(value: VarInt) -> Option<Self::Kind> {
        // Evaluated when the function is generated for a concrete set, so a
        // set whose parts overlap does not build. Each nested sum checks its
        // own two sides.
        const {
            assert!(
                H::FRAME_TYPE_VALUES.is_disjoint(T::FRAME_TYPE_VALUES),
                "two parts of the frame set claim the same Frame Type value"
            );
        }
        H::kind_of(value)
            .map(PartSum::First)
            .or_else(|| T::kind_of(value).map(PartSum::Rest))
    }

    async fn read_fields<F, A>(
        io: &mut A,
        kind: Self::Kind,
        value: VarInt,
    ) -> Result<Self::Frame<F::Chunk>, Self::FieldsError<F::Error>>
    where
        F: ReadChunk<Chunk: Default>,
        A: ReceiverAccess<Family = F>,
    {
        match kind {
            PartSum::First(kind) => H::read_fields(io, kind, value)
                .await
                .map(PartSum::First)
                .map_err(PartSum::First),
            PartSum::Rest(kind) => T::read_fields(io, kind, value)
                .await
                .map(PartSum::Rest)
                .map_err(PartSum::Rest),
        }
    }
}

impl<H: MergePadding, T: MergePadding> MergePadding for PartSum<H, T> {
    fn merge_padding(&mut self, rest: &mut impl Buf) {
        match self {
            Self::First(frame) => frame.merge_padding(rest),
            Self::Rest(frame) => frame.merge_padding(rest),
        }
    }
}

impl<H: FrameFieldsError, T: FrameFieldsError> FrameFieldsError for PartSum<H, T> {
    fn frame_type(&self) -> VarInt {
        match self {
            Self::First(error) => error.frame_type(),
            Self::Rest(error) => error.frame_type(),
        }
    }

    fn is_incomplete(&self) -> bool {
        match self {
            Self::First(error) => error.is_incomplete(),
            Self::Rest(error) => error.is_incomplete(),
        }
    }

    fn transport_error_code(&self) -> TransportErrorCode {
        match self {
            Self::First(error) => error.transport_error_code(),
            Self::Rest(error) => error.transport_error_code(),
        }
    }
}

/// A failure of one of the parts displays as that failure.
impl<H: fmt::Display, T: fmt::Display> fmt::Display for PartSum<H, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::First(error) => error.fmt(f),
            Self::Rest(error) => error.fmt(f),
        }
    }
}

/// A failure of one of the parts is that failure, with its source.
impl<H: Error, T: Error> Error for PartSum<H, T> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::First(error) => error.source(),
            Self::Rest(error) => error.source(),
        }
    }
}

/// The Frame Type values a part claims: ranges of values, or for a
/// [`PartSum`] those of its two sides.
#[derive(Debug)]
pub struct FrameTypeValues(Values);

#[derive(Debug)]
enum Values {
    Ranges(&'static [RangeInclusive<VarInt>]),
    Join(&'static FrameTypeValues, &'static FrameTypeValues),
}

impl FrameTypeValues {
    /// The values in `ranges`; an empty range claims no value.
    pub const fn new(ranges: &'static [RangeInclusive<VarInt>]) -> Self {
        Self(Values::Ranges(ranges))
    }

    /// The values of `first` and those of `rest`.
    const fn join(first: &'static Self, rest: &'static Self) -> Self {
        Self(Values::Join(first, rest))
    }

    /// Whether no value is in both `self` and `other`.
    pub const fn is_disjoint(&self, other: &Self) -> bool {
        match self.0 {
            Values::Ranges(ranges) => {
                let mut index = 0;
                while index < ranges.len() {
                    if !other.excludes(&ranges[index]) {
                        return false;
                    }
                    index += 1;
                }
                true
            }
            Values::Join(first, rest) => first.is_disjoint(other) && rest.is_disjoint(other),
        }
    }

    /// Whether no value of `range` is in `self`.
    const fn excludes(&self, range: &RangeInclusive<VarInt>) -> bool {
        match self.0 {
            Values::Ranges(ranges) => {
                let (start, end) = (range.start().get(), range.end().get());
                let mut index = 0;
                while index < ranges.len() {
                    let (other_start, other_end) =
                        (ranges[index].start().get(), ranges[index].end().get());
                    if start <= end
                        && other_start <= other_end
                        && start <= other_end
                        && other_start <= end
                    {
                        return false;
                    }
                    index += 1;
                }
                true
            }
            Values::Join(first, rest) => first.excludes(range) && rest.excludes(range),
        }
    }

    /// Whether `value` is in `self`.
    #[cfg(test)]
    pub(crate) const fn contains(&self, value: VarInt) -> bool {
        !self.excludes(&RangeInclusive::new(value, value))
    }
}

/// Asserts at compile time that the parts of a frame set claim disjoint
/// Frame Type values ([`FrameSetPart::PARTS_DISJOINT`]).
///
/// Whoever composes a frame set writes it for the set's type; `cargo check`
/// reports a set whose parts overlap.
///
/// ```
/// use sakuya_wire::{assert_frame_types_disjoint, v1};
///
/// assert_frame_types_disjoint!(v1::Part);
/// ```
#[macro_export]
macro_rules! assert_frame_types_disjoint {
    ($set:ty) => {
        const _: () = ::core::assert!(
            <$set as $crate::frame::FrameSetPart>::PARTS_DISJOINT,
            "two parts of the frame set claim the same Frame Type value"
        );
    };
}

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

/// Iterates over the frames of the frame set `P` in a packet payload held by
/// a memory source such as a byte slice or `Bytes`, reading each when it is
/// reached.
///
/// Each item is a frame or the error that ends the iteration; after an error
/// the iterator yields `None`. Consecutive PADDING frames are reported as one
/// frame ([`MergePadding`]). Payload fields are chunks of the source; see the
/// [module documentation](self).
#[derive(Clone, Debug)]
pub struct Frames<H, P> {
    source: H,
    consumed: usize,
    start: usize,
    failed: bool,
    part: PhantomData<P>,
}

impl<H: Buf, P> Frames<H, P> {
    /// Iterates over the frames of `payload`, of the frame set `P`.
    pub fn new(payload: H, part: PhantomData<P>) -> Self {
        Self {
            source: payload,
            consumed: 0,
            start: 0,
            failed: false,
            part,
        }
    }

    /// The offset in the payload of the next frame, or after a failure of
    /// the frame that failed.
    pub fn offset(&self) -> usize {
        self.start
    }

    /// The payload from the next frame on; after a failure, what the failed
    /// frame left unread.
    pub fn remainder(&self) -> &H {
        &self.source
    }

    /// Takes the payload from the next frame on.
    pub fn into_remainder(self) -> H {
        self.source
    }
}

impl<H, P> Iterator for Frames<H, P>
where
    H: Buf + Receiver<Family = Direct<H>> + Unpin,
    Direct<H>: ReadChunk<Chunk: Default>,
    P: FrameSetPart<Frame<<Direct<H> as ReadChunk>::Chunk>: MergePadding>,
{
    type Item = Result<
        P::Frame<<Direct<H> as ReadChunk>::Chunk>,
        codec::ReadFrameError<
            <Direct<H> as Read>::Error,
            P::FieldsError<<Direct<H> as Read>::Error>,
        >,
    >;

    fn next(&mut self) -> Option<Self::Item> {
        use codec::ReadFrameHostExt as _;
        if self.failed || !self.source.has_remaining() {
            return None;
        }
        self.start = self.consumed;
        let before = self.source.remaining();
        let result = self.source.sync_read_frame_unpin(self.part);
        let result = result.map(|mut frame| {
            frame.merge_padding(&mut self.source);
            frame
        });
        self.consumed += before - self.source.remaining();
        if result.is_err() {
            self.failed = true;
        } else {
            self.start = self.consumed;
        }
        Some(result)
    }
}

impl<H, P> FusedIterator for Frames<H, P>
where
    H: Buf + Receiver<Family = Direct<H>> + Unpin,
    Direct<H>: ReadChunk<Chunk: Default>,
    P: FrameSetPart<Frame<<Direct<H> as ReadChunk>::Chunk>: MergePadding>,
{
}
