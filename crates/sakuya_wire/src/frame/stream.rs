//! STREAM frames ([RFC 9000 §19.8]).
//!
//! [RFC 9000 §19.8]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.8
use super::{
    DataEndError, Head, InvalidDataError, LengthError, LengthKind, NoLength, length_width,
    max_len_with_length_field, type_value, type_var_int,
};
use crate::{
    stream_id::StreamId,
    var_int::{VarInt, VarIntField, VarIntWidth},
};
use bytes::Buf;
use either::Either;

/// The bits of a STREAM frame type ([RFC 9000 §19.8]).
///
/// [RFC 9000 §19.8]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.8
pub(crate) mod bits {
    pub(crate) const OFF: u64 = 0x04;
    pub(crate) const LEN: u64 = 0x02;
    pub(crate) const FIN: u64 = 0x01;
}

/// A STREAM frame ([RFC 9000 §19.8]), of any of the types `0x08..=0x0f`.
///
/// The fields state the Frame Type: the OFF bit is set when the frame has an
/// Offset field, the LEN bit when it has a Length field, and the FIN bit
/// when [`fin`](Self::fin) is true. An Offset field may hold 0, so a frame
/// with the OFF bit set and offset 0 is distinct from one without the bit.
/// The Length field holds the length of the data, so only its width is
/// stored. Every variable-length integer keeps the width of its encoding.
///
/// `L` states the Length field, as a [`LengthKind`]: [`VarIntWidth`] for a
/// frame with a Length field of that width, [`NoLength`] for one without,
/// whose data extends to the end of the packet, and
/// [`Either<NoLength, VarIntWidth>`](Either) or
/// [`Either<VarIntWidth, NoLength>`](Either) for either of the two. Reading
/// gives `StreamFrame<D>`, the default, `Either<NoLength, VarIntWidth>`. `From`
/// converts the two single kinds into either `Either` kind, a frame of an
/// `Either` kind into an `Either` of frames of its two kinds in the same
/// order and back, and one `Either` kind into the other.
///
/// The end of the data, its offset plus its length, is at most
/// [`VarInt::MAX`], and the Length field, if present, can state the length
/// of the data. [`with_length`](StreamFrame::with_length),
/// [`without_length`](StreamFrame::without_length) and [`new`](StreamFrame::new),
/// which construct a frame with a Length field, without one, and with
/// either as a frame that was read, check the limits that apply, so every
/// value writes an encoding that reads back to the same value; the fields
/// are read through methods of the same names. `D` holds
/// the data: the source's chunk type for a frame that was read, any [`Buf`]
/// for one to write.
///
/// [RFC 9000 §19.8]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.8
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamFrame<D, L = Either<NoLength, VarIntWidth>> {
    stream_id: VarIntField<StreamId>,
    offset: Option<VarIntField<VarInt>>,
    length: L,
    data: D,
    fin: bool,
}

/// The longest encoding of the fields before the data.
const HEAD_MAX: usize = 1 + 8 + 8 + 8;

impl<D, L: LengthKind> StreamFrame<D, L> {
    /// The Stream ID field: the stream the data belongs to.
    pub const fn stream_id(&self) -> VarIntField<StreamId> {
        self.stream_id
    }

    /// The Offset field, present when the OFF bit is set: the byte offset of
    /// the data in the stream. Without it, the data starts at offset 0.
    pub const fn offset(&self) -> Option<VarIntField<VarInt>> {
        self.offset
    }

    /// The Length field, present when the LEN bit is set: its width, since
    /// the field holds the length of the data, or [`NoLength`] without it,
    /// when the data extends to the end of the packet.
    pub const fn length(&self) -> L {
        self.length
    }

    /// The stream data.
    pub const fn data(&self) -> &D {
        &self.data
    }

    /// Takes the stream data.
    pub fn into_data(self) -> D {
        self.data
    }

    /// Whether the data ends the stream: the FIN bit.
    pub const fn fin(&self) -> bool {
        self.fin
    }

    /// The Frame Type value, which the OFF, LEN and FIN bits complete.
    pub fn type_value(&self) -> VarInt {
        let mut value = type_value::STREAM;
        if self.offset.is_some() {
            value |= bits::OFF;
        }
        if length_width(self.length).is_some() {
            value |= bits::LEN;
        }
        if self.fin {
            value |= bits::FIN;
        }
        type_var_int(value)
    }

    /// The byte offset of the data in the stream: the Offset field, or 0
    /// without one.
    pub fn data_offset(&self) -> VarInt {
        self.offset.map_or(VarInt::ZERO, |offset| offset.get())
    }
}

impl<D, L> StreamFrame<D, L> {
    /// The same frame with the Length field stated as `length`, which states
    /// the same field.
    fn restate_length<M>(self, length: M) -> StreamFrame<D, M> {
        StreamFrame {
            stream_id: self.stream_id,
            offset: self.offset,
            length,
            data: self.data,
            fin: self.fin,
        }
    }
}

impl<D: Buf, L: LengthKind> StreamFrame<D, L> {
    /// The number of bytes the write operations of [`codec`] write.
    pub fn encoded_len(&self) -> usize {
        1 + self.stream_id.encoded_len()
            + self.offset.map_or(0, |offset| offset.encoded_len())
            + length_width(self.length).map_or(0, VarIntWidth::encoded_len)
            + self.data.remaining()
    }

    /// The fields before the data.
    pub(crate) fn head(&self) -> Head<HEAD_MAX> {
        let mut head = Head::new(self.type_value()).field(self.stream_id);
        if let Some(offset) = self.offset {
            head = head.field(offset);
        }
        if let Some(width) = length_width(self.length) {
            // Construction checked that the width holds the data length.
            let length = VarInt::try_from(self.data.remaining()).unwrap_or(VarInt::ZERO);
            head = head.var_int_of(length, width);
        }
        head
    }
}

/// The data offset that `offset` states.
fn start(offset: Option<VarIntField<VarInt>>) -> VarInt {
    offset.map_or(VarInt::ZERO, |offset| offset.get())
}

/// The length of the fields before the data, other than the Length field.
fn fixed_len(stream_id: VarIntField<StreamId>, offset: Option<VarIntField<VarInt>>) -> usize {
    1 + stream_id.encoded_len() + offset.map_or(0, |offset| offset.encoded_len())
}

impl<D: Buf> StreamFrame<D, VarIntWidth> {
    /// The STREAM frame with a Length field of width `width` and these other
    /// fields.
    ///
    /// # Errors
    ///
    /// [`InvalidDataError::DataEnd`] if the data would end beyond
    /// 2<sup>62</sup> − 1, and [`InvalidDataError::Length`] if the Length
    /// field is too narrow for the length of the data.
    pub fn with_length(
        stream_id: VarIntField<StreamId>,
        offset: Option<VarIntField<VarInt>>,
        width: VarIntWidth,
        data: D,
        fin: bool,
    ) -> Result<Self, InvalidDataError> {
        let data_len = data.remaining();
        DataEndError::check(start(offset), data_len as u64)?;
        LengthError::check(data_len, width)?;
        Ok(Self {
            stream_id,
            offset,
            length: width,
            data,
            fin,
        })
    }
}

impl<D> StreamFrame<D, VarIntWidth> {
    /// The largest data length for which a STREAM frame with these Stream ID
    /// and Offset fields and a Length field takes at most `room` bytes, or
    /// `None` if not even an empty frame fits.
    ///
    /// The length accounts for the Length field growing with the data: a
    /// frame with that much data and the shortest Length field,
    /// [`VarIntWidth::shortest`] of the length, fits `room`. The
    /// 2<sup>62</sup> − 1 bound on the end of the data is also applied.
    ///
    /// This signature is provisional.
    pub fn max_data_len(
        stream_id: VarIntField<StreamId>,
        offset: Option<VarIntField<VarInt>>,
        room: usize,
    ) -> Option<usize> {
        let limit = DataEndError::limit(start(offset));
        max_len_with_length_field(fixed_len(stream_id, offset), limit, room)
    }
}

impl<D: Buf> StreamFrame<D, NoLength> {
    /// The STREAM frame without a Length field and with these other fields.
    ///
    /// # Errors
    ///
    /// [`DataEndError`] if the data would end beyond 2<sup>62</sup> − 1.
    pub fn without_length(
        stream_id: VarIntField<StreamId>,
        offset: Option<VarIntField<VarInt>>,
        data: D,
        fin: bool,
    ) -> Result<Self, DataEndError> {
        DataEndError::check(start(offset), data.remaining() as u64)?;
        Ok(Self {
            stream_id,
            offset,
            length: NoLength,
            data,
            fin,
        })
    }
}

impl<D> StreamFrame<D, NoLength> {
    /// The largest data length for which a STREAM frame with these Stream ID
    /// and Offset fields and no Length field takes at most `room` bytes, or
    /// `None` if not even an empty frame fits.
    ///
    /// The frame fills `room` exactly when the data is that long, unless the
    /// 2<sup>62</sup> − 1 bound on the end of the data is lower.
    ///
    /// This signature is provisional.
    pub fn max_data_len(
        stream_id: VarIntField<StreamId>,
        offset: Option<VarIntField<VarInt>>,
        room: usize,
    ) -> Option<usize> {
        let limit = DataEndError::limit(start(offset));
        room.checked_sub(fixed_len(stream_id, offset))
            .map(|left| left.min(limit))
    }
}

impl<D: Buf> StreamFrame<D> {
    /// The STREAM frame with these fields, with or without a Length field as
    /// `length` states: [`with_length`](StreamFrame::with_length) or
    /// [`without_length`](StreamFrame::without_length), as a frame that was read.
    ///
    /// # Errors
    ///
    /// [`InvalidDataError::DataEnd`] if the data would end beyond
    /// 2<sup>62</sup> − 1, and, with a Length field,
    /// [`InvalidDataError::Length`] if it is too narrow for the length of the
    /// data.
    pub fn new(
        stream_id: VarIntField<StreamId>,
        offset: Option<VarIntField<VarInt>>,
        length: Either<NoLength, VarIntWidth>,
        data: D,
        fin: bool,
    ) -> Result<Self, InvalidDataError> {
        Ok(match length {
            Either::Left(NoLength) => {
                StreamFrame::without_length(stream_id, offset, data, fin)?.into()
            }
            Either::Right(width) => {
                StreamFrame::with_length(stream_id, offset, width, data, fin)?.into()
            }
        })
    }
}

impl<D> From<StreamFrame<D, VarIntWidth>> for StreamFrame<D, Either<NoLength, VarIntWidth>> {
    /// The same frame, which has a Length field.
    fn from(frame: StreamFrame<D, VarIntWidth>) -> Self {
        let length = Either::Right(frame.length);
        frame.restate_length(length)
    }
}

impl<D> From<StreamFrame<D, NoLength>> for StreamFrame<D, Either<NoLength, VarIntWidth>> {
    /// The same frame, which has no Length field.
    fn from(frame: StreamFrame<D, NoLength>) -> Self {
        let length = Either::Left(frame.length);
        frame.restate_length(length)
    }
}

impl<D> From<StreamFrame<D, VarIntWidth>> for StreamFrame<D, Either<VarIntWidth, NoLength>> {
    /// The same frame, which has a Length field.
    fn from(frame: StreamFrame<D, VarIntWidth>) -> Self {
        let length = Either::Left(frame.length);
        frame.restate_length(length)
    }
}

impl<D> From<StreamFrame<D, NoLength>> for StreamFrame<D, Either<VarIntWidth, NoLength>> {
    /// The same frame, which has no Length field.
    fn from(frame: StreamFrame<D, NoLength>) -> Self {
        let length = Either::Right(frame.length);
        frame.restate_length(length)
    }
}

impl<D, A, B> From<StreamFrame<D, Either<A, B>>> for Either<StreamFrame<D, A>, StreamFrame<D, B>>
where
    A: LengthKind,
    B: LengthKind,
    Either<A, B>: LengthKind,
{
    /// The same frame as the side of `Either` that its Length field is on:
    /// `StreamFrame<D, Either<A, B>>` becomes `Either<StreamFrame<D, A>, StreamFrame<D, B>>`,
    /// in the same order.
    fn from(frame: StreamFrame<D, Either<A, B>>) -> Self {
        match frame.length {
            Either::Left(length) => Either::Left(frame.restate_length(length)),
            Either::Right(length) => Either::Right(frame.restate_length(length)),
        }
    }
}

impl<D, A, B> From<Either<StreamFrame<D, A>, StreamFrame<D, B>>> for StreamFrame<D, Either<A, B>>
where
    A: LengthKind,
    B: LengthKind,
    Either<A, B>: LengthKind,
{
    /// The frame on either side, with its Length field on the same side:
    /// `Either<StreamFrame<D, A>, StreamFrame<D, B>>` becomes `StreamFrame<D, Either<A, B>>`,
    /// in the same order.
    fn from(frame: Either<StreamFrame<D, A>, StreamFrame<D, B>>) -> Self {
        match frame {
            Either::Left(frame) => {
                let length = Either::Left(frame.length);
                frame.restate_length(length)
            }
            Either::Right(frame) => {
                let length = Either::Right(frame.length);
                frame.restate_length(length)
            }
        }
    }
}

impl<D> From<StreamFrame<D, Either<NoLength, VarIntWidth>>>
    for StreamFrame<D, Either<VarIntWidth, NoLength>>
{
    /// The same frame, with the sides of `Either` swapped.
    fn from(frame: StreamFrame<D, Either<NoLength, VarIntWidth>>) -> Self {
        let length = frame.length.flip();
        frame.restate_length(length)
    }
}

impl<D> From<StreamFrame<D, Either<VarIntWidth, NoLength>>>
    for StreamFrame<D, Either<NoLength, VarIntWidth>>
{
    /// The same frame, with the sides of `Either` swapped.
    fn from(frame: StreamFrame<D, Either<VarIntWidth, NoLength>>) -> Self {
        let length = frame.length.flip();
        frame.restate_length(length)
    }
}

/// The Frame Type value of a STREAM frame, `0x08..=0x0f`: `0x08` with the
/// OFF, LEN and FIN bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamTypeValue(VarInt);

impl StreamTypeValue {
    /// The Frame Type value `value` if it is that of a STREAM frame, and
    /// `None` otherwise.
    pub(crate) const fn new(value: VarInt) -> Option<Self> {
        match value.get() {
            0x08..=0x0f => Some(Self(value)),
            _ => None,
        }
    }

    /// The Frame Type value.
    pub const fn get(self) -> VarInt {
        self.0
    }

    /// Whether `bit` of the type is set.
    const fn has(self, bit: u64) -> bool {
        self.0.get() & bit != 0
    }
}

impl From<StreamTypeValue> for VarInt {
    fn from(value: StreamTypeValue) -> Self {
        value.0
    }
}

pub mod codec {
    //! Writing STREAM frames as `nitori_call` operations; reading is part of
    //! [`read_frame`](crate::frame::codec::read_frame).
    //!
    //! There is a write operation for each kind of Length field:
    //! [`write_stream_frame_with_length`] for `StreamFrame<D, VarIntWidth>`,
    //! [`write_stream_frame_without_length`] for `StreamFrame<D, NoLength>`, and
    //! [`write_stream_frame`] for `StreamFrame<D>`, which writes as one of the two.
    //! Each is also an operation struct, such as [`WriteStreamFrame`], with
    //! `{Name}Ext` on receiver accesses and `{Name}HostExt` on call
    //! executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::{StreamFrame, StreamTypeValue, bits};
    use crate::{
        frame::{DataEndError, InvalidDataError, NoLength, read_field},
        payload::{ReadPayloadError, read_payload, read_payload_to_end},
        var_int::{VarInt, VarIntField, VarIntWidth, codec::ReadVarIntError},
    };
    use bytes::Buf;
    use either::Either;
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};
    use snafu::{ResultExt, Snafu};

    /// Reads the fields that follow a STREAM Frame Type `frame_type`, and the
    /// data as one chunk of the source: of the Length field's length, or to
    /// the end of the source without one.
    pub(crate) async fn read_stream_frame<F, A>(
        io: &mut A,
        frame_type: StreamTypeValue,
    ) -> Result<StreamFrame<F::Chunk>, ReadStreamFrameError<F::Error>>
    where
        F: ReadChunk<Chunk: Default>,
        A: ReceiverAccess<Family = F>,
    {
        use read_stream_error::*;
        let stream_id = read_field(io).await.context(StreamIdSnafu)?;
        let offset = if frame_type.has(bits::OFF) {
            Some(read_field(io).await.context(OffsetSnafu)?)
        } else {
            None
        };
        let (length, data) = if frame_type.has(bits::LEN) {
            let length: VarIntField<VarInt> = read_field(io).await.context(LengthSnafu)?;
            // The end of the data follows from the fields, so a frame that
            // breaks the bound is rejected before its data is read.
            DataEndError::check(super::start(offset), length.get().get())?;
            // The end check bounds the length by 2^62 - 1; where `usize` is
            // narrower, a saturated length exceeds every source.
            let data_len = usize::try_from(length.get().get()).unwrap_or(usize::MAX);
            let data = read_payload(io, data_len).await.context(DataSnafu)?;
            (Either::Right(length.width()), data)
        } else {
            let data = read_payload_to_end(io).await.context(DataSnafu)?;
            (Either::Left(NoLength), data)
        };
        let fin = frame_type.has(bits::FIN);
        StreamFrame::new(stream_id, offset, length, data, fin).map_err(|error| match error {
            InvalidDataError::DataEnd { source } => ReadStreamFrameError::DataEnd { source },
            // invariant: the Length field was read at this width, and
            // `read_payload` returns data of exactly the length it states: it
            // fails on shorter data and panics on a longer chunk.
            InvalidDataError::Length { source } => unreachable!("{source}"),
        })
    }

    /// Failures of reading a STREAM frame.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_stream_error), visibility(pub(crate)))]
    pub enum ReadStreamFrameError<E> {
        /// The Stream ID field could not be read.
        #[snafu(display("STREAM Stream ID read failed"))]
        StreamId {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The Offset field could not be read.
        #[snafu(display("STREAM Offset read failed"))]
        Offset {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The Length field could not be read.
        #[snafu(display("STREAM Length read failed"))]
        Length {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The data would end beyond 2<sup>62</sup> − 1.
        #[snafu(transparent)]
        DataEnd {
            /// The broken limit.
            source: DataEndError,
        },
        /// The data could not be read.
        #[snafu(display("STREAM data read failed"))]
        Data {
            /// The failure of reading the data.
            source: ReadPayloadError<E>,
        },
    }

    /// Writes `frame`, as [`write_stream_frame_with_length`] or
    /// [`write_stream_frame_without_length`] as its Length field states; its
    /// constructor checked its limits.
    ///
    /// A frame without a Length field extends to the end of the packet;
    /// nothing may be written after it.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_stream_frame<F, A, D>(
        io: &mut A,
        frame: StreamFrame<D>,
    ) -> Result<(), WriteAllError<F::Error>>
    where
        F: Write,
        A: ReceiverAccess<Family = F>,
        D: Buf,
    {
        match frame.length {
            Either::Left(length) => {
                write_stream_frame_without_length(io, frame.restate_length(length)).await
            }
            Either::Right(length) => {
                write_stream_frame_with_length(io, frame.restate_length(length)).await
            }
        }
    }

    /// Writes `frame`, which has a Length field;
    /// [`StreamFrame::with_length`] checked its limits.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_stream_frame_with_length<F, A, D>(
        io: &mut A,
        frame: StreamFrame<D, VarIntWidth>,
    ) -> Result<(), WriteAllError<F::Error>>
    where
        F: Write,
        A: ReceiverAccess<Family = F>,
        D: Buf,
    {
        let head = frame.head();
        io.write_all(head.as_slice().chain(frame.data)).await
    }

    /// Writes `frame`, which has no Length field;
    /// [`StreamFrame::without_length`] checked its limits.
    ///
    /// The frame extends to the end of the packet; nothing may be written
    /// after it.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_stream_frame_without_length<F, A, D>(
        io: &mut A,
        frame: StreamFrame<D, NoLength>,
    ) -> Result<(), WriteAllError<F::Error>>
    where
        F: Write,
        A: ReceiverAccess<Family = F>,
        D: Buf,
    {
        let head = frame.head();
        io.write_all(head.as_slice().chain(frame.data)).await
    }
}

#[cfg(test)]
mod tests;
