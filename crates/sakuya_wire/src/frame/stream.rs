//! STREAM frames ([RFC 9000 §19.8]).
//!
//! [RFC 9000 §19.8]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.8
use super::{
    DataEndError, Head, InvalidDataError, LengthError, max_len_with_length_field, type_value,
    type_var_int,
};
use crate::{
    stream_id::StreamId,
    var_int::{VarInt, VarIntField, VarIntWidth},
};
use bytes::Buf;

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
/// when `fin` is true. An Offset field may hold 0, so a frame with the OFF
/// bit set and offset 0 is distinct from one without the bit. The Length
/// field holds the length of the data, so only its width is stored. Every
/// variable-length integer keeps the width of its encoding.
///
/// The end of the data, its offset plus its length, is at most
/// [`VarInt::MAX`]. `D` holds the data: the source's chunk type for a frame
/// that was read, any [`Buf`] for one to write.
///
/// [RFC 9000 §19.8]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.8
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Stream<D> {
    /// The Stream ID field: the stream the data belongs to.
    pub stream_id: VarIntField<StreamId>,
    /// The Offset field, present when the OFF bit is set: the byte offset of
    /// the data in the stream. Without it, the data starts at offset 0.
    pub offset: Option<VarIntField<VarInt>>,
    /// The width of the Length field, present when the LEN bit is set; the
    /// field holds the length of `data`. Without a Length field, the data
    /// extends to the end of the packet.
    pub length_width: Option<VarIntWidth>,
    /// The stream data.
    pub data: D,
    /// Whether the data ends the stream: the FIN bit.
    pub fin: bool,
}

/// The longest encoding of the fields before the data.
const HEAD_MAX: usize = 1 + 8 + 8 + 8;

impl<D> Stream<D> {
    /// The Frame Type value, which the OFF, LEN and FIN bits complete.
    pub const fn type_value(&self) -> VarInt {
        let mut value = type_value::STREAM;
        if self.offset.is_some() {
            value |= bits::OFF;
        }
        if self.length_width.is_some() {
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

    /// The largest data length for which a STREAM frame with these Stream ID
    /// and Offset fields takes at most `room` bytes, or `None` if not even an
    /// empty frame fits.
    ///
    /// With `has_length`, the length accounts for the Length field growing
    /// with the data: a frame with that much data and the shortest Length
    /// field, [`VarIntWidth::shortest`] of the length, fits `room`. Without,
    /// the frame fills `room` exactly when the data is that long. The
    /// 2<sup>62</sup> − 1 bound on the end of the data is also applied.
    ///
    /// This signature is provisional.
    pub fn max_data_len(
        stream_id: VarIntField<StreamId>,
        offset: Option<VarIntField<VarInt>>,
        has_length: bool,
        room: usize,
    ) -> Option<usize> {
        let fixed = 1 + stream_id.encoded_len() + offset.map_or(0, |offset| offset.encoded_len());
        let limit = DataEndError::limit(offset.map_or(VarInt::ZERO, |offset| offset.get()));
        if has_length {
            max_len_with_length_field(fixed, limit, room)
        } else {
            room.checked_sub(fixed).map(|left| left.min(limit))
        }
    }
}

impl<D: Buf> Stream<D> {
    /// The number of bytes [`codec::write_stream`] writes.
    pub fn encoded_len(&self) -> usize {
        1 + self.stream_id.encoded_len()
            + self.offset.map_or(0, |offset| offset.encoded_len())
            + self.length_width.map_or(0, VarIntWidth::encoded_len)
            + self.data.remaining()
    }

    /// Checks the 2<sup>62</sup> − 1 bound on the end of the data, and that
    /// the Length field, if present, can state the length of the data.
    ///
    /// # Errors
    ///
    /// [`InvalidDataError`] for the broken limit.
    pub fn validate(&self) -> Result<(), InvalidDataError> {
        let length = self.data.remaining();
        DataEndError::check(self.data_offset(), length as u64)?;
        if let Some(width) = self.length_width {
            LengthError::check(length, width)?;
        }
        Ok(())
    }

    /// The fields before the data of a frame that passed validation.
    pub(crate) fn head(&self) -> Head<HEAD_MAX> {
        let mut head = Head::new(self.type_value()).field(self.stream_id);
        if let Some(offset) = self.offset {
            head = head.field(offset);
        }
        if let Some(width) = self.length_width {
            // Validation checked that the width holds the data length.
            let length = VarInt::try_from(self.data.remaining()).unwrap_or(VarInt::ZERO);
            head = head.var_int_of(length, width);
        }
        head
    }
}

pub mod codec {
    //! Writing STREAM frames as a `nitori_call` operation; reading is part of
    //! [`read_frame`](crate::frame::codec::read_frame).
    //!
    //! [`write_stream`] is also the operation struct [`WriteStream`], with
    //! `WriteStreamExt` on receiver accesses and `WriteStreamHostExt` on call
    //! executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::{Stream, bits};
    use crate::{
        frame::{DataEndError, InvalidDataError, read_field},
        payload::{ReadPayloadError, read_payload, read_payload_to_end},
        var_int::{VarInt, VarIntField, codec::ReadVarIntError},
    };
    use bytes::Buf;
    use core::convert::Infallible;
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};
    use snafu::{ResultExt, Snafu};

    /// Reads the fields that follow a STREAM Frame Type `frame_type`, and the
    /// data as one chunk of the source: of the Length field's length, or to
    /// the end of the source without one.
    pub(crate) async fn read_stream<F, A>(
        io: &mut A,
        frame_type: VarInt,
    ) -> Result<Stream<F::Chunk>, ReadStreamError<F::Error>>
    where
        F: ReadChunk<Chunk: Default>,
        A: ReceiverAccess<Family = F>,
    {
        let type_bits = frame_type.get();
        let stream_id = field(io).await?;
        let offset = if type_bits & bits::OFF != 0 {
            Some(field(io).await?)
        } else {
            None
        };
        let start = offset.map_or(VarInt::ZERO, |offset: VarIntField<VarInt>| offset.get());
        let (length_width, data) = if type_bits & bits::LEN != 0 {
            let length: VarIntField<VarInt> = field(io).await?;
            DataEndError::check(start, length.get().get())?;
            // The end check bounds the length by 2^62 - 1; where `usize` is
            // narrower, a saturated length exceeds every source.
            let data_len = usize::try_from(length.get().get()).unwrap_or(usize::MAX);
            let data = read_payload(io, data_len)
                .await
                .context(read_stream_error::DataSnafu)?;
            (Some(length.width()), data)
        } else {
            let data = read_payload_to_end(io)
                .await
                .context(read_stream_error::DataSnafu)?;
            DataEndError::check(start, data.remaining() as u64)?;
            (None, data)
        };
        Ok(Stream {
            stream_id,
            offset,
            length_width,
            data,
            fin: type_bits & bits::FIN != 0,
        })
    }

    async fn field<T, F, A>(io: &mut A) -> Result<VarIntField<T>, ReadStreamError<F::Error>>
    where
        T: Copy + Into<VarInt> + TryFrom<VarInt, Error = Infallible>,
        F: Read,
        A: ReceiverAccess<Family = F>,
    {
        read_field(io).await.context(read_stream_error::FieldSnafu)
    }

    /// Failures of reading a STREAM frame.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_stream_error), visibility(pub(crate)))]
    pub enum ReadStreamError<E> {
        /// The Stream ID, Offset or Length field could not be read.
        #[snafu(display("STREAM field read failed"))]
        Field {
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

    /// Writes `frame`, after checking it with [`Stream::validate`].
    ///
    /// A frame without a Length field extends to the end of the packet;
    /// nothing may be written after it.
    ///
    /// # Errors
    ///
    /// [`WriteStreamError::Invalid`] before writing anything, and
    /// [`WriteStreamError::Write`] if the receiver stops accepting bytes or
    /// fails; bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_stream<F, A, D>(
        io: &mut A,
        frame: Stream<D>,
    ) -> Result<(), WriteStreamError<F::Error>>
    where
        F: Write,
        A: ReceiverAccess<Family = F>,
        D: Buf,
    {
        frame.validate()?;
        write_body(io, frame)
            .await
            .context(write_stream_error::WriteSnafu)
    }

    /// Writes a frame that has been checked.
    pub(crate) async fn write_body<F, A, D>(
        io: &mut A,
        frame: Stream<D>,
    ) -> Result<(), WriteAllError<F::Error>>
    where
        F: Write,
        A: ReceiverAccess<Family = F>,
        D: Buf,
    {
        let head = frame.head();
        io.write_all(head.as_slice().chain(frame.data)).await
    }

    /// Failures that [`write_stream`] can produce.
    #[derive(Debug, Snafu)]
    #[snafu(module(write_stream_error), visibility(pub(crate)))]
    pub enum WriteStreamError<E> {
        /// The frame breaks a limit of the encoding; nothing was written.
        #[snafu(transparent)]
        Invalid {
            /// The broken limit.
            source: InvalidDataError,
        },
        /// The receiver stopped accepting bytes or failed.
        #[snafu(display("STREAM write failed"))]
        Write {
            /// The failure of writing.
            source: WriteAllError<E>,
        },
    }
}

#[cfg(test)]
mod tests;
