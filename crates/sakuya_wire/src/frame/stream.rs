//! STREAM frames ([RFC 9000 §19.8]).
//!
//! [RFC 9000 §19.8]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.8
use super::{
    DataEndError, Head, length_field_len, max_len_with_length_field, type_value, type_var_int,
};
use crate::{stream_id::StreamId, var_int::VarInt};
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
/// The Frame Type is derived from the fields: the OFF bit is set when
/// `offset` is not zero, the LEN bit when `has_length` is true, and the FIN
/// bit when `fin` is true. The end of the data, `offset` plus its length, is
/// at most [`VarInt::MAX`]. `D` holds the data: the source's chunk type for a
/// frame that was read, any [`Buf`] for one to write.
///
/// [RFC 9000 §19.8]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.8
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Stream<D> {
    /// The stream the data belongs to.
    pub stream_id: StreamId,
    /// The byte offset of the data in the stream.
    pub offset: VarInt,
    /// The stream data.
    pub data: D,
    /// Whether the data ends the stream.
    pub fin: bool,
    /// Whether the frame carries a Length field. Without one, the data
    /// extends to the end of the packet.
    pub has_length: bool,
}

/// The longest encoding of the fields before the data.
const HEAD_MAX: usize = 1 + 8 + 8 + 8;

impl<D> Stream<D> {
    /// The Frame Type value, which the OFF, LEN and FIN bits complete.
    pub const fn type_value(&self) -> VarInt {
        let mut value = type_value::STREAM;
        if self.offset.get() != 0 {
            value |= bits::OFF;
        }
        if self.has_length {
            value |= bits::LEN;
        }
        if self.fin {
            value |= bits::FIN;
        }
        type_var_int(value)
    }

    /// The largest data length for which a STREAM frame takes at most `room`
    /// bytes, or `None` if not even an empty frame fits.
    ///
    /// With `has_length`, the length accounts for the Length field growing
    /// with the data; without, the frame fills `room` exactly when the data
    /// is that long. The 2<sup>62</sup> − 1 bound on the end of the data is
    /// also applied.
    pub fn max_data_len(
        stream_id: StreamId,
        offset: VarInt,
        has_length: bool,
        room: usize,
    ) -> Option<usize> {
        let fixed = 1 + stream_id.get().encoded_len() + offset_len(offset);
        let limit = DataEndError::limit(offset);
        if has_length {
            max_len_with_length_field(fixed, limit, room)
        } else {
            room.checked_sub(fixed).map(|left| left.min(limit))
        }
    }
}

/// The encoded length of the Offset field, absent for offset zero.
fn offset_len(offset: VarInt) -> usize {
    if offset == VarInt::ZERO {
        0
    } else {
        offset.encoded_len()
    }
}

impl<D: Buf> Stream<D> {
    /// The number of bytes [`codec::write_stream`] writes.
    pub fn encoded_len(&self) -> usize {
        let length = self.data.remaining();
        let length_len = if self.has_length {
            length_field_len(length)
        } else {
            0
        };
        1 + self.stream_id.get().encoded_len() + offset_len(self.offset) + length_len + length
    }

    /// Checks the 2<sup>62</sup> − 1 bound on the end of the data.
    ///
    /// # Errors
    ///
    /// [`DataEndError`] if the data ends beyond it.
    pub fn validate(&self) -> Result<(), DataEndError> {
        DataEndError::check(self.offset, self.data.remaining() as u64)
    }

    /// The fields before the data of a frame that passed validation.
    pub(crate) fn head(&self) -> Head<HEAD_MAX> {
        let mut head = Head::new(self.type_value()).var_int(self.stream_id.get());
        if self.offset != VarInt::ZERO {
            head = head.var_int(self.offset);
        }
        if self.has_length {
            // Validation bounds the data length by 2^62 - 1.
            head = head.var_int(VarInt::try_from(self.data.remaining()).unwrap_or(VarInt::MAX));
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
        frame::DataEndError,
        payload::{ReadPayloadError, read_payload, read_payload_to_end},
        stream_id::StreamId,
        var_int::{
            VarInt,
            codec::{ReadVarIntError, ReadVarIntExt as _},
        },
    };
    use bytes::Buf;
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
        let stream_id = StreamId::from_var_int(field(io).await?);
        let offset = if type_bits & bits::OFF != 0 {
            field(io).await?
        } else {
            VarInt::ZERO
        };
        let has_length = type_bits & bits::LEN != 0;
        let data = if has_length {
            let length = field(io).await?;
            DataEndError::check(offset, length.get())?;
            // The end check bounds the length by 2^62 - 1; where `usize` is
            // narrower, a saturated length exceeds every source.
            let length = usize::try_from(length.get()).unwrap_or(usize::MAX);
            read_payload(io, length)
                .await
                .context(read_stream_error::DataSnafu)?
        } else {
            let data = read_payload_to_end(io)
                .await
                .context(read_stream_error::DataSnafu)?;
            DataEndError::check(offset, data.remaining() as u64)?;
            data
        };
        Ok(Stream {
            stream_id,
            offset,
            data,
            fin: type_bits & bits::FIN != 0,
            has_length,
        })
    }

    async fn field<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<VarInt, ReadStreamError<F::Error>> {
        io.read_var_int()
            .await
            .context(read_stream_error::FieldSnafu)
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
            source: DataEndError,
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
