//! CRYPTO frames ([RFC 9000 §19.6]).
//!
//! [RFC 9000 §19.6]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.6
use super::{FrameType, type_value};
use crate::frame::{
    DataEndError, Head, InvalidDataError, LengthError, max_len_with_length_field, type_var_int,
};
use crate::var_int::{VarInt, VarIntField, VarIntWidth};
use bytes::Buf;

/// A CRYPTO frame ([RFC 9000 §19.6]).
///
/// The Offset and Length fields are always present. The Length field holds
/// the length of the data, so only its width is stored; the Offset field
/// keeps the width of its encoding.
///
/// The end of the data, the offset plus its length, is at most
/// [`VarInt::MAX`], and the Length field can state the length of the data.
/// [`CryptoFrame::new`] checks both, so every value writes an encoding that reads
/// back to the same value; the fields are read through methods of the same
/// names. `D` holds the data: the source's chunk type for a frame that was
/// read, any [`Buf`] for one to write.
///
/// [RFC 9000 §19.6]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.6
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CryptoFrame<D> {
    offset: VarIntField<VarInt>,
    length_width: VarIntWidth,
    data: D,
}

/// The longest encoding of the fields before the data.
const HEAD_MAX: usize = 1 + 8 + 8;

impl<D> CryptoFrame<D> {
    /// The Offset field: the byte offset of the data in the crypto stream of
    /// its level.
    pub const fn offset(&self) -> VarIntField<VarInt> {
        self.offset
    }

    /// The width of the Length field, which holds the length of the data.
    pub const fn length_width(&self) -> VarIntWidth {
        self.length_width
    }

    /// The cryptographic message data.
    pub const fn data(&self) -> &D {
        &self.data
    }

    /// Takes the cryptographic message data.
    pub fn into_data(self) -> D {
        self.data
    }

    /// The kind of the frame, [`FrameType::Crypto`].
    pub const fn frame_type(&self) -> FrameType {
        FrameType::Crypto
    }

    /// The Frame Type value, `0x06`.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(type_value::CRYPTO)
    }

    /// The largest data length for which a CRYPTO frame with this Offset
    /// field takes at most `room` bytes, or `None` if not even an empty frame
    /// fits.
    ///
    /// The length accounts for the Length field growing with the data: a
    /// frame with that much data and the shortest Length field,
    /// [`VarIntWidth::shortest`] of the length, fits `room`. The
    /// 2<sup>62</sup> − 1 bound on the end of the data is also applied.
    ///
    /// This signature is provisional.
    pub fn max_data_len(offset: VarIntField<VarInt>, room: usize) -> Option<usize> {
        let fixed = 1 + offset.encoded_len();
        max_len_with_length_field(fixed, DataEndError::limit(offset.get()), room)
    }
}

impl<D: Buf> CryptoFrame<D> {
    /// The CRYPTO frame with these fields.
    ///
    /// # Errors
    ///
    /// [`InvalidDataError::DataEnd`] if the data would end beyond
    /// 2<sup>62</sup> − 1, and [`InvalidDataError::Length`] if the Length
    /// field is too narrow for the length of the data.
    pub fn new(
        offset: VarIntField<VarInt>,
        length_width: VarIntWidth,
        data: D,
    ) -> Result<Self, InvalidDataError> {
        let length = data.remaining();
        DataEndError::check(offset.get(), length as u64)?;
        LengthError::check(length, length_width)?;
        Ok(Self {
            offset,
            length_width,
            data,
        })
    }

    /// The number of bytes [`codec::write_crypto_frame`] writes.
    pub fn encoded_len(&self) -> usize {
        1 + self.offset.encoded_len() + self.length_width.encoded_len() + self.data.remaining()
    }

    /// The fields before the data.
    pub(in crate::v1) fn head(&self) -> Head<HEAD_MAX> {
        // Construction checked that the width holds the data length.
        let length = VarInt::try_from(self.data.remaining()).unwrap_or(VarInt::ZERO);
        Head::new(self.type_value())
            .field(self.offset)
            .var_int_of(length, self.length_width)
    }
}

pub mod codec {
    //! Writing CRYPTO frames as a `nitori_call` operation; reading is done by
    //! [`Frames`](crate::v1::frame::set::Frames).
    //!
    //! [`write_crypto_frame`] is also the operation struct [`WriteCryptoFrame`], with
    //! `WriteCryptoFrameExt` on receiver accesses and `WriteCryptoFrameHostExt` on call
    //! executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::CryptoFrame;
    use crate::{
        frame::{DataEndError, InvalidDataError, read_field},
        payload::{ReadPayloadError, read_payload},
        var_int::{VarInt, VarIntField, codec::ReadVarIntError},
    };
    use bytes::Buf;
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};
    use snafu::{ResultExt, Snafu};

    /// Reads the fields that follow the Frame Type, and the data as one
    /// chunk of the source.
    pub(in crate::v1) async fn read_crypto_frame<F, A>(
        io: &mut A,
    ) -> Result<CryptoFrame<F::Chunk>, ReadCryptoFrameError<F::Error>>
    where
        F: ReadChunk<Chunk: Default>,
        A: ReceiverAccess<Family = F>,
    {
        let offset: VarIntField<VarInt> = read_field(io)
            .await
            .context(read_crypto_error::OffsetSnafu)?;
        let length: VarIntField<VarInt> = read_field(io)
            .await
            .context(read_crypto_error::LengthSnafu)?;
        // The end of the data follows from the fields, so a frame that
        // breaks the bound is rejected before its data is read.
        DataEndError::check(offset.get(), length.get().get())?;
        // The end check bounds the length by 2^62 - 1; where `usize` is
        // narrower, a saturated length exceeds every source.
        let data_len = usize::try_from(length.get().get()).unwrap_or(usize::MAX);
        let data = read_payload(io, data_len)
            .await
            .context(read_crypto_error::DataSnafu)?;
        CryptoFrame::new(offset, length.width(), data).map_err(|error| match error {
            InvalidDataError::DataEnd { source } => ReadCryptoFrameError::DataEnd { source },
            // invariant: the Length field was read at this width, and
            // `read_payload` returns data of exactly the length it states: it
            // fails on shorter data and panics on a longer chunk.
            InvalidDataError::Length { source } => unreachable!("{source}"),
        })
    }

    /// Failures of reading a CRYPTO frame.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_crypto_error), visibility(pub(in crate::v1)))]
    pub enum ReadCryptoFrameError<E> {
        /// The Offset field could not be read.
        #[snafu(display("CRYPTO Offset read failed"))]
        Offset {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The Length field could not be read.
        #[snafu(display("CRYPTO Length read failed"))]
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
        #[snafu(display("CRYPTO data read failed"))]
        Data {
            /// The failure of reading the data.
            source: ReadPayloadError<E>,
        },
    }

    /// Writes `frame`; [`CryptoFrame::new`] checked its limits.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_crypto_frame<F, A, D>(
        io: &mut A,
        frame: CryptoFrame<D>,
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
