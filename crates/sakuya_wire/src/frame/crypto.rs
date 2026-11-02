//! CRYPTO frames ([RFC 9000 §19.6]).
//!
//! [RFC 9000 §19.6]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.6
use super::{
    DataEndError, Head, InvalidDataError, LengthError, max_len_with_length_field, type_value,
    type_var_int,
};
use crate::var_int::{VarInt, VarIntField, VarIntWidth};
use bytes::Buf;

/// A CRYPTO frame ([RFC 9000 §19.6]).
///
/// The Offset and Length fields are always present. The Length field holds
/// the length of the data, so only its width is stored; the Offset field
/// keeps the width of its encoding. The end of the data, the offset plus
/// its length, is at most [`VarInt::MAX`]. `D` holds the data: the source's
/// chunk type for a frame that was read, any [`Buf`] for one to write.
///
/// [RFC 9000 §19.6]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.6
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Crypto<D> {
    /// The Offset field: the byte offset of the data in the crypto stream of
    /// its level.
    pub offset: VarIntField<VarInt>,
    /// The width of the Length field, which holds the length of `data`.
    pub length_width: VarIntWidth,
    /// The cryptographic message data.
    pub data: D,
}

/// The longest encoding of the fields before the data.
const HEAD_MAX: usize = 1 + 8 + 8;

impl<D> Crypto<D> {
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

impl<D: Buf> Crypto<D> {
    /// The number of bytes [`codec::write_crypto`] writes.
    pub fn encoded_len(&self) -> usize {
        1 + self.offset.encoded_len() + self.length_width.encoded_len() + self.data.remaining()
    }

    /// Checks the 2<sup>62</sup> − 1 bound on the end of the data, and that
    /// the Length field can state the length of the data.
    ///
    /// # Errors
    ///
    /// [`InvalidDataError`] for the broken limit.
    pub fn validate(&self) -> Result<(), InvalidDataError> {
        let length = self.data.remaining();
        DataEndError::check(self.offset.get(), length as u64)?;
        LengthError::check(length, self.length_width)?;
        Ok(())
    }

    /// The fields before the data of a frame that passed validation.
    pub(crate) fn head(&self) -> Head<HEAD_MAX> {
        // Validation checked that the width holds the data length.
        let length = VarInt::try_from(self.data.remaining()).unwrap_or(VarInt::ZERO);
        Head::new(self.type_value())
            .field(self.offset)
            .var_int_of(length, self.length_width)
    }
}

pub mod codec {
    //! Writing CRYPTO frames as a `nitori_call` operation; reading is part of
    //! [`read_frame`](crate::frame::codec::read_frame).
    //!
    //! [`write_crypto`] is also the operation struct [`WriteCrypto`], with
    //! `WriteCryptoExt` on receiver accesses and `WriteCryptoHostExt` on call
    //! executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::Crypto;
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
    pub(crate) async fn read_crypto<F, A>(
        io: &mut A,
    ) -> Result<Crypto<F::Chunk>, ReadCryptoError<F::Error>>
    where
        F: ReadChunk<Chunk: Default>,
        A: ReceiverAccess<Family = F>,
    {
        let offset: VarIntField<VarInt> = read_field(io)
            .await
            .context(read_crypto_error::FieldSnafu)?;
        let length: VarIntField<VarInt> = read_field(io)
            .await
            .context(read_crypto_error::FieldSnafu)?;
        DataEndError::check(offset.get(), length.get().get())?;
        // The end check bounds the length by 2^62 - 1; where `usize` is
        // narrower, a saturated length exceeds every source.
        let data_len = usize::try_from(length.get().get()).unwrap_or(usize::MAX);
        let data = read_payload(io, data_len)
            .await
            .context(read_crypto_error::DataSnafu)?;
        Ok(Crypto {
            offset,
            length_width: length.width(),
            data,
        })
    }

    /// Failures of reading a CRYPTO frame.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_crypto_error), visibility(pub(crate)))]
    pub enum ReadCryptoError<E> {
        /// The Offset or the Length field could not be read.
        #[snafu(display("CRYPTO field read failed"))]
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
        #[snafu(display("CRYPTO data read failed"))]
        Data {
            /// The failure of reading the data.
            source: ReadPayloadError<E>,
        },
    }

    /// Writes `frame`, after checking it with [`Crypto::validate`].
    ///
    /// # Errors
    ///
    /// [`WriteCryptoError::Invalid`] before writing anything, and
    /// [`WriteCryptoError::Write`] if the receiver stops accepting bytes or
    /// fails; bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_crypto<F, A, D>(
        io: &mut A,
        frame: Crypto<D>,
    ) -> Result<(), WriteCryptoError<F::Error>>
    where
        F: Write,
        A: ReceiverAccess<Family = F>,
        D: Buf,
    {
        frame.validate()?;
        write_body(io, frame)
            .await
            .context(write_crypto_error::WriteSnafu)
    }

    /// Writes a frame that has been checked.
    pub(crate) async fn write_body<F, A, D>(
        io: &mut A,
        frame: Crypto<D>,
    ) -> Result<(), WriteAllError<F::Error>>
    where
        F: Write,
        A: ReceiverAccess<Family = F>,
        D: Buf,
    {
        let head = frame.head();
        io.write_all(head.as_slice().chain(frame.data)).await
    }

    /// Failures that [`write_crypto`] can produce.
    #[derive(Debug, Snafu)]
    #[snafu(module(write_crypto_error), visibility(pub(crate)))]
    pub enum WriteCryptoError<E> {
        /// The frame breaks a limit of the encoding; nothing was written.
        #[snafu(transparent)]
        Invalid {
            /// The broken limit.
            source: InvalidDataError,
        },
        /// The receiver stopped accepting bytes or failed.
        #[snafu(display("CRYPTO write failed"))]
        Write {
            /// The failure of writing.
            source: WriteAllError<E>,
        },
    }
}

#[cfg(test)]
mod tests;
