//! RESET_STREAM frames ([RFC 9000 §19.4]).
//!
//! [RFC 9000 §19.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.4
use super::{Head, type_value, type_var_int};
use crate::application_error::ApplicationErrorCode;
use crate::stream_id::StreamId;
use crate::var_int::VarInt;

/// A RESET_STREAM frame ([RFC 9000 §19.4]): the sender abruptly terminates the sending part of a stream.
///
/// [RFC 9000 §19.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.4
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ResetStream {
    /// The stream being terminated.
    pub stream_id: StreamId,
    /// The application protocol error code.
    pub application_error_code: ApplicationErrorCode,
    /// The final size of the stream, in bytes.
    pub final_size: VarInt,
}

impl ResetStream {
    /// The Frame Type value.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(type_value::RESET_STREAM)
    }

    /// The number of bytes [`codec::write_reset_stream`] writes.
    pub fn encoded_len(&self) -> usize {
        self.head().len()
    }

    /// The encoded frame.
    pub(crate) fn head(&self) -> Head<25> {
        Head::new(self.type_value())
            .var_int(VarInt::from(self.stream_id))
            .var_int(VarInt::from(self.application_error_code))
            .var_int(self.final_size)
    }
}

pub mod codec {
    //! Writing RESET_STREAM as a `nitori_call` operation; reading is part of
    //! [`read_frame`](crate::frame::codec::read_frame).
    //!
    //! [`write_reset_stream`] is also the operation struct [`WriteResetStream`], with
    //! `WriteResetStreamExt` on receiver accesses and `WriteResetStreamHostExt` on call
    //! executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::ApplicationErrorCode;
    use super::ResetStream;
    use super::StreamId;
    use crate::var_int::codec::{ReadVarIntError, ReadVarIntExt as _};
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};

    /// Reads the fields that follow the Frame Type.
    pub(crate) async fn read_reset_stream<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<ResetStream, ReadVarIntError<F::Error>> {
        Ok(ResetStream {
            stream_id: StreamId::from_var_int(io.read_var_int().await?),
            application_error_code: ApplicationErrorCode::new(io.read_var_int().await?),
            final_size: io.read_var_int().await?,
        })
    }

    /// Writes the frame.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_reset_stream<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        frame: ResetStream,
    ) -> Result<(), WriteAllError<F::Error>> {
        io.write_all(frame.head().as_slice()).await
    }
}

#[cfg(test)]
mod tests {
    use super::ResetStream;
    use crate::application_error::ApplicationErrorCode;
    use crate::stream_id::StreamId;
    use crate::{
        frame::{Frame, tests::assert_round_trip},
        var_int::VarInt,
    };

    #[test]
    fn round_trips() {
        let frame = ResetStream {
            stream_id: StreamId::from_var_int(VarInt::from(4u8)),
            application_error_code: ApplicationErrorCode::new(VarInt::from(0x100u16)),
            final_size: VarInt::from(70_000u32),
        };
        assert_eq!(
            assert_round_trip(Frame::ResetStream(frame)),
            [0x04, 0x04, 0x41, 0x00, 0x80, 0x01, 0x11, 0x70]
        );
    }
}
