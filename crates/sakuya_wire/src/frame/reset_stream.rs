//! RESET_STREAM frames ([RFC 9000 §19.4]).
//!
//! [RFC 9000 §19.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.4
use super::{Head, type_value, type_var_int};
use crate::v1::application_error::ApplicationErrorCode;
use crate::v1::stream_id::StreamId;
use crate::var_int::{VarInt, VarIntField};

/// A RESET_STREAM frame ([RFC 9000 §19.4]): the sender abruptly terminates the sending part of a stream.
///
/// Each field keeps the width of its variable-length integer encoding.
/// No limit ties the fields together, so [`ResetStreamFrame::new`] accepts any
/// values; the fields are read through methods of the same names.
///
/// [RFC 9000 §19.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.4
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ResetStreamFrame {
    stream_id: VarIntField<StreamId>,
    application_error_code: VarIntField<ApplicationErrorCode>,
    final_size: VarIntField<VarInt>,
}

impl ResetStreamFrame {
    /// The RESET_STREAM frame with these fields.
    pub const fn new(
        stream_id: VarIntField<StreamId>,
        application_error_code: VarIntField<ApplicationErrorCode>,
        final_size: VarIntField<VarInt>,
    ) -> Self {
        Self {
            stream_id,
            application_error_code,
            final_size,
        }
    }

    /// The stream being terminated.
    pub const fn stream_id(&self) -> VarIntField<StreamId> {
        self.stream_id
    }

    /// The application protocol error code.
    pub const fn application_error_code(&self) -> VarIntField<ApplicationErrorCode> {
        self.application_error_code
    }

    /// The final size of the stream, in bytes.
    pub const fn final_size(&self) -> VarIntField<VarInt> {
        self.final_size
    }

    /// The Frame Type value.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(type_value::RESET_STREAM)
    }

    /// The number of bytes [`codec::write_reset_stream_frame`] writes.
    pub fn encoded_len(&self) -> usize {
        self.head().len()
    }

    /// The encoded frame.
    pub(crate) fn head(&self) -> Head<25> {
        Head::new(self.type_value())
            .field(self.stream_id)
            .field(self.application_error_code)
            .field(self.final_size)
    }
}

pub mod codec {
    //! Writing RESET_STREAM as a `nitori_call` operation; reading is part of
    //! [`read_frame`](crate::frame::codec::read_frame).
    //!
    //! [`write_reset_stream_frame`] is also the operation struct [`WriteResetStreamFrame`], with
    //! `WriteResetStreamFrameExt` on receiver accesses and `WriteResetStreamFrameHostExt` on call
    //! executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::ResetStreamFrame;
    use crate::{frame::read_field, var_int::codec::ReadVarIntError};
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};
    use snafu::{ResultExt, Snafu};

    /// Reads the fields that follow the Frame Type.
    pub(crate) async fn read_reset_stream_frame<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<ResetStreamFrame, ReadResetStreamFrameError<F::Error>> {
        use read_reset_stream_error::*;
        let stream_id = read_field(io).await.context(StreamIdSnafu)?;
        let application_error_code = read_field(io)
            .await
            .context(ApplicationProtocolErrorCodeSnafu)?;
        let final_size = read_field(io).await.context(FinalSizeSnafu)?;
        Ok(ResetStreamFrame::new(
            stream_id,
            application_error_code,
            final_size,
        ))
    }

    /// Failures of reading a RESET_STREAM frame.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_reset_stream_error), visibility(pub(crate)))]
    pub enum ReadResetStreamFrameError<E> {
        /// The Stream ID field could not be read.
        #[snafu(display("RESET_STREAM Stream ID read failed"))]
        StreamId {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The Application Protocol Error Code field could not be read.
        #[snafu(display("RESET_STREAM Application Protocol Error Code read failed"))]
        ApplicationProtocolErrorCode {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The Final Size field could not be read.
        #[snafu(display("RESET_STREAM Final Size read failed"))]
        FinalSize {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
    }

    /// Writes the frame.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_reset_stream_frame<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        frame: ResetStreamFrame,
    ) -> Result<(), WriteAllError<F::Error>> {
        io.write_all(frame.head().as_slice()).await
    }
}

#[cfg(test)]
mod tests {
    use super::ResetStreamFrame;
    use crate::v1::application_error::ApplicationErrorCode;
    use crate::v1::stream_id::StreamId;
    use crate::{
        frame::{
            Frame,
            tests::{assert_bytes_round_trip, assert_round_trip},
        },
        var_int::{VarInt, VarIntField},
    };

    #[test]
    fn round_trips() {
        let stream_id = VarIntField::shortest(StreamId::from_var_int(VarInt::from(4u8)));
        let code = VarIntField::shortest(ApplicationErrorCode::new(VarInt::from(0x100u16)));
        let final_size = VarIntField::shortest(VarInt::from(70_000u32));
        let frame = ResetStreamFrame::new(stream_id, code, final_size);
        let encoding = assert_round_trip(Frame::ResetStream(frame));
        assert_eq!(encoding, [0x04, 0x04, 0x41, 0x00, 0x80, 0x01, 0x11, 0x70]);
        let Frame::ResetStream(read) = assert_bytes_round_trip(&encoding) else {
            panic!("{encoding:02x?}")
        };
        assert_eq!(read.stream_id(), stream_id);
        assert_eq!(read.application_error_code(), code);
        assert_eq!(read.final_size(), final_size);
    }
}
