//! STOP_SENDING frames ([RFC 9000 §19.5]).
//!
//! [RFC 9000 §19.5]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.5
use super::{FrameType, type_value};
use crate::frame::{Head, type_var_int};
use crate::v1::application_error::ApplicationErrorCode;
use crate::v1::stream_id::StreamId;
use crate::var_int::{VarInt, VarIntField};

/// A STOP_SENDING frame ([RFC 9000 §19.5]): the receiver asks the peer to stop sending on a stream.
///
/// Each field keeps the width of its variable-length integer encoding.
/// No limit ties the fields together, so [`StopSendingFrame::new`] accepts any
/// values; the fields are read through methods of the same names.
///
/// [RFC 9000 §19.5]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.5
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StopSendingFrame {
    stream_id: VarIntField<StreamId>,
    application_error_code: VarIntField<ApplicationErrorCode>,
}

impl StopSendingFrame {
    /// The STOP_SENDING frame with these fields.
    pub const fn new(
        stream_id: VarIntField<StreamId>,
        application_error_code: VarIntField<ApplicationErrorCode>,
    ) -> Self {
        Self {
            stream_id,
            application_error_code,
        }
    }

    /// The stream whose data is being discarded.
    pub const fn stream_id(&self) -> VarIntField<StreamId> {
        self.stream_id
    }

    /// The application protocol error code.
    pub const fn application_error_code(&self) -> VarIntField<ApplicationErrorCode> {
        self.application_error_code
    }

    /// The kind of the frame, [`FrameType::StopSending`].
    pub const fn frame_type(&self) -> FrameType {
        FrameType::StopSending
    }

    /// The Frame Type value.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(type_value::STOP_SENDING)
    }

    /// The number of bytes [`codec::write_stop_sending_frame`] writes.
    pub fn encoded_len(&self) -> usize {
        self.head().len()
    }

    /// The encoded frame.
    pub(in crate::v1) fn head(&self) -> Head<17> {
        Head::new(self.type_value())
            .field(self.stream_id)
            .field(self.application_error_code)
    }
}

pub mod codec {
    //! Writing STOP_SENDING as a `nitori_call` operation; reading is part of
    //! [`read_frame`](crate::frame::codec::read_frame).
    //!
    //! [`write_stop_sending_frame`] is also the operation struct [`WriteStopSendingFrame`], with
    //! `WriteStopSendingFrameExt` on receiver accesses and `WriteStopSendingFrameHostExt` on call
    //! executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::StopSendingFrame;
    use crate::{frame::read_field, var_int::codec::ReadVarIntError};
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};
    use snafu::{ResultExt, Snafu};

    /// Reads the fields that follow the Frame Type.
    pub(in crate::v1) async fn read_stop_sending_frame<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<StopSendingFrame, ReadStopSendingFrameError<F::Error>> {
        use read_stop_sending_error::*;
        let stream_id = read_field(io).await.context(StreamIdSnafu)?;
        let application_error_code = read_field(io)
            .await
            .context(ApplicationProtocolErrorCodeSnafu)?;
        Ok(StopSendingFrame::new(stream_id, application_error_code))
    }

    /// Failures of reading a STOP_SENDING frame.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_stop_sending_error), visibility(pub(in crate::v1)))]
    pub enum ReadStopSendingFrameError<E> {
        /// The Stream ID field could not be read.
        #[snafu(display("STOP_SENDING Stream ID read failed"))]
        StreamId {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The Application Protocol Error Code field could not be read.
        #[snafu(display("STOP_SENDING Application Protocol Error Code read failed"))]
        ApplicationProtocolErrorCode {
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
    pub async fn write_stop_sending_frame<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        frame: StopSendingFrame,
    ) -> Result<(), WriteAllError<F::Error>> {
        io.write_all(frame.head().as_slice()).await
    }
}

#[cfg(test)]
mod tests {
    use super::StopSendingFrame;
    use crate::v1::application_error::ApplicationErrorCode;
    use crate::v1::stream_id::StreamId;
    use crate::{
        v1::frame::{
            Frame,
            tests::{assert_bytes_round_trip, assert_round_trip},
        },
        var_int::{VarInt, VarIntField},
    };

    #[test]
    fn round_trips() {
        let stream_id = VarIntField::shortest(StreamId::from_var_int(VarInt::from(3u8)));
        let code = VarIntField::shortest(ApplicationErrorCode::new(VarInt::from(7u8)));
        let encoding =
            assert_round_trip(Frame::StopSending(StopSendingFrame::new(stream_id, code)));
        assert_eq!(encoding, [0x05, 0x03, 0x07]);
        let Frame::StopSending(read) = assert_bytes_round_trip(&encoding) else {
            panic!("{encoding:02x?}")
        };
        assert_eq!(read.stream_id(), stream_id);
        assert_eq!(read.application_error_code(), code);
    }
}
