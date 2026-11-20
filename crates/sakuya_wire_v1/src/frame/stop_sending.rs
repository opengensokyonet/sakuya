//! STOP_SENDING frames ([RFC 9000 §19.5]).
//!
//! [RFC 9000 §19.5]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.5
use super::{FrameType, type_value};
use crate::application_error::ApplicationErrorCode;
use crate::stream_id::StreamId;
use sakuya_wire::frame::{Head, type_var_int};
use sakuya_wire::var_int::{VarInt, VarIntField};

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
    pub(crate) fn head(&self) -> Head<17> {
        // invariant: `17` is the longest encoding of the frame's fields
        // here, so they fit.
        Head::new(self.type_value())
            .and_then(|head| head.field(self.stream_id))
            .and_then(|head| head.field(self.application_error_code))
            .expect("the head holds the fields")
    }
}

pub mod codec {
    //! Writing STOP_SENDING; reading is done by
    //! [`Frames`](crate::frame::set::Frames).

    use super::StopSendingFrame;
    use bytes::{Buf, BufMut};
    use nitori_io::error::IncompleteError;
    use sakuya_wire::frame::read_field;
    use snafu::{ResultExt, Snafu};

    /// Reads the fields that follow the Frame Type.
    pub(crate) fn read_stop_sending_frame(
        src: &mut impl Buf,
    ) -> Result<StopSendingFrame, ReadStopSendingFrameError> {
        use read_stop_sending_error::*;
        let stream_id = read_field(src).context(StreamIdSnafu)?;
        let application_error_code = read_field(src).context(ApplicationProtocolErrorCodeSnafu)?;
        Ok(StopSendingFrame::new(stream_id, application_error_code))
    }

    /// Failures of reading a STOP_SENDING frame.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_stop_sending_error), visibility(pub(crate)))]
    pub enum ReadStopSendingFrameError {
        /// The Stream ID field could not be read.
        #[snafu(display("STOP_SENDING Stream ID read failed"))]
        StreamId {
            /// The failure of reading the field.
            source: IncompleteError,
        },
        /// The Application Protocol Error Code field could not be read.
        #[snafu(display("STOP_SENDING Application Protocol Error Code read failed"))]
        ApplicationProtocolErrorCode {
            /// The failure of reading the field.
            source: IncompleteError,
        },
    }

    /// Writes the frame.
    ///
    /// # Panics
    ///
    /// If `dst` has no room for the frame, as [`BufMut`] does.
    pub fn write_stop_sending_frame(dst: &mut impl BufMut, frame: StopSendingFrame) {
        dst.put_slice(frame.head().as_slice());
    }
}

#[cfg(test)]
mod tests {
    use super::StopSendingFrame;
    use crate::application_error::ApplicationErrorCode;
    use crate::frame::{
        Frame,
        tests::{assert_bytes_round_trip, assert_round_trip},
    };
    use crate::stream_id::StreamId;
    use sakuya_wire::var_int::{VarInt, VarIntField};

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
