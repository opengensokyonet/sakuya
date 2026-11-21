//! RESET_STREAM frames ([RFC 9000 §19.4]).
//!
//! [RFC 9000 §19.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.4
use super::{FrameType, type_value};
use crate::application_error::ApplicationErrorCode;
use crate::frame::{Head, type_var_int};
use crate::stream_id::StreamId;
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

    /// The kind of the frame, [`FrameType::ResetStream`].
    pub const fn frame_type(&self) -> FrameType {
        FrameType::ResetStream
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
        // invariant: `25` is the longest encoding of the frame's fields
        // here, so they fit.
        Head::new(self.type_value())
            .and_then(|head| head.field(self.stream_id))
            .and_then(|head| head.field(self.application_error_code))
            .and_then(|head| head.field(self.final_size))
            .expect("the head holds the fields")
    }
}

pub mod codec {
    //! Writing RESET_STREAM; reading is done by
    //! [`Frames`](crate::frame::set::Frames).

    use super::ResetStreamFrame;
    use crate::frame::read_field;
    use bytes::{Buf, BufMut};
    use nitori_io::error::IncompleteError;
    use snafu::{ResultExt, Snafu};

    /// Reads the fields that follow the Frame Type.
    pub(crate) fn read_reset_stream_frame(
        src: &mut impl Buf,
    ) -> Result<ResetStreamFrame, ReadResetStreamFrameError> {
        use read_reset_stream_error::*;
        let stream_id = read_field(src).context(StreamIdSnafu)?;
        let application_error_code = read_field(src).context(ApplicationProtocolErrorCodeSnafu)?;
        let final_size = read_field(src).context(FinalSizeSnafu)?;
        Ok(ResetStreamFrame::new(
            stream_id,
            application_error_code,
            final_size,
        ))
    }

    /// Failures of reading a RESET_STREAM frame.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_reset_stream_error), visibility(pub(crate)))]
    pub enum ReadResetStreamFrameError {
        /// The Stream ID field could not be read.
        #[snafu(display("RESET_STREAM Stream ID read failed"))]
        StreamId {
            /// The failure of reading the field.
            source: IncompleteError,
        },
        /// The Application Protocol Error Code field could not be read.
        #[snafu(display("RESET_STREAM Application Protocol Error Code read failed"))]
        ApplicationProtocolErrorCode {
            /// The failure of reading the field.
            source: IncompleteError,
        },
        /// The Final Size field could not be read.
        #[snafu(display("RESET_STREAM Final Size read failed"))]
        FinalSize {
            /// The failure of reading the field.
            source: IncompleteError,
        },
    }

    /// Writes the frame.
    ///
    /// # Panics
    ///
    /// If `dst` has no room for the frame, as [`BufMut`] does.
    pub fn write_reset_stream_frame(dst: &mut impl BufMut, frame: ResetStreamFrame) {
        dst.put_slice(frame.head().as_slice());
    }
}

#[cfg(test)]
mod tests {
    use super::ResetStreamFrame;
    use crate::application_error::ApplicationErrorCode;
    use crate::frame::{
        Frame,
        tests::{assert_bytes_round_trip, assert_round_trip},
    };
    use crate::stream_id::StreamId;
    use crate::var_int::{VarInt, VarIntField};

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
