//! PATH_RESPONSE frames ([RFC 9000 §19.18]).
//!
//! [RFC 9000 §19.18]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.18
use super::{FrameType, PATH_DATA_LEN, type_value};
use crate::frame::{Head, type_var_int};
use crate::var_int::VarInt;

/// A PATH_RESPONSE frame ([RFC 9000 §19.18]).
///
/// [`PathResponseFrame::new`] accepts any data, which is read through
/// [`PathResponseFrame::data`].
///
/// [RFC 9000 §19.18]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.18
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PathResponseFrame {
    data: [u8; PATH_DATA_LEN],
}

impl PathResponseFrame {
    /// The PATH_RESPONSE frame with this data.
    pub const fn new(data: [u8; PATH_DATA_LEN]) -> Self {
        Self { data }
    }

    /// The data of the PATH_CHALLENGE being answered.
    pub const fn data(&self) -> [u8; PATH_DATA_LEN] {
        self.data
    }

    /// The kind of the frame, [`FrameType::PathResponse`].
    pub const fn frame_type(&self) -> FrameType {
        FrameType::PathResponse
    }

    /// The Frame Type value.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(type_value::PATH_RESPONSE)
    }

    /// The number of bytes [`codec::write_path_response_frame`] writes.
    pub const fn encoded_len(&self) -> usize {
        1 + PATH_DATA_LEN
    }

    /// The encoded frame.
    pub(crate) fn head(&self) -> Head<{ 1 + PATH_DATA_LEN }> {
        // invariant: `1 + PATH_DATA_LEN` is the longest encoding of the frame's fields
        // here, so they fit.
        Head::new(self.type_value())
            .and_then(|head| head.bytes(&self.data))
            .expect("the head holds the fields")
    }
}

pub mod codec {
    //! Writing PATH_RESPONSE; reading is done by
    //! [`Frames`](crate::frame::set::Frames).

    use super::PathResponseFrame;
    use crate::frame::PATH_DATA_LEN;
    use bytes::{Buf, BufMut};
    use nitori_io::error::IncompleteError;
    use sakuya_wire::source::read_array;

    /// Reads the data that follows the Frame Type.
    pub(crate) fn read_path_response_frame(
        src: &mut impl Buf,
    ) -> Result<PathResponseFrame, IncompleteError> {
        Ok(PathResponseFrame::new(read_array::<PATH_DATA_LEN>(src)?))
    }

    /// Writes the frame.
    ///
    /// # Panics
    ///
    /// If `dst` has no room for the frame, as [`BufMut`] does.
    pub fn write_path_response_frame(dst: &mut impl BufMut, frame: PathResponseFrame) {
        dst.put_slice(frame.head().as_slice());
    }
}

#[cfg(test)]
mod tests {
    use super::PathResponseFrame;
    use crate::frame::{
        Frame,
        tests::{assert_bytes_round_trip, assert_round_trip},
    };

    #[test]
    fn round_trips() {
        let encoding = assert_round_trip(Frame::PathResponse(PathResponseFrame::new(*b"response")));
        assert_eq!(encoding[1..], *b"response");
        let Frame::PathResponse(read) = assert_bytes_round_trip(&encoding) else {
            panic!("{encoding:02x?}")
        };
        assert_eq!(read.data(), *b"response");
    }
}
