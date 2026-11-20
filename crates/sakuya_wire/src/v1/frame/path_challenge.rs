//! PATH_CHALLENGE frames ([RFC 9000 §19.17]).
//!
//! [RFC 9000 §19.17]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.17
use super::{FrameType, PATH_DATA_LEN, type_value};
use crate::frame::{Head, type_var_int};
use crate::var_int::VarInt;

/// A PATH_CHALLENGE frame ([RFC 9000 §19.17]).
///
/// [`PathChallengeFrame::new`] accepts any data, which is read through
/// [`PathChallengeFrame::data`].
///
/// [RFC 9000 §19.17]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.17
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PathChallengeFrame {
    data: [u8; PATH_DATA_LEN],
}

impl PathChallengeFrame {
    /// The PATH_CHALLENGE frame with this data.
    pub const fn new(data: [u8; PATH_DATA_LEN]) -> Self {
        Self { data }
    }

    /// The data the peer echoes in PATH_RESPONSE.
    pub const fn data(&self) -> [u8; PATH_DATA_LEN] {
        self.data
    }

    /// The kind of the frame, [`FrameType::PathChallenge`].
    pub const fn frame_type(&self) -> FrameType {
        FrameType::PathChallenge
    }

    /// The Frame Type value.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(type_value::PATH_CHALLENGE)
    }

    /// The number of bytes [`codec::write_path_challenge_frame`] writes.
    pub const fn encoded_len(&self) -> usize {
        1 + PATH_DATA_LEN
    }

    /// The encoded frame.
    pub(in crate::v1) fn head(&self) -> Head<{ 1 + PATH_DATA_LEN }> {
        // invariant: `1 + PATH_DATA_LEN` is the longest encoding of the frame's fields
        // here, so they fit.
        Head::new(self.type_value())
            .and_then(|head| head.bytes(&self.data))
            .expect("the head holds the fields")
    }
}

pub mod codec {
    //! Writing PATH_CHALLENGE; reading is done by
    //! [`Frames`](crate::v1::frame::set::Frames).

    use super::PathChallengeFrame;
    use crate::source::read_array;
    use crate::v1::frame::PATH_DATA_LEN;
    use bytes::{Buf, BufMut};
    use nitori_io::error::IncompleteError;

    /// Reads the data that follows the Frame Type.
    pub(in crate::v1) fn read_path_challenge_frame(
        src: &mut impl Buf,
    ) -> Result<PathChallengeFrame, IncompleteError> {
        Ok(PathChallengeFrame::new(read_array::<PATH_DATA_LEN>(src)?))
    }

    /// Writes the frame.
    ///
    /// # Panics
    ///
    /// If `dst` has no room for the frame, as [`BufMut`] does.
    pub fn write_path_challenge_frame(dst: &mut impl BufMut, frame: PathChallengeFrame) {
        dst.put_slice(frame.head().as_slice());
    }
}

#[cfg(test)]
mod tests {
    use super::PathChallengeFrame;
    use crate::v1::frame::{
        Frame,
        tests::{assert_bytes_round_trip, assert_round_trip},
    };

    #[test]
    fn round_trips() {
        let encoding =
            assert_round_trip(Frame::PathChallenge(PathChallengeFrame::new(*b"challeng")));
        assert_eq!(encoding[1..], *b"challeng");
        let Frame::PathChallenge(read) = assert_bytes_round_trip(&encoding) else {
            panic!("{encoding:02x?}")
        };
        assert_eq!(read.data(), *b"challeng");
    }
}
