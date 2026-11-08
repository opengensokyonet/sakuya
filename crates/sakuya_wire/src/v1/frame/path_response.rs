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
    pub(in crate::v1) fn head(&self) -> Head<{ 1 + PATH_DATA_LEN }> {
        Head::new(self.type_value()).bytes(&self.data)
    }
}

pub mod codec {
    //! Writing PATH_RESPONSE as a `nitori_call` operation; reading is part of
    //! [`read_frame`](crate::frame::codec::read_frame).
    //!
    //! [`write_path_response_frame`] is also the operation struct [`WritePathResponseFrame`], with
    //! `WritePathResponseFrameExt` on receiver accesses and `WritePathResponseFrameHostExt` on call
    //! executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::PathResponseFrame;
    use crate::v1::frame::PATH_DATA_LEN;
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{
        calls::{ReadArrayError, WriteAllError},
        prelude::*,
    };

    /// Reads the data that follows the Frame Type.
    pub(in crate::v1) async fn read_path_response_frame<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<PathResponseFrame, ReadArrayError<F::Error>> {
        Ok(PathResponseFrame::new(
            io.read_array::<PATH_DATA_LEN>().await?,
        ))
    }

    /// Writes the frame.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_path_response_frame<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        frame: PathResponseFrame,
    ) -> Result<(), WriteAllError<F::Error>> {
        io.write_all(frame.head().as_slice()).await
    }
}

#[cfg(test)]
mod tests {
    use super::PathResponseFrame;
    use crate::v1::frame::{
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
