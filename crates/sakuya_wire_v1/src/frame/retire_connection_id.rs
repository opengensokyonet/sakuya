//! RETIRE_CONNECTION_ID frames ([RFC 9000 §19.16]).
//!
//! [RFC 9000 §19.16]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.16
use super::{FrameType, type_value};
use sakuya_wire::frame::{Head, type_var_int};
use sakuya_wire::var_int::{VarInt, VarIntField};

/// A RETIRE_CONNECTION_ID frame ([RFC 9000 §19.16]).
///
/// Each field keeps the width of its variable-length integer encoding.
/// No limit ties the fields together, so [`RetireConnectionIdFrame::new`] accepts any
/// values; the fields are read through methods of the same names.
///
/// [RFC 9000 §19.16]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.16
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RetireConnectionIdFrame {
    sequence_number: VarIntField<VarInt>,
}

impl RetireConnectionIdFrame {
    /// The RETIRE_CONNECTION_ID frame with this field.
    pub const fn new(sequence_number: VarIntField<VarInt>) -> Self {
        Self { sequence_number }
    }

    /// The sequence number of the connection ID being retired.
    pub const fn sequence_number(&self) -> VarIntField<VarInt> {
        self.sequence_number
    }

    /// The kind of the frame, [`FrameType::RetireConnectionId`].
    pub const fn frame_type(&self) -> FrameType {
        FrameType::RetireConnectionId
    }

    /// The Frame Type value.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(type_value::RETIRE_CONNECTION_ID)
    }

    /// The number of bytes [`codec::write_retire_connection_id_frame`] writes.
    pub fn encoded_len(&self) -> usize {
        self.head().len()
    }

    /// The encoded frame.
    pub(crate) fn head(&self) -> Head<9> {
        // invariant: `9` is the longest encoding of the frame's fields
        // here, so they fit.
        Head::new(self.type_value())
            .and_then(|head| head.field(self.sequence_number))
            .expect("the head holds the fields")
    }
}

pub mod codec {
    //! Writing RETIRE_CONNECTION_ID; reading is done by
    //! [`Frames`](crate::frame::set::Frames).

    use super::RetireConnectionIdFrame;
    use bytes::{Buf, BufMut};
    use nitori_io::error::IncompleteError;
    use sakuya_wire::frame::read_field;

    /// Reads the fields that follow the Frame Type.
    pub(crate) fn read_retire_connection_id_frame(
        src: &mut impl Buf,
    ) -> Result<RetireConnectionIdFrame, IncompleteError> {
        Ok(RetireConnectionIdFrame::new(read_field(src)?))
    }

    /// Writes the frame.
    ///
    /// # Panics
    ///
    /// If `dst` has no room for the frame, as [`BufMut`] does.
    pub fn write_retire_connection_id_frame(dst: &mut impl BufMut, frame: RetireConnectionIdFrame) {
        dst.put_slice(frame.head().as_slice());
    }
}

#[cfg(test)]
mod tests {
    use super::RetireConnectionIdFrame;
    use crate::frame::{
        Frame,
        tests::{assert_bytes_round_trip, assert_round_trip},
    };
    use sakuya_wire::var_int::{VarInt, VarIntField};

    #[test]
    fn round_trips() {
        let sequence_number = VarIntField::shortest(VarInt::from(9u8));
        let encoding = assert_round_trip(Frame::RetireConnectionId(RetireConnectionIdFrame::new(
            sequence_number,
        )));
        assert_eq!(encoding, [0x19, 0x09]);
        let Frame::RetireConnectionId(read) = assert_bytes_round_trip(&encoding) else {
            panic!("{encoding:02x?}")
        };
        assert_eq!(read.sequence_number(), sequence_number);
    }
}
