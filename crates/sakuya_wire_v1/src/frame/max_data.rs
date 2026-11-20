//! MAX_DATA frames ([RFC 9000 §19.9]).
//!
//! [RFC 9000 §19.9]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.9
use super::{FrameType, type_value};
use sakuya_wire::frame::{Head, type_var_int};
use sakuya_wire::var_int::{VarInt, VarIntField};

/// A MAX_DATA frame ([RFC 9000 §19.9]).
///
/// Each field keeps the width of its variable-length integer encoding.
/// No limit ties the fields together, so [`MaxDataFrame::new`] accepts any
/// values; the fields are read through methods of the same names.
///
/// [RFC 9000 §19.9]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.9
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MaxDataFrame {
    maximum_data: VarIntField<VarInt>,
}

impl MaxDataFrame {
    /// The MAX_DATA frame with this field.
    pub const fn new(maximum_data: VarIntField<VarInt>) -> Self {
        Self { maximum_data }
    }

    /// The maximum amount of data that can be sent on the connection, in bytes.
    pub const fn maximum_data(&self) -> VarIntField<VarInt> {
        self.maximum_data
    }

    /// The kind of the frame, [`FrameType::MaxData`].
    pub const fn frame_type(&self) -> FrameType {
        FrameType::MaxData
    }

    /// The Frame Type value.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(type_value::MAX_DATA)
    }

    /// The number of bytes [`codec::write_max_data_frame`] writes.
    pub fn encoded_len(&self) -> usize {
        self.head().len()
    }

    /// The encoded frame.
    pub(crate) fn head(&self) -> Head<9> {
        // invariant: `9` is the longest encoding of the frame's fields
        // here, so they fit.
        Head::new(self.type_value())
            .and_then(|head| head.field(self.maximum_data))
            .expect("the head holds the fields")
    }
}

pub mod codec {
    //! Writing MAX_DATA; reading is done by
    //! [`Frames`](crate::frame::set::Frames).

    use super::MaxDataFrame;
    use bytes::{Buf, BufMut};
    use nitori_io::error::IncompleteError;
    use sakuya_wire::frame::read_field;

    /// Reads the fields that follow the Frame Type.
    pub(crate) fn read_max_data_frame(src: &mut impl Buf) -> Result<MaxDataFrame, IncompleteError> {
        Ok(MaxDataFrame::new(read_field(src)?))
    }

    /// Writes the frame.
    ///
    /// # Panics
    ///
    /// If `dst` has no room for the frame, as [`BufMut`] does.
    pub fn write_max_data_frame(dst: &mut impl BufMut, frame: MaxDataFrame) {
        dst.put_slice(frame.head().as_slice());
    }
}

#[cfg(test)]
mod tests {
    use super::MaxDataFrame;
    use crate::frame::{
        Frame,
        tests::{assert_bytes_round_trip, assert_round_trip},
    };
    use sakuya_wire::var_int::{VarInt, VarIntField};

    #[test]
    fn round_trips() {
        let maximum_data = VarIntField::shortest(VarInt::from(16_384u16));
        let encoding = assert_round_trip(Frame::MaxData(MaxDataFrame::new(maximum_data)));
        assert_eq!(encoding, [0x10, 0x80, 0x00, 0x40, 0x00]);
        let Frame::MaxData(read) = assert_bytes_round_trip(&encoding) else {
            panic!("{encoding:02x?}")
        };
        assert_eq!(read.maximum_data(), maximum_data);
    }
}
