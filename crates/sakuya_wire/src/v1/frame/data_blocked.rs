//! DATA_BLOCKED frames ([RFC 9000 §19.12]).
//!
//! [RFC 9000 §19.12]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.12
use super::{FrameType, type_value};
use crate::frame::{Head, type_var_int};
use crate::var_int::{VarInt, VarIntField};

/// A DATA_BLOCKED frame ([RFC 9000 §19.12]).
///
/// Each field keeps the width of its variable-length integer encoding.
/// No limit ties the fields together, so [`DataBlockedFrame::new`] accepts any
/// values; the fields are read through methods of the same names.
///
/// [RFC 9000 §19.12]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.12
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DataBlockedFrame {
    maximum_data: VarIntField<VarInt>,
}

impl DataBlockedFrame {
    /// The DATA_BLOCKED frame with this field.
    pub const fn new(maximum_data: VarIntField<VarInt>) -> Self {
        Self { maximum_data }
    }

    /// The connection-level limit at which blocking occurred.
    pub const fn maximum_data(&self) -> VarIntField<VarInt> {
        self.maximum_data
    }

    /// The kind of the frame, [`FrameType::DataBlocked`].
    pub const fn frame_type(&self) -> FrameType {
        FrameType::DataBlocked
    }

    /// The Frame Type value.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(type_value::DATA_BLOCKED)
    }

    /// The number of bytes [`codec::write_data_blocked_frame`] writes.
    pub fn encoded_len(&self) -> usize {
        self.head().len()
    }

    /// The encoded frame.
    pub(in crate::v1) fn head(&self) -> Head<9> {
        // invariant: `9` is the longest encoding of the frame's fields
        // here, so they fit.
        Head::new(self.type_value())
            .and_then(|head| head.field(self.maximum_data))
            .expect("the head holds the fields")
    }
}

pub mod codec {
    //! Writing DATA_BLOCKED; reading is done by
    //! [`Frames`](crate::v1::frame::set::Frames).

    use super::DataBlockedFrame;
    use crate::frame::read_field;
    use bytes::{Buf, BufMut};
    use nitori_io::error::IncompleteError;

    /// Reads the fields that follow the Frame Type.
    pub(in crate::v1) fn read_data_blocked_frame(
        src: &mut impl Buf,
    ) -> Result<DataBlockedFrame, IncompleteError> {
        Ok(DataBlockedFrame::new(read_field(src)?))
    }

    /// Writes the frame.
    ///
    /// # Panics
    ///
    /// If `dst` has no room for the frame, as [`BufMut`] does.
    pub fn write_data_blocked_frame(dst: &mut impl BufMut, frame: DataBlockedFrame) {
        dst.put_slice(frame.head().as_slice());
    }
}

#[cfg(test)]
mod tests {
    use super::DataBlockedFrame;
    use crate::{
        v1::frame::{
            Frame,
            tests::{assert_bytes_round_trip, assert_round_trip},
        },
        var_int::{VarInt, VarIntField},
    };

    #[test]
    fn round_trips() {
        let maximum_data = VarIntField::shortest(VarInt::from(64u8));
        let encoding = assert_round_trip(Frame::DataBlocked(DataBlockedFrame::new(maximum_data)));
        assert_eq!(encoding, [0x14, 0x40, 0x40]);
        let Frame::DataBlocked(read) = assert_bytes_round_trip(&encoding) else {
            panic!("{encoding:02x?}")
        };
        assert_eq!(read.maximum_data(), maximum_data);
    }
}
