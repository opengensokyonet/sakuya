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
        Head::new(self.type_value()).field(self.maximum_data)
    }
}

pub mod codec {
    //! Writing DATA_BLOCKED as a `nitori_call` operation; reading is done by
    //! [`Frames`](crate::v1::frame::set::Frames).
    //!
    //! [`write_data_blocked_frame`] is also the operation struct [`WriteDataBlockedFrame`], with
    //! `WriteDataBlockedFrameExt` on receiver accesses and `WriteDataBlockedFrameHostExt` on call
    //! executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::DataBlockedFrame;
    use crate::{frame::read_field, var_int::codec::ReadVarIntError};
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};

    /// Reads the fields that follow the Frame Type.
    pub(in crate::v1) async fn read_data_blocked_frame<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<DataBlockedFrame, ReadVarIntError<F::Error>> {
        Ok(DataBlockedFrame::new(read_field(io).await?))
    }

    /// Writes the frame.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_data_blocked_frame<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        frame: DataBlockedFrame,
    ) -> Result<(), WriteAllError<F::Error>> {
        io.write_all(frame.head().as_slice()).await
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
