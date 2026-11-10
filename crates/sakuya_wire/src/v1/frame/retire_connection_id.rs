//! RETIRE_CONNECTION_ID frames ([RFC 9000 §19.16]).
//!
//! [RFC 9000 §19.16]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.16
use super::{FrameType, type_value};
use crate::frame::{Head, type_var_int};
use crate::var_int::{VarInt, VarIntField};

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
    pub(in crate::v1) fn head(&self) -> Head<9> {
        Head::new(self.type_value()).field(self.sequence_number)
    }
}

pub mod codec {
    //! Writing RETIRE_CONNECTION_ID as a `nitori_call` operation; reading is done by
    //! [`Frames`](crate::v1::frame::set::Frames).
    //!
    //! [`write_retire_connection_id_frame`] is also the operation struct [`WriteRetireConnectionIdFrame`], with
    //! `WriteRetireConnectionIdFrameExt` on receiver accesses and `WriteRetireConnectionIdFrameHostExt` on call
    //! executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::RetireConnectionIdFrame;
    use crate::{frame::read_field, var_int::codec::ReadVarIntError};
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};

    /// Reads the fields that follow the Frame Type.
    pub(in crate::v1) async fn read_retire_connection_id_frame<
        F: Read,
        A: ReceiverAccess<Family = F>,
    >(
        io: &mut A,
    ) -> Result<RetireConnectionIdFrame, ReadVarIntError<F::Error>> {
        Ok(RetireConnectionIdFrame::new(read_field(io).await?))
    }

    /// Writes the frame.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_retire_connection_id_frame<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        frame: RetireConnectionIdFrame,
    ) -> Result<(), WriteAllError<F::Error>> {
        io.write_all(frame.head().as_slice()).await
    }
}

#[cfg(test)]
mod tests {
    use super::RetireConnectionIdFrame;
    use crate::{
        v1::frame::{
            Frame,
            tests::{assert_bytes_round_trip, assert_round_trip},
        },
        var_int::{VarInt, VarIntField},
    };

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
