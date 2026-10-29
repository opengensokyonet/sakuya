//! RETIRE_CONNECTION_ID frames ([RFC 9000 §19.16]).
//!
//! [RFC 9000 §19.16]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.16
use super::{Head, type_value, type_var_int};
use crate::var_int::VarInt;

/// A RETIRE_CONNECTION_ID frame ([RFC 9000 §19.16]).
///
/// [RFC 9000 §19.16]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.16
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RetireConnectionId {
    /// The sequence number of the connection ID being retired.
    pub sequence_number: VarInt,
}

impl RetireConnectionId {
    /// The Frame Type value.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(type_value::RETIRE_CONNECTION_ID)
    }

    /// The number of bytes [`codec::write_retire_connection_id`] writes.
    pub fn encoded_len(&self) -> usize {
        self.head().len()
    }

    /// The encoded frame.
    pub(crate) fn head(&self) -> Head<9> {
        Head::new(self.type_value()).var_int(self.sequence_number)
    }
}

pub mod codec {
    //! Writing RETIRE_CONNECTION_ID as a `nitori_call` operation; reading is part of
    //! [`read_frame`](crate::frame::codec::read_frame).
    //!
    //! [`write_retire_connection_id`] is also the operation struct [`WriteRetireConnectionId`], with
    //! `WriteRetireConnectionIdExt` on receiver accesses and `WriteRetireConnectionIdHostExt` on call
    //! executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::RetireConnectionId;
    use crate::var_int::codec::{ReadVarIntError, ReadVarIntExt as _};
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};

    /// Reads the fields that follow the Frame Type.
    pub(crate) async fn read_retire_connection_id<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<RetireConnectionId, ReadVarIntError<F::Error>> {
        Ok(RetireConnectionId {
            sequence_number: io.read_var_int().await?,
        })
    }

    /// Writes the frame.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_retire_connection_id<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        frame: RetireConnectionId,
    ) -> Result<(), WriteAllError<F::Error>> {
        io.write_all(frame.head().as_slice()).await
    }
}

#[cfg(test)]
mod tests {
    use super::RetireConnectionId;
    use crate::{
        frame::{Frame, tests::assert_round_trip},
        var_int::VarInt,
    };

    #[test]
    fn round_trips() {
        let frame = RetireConnectionId {
            sequence_number: VarInt::from(9u8),
        };
        assert_eq!(
            assert_round_trip(Frame::RetireConnectionId(frame)),
            [0x19, 0x09]
        );
    }
}
