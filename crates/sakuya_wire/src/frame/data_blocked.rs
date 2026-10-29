//! DATA_BLOCKED frames ([RFC 9000 §19.12]).
//!
//! [RFC 9000 §19.12]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.12
use super::{Head, type_value, type_var_int};
use crate::var_int::VarInt;

/// A DATA_BLOCKED frame ([RFC 9000 §19.12]).
///
/// [RFC 9000 §19.12]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.12
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DataBlocked {
    /// The connection-level limit at which blocking occurred.
    pub maximum_data: VarInt,
}

impl DataBlocked {
    /// The Frame Type value.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(type_value::DATA_BLOCKED)
    }

    /// The number of bytes [`codec::write_data_blocked`] writes.
    pub fn encoded_len(&self) -> usize {
        self.head().len()
    }

    /// The encoded frame.
    pub(crate) fn head(&self) -> Head<9> {
        Head::new(self.type_value()).var_int(self.maximum_data)
    }
}

pub mod codec {
    //! Writing DATA_BLOCKED as a `nitori_call` operation; reading is part of
    //! [`read_frame`](crate::frame::codec::read_frame).
    //!
    //! [`write_data_blocked`] is also the operation struct [`WriteDataBlocked`], with
    //! `WriteDataBlockedExt` on receiver accesses and `WriteDataBlockedHostExt` on call
    //! executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::DataBlocked;
    use crate::var_int::codec::{ReadVarIntError, ReadVarIntExt as _};
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};

    /// Reads the fields that follow the Frame Type.
    pub(crate) async fn read_data_blocked<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<DataBlocked, ReadVarIntError<F::Error>> {
        Ok(DataBlocked {
            maximum_data: io.read_var_int().await?,
        })
    }

    /// Writes the frame.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_data_blocked<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        frame: DataBlocked,
    ) -> Result<(), WriteAllError<F::Error>> {
        io.write_all(frame.head().as_slice()).await
    }
}

#[cfg(test)]
mod tests {
    use super::DataBlocked;
    use crate::{
        frame::{Frame, tests::assert_round_trip},
        var_int::VarInt,
    };

    #[test]
    fn round_trips() {
        let frame = DataBlocked {
            maximum_data: VarInt::from(64u8),
        };
        assert_eq!(
            assert_round_trip(Frame::DataBlocked(frame)),
            [0x14, 0x40, 0x40]
        );
    }
}
