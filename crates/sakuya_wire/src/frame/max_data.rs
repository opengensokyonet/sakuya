//! MAX_DATA frames ([RFC 9000 §19.9]).
//!
//! [RFC 9000 §19.9]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.9
use super::{Head, type_value, type_var_int};
use crate::var_int::VarInt;

/// A MAX_DATA frame ([RFC 9000 §19.9]).
///
/// [RFC 9000 §19.9]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.9
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MaxData {
    /// The maximum amount of data that can be sent on the connection, in bytes.
    pub maximum_data: VarInt,
}

impl MaxData {
    /// The Frame Type value.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(type_value::MAX_DATA)
    }

    /// The number of bytes [`codec::write_max_data`] writes.
    pub fn encoded_len(&self) -> usize {
        self.head().len()
    }

    /// The encoded frame.
    pub(crate) fn head(&self) -> Head<9> {
        Head::new(self.type_value()).var_int(self.maximum_data)
    }
}

pub mod codec {
    //! Writing MAX_DATA as a `nitori_call` operation; reading is part of
    //! [`read_frame`](crate::frame::codec::read_frame).
    //!
    //! [`write_max_data`] is also the operation struct [`WriteMaxData`], with
    //! `WriteMaxDataExt` on receiver accesses and `WriteMaxDataHostExt` on call
    //! executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::MaxData;
    use crate::var_int::codec::{ReadVarIntError, ReadVarIntExt as _};
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};

    /// Reads the fields that follow the Frame Type.
    pub(crate) async fn read_max_data<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<MaxData, ReadVarIntError<F::Error>> {
        Ok(MaxData {
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
    pub async fn write_max_data<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        frame: MaxData,
    ) -> Result<(), WriteAllError<F::Error>> {
        io.write_all(frame.head().as_slice()).await
    }
}

#[cfg(test)]
mod tests {
    use super::MaxData;
    use crate::{
        frame::{Frame, tests::assert_round_trip},
        var_int::VarInt,
    };

    #[test]
    fn round_trips() {
        let frame = MaxData {
            maximum_data: VarInt::from(16_384u16),
        };
        assert_eq!(
            assert_round_trip(Frame::MaxData(frame)),
            [0x10, 0x80, 0x00, 0x40, 0x00]
        );
    }
}
