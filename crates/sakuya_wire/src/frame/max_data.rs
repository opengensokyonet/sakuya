//! MAX_DATA frames ([RFC 9000 §19.9]).
//!
//! [RFC 9000 §19.9]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.9
use super::{Head, type_value, type_var_int};
use crate::var_int::{VarInt, VarIntField};

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
        Head::new(self.type_value()).field(self.maximum_data)
    }
}

pub mod codec {
    //! Writing MAX_DATA as a `nitori_call` operation; reading is part of
    //! [`read_frame`](crate::frame::codec::read_frame).
    //!
    //! [`write_max_data_frame`] is also the operation struct [`WriteMaxDataFrame`], with
    //! `WriteMaxDataFrameExt` on receiver accesses and `WriteMaxDataFrameHostExt` on call
    //! executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::MaxDataFrame;
    use crate::{frame::read_field, var_int::codec::ReadVarIntError};
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};

    /// Reads the fields that follow the Frame Type.
    pub(crate) async fn read_max_data_frame<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<MaxDataFrame, ReadVarIntError<F::Error>> {
        Ok(MaxDataFrame::new(read_field(io).await?))
    }

    /// Writes the frame.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_max_data_frame<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        frame: MaxDataFrame,
    ) -> Result<(), WriteAllError<F::Error>> {
        io.write_all(frame.head().as_slice()).await
    }
}

#[cfg(test)]
mod tests {
    use super::MaxDataFrame;
    use crate::{
        frame::{
            Frame,
            tests::{assert_bytes_round_trip, assert_round_trip},
        },
        var_int::{VarInt, VarIntField},
    };

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
