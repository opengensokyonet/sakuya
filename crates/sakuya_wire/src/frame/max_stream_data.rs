//! MAX_STREAM_DATA frames ([RFC 9000 §19.10]).
//!
//! [RFC 9000 §19.10]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.10
use super::{Head, type_value, type_var_int};
use crate::stream_id::StreamId;
use crate::var_int::{VarInt, VarIntField};

/// A MAX_STREAM_DATA frame ([RFC 9000 §19.10]).
///
/// Each field keeps the width of its variable-length integer encoding.
///
/// [RFC 9000 §19.10]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.10
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MaxStreamData {
    /// The stream the limit applies to.
    pub stream_id: VarIntField<StreamId>,
    /// The maximum amount of data that can be sent on the stream, in bytes.
    pub maximum_stream_data: VarIntField<VarInt>,
}

impl MaxStreamData {
    /// The Frame Type value.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(type_value::MAX_STREAM_DATA)
    }

    /// The number of bytes [`codec::write_max_stream_data`] writes.
    pub fn encoded_len(&self) -> usize {
        self.head().len()
    }

    /// The encoded frame.
    pub(crate) fn head(&self) -> Head<17> {
        Head::new(self.type_value())
            .field(self.stream_id)
            .field(self.maximum_stream_data)
    }
}

pub mod codec {
    //! Writing MAX_STREAM_DATA as a `nitori_call` operation; reading is part of
    //! [`read_frame`](crate::frame::codec::read_frame).
    //!
    //! [`write_max_stream_data`] is also the operation struct [`WriteMaxStreamData`], with
    //! `WriteMaxStreamDataExt` on receiver accesses and `WriteMaxStreamDataHostExt` on call
    //! executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::MaxStreamData;
    use crate::{frame::read_field, var_int::codec::ReadVarIntError};
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};

    /// Reads the fields that follow the Frame Type.
    pub(crate) async fn read_max_stream_data<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<MaxStreamData, ReadVarIntError<F::Error>> {
        Ok(MaxStreamData {
            stream_id: read_field(io).await?,
            maximum_stream_data: read_field(io).await?,
        })
    }

    /// Writes the frame.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_max_stream_data<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        frame: MaxStreamData,
    ) -> Result<(), WriteAllError<F::Error>> {
        io.write_all(frame.head().as_slice()).await
    }
}

#[cfg(test)]
mod tests {
    use super::MaxStreamData;
    use crate::stream_id::StreamId;
    use crate::{
        frame::{Frame, tests::assert_round_trip},
        var_int::{VarInt, VarIntField},
    };

    #[test]
    fn round_trips() {
        let frame = MaxStreamData {
            stream_id: VarIntField::shortest(StreamId::from_var_int(VarInt::from(8u8))),
            maximum_stream_data: VarIntField::shortest(VarInt::from(63u8)),
        };
        assert_eq!(
            assert_round_trip(Frame::MaxStreamData(frame)),
            [0x11, 0x08, 0x3f]
        );
    }
}
