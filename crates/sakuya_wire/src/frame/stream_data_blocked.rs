//! STREAM_DATA_BLOCKED frames ([RFC 9000 §19.13]).
//!
//! [RFC 9000 §19.13]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.13
use super::{Head, type_value, type_var_int};
use crate::stream_id::StreamId;
use crate::var_int::VarInt;

/// A STREAM_DATA_BLOCKED frame ([RFC 9000 §19.13]).
///
/// [RFC 9000 §19.13]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.13
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamDataBlocked {
    /// The blocked stream.
    pub stream_id: StreamId,
    /// The offset of the stream at which blocking occurred.
    pub maximum_stream_data: VarInt,
}

impl StreamDataBlocked {
    /// The Frame Type value.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(type_value::STREAM_DATA_BLOCKED)
    }

    /// The number of bytes [`codec::write_stream_data_blocked`] writes.
    pub fn encoded_len(&self) -> usize {
        self.head().len()
    }

    /// The encoded frame.
    pub(crate) fn head(&self) -> Head<17> {
        Head::new(self.type_value())
            .var_int(VarInt::from(self.stream_id))
            .var_int(self.maximum_stream_data)
    }
}

pub mod codec {
    //! Writing STREAM_DATA_BLOCKED as a `nitori_call` operation; reading is part of
    //! [`read_frame`](crate::frame::codec::read_frame).
    //!
    //! [`write_stream_data_blocked`] is also the operation struct [`WriteStreamDataBlocked`], with
    //! `WriteStreamDataBlockedExt` on receiver accesses and `WriteStreamDataBlockedHostExt` on call
    //! executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::StreamDataBlocked;
    use super::StreamId;
    use crate::var_int::codec::{ReadVarIntError, ReadVarIntExt as _};
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};

    /// Reads the fields that follow the Frame Type.
    pub(crate) async fn read_stream_data_blocked<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<StreamDataBlocked, ReadVarIntError<F::Error>> {
        Ok(StreamDataBlocked {
            stream_id: StreamId::from_var_int(io.read_var_int().await?),
            maximum_stream_data: io.read_var_int().await?,
        })
    }

    /// Writes the frame.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_stream_data_blocked<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        frame: StreamDataBlocked,
    ) -> Result<(), WriteAllError<F::Error>> {
        io.write_all(frame.head().as_slice()).await
    }
}

#[cfg(test)]
mod tests {
    use super::StreamDataBlocked;
    use crate::stream_id::StreamId;
    use crate::{
        frame::{Frame, tests::assert_round_trip},
        var_int::VarInt,
    };

    #[test]
    fn round_trips() {
        let frame = StreamDataBlocked {
            stream_id: StreamId::from_var_int(VarInt::from(2u8)),
            maximum_stream_data: VarInt::from(63u8),
        };
        assert_eq!(
            assert_round_trip(Frame::StreamDataBlocked(frame)),
            [0x15, 0x02, 0x3f]
        );
    }
}
