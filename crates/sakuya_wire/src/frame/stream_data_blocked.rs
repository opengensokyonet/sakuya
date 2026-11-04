//! STREAM_DATA_BLOCKED frames ([RFC 9000 §19.13]).
//!
//! [RFC 9000 §19.13]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.13
use super::{Head, type_value, type_var_int};
use crate::stream_id::StreamId;
use crate::var_int::{VarInt, VarIntField};

/// A STREAM_DATA_BLOCKED frame ([RFC 9000 §19.13]).
///
/// Each field keeps the width of its variable-length integer encoding.
/// No limit ties the fields together, so [`StreamDataBlockedFrame::new`] accepts any
/// values; the fields are read through methods of the same names.
///
/// [RFC 9000 §19.13]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.13
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamDataBlockedFrame {
    stream_id: VarIntField<StreamId>,
    maximum_stream_data: VarIntField<VarInt>,
}

impl StreamDataBlockedFrame {
    /// The STREAM_DATA_BLOCKED frame with these fields.
    pub const fn new(
        stream_id: VarIntField<StreamId>,
        maximum_stream_data: VarIntField<VarInt>,
    ) -> Self {
        Self {
            stream_id,
            maximum_stream_data,
        }
    }

    /// The blocked stream.
    pub const fn stream_id(&self) -> VarIntField<StreamId> {
        self.stream_id
    }

    /// The offset of the stream at which blocking occurred.
    pub const fn maximum_stream_data(&self) -> VarIntField<VarInt> {
        self.maximum_stream_data
    }

    /// The Frame Type value.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(type_value::STREAM_DATA_BLOCKED)
    }

    /// The number of bytes [`codec::write_stream_data_blocked_frame`] writes.
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
    //! Writing STREAM_DATA_BLOCKED as a `nitori_call` operation; reading is part of
    //! [`read_frame`](crate::frame::codec::read_frame).
    //!
    //! [`write_stream_data_blocked_frame`] is also the operation struct [`WriteStreamDataBlockedFrame`], with
    //! `WriteStreamDataBlockedFrameExt` on receiver accesses and `WriteStreamDataBlockedFrameHostExt` on call
    //! executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::StreamDataBlockedFrame;
    use crate::{frame::read_field, var_int::codec::ReadVarIntError};
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};
    use snafu::{ResultExt, Snafu};

    /// Reads the fields that follow the Frame Type.
    pub(crate) async fn read_stream_data_blocked_frame<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<StreamDataBlockedFrame, ReadStreamDataBlockedFrameError<F::Error>> {
        use read_stream_data_blocked_error::*;
        let stream_id = read_field(io).await.context(StreamIdSnafu)?;
        let maximum_stream_data = read_field(io).await.context(MaximumStreamDataSnafu)?;
        Ok(StreamDataBlockedFrame::new(stream_id, maximum_stream_data))
    }

    /// Failures of reading a STREAM_DATA_BLOCKED frame.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_stream_data_blocked_error), visibility(pub(crate)))]
    pub enum ReadStreamDataBlockedFrameError<E> {
        /// The Stream ID field could not be read.
        #[snafu(display("STREAM_DATA_BLOCKED Stream ID read failed"))]
        StreamId {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The Maximum Stream Data field could not be read.
        #[snafu(display("STREAM_DATA_BLOCKED Maximum Stream Data read failed"))]
        MaximumStreamData {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
    }

    /// Writes the frame.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_stream_data_blocked_frame<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        frame: StreamDataBlockedFrame,
    ) -> Result<(), WriteAllError<F::Error>> {
        io.write_all(frame.head().as_slice()).await
    }
}

#[cfg(test)]
mod tests {
    use super::StreamDataBlockedFrame;
    use crate::stream_id::StreamId;
    use crate::{
        frame::{
            Frame,
            tests::{assert_bytes_round_trip, assert_round_trip},
        },
        var_int::{VarInt, VarIntField},
    };

    #[test]
    fn round_trips() {
        let stream_id = VarIntField::shortest(StreamId::from_var_int(VarInt::from(2u8)));
        let maximum_stream_data = VarIntField::shortest(VarInt::from(63u8));
        let frame = StreamDataBlockedFrame::new(stream_id, maximum_stream_data);
        let encoding = assert_round_trip(Frame::StreamDataBlocked(frame));
        assert_eq!(encoding, [0x15, 0x02, 0x3f]);
        let Frame::StreamDataBlocked(read) = assert_bytes_round_trip(&encoding) else {
            panic!("{encoding:02x?}")
        };
        assert_eq!(read.stream_id(), stream_id);
        assert_eq!(read.maximum_stream_data(), maximum_stream_data);
    }
}
