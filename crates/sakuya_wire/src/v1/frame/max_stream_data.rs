//! MAX_STREAM_DATA frames ([RFC 9000 §19.10]).
//!
//! [RFC 9000 §19.10]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.10
use super::{FrameType, type_value};
use crate::frame::{Head, type_var_int};
use crate::v1::stream_id::StreamId;
use crate::var_int::{VarInt, VarIntField};

/// A MAX_STREAM_DATA frame ([RFC 9000 §19.10]).
///
/// Each field keeps the width of its variable-length integer encoding.
/// No limit ties the fields together, so [`MaxStreamDataFrame::new`] accepts any
/// values; the fields are read through methods of the same names.
///
/// [RFC 9000 §19.10]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.10
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MaxStreamDataFrame {
    stream_id: VarIntField<StreamId>,
    maximum_stream_data: VarIntField<VarInt>,
}

impl MaxStreamDataFrame {
    /// The MAX_STREAM_DATA frame with these fields.
    pub const fn new(
        stream_id: VarIntField<StreamId>,
        maximum_stream_data: VarIntField<VarInt>,
    ) -> Self {
        Self {
            stream_id,
            maximum_stream_data,
        }
    }

    /// The stream the limit applies to.
    pub const fn stream_id(&self) -> VarIntField<StreamId> {
        self.stream_id
    }

    /// The maximum amount of data that can be sent on the stream, in bytes.
    pub const fn maximum_stream_data(&self) -> VarIntField<VarInt> {
        self.maximum_stream_data
    }

    /// The kind of the frame, [`FrameType::MaxStreamData`].
    pub const fn frame_type(&self) -> FrameType {
        FrameType::MaxStreamData
    }

    /// The Frame Type value.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(type_value::MAX_STREAM_DATA)
    }

    /// The number of bytes [`codec::write_max_stream_data_frame`] writes.
    pub fn encoded_len(&self) -> usize {
        self.head().len()
    }

    /// The encoded frame.
    pub(in crate::v1) fn head(&self) -> Head<17> {
        Head::new(self.type_value())
            .field(self.stream_id)
            .field(self.maximum_stream_data)
    }
}

pub mod codec {
    //! Writing MAX_STREAM_DATA as a `nitori_call` operation; reading is part of
    //! [`read_frame`](crate::frame::codec::read_frame).
    //!
    //! [`write_max_stream_data_frame`] is also the operation struct [`WriteMaxStreamDataFrame`], with
    //! `WriteMaxStreamDataFrameExt` on receiver accesses and `WriteMaxStreamDataFrameHostExt` on call
    //! executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::MaxStreamDataFrame;
    use crate::{frame::read_field, var_int::codec::ReadVarIntError};
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};
    use snafu::{ResultExt, Snafu};

    /// Reads the fields that follow the Frame Type.
    pub(in crate::v1) async fn read_max_stream_data_frame<
        F: Read,
        A: ReceiverAccess<Family = F>,
    >(
        io: &mut A,
    ) -> Result<MaxStreamDataFrame, ReadMaxStreamDataFrameError<F::Error>> {
        use read_max_stream_data_error::*;
        let stream_id = read_field(io).await.context(StreamIdSnafu)?;
        let maximum_stream_data = read_field(io).await.context(MaximumStreamDataSnafu)?;
        Ok(MaxStreamDataFrame::new(stream_id, maximum_stream_data))
    }

    /// Failures of reading a MAX_STREAM_DATA frame.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_max_stream_data_error), visibility(pub(in crate::v1)))]
    pub enum ReadMaxStreamDataFrameError<E> {
        /// The Stream ID field could not be read.
        #[snafu(display("MAX_STREAM_DATA Stream ID read failed"))]
        StreamId {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The Maximum Stream Data field could not be read.
        #[snafu(display("MAX_STREAM_DATA Maximum Stream Data read failed"))]
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
    pub async fn write_max_stream_data_frame<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        frame: MaxStreamDataFrame,
    ) -> Result<(), WriteAllError<F::Error>> {
        io.write_all(frame.head().as_slice()).await
    }
}

#[cfg(test)]
mod tests {
    use super::MaxStreamDataFrame;
    use crate::v1::stream_id::StreamId;
    use crate::{
        v1::frame::{
            Frame,
            tests::{assert_bytes_round_trip, assert_round_trip},
        },
        var_int::{VarInt, VarIntField},
    };

    #[test]
    fn round_trips() {
        let stream_id = VarIntField::shortest(StreamId::from_var_int(VarInt::from(8u8)));
        let maximum_stream_data = VarIntField::shortest(VarInt::from(63u8));
        let frame = MaxStreamDataFrame::new(stream_id, maximum_stream_data);
        let encoding = assert_round_trip(Frame::MaxStreamData(frame));
        assert_eq!(encoding, [0x11, 0x08, 0x3f]);
        let Frame::MaxStreamData(read) = assert_bytes_round_trip(&encoding) else {
            panic!("{encoding:02x?}")
        };
        assert_eq!(read.stream_id(), stream_id);
        assert_eq!(read.maximum_stream_data(), maximum_stream_data);
    }
}
