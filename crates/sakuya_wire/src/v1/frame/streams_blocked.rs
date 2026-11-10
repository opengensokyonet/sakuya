//! STREAMS_BLOCKED frames ([RFC 9000 §19.14]).
//!
//! [RFC 9000 §19.14]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.14
use super::{FrameType, type_value};
use crate::frame::{Head, type_var_int};
use crate::{
    v1::stream_count::StreamCount,
    v1::stream_id::Directionality,
    var_int::{VarInt, VarIntField},
};

/// A STREAMS_BLOCKED frame ([RFC 9000 §19.14]): type `0x16` for
/// bidirectional streams, `0x17` for unidirectional ones.
///
/// The Maximum Streams field keeps the width of its encoding.
/// No limit ties the fields together, so [`StreamsBlockedFrame::new`] accepts any
/// values; the fields are read through methods of the same names.
///
/// [RFC 9000 §19.14]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.14
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamsBlockedFrame {
    directionality: Directionality,
    maximum_streams: VarIntField<StreamCount>,
}

impl StreamsBlockedFrame {
    /// The STREAMS_BLOCKED frame with these fields.
    pub const fn new(
        directionality: Directionality,
        maximum_streams: VarIntField<StreamCount>,
    ) -> Self {
        Self {
            directionality,
            maximum_streams,
        }
    }

    /// The type of streams that could not be opened.
    pub const fn directionality(&self) -> Directionality {
        self.directionality
    }

    /// The stream limit at the time the frame was sent.
    pub const fn maximum_streams(&self) -> VarIntField<StreamCount> {
        self.maximum_streams
    }

    /// The kind of the frame, [`FrameType::StreamsBlocked`].
    pub const fn frame_type(&self) -> FrameType {
        FrameType::StreamsBlocked
    }

    /// The Frame Type value: one for each directionality.
    pub const fn type_value(&self) -> VarInt {
        type_value_of(self.directionality)
    }

    /// The number of bytes [`codec::write_streams_blocked_frame`] writes.
    pub fn encoded_len(&self) -> usize {
        self.head().len()
    }

    /// The encoded frame.
    pub(in crate::v1) fn head(&self) -> Head<9> {
        Head::new(self.type_value()).field(self.maximum_streams)
    }
}

/// The Frame Type value of a STREAMS_BLOCKED frame for streams of `directionality`.
pub(in crate::v1) const fn type_value_of(directionality: Directionality) -> VarInt {
    type_var_int(match directionality {
        Directionality::Bidirectional => type_value::STREAMS_BLOCKED_BIDI,
        Directionality::Unidirectional => type_value::STREAMS_BLOCKED_UNI,
    })
}

pub mod codec {
    //! Writing STREAMS_BLOCKED as a `nitori_call` operation; reading is done by
    //! [`Frames`](crate::v1::frame::set::Frames).
    //!
    //! [`write_streams_blocked_frame`] is also the operation struct [`WriteStreamsBlockedFrame`], with
    //! `WriteStreamsBlockedFrameExt` on receiver accesses and `WriteStreamsBlockedFrameHostExt` on call
    //! executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::StreamsBlockedFrame;
    use crate::{
        v1::stream_count::{StreamCount, StreamCountError},
        v1::stream_id::Directionality,
        var_int::codec::{ReadVarIntError, ReadVarIntFieldError, read_var_int_field},
    };
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};
    use snafu::{IntoError, Snafu};

    /// Reads the count that follows the Frame Type of a frame for streams of
    /// `directionality`.
    pub(in crate::v1) async fn read_streams_blocked_frame<
        F: Read,
        A: ReceiverAccess<Family = F>,
    >(
        io: &mut A,
        directionality: Directionality,
    ) -> Result<StreamsBlockedFrame, ReadStreamsBlockedFrameError<F::Error>> {
        let maximum_streams =
            read_var_int_field::<StreamCount, _, _>(io)
                .await
                .map_err(|error| match error {
                    ReadVarIntFieldError::VarInt { source } => {
                        read_streams_blocked_error::FieldSnafu.into_error(source)
                    }
                    ReadVarIntFieldError::Value { source, .. } => source.into(),
                })?;
        Ok(StreamsBlockedFrame::new(directionality, maximum_streams))
    }

    /// Failures of reading a STREAMS_BLOCKED frame.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_streams_blocked_error), visibility(pub(in crate::v1)))]
    pub enum ReadStreamsBlockedFrameError<E> {
        /// The count could not be read.
        #[snafu(display("STREAMS_BLOCKED field read failed"))]
        Field {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The count exceeds 2<sup>60</sup>.
        #[snafu(transparent)]
        StreamCount {
            /// The broken limit.
            source: StreamCountError,
        },
    }

    /// Writes the frame.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_streams_blocked_frame<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        frame: StreamsBlockedFrame,
    ) -> Result<(), WriteAllError<F::Error>> {
        io.write_all(frame.head().as_slice()).await
    }
}

#[cfg(test)]
mod tests {
    use super::{StreamsBlockedFrame, codec::ReadStreamsBlockedFrameError};
    use crate::parts::{Coproduct, PartsError};
    use crate::v1::frame::codec::ReadFieldsError;
    use crate::v1::frame::set::codec::ReadFrameError;
    use crate::v1::frame::tests::ReadOneFrame as _;
    use crate::{
        v1::frame::{
            Frame,
            tests::{assert_bytes_round_trip, assert_round_trip},
        },
        v1::stream_count::StreamCount,
        v1::stream_id::Directionality,
        var_int::{VarInt, VarIntField},
    };

    #[test]
    fn round_trips_both_directionalities() {
        for (directionality, type_value) in [
            (Directionality::Bidirectional, type_value_of(false)),
            (Directionality::Unidirectional, type_value_of(true)),
        ] {
            let maximum_streams = VarIntField::shortest(StreamCount::MAX);
            let frame = StreamsBlockedFrame::new(directionality, maximum_streams);
            let encoding = assert_round_trip(Frame::StreamsBlocked(frame));
            assert_eq!(encoding[0], type_value);
            let Frame::StreamsBlocked(read) = assert_bytes_round_trip(&encoding) else {
                panic!("{encoding:02x?}")
            };
            assert_eq!(read.directionality(), directionality);
            assert_eq!(read.maximum_streams(), maximum_streams);
        }
    }

    fn type_value_of(unidirectional: bool) -> u8 {
        let bidi = StreamsBlockedFrame::new(
            Directionality::Bidirectional,
            VarIntField::shortest(StreamCount::ZERO),
        )
        .type_value()
        .get() as u8;
        bidi + u8::from(unidirectional)
    }

    #[test]
    fn counts_above_2_60_are_rejected() {
        let too_many = StreamCount::MAX.get() + 1;
        let mut encoding = vec![type_value_of(true)];
        encoding.extend_from_slice(&(too_many | 0xc000_0000_0000_0000).to_be_bytes());
        let error = encoding.as_slice().read_one_frame().unwrap_err();
        assert_eq!(error.frame_type(), Some(VarInt::from(type_value_of(true))));
        assert!(matches!(
            error,
            ReadFrameError::Fields { source: PartsError(Coproduct::Inl(ReadFieldsError::StreamsBlocked {
                source: ReadStreamsBlockedFrameError::StreamCount {
                    source
                },
                ..
            })) } if source == StreamCount::new(too_many).unwrap_err()
        ));
        assert_eq!(
            error.transport_error_code(),
            crate::v1::transport_error::TransportErrorCode::FRAME_ENCODING_ERROR
        );
    }
}
