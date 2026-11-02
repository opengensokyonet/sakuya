//! MAX_STREAMS frames ([RFC 9000 §19.11]).
//!
//! [RFC 9000 §19.11]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.11
use super::{Head, type_value, type_var_int};
use crate::{
    stream_count::StreamCount,
    stream_id::Directionality,
    var_int::{VarInt, VarIntField},
};

/// A MAX_STREAMS frame ([RFC 9000 §19.11]): type `0x12` for
/// bidirectional streams, `0x13` for unidirectional ones.
///
/// The Maximum Streams field keeps the width of its encoding.
///
/// [RFC 9000 §19.11]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.11
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MaxStreams {
    /// The type of streams the limit applies to.
    pub directionality: Directionality,
    /// The cumulative number of streams of that type that can be opened.
    pub maximum_streams: VarIntField<StreamCount>,
}

impl MaxStreams {
    /// The Frame Type value: one for each directionality.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(match self.directionality {
            Directionality::Bidirectional => type_value::MAX_STREAMS_BIDI,
            Directionality::Unidirectional => type_value::MAX_STREAMS_UNI,
        })
    }

    /// The number of bytes [`codec::write_max_streams`] writes.
    pub fn encoded_len(&self) -> usize {
        self.head().len()
    }

    /// The encoded frame.
    pub(crate) fn head(&self) -> Head<9> {
        Head::new(self.type_value()).field(self.maximum_streams)
    }
}

pub mod codec {
    //! Writing MAX_STREAMS as a `nitori_call` operation; reading is part of
    //! [`read_frame`](crate::frame::codec::read_frame).
    //!
    //! [`write_max_streams`] is also the operation struct [`WriteMaxStreams`], with
    //! `WriteMaxStreamsExt` on receiver accesses and `WriteMaxStreamsHostExt` on call
    //! executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::MaxStreams;
    use crate::{
        stream_count::{StreamCount, StreamCountError},
        stream_id::Directionality,
        var_int::codec::{ReadVarIntError, ReadVarIntFieldError, read_var_int_field},
    };
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};
    use snafu::{IntoError, Snafu};

    /// Reads the count that follows the Frame Type of a frame for streams of
    /// `directionality`.
    pub(crate) async fn read_max_streams<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        directionality: Directionality,
    ) -> Result<MaxStreams, ReadMaxStreamsError<F::Error>> {
        let maximum_streams =
            read_var_int_field::<StreamCount, _, _>(io)
                .await
                .map_err(|error| match error {
                    ReadVarIntFieldError::VarInt { source } => {
                        read_max_streams_error::FieldSnafu.into_error(source)
                    }
                    ReadVarIntFieldError::Value { source, .. } => source.into(),
                })?;
        Ok(MaxStreams {
            directionality,
            maximum_streams,
        })
    }

    /// Failures of reading a MAX_STREAMS frame.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_max_streams_error), visibility(pub(crate)))]
    pub enum ReadMaxStreamsError<E> {
        /// The count could not be read.
        #[snafu(display("MAX_STREAMS field read failed"))]
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
    pub async fn write_max_streams<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        frame: MaxStreams,
    ) -> Result<(), WriteAllError<F::Error>> {
        io.write_all(frame.head().as_slice()).await
    }
}

#[cfg(test)]
mod tests {
    use super::{MaxStreams, codec::ReadMaxStreamsError};
    use crate::{
        frame::{
            Extensions, Frame,
            codec::{ReadFrameError, ReadFrameHostExt as _},
            tests::assert_round_trip,
        },
        stream_count::{StreamCount, StreamCountError},
        stream_id::Directionality,
        var_int::{VarInt, VarIntField},
    };

    #[test]
    fn round_trips_both_directionalities() {
        for (directionality, type_value) in [
            (Directionality::Bidirectional, type_value_of(false)),
            (Directionality::Unidirectional, type_value_of(true)),
        ] {
            let frame = MaxStreams {
                directionality,
                maximum_streams: VarIntField::shortest(StreamCount::MAX),
            };
            let encoding = assert_round_trip(Frame::MaxStreams(frame));
            assert_eq!(encoding[0], type_value);
        }
    }

    fn type_value_of(unidirectional: bool) -> u8 {
        let bidi = MaxStreams {
            directionality: Directionality::Bidirectional,
            maximum_streams: VarIntField::shortest(StreamCount::ZERO),
        }
        .type_value()
        .get() as u8;
        bidi + u8::from(unidirectional)
    }

    #[test]
    fn counts_above_2_60_are_rejected() {
        let too_many = StreamCount::MAX.get() + 1;
        let mut encoding = vec![type_value_of(true)];
        encoding.extend_from_slice(&(too_many | 0xc000_0000_0000_0000).to_be_bytes());
        let error = encoding
            .as_slice()
            .sync_read_frame_unpin(Extensions::NONE)
            .unwrap_err();
        assert_eq!(error.frame_type(), Some(VarInt::from(type_value_of(true))));
        assert!(matches!(
            error,
            ReadFrameError::MaxStreams {
                source: ReadMaxStreamsError::StreamCount {
                    source: StreamCountError { value }
                },
                ..
            } if value == too_many
        ));
        assert_eq!(
            error.transport_error_code(),
            crate::transport_error::TransportErrorCode::FRAME_ENCODING_ERROR
        );
    }
}
