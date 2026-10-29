//! STREAMS_BLOCKED frames ([RFC 9000 §19.14]).
//!
//! [RFC 9000 §19.14]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.14
use super::{Head, StreamCountError, type_value, type_var_int};
use crate::{stream_id::Directionality, var_int::VarInt};

/// A STREAMS_BLOCKED frame ([RFC 9000 §19.14]): type `0x16` for
/// bidirectional streams, `0x17` for unidirectional ones.
///
/// The count is at most [`MAX_STREAM_COUNT`](super::MAX_STREAM_COUNT).
///
/// [RFC 9000 §19.14]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.14
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamsBlocked {
    /// The type of streams that could not be opened.
    pub directionality: Directionality,
    /// The stream limit at the time the frame was sent.
    pub maximum_streams: VarInt,
}

impl StreamsBlocked {
    /// The Frame Type value: one for each directionality.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(match self.directionality {
            Directionality::Bidirectional => type_value::STREAMS_BLOCKED_BIDI,
            Directionality::Unidirectional => type_value::STREAMS_BLOCKED_UNI,
        })
    }

    /// The number of bytes [`codec::write_streams_blocked`] writes.
    pub fn encoded_len(&self) -> usize {
        self.head().len()
    }

    /// Checks the count against [`MAX_STREAM_COUNT`](super::MAX_STREAM_COUNT).
    ///
    /// # Errors
    ///
    /// [`StreamCountError`] for a larger count.
    pub fn validate(&self) -> Result<(), StreamCountError> {
        StreamCountError::check(self.maximum_streams)
    }

    /// The encoded frame.
    pub(crate) fn head(&self) -> Head<9> {
        Head::new(self.type_value()).var_int(self.maximum_streams)
    }
}

pub mod codec {
    //! Writing STREAMS_BLOCKED as a `nitori_call` operation; reading is part of
    //! [`read_frame`](crate::frame::codec::read_frame).
    //!
    //! [`write_streams_blocked`] is also the operation struct [`WriteStreamsBlocked`], with
    //! `WriteStreamsBlockedExt` on receiver accesses and `WriteStreamsBlockedHostExt` on call
    //! executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::StreamsBlocked;
    use crate::{
        frame::StreamCountError,
        stream_id::Directionality,
        var_int::codec::{ReadVarIntError, ReadVarIntExt as _},
    };
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};
    use snafu::{ResultExt, Snafu};

    /// Reads the count that follows the Frame Type of a frame for streams of
    /// `directionality`.
    pub(crate) async fn read_streams_blocked<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        directionality: Directionality,
    ) -> Result<StreamsBlocked, ReadStreamsBlockedError<F::Error>> {
        let maximum_streams = io
            .read_var_int()
            .await
            .context(read_streams_blocked_error::FieldSnafu)?;
        StreamCountError::check(maximum_streams)?;
        Ok(StreamsBlocked {
            directionality,
            maximum_streams,
        })
    }

    /// Failures of reading a STREAMS_BLOCKED frame.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_streams_blocked_error), visibility(pub(crate)))]
    pub enum ReadStreamsBlockedError<E> {
        /// The count could not be read.
        #[snafu(display("STREAMS_BLOCKED field read failed"))]
        Field {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The count exceeds the limit.
        #[snafu(transparent)]
        StreamCount {
            /// The broken limit.
            source: StreamCountError,
        },
    }

    /// Writes the frame, after checking it with [`StreamsBlocked::validate`].
    ///
    /// # Errors
    ///
    /// [`WriteStreamsBlockedError::Invalid`] before writing anything, and
    /// [`WriteStreamsBlockedError::Write`] if the receiver stops accepting bytes or
    /// fails; bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_streams_blocked<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        frame: StreamsBlocked,
    ) -> Result<(), WriteStreamsBlockedError<F::Error>> {
        frame.validate()?;
        io.write_all(frame.head().as_slice())
            .await
            .context(write_streams_blocked_error::WriteSnafu)
    }

    /// Failures that [`write_streams_blocked`] can produce.
    #[derive(Debug, Snafu)]
    #[snafu(module(write_streams_blocked_error), visibility(pub(crate)))]
    pub enum WriteStreamsBlockedError<E> {
        /// The frame breaks a limit of the encoding; nothing was written.
        #[snafu(transparent)]
        Invalid {
            /// The broken limit.
            source: StreamCountError,
        },
        /// The receiver stopped accepting bytes or failed.
        #[snafu(display("STREAMS_BLOCKED write failed"))]
        Write {
            /// The failure of writing.
            source: WriteAllError<E>,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{
        StreamsBlocked,
        codec::{WriteStreamsBlockedError, WriteStreamsBlockedHostExt as _},
    };
    use crate::{
        frame::{
            Extensions, Frame, MAX_STREAM_COUNT, StreamCountError,
            codec::{ReadFrameError, ReadFrameHostExt as _},
            tests::assert_round_trip,
        },
        stream_id::Directionality,
        var_int::VarInt,
    };

    #[test]
    fn round_trips_both_directionalities() {
        for (directionality, type_value) in [
            (Directionality::Bidirectional, type_value_of(false)),
            (Directionality::Unidirectional, type_value_of(true)),
        ] {
            let frame = StreamsBlocked {
                directionality,
                maximum_streams: VarInt::try_from(MAX_STREAM_COUNT).unwrap(),
            };
            let encoding = assert_round_trip(Frame::StreamsBlocked(frame));
            assert_eq!(encoding[0], type_value);
        }
    }

    fn type_value_of(unidirectional: bool) -> u8 {
        let bidi = StreamsBlocked {
            directionality: Directionality::Bidirectional,
            maximum_streams: VarInt::ZERO,
        }
        .type_value()
        .get() as u8;
        bidi + u8::from(unidirectional)
    }

    #[test]
    fn counts_above_2_60_are_rejected() {
        let too_many = VarInt::try_from(MAX_STREAM_COUNT + 1).unwrap();
        let mut encoding = vec![type_value_of(true)];
        encoding.extend_from_slice(&((MAX_STREAM_COUNT + 1) | 0xc000_0000_0000_0000).to_be_bytes());
        let error = encoding
            .as_slice()
            .sync_read_frame_unpin(Extensions::NONE)
            .unwrap_err();
        assert_eq!(error.frame_type(), Some(VarInt::from(type_value_of(true))));
        assert!(matches!(
            error,
            ReadFrameError::StreamsBlocked { source, .. }
                if matches!(source.to_string().as_str(), "stream count 1152921504606846977 exceeds 2^60")
        ));

        let frame = StreamsBlocked {
            directionality: Directionality::Bidirectional,
            maximum_streams: too_many,
        };
        assert_eq!(
            frame.validate(),
            Err(StreamCountError {
                maximum_streams: too_many
            })
        );
        let mut written = Vec::new();
        assert!(matches!(
            written.sync_write_streams_blocked_unpin(frame),
            Err(WriteStreamsBlockedError::Invalid { .. })
        ));
        assert!(written.is_empty());
    }
}
