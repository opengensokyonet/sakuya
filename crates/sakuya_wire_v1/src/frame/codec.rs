//! Reading the fields of version 1 frames and writing frames of any version 1
//! type.
//!
//! [`read_fields`] reads one version 1 frame of any type from its fields on,
//! once its Frame Type has been read
//! ([`read_frame_type`](super::set::codec::read_frame_type));
//! [`ReadFieldsError`] holds the failure of each frame type.
//! [`v1::Part`](crate::Part) reads with it when
//! [`Frames`](super::set::Frames) reads a frame set that has the part.
//! [`write_frame`] writes any version 1 [`Frame`] and [`write_frame_run`]
//! any [`FrameRun`]; the modules of the frame types also have write
//! functions of their own, such as
//! [`write_stream_frame`](super::stream::codec::write_stream_frame).
//!
//! ```
//! use core::marker::PhantomData;
//! use sakuya_wire::{
//!     parts::HList,
//!     var_int::{VarInt, VarIntField, VarIntWidth},
//! };
//! use sakuya_wire_v1::{
//!     frame::{
//!         Frame,
//!         FrameRun,
//!         codec::{write_frame, write_frame_run},
//!         max_data::MaxDataFrame,
//!         padding::PaddingRun,
//!         set::Frames,
//!         stream::StreamFrame,
//!     },
//!     stream_id::StreamId,
//! };
//! use sakuya_wire_v1 as v1;
//!
//! let set = PhantomData::<HList![v1::Part]>;
//! let mut output = Vec::new();
//! let maximum_data = VarIntField::shortest(VarInt::from(1_000_000u32));
//! let max_data = Frame::<&[u8]>::MaxData(MaxDataFrame::new(maximum_data));
//! write_frame(&mut output, max_data.clone());
//! let stream_id = VarIntField::shortest(StreamId::from_var_int(VarInt::from(4u8)));
//! // A STREAM frame with a Length field. Reading gives `StreamFrame<D>`, which
//! // states its Length field as `Either`; `into` converts to it.
//! let stream = StreamFrame::with_length(stream_id, None, VarIntWidth::One, &b"hello"[..], true);
//! let stream = Frame::Stream(stream.unwrap().into());
//! write_frame(&mut output, stream.clone());
//!
//! // A STREAM frame checks its fields when it is constructed, so writing it
//! // checks nothing: a one-byte Length field cannot state 64 bytes of data.
//! let data = [0; 64];
//! let long = StreamFrame::with_length(stream_id, None, VarIntWidth::One, &data[..], true);
//! assert!(long.is_err());
//!
//! // Reading a byte slice yields subslices of it as payload fields.
//! let mut frames = Frames::new(output.as_slice(), set);
//! assert_eq!(frames.next().unwrap().unwrap().extract(), FrameRun::from(max_data));
//! assert_eq!(frames.next().unwrap().unwrap().extract(), FrameRun::from(stream));
//! assert!(frames.next().is_none());
//!
//! // A longer encoding of a field is kept, and written back as it was.
//! let input = [0x10, 0x80, 0x00, 0x00, 0x05];
//! let run = Frames::new(&input[..], set).next().unwrap().unwrap().extract();
//! let FrameRun::MaxData(max_data) = &run else { panic!() };
//! assert_eq!(max_data.maximum_data().width(), VarIntWidth::Four);
//! let mut output = Vec::new();
//! write_frame_run(&mut output, run);
//! assert_eq!(output, input);
//!
//! // A run of PADDING frames is written as a zero byte for each.
//! let padding = FrameRun::<&[u8]>::Padding(PaddingRun::new(3.try_into().unwrap()));
//! let mut output = Vec::new();
//! write_frame_run(&mut output, padding);
//! assert_eq!(output, [0, 0, 0]);
//! ```

use super::{
    Frame, FrameRun, FrameType, FrameTypeValue,
    ack::codec::{ReadAckFrameEcnError, ReadAckFrameError, read_ack_frame, read_ack_frame_ecn},
    connection_close::codec::{
        ReadConnectionCloseFrameApplicationError, ReadConnectionCloseFrameTransportError,
        read_connection_close_frame_application, read_connection_close_frame_transport,
    },
    crypto::codec::{ReadCryptoFrameError, read_crypto_frame},
    data_blocked::codec::read_data_blocked_frame,
    handshake_done::HandshakeDoneFrame,
    max_data::codec::read_max_data_frame,
    max_stream_data::codec::{ReadMaxStreamDataFrameError, read_max_stream_data_frame},
    max_streams::codec::{ReadMaxStreamsFrameError, read_max_streams_frame},
    new_connection_id::codec::{ReadNewConnectionIdFrameError, read_new_connection_id_frame},
    new_token::codec::{ReadNewTokenFrameError, read_new_token_frame},
    padding::PaddingFrame,
    path_challenge::codec::read_path_challenge_frame,
    path_response::codec::read_path_response_frame,
    ping::PingFrame,
    reset_stream::codec::{ReadResetStreamFrameError, read_reset_stream_frame},
    retire_connection_id::codec::read_retire_connection_id_frame,
    set::FrameFieldsError,
    stop_sending::codec::{ReadStopSendingFrameError, read_stop_sending_frame},
    stream::{
        StreamTypeValue,
        codec::{ReadStreamFrameError, read_stream_frame},
    },
    stream_data_blocked::codec::{ReadStreamDataBlockedFrameError, read_stream_data_blocked_frame},
    streams_blocked::codec::{ReadStreamsBlockedFrameError, read_streams_blocked_frame},
    type_value,
};
use crate::{stream_id::Directionality, transport_error::TransportErrorCode};
use bytes::{Buf, BufMut};
use nitori_io::{SplitTo, error::IncompleteError};
use sakuya_wire::{frame::type_var_int, var_int::VarInt};
use snafu::{ResultExt, Snafu};

/// Reads one version 1 frame from the fields that follow its Frame Type
/// `frame_type`.
///
/// The Frame Type has been read from the source already, with
/// [`read_frame_type`](super::set::codec::read_frame_type) for a frame set
/// that has [`v1::Part`](crate::Part); [`FrameTypeValue::of`] gives
/// `frame_type` for the value that was read.
///
/// The source is the rest of a packet payload: a STREAM frame without a
/// Length field takes all of it. Payload fields are pieces of the source,
/// cut off with [`SplitTo`]. A
/// PADDING frame has no fields: it is one byte, its Frame Type, and the
/// PADDING frames that follow it stay unread, where
/// [`Frames`](super::set::Frames) gives them as one run.
///
/// # Errors
///
/// The variant of [`ReadFieldsError`] named after the frame type if its
/// fields cannot be read or break a limit of the encoding. Bytes read before
/// a failure stay consumed.
pub fn read_fields<S: Buf + SplitTo>(
    src: &mut S,
    frame_type: FrameTypeValue,
) -> Result<Frame<S>, ReadFieldsError> {
    use read_fields_error::*;
    use type_value::*;
    let kind = frame_type.kind();
    let frame_type = frame_type.get();
    let value = frame_type.get();
    Ok(match kind {
        FrameType::Padding => Frame::Padding(PaddingFrame),
        FrameType::Ping => Frame::Ping(PingFrame),
        FrameType::Ack if value == u64::from(ACK_ECN) => {
            Frame::Ack(read_ack_frame_ecn(src).context(AckEcnSnafu)?)
        }
        FrameType::Ack => Frame::Ack(read_ack_frame(src).context(AckSnafu)?),
        FrameType::ResetStream => {
            Frame::ResetStream(read_reset_stream_frame(src).context(ResetStreamSnafu)?)
        }
        FrameType::StopSending => {
            Frame::StopSending(read_stop_sending_frame(src).context(StopSendingSnafu)?)
        }
        FrameType::Crypto => Frame::Crypto(read_crypto_frame(src).context(CryptoSnafu)?),
        FrameType::NewToken => Frame::NewToken(read_new_token_frame(src).context(NewTokenSnafu)?),
        FrameType::Stream => {
            let frame_type = StreamTypeValue::new(frame_type);
            // invariant: a `FrameTypeValue` has the kind `FrameType::of` gives
            // for its value, which is `Stream` for exactly the STREAM Frame
            // Type values.
            let frame_type = frame_type.unwrap_or_else(|| unreachable!("STREAM {value:#x}"));
            Frame::Stream(read_stream_frame(src, frame_type).context(StreamSnafu { frame_type })?)
        }
        FrameType::MaxData => Frame::MaxData(read_max_data_frame(src).context(MaxDataSnafu)?),
        FrameType::MaxStreamData => {
            Frame::MaxStreamData(read_max_stream_data_frame(src).context(MaxStreamDataSnafu)?)
        }
        FrameType::MaxStreams => {
            let directionality = directionality(value == u64::from(MAX_STREAMS_UNI));
            Frame::MaxStreams(
                read_max_streams_frame(src, directionality)
                    .context(MaxStreamsSnafu { directionality })?,
            )
        }
        FrameType::DataBlocked => {
            Frame::DataBlocked(read_data_blocked_frame(src).context(DataBlockedSnafu)?)
        }
        FrameType::StreamDataBlocked => Frame::StreamDataBlocked(
            read_stream_data_blocked_frame(src).context(StreamDataBlockedSnafu)?,
        ),
        FrameType::StreamsBlocked => {
            let directionality = directionality(value == u64::from(STREAMS_BLOCKED_UNI));
            Frame::StreamsBlocked(
                read_streams_blocked_frame(src, directionality)
                    .context(StreamsBlockedSnafu { directionality })?,
            )
        }
        FrameType::NewConnectionId => {
            Frame::NewConnectionId(read_new_connection_id_frame(src).context(NewConnectionIdSnafu)?)
        }
        FrameType::RetireConnectionId => Frame::RetireConnectionId(
            read_retire_connection_id_frame(src).context(RetireConnectionIdSnafu)?,
        ),
        FrameType::PathChallenge => {
            Frame::PathChallenge(read_path_challenge_frame(src).context(PathChallengeSnafu)?)
        }
        FrameType::PathResponse => {
            Frame::PathResponse(read_path_response_frame(src).context(PathResponseSnafu)?)
        }
        FrameType::ConnectionCloseApplication => Frame::ConnectionClose(
            read_connection_close_frame_application(src)
                .context(ConnectionCloseApplicationSnafu)?,
        ),
        FrameType::ConnectionCloseTransport => Frame::ConnectionClose(
            read_connection_close_frame_transport(src).context(ConnectionCloseTransportSnafu)?,
        ),
        FrameType::HandshakeDone => Frame::HandshakeDone(HandshakeDoneFrame),
    })
}

fn directionality(unidirectional: bool) -> Directionality {
    if unidirectional {
        Directionality::Unidirectional
    } else {
        Directionality::Bidirectional
    }
}

/// Failures of reading the fields of a version 1 frame after its Frame Type.
///
/// Each variant is named after a frame type and holds the failure of reading
/// the fields of that type. ACK and CONNECTION_CLOSE have a variant for each
/// of their two Frame Type values, since the two have different fields;
/// MAX_STREAMS and STREAMS_BLOCKED say which of their two values was read,
/// and STREAM holds the Frame Type value. Every failure corresponds to
/// FRAME_ENCODING_ERROR ([RFC 9000 §12.4]).
///
/// [RFC 9000 §12.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4
#[derive(Debug, Snafu)]
#[snafu(module(read_fields_error), visibility(pub(crate)))]
pub enum ReadFieldsError {
    /// An ACK frame of type `0x02`, without ECN counts, could not be read.
    #[snafu(display("ACK frame read failed"))]
    Ack {
        /// The failure.
        source: ReadAckFrameError,
    },
    /// An ACK frame of type `0x03`, with ECN counts, could not be read.
    #[snafu(display("ACK frame with ECN counts read failed"))]
    AckEcn {
        /// The failure.
        source: ReadAckFrameEcnError,
    },
    /// A RESET_STREAM frame could not be read.
    #[snafu(display("RESET_STREAM frame read failed"))]
    ResetStream {
        /// The failure.
        source: ReadResetStreamFrameError,
    },
    /// A STOP_SENDING frame could not be read.
    #[snafu(display("STOP_SENDING frame read failed"))]
    StopSending {
        /// The failure.
        source: ReadStopSendingFrameError,
    },
    /// A CRYPTO frame could not be read.
    #[snafu(display("CRYPTO frame read failed"))]
    Crypto {
        /// The failure.
        source: ReadCryptoFrameError,
    },
    /// A NEW_TOKEN frame could not be read.
    #[snafu(display("NEW_TOKEN frame read failed"))]
    NewToken {
        /// The failure.
        source: ReadNewTokenFrameError,
    },
    /// A STREAM frame could not be read.
    #[snafu(display("STREAM frame read failed"))]
    Stream {
        /// The Frame Type.
        frame_type: StreamTypeValue,
        /// The failure.
        source: ReadStreamFrameError,
    },
    /// A MAX_DATA frame could not be read.
    #[snafu(display("MAX_DATA frame read failed"))]
    MaxData {
        /// The failure.
        source: IncompleteError,
    },
    /// A MAX_STREAM_DATA frame could not be read.
    #[snafu(display("MAX_STREAM_DATA frame read failed"))]
    MaxStreamData {
        /// The failure.
        source: ReadMaxStreamDataFrameError,
    },
    /// A MAX_STREAMS frame could not be read.
    #[snafu(display("MAX_STREAMS frame read failed"))]
    MaxStreams {
        /// The type of streams of the Frame Type: `0x12` for bidirectional,
        /// `0x13` for unidirectional streams.
        directionality: Directionality,
        /// The failure.
        source: ReadMaxStreamsFrameError,
    },
    /// A DATA_BLOCKED frame could not be read.
    #[snafu(display("DATA_BLOCKED frame read failed"))]
    DataBlocked {
        /// The failure.
        source: IncompleteError,
    },
    /// A STREAM_DATA_BLOCKED frame could not be read.
    #[snafu(display("STREAM_DATA_BLOCKED frame read failed"))]
    StreamDataBlocked {
        /// The failure.
        source: ReadStreamDataBlockedFrameError,
    },
    /// A STREAMS_BLOCKED frame could not be read.
    #[snafu(display("STREAMS_BLOCKED frame read failed"))]
    StreamsBlocked {
        /// The type of streams of the Frame Type: `0x16` for bidirectional,
        /// `0x17` for unidirectional streams.
        directionality: Directionality,
        /// The failure.
        source: ReadStreamsBlockedFrameError,
    },
    /// A NEW_CONNECTION_ID frame could not be read.
    #[snafu(display("NEW_CONNECTION_ID frame read failed"))]
    NewConnectionId {
        /// The failure.
        source: ReadNewConnectionIdFrameError,
    },
    /// A RETIRE_CONNECTION_ID frame could not be read.
    #[snafu(display("RETIRE_CONNECTION_ID frame read failed"))]
    RetireConnectionId {
        /// The failure.
        source: IncompleteError,
    },
    /// A PATH_CHALLENGE frame could not be read.
    #[snafu(display("PATH_CHALLENGE frame read failed"))]
    PathChallenge {
        /// The failure.
        source: IncompleteError,
    },
    /// A PATH_RESPONSE frame could not be read.
    #[snafu(display("PATH_RESPONSE frame read failed"))]
    PathResponse {
        /// The failure.
        source: IncompleteError,
    },
    /// A CONNECTION_CLOSE frame of type `0x1c`, for a transport error,
    /// could not be read.
    #[snafu(display("CONNECTION_CLOSE frame read failed"))]
    ConnectionCloseTransport {
        /// The failure.
        source: ReadConnectionCloseFrameTransportError,
    },
    /// A CONNECTION_CLOSE frame of type `0x1d`, for an application error,
    /// could not be read.
    #[snafu(display("application CONNECTION_CLOSE frame read failed"))]
    ConnectionCloseApplication {
        /// The failure.
        source: ReadConnectionCloseFrameApplicationError,
    },
}

impl FrameFieldsError for ReadFieldsError {
    fn frame_type(&self) -> VarInt {
        use super::{max_streams, streams_blocked};
        use type_value::*;
        match *self {
            Self::Stream { frame_type, .. } => frame_type.get(),
            Self::Ack { .. } => type_var_int(ACK),
            Self::AckEcn { .. } => type_var_int(ACK_ECN),
            Self::MaxStreams { directionality, .. } => max_streams::type_value_of(directionality),
            Self::StreamsBlocked { directionality, .. } => {
                streams_blocked::type_value_of(directionality)
            }
            Self::ConnectionCloseTransport { .. } => type_var_int(CONNECTION_CLOSE),
            Self::ConnectionCloseApplication { .. } => type_var_int(CONNECTION_CLOSE_APPLICATION),
            Self::ResetStream { .. } => type_var_int(RESET_STREAM),
            Self::StopSending { .. } => type_var_int(STOP_SENDING),
            Self::Crypto { .. } => type_var_int(CRYPTO),
            Self::NewToken { .. } => type_var_int(NEW_TOKEN),
            Self::MaxData { .. } => type_var_int(MAX_DATA),
            Self::MaxStreamData { .. } => type_var_int(MAX_STREAM_DATA),
            Self::DataBlocked { .. } => type_var_int(DATA_BLOCKED),
            Self::StreamDataBlocked { .. } => type_var_int(STREAM_DATA_BLOCKED),
            Self::NewConnectionId { .. } => type_var_int(NEW_CONNECTION_ID),
            Self::RetireConnectionId { .. } => type_var_int(RETIRE_CONNECTION_ID),
            Self::PathChallenge { .. } => type_var_int(PATH_CHALLENGE),
            Self::PathResponse { .. } => type_var_int(PATH_RESPONSE),
        }
    }

    fn is_incomplete(&self) -> bool {
        match self {
            Self::MaxData { .. }
            | Self::DataBlocked { .. }
            | Self::RetireConnectionId { .. }
            | Self::ResetStream { .. }
            | Self::StopSending { .. }
            | Self::MaxStreamData { .. }
            | Self::StreamDataBlocked { .. }
            | Self::PathChallenge { .. }
            | Self::PathResponse { .. }
            | Self::ConnectionCloseTransport { .. }
            | Self::ConnectionCloseApplication { .. } => true,
            Self::Ack { source } => source.is_incomplete(),
            Self::AckEcn { source } => source.is_incomplete(),
            Self::Crypto { source, .. } => match source {
                ReadCryptoFrameError::Offset { .. }
                | ReadCryptoFrameError::Length { .. }
                | ReadCryptoFrameError::Data { .. } => true,
                ReadCryptoFrameError::DataEnd { .. } => false,
            },
            Self::NewToken { source, .. } => match source {
                ReadNewTokenFrameError::TokenLength { .. }
                | ReadNewTokenFrameError::Token { .. } => true,
                ReadNewTokenFrameError::Empty { .. } => false,
            },
            Self::Stream { source, .. } => match source {
                ReadStreamFrameError::StreamId { .. }
                | ReadStreamFrameError::Offset { .. }
                | ReadStreamFrameError::Length { .. }
                | ReadStreamFrameError::Data { .. } => true,
                ReadStreamFrameError::DataEnd { .. } => false,
            },
            Self::MaxStreams { source, .. } => {
                matches!(source, ReadMaxStreamsFrameError::Field { .. })
            }
            Self::StreamsBlocked { source, .. } => {
                matches!(source, ReadStreamsBlockedFrameError::Field { .. })
            }
            Self::NewConnectionId { source, .. } => match source {
                ReadNewConnectionIdFrameError::SequenceNumber { .. }
                | ReadNewConnectionIdFrameError::RetirePriorTo { .. }
                | ReadNewConnectionIdFrameError::StatelessResetToken { .. } => true,
                ReadNewConnectionIdFrameError::ConnectionId { source } => source.is_incomplete(),
                ReadNewConnectionIdFrameError::EmptyConnectionId { .. }
                | ReadNewConnectionIdFrameError::RetirePriorToAboveSequenceNumber { .. } => false,
            },
        }
    }

    /// FRAME_ENCODING_ERROR for every failure ([RFC 9000 §12.4]).
    ///
    /// [RFC 9000 §12.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4
    fn transport_error_code(&self) -> TransportErrorCode {
        TransportErrorCode::FRAME_ENCODING_ERROR
    }
}

/// Writes the variants of `$frame`, a `$enum` (`Frame` or `FrameRun`), with
/// `$write_padding` for PADDING.
macro_rules! write_variants {
    ($enum:ident, $dst:ident, $frame:ident, $write_padding:path) => {{
        use $crate::frame::{
            ack, connection_close, crypto, data_blocked, handshake_done, max_data, max_stream_data,
            max_streams, new_connection_id, new_token, path_challenge, path_response, ping,
            reset_stream, retire_connection_id, stop_sending, stream, stream_data_blocked,
            streams_blocked,
        };
        match $frame {
            $enum::Padding(frame) => $write_padding($dst, frame),
            $enum::Ping(frame) => ping::codec::write_ping_frame($dst, frame),
            $enum::Ack(frame) => ack::codec::write_ack_frame($dst, frame),
            $enum::ResetStream(frame) => reset_stream::codec::write_reset_stream_frame($dst, frame),
            $enum::StopSending(frame) => stop_sending::codec::write_stop_sending_frame($dst, frame),
            $enum::Crypto(frame) => crypto::codec::write_crypto_frame($dst, frame),
            $enum::NewToken(frame) => new_token::codec::write_new_token_frame($dst, frame),
            $enum::Stream(frame) => stream::codec::write_stream_frame($dst, frame),
            $enum::MaxData(frame) => max_data::codec::write_max_data_frame($dst, frame),
            $enum::MaxStreamData(frame) => {
                max_stream_data::codec::write_max_stream_data_frame($dst, frame)
            }
            $enum::MaxStreams(frame) => max_streams::codec::write_max_streams_frame($dst, frame),
            $enum::DataBlocked(frame) => data_blocked::codec::write_data_blocked_frame($dst, frame),
            $enum::StreamDataBlocked(frame) => {
                stream_data_blocked::codec::write_stream_data_blocked_frame($dst, frame)
            }
            $enum::StreamsBlocked(frame) => {
                streams_blocked::codec::write_streams_blocked_frame($dst, frame)
            }
            $enum::NewConnectionId(frame) => {
                new_connection_id::codec::write_new_connection_id_frame($dst, frame)
            }
            $enum::RetireConnectionId(frame) => {
                retire_connection_id::codec::write_retire_connection_id_frame($dst, frame)
            }
            $enum::PathChallenge(frame) => {
                path_challenge::codec::write_path_challenge_frame($dst, frame)
            }
            $enum::PathResponse(frame) => {
                path_response::codec::write_path_response_frame($dst, frame)
            }
            $enum::ConnectionClose(frame) => {
                connection_close::codec::write_connection_close_frame($dst, frame)
            }
            $enum::HandshakeDone(frame) => {
                handshake_done::codec::write_handshake_done_frame($dst, frame)
            }
        }
    }};
}

/// Writes `frame`.
///
/// Every frame type checks its limits when it is constructed, so nothing is
/// checked here.
///
/// # Panics
///
/// If `dst` has no room for the frame, as [`BufMut`] does.
pub fn write_frame<D: Buf>(dst: &mut impl BufMut, frame: Frame<D>) {
    write_variants!(
        Frame,
        dst,
        frame,
        crate::frame::padding::codec::write_padding_frame
    )
}

/// Writes `run`: the PADDING frames of a
/// [`PaddingRun`](super::padding::PaddingRun), or the one frame of any other
/// type, as [`write_frame`] writes it.
///
/// # Panics
///
/// If `dst` has no room for the frames, as [`BufMut`] does.
pub fn write_frame_run<D: Buf>(dst: &mut impl BufMut, run: FrameRun<D>) {
    write_variants!(
        FrameRun,
        dst,
        run,
        crate::frame::padding::codec::write_padding_run
    )
}
