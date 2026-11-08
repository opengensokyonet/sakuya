//! Reading the fields of version 1 frames and writing frames of any version 1
//! type as `nitori_call` operations.
//!
//! [`v1::Part`](crate::v1::Part) reads the fields after the Frame Type of a
//! version 1 frame, through
//! [`read_frame`](crate::frame::codec::read_frame) of a frame set that has
//! it; [`ReadFieldsError`] holds the failure of each frame type.
//! [`write_frame`] writes any version 1 [`Frame`]; the modules of the frame
//! types also have write operations of their own, such as
//! [`write_stream_frame`](super::stream::codec::write_stream_frame).
//!
//! [`write_frame`] is also the operation struct [`WriteFrame`], with
//! `WriteFrameExt` on receiver accesses inside other operations and
//! `WriteFrameHostExt` on call executors, including the `sync_` methods for
//! receivers that never wait. Constructing an operation performs no IO.
//!
//! ```
//! use core::marker::PhantomData;
//! use sakuya_wire::{
//!     frame::codec::ReadFrameHostExt as _,
//!     v1::{
//!         self,
//!         frame::{
//!             Frame, codec::WriteFrameHostExt as _, max_data::MaxDataFrame, stream::StreamFrame,
//!         },
//!         stream_id::StreamId,
//!     },
//!     var_int::{VarInt, VarIntField, VarIntWidth},
//! };
//!
//! let set = PhantomData::<v1::Part>;
//! let mut output = Vec::new();
//! let maximum_data = VarIntField::shortest(VarInt::from(1_000_000u32));
//! let max_data = Frame::<&[u8]>::MaxData(MaxDataFrame::new(maximum_data));
//! output.sync_write_frame_unpin(max_data.clone()).unwrap();
//! let stream_id = VarIntField::shortest(StreamId::from_var_int(VarInt::from(4u8)));
//! // A STREAM frame with a Length field. Reading gives `StreamFrame<D>`, which
//! // states its Length field as `Either`; `into` converts to it.
//! let stream = StreamFrame::with_length(stream_id, None, VarIntWidth::One, &b"hello"[..], true);
//! let stream = Frame::Stream(stream.unwrap().into());
//! output.sync_write_frame_unpin(stream.clone()).unwrap();
//!
//! // A STREAM frame checks its fields when it is constructed, so writing it
//! // checks nothing: a one-byte Length field cannot state 64 bytes of data.
//! let data = [0; 64];
//! let long = StreamFrame::with_length(stream_id, None, VarIntWidth::One, &data[..], true);
//! assert!(long.is_err());
//!
//! // Reading a byte slice yields subslices of it as payload fields.
//! let mut input = output.as_slice();
//! assert_eq!(input.sync_read_frame_unpin(set).unwrap(), max_data);
//! assert_eq!(input.sync_read_frame_unpin(set).unwrap(), stream);
//! assert!(input.is_empty());
//!
//! // A longer encoding of a field is kept, and written back as it was.
//! let mut input = &[0x10, 0x80, 0x00, 0x00, 0x05][..];
//! let frame = input.sync_read_frame_unpin(set).unwrap();
//! let Frame::MaxData(max_data) = &frame else { panic!() };
//! assert_eq!(max_data.maximum_data().width(), VarIntWidth::Four);
//! let mut output = Vec::new();
//! output.sync_write_frame_unpin(frame).unwrap();
//! assert_eq!(output, [0x10, 0x80, 0x00, 0x00, 0x05]);
//! ```
// `#[call]` generates constructors, fields and extension traits without
// documentation comments; the module documentation above describes them.
#![allow(missing_docs)]

use super::{
    Frame, FrameType,
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
    stop_sending::codec::{ReadStopSendingFrameError, read_stop_sending_frame},
    stream::{
        StreamTypeValue,
        codec::{ReadStreamFrameError, read_stream_frame},
    },
    stream_data_blocked::codec::{ReadStreamDataBlockedFrameError, read_stream_data_blocked_frame},
    streams_blocked::codec::{ReadStreamsBlockedFrameError, read_streams_blocked_frame},
    type_value,
};
use crate::{
    frame::{FrameFieldsError, type_var_int},
    payload::ReadPayloadError,
    v1::stream_id::Directionality,
    v1::transport_error::TransportErrorCode,
    var_int::{VarInt, codec::ReadVarIntError},
};
use bytes::Buf;
use core::num::NonZeroUsize;
use nitori_call::{ReceiverAccess, call};
use nitori_io::{
    calls::{ReadArrayError, WriteAllError},
    prelude::*,
};
use snafu::{ResultExt, Snafu};

/// Reads the fields that follow the Frame Type `frame_type`, of the kind
/// `kind` that [`FrameType::of`] gives for it.
///
/// The source is the rest of a packet payload: a STREAM frame without a
/// Length field takes all of it. Payload fields are chunks of the source. A
/// PADDING frame has no fields: it is one byte, its Frame Type.
///
/// # Errors
///
/// The variant of [`ReadFieldsError`] named after the frame type if its
/// fields cannot be read or break a limit of the encoding. Bytes read before
/// a failure stay consumed.
///
/// # Panics
///
/// If the receiver returns a chunk longer than requested, which breaks the
/// `ReadChunk` contract of `nitori_io`; see [`payload`](crate::payload).
pub(in crate::v1) async fn read_fields<F, A>(
    io: &mut A,
    kind: FrameType,
    frame_type: VarInt,
) -> Result<Frame<F::Chunk>, ReadFieldsError<F::Error>>
where
    F: ReadChunk<Chunk: Default>,
    A: ReceiverAccess<Family = F>,
{
    use read_fields_error::*;
    use type_value::*;
    let value = frame_type.get();
    Ok(match kind {
        FrameType::Padding => Frame::Padding(PaddingFrame::new(NonZeroUsize::MIN)),
        FrameType::Ping => Frame::Ping(PingFrame),
        FrameType::Ack if value == ACK_ECN => {
            Frame::Ack(read_ack_frame_ecn(io).await.context(AckEcnSnafu)?)
        }
        FrameType::Ack => Frame::Ack(read_ack_frame(io).await.context(AckSnafu)?),
        FrameType::ResetStream => Frame::ResetStream(
            read_reset_stream_frame(io)
                .await
                .context(ResetStreamSnafu)?,
        ),
        FrameType::StopSending => Frame::StopSending(
            read_stop_sending_frame(io)
                .await
                .context(StopSendingSnafu)?,
        ),
        FrameType::Crypto => Frame::Crypto(read_crypto_frame(io).await.context(CryptoSnafu)?),
        FrameType::NewToken => {
            Frame::NewToken(read_new_token_frame(io).await.context(NewTokenSnafu)?)
        }
        FrameType::Stream => {
            let frame_type = StreamTypeValue::new(frame_type);
            // invariant: `FrameType::of` gives `Stream` for exactly the STREAM
            // Frame Type values.
            let frame_type = frame_type.unwrap_or_else(|| unreachable!("STREAM {value:#x}"));
            Frame::Stream(
                read_stream_frame(io, frame_type)
                    .await
                    .context(StreamSnafu { frame_type })?,
            )
        }
        FrameType::MaxData => Frame::MaxData(read_max_data_frame(io).await.context(MaxDataSnafu)?),
        FrameType::MaxStreamData => Frame::MaxStreamData(
            read_max_stream_data_frame(io)
                .await
                .context(MaxStreamDataSnafu)?,
        ),
        FrameType::MaxStreams => {
            let directionality = directionality(value == MAX_STREAMS_UNI);
            Frame::MaxStreams(
                read_max_streams_frame(io, directionality)
                    .await
                    .context(MaxStreamsSnafu { directionality })?,
            )
        }
        FrameType::DataBlocked => Frame::DataBlocked(
            read_data_blocked_frame(io)
                .await
                .context(DataBlockedSnafu)?,
        ),
        FrameType::StreamDataBlocked => Frame::StreamDataBlocked(
            read_stream_data_blocked_frame(io)
                .await
                .context(StreamDataBlockedSnafu)?,
        ),
        FrameType::StreamsBlocked => {
            let directionality = directionality(value == STREAMS_BLOCKED_UNI);
            Frame::StreamsBlocked(
                read_streams_blocked_frame(io, directionality)
                    .await
                    .context(StreamsBlockedSnafu { directionality })?,
            )
        }
        FrameType::NewConnectionId => Frame::NewConnectionId(
            read_new_connection_id_frame(io)
                .await
                .context(NewConnectionIdSnafu)?,
        ),
        FrameType::RetireConnectionId => Frame::RetireConnectionId(
            read_retire_connection_id_frame(io)
                .await
                .context(RetireConnectionIdSnafu)?,
        ),
        FrameType::PathChallenge => Frame::PathChallenge(
            read_path_challenge_frame(io)
                .await
                .context(PathChallengeSnafu)?,
        ),
        FrameType::PathResponse => Frame::PathResponse(
            read_path_response_frame(io)
                .await
                .context(PathResponseSnafu)?,
        ),
        FrameType::ConnectionCloseApplication => Frame::ConnectionClose(
            read_connection_close_frame_application(io)
                .await
                .context(ConnectionCloseApplicationSnafu)?,
        ),
        FrameType::ConnectionCloseTransport => Frame::ConnectionClose(
            read_connection_close_frame_transport(io)
                .await
                .context(ConnectionCloseTransportSnafu)?,
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
#[snafu(module(read_fields_error), visibility(pub(in crate::v1)))]
pub enum ReadFieldsError<E> {
    /// An ACK frame of type `0x02`, without ECN counts, could not be read.
    #[snafu(display("ACK frame read failed"))]
    Ack {
        /// The failure.
        source: ReadAckFrameError<E>,
    },
    /// An ACK frame of type `0x03`, with ECN counts, could not be read.
    #[snafu(display("ACK frame with ECN counts read failed"))]
    AckEcn {
        /// The failure.
        source: ReadAckFrameEcnError<E>,
    },
    /// A RESET_STREAM frame could not be read.
    #[snafu(display("RESET_STREAM frame read failed"))]
    ResetStream {
        /// The failure.
        source: ReadResetStreamFrameError<E>,
    },
    /// A STOP_SENDING frame could not be read.
    #[snafu(display("STOP_SENDING frame read failed"))]
    StopSending {
        /// The failure.
        source: ReadStopSendingFrameError<E>,
    },
    /// A CRYPTO frame could not be read.
    #[snafu(display("CRYPTO frame read failed"))]
    Crypto {
        /// The failure.
        source: ReadCryptoFrameError<E>,
    },
    /// A NEW_TOKEN frame could not be read.
    #[snafu(display("NEW_TOKEN frame read failed"))]
    NewToken {
        /// The failure.
        source: ReadNewTokenFrameError<E>,
    },
    /// A STREAM frame could not be read.
    #[snafu(display("STREAM frame read failed"))]
    Stream {
        /// The Frame Type.
        frame_type: StreamTypeValue,
        /// The failure.
        source: ReadStreamFrameError<E>,
    },
    /// A MAX_DATA frame could not be read.
    #[snafu(display("MAX_DATA frame read failed"))]
    MaxData {
        /// The failure.
        source: ReadVarIntError<E>,
    },
    /// A MAX_STREAM_DATA frame could not be read.
    #[snafu(display("MAX_STREAM_DATA frame read failed"))]
    MaxStreamData {
        /// The failure.
        source: ReadMaxStreamDataFrameError<E>,
    },
    /// A MAX_STREAMS frame could not be read.
    #[snafu(display("MAX_STREAMS frame read failed"))]
    MaxStreams {
        /// The type of streams of the Frame Type: `0x12` for bidirectional,
        /// `0x13` for unidirectional streams.
        directionality: Directionality,
        /// The failure.
        source: ReadMaxStreamsFrameError<E>,
    },
    /// A DATA_BLOCKED frame could not be read.
    #[snafu(display("DATA_BLOCKED frame read failed"))]
    DataBlocked {
        /// The failure.
        source: ReadVarIntError<E>,
    },
    /// A STREAM_DATA_BLOCKED frame could not be read.
    #[snafu(display("STREAM_DATA_BLOCKED frame read failed"))]
    StreamDataBlocked {
        /// The failure.
        source: ReadStreamDataBlockedFrameError<E>,
    },
    /// A STREAMS_BLOCKED frame could not be read.
    #[snafu(display("STREAMS_BLOCKED frame read failed"))]
    StreamsBlocked {
        /// The type of streams of the Frame Type: `0x16` for bidirectional,
        /// `0x17` for unidirectional streams.
        directionality: Directionality,
        /// The failure.
        source: ReadStreamsBlockedFrameError<E>,
    },
    /// A NEW_CONNECTION_ID frame could not be read.
    #[snafu(display("NEW_CONNECTION_ID frame read failed"))]
    NewConnectionId {
        /// The failure.
        source: ReadNewConnectionIdFrameError<E>,
    },
    /// A RETIRE_CONNECTION_ID frame could not be read.
    #[snafu(display("RETIRE_CONNECTION_ID frame read failed"))]
    RetireConnectionId {
        /// The failure.
        source: ReadVarIntError<E>,
    },
    /// A PATH_CHALLENGE frame could not be read.
    #[snafu(display("PATH_CHALLENGE frame read failed"))]
    PathChallenge {
        /// The failure.
        source: ReadArrayError<E>,
    },
    /// A PATH_RESPONSE frame could not be read.
    #[snafu(display("PATH_RESPONSE frame read failed"))]
    PathResponse {
        /// The failure.
        source: ReadArrayError<E>,
    },
    /// A CONNECTION_CLOSE frame of type `0x1c`, for a transport error,
    /// could not be read.
    #[snafu(display("CONNECTION_CLOSE frame read failed"))]
    ConnectionCloseTransport {
        /// The failure.
        source: ReadConnectionCloseFrameTransportError<E>,
    },
    /// A CONNECTION_CLOSE frame of type `0x1d`, for an application error,
    /// could not be read.
    #[snafu(display("application CONNECTION_CLOSE frame read failed"))]
    ConnectionCloseApplication {
        /// The failure.
        source: ReadConnectionCloseFrameApplicationError<E>,
    },
}

impl<E> FrameFieldsError for ReadFieldsError<E> {
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
        use crate::v1::frame::{
            crypto::codec::ReadCryptoFrameError as CryptoFrame,
            stream::codec::ReadStreamFrameError as StreamFrame,
        };
        fn payload<E>(error: &ReadPayloadError<E>) -> bool {
            error.is_incomplete()
        }
        fn array<E>(error: &ReadArrayError<E>) -> bool {
            matches!(error, ReadArrayError::Incomplete { .. })
        }
        match self {
            Self::MaxData { source, .. }
            | Self::DataBlocked { source, .. }
            | Self::RetireConnectionId { source, .. } => source.is_incomplete(),
            Self::ResetStream { source, .. } => match source {
                ReadResetStreamFrameError::StreamId { source }
                | ReadResetStreamFrameError::ApplicationProtocolErrorCode { source }
                | ReadResetStreamFrameError::FinalSize { source } => source.is_incomplete(),
            },
            Self::StopSending { source, .. } => match source {
                ReadStopSendingFrameError::StreamId { source }
                | ReadStopSendingFrameError::ApplicationProtocolErrorCode { source } => {
                    source.is_incomplete()
                }
            },
            Self::MaxStreamData { source, .. } => match source {
                ReadMaxStreamDataFrameError::StreamId { source }
                | ReadMaxStreamDataFrameError::MaximumStreamData { source } => {
                    source.is_incomplete()
                }
            },
            Self::StreamDataBlocked { source, .. } => match source {
                ReadStreamDataBlockedFrameError::StreamId { source }
                | ReadStreamDataBlockedFrameError::MaximumStreamData { source } => {
                    source.is_incomplete()
                }
            },
            Self::Ack { source } => source.is_incomplete(),
            Self::AckEcn { source } => source.is_incomplete(),
            Self::Crypto { source, .. } => match source {
                CryptoFrame::Offset { source } | CryptoFrame::Length { source } => {
                    source.is_incomplete()
                }
                CryptoFrame::Data { source } => payload(source),
                CryptoFrame::DataEnd { .. } => false,
            },
            Self::NewToken { source, .. } => match source {
                ReadNewTokenFrameError::TokenLength { source } => source.is_incomplete(),
                ReadNewTokenFrameError::Token { source } => payload(source),
                ReadNewTokenFrameError::Empty { .. } => false,
            },
            Self::Stream { source, .. } => match source {
                StreamFrame::StreamId { source }
                | StreamFrame::Offset { source }
                | StreamFrame::Length { source } => source.is_incomplete(),
                StreamFrame::Data { source } => payload(source),
                StreamFrame::DataEnd { .. } => false,
            },
            Self::MaxStreams { source, .. } => {
                matches!(source, ReadMaxStreamsFrameError::Field { source } if source.is_incomplete())
            }
            Self::StreamsBlocked { source, .. } => {
                matches!(source, ReadStreamsBlockedFrameError::Field { source } if source.is_incomplete())
            }
            Self::NewConnectionId { source, .. } => match source {
                ReadNewConnectionIdFrameError::SequenceNumber { source }
                | ReadNewConnectionIdFrameError::RetirePriorTo { source } => source.is_incomplete(),
                ReadNewConnectionIdFrameError::ConnectionId { source } => source.is_incomplete(),
                ReadNewConnectionIdFrameError::StatelessResetToken { source } => array(source),
                ReadNewConnectionIdFrameError::EmptyConnectionId { .. }
                | ReadNewConnectionIdFrameError::RetirePriorToAboveSequenceNumber { .. } => false,
            },
            Self::PathChallenge { source, .. } | Self::PathResponse { source, .. } => array(source),
            Self::ConnectionCloseTransport { source } => source.is_incomplete(),
            Self::ConnectionCloseApplication { source } => source.is_incomplete(),
        }
    }

    /// FRAME_ENCODING_ERROR for every failure ([RFC 9000 §12.4]).
    ///
    /// [RFC 9000 §12.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4
    fn transport_error_code(&self) -> TransportErrorCode {
        TransportErrorCode::FRAME_ENCODING_ERROR
    }
}

/// Writes `frame` completely.
///
/// Every frame type checks its limits when it is constructed, so nothing is
/// checked here. Acceptance by the receiver does not imply flushing or
/// delivery.
///
/// # Errors
///
/// [`WriteAllError`] if the receiver stops accepting bytes or fails; bytes
/// accepted before stay written.
#[call(sync)]
pub async fn write_frame<F, A, D>(
    io: &mut A,
    frame: Frame<D>,
) -> Result<(), WriteAllError<F::Error>>
where
    F: Write,
    A: ReceiverAccess<Family = F>,
    D: Buf,
{
    use super::{
        ack, connection_close, crypto, data_blocked, handshake_done, max_data, max_stream_data,
        max_streams, new_connection_id, new_token, padding, path_challenge, path_response, ping,
        reset_stream, retire_connection_id, stop_sending, stream, stream_data_blocked,
        streams_blocked,
    };
    match frame {
        Frame::Padding(frame) => padding::codec::write_padding_frame(io, frame).await,
        Frame::Ping(frame) => ping::codec::write_ping_frame(io, frame).await,
        Frame::Ack(frame) => ack::codec::write_ack_frame(io, frame).await,
        Frame::ResetStream(frame) => reset_stream::codec::write_reset_stream_frame(io, frame).await,
        Frame::StopSending(frame) => stop_sending::codec::write_stop_sending_frame(io, frame).await,
        Frame::Crypto(frame) => crypto::codec::write_crypto_frame(io, frame).await,
        Frame::NewToken(frame) => new_token::codec::write_new_token_frame(io, frame).await,
        Frame::Stream(frame) => stream::codec::write_stream_frame(io, frame).await,
        Frame::MaxData(frame) => max_data::codec::write_max_data_frame(io, frame).await,
        Frame::MaxStreamData(frame) => {
            max_stream_data::codec::write_max_stream_data_frame(io, frame).await
        }
        Frame::MaxStreams(frame) => max_streams::codec::write_max_streams_frame(io, frame).await,
        Frame::DataBlocked(frame) => data_blocked::codec::write_data_blocked_frame(io, frame).await,
        Frame::StreamDataBlocked(frame) => {
            stream_data_blocked::codec::write_stream_data_blocked_frame(io, frame).await
        }
        Frame::StreamsBlocked(frame) => {
            streams_blocked::codec::write_streams_blocked_frame(io, frame).await
        }
        Frame::NewConnectionId(frame) => {
            new_connection_id::codec::write_new_connection_id_frame(io, frame).await
        }
        Frame::RetireConnectionId(frame) => {
            retire_connection_id::codec::write_retire_connection_id_frame(io, frame).await
        }
        Frame::PathChallenge(frame) => {
            path_challenge::codec::write_path_challenge_frame(io, frame).await
        }
        Frame::PathResponse(frame) => {
            path_response::codec::write_path_response_frame(io, frame).await
        }
        Frame::ConnectionClose(frame) => {
            connection_close::codec::write_connection_close_frame(io, frame).await
        }
        Frame::HandshakeDone(frame) => {
            handshake_done::codec::write_handshake_done_frame(io, frame).await
        }
    }
}
