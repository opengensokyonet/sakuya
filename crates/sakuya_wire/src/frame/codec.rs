//! Reading and writing frames of any type as `nitori_call` operations.
//!
//! [`read_frame`] reads one frame: its Frame Type, checked against the
//! enabled [`Extensions`], and the fields of that type. [`write_frame`]
//! writes any [`Frame`]; the modules of the frame types also have write
//! operations of their own, such as
//! [`write_stream`](super::stream::codec::write_stream).
//!
//! Each function is also an operation struct, [`ReadFrame`] and
//! [`WriteFrame`], with `{Name}Ext` on receiver accesses inside other
//! operations and `{Name}HostExt` on call executors, including the `sync_`
//! methods for receivers that never wait. Constructing an operation performs
//! no IO.
//!
//! ```
//! use sakuya_wire::frame::{
//!     Extensions, Frame,
//!     codec::{ReadFrameHostExt as _, WriteFrameHostExt as _},
//!     max_data::MaxData,
//!     stream::Stream,
//! };
//! use sakuya_wire::{
//!     stream_id::StreamId,
//!     var_int::{VarInt, VarIntField, VarIntWidth},
//! };
//!
//! let mut output = Vec::new();
//! let maximum_data = VarIntField::shortest(VarInt::from(1_000_000u32));
//! let max_data = Frame::<&[u8]>::MaxData(MaxData::new(maximum_data));
//! output.sync_write_frame_unpin(max_data.clone()).unwrap();
//! let stream_id = VarIntField::shortest(StreamId::from_var_int(VarInt::from(4u8)));
//! // A STREAM frame with a Length field. Reading gives `Stream<D>`, which
//! // states its Length field as `Either`; `into` converts to it.
//! let stream = Stream::with_length(stream_id, None, VarIntWidth::One, &b"hello"[..], true);
//! let stream = Frame::Stream(stream.unwrap().into());
//! output.sync_write_frame_unpin(stream.clone()).unwrap();
//!
//! // A STREAM frame checks its fields when it is constructed, so writing it
//! // checks nothing: a one-byte Length field cannot state 64 bytes of data.
//! let data = [0; 64];
//! let long = Stream::with_length(stream_id, None, VarIntWidth::One, &data[..], true);
//! assert!(long.is_err());
//!
//! // Reading a byte slice yields subslices of it as payload fields.
//! let mut input = output.as_slice();
//! assert_eq!(input.sync_read_frame_unpin(Extensions::NONE).unwrap(), max_data);
//! assert_eq!(input.sync_read_frame_unpin(Extensions::NONE).unwrap(), stream);
//! assert!(input.is_empty());
//!
//! // A frame cut short is an incomplete failure.
//! let mut input = &output[..3];
//! assert!(input.sync_read_frame_unpin(Extensions::NONE).unwrap_err().is_incomplete());
//!
//! // A longer encoding of a field is kept, and written back as it was.
//! let mut input = &[0x10, 0x80, 0x00, 0x00, 0x05][..];
//! let frame = input.sync_read_frame_unpin(Extensions::NONE).unwrap();
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
    Extensions, Frame, FrameType, UnknownFrameTypeError,
    ack::codec::{ReadAckEcnError, ReadAckError, read_ack, read_ack_ecn},
    connection_close::codec::{
        ReadConnectionCloseApplicationError, ReadConnectionCloseTransportError,
        read_connection_close_application, read_connection_close_transport,
    },
    crypto::codec::{ReadCryptoError, read_crypto},
    data_blocked::codec::read_data_blocked,
    datagram::{
        DatagramTypeValue,
        codec::{ReadDatagramError, read_datagram},
    },
    handshake_done::HandshakeDone,
    max_data::codec::read_max_data,
    max_stream_data::codec::{ReadMaxStreamDataError, read_max_stream_data},
    max_streams::codec::{ReadMaxStreamsError, read_max_streams},
    new_connection_id::codec::{ReadNewConnectionIdError, read_new_connection_id},
    new_token::codec::{ReadNewTokenError, read_new_token},
    padding::Padding,
    path_challenge::codec::read_path_challenge,
    path_response::codec::read_path_response,
    ping::Ping,
    reset_stream::codec::{ReadResetStreamError, read_reset_stream},
    reset_stream_at::codec::{ReadResetStreamAtError, read_reset_stream_at},
    retire_connection_id::codec::read_retire_connection_id,
    stop_sending::codec::{ReadStopSendingError, read_stop_sending},
    stream::{
        StreamTypeValue,
        codec::{ReadStreamError, read_stream},
    },
    stream_data_blocked::codec::{ReadStreamDataBlockedError, read_stream_data_blocked},
    streams_blocked::codec::{ReadStreamsBlockedError, read_streams_blocked},
    type_value, type_var_int,
};
use crate::{
    payload::ReadPayloadError,
    stream_id::Directionality,
    transport_error::TransportErrorCode,
    var_int::{
        VarInt, VarIntWidth,
        codec::{ReadVarIntError, read_var_int_with_width},
    },
};
use bytes::Buf;
use core::num::NonZeroUsize;
use nitori_call::{ReceiverAccess, call};
use nitori_io::{
    calls::{ReadArrayError, WriteAllError},
    prelude::*,
};
use snafu::{ResultExt, Snafu};

/// Reads one frame, accepting the extension frames in `extensions`.
///
/// The source is the rest of a packet payload: a STREAM or DATAGRAM frame
/// without a Length field takes all of it. Payload fields are chunks of the
/// source. A PADDING frame reads only its one-byte Frame Type.
///
/// The Frame Type must use its shortest encoding ([RFC 9000 §12.4]); a
/// longer one is rejected before the type is looked up.
///
/// # Errors
///
/// [`ReadFrameError::FrameType`] if the Frame Type cannot be read,
/// [`ReadFrameError::LongerTypeEncoding`] if it uses a longer encoding than
/// necessary, [`ReadFrameError::UnknownType`] for a type that is unknown,
/// [`ReadFrameError::ExtensionNotEnabled`] for an extension frame type that
/// `extensions` does not enable, and the variant named after the frame type
/// if its fields cannot be read or break a limit of the encoding. Bytes read
/// before a failure stay consumed.
///
/// # Panics
///
/// If the receiver returns a chunk longer than requested, which breaks the
/// `ReadChunk` contract of `nitori_io`; see [`payload`](crate::payload).
///
/// [RFC 9000 §12.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4
#[call(sync)]
pub async fn read_frame<F, A>(
    io: &mut A,
    extensions: Extensions,
) -> Result<Frame<F::Chunk>, ReadFrameError<F::Error>>
where
    F: ReadChunk<Chunk: Default>,
    A: ReceiverAccess<Family = F>,
{
    use read_frame_error::*;
    use type_value::*;
    let (frame_type, width) = read_var_int_with_width(io).await.context(FrameTypeSnafu)?;
    LongerTypeEncodingError::check(frame_type, width)?;
    let kind = FrameType::of(frame_type)?;
    // Every frame type that is not an extension frame type is permitted.
    if let Some(extension) = ExtensionTypeValue::new(frame_type)
        && !extensions.permits(kind)
    {
        return ExtensionNotEnabledSnafu {
            frame_type: extension,
        }
        .fail();
    }
    let value = frame_type.get();
    Ok(match kind {
        FrameType::Padding => Frame::Padding(Padding::new(NonZeroUsize::MIN)),
        FrameType::Ping => Frame::Ping(Ping),
        FrameType::Ack if value == ACK_ECN => {
            Frame::Ack(read_ack_ecn(io).await.context(AckEcnSnafu)?)
        }
        FrameType::Ack => Frame::Ack(read_ack(io).await.context(AckSnafu)?),
        FrameType::ResetStream => {
            Frame::ResetStream(read_reset_stream(io).await.context(ResetStreamSnafu)?)
        }
        FrameType::StopSending => {
            Frame::StopSending(read_stop_sending(io).await.context(StopSendingSnafu)?)
        }
        FrameType::Crypto => Frame::Crypto(read_crypto(io).await.context(CryptoSnafu)?),
        FrameType::NewToken => Frame::NewToken(read_new_token(io).await.context(NewTokenSnafu)?),
        FrameType::Stream => {
            let frame_type = StreamTypeValue::new(frame_type);
            // invariant: `FrameType::of` gives `Stream` for exactly the STREAM
            // Frame Type values.
            let frame_type = frame_type.unwrap_or_else(|| unreachable!("STREAM {value:#x}"));
            Frame::Stream(
                read_stream(io, frame_type)
                    .await
                    .context(StreamSnafu { frame_type })?,
            )
        }
        FrameType::MaxData => Frame::MaxData(read_max_data(io).await.context(MaxDataSnafu)?),
        FrameType::MaxStreamData => {
            Frame::MaxStreamData(read_max_stream_data(io).await.context(MaxStreamDataSnafu)?)
        }
        FrameType::MaxStreams => {
            let directionality = directionality(value == MAX_STREAMS_UNI);
            Frame::MaxStreams(
                read_max_streams(io, directionality)
                    .await
                    .context(MaxStreamsSnafu { directionality })?,
            )
        }
        FrameType::DataBlocked => {
            Frame::DataBlocked(read_data_blocked(io).await.context(DataBlockedSnafu)?)
        }
        FrameType::StreamDataBlocked => Frame::StreamDataBlocked(
            read_stream_data_blocked(io)
                .await
                .context(StreamDataBlockedSnafu)?,
        ),
        FrameType::StreamsBlocked => {
            let directionality = directionality(value == STREAMS_BLOCKED_UNI);
            Frame::StreamsBlocked(
                read_streams_blocked(io, directionality)
                    .await
                    .context(StreamsBlockedSnafu { directionality })?,
            )
        }
        FrameType::NewConnectionId => Frame::NewConnectionId(
            read_new_connection_id(io)
                .await
                .context(NewConnectionIdSnafu)?,
        ),
        FrameType::RetireConnectionId => Frame::RetireConnectionId(
            read_retire_connection_id(io)
                .await
                .context(RetireConnectionIdSnafu)?,
        ),
        FrameType::PathChallenge => {
            Frame::PathChallenge(read_path_challenge(io).await.context(PathChallengeSnafu)?)
        }
        FrameType::PathResponse => {
            Frame::PathResponse(read_path_response(io).await.context(PathResponseSnafu)?)
        }
        FrameType::ConnectionClose if value == CONNECTION_CLOSE_APPLICATION => {
            Frame::ConnectionClose(
                read_connection_close_application(io)
                    .await
                    .context(ConnectionCloseApplicationSnafu)?,
            )
        }
        FrameType::ConnectionClose => Frame::ConnectionClose(
            read_connection_close_transport(io)
                .await
                .context(ConnectionCloseTransportSnafu)?,
        ),
        FrameType::HandshakeDone => Frame::HandshakeDone(HandshakeDone),
        FrameType::ResetStreamAt => {
            Frame::ResetStreamAt(read_reset_stream_at(io).await.context(ResetStreamAtSnafu)?)
        }
        FrameType::Datagram => {
            let frame_type = DatagramTypeValue::new(frame_type);
            // invariant: `FrameType::of` gives `Datagram` for exactly the
            // DATAGRAM Frame Type values.
            let frame_type = frame_type.unwrap_or_else(|| unreachable!("DATAGRAM {value:#x}"));
            Frame::Datagram(
                read_datagram(io, frame_type)
                    .await
                    .context(DatagramSnafu { frame_type })?,
            )
        }
    })
}

fn directionality(unidirectional: bool) -> Directionality {
    if unidirectional {
        Directionality::Unidirectional
    } else {
        Directionality::Bidirectional
    }
}

/// A Frame Type value of an extension frame: `0x24` (RESET_STREAM_AT), or
/// `0x30` and `0x31` (DATAGRAM).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ExtensionTypeValue(VarInt);

impl ExtensionTypeValue {
    /// The Frame Type value `value` if it is that of an extension frame, and
    /// `None` otherwise.
    pub(crate) const fn new(value: VarInt) -> Option<Self> {
        match value.get() {
            type_value::RESET_STREAM_AT
            | type_value::DATAGRAM
            | type_value::DATAGRAM_WITH_LENGTH => Some(Self(value)),
            _ => None,
        }
    }

    /// The Frame Type value.
    pub const fn get(self) -> VarInt {
        self.0
    }
}

impl From<ExtensionTypeValue> for VarInt {
    fn from(value: ExtensionTypeValue) -> Self {
        value.0
    }
}

/// A Frame Type uses a longer encoding than necessary ([RFC 9000 §12.4]).
///
/// It is constructed only when the check fails, so its width is always
/// longer than the shortest encoding of its Frame Type.
///
/// [RFC 9000 §12.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "frame type {:#x} uses a {}-byte encoding, longer than necessary",
    frame_type.get(),
    width.encoded_len()
))]
pub struct LongerTypeEncodingError {
    frame_type: VarInt,
    width: VarIntWidth,
}

impl LongerTypeEncodingError {
    /// Checks that the Frame Type `frame_type` was read in an encoding of
    /// `width`, its shortest.
    pub(crate) fn check(frame_type: VarInt, width: VarIntWidth) -> Result<(), Self> {
        if width != VarIntWidth::shortest(frame_type) {
            return Err(Self { frame_type, width });
        }
        Ok(())
    }

    /// The Frame Type.
    pub const fn frame_type(self) -> VarInt {
        self.frame_type
    }

    /// The width of its encoding, longer than the shortest.
    pub const fn width(self) -> VarIntWidth {
        self.width
    }
}

/// Failures that [`read_frame`] can produce.
///
/// Every failure corresponds to the transport error FRAME_ENCODING_ERROR,
/// except two that correspond to PROTOCOL_VIOLATION
/// ([`ReadFrameError::transport_error_code`]):
/// [`ReadFrameError::LongerTypeEncoding`], and
/// [`ReadFrameError::ExtensionNotEnabled`] for a DATAGRAM frame. The variants
/// named after a frame type hold the failure of reading the fields of that
/// type. ACK and CONNECTION_CLOSE have a variant for each of their two Frame
/// Type values, since the two have different fields; MAX_STREAMS and
/// STREAMS_BLOCKED say which of their two values was read, and STREAM and
/// DATAGRAM hold the Frame Type value.
#[derive(Debug, Snafu)]
#[snafu(module(read_frame_error), visibility(pub(crate)))]
pub enum ReadFrameError<E> {
    /// The Frame Type could not be read.
    #[snafu(display("frame type read failed"))]
    FrameType {
        /// The failure of reading the variable-length integer.
        source: ReadVarIntError<E>,
    },
    /// The Frame Type uses a longer encoding than necessary.
    ///
    /// RFC 9000 §12.4 requires the shortest encoding of the Frame Type; a
    /// longer one is a PROTOCOL_VIOLATION, whether or not the type is known.
    #[snafu(transparent)]
    LongerTypeEncoding {
        /// The broken rule.
        source: LongerTypeEncodingError,
    },
    /// The Frame Type is defined neither by RFC 9000 nor by a supported
    /// extension.
    #[snafu(transparent)]
    UnknownType {
        /// The unknown Frame Type value.
        source: UnknownFrameTypeError,
    },
    /// The Frame Type is that of an extension frame, and the extension is
    /// not enabled.
    #[snafu(display(
        "frame type {:#x} belongs to an extension that is not enabled",
        frame_type.get().get()
    ))]
    ExtensionNotEnabled {
        /// The Frame Type.
        frame_type: ExtensionTypeValue,
    },
    /// An ACK frame of type `0x02`, without ECN counts, could not be read.
    #[snafu(display("ACK frame read failed"))]
    Ack {
        /// The failure.
        source: ReadAckError<E>,
    },
    /// An ACK frame of type `0x03`, with ECN counts, could not be read.
    #[snafu(display("ACK frame with ECN counts read failed"))]
    AckEcn {
        /// The failure.
        source: ReadAckEcnError<E>,
    },
    /// A RESET_STREAM frame could not be read.
    #[snafu(display("RESET_STREAM frame read failed"))]
    ResetStream {
        /// The failure.
        source: ReadResetStreamError<E>,
    },
    /// A STOP_SENDING frame could not be read.
    #[snafu(display("STOP_SENDING frame read failed"))]
    StopSending {
        /// The failure.
        source: ReadStopSendingError<E>,
    },
    /// A CRYPTO frame could not be read.
    #[snafu(display("CRYPTO frame read failed"))]
    Crypto {
        /// The failure.
        source: ReadCryptoError<E>,
    },
    /// A NEW_TOKEN frame could not be read.
    #[snafu(display("NEW_TOKEN frame read failed"))]
    NewToken {
        /// The failure.
        source: ReadNewTokenError<E>,
    },
    /// A STREAM frame could not be read.
    #[snafu(display("STREAM frame read failed"))]
    Stream {
        /// The Frame Type.
        frame_type: StreamTypeValue,
        /// The failure.
        source: ReadStreamError<E>,
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
        source: ReadMaxStreamDataError<E>,
    },
    /// A MAX_STREAMS frame could not be read.
    #[snafu(display("MAX_STREAMS frame read failed"))]
    MaxStreams {
        /// The type of streams of the Frame Type: `0x12` for bidirectional,
        /// `0x13` for unidirectional streams.
        directionality: Directionality,
        /// The failure.
        source: ReadMaxStreamsError<E>,
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
        source: ReadStreamDataBlockedError<E>,
    },
    /// A STREAMS_BLOCKED frame could not be read.
    #[snafu(display("STREAMS_BLOCKED frame read failed"))]
    StreamsBlocked {
        /// The type of streams of the Frame Type: `0x16` for bidirectional,
        /// `0x17` for unidirectional streams.
        directionality: Directionality,
        /// The failure.
        source: ReadStreamsBlockedError<E>,
    },
    /// A NEW_CONNECTION_ID frame could not be read.
    #[snafu(display("NEW_CONNECTION_ID frame read failed"))]
    NewConnectionId {
        /// The failure.
        source: ReadNewConnectionIdError<E>,
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
        source: ReadConnectionCloseTransportError<E>,
    },
    /// A CONNECTION_CLOSE frame of type `0x1d`, for an application error,
    /// could not be read.
    #[snafu(display("application CONNECTION_CLOSE frame read failed"))]
    ConnectionCloseApplication {
        /// The failure.
        source: ReadConnectionCloseApplicationError<E>,
    },
    /// A RESET_STREAM_AT frame could not be read.
    #[snafu(display("RESET_STREAM_AT frame read failed"))]
    ResetStreamAt {
        /// The failure.
        source: ReadResetStreamAtError<E>,
    },
    /// A DATAGRAM frame could not be read.
    #[snafu(display("DATAGRAM frame read failed"))]
    Datagram {
        /// The Frame Type.
        frame_type: DatagramTypeValue,
        /// The failure.
        source: ReadDatagramError<E>,
    },
}

impl<E> ReadFrameError<E> {
    /// The Frame Type of the frame, if it could be read.
    ///
    /// This is the value for the Frame Type field of the CONNECTION_CLOSE
    /// frame that reports the error.
    pub fn frame_type(&self) -> Option<VarInt> {
        use super::{max_streams, streams_blocked};
        use type_value::*;
        Some(match *self {
            Self::FrameType { .. } => return None,
            Self::LongerTypeEncoding { source } => source.frame_type(),
            Self::Stream { frame_type, .. } => frame_type.get(),
            Self::Datagram { frame_type, .. } => frame_type.get(),
            Self::UnknownType { source } => source.frame_type.get(),
            Self::ExtensionNotEnabled { frame_type } => frame_type.get(),
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
            Self::ResetStreamAt { .. } => type_var_int(RESET_STREAM_AT),
        })
    }

    /// Whether the source ended within the frame.
    pub fn is_incomplete(&self) -> bool {
        use crate::frame::{
            crypto::codec::ReadCryptoError as Crypto, stream::codec::ReadStreamError as Stream,
        };
        fn payload<E>(error: &ReadPayloadError<E>) -> bool {
            error.is_incomplete()
        }
        fn array<E>(error: &ReadArrayError<E>) -> bool {
            matches!(error, ReadArrayError::Incomplete { .. })
        }
        match self {
            Self::FrameType { source }
            | Self::MaxData { source, .. }
            | Self::DataBlocked { source, .. }
            | Self::RetireConnectionId { source, .. } => source.is_incomplete(),
            Self::ResetStream { source, .. } => match source {
                ReadResetStreamError::StreamId { source }
                | ReadResetStreamError::ApplicationProtocolErrorCode { source }
                | ReadResetStreamError::FinalSize { source } => source.is_incomplete(),
            },
            Self::StopSending { source, .. } => match source {
                ReadStopSendingError::StreamId { source }
                | ReadStopSendingError::ApplicationProtocolErrorCode { source } => {
                    source.is_incomplete()
                }
            },
            Self::MaxStreamData { source, .. } => match source {
                ReadMaxStreamDataError::StreamId { source }
                | ReadMaxStreamDataError::MaximumStreamData { source } => source.is_incomplete(),
            },
            Self::StreamDataBlocked { source, .. } => match source {
                ReadStreamDataBlockedError::StreamId { source }
                | ReadStreamDataBlockedError::MaximumStreamData { source } => {
                    source.is_incomplete()
                }
            },
            Self::LongerTypeEncoding { .. }
            | Self::UnknownType { .. }
            | Self::ExtensionNotEnabled { .. } => false,
            Self::Ack { source } => source.is_incomplete(),
            Self::AckEcn { source } => source.is_incomplete(),
            Self::Crypto { source, .. } => match source {
                Crypto::Offset { source } | Crypto::Length { source } => source.is_incomplete(),
                Crypto::Data { source } => payload(source),
                Crypto::DataEnd { .. } => false,
            },
            Self::NewToken { source, .. } => match source {
                ReadNewTokenError::TokenLength { source } => source.is_incomplete(),
                ReadNewTokenError::Token { source } => payload(source),
                ReadNewTokenError::Empty { .. } => false,
            },
            Self::Stream { source, .. } => match source {
                Stream::StreamId { source }
                | Stream::Offset { source }
                | Stream::Length { source } => source.is_incomplete(),
                Stream::Data { source } => payload(source),
                Stream::DataEnd { .. } => false,
            },
            Self::MaxStreams { source, .. } => {
                matches!(source, ReadMaxStreamsError::Field { source } if source.is_incomplete())
            }
            Self::StreamsBlocked { source, .. } => {
                matches!(source, ReadStreamsBlockedError::Field { source } if source.is_incomplete())
            }
            Self::NewConnectionId { source, .. } => match source {
                ReadNewConnectionIdError::SequenceNumber { source }
                | ReadNewConnectionIdError::RetirePriorTo { source } => source.is_incomplete(),
                ReadNewConnectionIdError::ConnectionId { source } => source.is_incomplete(),
                ReadNewConnectionIdError::StatelessResetToken { source } => array(source),
                ReadNewConnectionIdError::EmptyConnectionId { .. }
                | ReadNewConnectionIdError::RetirePriorToAboveSequenceNumber { .. } => false,
            },
            Self::PathChallenge { source, .. } | Self::PathResponse { source, .. } => array(source),
            Self::ConnectionCloseTransport { source } => source.is_incomplete(),
            Self::ConnectionCloseApplication { source } => source.is_incomplete(),
            Self::ResetStreamAt { source, .. } => match source {
                ReadResetStreamAtError::StreamId { source }
                | ReadResetStreamAtError::ApplicationProtocolErrorCode { source }
                | ReadResetStreamAtError::FinalSize { source }
                | ReadResetStreamAtError::ReliableSize { source } => source.is_incomplete(),
                ReadResetStreamAtError::ReliableSizeAboveFinalSize { .. } => false,
            },
            Self::Datagram { source, .. } => match source {
                ReadDatagramError::Length { source } => source.is_incomplete(),
                ReadDatagramError::Data { source } => payload(source),
            },
        }
    }

    /// The transport error the failure corresponds to ([RFC 9000 §12.4],
    /// §19): PROTOCOL_VIOLATION for a Frame Type encoded longer than
    /// necessary and for a DATAGRAM frame that is not enabled ([RFC 9221 §3]),
    /// FRAME_ENCODING_ERROR for every other failure.
    ///
    /// [RFC 9000 §12.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4
    /// [RFC 9221 §3]: https://www.rfc-editor.org/rfc/rfc9221.html#section-3
    pub fn transport_error_code(&self) -> TransportErrorCode {
        match self {
            Self::LongerTypeEncoding { .. } => TransportErrorCode::PROTOCOL_VIOLATION,
            Self::ExtensionNotEnabled { frame_type }
                if matches!(FrameType::of(frame_type.get()), Ok(FrameType::Datagram)) =>
            {
                TransportErrorCode::PROTOCOL_VIOLATION
            }
            _ => TransportErrorCode::FRAME_ENCODING_ERROR,
        }
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
        ack, connection_close, crypto, data_blocked, datagram, handshake_done, max_data,
        max_stream_data, max_streams, new_connection_id, new_token, padding, path_challenge,
        path_response, ping, reset_stream, reset_stream_at, retire_connection_id, stop_sending,
        stream, stream_data_blocked, streams_blocked,
    };
    match frame {
        Frame::Padding(frame) => padding::codec::write_padding(io, frame).await,
        Frame::Ping(frame) => ping::codec::write_ping(io, frame).await,
        Frame::Ack(frame) => ack::codec::write_ack(io, frame).await,
        Frame::ResetStream(frame) => reset_stream::codec::write_reset_stream(io, frame).await,
        Frame::StopSending(frame) => stop_sending::codec::write_stop_sending(io, frame).await,
        Frame::Crypto(frame) => crypto::codec::write_crypto(io, frame).await,
        Frame::NewToken(frame) => new_token::codec::write_new_token(io, frame).await,
        Frame::Stream(frame) => stream::codec::write_stream(io, frame).await,
        Frame::MaxData(frame) => max_data::codec::write_max_data(io, frame).await,
        Frame::MaxStreamData(frame) => {
            max_stream_data::codec::write_max_stream_data(io, frame).await
        }
        Frame::MaxStreams(frame) => max_streams::codec::write_max_streams(io, frame).await,
        Frame::DataBlocked(frame) => data_blocked::codec::write_data_blocked(io, frame).await,
        Frame::StreamDataBlocked(frame) => {
            stream_data_blocked::codec::write_stream_data_blocked(io, frame).await
        }
        Frame::StreamsBlocked(frame) => {
            streams_blocked::codec::write_streams_blocked(io, frame).await
        }
        Frame::NewConnectionId(frame) => {
            new_connection_id::codec::write_new_connection_id(io, frame).await
        }
        Frame::RetireConnectionId(frame) => {
            retire_connection_id::codec::write_retire_connection_id(io, frame).await
        }
        Frame::PathChallenge(frame) => path_challenge::codec::write_path_challenge(io, frame).await,
        Frame::PathResponse(frame) => path_response::codec::write_path_response(io, frame).await,
        Frame::ConnectionClose(frame) => {
            connection_close::codec::write_connection_close(io, frame).await
        }
        Frame::HandshakeDone(frame) => handshake_done::codec::write_handshake_done(io, frame).await,
        Frame::ResetStreamAt(frame) => {
            reset_stream_at::codec::write_reset_stream_at(io, frame).await
        }
        Frame::Datagram(frame) => datagram::codec::write_datagram(io, frame).await,
    }
}
