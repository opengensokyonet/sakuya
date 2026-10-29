//! Reading and writing frames as `nitori_call` operations.
//!
//! These operations work on any `nitori_io` source or sink, including ones
//! that may wait between bytes. They read and write the same encoding as the
//! slice entry points of [`frame`](super):
//!
//! - [`read_frame_type`] reads a Frame Type and checks that it is known and
//!   enabled.
//! - [`read_fixed_frame`] reads the rest of a frame whose fields all have a
//!   fixed length or are variable-length integers: PADDING, PING,
//!   RESET_STREAM, STOP_SENDING, MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS,
//!   DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED, RETIRE_CONNECTION_ID,
//!   PATH_CHALLENGE, PATH_RESPONSE, HANDSHAKE_DONE and RESET_STREAM_AT.
//! - [`read_crypto_header`] and [`read_stream_header`] read the fields of a
//!   CRYPTO or STREAM frame up to its data. The data is then read with
//!   `nitori_io`'s `read_chunks_exact` for the stated length, or for a STREAM
//!   frame without a Length field with `read_chunks` to the end of the
//!   source, which yield the data as `ReadChunk` chunks without collecting it.
//! - [`write_frame`] writes any [`Frame`], after the checks of
//!   [`Frame::validate`].
//!
//! Each function is also an operation struct, such as [`ReadFrameType`], with
//! `{Name}Ext` on receiver accesses inside other operations and
//! `{Name}HostExt` on call executors, including the `sync_` methods for
//! receivers that never wait. Constructing an operation performs no IO.
//!
//! Unlike [`Frame::encode`], [`write_frame`] cannot check the room of the
//! sink in advance: if the sink stops accepting bytes, the bytes accepted
//! before stay written, and [`WriteFrameError::completed`] reports how many.
//!
//! ```
//! use sakuya_wire::frame::{
//!     Extensions, Frame, MaxData,
//!     calls::{ReadFixedFrameHostExt as _, ReadFrameTypeHostExt as _, WriteFrameHostExt as _},
//! };
//! use sakuya_wire::var_int::VarInt;
//!
//! let frame = Frame::MaxData(MaxData { maximum_data: VarInt::from(1_000_000u32) });
//! let mut output = Vec::new();
//! output.sync_write_frame_unpin(&frame).unwrap();
//!
//! let mut input = output.as_slice();
//! let frame_type = input.sync_read_frame_type_unpin(Extensions::NONE).unwrap();
//! assert_eq!(input.sync_read_fixed_frame_unpin(frame_type).unwrap(), frame);
//! assert!(input.is_empty());
//! ```
// `#[call]` generates constructors, fields and extension traits without
// documentation comments; the module documentation above describes them.
#![allow(missing_docs)]

use super::{
    DataBlocked, Extensions, Frame, FrameType, HandshakeDone, MaxData, MaxStreamData, MaxStreams,
    PATH_DATA_LEN, Padding, PathChallenge, PathResponse, Ping, ResetStream, ResetStreamAt,
    RetireConnectionId, StopSending, StreamDataBlocked, StreamsBlocked,
    decode::directionality,
    each_frame,
    encode::{AckFields, Body, HEAD_MAX, put_var_int},
    stream_bits, type_value,
};
use crate::{
    frame::{InvalidFrameError, MAX_STREAM_COUNT},
    stream_id::StreamId,
    var_int::{
        VarInt,
        calls::{ReadVarIntError, ReadVarIntExt as _},
    },
};
use core::num::NonZeroUsize;
use nitori_call::{ReceiverAccess, call};
use nitori_io::{
    calls::{ReadArrayError, WriteAllError},
    error::WriteZero,
    prelude::*,
};
use snafu::{IntoError, ResultExt, Snafu};

/// Reads a Frame Type and checks that it is known and, for an extension
/// frame, enabled in `extensions`.
///
/// # Errors
///
/// [`ReadFrameTypeError::Field`] if the type cannot be read, and
/// [`ReadFrameTypeError::UnknownType`] for an unknown or disabled type,
/// which corresponds to FRAME_ENCODING_ERROR.
#[call(sync)]
pub async fn read_frame_type<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    extensions: Extensions,
) -> Result<VarInt, ReadFrameTypeError<F::Error>> {
    let frame_type = io
        .read_var_int()
        .await
        .context(read_frame_type_error::FieldSnafu)?;
    match FrameType::of(frame_type) {
        Some(kind) if extensions.permits(kind) => Ok(frame_type),
        _ => read_frame_type_error::UnknownTypeSnafu { frame_type }.fail(),
    }
}

/// Failures that [`read_frame_type`] can produce.
#[derive(Debug, Snafu)]
#[snafu(module(read_frame_type_error), visibility(pub(crate)))]
pub enum ReadFrameTypeError<E> {
    /// The Frame Type could not be read.
    #[snafu(display("frame type read failed"))]
    Field {
        /// The failure of reading the variable-length integer.
        source: ReadVarIntError<E>,
    },
    /// The frame type is neither defined nor an enabled extension.
    #[snafu(display("unknown frame type {:#x}", frame_type.get()))]
    UnknownType {
        /// The Frame Type.
        frame_type: VarInt,
    },
}

/// Reads the fields that follow the Frame Type `frame_type` of a frame whose
/// fields all have a fixed length or are variable-length integers.
///
/// Returns the frame. A PADDING type yields a [`Padding`] of length 1: the
/// operation reads nothing after the type, so consecutive PADDING frames are
/// read one at a time. The type is not checked against the enabled
/// extensions; [`read_frame_type`] does that.
///
/// # Errors
///
/// [`ReadFixedFrameError::NotFixed`] for any other type, without reading;
/// [`ReadFixedFrameError::Field`] and [`ReadFixedFrameError::PathData`] if a
/// field cannot be read; [`ReadFixedFrameError::StreamCount`] and
/// [`ReadFixedFrameError::ReliableSize`] for values that break a limit of the
/// encoding, which correspond to FRAME_ENCODING_ERROR.
#[call(sync)]
pub async fn read_fixed_frame<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    frame_type: VarInt,
) -> Result<Frame<'static>, ReadFixedFrameError<F::Error>> {
    use type_value::*;
    let value = frame_type.get();
    Ok(match value {
        PADDING => Frame::Padding(Padding {
            len: NonZeroUsize::MIN,
        }),
        PING => Frame::Ping(Ping),
        RESET_STREAM => Frame::ResetStream(ResetStream {
            stream_id: field(io).await?.into(),
            application_error_code: field(io).await?,
            final_size: field(io).await?,
        }),
        STOP_SENDING => Frame::StopSending(StopSending {
            stream_id: field(io).await?.into(),
            application_error_code: field(io).await?,
        }),
        MAX_DATA => Frame::MaxData(MaxData {
            maximum_data: field(io).await?,
        }),
        MAX_STREAM_DATA => Frame::MaxStreamData(MaxStreamData {
            stream_id: field(io).await?.into(),
            maximum_stream_data: field(io).await?,
        }),
        MAX_STREAMS_BIDI | MAX_STREAMS_UNI => Frame::MaxStreams(MaxStreams {
            directionality: directionality(value == MAX_STREAMS_UNI),
            maximum_streams: stream_count(io, frame_type).await?,
        }),
        DATA_BLOCKED => Frame::DataBlocked(DataBlocked {
            maximum_data: field(io).await?,
        }),
        STREAM_DATA_BLOCKED => Frame::StreamDataBlocked(StreamDataBlocked {
            stream_id: field(io).await?.into(),
            maximum_stream_data: field(io).await?,
        }),
        STREAMS_BLOCKED_BIDI | STREAMS_BLOCKED_UNI => Frame::StreamsBlocked(StreamsBlocked {
            directionality: directionality(value == STREAMS_BLOCKED_UNI),
            maximum_streams: stream_count(io, frame_type).await?,
        }),
        RETIRE_CONNECTION_ID => Frame::RetireConnectionId(RetireConnectionId {
            sequence_number: field(io).await?,
        }),
        PATH_CHALLENGE => Frame::PathChallenge(PathChallenge {
            data: path_data(io).await?,
        }),
        PATH_RESPONSE => Frame::PathResponse(PathResponse {
            data: path_data(io).await?,
        }),
        HANDSHAKE_DONE => Frame::HandshakeDone(HandshakeDone),
        RESET_STREAM_AT => {
            let stream_id = field(io).await?.into();
            let application_error_code = field(io).await?;
            let final_size = field(io).await?;
            let reliable_size = field(io).await?;
            if reliable_size > final_size {
                return read_fixed_frame_error::ReliableSizeSnafu {
                    final_size,
                    reliable_size,
                }
                .fail();
            }
            Frame::ResetStreamAt(ResetStreamAt {
                stream_id,
                application_error_code,
                final_size,
                reliable_size,
            })
        }
        _ => return read_fixed_frame_error::NotFixedSnafu { frame_type }.fail(),
    })
}

async fn field<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> Result<VarInt, ReadFixedFrameError<F::Error>> {
    io.read_var_int()
        .await
        .context(read_fixed_frame_error::FieldSnafu)
}

async fn path_data<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> Result<[u8; PATH_DATA_LEN], ReadFixedFrameError<F::Error>> {
    io.read_array::<PATH_DATA_LEN>()
        .await
        .context(read_fixed_frame_error::PathDataSnafu)
}

async fn stream_count<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    frame_type: VarInt,
) -> Result<VarInt, ReadFixedFrameError<F::Error>> {
    let maximum_streams = field(io).await?;
    if maximum_streams.get() > MAX_STREAM_COUNT {
        return read_fixed_frame_error::StreamCountSnafu {
            frame_type,
            maximum_streams,
        }
        .fail();
    }
    Ok(maximum_streams)
}

/// Failures that [`read_fixed_frame`] can produce.
#[derive(Debug, Snafu)]
#[snafu(module(read_fixed_frame_error), visibility(pub(crate)))]
pub enum ReadFixedFrameError<E> {
    /// The frame type has a payload, ACK ranges, or is unknown.
    #[snafu(display("frame type {:#x} does not have only fixed fields", frame_type.get()))]
    NotFixed {
        /// The Frame Type.
        frame_type: VarInt,
    },
    /// A variable-length integer field could not be read.
    #[snafu(display("frame field read failed"))]
    Field {
        /// The failure of reading the field.
        source: ReadVarIntError<E>,
    },
    /// The data of PATH_CHALLENGE or PATH_RESPONSE could not be read.
    #[snafu(display("path validation data read failed"))]
    PathData {
        /// The failure of reading the data.
        source: ReadArrayError<E>,
    },
    /// A MAX_STREAMS or STREAMS_BLOCKED count exceeds 2<sup>60</sup>.
    #[snafu(display("stream count {maximum_streams} exceeds 2^60"))]
    StreamCount {
        /// The Frame Type.
        frame_type: VarInt,
        /// The Maximum Streams field.
        maximum_streams: VarInt,
    },
    /// A RESET_STREAM_AT reliable size exceeds its final size.
    #[snafu(display("reliable size {reliable_size} is beyond final size {final_size}"))]
    ReliableSize {
        /// The Final Size field.
        final_size: VarInt,
        /// The Reliable Size field.
        reliable_size: VarInt,
    },
}

/// The fields of a CRYPTO frame before its data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CryptoHeader {
    /// The Offset field.
    pub offset: VarInt,
    /// The Length field: the number of data bytes that follow.
    pub length: VarInt,
}

/// Reads the Offset and Length fields that follow the Frame Type of a CRYPTO
/// frame, and nothing after them.
///
/// # Errors
///
/// [`ReadCryptoHeaderError::Field`] if a field cannot be read, and
/// [`ReadCryptoHeaderError::DataEnd`] if the data would end beyond
/// 2<sup>62</sup> − 1, which corresponds to FRAME_ENCODING_ERROR.
#[call(sync)]
pub async fn read_crypto_header<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> Result<CryptoHeader, ReadCryptoHeaderError<F::Error>> {
    let offset = io
        .read_var_int()
        .await
        .context(read_crypto_header_error::FieldSnafu)?;
    let length = io
        .read_var_int()
        .await
        .context(read_crypto_header_error::FieldSnafu)?;
    if offset.checked_add(length).is_none() {
        return read_crypto_header_error::DataEndSnafu { offset, length }.fail();
    }
    Ok(CryptoHeader { offset, length })
}

/// Failures that [`read_crypto_header`] can produce.
#[derive(Debug, Snafu)]
#[snafu(module(read_crypto_header_error), visibility(pub(crate)))]
pub enum ReadCryptoHeaderError<E> {
    /// A field could not be read.
    #[snafu(display("CRYPTO field read failed"))]
    Field {
        /// The failure of reading the field.
        source: ReadVarIntError<E>,
    },
    /// The data would end beyond 2<sup>62</sup> − 1.
    #[snafu(display("CRYPTO data at offset {offset} of length {length} ends beyond 2^62 - 1"))]
    DataEnd {
        /// The Offset field.
        offset: VarInt,
        /// The Length field.
        length: VarInt,
    },
}

/// The fields of a STREAM frame before its data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamHeader {
    /// The Stream ID field.
    pub stream_id: StreamId,
    /// The Offset field, or zero without the OFF bit.
    pub offset: VarInt,
    /// The Length field, or `None` without the LEN bit, in which case the
    /// data extends to the end of the packet.
    pub length: Option<VarInt>,
    /// Whether the FIN bit is set.
    pub fin: bool,
}

/// Reads the fields that follow the STREAM Frame Type `frame_type`, up to
/// the data, and nothing after them.
///
/// Without a Length field the end of the data is known only once it has been
/// read to the end of the source; the caller then checks it with
/// [`StreamHeader::offset`] against 2<sup>62</sup> − 1.
///
/// # Errors
///
/// [`ReadStreamHeaderError::NotStream`] for a type outside `0x08..=0x0f`,
/// without reading; [`ReadStreamHeaderError::Field`] if a field cannot be
/// read; and [`ReadStreamHeaderError::DataEnd`] if a Length field makes the
/// data end beyond 2<sup>62</sup> − 1, which corresponds to
/// FRAME_ENCODING_ERROR.
#[call(sync)]
pub async fn read_stream_header<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    frame_type: VarInt,
) -> Result<StreamHeader, ReadStreamHeaderError<F::Error>> {
    let value = frame_type.get();
    if FrameType::of(frame_type) != Some(FrameType::Stream) {
        return read_stream_header_error::NotStreamSnafu { frame_type }.fail();
    }
    let stream_id = io
        .read_var_int()
        .await
        .context(read_stream_header_error::FieldSnafu)?
        .into();
    let offset = if value & stream_bits::OFF != 0 {
        io.read_var_int()
            .await
            .context(read_stream_header_error::FieldSnafu)?
    } else {
        VarInt::ZERO
    };
    let length = if value & stream_bits::LEN != 0 {
        let length = io
            .read_var_int()
            .await
            .context(read_stream_header_error::FieldSnafu)?;
        if offset.checked_add(length).is_none() {
            return read_stream_header_error::DataEndSnafu { offset, length }.fail();
        }
        Some(length)
    } else {
        None
    };
    Ok(StreamHeader {
        stream_id,
        offset,
        length,
        fin: value & stream_bits::FIN != 0,
    })
}

/// Failures that [`read_stream_header`] can produce.
#[derive(Debug, Snafu)]
#[snafu(module(read_stream_header_error), visibility(pub(crate)))]
pub enum ReadStreamHeaderError<E> {
    /// The frame type is not a STREAM type.
    #[snafu(display("frame type {:#x} is not a STREAM type", frame_type.get()))]
    NotStream {
        /// The Frame Type.
        frame_type: VarInt,
    },
    /// A field could not be read.
    #[snafu(display("STREAM field read failed"))]
    Field {
        /// The failure of reading the field.
        source: ReadVarIntError<E>,
    },
    /// The data would end beyond 2<sup>62</sup> − 1.
    #[snafu(display("STREAM data at offset {offset} of length {length} ends beyond 2^62 - 1"))]
    DataEnd {
        /// The Offset field.
        offset: VarInt,
        /// The Length field.
        length: VarInt,
    },
}

/// Writes `frame` completely, after checking it with [`Frame::validate`].
///
/// Acceptance by the receiver does not imply flushing or delivery.
///
/// # Errors
///
/// [`WriteFrameError::Invalid`] before writing anything if the frame breaks
/// a limit of the encoding; [`WriteFrameError::WriteZero`] if the receiver
/// accepts nothing from a nonempty remainder, and
/// [`WriteFrameError::Receiver`] if it fails. Bytes accepted before a failure
/// stay written; [`WriteFrameError::completed`] reports how many there were.
#[call(sync)]
pub async fn write_frame<F: Write, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    frame: &Frame<'_>,
) -> Result<(), WriteFrameError<F::Error>> {
    frame.validate()?;
    let mut written = 0;
    match frame {
        Frame::Padding(padding) => {
            let zeros = [0; HEAD_MAX];
            let mut left = padding.len.get();
            while left > 0 {
                let count = left.min(HEAD_MAX);
                put(io, &zeros[..count], &mut written).await?;
                left -= count;
            }
        }
        Frame::Ack(ack) => {
            let fields = AckFields::of(ack.ranges.clone());
            for value in ack.values(&fields) {
                let mut encoding = [0; VarInt::MAX_ENCODED_LEN];
                let length = fill(&mut encoding, |buffer| {
                    put_var_int(buffer, VarInt::new(value).unwrap_or(VarInt::MAX));
                });
                put(io, &encoding[..length], &mut written).await?;
            }
        }
        _ => {
            let (head, head_len, payload) = each_frame!(frame, body => split(body));
            put(io, &head[..head_len], &mut written).await?;
            put(io, payload, &mut written).await?;
        }
    }
    Ok(())
}

/// Writes into `bytes` with `write` and returns how many bytes it wrote.
fn fill<const LEN: usize>(bytes: &mut [u8; LEN], write: impl FnOnce(&mut &mut [u8])) -> usize {
    let mut cursor = &mut bytes[..];
    write(&mut cursor);
    LEN - cursor.len()
}

/// The head of a validated frame other than PADDING and ACK, which fits
/// [`HEAD_MAX`], and its payload.
fn split<T: Body + ?Sized>(body: &T) -> ([u8; HEAD_MAX], usize, &[u8]) {
    let mut head = [0; HEAD_MAX];
    let length = fill(&mut head, |buffer| body.put_head(buffer));
    (head, length, body.payload())
}

async fn put<F: Write, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    bytes: &[u8],
    written: &mut usize,
) -> Result<(), WriteFrameError<F::Error>> {
    let result = io.write_all(bytes).await;
    let completed = *written
        + result
            .as_ref()
            .map_or_else(WriteAllError::completed, |()| bytes.len());
    *written = completed;
    result.map_err(|error| match error {
        WriteAllError::WriteZero { .. } => WriteZero { completed }.into(),
        WriteAllError::Receiver { source, .. } => {
            write_frame_error::ReceiverSnafu { completed }.into_error(source)
        }
    })
}

/// Failures that [`write_frame`] can produce.
#[derive(Debug, Snafu)]
#[snafu(module(write_frame_error), visibility(pub(crate)))]
pub enum WriteFrameError<E> {
    /// The frame breaks a limit of the encoding; nothing was written.
    #[snafu(transparent)]
    Invalid {
        /// The broken limit.
        source: InvalidFrameError,
    },
    /// The receiver accepted nothing from a nonempty remainder.
    #[snafu(transparent)]
    WriteZero {
        /// The bytes of the frame accepted before the receiver stopped
        /// accepting.
        source: WriteZero,
    },
    /// The receiver failed.
    #[snafu(display("frame write failed after {completed} bytes"))]
    Receiver {
        /// The receiver's error.
        source: E,
        /// Bytes of the frame accepted before the failure.
        completed: usize,
    },
}

impl<E> WriteFrameError<E> {
    /// Bytes of the frame accepted before the failure.
    pub fn completed(&self) -> usize {
        match self {
            Self::Invalid { .. } => 0,
            Self::WriteZero { source } => source.completed,
            Self::Receiver { completed, .. } => *completed,
        }
    }

    /// The receiver's error, if the failure came from the receiver.
    pub fn host_error(&self) -> Option<&E> {
        match self {
            Self::Receiver { source, .. } => Some(source),
            Self::Invalid { .. } | Self::WriteZero { .. } => None,
        }
    }
}
