//! QUIC version 1 frames ([RFC 9000 §19]) and two negotiated extensions.
//!
//! The payload of a QUIC packet, once packet protection is removed, is a
//! sequence of frames, each starting with a Frame Type field. A frame never
//! extends past the end of its packet ([RFC 9000 §12.4]), so frames are read
//! from a source that holds the complete payload of one packet: a frame that
//! the payload cuts short is a terminal incomplete failure, not a reason to
//! wait for more bytes.
//!
//! Besides the frames of RFC 9000, two extensions are supported:
//!
//! - DATAGRAM ([RFC 9221]), types `0x30` and `0x31`;
//! - RESET_STREAM_AT, type `0x24`, as specified by the Internet-Draft
//!   [draft-ietf-quic-reliable-stream-reset-11]. The draft is not an RFC and
//!   may still change.
//!
//! Which extensions the peers negotiated is a run-time fact: reading takes an
//! [`Extensions`] set, and rejects a frame of an extension that is not in the
//! set. Like an unknown frame type, that is a FRAME_ENCODING_ERROR
//! ([RFC 9000 §12.4]), except for DATAGRAM, for which [RFC 9221] requires
//! PROTOCOL_VIOLATION.
//!
//! Each frame type has its own module with its struct, the checks its
//! encoding imposes, and its write operation. [`Frame`] holds any of them.
//!
//! # Frame values and their encoding
//!
//! A frame value states every detail of its encoding, and converts to bytes
//! and back without loss: reading a frame and writing it again reproduces
//! the bytes that were read, and writing a frame and reading it back gives
//! the same value.
//!
//! - Each variable-length integer field is a [`VarIntField`]: its value and
//!   the width of its encoding, 1, 2, 4 or 8 bytes. Reading keeps the width
//!   it finds; writing uses the width the field holds, which need not be the
//!   shortest. [`VarIntField::shortest`] gives the shortest encoding that a
//!   sender normally uses.
//! - A Length field whose value is the length of a payload field (the Length
//!   of CRYPTO, STREAM and DATAGRAM, the Token Length of NEW_TOKEN, the
//!   Reason Phrase Length of CONNECTION_CLOSE) stores only its width; the
//!   ACK Range Count of ACK likewise.
//! - Optional fields are present or absent as the Frame Type announces them.
//!   The Offset of STREAM is an `Option`, so a STREAM frame with the OFF bit
//!   set and offset 0 is distinct from one without the bit.
//! - Whether a STREAM or DATAGRAM frame has a Length field is stated by the
//!   type parameter `L` of [`stream::Stream`] and [`datagram::Datagram`], a
//!   [`LengthKind`] of one of four types: [`VarIntWidth`], for a frame with
//!   a Length field of that width; [`NoLength`], for a frame without one,
//!   whose data extends to the end of the packet; and
//!   [`Either<NoLength, VarIntWidth>`](Either) and
//!   [`Either<VarIntWidth, NoLength>`](Either), of the `either` crate, for
//!   either of the two. `Either<NoLength, VarIntWidth>` is the default and
//!   what reading gives, since only the Frame Type that was read tells which
//!   it is. The kinds convert into one another with `From` as
//!   [`LengthKind`] describes. A frame with a Length field is constructed by
//!   `with_length`, one without by `without_length`, and one as reading
//!   gives it by `new`; each of these kinds has its own write operation, so
//!   a writer that knows which kind it writes states it in the type.
//! - An ACK frame holds its fields as encoded, and owns its ACK Ranges in
//!   [`ack::AckRanges`]; [`ack::Ack::packet_ranges`] computes the
//!   acknowledged packet numbers from them.
//!
//! The Frame Type is the exception: it must use its shortest encoding
//! ([RFC 9000 §12.4]), so a frame value does not store its width. Reading
//! rejects a longer encoding, and writing always uses the shortest.
//!
//! Every frame is checked when it is constructed. Some limits tie fields of
//! one frame together: the end of STREAM and CRYPTO data is at most
//! 2<sup>62</sup> − 1, the width of a Length field can state the length of
//! its payload, a NEW_TOKEN token is not empty, the Retire Prior To of
//! NEW_CONNECTION_ID does not exceed its Sequence Number, the Reliable Size
//! of RESET_STREAM_AT does not exceed its Final Size, no range of an ACK
//! frame extends below packet number 0, and the ACK Range Count field of ACK
//! can state the number of ACK Ranges. The constructors of these frame
//! types, such as [`stream::Stream::with_length`] and [`ack::Ack::new`],
//! return an error for fields that break one; a DATAGRAM frame without a
//! Length field has no such limit. The other frame types have no such limit,
//! and their `new`, such as [`max_data::MaxData::new`], accepts any fields. The
//! fields of every frame type are private and are read through methods of
//! the same names, so every frame value converts to bytes and back without
//! loss.
//!
//! # Reading
//!
//! [`codec::read_frame`] reads one frame as a `nitori_call` operation.
//! [`Frames`] walks a packet payload held by a byte slice or `Bytes`, frame
//! by frame, without collecting the frames first. Payload fields are chunks
//! of the source, of the type parameter `D`: subslices of a byte slice and
//! `Bytes` that share the storage of a `Bytes` source, so reading copies no
//! payload. These are STREAM, CRYPTO and DATAGRAM data, NEW_TOKEN tokens and
//! CONNECTION_CLOSE reason phrases. The ACK Ranges of an ACK frame are
//! collected into [`ack::AckRanges`].
//!
//! Reading checks what the encoding alone determines: that every field is
//! present, the limits the frame definitions state for single fields, and
//! the limits that tie fields of one frame together. Each frame is
//! constructed through its `new`, so a frame that was read meets the same
//! limits as one constructed to be written. A broken limit is reported as
//! soon as the fields it depends on are read: the end of STREAM or CRYPTO
//! data before the data, and an ACK range below packet number 0 before the
//! ACK Ranges that follow it. Whether a frame is allowed in the packet type,
//! whether a stream exists or may be opened, and flow control are for the
//! receiver of the frame to check.
//!
//! Each failure has a variant of its own. Besides the failures of the Frame
//! Type, [`codec::ReadFrameError`] has a variant for each frame type, which
//! holds the error of that type; ACK and CONNECTION_CLOSE have one for each
//! of their two Frame Type values, whose fields differ, such as
//! [`codec::ReadFrameError::AckEcn`] for an ACK frame with ECN counts. The
//! error of a frame type has a variant for
//! each field that cannot be read, named after the field, such as
//! [`ack::codec::ReadAckError::LargestAcknowledged`]; the Gap and ACK Range
//! Length of an ACK Range carry the position of their ACK Range. Each
//! broken limit has a variant of its own as well, named after the rule,
//! such as
//! [`new_connection_id::codec::ReadNewConnectionIdError::RetirePriorToAboveSequenceNumber`].
//!
//! Every [`codec::ReadFrameError`] corresponds to FRAME_ENCODING_ERROR, with
//! two exceptions that correspond to PROTOCOL_VIOLATION
//! ([`codec::ReadFrameError::transport_error_code`]): a Frame Type encoded
//! longer than necessary ([RFC 9000 §12.4]), and a DATAGRAM frame that is
//! not enabled ([RFC 9221]).
//!
//! ```
//! use either::Either;
//! use sakuya_wire::{
//!     frame::{Extensions, Frame, Frames},
//!     var_int::VarIntWidth,
//! };
//!
//! // PING, then a STREAM frame with LEN and FIN on stream 4, whose Stream ID
//! // takes two bytes.
//! let payload = [0x01, 0x0b, 0x40, 0x04, 0x02, b'h', b'i'];
//! let mut frames = Frames::new(&payload[..], Extensions::NONE);
//! assert!(matches!(frames.next(), Some(Ok(Frame::Ping(_)))));
//! let Some(Ok(Frame::Stream(stream))) = frames.next() else { panic!() };
//! assert_eq!(stream.stream_id().get().index(), 1);
//! assert_eq!(stream.stream_id().width(), VarIntWidth::Two);
//! assert_eq!(stream.offset(), None);
//! assert_eq!(stream.length(), Either::Right(VarIntWidth::One));
//! assert_eq!((*stream.data(), stream.fin()), (&b"hi"[..], true));
//! assert!(frames.next().is_none());
//! ```
//!
//! # Writing
//!
//! Every frame type has `encoded_len` and a write operation in its module's
//! `codec`, such as [`stream::codec::write_stream`], and STREAM and DATAGRAM
//! have one for each kind of Length field; [`codec::write_frame`] writes any
//! [`Frame`]. Writing writes the encoding the value states and
//! chooses nothing: the width of each field comes from the value. Every
//! frame checked its limits when it was constructed, so writing checks
//! nothing, and its only failure is that of the receiver: a sink that stops
//! accepting bytes or fails keeps the bytes it accepted, and the
//! `WriteAllError` counts them. `encoded_len`
//! gives the length in advance, so that a packet encoder can choose frames
//! and payload sizes before writing.
//! The `max_data_len` of `Stream<D, VarIntWidth>` and of
//! `Stream<D, NoLength>`, and [`crypto::Crypto::max_data_len`], give the
//! largest amount of data that fits a given room, taking into account that
//! the shortest Length field grows with the data.
//! [`ack::Ack::from_packet_ranges`] states packet number ranges as an ACK
//! frame in the shortest encodings. Payload fields are written from any
//! [`bytes::Buf`].
//!
//! A STREAM or DATAGRAM frame without a Length field extends to the end of the
//! packet; whoever writes one must not append anything after it.
//!
//! # Recovery properties
//!
//! [`FrameType::is_ack_eliciting`] and [`FrameType::counts_in_flight`] are
//! the per-frame facts from which [RFC 9002 §2] derives whether a packet is
//! ack-eliciting and whether it counts as in flight.
//!
//! [RFC 9000 §19]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19
//! [RFC 9000 §12.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4
//! [RFC 9221]: https://www.rfc-editor.org/rfc/rfc9221.html
//! [draft-ietf-quic-reliable-stream-reset-11]: https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-11.html
//! [RFC 9002 §2]: https://www.rfc-editor.org/rfc/rfc9002.html#section-2
use crate::var_int::{
    VarInt, VarIntField, VarIntWidth,
    codec::{ReadVarIntError, read_var_int_field},
};
use bytes::Buf;
use core::{convert::Infallible, iter::FusedIterator};
use either::Either;
use nitori_call::{Direct, Receiver, ReceiverAccess};
use nitori_io::{Read, ReadChunk};
use snafu::Snafu;

pub mod ack;
pub mod codec;
pub mod connection_close;
pub mod crypto;
pub mod data_blocked;
pub mod datagram;
pub mod handshake_done;
pub mod max_data;
pub mod max_stream_data;
pub mod max_streams;
pub mod new_connection_id;
pub mod new_token;
pub mod padding;
pub mod path_challenge;
pub mod path_response;
pub mod ping;
pub mod reset_stream;
pub mod reset_stream_at;
pub mod retire_connection_id;
pub mod stop_sending;
pub mod stream;
pub mod stream_data_blocked;
pub mod streams_blocked;

#[cfg(test)]
mod tests;

/// Frame Type values.
pub(crate) mod type_value {
    pub(crate) const PADDING: u64 = 0x00;
    pub(crate) const PING: u64 = 0x01;
    pub(crate) const ACK: u64 = 0x02;
    pub(crate) const ACK_ECN: u64 = 0x03;
    pub(crate) const RESET_STREAM: u64 = 0x04;
    pub(crate) const STOP_SENDING: u64 = 0x05;
    pub(crate) const CRYPTO: u64 = 0x06;
    pub(crate) const NEW_TOKEN: u64 = 0x07;
    pub(crate) const STREAM: u64 = 0x08;
    pub(crate) const MAX_DATA: u64 = 0x10;
    pub(crate) const MAX_STREAM_DATA: u64 = 0x11;
    pub(crate) const MAX_STREAMS_BIDI: u64 = 0x12;
    pub(crate) const MAX_STREAMS_UNI: u64 = 0x13;
    pub(crate) const DATA_BLOCKED: u64 = 0x14;
    pub(crate) const STREAM_DATA_BLOCKED: u64 = 0x15;
    pub(crate) const STREAMS_BLOCKED_BIDI: u64 = 0x16;
    pub(crate) const STREAMS_BLOCKED_UNI: u64 = 0x17;
    pub(crate) const NEW_CONNECTION_ID: u64 = 0x18;
    pub(crate) const RETIRE_CONNECTION_ID: u64 = 0x19;
    pub(crate) const PATH_CHALLENGE: u64 = 0x1a;
    pub(crate) const PATH_RESPONSE: u64 = 0x1b;
    pub(crate) const CONNECTION_CLOSE: u64 = 0x1c;
    pub(crate) const CONNECTION_CLOSE_APPLICATION: u64 = 0x1d;
    pub(crate) const HANDSHAKE_DONE: u64 = 0x1e;
    pub(crate) const RESET_STREAM_AT: u64 = 0x24;
    pub(crate) const DATAGRAM: u64 = 0x30;
    pub(crate) const DATAGRAM_WITH_LENGTH: u64 = 0x31;
}

/// A Frame Type value as a variable-length integer; every value above is
/// below 2<sup>6</sup>.
pub(crate) const fn type_var_int(value: u64) -> VarInt {
    VarInt::from_u32(value as u32)
}

/// The length of the data of PATH_CHALLENGE and PATH_RESPONSE.
pub const PATH_DATA_LEN: usize = 8;

/// The kind of a frame, as its Frame Type field announces it.
///
/// Several Frame Type values announce the same kind: the eight STREAM types
/// `0x08..=0x0f`, ACK with and without ECN counts, both CONNECTION_CLOSE
/// types, and the bidirectional and unidirectional forms of MAX_STREAMS and
/// STREAMS_BLOCKED. The variants are named after the frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FrameType {
    /// PADDING, `0x00`.
    Padding,
    /// PING, `0x01`.
    Ping,
    /// ACK, `0x02` and `0x03`.
    Ack,
    /// RESET_STREAM, `0x04`.
    ResetStream,
    /// STOP_SENDING, `0x05`.
    StopSending,
    /// CRYPTO, `0x06`.
    Crypto,
    /// NEW_TOKEN, `0x07`.
    NewToken,
    /// STREAM, `0x08..=0x0f`.
    Stream,
    /// MAX_DATA, `0x10`.
    MaxData,
    /// MAX_STREAM_DATA, `0x11`.
    MaxStreamData,
    /// MAX_STREAMS, `0x12` and `0x13`.
    MaxStreams,
    /// DATA_BLOCKED, `0x14`.
    DataBlocked,
    /// STREAM_DATA_BLOCKED, `0x15`.
    StreamDataBlocked,
    /// STREAMS_BLOCKED, `0x16` and `0x17`.
    StreamsBlocked,
    /// NEW_CONNECTION_ID, `0x18`.
    NewConnectionId,
    /// RETIRE_CONNECTION_ID, `0x19`.
    RetireConnectionId,
    /// PATH_CHALLENGE, `0x1a`.
    PathChallenge,
    /// PATH_RESPONSE, `0x1b`.
    PathResponse,
    /// CONNECTION_CLOSE, `0x1c` and `0x1d`.
    ConnectionClose,
    /// HANDSHAKE_DONE, `0x1e`.
    HandshakeDone,
    /// RESET_STREAM_AT, `0x24`, of draft-ietf-quic-reliable-stream-reset-11.
    ResetStreamAt,
    /// DATAGRAM, `0x30` and `0x31`, of RFC 9221.
    Datagram,
}

impl FrameType {
    /// The kind a Frame Type value announces.
    ///
    /// This is the `const` form of `FrameType::try_from(value)`.
    ///
    /// # Errors
    ///
    /// [`UnknownFrameTypeError`] for a value neither RFC 9000 nor a
    /// supported extension defines.
    pub const fn of(value: VarInt) -> Result<Self, UnknownFrameTypeError> {
        use type_value::*;
        Ok(match value.get() {
            PADDING => Self::Padding,
            PING => Self::Ping,
            ACK | ACK_ECN => Self::Ack,
            RESET_STREAM => Self::ResetStream,
            STOP_SENDING => Self::StopSending,
            CRYPTO => Self::Crypto,
            NEW_TOKEN => Self::NewToken,
            0x08..=0x0f => Self::Stream,
            MAX_DATA => Self::MaxData,
            MAX_STREAM_DATA => Self::MaxStreamData,
            MAX_STREAMS_BIDI | MAX_STREAMS_UNI => Self::MaxStreams,
            DATA_BLOCKED => Self::DataBlocked,
            STREAM_DATA_BLOCKED => Self::StreamDataBlocked,
            STREAMS_BLOCKED_BIDI | STREAMS_BLOCKED_UNI => Self::StreamsBlocked,
            NEW_CONNECTION_ID => Self::NewConnectionId,
            RETIRE_CONNECTION_ID => Self::RetireConnectionId,
            PATH_CHALLENGE => Self::PathChallenge,
            PATH_RESPONSE => Self::PathResponse,
            CONNECTION_CLOSE | CONNECTION_CLOSE_APPLICATION => Self::ConnectionClose,
            HANDSHAKE_DONE => Self::HandshakeDone,
            RESET_STREAM_AT => Self::ResetStreamAt,
            DATAGRAM | DATAGRAM_WITH_LENGTH => Self::Datagram,
            // Every value not matched above is unknown.
            _ => {
                return Err(UnknownFrameTypeError {
                    frame_type: UnknownTypeValue(value),
                });
            }
        })
    }

    /// Whether a packet containing this frame is ack-eliciting
    /// ([RFC 9002 §2]).
    ///
    /// Every frame except ACK, PADDING and CONNECTION_CLOSE is ack-eliciting;
    /// RFC 9221 §5.2 and the RESET_STREAM_AT draft state it for their frames.
    ///
    /// [RFC 9002 §2]: https://www.rfc-editor.org/rfc/rfc9002.html#section-2
    pub const fn is_ack_eliciting(self) -> bool {
        !matches!(self, Self::Ack | Self::Padding | Self::ConnectionClose)
    }

    /// Whether a packet containing this frame counts as in flight
    /// ([RFC 9002 §2]).
    ///
    /// A packet is in flight when it is ack-eliciting or contains PADDING;
    /// this is true for every ack-eliciting frame and for PADDING, and false
    /// for ACK and CONNECTION_CLOSE.
    ///
    /// [RFC 9002 §2]: https://www.rfc-editor.org/rfc/rfc9002.html#section-2
    pub const fn counts_in_flight(self) -> bool {
        !matches!(self, Self::Ack | Self::ConnectionClose)
    }
}

impl TryFrom<VarInt> for FrameType {
    type Error = UnknownFrameTypeError;

    /// The kind a Frame Type value announces; see [`FrameType::of`].
    fn try_from(value: VarInt) -> Result<Self, Self::Error> {
        Self::of(value)
    }
}

/// A Frame Type value is unknown: neither RFC 9000 nor a supported extension
/// defines it.
///
/// [`FrameType::of`] returns it, and reading a frame reports it as
/// [`codec::ReadFrameError::UnknownType`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("unknown frame type {:#x}", frame_type.get().get()))]
pub struct UnknownFrameTypeError {
    /// The Frame Type value.
    pub frame_type: UnknownTypeValue,
}

/// A Frame Type value that neither RFC 9000 nor a supported extension
/// defines; [`FrameType::of`] rejects exactly these values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UnknownTypeValue(VarInt);

impl UnknownTypeValue {
    /// The Frame Type value.
    pub const fn get(self) -> VarInt {
        self.0
    }
}

impl From<UnknownTypeValue> for VarInt {
    fn from(value: UnknownTypeValue) -> Self {
        value.0
    }
}

/// The extension frames a reader accepts.
///
/// Each extension is negotiated through a transport parameter. Reading
/// rejects a frame of an extension that is not enabled with
/// [`codec::ReadFrameError::ExtensionNotEnabled`]. Sending and receiving can
/// be permitted separately; pass the set that applies to the direction being
/// read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Extensions {
    /// Accept DATAGRAM frames ([RFC 9221]).
    ///
    /// [RFC 9221]: https://www.rfc-editor.org/rfc/rfc9221.html
    pub datagram: bool,
    /// Accept RESET_STREAM_AT frames (draft-ietf-quic-reliable-stream-reset-11).
    pub reset_stream_at: bool,
}

impl Extensions {
    /// No extension: only the frames of RFC 9000.
    pub const NONE: Self = Self {
        datagram: false,
        reset_stream_at: false,
    };

    /// Every supported extension.
    pub const ALL: Self = Self {
        datagram: true,
        reset_stream_at: true,
    };

    /// Whether frames of `frame_type` are accepted: always for RFC 9000
    /// frames, and for extension frames when their extension is enabled.
    pub const fn permits(self, frame_type: FrameType) -> bool {
        match frame_type {
            FrameType::Datagram => self.datagram,
            FrameType::ResetStreamAt => self.reset_stream_at,
            _ => true,
        }
    }
}

/// A frame of any type.
///
/// `D` is the type of the payload fields: the chunk type of the source a
/// frame was read from, or any [`Buf`] for a frame to write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame<D> {
    /// PADDING, one or more bytes.
    Padding(padding::Padding),
    /// A PING frame.
    Ping(ping::Ping),
    /// An ACK frame.
    Ack(ack::Ack),
    /// A RESET_STREAM frame.
    ResetStream(reset_stream::ResetStream),
    /// A STOP_SENDING frame.
    StopSending(stop_sending::StopSending),
    /// A CRYPTO frame.
    Crypto(crypto::Crypto<D>),
    /// A NEW_TOKEN frame.
    NewToken(new_token::NewToken<D>),
    /// A STREAM frame.
    Stream(stream::Stream<D>),
    /// A MAX_DATA frame.
    MaxData(max_data::MaxData),
    /// A MAX_STREAM_DATA frame.
    MaxStreamData(max_stream_data::MaxStreamData),
    /// A MAX_STREAMS frame.
    MaxStreams(max_streams::MaxStreams),
    /// A DATA_BLOCKED frame.
    DataBlocked(data_blocked::DataBlocked),
    /// A STREAM_DATA_BLOCKED frame.
    StreamDataBlocked(stream_data_blocked::StreamDataBlocked),
    /// A STREAMS_BLOCKED frame.
    StreamsBlocked(streams_blocked::StreamsBlocked),
    /// A NEW_CONNECTION_ID frame.
    NewConnectionId(new_connection_id::NewConnectionId),
    /// A RETIRE_CONNECTION_ID frame.
    RetireConnectionId(retire_connection_id::RetireConnectionId),
    /// A PATH_CHALLENGE frame.
    PathChallenge(path_challenge::PathChallenge),
    /// A PATH_RESPONSE frame.
    PathResponse(path_response::PathResponse),
    /// A CONNECTION_CLOSE frame.
    ConnectionClose(connection_close::ConnectionClose<D>),
    /// A HANDSHAKE_DONE frame.
    HandshakeDone(handshake_done::HandshakeDone),
    /// A RESET_STREAM_AT frame.
    ResetStreamAt(reset_stream_at::ResetStreamAt),
    /// A DATAGRAM frame.
    Datagram(datagram::Datagram<D>),
}

/// Applies `$body` to the frame inside each variant of a [`Frame`].
macro_rules! each_frame {
    ($frame:expr, $inner:ident => $body:expr) => {
        match $frame {
            Frame::Padding($inner) => $body,
            Frame::Ping($inner) => $body,
            Frame::Ack($inner) => $body,
            Frame::ResetStream($inner) => $body,
            Frame::StopSending($inner) => $body,
            Frame::Crypto($inner) => $body,
            Frame::NewToken($inner) => $body,
            Frame::Stream($inner) => $body,
            Frame::MaxData($inner) => $body,
            Frame::MaxStreamData($inner) => $body,
            Frame::MaxStreams($inner) => $body,
            Frame::DataBlocked($inner) => $body,
            Frame::StreamDataBlocked($inner) => $body,
            Frame::StreamsBlocked($inner) => $body,
            Frame::NewConnectionId($inner) => $body,
            Frame::RetireConnectionId($inner) => $body,
            Frame::PathChallenge($inner) => $body,
            Frame::PathResponse($inner) => $body,
            Frame::ConnectionClose($inner) => $body,
            Frame::HandshakeDone($inner) => $body,
            Frame::ResetStreamAt($inner) => $body,
            Frame::Datagram($inner) => $body,
        }
    };
}

impl<D> Frame<D> {
    /// The kind of the frame.
    pub fn frame_type(&self) -> FrameType {
        match self {
            Self::Padding(_) => FrameType::Padding,
            Self::Ping(_) => FrameType::Ping,
            Self::Ack(_) => FrameType::Ack,
            Self::ResetStream(_) => FrameType::ResetStream,
            Self::StopSending(_) => FrameType::StopSending,
            Self::Crypto(_) => FrameType::Crypto,
            Self::NewToken(_) => FrameType::NewToken,
            Self::Stream(_) => FrameType::Stream,
            Self::MaxData(_) => FrameType::MaxData,
            Self::MaxStreamData(_) => FrameType::MaxStreamData,
            Self::MaxStreams(_) => FrameType::MaxStreams,
            Self::DataBlocked(_) => FrameType::DataBlocked,
            Self::StreamDataBlocked(_) => FrameType::StreamDataBlocked,
            Self::StreamsBlocked(_) => FrameType::StreamsBlocked,
            Self::NewConnectionId(_) => FrameType::NewConnectionId,
            Self::RetireConnectionId(_) => FrameType::RetireConnectionId,
            Self::PathChallenge(_) => FrameType::PathChallenge,
            Self::PathResponse(_) => FrameType::PathResponse,
            Self::ConnectionClose(_) => FrameType::ConnectionClose,
            Self::HandshakeDone(_) => FrameType::HandshakeDone,
            Self::ResetStreamAt(_) => FrameType::ResetStreamAt,
            Self::Datagram(_) => FrameType::Datagram,
        }
    }

    /// Whether a packet containing this frame is ack-eliciting; see
    /// [`FrameType::is_ack_eliciting`].
    pub fn is_ack_eliciting(&self) -> bool {
        self.frame_type().is_ack_eliciting()
    }

    /// Whether a packet containing this frame counts as in flight; see
    /// [`FrameType::counts_in_flight`].
    pub fn counts_in_flight(&self) -> bool {
        self.frame_type().counts_in_flight()
    }

    /// The Frame Type value [`codec::write_frame`] writes.
    pub fn type_value(&self) -> VarInt {
        each_frame!(self, frame => frame.type_value())
    }
}

impl<D: Buf> Frame<D> {
    /// The number of bytes [`codec::write_frame`] writes.
    pub fn encoded_len(&self) -> usize {
        each_frame!(self, frame => frame.encoded_len())
    }
}

/// The absence of a Length field in a STREAM or DATAGRAM frame: the data
/// extends to the end of the packet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct NoLength;

mod sealed {
    use crate::var_int::VarIntWidth;

    /// Restricts [`LengthKind`](super::LengthKind) to the types of this
    /// crate.
    pub trait Sealed: Copy {
        /// The width of the Length field, or `None` without one.
        fn length_width(self) -> Option<VarIntWidth>;
    }
}

/// What a STREAM or DATAGRAM frame states about its Length field, as the
/// type parameter `L` of [`stream::Stream`] and [`datagram::Datagram`].
///
/// It is implemented by exactly four types:
///
/// - [`VarIntWidth`]: the frame has a Length field, of this width;
/// - [`NoLength`]: the frame has no Length field, and its data extends to
///   the end of the packet;
/// - [`Either<NoLength, VarIntWidth>`](Either): either of the two, as a frame
///   that was read states it. This is the default, so `Stream<D>` and
///   `Datagram<D>` are frames as they are read;
/// - [`Either<VarIntWidth, NoLength>`](Either): either of the two, in the
///   other order.
///
/// The two single kinds convert into each `Either` kind with `From`. A frame
/// of an `Either` kind converts with `From` into an `Either` of frames of
/// its two kinds, in the same order, such as
/// `Either<Stream<D, NoLength>, Stream<D, VarIntWidth>>` for `Stream<D>`,
/// and back; and into a frame of the other `Either` kind, with the sides
/// swapped.
pub trait LengthKind: sealed::Sealed {}

impl sealed::Sealed for VarIntWidth {
    fn length_width(self) -> Option<VarIntWidth> {
        Some(self)
    }
}

impl LengthKind for VarIntWidth {}

impl sealed::Sealed for NoLength {
    fn length_width(self) -> Option<VarIntWidth> {
        None
    }
}

impl LengthKind for NoLength {}

impl sealed::Sealed for Either<NoLength, VarIntWidth> {
    fn length_width(self) -> Option<VarIntWidth> {
        match self {
            Either::Left(NoLength) => None,
            Either::Right(width) => Some(width),
        }
    }
}

impl LengthKind for Either<NoLength, VarIntWidth> {}

impl sealed::Sealed for Either<VarIntWidth, NoLength> {
    fn length_width(self) -> Option<VarIntWidth> {
        match self {
            Either::Left(width) => Some(width),
            Either::Right(NoLength) => None,
        }
    }
}

impl LengthKind for Either<VarIntWidth, NoLength> {}

/// The width of the Length field that `length` states, or `None` without
/// one.
pub(crate) fn length_width<L: LengthKind>(length: L) -> Option<VarIntWidth> {
    sealed::Sealed::length_width(length)
}

/// The data of a STREAM or CRYPTO frame ends beyond 2<sup>62</sup> − 1.
///
/// It is constructed only when the check fails, so its offset plus its
/// length always exceeds 2<sup>62</sup> − 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("data at offset {offset} of length {length} ends beyond 2^62 - 1"))]
pub struct DataEndError {
    offset: VarInt,
    length: u64,
}

impl DataEndError {
    /// The Offset field.
    pub const fn offset(self) -> VarInt {
        self.offset
    }

    /// The length of the data, which ends beyond 2<sup>62</sup> − 1 after
    /// [`offset`](Self::offset).
    pub const fn length(self) -> u64 {
        self.length
    }

    /// Checks that `length` bytes of data at `offset` end at most at
    /// 2<sup>62</sup> − 1.
    pub(crate) fn check(offset: VarInt, length: u64) -> Result<(), Self> {
        if length > VarInt::MAX.get() - offset.get() {
            return Err(Self { offset, length });
        }
        Ok(())
    }

    /// The largest data length permitted after `offset`, capped to `usize`.
    pub(crate) fn limit(offset: VarInt) -> usize {
        usize::try_from(VarInt::MAX.get() - offset.get()).unwrap_or(usize::MAX)
    }
}

/// A payload field is longer than its Length field can state at the
/// field's width.
///
/// It is constructed only when the check fails, so the length always
/// exceeds what the width holds: for an 8-byte width, 2<sup>62</sup> − 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "field of {length} bytes is longer than a {}-byte Length field can state",
    width.encoded_len()
))]
pub struct LengthError {
    length: usize,
    width: VarIntWidth,
}

impl LengthError {
    /// The length of the payload field, which exceeds what
    /// [`width`](Self::width) holds.
    pub const fn length(self) -> usize {
        self.length
    }

    /// The width of the Length field.
    pub const fn width(self) -> VarIntWidth {
        self.width
    }

    /// The value of a Length field of `width` for a payload of `length`
    /// bytes.
    pub(crate) fn check(length: usize, width: VarIntWidth) -> Result<VarInt, Self> {
        match VarInt::try_from(length) {
            Ok(value) if width.fits(value) => Ok(value),
            _ => Err(Self { length, width }),
        }
    }
}

/// The data of a STREAM or CRYPTO frame breaks a limit of the encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
pub enum InvalidDataError {
    /// The data ends beyond 2<sup>62</sup> − 1.
    #[snafu(transparent)]
    DataEnd {
        /// The broken limit.
        source: DataEndError,
    },
    /// The Length field is too narrow for the length of the data.
    #[snafu(transparent)]
    Length {
        /// The broken limit.
        source: LengthError,
    },
}

/// The encoded length of the shortest Length field for `length` bytes; a
/// length above 2<sup>62</sup> − 1 counts as the longest encoding.
pub(crate) fn length_field_len(length: usize) -> usize {
    VarInt::try_from(length).map_or(VarInt::MAX_ENCODED_LEN, VarInt::encoded_len)
}

/// Reads a variable-length integer field of a type that every value
/// converts into.
pub(crate) async fn read_field<T, F, A>(
    io: &mut A,
) -> Result<VarIntField<T>, ReadVarIntError<F::Error>>
where
    T: Copy + Into<VarInt> + TryFrom<VarInt, Error = Infallible>,
    F: Read,
    A: ReceiverAccess<Family = F>,
{
    read_var_int_field(io).await.map_err(ReadVarIntError::from)
}

/// The largest `n` with `fixed + len(n) + n <= room` and `n <= limit`, where
/// `len(n)` is the length of the Length field.
pub(crate) fn max_len_with_length_field(fixed: usize, limit: usize, room: usize) -> Option<usize> {
    const CLASSES: [(usize, u64); 4] = [
        (1, (1 << 6) - 1),
        (2, (1 << 14) - 1),
        (4, (1 << 30) - 1),
        (8, (1 << 62) - 1),
    ];
    CLASSES
        .iter()
        .filter_map(|&(field_len, class_max)| {
            let left = room.checked_sub(fixed + field_len)?;
            let class_max = usize::try_from(class_max).unwrap_or(usize::MAX);
            Some(left.min(class_max).min(limit))
        })
        .max()
}

/// The fields of a frame before its payload, encoded for one write.
///
/// `N` is the longest encoding of those fields for the frame type.
pub(crate) struct Head<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> Head<N> {
    /// A head starting with the Frame Type `frame_type`.
    pub(crate) fn new(frame_type: VarInt) -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
        .var_int(frame_type)
    }

    /// Appends the shortest encoding of `value`.
    pub(crate) fn var_int(self, value: VarInt) -> Self {
        self.var_int_of(value, VarIntWidth::shortest(value))
    }

    /// Appends the encoding of `value` of `width`, which holds the value.
    pub(crate) fn var_int_of(self, value: VarInt, width: VarIntWidth) -> Self {
        let (encoding, encoded_len) = value.to_encoding_of(width);
        self.bytes(&encoding[..encoded_len])
    }

    /// Appends the encoding of `field` at its width.
    pub(crate) fn field<T>(self, field: VarIntField<T>) -> Self
    where
        T: Copy + Into<VarInt> + TryFrom<VarInt>,
    {
        self.var_int_of(field.to_var_int(), field.width())
    }

    /// Appends `bytes`.
    pub(crate) fn bytes(mut self, bytes: &[u8]) -> Self {
        // invariant: every frame type sizes `N` for the longest encoding of
        // its fields, so the bytes fit.
        self.bytes[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        self
    }

    /// The encoded fields.
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// The length of the encoded fields.
    pub(crate) fn len(&self) -> usize {
        self.len
    }
}

/// Iterates over the frames of a packet payload held by a memory source such
/// as a byte slice or `Bytes`, reading each when it is reached.
///
/// Each item is a frame or the error that ends the iteration; after an error
/// the iterator yields `None`. Consecutive PADDING frames are reported as one
/// [`padding::Padding`]. Payload fields are chunks of the source; see the
/// [module documentation](self).
#[derive(Clone, Debug)]
pub struct Frames<H> {
    source: H,
    consumed: usize,
    start: usize,
    extensions: Extensions,
    failed: bool,
}

impl<H: Buf> Frames<H> {
    /// Iterates over the frames of `payload`, accepting the extension frames
    /// in `extensions`.
    pub fn new(payload: H, extensions: Extensions) -> Self {
        Self {
            source: payload,
            consumed: 0,
            start: 0,
            extensions,
            failed: false,
        }
    }

    /// The offset in the payload of the next frame, or after a failure of
    /// the frame that failed.
    pub fn offset(&self) -> usize {
        self.start
    }

    /// The payload from the next frame on; after a failure, what the failed
    /// frame left unread.
    pub fn remainder(&self) -> &H {
        &self.source
    }

    /// Takes the payload from the next frame on.
    pub fn into_remainder(self) -> H {
        self.source
    }
}

impl<H> Iterator for Frames<H>
where
    H: Buf + Receiver<Family = Direct<H>> + Unpin,
    Direct<H>: ReadChunk<Chunk: Default>,
{
    type Item = Result<
        Frame<<Direct<H> as ReadChunk>::Chunk>,
        codec::ReadFrameError<<Direct<H> as Read>::Error>,
    >;

    fn next(&mut self) -> Option<Self::Item> {
        use codec::ReadFrameHostExt as _;
        if self.failed || !self.source.has_remaining() {
            return None;
        }
        self.start = self.consumed;
        let before = self.source.remaining();
        let result = self.source.sync_read_frame_unpin(self.extensions);
        let result = result.map(|frame| match frame {
            Frame::Padding(padding) => Frame::Padding(padding.extend(skip_zeros(&mut self.source))),
            frame => frame,
        });
        self.consumed += before - self.source.remaining();
        if result.is_err() {
            self.failed = true;
        } else {
            self.start = self.consumed;
        }
        Some(result)
    }
}

impl<H> FusedIterator for Frames<H>
where
    H: Buf + Receiver<Family = Direct<H>> + Unpin,
    Direct<H>: ReadChunk<Chunk: Default>,
{
}

/// Consumes the zero bytes at the start of `source`, each a PADDING frame,
/// and returns how many there were.
fn skip_zeros(source: &mut impl Buf) -> usize {
    let mut count = 0;
    loop {
        let chunk = source.chunk();
        let zeros = chunk.iter().take_while(|&&byte| byte == 0).count();
        let whole_chunk = zeros == chunk.len();
        source.advance(zeros);
        count += zeros;
        if zeros == 0 || !whole_chunk {
            return count;
        }
    }
}
