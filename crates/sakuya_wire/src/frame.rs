//! QUIC version 1 frames ([RFC 9000 §19]) and two negotiated extensions.
//!
//! The payload of a QUIC packet, once packet protection is removed, is a
//! sequence of frames, each starting with a Frame Type field. A frame never
//! extends past the end of its packet ([RFC 9000 §12.4]), so the decoders here
//! work on the complete payload of one packet: a frame that the payload cuts
//! short is a terminal [`DecodeError::Truncated`], not a reason to wait for
//! more bytes.
//!
//! Besides the frames of RFC 9000, two extensions are supported:
//!
//! - DATAGRAM ([RFC 9221]), types `0x30` and `0x31`;
//! - RESET_STREAM_AT, type `0x24`, as specified by the Internet-Draft
//!   [draft-ietf-quic-reliable-stream-reset-11]. The draft is not an RFC and
//!   may still change.
//!
//! Which extensions the peers negotiated is a run-time fact: the decoders take
//! an [`Extensions`] set, and a frame of an extension that is not in the set
//! is reported as an unknown frame type, as RFC 9000 §12.4 requires.
//!
//! # Decoding
//!
//! [`Frames`] walks a packet payload frame by frame, without collecting the
//! frames first; [`Frame::decode`] decodes the single frame at the start of a
//! slice. Payload fields borrow from the input: STREAM, CRYPTO and DATAGRAM
//! data, NEW_TOKEN tokens, CONNECTION_CLOSE reason phrases, and the connection
//! ID and Stateless Reset Token of NEW_CONNECTION_ID. The ranges of an ACK
//! frame are produced by the [`AckRanges`] iterator.
//!
//! Decoding checks what the encoding alone determines: that every field is
//! present, that lengths stay within the payload, and the limits the frame
//! definitions state for single fields, such as the 2<sup>62</sup> − 1 bound
//! on the end of STREAM and CRYPTO data or the lengths a NEW_CONNECTION_ID
//! connection ID may have. Whether a frame is allowed in the packet type,
//! whether a stream exists or may be opened, and flow control are for the
//! receiver of the frame to check. Every [`DecodeError`] corresponds to
//! FRAME_ENCODING_ERROR.
//!
//! ```
//! use sakuya_wire::frame::{Extensions, Frame, Frames};
//!
//! // PING, then a STREAM frame with LEN and FIN on stream 4.
//! let payload = [0x01, 0x0b, 0x04, 0x02, b'h', b'i'];
//! let mut frames = Frames::new(&payload, Extensions::NONE);
//! assert!(matches!(frames.next(), Some(Ok(Frame::Ping(_)))));
//! let Some(Ok(Frame::Stream(stream))) = frames.next() else { panic!() };
//! assert_eq!((stream.stream_id.get().get(), stream.data, stream.fin), (4, &b"hi"[..], true));
//! assert!(frames.next().is_none());
//! ```
//!
//! # Encoding
//!
//! Every frame type has `encoded_len` and `encode`. `encode` appends the
//! whole frame to a [`BufMut`], such as a `&mut [u8]` holding the rest of a
//! packet, or fails without writing anything: it first checks the frame
//! ([`InvalidFrameError`]) and then the room in the buffer. `encoded_len`
//! gives the length in advance, so that a packet encoder can choose frames
//! and payload sizes before writing. [`Stream::max_data_len`] and
//! [`Crypto::max_data_len`] give the largest amount of data that fits a given
//! room, taking into account that the Length field grows with the data.
//!
//! A STREAM or DATAGRAM frame without a Length field extends to the end of the
//! packet; whoever writes one must not append anything after it.
//!
//! The [`calls`] module reads and writes frames as `nitori_call` operations.
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
use crate::{
    stream_id::{Directionality, StreamId},
    transport_error::TransportErrorCode,
    var_int::VarInt,
};
use bytes::BufMut;
use core::{iter::FusedIterator, num::NonZeroUsize, ops::RangeInclusive};
use snafu::Snafu;

pub mod calls;
mod decode;
mod encode;

use decode::decode_at;
use encode::{Body, body_len, data_limit, encode_body, max_len_with_length_field};

/// Frame Type values.
mod type_value {
    pub(super) const PADDING: u64 = 0x00;
    pub(super) const PING: u64 = 0x01;
    pub(super) const ACK: u64 = 0x02;
    pub(super) const ACK_ECN: u64 = 0x03;
    pub(super) const RESET_STREAM: u64 = 0x04;
    pub(super) const STOP_SENDING: u64 = 0x05;
    pub(super) const CRYPTO: u64 = 0x06;
    pub(super) const NEW_TOKEN: u64 = 0x07;
    pub(super) const STREAM: u64 = 0x08;
    pub(super) const MAX_DATA: u64 = 0x10;
    pub(super) const MAX_STREAM_DATA: u64 = 0x11;
    pub(super) const MAX_STREAMS_BIDI: u64 = 0x12;
    pub(super) const MAX_STREAMS_UNI: u64 = 0x13;
    pub(super) const DATA_BLOCKED: u64 = 0x14;
    pub(super) const STREAM_DATA_BLOCKED: u64 = 0x15;
    pub(super) const STREAMS_BLOCKED_BIDI: u64 = 0x16;
    pub(super) const STREAMS_BLOCKED_UNI: u64 = 0x17;
    pub(super) const NEW_CONNECTION_ID: u64 = 0x18;
    pub(super) const RETIRE_CONNECTION_ID: u64 = 0x19;
    pub(super) const PATH_CHALLENGE: u64 = 0x1a;
    pub(super) const PATH_RESPONSE: u64 = 0x1b;
    pub(super) const CONNECTION_CLOSE: u64 = 0x1c;
    pub(super) const CONNECTION_CLOSE_APPLICATION: u64 = 0x1d;
    pub(super) const HANDSHAKE_DONE: u64 = 0x1e;
    pub(super) const RESET_STREAM_AT: u64 = 0x24;
    pub(super) const DATAGRAM: u64 = 0x30;
    pub(super) const DATAGRAM_WITH_LENGTH: u64 = 0x31;
}

/// The bits of a STREAM frame type ([RFC 9000 §19.8]).
///
/// [RFC 9000 §19.8]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.8
mod stream_bits {
    pub(super) const OFF: u64 = 0x04;
    pub(super) const LEN: u64 = 0x02;
    pub(super) const FIN: u64 = 0x01;
}

/// The largest stream count MAX_STREAMS and STREAMS_BLOCKED may carry,
/// 2<sup>60</sup> ([RFC 9000 §19.11]).
///
/// [RFC 9000 §19.11]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.11
pub const MAX_STREAM_COUNT: u64 = 1 << 60;

/// The length of a Stateless Reset Token ([RFC 9000 §10.3]).
///
/// [RFC 9000 §10.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-10.3
pub const STATELESS_RESET_TOKEN_LEN: usize = 16;

/// The length of the data of PATH_CHALLENGE and PATH_RESPONSE.
pub const PATH_DATA_LEN: usize = 8;

/// The longest connection ID NEW_CONNECTION_ID may carry.
const MAX_CID_LEN: usize = crate::connection_id::ConnectionId::MAX_LEN;

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
    /// The kind a Frame Type value announces, or `None` for a value neither
    /// RFC 9000 nor a supported extension defines.
    pub const fn of(value: VarInt) -> Option<Self> {
        use type_value::*;
        Some(match value.get() {
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
            _ => return None,
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

/// The extension frames a decoder accepts.
///
/// Each extension is negotiated through a transport parameter. A frame of an
/// extension that is not enabled decodes as an unknown frame type. Sending
/// and receiving can be permitted separately; pass the set that applies to
/// the direction being decoded.
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

/// A decoded frame.
///
/// Payload fields borrow from the decoded input for `'a`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame<'a> {
    /// One or more consecutive PADDING frames.
    Padding(Padding),
    /// A PING frame.
    Ping(Ping),
    /// An ACK frame.
    Ack(Ack<AckRanges<'a>>),
    /// A RESET_STREAM frame.
    ResetStream(ResetStream),
    /// A STOP_SENDING frame.
    StopSending(StopSending),
    /// A CRYPTO frame.
    Crypto(Crypto<'a>),
    /// A NEW_TOKEN frame.
    NewToken(NewToken<'a>),
    /// A STREAM frame.
    Stream(Stream<'a>),
    /// A MAX_DATA frame.
    MaxData(MaxData),
    /// A MAX_STREAM_DATA frame.
    MaxStreamData(MaxStreamData),
    /// A MAX_STREAMS frame.
    MaxStreams(MaxStreams),
    /// A DATA_BLOCKED frame.
    DataBlocked(DataBlocked),
    /// A STREAM_DATA_BLOCKED frame.
    StreamDataBlocked(StreamDataBlocked),
    /// A STREAMS_BLOCKED frame.
    StreamsBlocked(StreamsBlocked),
    /// A NEW_CONNECTION_ID frame.
    NewConnectionId(NewConnectionId<'a>),
    /// A RETIRE_CONNECTION_ID frame.
    RetireConnectionId(RetireConnectionId),
    /// A PATH_CHALLENGE frame.
    PathChallenge(PathChallenge),
    /// A PATH_RESPONSE frame.
    PathResponse(PathResponse),
    /// A CONNECTION_CLOSE frame.
    ConnectionClose(ConnectionClose<'a>),
    /// A HANDSHAKE_DONE frame.
    HandshakeDone(HandshakeDone),
    /// A RESET_STREAM_AT frame.
    ResetStreamAt(ResetStreamAt),
    /// A DATAGRAM frame.
    Datagram(Datagram<'a>),
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
use each_frame;

impl<'a> Frame<'a> {
    /// Decodes the frame at the start of `input`, accepting the extension
    /// frames in `extensions`.
    ///
    /// `input` is the rest of a packet payload: a STREAM or DATAGRAM frame
    /// without a Length field takes all of it. Returns the frame and the
    /// number of bytes it took; a run of consecutive PADDING frames decodes
    /// as one [`Padding`]. Offsets in errors count from the start of `input`.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] if the frame type is unknown or not enabled, the input
    /// ends within the frame, or a field breaks a limit of the encoding.
    pub fn decode(input: &'a [u8], extensions: Extensions) -> Result<(Self, usize), DecodeError> {
        decode_at(input, 0, extensions)
    }

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

    /// The Frame Type value [`Frame::encode`] writes.
    pub fn type_value(&self) -> VarInt {
        each_frame!(self, frame => Body::type_value(frame))
    }

    /// The number of bytes [`Frame::encode`] writes.
    pub fn encoded_len(&self) -> usize {
        each_frame!(self, frame => body_len(frame))
    }

    /// Checks the limits that [`Frame::encode`] checks before writing.
    ///
    /// # Errors
    ///
    /// [`InvalidFrameError`] for a field that breaks a limit of the encoding.
    pub fn validate(&self) -> Result<(), InvalidFrameError> {
        each_frame!(self, frame => Body::validate(frame))
    }

    /// Appends the encoding of the frame to `buffer`.
    ///
    /// Nothing is written unless the frame is valid and fits.
    ///
    /// # Errors
    ///
    /// [`EncodeError::Invalid`] if [`Frame::validate`] fails, and
    /// [`EncodeError::Capacity`] if `buffer.remaining_mut()` is below
    /// [`Frame::encoded_len`].
    pub fn encode<B: BufMut + ?Sized>(&self, buffer: &mut B) -> Result<(), EncodeError> {
        each_frame!(self, frame => encode_body(frame, buffer))
    }
}

/// A run of one or more consecutive PADDING frames ([RFC 9000 §19.1]).
///
/// Each PADDING frame is the single byte `0x00`. Decoding reports a run of
/// them as one value, and encoding writes `len` zero bytes.
///
/// [RFC 9000 §19.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.1
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Padding {
    /// The number of bytes, each one PADDING frame.
    pub len: NonZeroUsize,
}

/// A PING frame ([RFC 9000 §19.2]).
///
/// [RFC 9000 §19.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.2
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Ping;

/// An ACK frame ([RFC 9000 §19.3]).
///
/// `ranges` yields the acknowledged packet numbers as inclusive ranges, from
/// the largest packet number down: each range lies below the previous one
/// and is separated from it by at least one unacknowledged packet number. A
/// decoded frame holds [`AckRanges`]; to encode, any [`Clone`] iterator of
/// such ranges can be used, for example
/// `ranges.iter().cloned()` over a slice of ranges.
///
/// [RFC 9000 §19.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.3
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ack<R> {
    /// The ACK Delay field: the acknowledgment delay in microseconds, divided
    /// by 2 to the power of the sender's `ack_delay_exponent`.
    pub ack_delay: VarInt,
    /// The acknowledged ranges, largest first.
    pub ranges: R,
    /// The ECN counts; present in type `0x03`.
    pub ecn_counts: Option<EcnCounts>,
}

/// The ECN counts of an ACK frame of type `0x03` ([RFC 9000 §19.3.2]).
///
/// [RFC 9000 §19.3.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.3.2
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct EcnCounts {
    /// ECT0 Count: packets received with the ECT(0) codepoint.
    pub ect0: VarInt,
    /// ECT1 Count: packets received with the ECT(1) codepoint.
    pub ect1: VarInt,
    /// ECN-CE Count: packets received with the ECN-CE codepoint.
    pub ce: VarInt,
}

impl<R: Iterator<Item = RangeInclusive<u64>> + Clone> Ack<R> {
    /// The largest acknowledged packet number: the end of the first range.
    pub fn largest_acknowledged(&self) -> Option<u64> {
        self.ranges.clone().next().map(|range| *range.end())
    }

    /// The Frame Type value [`Ack::encode`] writes: `0x03` with ECN counts,
    /// `0x02` without.
    pub fn type_value(&self) -> VarInt {
        Body::type_value(self)
    }

    /// The number of bytes [`Ack::encode`] writes.
    ///
    /// Iterates over a clone of the ranges. For ranges that
    /// [`Ack::validate`] rejects, the value has no meaning.
    pub fn encoded_len(&self) -> usize {
        body_len(self)
    }

    /// Checks that there is at least one range and that the ranges are
    /// ordered as the encoding requires.
    ///
    /// # Errors
    ///
    /// [`InvalidFrameError::EmptyAck`] without ranges, and
    /// [`InvalidFrameError::AckRange`] for the first range that is empty,
    /// exceeds [`VarInt::MAX`], or does not lie below the previous range with
    /// at least one packet number between them.
    pub fn validate(&self) -> Result<(), InvalidFrameError> {
        Body::validate(self)
    }

    /// Appends the encoding of the frame to `buffer`, iterating over two
    /// clones of the ranges.
    ///
    /// Nothing is written unless the frame is valid and fits.
    ///
    /// # Errors
    ///
    /// [`EncodeError::Invalid`] if [`Ack::validate`] fails, and
    /// [`EncodeError::Capacity`] if `buffer.remaining_mut()` is below
    /// [`Ack::encoded_len`].
    pub fn encode<B: BufMut + ?Sized>(&self, buffer: &mut B) -> Result<(), EncodeError> {
        encode_body(self, buffer)
    }
}

/// The ranges of a decoded ACK frame, largest first.
///
/// Each item is the inclusive range of packet numbers that one ACK Range
/// acknowledges, restored from the Largest Acknowledged, First ACK Range and
/// Gap fields. The decoder checked the whole sequence, so iteration cannot
/// fail. Equality compares the ranges, not their encoding.
#[derive(Clone, Debug)]
pub struct AckRanges<'a> {
    /// The encoded First ACK Range and ACK Ranges not yet produced.
    encoded: &'a [u8],
    /// Largest Acknowledged.
    largest: u64,
    /// The smallest packet number of the range produced last.
    previous_smallest: Option<u64>,
    /// The ranges not yet produced.
    remaining: usize,
}

impl AckRanges<'_> {
    /// Reads the next encoded value, which the decoder has checked.
    fn take(&mut self) -> Option<u64> {
        let (value, len) = VarInt::decode(self.encoded).ok()?;
        self.encoded = &self.encoded[len..];
        Some(value.get())
    }

    fn next_range(&mut self) -> Option<RangeInclusive<u64>> {
        let largest = match self.previous_smallest {
            None => self.largest,
            Some(smallest) => smallest.checked_sub(self.take()?)?.checked_sub(2)?,
        };
        let smallest = largest.checked_sub(self.take()?)?;
        self.previous_smallest = Some(smallest);
        Some(smallest..=largest)
    }
}

impl Iterator for AckRanges<'_> {
    type Item = RangeInclusive<u64>;

    fn next(&mut self) -> Option<RangeInclusive<u64>> {
        if self.remaining == 0 {
            return None;
        }
        let range = self.next_range();
        // The decoder validated every range; a failure here would mean the
        // input changed, so end the sequence rather than produce garbage.
        self.remaining = if range.is_some() {
            self.remaining - 1
        } else {
            0
        };
        range
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for AckRanges<'_> {}

impl FusedIterator for AckRanges<'_> {}

impl PartialEq for AckRanges<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.clone().eq(other.clone())
    }
}

impl Eq for AckRanges<'_> {}

/// A RESET_STREAM frame ([RFC 9000 §19.4]).
///
/// [RFC 9000 §19.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.4
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ResetStream {
    /// The stream being terminated.
    pub stream_id: StreamId,
    /// The application protocol error code.
    pub application_error_code: VarInt,
    /// The final size of the stream, in bytes.
    pub final_size: VarInt,
}

/// A STOP_SENDING frame ([RFC 9000 §19.5]).
///
/// [RFC 9000 §19.5]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.5
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StopSending {
    /// The stream whose data is being discarded.
    pub stream_id: StreamId,
    /// The application protocol error code.
    pub application_error_code: VarInt,
}

/// A CRYPTO frame ([RFC 9000 §19.6]).
///
/// The Offset and Length fields are always present. The end of the data,
/// `offset` plus its length, is at most [`VarInt::MAX`].
///
/// [RFC 9000 §19.6]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.6
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Crypto<'a> {
    /// The byte offset of the data in the crypto stream of its level.
    pub offset: VarInt,
    /// The cryptographic message data.
    pub data: &'a [u8],
}

impl Crypto<'_> {
    /// The largest data length for which a CRYPTO frame at `offset` takes at
    /// most `room` bytes, or `None` if not even an empty frame fits.
    ///
    /// The length accounts for the Length field growing with the data and
    /// for the 2<sup>62</sup> − 1 bound on the end of the data.
    pub fn max_data_len(offset: VarInt, room: usize) -> Option<usize> {
        let fixed = 1 + offset.encoded_len();
        max_len_with_length_field(fixed, data_limit(offset), room)
    }
}

/// A NEW_TOKEN frame ([RFC 9000 §19.7]).
///
/// The token is not empty.
///
/// [RFC 9000 §19.7]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.7
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NewToken<'a> {
    /// The opaque token for a future Initial packet.
    pub token: &'a [u8],
}

/// A STREAM frame ([RFC 9000 §19.8]), of any of the types `0x08..=0x0f`.
///
/// The Frame Type is derived from the fields: the OFF bit is set when
/// `offset` is not zero, the LEN bit when `has_length` is true, and the FIN
/// bit when `fin` is true. The end of the data, `offset` plus its length, is
/// at most [`VarInt::MAX`].
///
/// [RFC 9000 §19.8]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.8
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Stream<'a> {
    /// The stream the data belongs to.
    pub stream_id: StreamId,
    /// The byte offset of the data in the stream.
    pub offset: VarInt,
    /// The stream data.
    pub data: &'a [u8],
    /// Whether the data ends the stream.
    pub fin: bool,
    /// Whether the frame carries a Length field. Without one, the data
    /// extends to the end of the packet.
    pub has_length: bool,
}

impl Stream<'_> {
    /// The largest data length for which a STREAM frame takes at most `room`
    /// bytes, or `None` if not even an empty frame fits.
    ///
    /// With `has_length`, the length accounts for the Length field growing
    /// with the data; without, the frame fills `room` exactly when the data
    /// is that long. The 2<sup>62</sup> − 1 bound on the end of the data is
    /// also applied.
    pub fn max_data_len(
        stream_id: StreamId,
        offset: VarInt,
        has_length: bool,
        room: usize,
    ) -> Option<usize> {
        let offset_len = if offset == VarInt::ZERO {
            0
        } else {
            offset.encoded_len()
        };
        let fixed = 1 + stream_id.get().encoded_len() + offset_len;
        let limit = data_limit(offset);
        if has_length {
            max_len_with_length_field(fixed, limit, room)
        } else {
            room.checked_sub(fixed).map(|left| left.min(limit))
        }
    }
}

/// A MAX_DATA frame ([RFC 9000 §19.9]).
///
/// [RFC 9000 §19.9]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.9
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MaxData {
    /// The maximum amount of data that can be sent on the connection, in bytes.
    pub maximum_data: VarInt,
}

/// A MAX_STREAM_DATA frame ([RFC 9000 §19.10]).
///
/// [RFC 9000 §19.10]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.10
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MaxStreamData {
    /// The stream the limit applies to.
    pub stream_id: StreamId,
    /// The maximum amount of data that can be sent on the stream, in bytes.
    pub maximum_stream_data: VarInt,
}

/// A MAX_STREAMS frame ([RFC 9000 §19.11]): type `0x12` for bidirectional
/// streams, `0x13` for unidirectional ones.
///
/// The count is at most [`MAX_STREAM_COUNT`].
///
/// [RFC 9000 §19.11]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.11
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MaxStreams {
    /// The type of streams the limit applies to.
    pub directionality: Directionality,
    /// The cumulative number of streams of that type that can be opened.
    pub maximum_streams: VarInt,
}

/// A DATA_BLOCKED frame ([RFC 9000 §19.12]).
///
/// [RFC 9000 §19.12]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.12
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DataBlocked {
    /// The connection-level limit at which blocking occurred.
    pub maximum_data: VarInt,
}

/// A STREAM_DATA_BLOCKED frame ([RFC 9000 §19.13]).
///
/// [RFC 9000 §19.13]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.13
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamDataBlocked {
    /// The blocked stream.
    pub stream_id: StreamId,
    /// The offset of the stream at which blocking occurred.
    pub maximum_stream_data: VarInt,
}

/// A STREAMS_BLOCKED frame ([RFC 9000 §19.14]): type `0x16` for
/// bidirectional streams, `0x17` for unidirectional ones.
///
/// The count is at most [`MAX_STREAM_COUNT`].
///
/// [RFC 9000 §19.14]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.14
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamsBlocked {
    /// The type of streams that could not be opened.
    pub directionality: Directionality,
    /// The stream limit at the time the frame was sent.
    pub maximum_streams: VarInt,
}

/// A NEW_CONNECTION_ID frame ([RFC 9000 §19.15]).
///
/// The connection ID is 1 to 20 bytes long, and `retire_prior_to` is at most
/// `sequence_number`.
///
/// [RFC 9000 §19.15]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.15
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NewConnectionId<'a> {
    /// The sequence number the sender assigned to the connection ID.
    pub sequence_number: VarInt,
    /// The sequence number below which connection IDs are to be retired.
    pub retire_prior_to: VarInt,
    /// The connection ID; convert it with
    /// [`NonEmptyCid::try_from`](crate::connection_id::NonEmptyCid) to keep it.
    pub connection_id: &'a [u8],
    /// The Stateless Reset Token for the connection ID.
    pub stateless_reset_token: &'a [u8; STATELESS_RESET_TOKEN_LEN],
}

/// A RETIRE_CONNECTION_ID frame ([RFC 9000 §19.16]).
///
/// [RFC 9000 §19.16]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.16
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RetireConnectionId {
    /// The sequence number of the connection ID being retired.
    pub sequence_number: VarInt,
}

/// A PATH_CHALLENGE frame ([RFC 9000 §19.17]).
///
/// [RFC 9000 §19.17]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.17
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PathChallenge {
    /// The data the peer echoes in PATH_RESPONSE.
    pub data: [u8; PATH_DATA_LEN],
}

/// A PATH_RESPONSE frame ([RFC 9000 §19.18]).
///
/// [RFC 9000 §19.18]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.18
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PathResponse {
    /// The data of the PATH_CHALLENGE being answered.
    pub data: [u8; PATH_DATA_LEN],
}

/// A CONNECTION_CLOSE frame ([RFC 9000 §19.19]).
///
/// Type `0x1c` signals an error of the QUIC layer and carries the type of the
/// frame that triggered it; type `0x1d` signals an application error and
/// carries no frame type.
///
/// [RFC 9000 §19.19]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.19
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConnectionClose<'a> {
    /// A transport error code for type `0x1c`, an application protocol error
    /// code for type `0x1d`.
    pub error_code: VarInt,
    /// `Some` for type `0x1c`: the Frame Type of the frame that triggered the
    /// error, or 0 if it is unknown. `None` for type `0x1d`.
    pub frame_type: Option<VarInt>,
    /// The reason phrase; UTF-8 is expected but not checked.
    pub reason_phrase: &'a [u8],
}

impl ConnectionClose<'_> {
    /// The error code as a transport error code, for type `0x1c`.
    pub fn transport_error_code(&self) -> Option<TransportErrorCode> {
        self.frame_type.map(|_| self.error_code.into())
    }
}

/// A HANDSHAKE_DONE frame ([RFC 9000 §19.20]).
///
/// [RFC 9000 §19.20]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.20
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct HandshakeDone;

/// A RESET_STREAM_AT frame, type `0x24`, as specified by the Internet-Draft
/// [draft-ietf-quic-reliable-stream-reset-11] §4.
///
/// It is a RESET_STREAM that also states how much of the stream must still
/// be delivered reliably. `reliable_size` is at most `final_size`.
///
/// [draft-ietf-quic-reliable-stream-reset-11]: https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-11.html#section-4
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ResetStreamAt {
    /// The stream being terminated.
    pub stream_id: StreamId,
    /// The application protocol error code.
    pub application_error_code: VarInt,
    /// The final size of the stream, in bytes.
    pub final_size: VarInt,
    /// The amount of data, from the start of the stream, that must be
    /// delivered to the application despite the reset.
    pub reliable_size: VarInt,
}

/// A DATAGRAM frame ([RFC 9221 §4]): type `0x31` with a Length field, `0x30`
/// without.
///
/// [RFC 9221 §4]: https://www.rfc-editor.org/rfc/rfc9221.html#section-4
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Datagram<'a> {
    /// The application data.
    pub data: &'a [u8],
    /// Whether the frame carries a Length field. Without one, the data
    /// extends to the end of the packet.
    pub has_length: bool,
}

/// Iterates over the frames of a packet payload, decoding each when it is
/// reached.
///
/// Each item is a frame or the error that ends the iteration; after an error
/// the iterator yields `None`. Consecutive PADDING frames are reported as one
/// [`Padding`]. Offsets in errors count from the start of the payload.
#[derive(Clone, Debug)]
pub struct Frames<'a> {
    payload: &'a [u8],
    offset: usize,
    extensions: Extensions,
    failed: bool,
}

impl<'a> Frames<'a> {
    /// Iterates over the frames of `payload`, accepting the extension frames
    /// in `extensions`.
    pub fn new(payload: &'a [u8], extensions: Extensions) -> Self {
        Self {
            payload,
            offset: 0,
            extensions,
            failed: false,
        }
    }

    /// The offset in the payload of the next frame.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// The payload from the next frame on.
    pub fn remainder(&self) -> &'a [u8] {
        &self.payload[self.offset..]
    }
}

impl<'a> Iterator for Frames<'a> {
    type Item = Result<Frame<'a>, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.offset == self.payload.len() {
            return None;
        }
        match decode_at(self.payload, self.offset, self.extensions) {
            Ok((frame, len)) => {
                self.offset += len;
                Some(Ok(frame))
            }
            Err(error) => {
                self.failed = true;
                Some(Err(error))
            }
        }
    }
}

impl FusedIterator for Frames<'_> {}

/// Failures of decoding a frame.
///
/// `offset` is where the frame starts. Every failure corresponds to the
/// transport error FRAME_ENCODING_ERROR ([`DecodeError::transport_error_code`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(decode_error), visibility(pub(crate)))]
pub enum DecodeError {
    /// The input ends within the frame.
    #[snafu(display(
        "frame at offset {offset} needs {required} bytes of input, but there are {available}"
    ))]
    Truncated {
        /// Where the frame starts.
        offset: usize,
        /// The Frame Type, if the input holds it completely.
        frame_type: Option<VarInt>,
        /// The input length the next field requires, counted from the start
        /// of the input.
        required: usize,
        /// The input length.
        available: usize,
    },
    /// The frame type is neither defined nor an enabled extension.
    #[snafu(display("unknown frame type {:#x} at offset {offset}", frame_type.get()))]
    UnknownType {
        /// Where the frame starts.
        offset: usize,
        /// The Frame Type.
        frame_type: VarInt,
    },
    /// An ACK range extends below packet number 0.
    #[snafu(display(
        "ACK range {index} of the frame at offset {offset} extends below packet number 0"
    ))]
    AckRange {
        /// Where the frame starts.
        offset: usize,
        /// The Frame Type.
        frame_type: VarInt,
        /// The position of the range: 0 for the First ACK Range.
        index: u64,
    },
    /// The data of a STREAM or CRYPTO frame ends beyond 2<sup>62</sup> − 1.
    #[snafu(display(
        "data of the frame at offset {offset} ends at {}, beyond 2^62 - 1",
        u128::from(data_offset.get()) + u128::from(*length)
    ))]
    DataEnd {
        /// Where the frame starts.
        offset: usize,
        /// The Frame Type.
        frame_type: VarInt,
        /// The Offset field.
        data_offset: VarInt,
        /// The length of the data.
        length: u64,
    },
    /// A NEW_CONNECTION_ID connection ID length is outside 1 to 20.
    #[snafu(display(
        "NEW_CONNECTION_ID at offset {offset} has a connection ID of {length} bytes, outside 1 to 20"
    ))]
    ConnectionIdLength {
        /// Where the frame starts.
        offset: usize,
        /// The Length field.
        length: u8,
    },
    /// NEW_CONNECTION_ID retires sequence numbers beyond its own.
    #[snafu(display(
        "NEW_CONNECTION_ID at offset {offset} retires prior to {retire_prior_to}, beyond its sequence number {sequence_number}"
    ))]
    RetirePriorTo {
        /// Where the frame starts.
        offset: usize,
        /// The Sequence Number field.
        sequence_number: VarInt,
        /// The Retire Prior To field.
        retire_prior_to: VarInt,
    },
    /// A MAX_STREAMS or STREAMS_BLOCKED count exceeds 2<sup>60</sup>.
    #[snafu(display(
        "stream count {maximum_streams} of the frame at offset {offset} exceeds 2^60"
    ))]
    StreamCount {
        /// Where the frame starts.
        offset: usize,
        /// The Frame Type.
        frame_type: VarInt,
        /// The Maximum Streams field.
        maximum_streams: VarInt,
    },
    /// A NEW_TOKEN token is empty.
    #[snafu(display("NEW_TOKEN at offset {offset} has an empty token"))]
    EmptyToken {
        /// Where the frame starts.
        offset: usize,
    },
    /// A RESET_STREAM_AT reliable size exceeds its final size.
    #[snafu(display(
        "RESET_STREAM_AT at offset {offset} has reliable size {reliable_size} beyond final size {final_size}"
    ))]
    ReliableSize {
        /// Where the frame starts.
        offset: usize,
        /// The Final Size field.
        final_size: VarInt,
        /// The Reliable Size field.
        reliable_size: VarInt,
    },
}

impl DecodeError {
    /// Where the frame starts in the input.
    pub fn offset(&self) -> usize {
        match *self {
            Self::Truncated { offset, .. }
            | Self::UnknownType { offset, .. }
            | Self::AckRange { offset, .. }
            | Self::DataEnd { offset, .. }
            | Self::ConnectionIdLength { offset, .. }
            | Self::RetirePriorTo { offset, .. }
            | Self::StreamCount { offset, .. }
            | Self::EmptyToken { offset }
            | Self::ReliableSize { offset, .. } => offset,
        }
    }

    /// The Frame Type of the frame, if the input holds it completely.
    ///
    /// This is the value for the Frame Type field of the CONNECTION_CLOSE
    /// frame that reports the error.
    pub fn frame_type(&self) -> Option<VarInt> {
        match *self {
            Self::Truncated { frame_type, .. } => frame_type,
            Self::UnknownType { frame_type, .. }
            | Self::AckRange { frame_type, .. }
            | Self::DataEnd { frame_type, .. }
            | Self::StreamCount { frame_type, .. } => Some(frame_type),
            Self::ConnectionIdLength { .. } | Self::RetirePriorTo { .. } => {
                Some(VarInt::from_u32(type_value::NEW_CONNECTION_ID as u32))
            }
            Self::EmptyToken { .. } => Some(VarInt::from_u32(type_value::NEW_TOKEN as u32)),
            Self::ReliableSize { .. } => Some(VarInt::from_u32(type_value::RESET_STREAM_AT as u32)),
        }
    }

    /// The transport error the failure corresponds to: always
    /// FRAME_ENCODING_ERROR ([RFC 9000 §12.4], §19).
    ///
    /// [RFC 9000 §12.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4
    pub fn transport_error_code(&self) -> TransportErrorCode {
        TransportErrorCode::FRAME_ENCODING_ERROR
    }
}

/// Failures of encoding a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(encode_error), visibility(pub(crate)))]
pub enum EncodeError {
    /// The buffer cannot take the whole frame.
    #[snafu(display("frame needs {required} bytes, but the buffer has room for {available}"))]
    Capacity {
        /// The length of the frame.
        required: usize,
        /// The room the buffer reported.
        available: usize,
    },
    /// A field breaks a limit of the encoding.
    #[snafu(transparent)]
    Invalid {
        /// The broken limit.
        source: InvalidFrameError,
    },
}

/// A frame field breaks a limit of the encoding.
///
/// These are the limits that decoding enforces, so a frame that passes
/// validation decodes back to the same values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(invalid_frame_error), visibility(pub(crate)))]
pub enum InvalidFrameError {
    /// The data of a STREAM or CRYPTO frame would end beyond 2<sup>62</sup> − 1.
    #[snafu(display("data at offset {offset} of length {length} ends beyond 2^62 - 1"))]
    DataEnd {
        /// The Frame Type.
        frame_type: VarInt,
        /// The offset of the data.
        offset: VarInt,
        /// The length of the data.
        length: usize,
    },
    /// A payload field is longer than a Length field can state.
    #[snafu(display("field of {length} bytes is longer than 2^62 - 1"))]
    Length {
        /// The Frame Type.
        frame_type: VarInt,
        /// The length of the field.
        length: usize,
    },
    /// A NEW_CONNECTION_ID connection ID length is outside 1 to 20.
    #[snafu(display("connection ID of {length} bytes is outside 1 to 20"))]
    ConnectionIdLength {
        /// The length of the connection ID.
        length: usize,
    },
    /// NEW_CONNECTION_ID would retire sequence numbers beyond its own.
    #[snafu(display(
        "retire prior to {retire_prior_to} is beyond sequence number {sequence_number}"
    ))]
    RetirePriorTo {
        /// The sequence number.
        sequence_number: VarInt,
        /// The sequence number below which to retire.
        retire_prior_to: VarInt,
    },
    /// A MAX_STREAMS or STREAMS_BLOCKED count exceeds 2<sup>60</sup>.
    #[snafu(display("stream count {maximum_streams} exceeds 2^60"))]
    StreamCount {
        /// The Frame Type.
        frame_type: VarInt,
        /// The stream count.
        maximum_streams: VarInt,
    },
    /// A NEW_TOKEN token is empty.
    #[snafu(display("NEW_TOKEN token is empty"))]
    EmptyToken,
    /// A RESET_STREAM_AT reliable size exceeds its final size.
    #[snafu(display("reliable size {reliable_size} is beyond final size {final_size}"))]
    ReliableSize {
        /// The final size.
        final_size: VarInt,
        /// The reliable size.
        reliable_size: VarInt,
    },
    /// An ACK frame has no range.
    #[snafu(display("ACK frame has no range"))]
    EmptyAck,
    /// An ACK range is empty, exceeds [`VarInt::MAX`], or does not lie below
    /// the previous range with at least one packet number between them.
    #[snafu(display("ACK range {index} is empty, too large, or out of order"))]
    AckRange {
        /// The position of the range: 0 for the first.
        index: usize,
    },
}

#[cfg(test)]
mod tests;
