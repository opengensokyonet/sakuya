//! QUIC version 1 frames ([RFC 9000 §19]).
//!
//! These are the frames of the part of a frame set that
//! [`v1::Part`](crate::Part) names; [`crate::frame`] describes frame sets,
//! how they are read, and how a set of version 1 alone reads the Frame Type
//! values of extensions, `0x24`, `0x30` and `0x31` among them: as unknown
//! types, FRAME_ENCODING_ERROR ([RFC 9000 §12.4]).
//!
//! Each frame type has its own module with its struct, the checks its
//! encoding imposes, and its write function. [`Frame`] holds any of them,
//! [`FrameRun`] holds any of them with PADDING as a run, and [`FrameType`]
//! names their kinds.
//!
//! # Frame values and their encoding
//!
//! A frame value states every detail of its encoding, and converts to bytes
//! and back without loss: reading a frame and writing it again reproduces
//! the bytes that were read, and writing a frame and reading it back gives
//! the same value.
//!
//! - Each variable-length integer field is a
//!   [`VarIntField`]: its value and
//!   the width of its encoding, 1, 2, 4 or 8 bytes. Reading keeps the width
//!   it finds; writing uses the width the field holds, which need not be the
//!   shortest. [`VarIntField::shortest`](crate::var_int::VarIntField::shortest)
//!   gives the shortest encoding that a
//!   sender normally uses.
//! - A Length field whose value is the length of a payload field (the Length
//!   of CRYPTO and STREAM, the Token Length of NEW_TOKEN, the
//!   Reason Phrase Length of CONNECTION_CLOSE) stores only its width; the
//!   ACK Range Count of ACK likewise.
//! - Optional fields are present or absent as the Frame Type announces them.
//!   The Offset of STREAM is an `Option`, so a STREAM frame with the OFF bit
//!   set and offset 0 is distinct from one without the bit.
//! - Whether a STREAM frame has a Length field is stated by the type
//!   parameter `L` of [`stream::StreamFrame`], a
//!   [`LengthKind`] of one of four types:
//!   `VarIntWidth`, for a frame with a Length field of that width;
//!   [`NoLength`], for a frame without one, whose
//!   data extends to the end of the packet; and `Either<NoLength,
//!   VarIntWidth>` and `Either<VarIntWidth, NoLength>`, of the `either`
//!   crate, for either of the two. `Either<NoLength, VarIntWidth>` is the default and
//!   what reading gives, since only the Frame Type that was read tells which
//!   it is. The kinds convert into one another with `From` as
//!   `LengthKind` describes. A frame with a Length field is constructed by
//!   `with_length`, one without by `without_length`, and a STREAM frame
//!   whose Length field is not decided yet, of the type
//!   [`UndecidedLength`]
//!   that has no write function, by `new`, followed by `into_with_length`
//!   or `into_without_length`; each of the decided kinds has its own write
//!   function, so a writer that knows which kind it writes states it in the
//!   type.
//! - An ACK frame holds its fields as encoded, and owns its ACK Ranges in
//!   [`ack::AckRanges`]; [`ack::AckFrame::packet_ranges`] computes the
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
//! NEW_CONNECTION_ID does not exceed its Sequence Number, no range of an ACK
//! frame extends below packet number 0, and the ACK Range Count field of ACK
//! can state the number of ACK Ranges. The constructors of these frame
//! types, such as [`stream::StreamFrame::with_length`] and [`ack::AckFrame::new`],
//! return an error for fields that break one. The other frame types have no such limit,
//! and their `new`, such as [`max_data::MaxDataFrame::new`], accepts any fields. The
//! fields of every frame type are private and are read through methods of
//! the same names, so every frame value converts to bytes and back without
//! loss.
//!
//! # Length fields
//!
//! Whether a STREAM or DATAGRAM frame has a Length field is stated by the
//! type parameter `L` of the frame, a [`LengthKind`] of one of four types:
//! [`VarIntWidth`], for a frame with a Length field of that width;
//! [`NoLength`], for a frame without one, whose data extends to the end of
//! the packet; and [`Either<NoLength, VarIntWidth>`](Either) and
//! [`Either<VarIntWidth, NoLength>`](Either), of the `either` crate, for
//! either of the two. A STREAM frame whose Length field is not decided yet
//! is of the type [`UndecidedLength`], which has no write function.
//!
//! # Reading
//!
//! [`Frames`](set::Frames) walks a packet payload held by a byte slice or
//! `Bytes`, item by item; for a set of version 1 alone, the set is
//! `HList![v1::Part]`, whose item is a `Coproduct` of a [`FrameRun`] and
//! `CNil`, taken out with `extract`. A [`FrameRun`] is one frame of any type
//! but PADDING, or consecutive PADDING frames as one [`padding::PaddingRun`],
//! whose length is the number of PADDING frames. [`Frame`] is one frame as it
//! is encoded, with a [`padding::PaddingFrame`] for PADDING; a [`Frame`]
//! converts into a [`FrameRun`] with `From`, and a PADDING frame is a run of
//! one. Payload fields are pieces of the source, of the type parameter `D`:
//! subslices of a byte slice and `Bytes` that share the storage of a `Bytes`
//! source, so reading copies no payload. These are STREAM and CRYPTO data,
//! NEW_TOKEN tokens and CONNECTION_CLOSE reason phrases. The ACK Ranges of an
//! ACK frame are collected into [`ack::AckRanges`].
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
//! Type, which are the same for every frame set,
//! [`ReadFrameError::Fields`](set::codec::ReadFrameError::Fields)
//! holds a [`PartsError`](sakuya_wire::parts::PartsError) of a sum of the failures of
//! the parts. That of version 1 is a [`codec::ReadFieldsError`], which has a
//! variant for each frame type, holding the error of that type; ACK and CONNECTION_CLOSE have one
//! for each of their two Frame Type values, whose fields differ, such as
//! [`codec::ReadFieldsError::AckEcn`] for an ACK frame with ECN counts. The
//! error of a frame type has a variant for each field that cannot be read,
//! named after the field, such as
//! [`ack::codec::ReadAckFrameError::LargestAcknowledged`]; the Gap and ACK
//! Range Length of an ACK Range carry the position of their ACK Range. Each
//! broken limit has a variant of its own as well, named after the rule, such
//! as
//! [`new_connection_id::codec::ReadNewConnectionIdFrameError::RetirePriorToAboveSequenceNumber`].
//! Every [`codec::ReadFieldsError`] corresponds to FRAME_ENCODING_ERROR.
//!
//! ```
//! use core::marker::PhantomData;
//! use either::Either;
//! use sakuya_wire::parts::HList;
//! use sakuya_wire_v1::var_int::VarIntWidth;
//! use sakuya_wire_v1::{
//!     frame::{FrameRun, set::Frames},
//! };
//! use sakuya_wire_v1 as v1;
//!
//! // PING, then a STREAM frame with LEN and FIN on stream 4, whose Stream ID
//! // takes two bytes.
//! let payload = [0x01, 0x0b, 0x40, 0x04, 0x02, b'h', b'i'];
//! let mut frames = Frames::new(&payload[..], PhantomData::<HList![v1::Part]>);
//! let Some(Ok(run)) = frames.next() else { panic!() };
//! assert!(matches!(run.extract(), FrameRun::Ping(_)));
//! let Some(Ok(run)) = frames.next() else { panic!() };
//! let FrameRun::Stream(stream) = run.extract() else { panic!() };
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
//! Every frame type has `encoded_len` and a write function in its module's
//! `codec`, such as [`stream::codec::write_stream_frame`], and STREAM has
//! one for each kind of Length field; [`codec::write_frame`] writes any
//! [`Frame`] and [`codec::write_frame_run`] any [`FrameRun`]. Writing writes the encoding the value states and
//! chooses nothing: the width of each field comes from the value. Every
//! frame checked its limits when it was constructed, so writing checks
//! nothing, and has no failure: it writes to a [`bytes::BufMut`], and a
//! destination without room panics, as `BufMut` does. `encoded_len`
//! gives the length in advance, so that a packet encoder can choose frames
//! and payload sizes before writing.
//! The `max_data_len` of `StreamFrame<D, VarIntWidth>` and of
//! `StreamFrame<D, NoLength>`, and [`crypto::CryptoFrame::max_data_len`], give the
//! largest amount of data that fits a given room, taking into account that
//! the shortest Length field grows with the data.
//! [`ack::AckFrame::from_packet_ranges`] states packet number ranges as an ACK
//! frame in the shortest encodings. Payload fields are written from any
//! [`bytes::Buf`].
//!
//! A STREAM frame without a Length field extends to the end of the packet;
//! whoever writes one must not append anything after it.
//!
//! # Properties of the frame types
//!
//! [`FrameType`] implements [`FrameKind`], and each frame states its kind
//! with its `frame_type` method. [`FrameKind::is_ack_eliciting`] and
//! [`FrameKind::counts_in_flight`] are the per-frame facts from which
//! [RFC 9002 §2] derives whether a packet is ack-eliciting and whether it
//! counts as in flight. [`FrameKind::can_appear_in`] states in which packets
//! a frame type may appear, the "Pkts" column of [RFC 9000 §12.4] Table 3,
//! [`FrameKind::is_probing`] which frames are probing frames
//! ([RFC 9000 §9.1]), and [`FrameKind::receivable_by`] which frames only a
//! client receives. Reading a frame checks none of them: the receiver of the
//! packet does.
//!
//! [RFC 9000 §19]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19
//! [RFC 9000 §12.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4
//! [RFC 9000 §9.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-9.1
//! [RFC 9002 §2]: https://www.rfc-editor.org/rfc/rfc9002.html#section-2
use self::{
    padding::{PaddingFrame, PaddingRun},
    set::{FrameKind, FrameSetPart, FrameTypeValues},
};
use super::{encryption_level::EncryptionLevel, role::Role};
use crate::var_int::{VarInt, VarIntField, VarIntWidth, codec::read_var_int_field};
use bytes::Buf;
use core::{convert::Infallible, num::NonZeroUsize, ops::RangeInclusive};
use either::Either;
use nitori_io::{SplitTo, error::IncompleteError};
use snafu::Snafu;

pub mod ack;
pub mod codec;
pub mod connection_close;
pub mod crypto;
pub mod data_blocked;
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
pub mod retire_connection_id;
pub mod set;
pub mod stop_sending;
pub mod stream;
pub mod stream_data_blocked;
pub mod streams_blocked;
pub mod write;

#[cfg(test)]
mod tests;

/// Frame Type values.
pub(crate) mod type_value {
    pub(crate) const PADDING: u32 = 0x00;
    pub(crate) const PING: u32 = 0x01;
    pub(crate) const ACK: u32 = 0x02;
    pub(crate) const ACK_ECN: u32 = 0x03;
    pub(crate) const RESET_STREAM: u32 = 0x04;
    pub(crate) const STOP_SENDING: u32 = 0x05;
    pub(crate) const CRYPTO: u32 = 0x06;
    pub(crate) const NEW_TOKEN: u32 = 0x07;
    pub(crate) const STREAM: u32 = 0x08;
    pub(crate) const MAX_DATA: u32 = 0x10;
    pub(crate) const MAX_STREAM_DATA: u32 = 0x11;
    pub(crate) const MAX_STREAMS_BIDI: u32 = 0x12;
    pub(crate) const MAX_STREAMS_UNI: u32 = 0x13;
    pub(crate) const DATA_BLOCKED: u32 = 0x14;
    pub(crate) const STREAM_DATA_BLOCKED: u32 = 0x15;
    pub(crate) const STREAMS_BLOCKED_BIDI: u32 = 0x16;
    pub(crate) const STREAMS_BLOCKED_UNI: u32 = 0x17;
    pub(crate) const NEW_CONNECTION_ID: u32 = 0x18;
    pub(crate) const RETIRE_CONNECTION_ID: u32 = 0x19;
    pub(crate) const PATH_CHALLENGE: u32 = 0x1a;
    pub(crate) const PATH_RESPONSE: u32 = 0x1b;
    pub(crate) const CONNECTION_CLOSE: u32 = 0x1c;
    pub(crate) const CONNECTION_CLOSE_APPLICATION: u32 = 0x1d;
    pub(crate) const HANDSHAKE_DONE: u32 = 0x1e;
}

/// The length of the data of PATH_CHALLENGE and PATH_RESPONSE.
pub const PATH_DATA_LEN: usize = 8;

/// The kind of a frame of version 1, as its Frame Type field announces it.
///
/// Several Frame Type values announce the same kind: the eight STREAM types
/// `0x08..=0x0f`, ACK with and without ECN counts, and the bidirectional and
/// unidirectional forms of MAX_STREAMS and STREAMS_BLOCKED. The two
/// CONNECTION_CLOSE types are two kinds, because the packets they can appear
/// in differ. The variants are named after the frames.
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
    /// CONNECTION_CLOSE with an error of the QUIC layer, `0x1c`.
    ConnectionCloseTransport,
    /// CONNECTION_CLOSE with an error of the application, `0x1d`.
    ConnectionCloseApplication,
    /// HANDSHAKE_DONE, `0x1e`.
    HandshakeDone,
}

impl FrameType {
    /// The kind a Frame Type value announces, or `None` for a value that
    /// RFC 9000 does not define; [`v1::Part`](crate::Part) looks values
    /// up with it.
    pub const fn of(value: VarInt) -> Option<Self> {
        use type_value::*;
        // Every Frame Type of version 1 is below 2^32.
        if value.get() > u32::MAX as u64 {
            return None;
        }
        Some(match value.get() as u32 {
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
            CONNECTION_CLOSE => Self::ConnectionCloseTransport,
            CONNECTION_CLOSE_APPLICATION => Self::ConnectionCloseApplication,
            HANDSHAKE_DONE => Self::HandshakeDone,
            // Every value not matched above is not a frame of version 1.
            _ => return None,
        })
    }
}

/// A Frame Type value of version 1 with the kind it announces: a value that
/// RFC 9000 defines.
///
/// It is constructed only by [`FrameTypeValue::of`], so its kind is always
/// the kind of its value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FrameTypeValue {
    kind: FrameType,
    value: VarInt,
}

impl FrameTypeValue {
    /// The Frame Type value `value` with its kind, or `None` for a value that
    /// RFC 9000 does not define.
    pub const fn of(value: VarInt) -> Option<Self> {
        match FrameType::of(value) {
            Some(kind) => Some(Self { kind, value }),
            None => None,
        }
    }

    /// The kind the value announces.
    pub const fn kind(self) -> FrameType {
        self.kind
    }

    /// The Frame Type value.
    pub const fn get(self) -> VarInt {
        self.value
    }
}

impl FrameKind for FrameType {
    /// The "Pkts" column of [RFC 9000 §12.4] Table 3.
    ///
    /// A packet with a frame its level does not permit is a connection error
    /// of type PROTOCOL_VIOLATION; this method states only the rule of the
    /// frame type, for the receiver to apply.
    ///
    /// - PADDING, PING: every level.
    /// - ACK, CRYPTO: Initial, Handshake and 1-RTT.
    /// - NEW_TOKEN, PATH_RESPONSE, HANDSHAKE_DONE: 1-RTT only.
    /// - CONNECTION_CLOSE of type `0x1c` ([`FrameType::ConnectionCloseTransport`]):
    ///   every level.
    /// - CONNECTION_CLOSE of type `0x1d` ([`FrameType::ConnectionCloseApplication`]):
    ///   0-RTT and 1-RTT. The "ih" mark of the table says that only type
    ///   `0x1c` can appear in Initial and Handshake packets.
    /// - Every other frame: 0-RTT and 1-RTT.
    ///
    /// [RFC 9000 §12.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4
    fn can_appear_in(self, level: EncryptionLevel) -> bool {
        use EncryptionLevel::{Handshake, Initial, OneRtt, ZeroRtt};
        match self {
            Self::Padding | Self::Ping | Self::ConnectionCloseTransport => true,
            Self::Ack | Self::Crypto => matches!(level, Initial | Handshake | OneRtt),
            Self::NewToken | Self::PathResponse | Self::HandshakeDone => {
                matches!(level, OneRtt)
            }
            Self::ResetStream
            | Self::StopSending
            | Self::Stream
            | Self::MaxData
            | Self::MaxStreamData
            | Self::MaxStreams
            | Self::DataBlocked
            | Self::StreamDataBlocked
            | Self::StreamsBlocked
            | Self::NewConnectionId
            | Self::RetireConnectionId
            | Self::PathChallenge
            | Self::ConnectionCloseApplication => matches!(level, ZeroRtt | OneRtt),
        }
    }

    /// Every frame except ACK, PADDING and CONNECTION_CLOSE is ack-eliciting
    /// ([RFC 9002 §2]).
    ///
    /// [RFC 9002 §2]: https://www.rfc-editor.org/rfc/rfc9002.html#section-2
    fn is_ack_eliciting(self) -> bool {
        !matches!(
            self,
            Self::Ack
                | Self::Padding
                | Self::ConnectionCloseTransport
                | Self::ConnectionCloseApplication
        )
    }

    /// A packet is in flight when it is ack-eliciting or contains PADDING
    /// ([RFC 9002 §2]); this is true for every ack-eliciting frame and for
    /// PADDING, and false for ACK and CONNECTION_CLOSE.
    ///
    /// [RFC 9002 §2]: https://www.rfc-editor.org/rfc/rfc9002.html#section-2
    fn counts_in_flight(self) -> bool {
        !matches!(
            self,
            Self::Ack | Self::ConnectionCloseTransport | Self::ConnectionCloseApplication
        )
    }

    /// PATH_CHALLENGE, PATH_RESPONSE, NEW_CONNECTION_ID and PADDING are the
    /// probing frames ([RFC 9000 §9.1]).
    ///
    /// [RFC 9000 §9.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-9.1
    fn is_probing(self) -> bool {
        matches!(
            self,
            Self::PathChallenge | Self::PathResponse | Self::NewConnectionId | Self::Padding
        )
    }

    /// Only a client receives NEW_TOKEN ([RFC 9000 §19.7]) and
    /// HANDSHAKE_DONE ([RFC 9000 §19.20]); both endpoints receive every other
    /// frame.
    ///
    /// [RFC 9000 §19.7]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.7
    /// [RFC 9000 §19.20]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.20
    fn receivable_by(self, role: Role) -> bool {
        match self {
            Self::NewToken | Self::HandshakeDone => role == Role::Client,
            _ => true,
        }
    }
}

/// The frames of version 1, `0x00` to `0x1e`, form a part of a frame set:
/// [`FrameRun`], of the kinds [`FrameType`], claimed as [`FrameTypeValue`], read with the failures
/// [`codec::ReadFieldsError`]. Consecutive PADDING frames are one item, a
/// [`PaddingRun`], and every other frame is an item of its own.
impl FrameSetPart for super::Part {
    type Run<D> = FrameRun<D>;
    type Kind = FrameType;
    type TypeValue = FrameTypeValue;
    type FieldsError = codec::ReadFieldsError;

    const FRAME_TYPE_VALUES: &'static FrameTypeValues =
        &FrameTypeValues::new(&[RangeInclusive::new(
            VarInt::from_u32(type_value::PADDING),
            VarInt::from_u32(type_value::HANDSHAKE_DONE),
        )]);

    fn type_value_of(value: VarInt) -> Option<FrameTypeValue> {
        FrameTypeValue::of(value)
    }

    fn kind_of(type_value: FrameTypeValue) -> FrameType {
        type_value.kind()
    }

    fn run_kind<D>(run: &FrameRun<D>) -> FrameType {
        run.frame_type()
    }

    /// A PADDING frame and the PADDING frames that follow it are one run;
    /// every other frame is read as [`codec::read_fields`] reads it.
    fn read_run<S: Buf + SplitTo>(
        source: &mut S,
        type_value: FrameTypeValue,
    ) -> Result<FrameRun<S>, codec::ReadFieldsError> {
        if type_value.kind() == FrameType::Padding {
            // The Frame Type that was read is the first frame of the run.
            let len = NonZeroUsize::MIN.saturating_add(skip_zeros(source));
            return Ok(FrameRun::Padding(PaddingRun::new(len)));
        }
        codec::read_fields(source, type_value).map(FrameRun::from)
    }
}

/// A frame of version 1, of any type: one frame as it is encoded.
///
/// `D` is the type of the payload fields: the type of the source a frame
/// was read from, or any [`Buf`] for a frame to write.
/// [`FrameRun`] holds the same frames, with PADDING as a run of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame<D> {
    /// A PADDING frame.
    Padding(PaddingFrame),
    /// A PING frame.
    Ping(ping::PingFrame),
    /// An ACK frame.
    Ack(ack::AckFrame),
    /// A RESET_STREAM frame.
    ResetStream(reset_stream::ResetStreamFrame),
    /// A STOP_SENDING frame.
    StopSending(stop_sending::StopSendingFrame),
    /// A CRYPTO frame.
    Crypto(crypto::CryptoFrame<D>),
    /// A NEW_TOKEN frame.
    NewToken(new_token::NewTokenFrame<D>),
    /// A STREAM frame.
    Stream(stream::StreamFrame<D>),
    /// A MAX_DATA frame.
    MaxData(max_data::MaxDataFrame),
    /// A MAX_STREAM_DATA frame.
    MaxStreamData(max_stream_data::MaxStreamDataFrame),
    /// A MAX_STREAMS frame.
    MaxStreams(max_streams::MaxStreamsFrame),
    /// A DATA_BLOCKED frame.
    DataBlocked(data_blocked::DataBlockedFrame),
    /// A STREAM_DATA_BLOCKED frame.
    StreamDataBlocked(stream_data_blocked::StreamDataBlockedFrame),
    /// A STREAMS_BLOCKED frame.
    StreamsBlocked(streams_blocked::StreamsBlockedFrame),
    /// A NEW_CONNECTION_ID frame.
    NewConnectionId(new_connection_id::NewConnectionIdFrame),
    /// A RETIRE_CONNECTION_ID frame.
    RetireConnectionId(retire_connection_id::RetireConnectionIdFrame),
    /// A PATH_CHALLENGE frame.
    PathChallenge(path_challenge::PathChallengeFrame),
    /// A PATH_RESPONSE frame.
    PathResponse(path_response::PathResponseFrame),
    /// A CONNECTION_CLOSE frame.
    ConnectionClose(connection_close::ConnectionCloseFrame<D>),
    /// A HANDSHAKE_DONE frame.
    HandshakeDone(handshake_done::HandshakeDoneFrame),
}

/// A run of frames of version 1: consecutive PADDING frames, or one frame of
/// any other type.
///
/// `D` is the type of the payload fields, as for [`Frame`]. The variants are
/// those of [`Frame`], and hold the same frame structs, except that PADDING
/// holds a [`PaddingRun`]. This is what [`Frames`](set::Frames) gives for a
/// set of version 1, and what [`codec::write_frame_run`] writes. A [`Frame`]
/// converts into a run of one frame with `From`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameRun<D> {
    /// A run of PADDING frames.
    Padding(PaddingRun),
    /// A PING frame.
    Ping(ping::PingFrame),
    /// An ACK frame.
    Ack(ack::AckFrame),
    /// A RESET_STREAM frame.
    ResetStream(reset_stream::ResetStreamFrame),
    /// A STOP_SENDING frame.
    StopSending(stop_sending::StopSendingFrame),
    /// A CRYPTO frame.
    Crypto(crypto::CryptoFrame<D>),
    /// A NEW_TOKEN frame.
    NewToken(new_token::NewTokenFrame<D>),
    /// A STREAM frame.
    Stream(stream::StreamFrame<D>),
    /// A MAX_DATA frame.
    MaxData(max_data::MaxDataFrame),
    /// A MAX_STREAM_DATA frame.
    MaxStreamData(max_stream_data::MaxStreamDataFrame),
    /// A MAX_STREAMS frame.
    MaxStreams(max_streams::MaxStreamsFrame),
    /// A DATA_BLOCKED frame.
    DataBlocked(data_blocked::DataBlockedFrame),
    /// A STREAM_DATA_BLOCKED frame.
    StreamDataBlocked(stream_data_blocked::StreamDataBlockedFrame),
    /// A STREAMS_BLOCKED frame.
    StreamsBlocked(streams_blocked::StreamsBlockedFrame),
    /// A NEW_CONNECTION_ID frame.
    NewConnectionId(new_connection_id::NewConnectionIdFrame),
    /// A RETIRE_CONNECTION_ID frame.
    RetireConnectionId(retire_connection_id::RetireConnectionIdFrame),
    /// A PATH_CHALLENGE frame.
    PathChallenge(path_challenge::PathChallengeFrame),
    /// A PATH_RESPONSE frame.
    PathResponse(path_response::PathResponseFrame),
    /// A CONNECTION_CLOSE frame.
    ConnectionClose(connection_close::ConnectionCloseFrame<D>),
    /// A HANDSHAKE_DONE frame.
    HandshakeDone(handshake_done::HandshakeDoneFrame),
}

/// Applies `$body` to the frame struct inside each variant of the enum
/// `$enum`, [`Frame`] or [`FrameRun`], PADDING included.
macro_rules! each_frame {
    ($enum:ident, $frame:expr, $inner:ident => $body:expr) => {
        match $frame {
            $enum::Padding($inner) => $body,
            $enum::Ping($inner) => $body,
            $enum::Ack($inner) => $body,
            $enum::ResetStream($inner) => $body,
            $enum::StopSending($inner) => $body,
            $enum::Crypto($inner) => $body,
            $enum::NewToken($inner) => $body,
            $enum::Stream($inner) => $body,
            $enum::MaxData($inner) => $body,
            $enum::MaxStreamData($inner) => $body,
            $enum::MaxStreams($inner) => $body,
            $enum::DataBlocked($inner) => $body,
            $enum::StreamDataBlocked($inner) => $body,
            $enum::StreamsBlocked($inner) => $body,
            $enum::NewConnectionId($inner) => $body,
            $enum::RetireConnectionId($inner) => $body,
            $enum::PathChallenge($inner) => $body,
            $enum::PathResponse($inner) => $body,
            $enum::ConnectionClose($inner) => $body,
            $enum::HandshakeDone($inner) => $body,
        }
    };
}

/// Implements the methods that [`Frame`] and [`FrameRun`] share.
macro_rules! frame_methods {
    ($enum:ident) => {
        impl<D> $enum<D> {
            /// The kind of the frame, or of the frames of a run.
            pub fn frame_type(&self) -> FrameType {
                each_frame!($enum, self, frame => frame.frame_type())
            }

            /// Whether a packet containing this frame is ack-eliciting; see
            /// [`FrameKind::is_ack_eliciting`].
            pub fn is_ack_eliciting(&self) -> bool {
                self.frame_type().is_ack_eliciting()
            }

            /// Whether a packet containing this frame counts as in flight; see
            /// [`FrameKind::counts_in_flight`].
            pub fn counts_in_flight(&self) -> bool {
                self.frame_type().counts_in_flight()
            }

            /// The Frame Type value the write function writes, for each frame
            /// of a run.
            pub fn type_value(&self) -> VarInt {
                each_frame!($enum, self, frame => frame.type_value())
            }
        }

        impl<D: Buf> $enum<D> {
            /// The number of bytes the write function writes.
            pub fn encoded_len(&self) -> usize {
                each_frame!($enum, self, frame => frame.encoded_len())
            }
        }
    };
}

frame_methods!(Frame);
frame_methods!(FrameRun);

/// A frame is a run of one frame.
impl<D> From<Frame<D>> for FrameRun<D> {
    fn from(frame: Frame<D>) -> Self {
        match frame {
            Frame::Padding(frame) => Self::Padding(frame.into()),
            Frame::Ping(frame) => Self::Ping(frame),
            Frame::Ack(frame) => Self::Ack(frame),
            Frame::ResetStream(frame) => Self::ResetStream(frame),
            Frame::StopSending(frame) => Self::StopSending(frame),
            Frame::Crypto(frame) => Self::Crypto(frame),
            Frame::NewToken(frame) => Self::NewToken(frame),
            Frame::Stream(frame) => Self::Stream(frame),
            Frame::MaxData(frame) => Self::MaxData(frame),
            Frame::MaxStreamData(frame) => Self::MaxStreamData(frame),
            Frame::MaxStreams(frame) => Self::MaxStreams(frame),
            Frame::DataBlocked(frame) => Self::DataBlocked(frame),
            Frame::StreamDataBlocked(frame) => Self::StreamDataBlocked(frame),
            Frame::StreamsBlocked(frame) => Self::StreamsBlocked(frame),
            Frame::NewConnectionId(frame) => Self::NewConnectionId(frame),
            Frame::RetireConnectionId(frame) => Self::RetireConnectionId(frame),
            Frame::PathChallenge(frame) => Self::PathChallenge(frame),
            Frame::PathResponse(frame) => Self::PathResponse(frame),
            Frame::ConnectionClose(frame) => Self::ConnectionClose(frame),
            Frame::HandshakeDone(frame) => Self::HandshakeDone(frame),
        }
    }
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

// What the frames of every part share: the Length field of STREAM and DATAGRAM
// frames, the limits that tie a payload to its length and offset, and the
// encoding of the fields before a payload.

/// The Frame Type value `value` as a variable-length integer.
pub const fn type_var_int(value: u32) -> VarInt {
    VarInt::from_u32(value)
}

/// The absence of a Length field in a STREAM or DATAGRAM frame: the data
/// extends to the end of the packet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct NoLength;

/// A STREAM frame whose Length field is not decided yet, as the type
/// parameter `L` of `sakuya_wire_v1::frame::stream::StreamFrame`.
///
/// It is not a [`LengthKind`]: a frame of this kind has no write function, so
/// the types stop a frame from being written before its Length field is
/// decided. `sakuya_wire_v1::frame::stream::StreamFrame::into_with_length`
/// and `sakuya_wire_v1::frame::stream::StreamFrame::into_without_length`
/// decide it. Reading never gives this kind.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct UndecidedLength;

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
/// type parameter `L` of `sakuya_wire_v1::frame::stream::StreamFrame`
/// and of `DatagramFrame` in `sakuya_wire_datagram`.
///
/// It is implemented by exactly four types:
///
/// - [`VarIntWidth`]: the frame has a Length field, of this width;
/// - [`NoLength`]: the frame has no Length field, and its data extends to
///   the end of the packet;
/// - [`Either<NoLength, VarIntWidth>`](Either): either of the two, as a frame
///   that was read states it. This is the default, so `StreamFrame<D>` and
///   `DatagramFrame<D>` are frames as they are read;
/// - [`Either<VarIntWidth, NoLength>`](Either): either of the two, in the
///   other order.
///
/// The two single kinds convert into each `Either` kind with `From`. A frame
/// of an `Either` kind converts with `From` into an `Either` of frames of
/// its two kinds, in the same order, such as
/// `Either<StreamFrame<D, NoLength>, StreamFrame<D, VarIntWidth>>` for `StreamFrame<D>`,
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
pub fn length_width<L: LengthKind>(length: L) -> Option<VarIntWidth> {
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
    pub fn check(offset: VarInt, length: u64) -> Result<(), Self> {
        if length > VarInt::MAX.get() - offset.get() {
            return Err(Self { offset, length });
        }
        Ok(())
    }

    /// The largest data length permitted after `offset`, capped to `usize`.
    pub fn limit(offset: VarInt) -> usize {
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
    pub fn check(length: usize, width: VarIntWidth) -> Result<VarInt, Self> {
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
pub fn length_field_len(length: usize) -> usize {
    VarInt::try_from(length).map_or(VarInt::MAX_ENCODED_LEN, VarInt::encoded_len)
}

/// Reads a variable-length integer field of a type that every value
/// converts into.
pub fn read_field<T>(src: &mut impl Buf) -> Result<VarIntField<T>, IncompleteError>
where
    T: Copy + Into<VarInt> + TryFrom<VarInt, Error = Infallible>,
{
    read_var_int_field(src).map_err(IncompleteError::from)
}

/// The largest `n` with `fixed + len(n) + n <= room` and `n <= limit`, where
/// `len(n)` is the length of the Length field.
pub fn max_len_with_length_field(fixed: usize, limit: usize, room: usize) -> Option<usize> {
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
/// `N` is the number of bytes the head holds; a frame type that sizes it
/// for the longest encoding of its fields never has one refused.
pub struct Head<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> Head<N> {
    /// A head starting with the Frame Type `frame_type`.
    ///
    /// # Errors
    ///
    /// [`HeadCapacityError`] if the `N` bytes do not hold the Frame Type.
    pub fn new(frame_type: VarInt) -> Result<Self, HeadCapacityError> {
        Self {
            bytes: [0; N],
            len: 0,
        }
        .var_int(frame_type)
    }

    /// Appends the shortest encoding of `value`.
    ///
    /// # Errors
    ///
    /// [`HeadCapacityError`] if the bytes left do not hold the encoding.
    pub fn var_int(self, value: VarInt) -> Result<Self, HeadCapacityError> {
        self.var_int_of(value, VarIntWidth::shortest(value))
    }

    /// Appends the encoding of `value` of `width`, which holds the value.
    ///
    /// # Errors
    ///
    /// [`HeadCapacityError`] if the bytes left do not hold the encoding.
    pub fn var_int_of(self, value: VarInt, width: VarIntWidth) -> Result<Self, HeadCapacityError> {
        let (encoding, encoded_len) = value.to_encoding_of(width);
        self.bytes(&encoding[..encoded_len])
    }

    /// Appends the encoding of `field` at its width.
    ///
    /// # Errors
    ///
    /// [`HeadCapacityError`] if the bytes left do not hold the encoding.
    pub fn field<T>(self, field: VarIntField<T>) -> Result<Self, HeadCapacityError>
    where
        T: Copy + Into<VarInt> + TryFrom<VarInt>,
    {
        self.var_int_of(field.to_var_int(), field.width())
    }

    /// Appends `bytes`.
    ///
    /// # Errors
    ///
    /// [`HeadCapacityError`] if the bytes left do not hold `bytes`.
    pub fn bytes(mut self, bytes: &[u8]) -> Result<Self, HeadCapacityError> {
        let end = self.len + bytes.len();
        if end > N {
            return Err(HeadCapacityError {
                capacity: N,
                held: self.len,
                added: bytes.len(),
            });
        }
        self.bytes[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Ok(self)
    }

    /// The encoded fields.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// The length of the encoded fields.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether no field is encoded yet: never, once [`new`](Self::new)
    /// wrote the Frame Type.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// The bytes given to a frame head ([`Head`]) do not fit in what it holds.
///
/// It is constructed only when the check fails, so the bytes held and the
/// bytes added always exceed the capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("frame head of {capacity} bytes holds {held} and cannot take {added} more"))]
pub struct HeadCapacityError {
    capacity: usize,
    held: usize,
    added: usize,
}

impl HeadCapacityError {
    /// The number of bytes the head holds.
    pub const fn capacity(self) -> usize {
        self.capacity
    }

    /// The number of bytes the head held before.
    pub const fn held(self) -> usize {
        self.held
    }

    /// The number of bytes that were to be added, more than are left.
    pub const fn added(self) -> usize {
        self.added
    }
}
