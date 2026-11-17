//! Reading the version 1 fields of a long header packet, and writing version 1
//! headers.
//!
//! [`read_long_packet`] continues after [`read_long_header`] has read the
//! version-independent fields.
//!
//! ```
//! use sakuya_wire::header::codec::read_long_header;
//! use sakuya_wire::v1::header::{TypeFields, codec::read_long_packet};
//!
//! // A Handshake packet with an empty DCID and a 4-byte SCID, followed by
//! // the first byte of a coalesced short header packet.
//! let datagram = [0xe0, 0, 0, 0, 1, 0, 4, 9, 9, 9, 9, 3, 0xaa, 0xbb, 0xcc, 0x41];
//! let mut input = &datagram[..];
//! let header = read_long_header(&mut input).unwrap();
//! let packet = read_long_packet(&mut input, header).unwrap();
//! let TypeFields::Handshake { bounds, protected } = packet.fields() else { panic!() };
//! assert_eq!((bounds.packet_number_offset(), bounds.end()), (12, 15));
//! assert_eq!(*protected, [0xaa, 0xbb, 0xcc]);
//! assert_eq!(input, [0x41]); // The next packet starts here.
//! ```
//!
//! [`write_long_packet_header`] writes the header of an Initial, 0-RTT or
//! Handshake packet from the first byte to the Length field,
//! [`write_short_packet_header`] the header of a 1-RTT packet up to its
//! Packet Number field, and [`write_retry_packet_without_tag`] a Retry packet
//! up to its integrity tag.
//!
//! ```
//! use bytes::Bytes;
//! use sakuya_wire::{
//!     connection_id::ConnectionId,
//!     v1::header::{LongPacketHeader, codec::write_long_packet_header},
//!     v1::packet_number::PacketNumberLength,
//!     var_int::{VarInt, VarIntField, VarIntWidth, codec::write_var_int_field},
//! };
//!
//! let dcid = ConnectionId::new(&[1, 2]).unwrap();
//! // Reserve a two-byte Length field; write the real value once it is known.
//! let reserved = VarIntField::new(VarInt::from(0u8), VarIntWidth::Two).unwrap();
//! let header = LongPacketHeader::initial(
//!     dcid, ConnectionId::EMPTY, VarIntWidth::One, Bytes::new(), PacketNumberLength::Two, reserved,
//! ).unwrap();
//!
//! let mut packet = Vec::new();
//! write_long_packet_header(&mut packet, header.clone());
//! assert_eq!(packet.len(), header.packet_number_offset());
//! packet.extend_from_slice(&[0xaa; 20]); // Packet Number and payload.
//!
//! let length = VarIntField::new(VarInt::from(20u8), VarIntWidth::Two).unwrap();
//! write_var_int_field(&mut &mut packet[header.length_offset()..], length);
//! assert_eq!(packet[..8], [0xc1, 0, 0, 0, 1, 2, 1, 2]);
//! assert_eq!(packet[8..13], [0, 0, 0x40, 20, 0xaa]);
//! ```
//!
//! A Retry packet ends with an integrity tag computed over the bytes before
//! it and the original destination connection ID ([RFC 9001 §5.8]); the
//! sender computes it from what [`write_retry_packet_without_tag`] wrote and
//! appends it.
//!
//! ```
//! use sakuya_wire::{
//!     connection_id::ConnectionId,
//!     v1::header::codec::write_retry_packet_without_tag,
//! };
//!
//! let scid = ConnectionId::new(&[0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5]).unwrap();
//! let mut packet = Vec::new();
//! write_retry_packet_without_tag(&mut packet, 0x0f, ConnectionId::EMPTY, scid, b"token");
//! assert_eq!(packet[..7], [0xff, 0, 0, 0, 1, 0, 8]);
//! assert_eq!(packet[15..], *b"token");
//! // The 16-byte Retry Integrity Tag follows.
//! ```
//!
//! [`read_long_header`]: crate::header::codec::read_long_header
//! [RFC 9001 §5.8]: https://www.rfc-editor.org/rfc/rfc9001.html#section-5.8
use super::{
    FIXED_BIT, LongPacket, LongPacketHeader, LongPacketType, PacketBounds, RETRY_INTEGRITY_TAG_LEN,
    ShortPacketHeader, TypeFields, VERSION, WrittenKind,
};
use crate::{
    connection_id::{ConnectionId, ConnectionIdLengthError},
    header::{FORM_BIT, LongHeader},
    source::{read_payload, read_payload_to_end},
    var_int::{VarInt, codec::read_var_int_with_width},
    version::Version,
};
use bytes::{Buf, BufMut};
use nitori_io::{SplitTo, error::IncompleteError};
use snafu::{ResultExt, Snafu};

/// Reads the version 1 fields that follow the version-independent fields of
/// `header`: for Initial, 0-RTT and Handshake packets up to the end of the
/// Length field's range, and for a Retry packet the rest of the source.
///
/// # Errors
///
/// - [`ReadLongPacketError::Version`] if the version is not [`VERSION`], and
///   [`ReadLongPacketError::DcidLength`] or [`ReadLongPacketError::ScidLength`]
///   if a connection ID exceeds [`ConnectionId::MAX_LEN`], without reading;
/// - [`ReadLongPacketError::TokenLength`] or [`ReadLongPacketError::Token`] if
///   the token of an Initial packet cannot be read;
/// - [`ReadLongPacketError::Length`] if the Length field cannot be read, and
///   [`ReadLongPacketError::Protected`] if the source ends before the end of
///   its range;
/// - [`ReadLongPacketError::RetryIntegrityTag`] if the rest of a Retry
///   packet is too short for its integrity tag.
///
/// The token of an Initial packet and the range of the Length field are
/// pieces of the source.
pub fn read_long_packet<S: Buf + SplitTo>(
    src: &mut S,
    header: LongHeader,
) -> Result<LongPacket<S>, ReadLongPacketError> {
    NotV1VersionError::check(header.version())?;
    let dcid =
        ConnectionId::try_from(*header.dcid()).context(read_long_packet_error::DcidLengthSnafu)?;
    let scid =
        ConnectionId::try_from(*header.scid()).context(read_long_packet_error::ScidLengthSnafu)?;
    let offset = header.version_specific_offset();
    let fields = match LongPacketType::of(header.first_byte()) {
        LongPacketType::Initial => {
            let (token_len, token_len_width) =
                read_var_int_with_width(src).context(read_long_packet_error::TokenLengthSnafu)?;
            let token_len = saturating_usize(token_len);
            let token = read_payload(src, token_len).context(read_long_packet_error::TokenSnafu)?;
            let (bounds, protected) =
                read_bounded(src, offset + token_len_width.encoded_len() + token_len)?;
            TypeFields::Initial {
                token,
                bounds,
                protected,
            }
        }
        LongPacketType::ZeroRtt => {
            let (bounds, protected) = read_bounded(src, offset)?;
            TypeFields::ZeroRtt { bounds, protected }
        }
        LongPacketType::Handshake => {
            let (bounds, protected) = read_bounded(src, offset)?;
            TypeFields::Handshake { bounds, protected }
        }
        LongPacketType::Retry => {
            let mut rest = read_payload_to_end(src);
            let length = rest.remaining();
            let token_len = RetryIntegrityTagError::check(length)?;
            // invariant: `rest` holds `token_len` bytes and the tag after them.
            let token = rest.copy_to_bytes(token_len);
            let mut integrity_tag = [0; RETRY_INTEGRITY_TAG_LEN];
            rest.copy_to_slice(&mut integrity_tag);
            TypeFields::Retry {
                token,
                integrity_tag,
                end: offset + length,
            }
        }
    };
    Ok(LongPacket {
        header,
        dcid,
        scid,
        fields,
    })
}

/// Reads the Length field at `offset` and the range it covers.
fn read_bounded<S: Buf + SplitTo>(
    src: &mut S,
    offset: usize,
) -> Result<(PacketBounds, S), ReadLongPacketError> {
    let (length, length_width) =
        read_var_int_with_width(src).context(read_long_packet_error::LengthSnafu)?;
    let protected = read_payload(src, saturating_usize(length))
        .context(read_long_packet_error::ProtectedSnafu { length })?;
    let packet_number_offset = offset + length_width.encoded_len();
    let bounds = PacketBounds {
        length,
        packet_number_offset,
        end: packet_number_offset + protected.remaining(),
    };
    Ok((bounds, protected))
}

/// A variable-length integer as a length in memory, saturating where `usize`
/// is narrower; a saturated length exceeds every source.
fn saturating_usize(value: VarInt) -> usize {
    usize::try_from(value.get()).unwrap_or(usize::MAX)
}

/// Failures that [`read_long_packet`] can produce.
#[derive(Debug, Snafu)]
#[snafu(module(read_long_packet_error), visibility(pub(in crate::v1)))]
pub enum ReadLongPacketError {
    /// The version is not QUIC version 1.
    #[snafu(transparent)]
    Version {
        /// The broken rule.
        source: NotV1VersionError,
    },
    /// The destination connection ID is longer than version 1 allows.
    #[snafu(display("invalid destination connection ID"))]
    DcidLength {
        /// The rejected length.
        source: ConnectionIdLengthError,
    },
    /// The source connection ID is longer than version 1 allows.
    #[snafu(display("invalid source connection ID"))]
    ScidLength {
        /// The rejected length.
        source: ConnectionIdLengthError,
    },
    /// The Token Length field of an Initial packet could not be read.
    #[snafu(display("the Token Length field read failed"))]
    TokenLength {
        /// The failure of reading the field.
        source: IncompleteError,
    },
    /// The token of an Initial packet could not be read.
    #[snafu(display("token read failed"))]
    Token {
        /// The failure of reading the token.
        source: IncompleteError,
    },
    /// The Length field could not be read.
    #[snafu(display("the Length field read failed"))]
    Length {
        /// The failure of reading the field.
        source: IncompleteError,
    },
    /// The range of the Length field could not be read: the source ended
    /// within it, so the packet's boundary is unknown.
    #[snafu(display("the Length field range of {length} bytes read failed"))]
    Protected {
        /// The value of the Length field.
        length: VarInt,
        /// The failure of reading the range.
        source: IncompleteError,
    },
    /// A Retry packet is too short for its integrity tag.
    #[snafu(transparent)]
    RetryIntegrityTag {
        /// The broken rule.
        source: RetryIntegrityTagError,
    },
}

/// The Version field of a long header read as a version 1 packet is not
/// [`VERSION`].
///
/// It is constructed only when the check fails, so the version it holds is
/// never [`Version::V1`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("version {version} is not QUIC version 1"))]
pub struct NotV1VersionError {
    version: Version,
}

impl NotV1VersionError {
    /// The version field, not [`Version::V1`].
    pub const fn version(self) -> Version {
        self.version
    }

    /// Checks that `version` is QUIC version 1.
    fn check(version: Version) -> Result<(), Self> {
        if version != VERSION {
            return Err(Self { version });
        }
        Ok(())
    }
}

/// A Retry packet is too short for its 16-byte integrity tag.
///
/// It is constructed only when the check fails, so the length it holds is
/// always below 16.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "Retry packet has {length} bytes after its header, fewer than its 16-byte integrity tag"
))]
pub struct RetryIntegrityTagError {
    length: usize,
}

impl RetryIntegrityTagError {
    /// The bytes after the source connection ID, fewer than 16.
    pub const fn length(self) -> usize {
        self.length
    }

    /// The length of the token in the `length` bytes after the source
    /// connection ID, which end with the integrity tag.
    fn check(length: usize) -> Result<usize, Self> {
        length
            .checked_sub(RETRY_INTEGRITY_TAG_LEN)
            .ok_or(Self { length })
    }
}

impl ReadLongPacketError {
    /// Whether the source ended within the packet.
    pub fn is_incomplete(&self) -> bool {
        match self {
            Self::TokenLength { .. }
            | Self::Length { .. }
            | Self::Token { .. }
            | Self::Protected { .. }
            | Self::RetryIntegrityTag { .. } => true,
            Self::Version { .. } | Self::DcidLength { .. } | Self::ScidLength { .. } => false,
        }
    }
}

/// Writes `header` from the first byte to the end of the Length field, up to
/// the Packet Number field.
///
/// The Length field is written with the value and the width the header
/// states.
///
/// # Panics
///
/// If `dst` has no room for the header, as [`BufMut`] does.
pub fn write_long_packet_header(dst: &mut impl BufMut, header: LongPacketHeader) {
    dst.put_u8(header.first_byte());
    dst.put_slice(&VERSION.to_be_bytes());
    dst.put_u8(u8::from(header.dcid.length()));
    dst.put_slice(header.dcid.as_bytes());
    dst.put_u8(u8::from(header.scid.length()));
    dst.put_slice(header.scid.as_bytes());
    if let WrittenKind::Initial(initial) = &header.kind {
        // Construction checked that the width holds the token length.
        let token_len = VarInt::try_from(initial.token.len()).unwrap_or(VarInt::ZERO);
        let (encoding, encoded_len) = token_len.to_encoding_of(initial.length_width);
        dst.put_slice(&encoding[..encoded_len]);
        dst.put_slice(&initial.token);
    }
    let (length, length_len) = header
        .length
        .to_var_int()
        .to_encoding_of(header.length.width());
    dst.put_slice(&length[..length_len]);
}

/// Writes the first byte and the destination connection ID of `header`, up to
/// the Packet Number field.
///
/// # Panics
///
/// If `dst` has no room for the header, as [`BufMut`] does.
pub fn write_short_packet_header(dst: &mut impl BufMut, header: ShortPacketHeader) {
    dst.put_u8(header.first_byte());
    dst.put_slice(header.dcid().as_bytes());
}

/// The Long Packet Type bits of a Retry packet, `0b11`, in place in the
/// first byte.
const RETRY_TYPE_BITS: u8 = 0b11 << 4;

/// The bits of the first byte of a Retry packet that form its Unused field.
const RETRY_UNUSED_MASK: u8 = 0x0f;

/// Writes a Retry packet ([RFC 9000 §17.2.5]) from the first byte to the end
/// of the Retry Token, up to the Retry Integrity Tag.
///
/// The first byte has the form, the Fixed Bit and the Retry packet type set,
/// and its Unused field holds the low four bits of `unused`, the high four
/// bits of `unused` being ignored. [RFC 9000 §17.2.5] lets the server set the
/// Unused field to any value and requires the client to ignore it; nothing
/// in a Retry packet is protected. The version is [`VERSION`]. A server puts
/// the source connection ID of the client's Initial in `dcid` and a
/// connection ID of its choice, other than the destination connection ID of
/// that Initial, in `scid` ([RFC 9000 §17.2.5.1]). A client discards a Retry
/// packet whose `token` is empty ([RFC 9000 §17.2.5.2]).
///
/// The sender appends the 16-byte Retry Integrity Tag ([RFC 9001 §5.8]),
/// computed over the written bytes; the packet read back with
/// [`read_long_header`](crate::header::codec::read_long_header) and
/// [`read_long_packet`] then reads as the same fields.
///
/// # Panics
///
/// If `dst` has no room for the packet, as [`BufMut`] does.
///
/// [RFC 9000 §17.2.5]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.5
/// [RFC 9000 §17.2.5.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.5.1
/// [RFC 9000 §17.2.5.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.5.2
/// [RFC 9001 §5.8]: https://www.rfc-editor.org/rfc/rfc9001.html#section-5.8
pub fn write_retry_packet_without_tag(
    dst: &mut impl BufMut,
    unused: u8,
    dcid: ConnectionId,
    scid: ConnectionId,
    token: &[u8],
) {
    dst.put_u8(FORM_BIT | FIXED_BIT | RETRY_TYPE_BITS | (unused & RETRY_UNUSED_MASK));
    dst.put_slice(&VERSION.to_be_bytes());
    dst.put_u8(u8::from(dcid.length()));
    dst.put_slice(dcid.as_bytes());
    dst.put_u8(u8::from(scid.length()));
    dst.put_slice(scid.as_bytes());
    dst.put_slice(token);
}
