//! Reading the version 1 fields of a long header packet, and writing version 1
//! headers, as `nitori_call` operations.
//!
//! [`read_long_packet`] continues after [`read_long_header`] has read the
//! version-independent fields. It is also the operation struct
//! [`ReadLongPacket`], with `ReadLongPacketExt` on receiver accesses inside
//! other operations and `ReadLongPacketHostExt` on call executors, including
//! the `sync_` methods for receivers that never wait.
//!
//! ```
//! use sakuya_wire::header::codec::ReadLongHeaderHostExt as _;
//! use sakuya_wire::v1::header::{TypeFields, codec::ReadLongPacketHostExt as _};
//!
//! // A Handshake packet with an empty DCID and a 4-byte SCID, followed by
//! // the first byte of a coalesced short header packet.
//! let datagram = [0xe0, 0, 0, 0, 1, 0, 4, 9, 9, 9, 9, 3, 0xaa, 0xbb, 0xcc, 0x41];
//! let mut input = &datagram[..];
//! let header = input.sync_read_long_header_unpin().unwrap();
//! let packet = input.sync_read_long_packet_unpin(header).unwrap();
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
//! up to its integrity tag. Each is also an operation struct, such as
//! [`WriteLongPacketHeader`], with `{Name}Ext` and `{Name}HostExt`.
//!
//! ```
//! use bytes::Bytes;
//! use sakuya_wire::{
//!     connection_id::ConnectionId,
//!     v1::header::{LongPacketHeader, codec::WriteLongPacketHeaderHostExt as _},
//!     v1::packet_number::PacketNumberLength,
//!     var_int::{VarInt, VarIntField, VarIntWidth, codec::WriteVarIntFieldHostExt as _},
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
//! packet.sync_write_long_packet_header_unpin(header.clone()).unwrap();
//! assert_eq!(packet.len(), header.packet_number_offset());
//! packet.extend_from_slice(&[0xaa; 20]); // Packet Number and payload.
//!
//! let length = VarIntField::new(VarInt::from(20u8), VarIntWidth::Two).unwrap();
//! (&mut packet[header.length_offset()..]).sync_write_var_int_field_unpin(length).unwrap();
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
//!     v1::header::codec::WriteRetryPacketWithoutTagHostExt as _,
//! };
//!
//! let scid = ConnectionId::new(&[0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5]).unwrap();
//! let mut packet = Vec::new();
//! packet
//!     .sync_write_retry_packet_without_tag_unpin(0x0f, ConnectionId::EMPTY, scid, b"token")
//!     .unwrap();
//! assert_eq!(packet[..7], [0xff, 0, 0, 0, 1, 0, 8]);
//! assert_eq!(packet[15..], *b"token");
//! // The 16-byte Retry Integrity Tag follows.
//! ```
//!
//! [`read_long_header`]: crate::header::codec::read_long_header
//! [RFC 9001 §5.8]: https://www.rfc-editor.org/rfc/rfc9001.html#section-5.8
// `#[call]` generates constructors, fields and extension traits without
// documentation comments; the module documentation above describes them.
#![allow(missing_docs)]

use super::{
    FIXED_BIT, LongPacket, LongPacketHeader, LongPacketType, PacketBounds, RETRY_INTEGRITY_TAG_LEN,
    ShortPacketHeader, TypeFields, VERSION, WrittenKind,
};
use crate::{
    connection_id::{ConnectionId, ConnectionIdLengthError},
    header::{FORM_BIT, LongHeader},
    payload::{ReadPayloadError, read_payload, read_payload_to_end},
    var_int::{
        VarInt,
        codec::{ReadVarIntError, read_var_int_counted},
    },
    version::Version,
};
use bytes::{Buf, Bytes};
use nitori_call::{ReceiverAccess, call};
use nitori_io::{calls::WriteAllError, prelude::*};
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
/// - [`ReadLongPacketError::Retry`] if the rest of a Retry packet cannot be
///   read, and [`ReadLongPacketError::RetryIntegrityTag`] if it is too short
///   for its integrity tag.
///
/// # Panics
///
/// If the receiver returns a chunk longer than requested, which breaks the
/// `ReadChunk` contract of `nitori_io`; see [`payload`](crate::payload).
#[call(sync)]
pub async fn read_long_packet<F, A>(
    io: &mut A,
    header: LongHeader,
) -> Result<LongPacket<F::Chunk>, ReadLongPacketError<F::Error>>
where
    F: ReadChunk<Chunk: Default>,
    A: ReceiverAccess<Family = F>,
{
    NotV1VersionError::check(header.version())?;
    let dcid =
        ConnectionId::try_from(*header.dcid()).context(read_long_packet_error::DcidLengthSnafu)?;
    let scid =
        ConnectionId::try_from(*header.scid()).context(read_long_packet_error::ScidLengthSnafu)?;
    let offset = header.version_specific_offset();
    let fields = match LongPacketType::of(header.first_byte()) {
        LongPacketType::Initial => {
            let (token_len, token_len_len) = read_var_int_counted(io)
                .await
                .context(read_long_packet_error::TokenLengthSnafu)?;
            let token_len = saturating_usize(token_len);
            let token = read_payload(io, token_len)
                .await
                .context(read_long_packet_error::TokenSnafu)?;
            let (bounds, protected) = read_bounded(io, offset + token_len_len + token_len).await?;
            TypeFields::Initial {
                token,
                bounds,
                protected,
            }
        }
        LongPacketType::ZeroRtt => {
            let (bounds, protected) = read_bounded(io, offset).await?;
            TypeFields::ZeroRtt { bounds, protected }
        }
        LongPacketType::Handshake => {
            let (bounds, protected) = read_bounded(io, offset).await?;
            TypeFields::Handshake { bounds, protected }
        }
        LongPacketType::Retry => {
            let mut rest = read_payload_to_end(io)
                .await
                .context(read_long_packet_error::RetrySnafu)?;
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
async fn read_bounded<F, A>(
    io: &mut A,
    offset: usize,
) -> Result<(PacketBounds, F::Chunk), ReadLongPacketError<F::Error>>
where
    F: ReadChunk<Chunk: Default>,
    A: ReceiverAccess<Family = F>,
{
    let (length, length_len) = read_var_int_counted(io)
        .await
        .context(read_long_packet_error::LengthSnafu)?;
    let protected = read_payload(io, saturating_usize(length))
        .await
        .context(read_long_packet_error::ProtectedSnafu { length })?;
    let packet_number_offset = offset + length_len;
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
pub enum ReadLongPacketError<E> {
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
        source: ReadVarIntError<E>,
    },
    /// The token of an Initial packet could not be read.
    #[snafu(display("token read failed"))]
    Token {
        /// The failure of reading the token.
        source: ReadPayloadError<E>,
    },
    /// The Length field could not be read.
    #[snafu(display("the Length field read failed"))]
    Length {
        /// The failure of reading the field.
        source: ReadVarIntError<E>,
    },
    /// The range of the Length field could not be read; when the source
    /// ended within it, the packet's boundary is unknown.
    #[snafu(display("the Length field range of {length} bytes read failed"))]
    Protected {
        /// The value of the Length field.
        length: VarInt,
        /// The failure of reading the range.
        source: ReadPayloadError<E>,
    },
    /// The rest of a Retry packet could not be read.
    #[snafu(display("Retry packet read failed"))]
    Retry {
        /// The failure of reading the rest.
        source: ReadPayloadError<E>,
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

impl<E> ReadLongPacketError<E> {
    /// Whether the source ended within the packet.
    pub fn is_incomplete(&self) -> bool {
        match self {
            Self::TokenLength { source } | Self::Length { source } => source.is_incomplete(),
            Self::Token { source } | Self::Protected { source, .. } | Self::Retry { source } => {
                source.is_incomplete()
            }
            Self::RetryIntegrityTag { .. } => true,
            Self::Version { .. } | Self::DcidLength { .. } | Self::ScidLength { .. } => false,
        }
    }
}

/// The longest prefix of the header before the token and the Length field:
/// the first byte, the version, two connection IDs with their length bytes
/// and the longest Token Length field.
const PREFIX_MAX: usize = 1 + 4 + 1 + ConnectionId::MAX_LEN + 1 + ConnectionId::MAX_LEN + 8;

/// Writes `header` from the first byte to the end of the Length field, up to
/// the Packet Number field.
///
/// The Length field is written with the value and the width the header
/// states.
///
/// Acceptance by the receiver does not imply flushing or delivery.
///
/// # Errors
///
/// [`WriteAllError`] if the receiver stops accepting bytes or fails; bytes
/// accepted before stay written.
#[call(sync)]
pub async fn write_long_packet_header<F: Write, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    header: LongPacketHeader,
) -> Result<(), WriteAllError<F::Error>> {
    let mut prefix = [0; PREFIX_MAX];
    let mut len = 0;
    let mut put = |bytes: &[u8]| {
        // invariant: `PREFIX_MAX` is the longest the pieces below add up to.
        prefix[len..len + bytes.len()].copy_from_slice(bytes);
        len += bytes.len();
    };
    put(&[header.first_byte()]);
    put(&VERSION.to_be_bytes());
    put(&[u8::from(header.dcid.length())]);
    put(header.dcid.as_bytes());
    put(&[u8::from(header.scid.length())]);
    put(header.scid.as_bytes());
    let token = match &header.kind {
        WrittenKind::Initial(initial) => {
            // Construction checked that the width holds the token length.
            let token_len = VarInt::try_from(initial.token.len()).unwrap_or(VarInt::ZERO);
            let (encoding, encoded_len) = token_len.to_encoding_of(initial.length_width);
            put(&encoding[..encoded_len]);
            initial.token.clone()
        }
        WrittenKind::ZeroRtt | WrittenKind::Handshake => Bytes::new(),
    };
    let (length, length_len) = header
        .length
        .to_var_int()
        .to_encoding_of(header.length.width());
    io.write_all(prefix[..len].chain(token).chain(&length[..length_len]))
        .await
}

/// Writes the first byte and the destination connection ID of `header`, up to
/// the Packet Number field.
///
/// Acceptance by the receiver does not imply flushing or delivery.
///
/// # Errors
///
/// [`WriteAllError`] if the receiver stops accepting bytes or fails; bytes
/// accepted before stay written.
#[call(sync)]
pub async fn write_short_packet_header<F: Write, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    header: ShortPacketHeader,
) -> Result<(), WriteAllError<F::Error>> {
    let first_byte = [header.first_byte()];
    io.write_all(Buf::chain(&first_byte[..], header.dcid().as_bytes()))
        .await
}

/// The Long Packet Type bits of a Retry packet, `0b11`, in place in the
/// first byte.
const RETRY_TYPE_BITS: u8 = 0b11 << 4;

/// The bits of the first byte of a Retry packet that form its Unused field.
const RETRY_UNUSED_MASK: u8 = 0x0f;

/// The longest Retry packet before its token: the first byte, the version and
/// two connection IDs with their length bytes.
const RETRY_PREFIX_MAX: usize = 1 + 4 + 1 + ConnectionId::MAX_LEN + 1 + ConnectionId::MAX_LEN;

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
/// Acceptance by the receiver does not imply flushing or delivery.
///
/// # Errors
///
/// [`WriteAllError`] if the receiver stops accepting bytes or fails; bytes
/// accepted before stay written.
///
/// [RFC 9000 §17.2.5]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.5
/// [RFC 9000 §17.2.5.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.5.1
/// [RFC 9000 §17.2.5.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.5.2
/// [RFC 9001 §5.8]: https://www.rfc-editor.org/rfc/rfc9001.html#section-5.8
#[call(sync)]
pub async fn write_retry_packet_without_tag<F: Write, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    unused: u8,
    dcid: ConnectionId,
    scid: ConnectionId,
    token: &[u8],
) -> Result<(), WriteAllError<F::Error>> {
    let mut prefix = [0; RETRY_PREFIX_MAX];
    let mut len = 0;
    let mut put = |bytes: &[u8]| {
        // invariant: `RETRY_PREFIX_MAX` is the longest the pieces below add
        // up to.
        prefix[len..len + bytes.len()].copy_from_slice(bytes);
        len += bytes.len();
    };
    put(&[FORM_BIT | FIXED_BIT | RETRY_TYPE_BITS | (unused & RETRY_UNUSED_MASK)]);
    put(&VERSION.to_be_bytes());
    put(&[u8::from(dcid.length())]);
    put(dcid.as_bytes());
    put(&[u8::from(scid.length())]);
    put(scid.as_bytes());
    io.write_all(prefix[..len].chain(token)).await
}
