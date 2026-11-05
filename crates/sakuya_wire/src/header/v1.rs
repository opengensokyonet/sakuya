//! QUIC version 1 long headers ([RFC 9000 §17.2]).
//!
//! A [`LongPacket`] adds to the version-independent [`LongHeader`] what
//! version 1 states without protection: the packet type, the token of Initial
//! and Retry packets, and the extent of each packet. Initial, 0-RTT and
//! Handshake packets carry a Length field covering the packet number and the
//! payload, which bounds the packet within the datagram ([`PacketBounds`]); a
//! Retry packet extends to the end of the datagram and ends with its 16-byte
//! integrity tag. [`codec::read_long_packet`] reads these fields after the
//! long header.
//!
//! When a Length field cannot be read or its range extends past the end of
//! the source, the boundary of the packet is unknown; the error reports this,
//! and nothing here searches the following bytes for another packet.
//!
//! A sender describes the header of an Initial, 0-RTT or Handshake packet with
//! a [`LongPacketHeader`], which [`codec::write_long_packet_header`] writes up
//! to the Packet Number field.
//!
//! [RFC 9000 §17.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2
use super::{FORM_BIT, LongHeader, SAMPLE_DISTANCE, VERSION_LEN};
use crate::{
    connection_id::ConnectionId,
    frame::LengthError,
    packet_number::PacketNumberLength,
    var_int::{VarInt, VarIntField, VarIntWidth},
    version::Version,
};
use bytes::{Buf, Bytes};
use core::ops::Range;

pub mod codec;

/// The version field of QUIC version 1.
pub const VERSION: Version = Version::V1;

/// The length of the Retry Integrity Tag ([RFC 9001 §5.8]).
///
/// [RFC 9001 §5.8]: https://www.rfc-editor.org/rfc/rfc9001.html#section-5.8
pub const RETRY_INTEGRITY_TAG_LEN: usize = 16;

/// The Fixed Bit of the first byte ([RFC 9000 §17.2]).
///
/// [RFC 9000 §17.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2
pub const FIXED_BIT: u8 = 0x40;

/// The Long Packet Type: bits `0x30` of the first byte of a version 1 long
/// header ([RFC 9000 §17.2]).
///
/// [RFC 9000 §17.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LongPacketType {
    /// `0b00`: an Initial packet.
    Initial,
    /// `0b01`: a 0-RTT packet.
    ZeroRtt,
    /// `0b10`: a Handshake packet.
    Handshake,
    /// `0b11`: a Retry packet.
    Retry,
}

impl LongPacketType {
    /// The packet type that the first byte of a version 1 long header
    /// announces. Long packet type bits are not protected.
    pub const fn of(first_byte: u8) -> Self {
        match (first_byte >> 4) & 0b11 {
            0b00 => Self::Initial,
            0b01 => Self::ZeroRtt,
            0b10 => Self::Handshake,
            _ => Self::Retry,
        }
    }
}

/// The header of an Initial, 0-RTT or Handshake packet as a sender writes
/// it: every field before the Packet Number field ([RFC 9000 §17.2]).
///
/// The first byte states the form, the Fixed Bit, the packet type, the
/// reserved bits and the packet number length. The reserved bits are written
/// as 0, as [RFC 9000 §17.2] requires before header protection is applied.
/// The version field is [`VERSION`].
///
/// The Length field covers the packet number and the payload, which the
/// sender does not know when it starts the packet. It states the Length as a
/// [`VarIntField`] so that its width is chosen up front: the sender writes
/// the header with any value at the width it reserves, appends the packet
/// number and the payload, and writes the final value over the reserved bytes
/// at [`LongPacketHeader::length_offset`] with
/// [`write_var_int_field`](crate::var_int::codec::write_var_int_field).
///
/// A header written and read back with
/// [`read_long_header`](crate::header::codec::read_long_header) and
/// [`read_long_packet`](codec::read_long_packet) reads as the same fields.
///
/// [RFC 9000 §17.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LongPacketHeader {
    pn_length: PacketNumberLength,
    dcid: ConnectionId,
    scid: ConnectionId,
    kind: WrittenKind,
    length: VarIntField<VarInt>,
}

/// The packet types of version 1 that carry a Length field, with the fields
/// that depend on the type.
#[derive(Clone, Debug, PartialEq, Eq)]
enum WrittenKind {
    Initial(InitialToken),
    ZeroRtt,
    Handshake,
}

/// The token of an Initial packet and the width of its Token Length field.
#[derive(Clone, Debug, PartialEq, Eq)]
struct InitialToken {
    length_width: VarIntWidth,
    token: Bytes,
}

impl LongPacketHeader {
    /// The header of an Initial packet.
    ///
    /// `pn_length` is the length of the Packet Number field that follows the
    /// header. The token may be empty; the Token Length field is written at
    /// `token_length_width`.
    ///
    /// # Errors
    ///
    /// [`LengthError`] if the Token Length field is too narrow for the length
    /// of the token.
    pub fn initial(
        dcid: ConnectionId,
        scid: ConnectionId,
        token_length_width: VarIntWidth,
        token: Bytes,
        pn_length: PacketNumberLength,
        length: VarIntField<VarInt>,
    ) -> Result<Self, LengthError> {
        LengthError::check(token.len(), token_length_width)?;
        Ok(Self {
            pn_length,
            dcid,
            scid,
            kind: WrittenKind::Initial(InitialToken {
                length_width: token_length_width,
                token,
            }),
            length,
        })
    }

    /// The header of a 0-RTT packet.
    pub fn zero_rtt(
        dcid: ConnectionId,
        scid: ConnectionId,
        pn_length: PacketNumberLength,
        length: VarIntField<VarInt>,
    ) -> Self {
        Self::without_token(WrittenKind::ZeroRtt, dcid, scid, pn_length, length)
    }

    /// The header of a Handshake packet.
    pub fn handshake(
        dcid: ConnectionId,
        scid: ConnectionId,
        pn_length: PacketNumberLength,
        length: VarIntField<VarInt>,
    ) -> Self {
        Self::without_token(WrittenKind::Handshake, dcid, scid, pn_length, length)
    }

    fn without_token(
        kind: WrittenKind,
        dcid: ConnectionId,
        scid: ConnectionId,
        pn_length: PacketNumberLength,
        length: VarIntField<VarInt>,
    ) -> Self {
        Self {
            pn_length,
            dcid,
            scid,
            kind,
            length,
        }
    }

    /// The Long Packet Type: never [`LongPacketType::Retry`].
    pub fn packet_type(&self) -> LongPacketType {
        match self.kind {
            WrittenKind::Initial(_) => LongPacketType::Initial,
            WrittenKind::ZeroRtt => LongPacketType::ZeroRtt,
            WrittenKind::Handshake => LongPacketType::Handshake,
        }
    }

    /// The first byte of the packet: the form, the Fixed Bit, the packet type,
    /// zero reserved bits and the packet number length.
    pub fn first_byte(&self) -> u8 {
        let type_bits = match self.kind {
            WrittenKind::Initial(_) => 0b00,
            WrittenKind::ZeroRtt => 0b01,
            WrittenKind::Handshake => 0b10,
        };
        FORM_BIT | FIXED_BIT | (type_bits << 4) | self.pn_length.first_byte_bits()
    }

    /// The length of the Packet Number field that follows the header.
    pub fn pn_length(&self) -> PacketNumberLength {
        self.pn_length
    }

    /// The destination connection ID.
    pub fn dcid(&self) -> &ConnectionId {
        &self.dcid
    }

    /// The source connection ID.
    pub fn scid(&self) -> &ConnectionId {
        &self.scid
    }

    /// The token of an Initial packet, empty when the Token Length is zero;
    /// `None` for the other packet types.
    pub fn token(&self) -> Option<&Bytes> {
        match &self.kind {
            WrittenKind::Initial(initial) => Some(&initial.token),
            WrittenKind::ZeroRtt | WrittenKind::Handshake => None,
        }
    }

    /// The width of the Token Length field of an Initial packet; `None` for
    /// the other packet types.
    pub fn token_length_width(&self) -> Option<VarIntWidth> {
        match &self.kind {
            WrittenKind::Initial(initial) => Some(initial.length_width),
            WrittenKind::ZeroRtt | WrittenKind::Handshake => None,
        }
    }

    /// The Length field.
    pub fn length(&self) -> VarIntField<VarInt> {
        self.length
    }

    /// The offset of the Length field: the number of bytes before it.
    pub fn length_offset(&self) -> usize {
        let before_token = 1 + VERSION_LEN + 1 + self.dcid.len() + 1 + self.scid.len();
        match &self.kind {
            WrittenKind::Initial(initial) => {
                before_token + initial.length_width.encoded_len() + initial.token.len()
            }
            WrittenKind::ZeroRtt | WrittenKind::Handshake => before_token,
        }
    }

    /// The offset of the Packet Number field, right after the Length field:
    /// the number of bytes [`codec::write_long_packet_header`] writes.
    pub fn packet_number_offset(&self) -> usize {
        self.length_offset() + self.length.encoded_len()
    }
}

/// A QUIC version 1 long header packet, as far as its header states without
/// protection ([RFC 9000 §17.2]).
///
/// Offsets count from the first byte of the packet. `D` is the chunk type of
/// the source the packet was read from; it holds the token and the protected
/// packet number and payload.
///
/// [RFC 9000 §17.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LongPacket<D> {
    header: LongHeader,
    dcid: ConnectionId,
    scid: ConnectionId,
    fields: TypeFields<D>,
}

impl<D> LongPacket<D> {
    /// The version-independent fields.
    pub fn header(&self) -> &LongHeader {
        &self.header
    }

    /// The destination connection ID.
    pub fn dcid(&self) -> &ConnectionId {
        &self.dcid
    }

    /// The source connection ID.
    pub fn scid(&self) -> &ConnectionId {
        &self.scid
    }

    /// The Long Packet Type.
    pub fn packet_type(&self) -> LongPacketType {
        match self.fields {
            TypeFields::Initial { .. } => LongPacketType::Initial,
            TypeFields::ZeroRtt { .. } => LongPacketType::ZeroRtt,
            TypeFields::Handshake { .. } => LongPacketType::Handshake,
            TypeFields::Retry { .. } => LongPacketType::Retry,
        }
    }

    /// The fields that depend on the packet type.
    pub fn fields(&self) -> &TypeFields<D> {
        &self.fields
    }

    /// Takes the fields that depend on the packet type.
    pub fn into_fields(self) -> TypeFields<D> {
        self.fields
    }

    /// Whether the Fixed Bit is set.
    ///
    /// Version 1 requires it, unless the peers negotiated otherwise
    /// ([RFC 9287]); this interpretation does not check it.
    ///
    /// [RFC 9287]: https://www.rfc-editor.org/rfc/rfc9287.html
    pub fn fixed_bit(&self) -> bool {
        self.header.first_byte() & FIXED_BIT != 0
    }

    /// The offset just past this packet: the end of the Length field's range,
    /// or the end of the source for a Retry packet.
    pub fn end(&self) -> usize {
        match &self.fields {
            TypeFields::Initial { bounds, .. }
            | TypeFields::ZeroRtt { bounds, .. }
            | TypeFields::Handshake { bounds, .. } => bounds.end,
            TypeFields::Retry { end, .. } => *end,
        }
    }
}

impl<D: Buf> LongPacket<D> {
    /// The packet with the token and the protected bytes replaced by their
    /// ranges within `bytes`, the packet as it was read.
    ///
    /// The ranges let the packet outlive the borrow of `bytes` that reading
    /// it needed. A Retry packet keeps its token and integrity tag.
    pub(crate) fn into_ranges(self, bytes: &[u8]) -> LongPacket<Range<usize>> {
        let fields = match self.fields {
            TypeFields::Initial {
                token,
                bounds,
                protected,
            } => {
                // The Token Length field follows the connection IDs and was
                // read from `bytes`, so its first byte exists.
                let offset = self.header.version_specific_offset();
                let width = bytes
                    .get(offset)
                    .map_or(VarIntWidth::One, |&byte| VarIntWidth::of_first_byte(byte));
                let token_start = offset + width.encoded_len();
                TypeFields::Initial {
                    token: token_start..token_start + token.remaining(),
                    bounds,
                    protected: bounds.packet_number_offset
                        ..bounds.packet_number_offset + protected.remaining(),
                }
            }
            TypeFields::ZeroRtt { bounds, protected } => TypeFields::ZeroRtt {
                bounds,
                protected: bounds.packet_number_offset
                    ..bounds.packet_number_offset + protected.remaining(),
            },
            TypeFields::Handshake { bounds, protected } => TypeFields::Handshake {
                bounds,
                protected: bounds.packet_number_offset
                    ..bounds.packet_number_offset + protected.remaining(),
            },
            TypeFields::Retry {
                token,
                integrity_tag,
                end,
            } => TypeFields::Retry {
                token,
                integrity_tag,
                end,
            },
        };
        LongPacket {
            header: self.header,
            dcid: self.dcid,
            scid: self.scid,
            fields,
        }
    }
}

/// The fields of a version 1 long header that depend on its packet type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypeFields<D> {
    /// An Initial packet ([RFC 9000 §17.2.2]).
    ///
    /// [RFC 9000 §17.2.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.2
    Initial {
        /// The token, empty when the Token Length is zero.
        token: D,
        /// The Length field and the extent it gives the packet.
        bounds: PacketBounds,
        /// The protected packet number and payload.
        protected: D,
    },
    /// A 0-RTT packet ([RFC 9000 §17.2.3]).
    ///
    /// [RFC 9000 §17.2.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.3
    ZeroRtt {
        /// The Length field and the extent it gives the packet.
        bounds: PacketBounds,
        /// The protected packet number and payload.
        protected: D,
    },
    /// A Handshake packet ([RFC 9000 §17.2.4]).
    ///
    /// [RFC 9000 §17.2.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.4
    Handshake {
        /// The Length field and the extent it gives the packet.
        bounds: PacketBounds,
        /// The protected packet number and payload.
        protected: D,
    },
    /// A Retry packet ([RFC 9000 §17.2.5]).
    ///
    /// The packet extends to the end of the source.
    ///
    /// [RFC 9000 §17.2.5]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.5
    Retry {
        /// The Retry Token: everything between the source connection ID and
        /// the integrity tag. It may be empty here; a client discards a Retry
        /// packet with an empty token. It shares the source's storage when
        /// the source is `Bytes` and is copied otherwise.
        token: Bytes,
        /// The Retry Integrity Tag, the last 16 bytes of the source.
        integrity_tag: [u8; RETRY_INTEGRITY_TAG_LEN],
        /// The offset just past the packet.
        end: usize,
    },
}

/// The Length field of an Initial, 0-RTT or Handshake packet and the extent it
/// gives the packet.
///
/// Offsets count from the first byte of the packet. The range from
/// [`PacketBounds::packet_number_offset`] to [`PacketBounds::end`] holds the
/// protected packet number and payload; it lies within the source but may be
/// too short for them, which removing packet protection detects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PacketBounds {
    length: VarInt,
    packet_number_offset: usize,
    end: usize,
}

impl PacketBounds {
    /// The value of the Length field: the length of the packet number and
    /// payload.
    pub fn length(&self) -> VarInt {
        self.length
    }

    /// The offset of the packet number field, right after the Length field.
    ///
    /// The field is protected; its length is known only after header
    /// protection is removed.
    pub fn packet_number_offset(&self) -> usize {
        self.packet_number_offset
    }

    /// The offset of the header protection sample:
    /// [`PacketBounds::packet_number_offset`] plus [`SAMPLE_DISTANCE`].
    pub fn sample_offset(&self) -> usize {
        self.packet_number_offset + SAMPLE_DISTANCE
    }

    /// The offset just past the packet:
    /// [`PacketBounds::packet_number_offset`] plus [`PacketBounds::length`].
    pub fn end(&self) -> usize {
        self.end
    }
}
