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
//! [RFC 9000 §17.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2
use super::{LongHeader, SAMPLE_DISTANCE};
use crate::{connection_id::ConnectionId, var_int::VarInt, version::Version};
use bytes::Bytes;

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
