//! QUIC version 1 long headers ([RFC 9000 §17.2]).
//!
//! A [`LongPacket`] adds to the version-independent [`LongHeader`] what
//! version 1 states without protection: the packet type, the token of Initial
//! and Retry packets, and the extent of each packet. Initial, 0-RTT and
//! Handshake packets carry a Length field covering the packet number and the
//! payload, which bounds the packet within the datagram ([`PacketBounds`]); a
//! Retry packet extends to the end of the datagram and ends with its 16-byte
//! integrity tag.
//!
//! When a Length field cannot be read or points past the end of the input, the
//! boundary of the packet is unknown; the error reports this, and nothing here
//! searches the following bytes for another packet.
//!
//! [RFC 9000 §17.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2
use super::{LongHeader, Reader, TruncatedError};
use crate::{
    connection_id::{ConnectionId, ConnectionIdLengthError},
    var_int::VarInt,
};
use snafu::{OptionExt, ResultExt, Snafu};

/// The version field of QUIC version 1.
pub const VERSION: u32 = 0x0000_0001;

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
/// Offsets count from the start of the input the [`LongHeader`] was read
/// from, which is the first byte of this packet.
///
/// [RFC 9000 §17.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LongPacket<'a> {
    header: LongHeader<'a>,
    dcid: ConnectionId,
    scid: ConnectionId,
    fields: TypeFields<'a>,
}

impl<'a> LongPacket<'a> {
    /// The version-independent fields.
    pub fn header(&self) -> &LongHeader<'a> {
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
    pub fn fields(&self) -> &TypeFields<'a> {
        &self.fields
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
    /// or the end of the input for a Retry packet.
    pub fn end(&self) -> usize {
        match self.fields {
            TypeFields::Initial { bounds, .. }
            | TypeFields::ZeroRtt { bounds }
            | TypeFields::Handshake { bounds } => bounds.end,
            TypeFields::Retry { .. } => self.header.input().len(),
        }
    }

    /// The bytes of this packet.
    pub fn packet(&self) -> &'a [u8] {
        &self.header.input()[..self.end()]
    }

    /// The bytes of the input after this packet, where the next coalesced
    /// packet starts if there is one. Empty for a Retry packet.
    pub fn remainder(&self) -> &'a [u8] {
        &self.header.input()[self.end()..]
    }
}

impl<'a> TryFrom<LongHeader<'a>> for LongPacket<'a> {
    type Error = LongPacketError;

    /// Reads the version 1 fields that follow the version-independent ones.
    ///
    /// # Errors
    ///
    /// - [`LongPacketError::Version`] if the version is not [`VERSION`];
    /// - [`LongPacketError::DcidLength`] or [`LongPacketError::ScidLength`] if
    ///   a connection ID exceeds [`ConnectionId::MAX_LEN`];
    /// - [`LongPacketError::TokenLength`] or [`LongPacketError::Token`] if the
    ///   input ends within the token of an Initial packet;
    /// - [`LongPacketError::Length`] if it ends within the Length field, and
    ///   [`LongPacketError::LengthOutOfBounds`] if that field's range extends
    ///   past the end of the input;
    /// - [`LongPacketError::RetryIntegrityTag`] if a Retry packet is too short
    ///   for its integrity tag.
    fn try_from(header: LongHeader<'a>) -> Result<Self, Self::Error> {
        if header.version() != VERSION {
            return VersionSnafu {
                version: header.version(),
            }
            .fail();
        }
        let dcid = ConnectionId::new(header.dcid()).context(DcidLengthSnafu)?;
        let scid = ConnectionId::new(header.scid()).context(ScidLengthSnafu)?;
        let input = header.input();
        let mut reader = Reader::new(input, header.version_specific_offset());
        let fields = match LongPacketType::of(header.first_byte()) {
            LongPacketType::Initial => {
                let token_len = reader.take_var_int().context(TokenLengthSnafu)?;
                let token = reader
                    .take(saturating_usize(token_len))
                    .context(TokenSnafu)?;
                let bounds = PacketBounds::read(&mut reader)?;
                TypeFields::Initial { token, bounds }
            }
            LongPacketType::ZeroRtt => TypeFields::ZeroRtt {
                bounds: PacketBounds::read(&mut reader)?,
            },
            LongPacketType::Handshake => TypeFields::Handshake {
                bounds: PacketBounds::read(&mut reader)?,
            },
            LongPacketType::Retry => {
                let start = reader.offset();
                let tag_offset = input
                    .len()
                    .checked_sub(RETRY_INTEGRITY_TAG_LEN)
                    .filter(|&tag_offset| tag_offset >= start)
                    .ok_or(TruncatedError {
                        required: start + RETRY_INTEGRITY_TAG_LEN,
                        available: input.len(),
                    })
                    .context(RetryIntegrityTagSnafu)?;
                let (token, integrity_tag) = input[start..].split_at(tag_offset - start);
                TypeFields::Retry {
                    token,
                    integrity_tag: integrity_tag
                        .try_into()
                        .expect("the tag is the last RETRY_INTEGRITY_TAG_LEN bytes"),
                }
            }
        };
        Ok(Self {
            header,
            dcid,
            scid,
            fields,
        })
    }
}

/// Failures of converting a [`LongHeader`] into a version 1 [`LongPacket`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum LongPacketError {
    /// The version is not QUIC version 1.
    #[snafu(display("version {version:#010x} is not QUIC version 1"))]
    Version {
        /// The version field.
        version: u32,
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
    /// The input ends within the Token Length field of an Initial packet.
    #[snafu(display("truncated Token Length field"))]
    TokenLength {
        /// Where the input ended.
        source: TruncatedError,
    },
    /// The input ends within the token of an Initial packet.
    #[snafu(display("truncated token"))]
    Token {
        /// Where the input ended.
        source: TruncatedError,
    },
    /// The input ends within the Length field.
    #[snafu(display("truncated Length field"))]
    Length {
        /// Where the input ended.
        source: TruncatedError,
    },
    /// The range of the Length field extends past the end of the input, so the
    /// packet's boundary is unknown.
    #[snafu(display("Length field {length} exceeds the {available} bytes after it"))]
    LengthOutOfBounds {
        /// The value of the Length field.
        length: VarInt,
        /// The bytes of the input after the Length field.
        available: usize,
    },
    /// A Retry packet is too short for its integrity tag.
    #[snafu(display("truncated Retry Integrity Tag"))]
    RetryIntegrityTag {
        /// Where the input ended.
        source: TruncatedError,
    },
}

/// The fields of a version 1 long header that depend on its packet type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypeFields<'a> {
    /// An Initial packet ([RFC 9000 §17.2.2]).
    ///
    /// [RFC 9000 §17.2.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.2
    Initial {
        /// The token, empty when the Token Length is zero.
        token: &'a [u8],
        /// The Length field and the extent it gives the packet.
        bounds: PacketBounds,
    },
    /// A 0-RTT packet ([RFC 9000 §17.2.3]).
    ///
    /// [RFC 9000 §17.2.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.3
    ZeroRtt {
        /// The Length field and the extent it gives the packet.
        bounds: PacketBounds,
    },
    /// A Handshake packet ([RFC 9000 §17.2.4]).
    ///
    /// [RFC 9000 §17.2.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.4
    Handshake {
        /// The Length field and the extent it gives the packet.
        bounds: PacketBounds,
    },
    /// A Retry packet ([RFC 9000 §17.2.5]).
    ///
    /// The packet extends to the end of the input.
    ///
    /// [RFC 9000 §17.2.5]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.5
    Retry {
        /// The Retry Token: everything between the source connection ID and
        /// the integrity tag. It may be empty here; a client discards a Retry
        /// packet with an empty token.
        token: &'a [u8],
        /// The Retry Integrity Tag, the last 16 bytes of the input.
        integrity_tag: &'a [u8; RETRY_INTEGRITY_TAG_LEN],
    },
}

/// The Length field of an Initial, 0-RTT or Handshake packet and the extent it
/// gives the packet.
///
/// Offsets count from the first byte of the packet. The range from
/// [`PacketBounds::packet_number_offset`] to [`PacketBounds::end`] holds the
/// protected packet number and payload; it lies within the input but may be
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

    /// The offset just past the packet:
    /// [`PacketBounds::packet_number_offset`] plus [`PacketBounds::length`].
    pub fn end(&self) -> usize {
        self.end
    }

    /// Reads the Length field and checks that its range lies within the input.
    fn read(reader: &mut Reader<'_>) -> Result<Self, LongPacketError> {
        let length = reader.take_var_int().context(LengthSnafu)?;
        let packet_number_offset = reader.offset();
        let available = reader.input.len() - packet_number_offset;
        let end = usize::try_from(length.get())
            .ok()
            .filter(|&length| length <= available)
            .map(|length| packet_number_offset + length)
            .context(LengthOutOfBoundsSnafu { length, available })?;
        Ok(Self {
            length,
            packet_number_offset,
            end,
        })
    }
}

/// A variable-length integer as a length in memory, saturating where `usize`
/// is narrower.
fn saturating_usize(value: VarInt) -> usize {
    usize::try_from(value.get()).unwrap_or(usize::MAX)
}
