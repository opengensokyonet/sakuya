//! Packet header interpretation before packet protection is removed.
//!
//! Interpretation proceeds in layers, each of which reads only what its rules
//! define:
//!
//! 1. [`HeaderForm::of`] reads the most significant bit of the first byte.
//! 2. [`codec::read_long_header`] reads the fields every QUIC version shares
//!    ([RFC 8999 §5.1]): version and the two connection IDs, each 0 to 255
//!    bytes long. [`codec::read_short_header`] reads the destination
//!    connection ID of a short header, whose length the caller supplies
//!    because the header does not carry it ([RFC 8999 §5.2]).
//! 3. After a long header with [`Version::NEGOTIATION`],
//!    [`codec::read_version_negotiation`] reads the rest of a
//!    [`VersionNegotiation`] packet ([RFC 8999 §6]); after one with
//!    [`v1::header::VERSION`](crate::v1::header::VERSION),
//!    [`v1::header::codec::read_long_packet`](crate::v1::header::codec::read_long_packet)
//!    reads the rest of a [`v1::header::LongPacket`](crate::v1::header::LongPacket)
//!    ([RFC 9000 §17.2]). For any other version, only the version-independent
//!    fields of the [`LongHeader`] are known.
//!
//! Each layer is a `nitori_call` operation that continues where the previous
//! one stopped. The source is a datagram, or the part of it starting at the
//! packet to interpret, held by a host such as a byte slice or `Bytes`;
//! offsets reported by the layers count from the first byte of the packet. A
//! version 1 long packet with a Length field reads exactly its own bytes, so a
//! datagram that coalesces several packets can be interpreted packet by
//! packet from what remains in the source. Version Negotiation packets, Retry
//! packets and short headers extend to the end of the source.
//!
//! A sender describes the header of a version 1 packet with a
//! [`ShortPacketHeader`](crate::v1::header::ShortPacketHeader) or a
//! [`LongPacketHeader`](crate::v1::header::LongPacketHeader), which
//! [`crate::v1::header::codec`] writes up to the Packet Number field, which
//! the layer that protects the packet writes.
//!
//! No layer interprets protected bits or fields. The packet number offset
//! states where the protected packet number begins and the sample offset
//! where header protection takes its sample ([RFC 9001 §5.4.2]); the packet
//! number length, the reserved bits and the Key Phase bit are known only
//! after header protection is removed.
//!
//! ```
//! use sakuya_wire::header::{
//!     HeaderForm,
//!     codec::{
//!         ReadLongHeaderHostExt as _, ReadShortHeaderHostExt as _,
//!         ReadVersionNegotiationHostExt as _,
//!     },
//! };
//! use sakuya_wire::v1::header::{self as v1, codec::ReadLongPacketHostExt as _};
//! use sakuya_wire::{connection_id::ConnectionIdLength, version::Version};
//!
//! fn describe(datagram: &[u8], short_dcid_len: ConnectionIdLength) -> String {
//!     let Some(&first) = datagram.first() else { return "empty".into() };
//!     let mut input = datagram;
//!     match HeaderForm::of(first) {
//!         HeaderForm::Short => match input.sync_read_short_header_unpin(short_dcid_len) {
//!             Ok(short) => format!("short, packet number at {}", short.packet_number_offset()),
//!             Err(error) => error.to_string(),
//!         },
//!         HeaderForm::Long => {
//!             let long = match input.sync_read_long_header_unpin() {
//!                 Ok(long) => long,
//!                 Err(error) => return error.to_string(),
//!             };
//!             match long.version() {
//!                 Version::NEGOTIATION => match input.sync_read_version_negotiation_unpin(long) {
//!                     Ok(packet) => format!("{} versions offered", packet.supported_versions().len()),
//!                     Err(error) => error.to_string(),
//!                 },
//!                 v1::VERSION => match input.sync_read_long_packet_unpin(long) {
//!                     Ok(packet) => format!("{:?} ending at {}", packet.packet_type(), packet.end()),
//!                     Err(error) => error.to_string(),
//!                 },
//!                 version => format!("unsupported version {version}"),
//!             }
//!         }
//!     }
//! }
//!
//! let len = |length| ConnectionIdLength::new(length).unwrap();
//! assert_eq!(describe(&[0x40, 0xaa, 0xbb, 0x01], len(2)), "short, packet number at 3");
//! assert_eq!(
//!     describe(&[0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], len(0)),
//!     "1 versions offered",
//! );
//! assert_eq!(
//!     describe(&[0xe0, 0, 0, 0, 1, 0, 0, 0x01, 0xaa], len(0)),
//!     "Handshake ending at 9",
//! );
//! assert_eq!(
//!     describe(&[0xc0, 0x6b, 0x33, 0x43, 0xcf, 0, 0], len(0)),
//!     "unsupported version 0x6b3343cf",
//! );
//! ```
//!
//! [RFC 8999 §5.1]: https://www.rfc-editor.org/rfc/rfc8999.html#section-5.1
//! [RFC 8999 §5.2]: https://www.rfc-editor.org/rfc/rfc8999.html#section-5.2
//! [RFC 8999 §6]: https://www.rfc-editor.org/rfc/rfc8999.html#section-6
//! [RFC 9000 §17.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2
//! [RFC 9001 §5.4.2]: https://www.rfc-editor.org/rfc/rfc9001.html#section-5.4.2
use crate::{connection_id::RawConnectionId, version::Version};
use bytes::Buf;
use core::iter::FusedIterator;

pub mod codec;

/// The Header Form bit: set for long headers.
pub(crate) const FORM_BIT: u8 = 0x80;

/// The length of a version field.
pub(crate) const VERSION_LEN: usize = 4;

/// How many bytes after the start of the packet number field header
/// protection takes its sample: the packet number is taken to be four bytes
/// long ([RFC 9001 §5.4.2]).
///
/// [RFC 9001 §5.4.2]: https://www.rfc-editor.org/rfc/rfc9001.html#section-5.4.2
pub const SAMPLE_DISTANCE: usize = 4;

/// Whether a packet has a long or a short header: the most significant bit of
/// its first byte, the only bit whose meaning every QUIC version shares.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HeaderForm {
    /// The bit is 1.
    Long,
    /// The bit is 0.
    Short,
}

impl HeaderForm {
    /// The header form that `first_byte` announces.
    pub const fn of(first_byte: u8) -> Self {
        if first_byte & FORM_BIT == 0 {
            Self::Short
        } else {
            Self::Long
        }
    }
}

/// The version-independent fields of a long header ([RFC 8999 §5.1]).
///
/// The connection IDs may be up to 255 bytes long; only the rules of a
/// specific version restrict them further. The remaining seven bits of the
/// first byte and everything after the source connection ID belong to the
/// version.
///
/// [RFC 8999 §5.1]: https://www.rfc-editor.org/rfc/rfc8999.html#section-5.1
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LongHeader {
    first_byte: u8,
    version: Version,
    dcid: RawConnectionId,
    scid: RawConnectionId,
}

impl LongHeader {
    /// The first byte of the packet. Its low seven bits are version-specific
    /// and may be protected.
    pub fn first_byte(&self) -> u8 {
        self.first_byte
    }

    /// The version field.
    pub fn version(&self) -> Version {
        self.version
    }

    /// The destination connection ID: 0 to 255 bytes.
    pub fn dcid(&self) -> &RawConnectionId {
        &self.dcid
    }

    /// The source connection ID: 0 to 255 bytes.
    pub fn scid(&self) -> &RawConnectionId {
        &self.scid
    }

    /// The offset of the first version-specific byte after the source
    /// connection ID: the number of bytes the header took.
    pub fn version_specific_offset(&self) -> usize {
        1 + VERSION_LEN + 1 + self.dcid.len() + 1 + self.scid.len()
    }
}

/// A short header with the destination connection ID length the caller
/// supplied ([RFC 8999 §5.2], [RFC 9000 §17.3]).
///
/// A short header does not state the length of its destination connection
/// ID; the endpoint that chose the connection ID knows it. Different lengths
/// give different interpretations of the same bytes, and the header itself
/// cannot tell which is right. A short header packet extends to the end of the
/// source; `D` is the source's chunk type, which holds the protected rest, or
/// the range of those bytes within the packet when the header was located by
/// [`into_packets`](crate::v1::protected_packet::into_packets).
///
/// [RFC 8999 §5.2]: https://www.rfc-editor.org/rfc/rfc8999.html#section-5.2
/// [RFC 9000 §17.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.3
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShortHeader<D> {
    first_byte: u8,
    dcid: RawConnectionId,
    protected: D,
}

impl<D> ShortHeader<D> {
    /// The first byte of the packet. Its low seven bits are version-specific
    /// and some of them are protected.
    pub fn first_byte(&self) -> u8 {
        self.first_byte
    }

    /// The destination connection ID, of the length given to
    /// [`codec::read_short_header`].
    pub fn dcid(&self) -> &RawConnectionId {
        &self.dcid
    }

    /// The offset of the packet number field, the first byte after the
    /// destination connection ID.
    ///
    /// The field is protected; its length is known only after header
    /// protection is removed.
    pub fn packet_number_offset(&self) -> usize {
        1 + self.dcid.len()
    }

    /// The offset of the header protection sample:
    /// [`ShortHeader::packet_number_offset`] plus [`SAMPLE_DISTANCE`].
    pub fn sample_offset(&self) -> usize {
        self.packet_number_offset() + SAMPLE_DISTANCE
    }

    /// The protected packet number and payload.
    pub fn protected(&self) -> &D {
        &self.protected
    }

    /// Takes the protected packet number and payload.
    pub fn into_protected(self) -> D {
        self.protected
    }

    /// The header with `protected` mapped by `map`.
    pub(crate) fn map_protected<E>(self, map: impl FnOnce(D) -> E) -> ShortHeader<E> {
        ShortHeader {
            first_byte: self.first_byte,
            dcid: self.dcid,
            protected: map(self.protected),
        }
    }
}

impl<D: Buf> ShortHeader<D> {
    /// The offset just past the packet, the end of the source.
    pub fn end(&self) -> usize {
        self.packet_number_offset() + self.protected.remaining()
    }
}

/// A Version Negotiation packet ([RFC 8999 §6]): a long header with
/// [`Version::NEGOTIATION`].
///
/// The connection IDs echo those of the packet that prompted it and may be up
/// to 255 bytes long. The supported version list fills the rest of the
/// source; `D` is the source's chunk type, which holds it. The other bits of
/// the first byte are unused. Whether the packet answers a packet this
/// endpoint sent is for the client that sent it to decide.
///
/// [RFC 8999 §6]: https://www.rfc-editor.org/rfc/rfc8999.html#section-6
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionNegotiation<D> {
    header: LongHeader,
    versions: D,
}

impl<D> VersionNegotiation<D> {
    /// The version-independent fields.
    pub fn header(&self) -> &LongHeader {
        &self.header
    }

    /// The destination connection ID: 0 to 255 bytes.
    pub fn dcid(&self) -> &RawConnectionId {
        self.header.dcid()
    }

    /// The source connection ID: 0 to 255 bytes.
    pub fn scid(&self) -> &RawConnectionId {
        self.header.scid()
    }

    /// The supported version list, a whole number of versions: the chunk of
    /// the source that holds it, or its range within the packet when the
    /// packet was located by [`into_packets`](crate::v1::protected_packet::into_packets).
    pub fn versions(&self) -> &D {
        &self.versions
    }

    /// The packet with `versions` mapped by `map`.
    pub(crate) fn map_versions<E>(self, map: impl FnOnce(D) -> E) -> VersionNegotiation<E> {
        VersionNegotiation {
            header: self.header,
            versions: map(self.versions),
        }
    }
}

impl<D: Buf + Clone> VersionNegotiation<D> {
    /// The versions the list offers, in order. The list may be empty.
    pub fn supported_versions(&self) -> SupportedVersions<D> {
        SupportedVersions(self.versions.clone())
    }
}

/// The versions a [`VersionNegotiation`] packet offers, in order.
#[derive(Clone, Debug)]
pub struct SupportedVersions<D>(D);

impl<D: Buf> Iterator for SupportedVersions<D> {
    type Item = Version;

    fn next(&mut self) -> Option<Version> {
        // The list was checked to be a whole number of versions.
        (self.0.remaining() >= VERSION_LEN).then(|| Version::new(self.0.get_u32()))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let count = self.0.remaining() / VERSION_LEN;
        (count, Some(count))
    }
}

impl<D: Buf> ExactSizeIterator for SupportedVersions<D> {}

impl<D: Buf> FusedIterator for SupportedVersions<D> {}

#[cfg(test)]
mod tests;
