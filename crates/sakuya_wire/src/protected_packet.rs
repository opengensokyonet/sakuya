//! The packets of a datagram, cut apart with their protection still on
//! ([RFC 9000 §12.2]).
//!
//! A datagram can coalesce several QUIC packets. [`into_packets`] cuts one
//! apart without copying: for each packet it reads the header with the
//! `sakuya_wire` header operations to find where the packet ends, and splits
//! those bytes off the datagram with [`SplitTo`]. The datagram can be any
//! buffer that splits from the front and can be read as bytes, such as a
//! `BytesMut`, whose packets each keep their share of the storage and can be
//! rewritten in place, `Bytes`, whose packets share its storage read-only, or
//! a byte slice, whose packets are subslices.
//!
//! ```
//! use sakuya_wire::{
//!     connection_id::ConnectionIdLength,
//!     protected_packet::{ProtectedPacket, into_packets},
//! };
//!
//! // A Handshake packet with 3 bytes of packet number and payload, then a
//! // short header packet with a 2-byte destination connection ID.
//! let datagram: &[u8] = &[
//!     0xe0, 0, 0, 0, 1, 2, 7, 7, 0, 3, 0xaa, 0xbb, 0xcc, // Handshake
//!     0x40, 7, 7, 0x11, 0x22, 0x33, 0x44, 0x55,          // 1-RTT
//! ];
//! let packets = into_packets(datagram, ConnectionIdLength::new(2).unwrap()).collect::<Result<Vec<_>, _>>().unwrap();
//! assert!(matches!(packets[0], ProtectedPacket::Handshake(..)));
//! assert_eq!(packets[0].bytes().len(), 13);
//! assert!(matches!(packets[1], ProtectedPacket::OneRtt(..)));
//! assert_eq!(packets[1].bytes().len(), 8);
//! ```
//!
//! [RFC 9000 §12.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.2
use crate::{
    connection_id::{ConnectionIdLength, RawConnectionId},
    encryption_level::EncryptionLevel,
    header::{
        HeaderForm, ShortHeader,
        codec::{
            ReadLongHeaderError, ReadLongHeaderHostExt as _, ReadShortHeaderError,
            ReadShortHeaderHostExt as _,
        },
        v1::codec::ReadLongPacketHostExt as _,
        v1::{LongPacket, LongPacketType, codec::ReadLongPacketError},
    },
};
use core::{convert::Infallible, iter::FusedIterator, ops::Range};
use nitori_io::SplitTo;
use snafu::Snafu;

/// A packet cut from a datagram, with the protection still on.
///
/// It holds what the header operations read and the bytes of the whole
/// packet, which the removal of protection needs: the header protection
/// sample and the additional data of the AEAD are taken from them
/// ([RFC 9001 §5.3], [RFC 9001 §5.4]). `P` is the buffer the datagram was cut
/// from.
///
/// The header values hold ranges within the packet where they would hold the
/// token and the protected bytes, so that the packet can own its bytes:
/// [`LongPacket`]'s token and protected fields are `Range<usize>`, and so is
/// the protected field of [`ShortHeader`]. Offsets count from the first byte
/// of the packet.
///
/// [RFC 9001 §5.3]: https://www.rfc-editor.org/rfc/rfc9001.html#section-5.3
/// [RFC 9001 §5.4]: https://www.rfc-editor.org/rfc/rfc9001.html#section-5.4
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtectedPacket<P> {
    /// An Initial packet.
    Initial(LongPacket<Range<usize>>, P),
    /// A 0-RTT packet.
    ZeroRtt(LongPacket<Range<usize>>, P),
    /// A Handshake packet.
    Handshake(LongPacket<Range<usize>>, P),
    /// A 1-RTT packet, which extends to the end of the datagram.
    OneRtt(ShortHeader<Range<usize>>, P),
}

impl<P> ProtectedPacket<P> {
    /// The level the packet is protected at.
    pub fn level(&self) -> EncryptionLevel {
        match self {
            Self::Initial(..) => EncryptionLevel::Initial,
            Self::ZeroRtt(..) => EncryptionLevel::ZeroRtt,
            Self::Handshake(..) => EncryptionLevel::Handshake,
            Self::OneRtt(..) => EncryptionLevel::OneRtt,
        }
    }

    /// The bytes of the whole packet.
    pub fn bytes(&self) -> &P {
        match self {
            Self::Initial(_, bytes)
            | Self::ZeroRtt(_, bytes)
            | Self::Handshake(_, bytes)
            | Self::OneRtt(_, bytes) => bytes,
        }
    }

    /// Takes the bytes of the whole packet.
    pub fn into_bytes(self) -> P {
        match self {
            Self::Initial(_, bytes)
            | Self::ZeroRtt(_, bytes)
            | Self::Handshake(_, bytes)
            | Self::OneRtt(_, bytes) => bytes,
        }
    }
}

/// Cuts the packets out of `datagram`, one per item.
///
/// A short header does not state the length of its destination connection
/// ID, so `short_dcid_len` is the length the endpoint chose; the first packet
/// that is a short header packet extends to the end of the datagram.
///
/// Each item is a packet or the failure that stopped it:
/// [`IntoPacketsError::UnreadableBoundary`] and
/// [`IntoPacketsError::Retry`] end the iteration, since the rest of the
/// datagram cannot be cut apart; [`IntoPacketsError::DcidDiffersFromFirst`]
/// reports one packet that is to be ignored and the iteration goes on with the
/// next. An empty datagram has no items.
pub fn into_packets<P: SplitTo + AsRef<[u8]>>(
    datagram: P,
    short_dcid_len: ConnectionIdLength,
) -> IntoPackets<P> {
    IntoPackets {
        rest: datagram,
        short_dcid_len,
        first_dcid: None,
        finished: false,
    }
}

/// The iterator [`into_packets`] returns.
///
/// It takes a parameter, so it is not made with `IntoIterator`.
#[derive(Clone, Debug)]
pub struct IntoPackets<P> {
    rest: P,
    short_dcid_len: ConnectionIdLength,
    first_dcid: Option<RawConnectionId>,
    finished: bool,
}

impl<P: SplitTo + AsRef<[u8]>> IntoPackets<P> {
    /// Cuts the first `end` bytes of the rest off as one packet.
    fn split_packet(&mut self, end: usize) -> P {
        match self.rest.split_to(end) {
            Ok(packet) => packet,
            // invariant: `end` is where the header read from the rest says the
            // packet ends, which is the rest's length or a range of the Length
            // field that reading checked to lie within it.
            Err(_) => unreachable!("a packet ends within the datagram"),
        }
    }

    /// Reads the header of the packet at the start of the rest and cuts the
    /// packet off, with its destination connection ID.
    fn cut(&mut self) -> Result<(ProtectedPacket<P>, RawConnectionId), IntoPacketsError> {
        let bytes = self.rest.as_ref();
        match HeaderForm::of(bytes[0]) {
            HeaderForm::Short => {
                let mut input = bytes;
                let header = input
                    .sync_read_short_header_unpin(self.short_dcid_len)
                    .map_err(|source| PacketBoundaryError::ShortHeader { source })?;
                let dcid = *header.dcid();
                let packet_number_offset = header.packet_number_offset();
                let end = bytes.len();
                let header = header.map_protected(|_| packet_number_offset..end);
                Ok((
                    ProtectedPacket::OneRtt(header, self.split_packet(end)),
                    dcid,
                ))
            }
            HeaderForm::Long => {
                let mut input = bytes;
                let long = input
                    .sync_read_long_header_unpin()
                    .map_err(|source| PacketBoundaryError::LongHeader { source })?;
                let dcid = *long.dcid();
                let packet = input
                    .sync_read_long_packet_unpin(long)
                    .map_err(|source| PacketBoundaryError::LongPacket { source })?;
                let kind = packet.packet_type();
                if kind == LongPacketType::Retry {
                    return Err(IntoPacketsError::Retry);
                }
                let end = packet.end();
                let packet = packet.into_ranges(bytes);
                let bytes = self.split_packet(end);
                let packet = match kind {
                    LongPacketType::Initial => ProtectedPacket::Initial(packet, bytes),
                    LongPacketType::ZeroRtt => ProtectedPacket::ZeroRtt(packet, bytes),
                    LongPacketType::Handshake => ProtectedPacket::Handshake(packet, bytes),
                    // invariant: the Retry packet returned above.
                    LongPacketType::Retry => unreachable!("Retry packets are not cut"),
                };
                Ok((packet, dcid))
            }
        }
    }
}

impl<P: SplitTo + AsRef<[u8]>> Iterator for IntoPackets<P> {
    type Item = Result<ProtectedPacket<P>, IntoPacketsError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished || self.rest.as_ref().is_empty() {
            return None;
        }
        let (packet, dcid) = match self.cut() {
            Ok(cut) => cut,
            Err(error) => {
                self.finished = true;
                return Some(Err(error));
            }
        };
        if dcid != *self.first_dcid.get_or_insert(dcid) {
            return Some(Err(IntoPacketsError::DcidDiffersFromFirst));
        }
        Some(Ok(packet))
    }
}

impl<P: SplitTo + AsRef<[u8]>> FusedIterator for IntoPackets<P> {}

/// Failures of [`into_packets`] for one packet.
#[derive(Debug, Snafu)]
#[snafu(module(into_packets_error), visibility(pub(crate)))]
pub enum IntoPacketsError {
    /// The header does not tell where the packet ends. The rest of the
    /// datagram cannot be cut apart either, so the iteration ends.
    #[snafu(display("packet boundary unreadable"))]
    UnreadableBoundary {
        /// The failure of reading the header.
        source: PacketBoundaryError,
    },
    /// A packet's destination connection ID differs from the first packet's.
    /// RFC 9000 §12.2 says to ignore such a packet; the iteration goes on
    /// with the next one.
    #[snafu(display("destination connection ID differs from the first packet's"))]
    DcidDiffersFromFirst,
    /// The packet is a Retry packet, which is not protected and extends to
    /// the end of the datagram; the iteration ends.
    #[snafu(display("Retry packet is not protected"))]
    Retry,
}

impl From<PacketBoundaryError> for IntoPacketsError {
    fn from(source: PacketBoundaryError) -> Self {
        Self::UnreadableBoundary { source }
    }
}

/// The header of a packet could not be read.
#[derive(Debug, Snafu)]
pub enum PacketBoundaryError {
    /// The version-independent fields of a long header could not be read.
    #[snafu(display("long header read failed"))]
    LongHeader {
        /// The failure of reading the fields.
        source: ReadLongHeaderError<Infallible>,
    },
    /// The version 1 fields of a long header packet could not be read.
    #[snafu(display("long header packet read failed"))]
    LongPacket {
        /// The failure of reading the fields.
        source: ReadLongPacketError<Infallible>,
    },
    /// A short header could not be read.
    #[snafu(display("short header read failed"))]
    ShortHeader {
        /// The failure of reading the header.
        source: ReadShortHeaderError<Infallible>,
    },
}

#[cfg(test)]
mod tests;
