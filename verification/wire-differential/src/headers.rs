//! Packet header interpretation in the three implementations: one packet at
//! the start of a datagram, the packets a datagram is cut into, and the
//! headers a sender writes.
//!
//! The neutral model [`Packet`] holds what a header states before protection
//! is removed. Each implementation has an adapter that reads a datagram into
//! it; [`compare_quinn`] and [`compare_s2n`] classify where the adapters
//! disagree with sakuya.
use crate::tally::{self, Comparison};
use bytes::BytesMut;
use quinn_proto::{
    FixedLengthConnectionIdParser, LongType, PacketDecodeError, PartialDecode, ProtectedHeader,
};
use s2n_codec::DecoderBufferMut;
use s2n_quic_core::{
    connection::id::ConnectionInfo,
    inet::{IpV4Address, SocketAddress, SocketAddressV4},
    packet::ProtectedPacket,
};
use sakuya_wire::{
    connection_id::ConnectionIdLength,
    header::{
        HeaderForm, LongHeader, ShortHeader, VersionNegotiation,
        codec::{
            ReadLongHeaderError, ReadLongHeaderHostExt as _, ReadShortHeaderError,
            ReadShortHeaderHostExt as _, ReadVersionNegotiationError,
            ReadVersionNegotiationHostExt as _,
        },
    },
    v1::header::{
        self as v1, LongPacket, TypeFields,
        codec::{ReadLongPacketError, ReadLongPacketHostExt as _},
    },
    version::Version,
};
use std::convert::Infallible;

pub mod generate;
pub mod split;
pub mod write;

/// The kind of a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    VersionNegotiation,
    /// A long header of a version other than 0 and 1: only the fields of
    /// RFC 8999 §5.1 are known.
    OtherVersion,
    Short,
}

/// What a packet header states before protection is removed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub kind: Kind,
    pub version: Option<u32>,
    pub dcid: Vec<u8>,
    pub scid: Option<Vec<u8>>,
    /// The token of an Initial or Retry packet.
    pub token: Option<Vec<u8>>,
    /// The integrity tag of a Retry packet.
    pub integrity_tag: Option<Vec<u8>>,
    /// The supported version list of a Version Negotiation packet, as bytes.
    pub versions: Option<Vec<u8>>,
    /// The offset of the Packet Number field, where the reader states it.
    pub pn_offset: Option<usize>,
    /// The number of bytes that belong to this packet, where it is known.
    pub end: Option<usize>,
}

impl Packet {
    fn new(kind: Kind, dcid: &[u8]) -> Self {
        Self {
            kind,
            version: None,
            dcid: dcid.to_vec(),
            scid: None,
            token: None,
            integrity_tag: None,
            versions: None,
            pn_offset: None,
            end: None,
        }
    }

    /// Whether a connection ID is longer than version 1 allows.
    pub fn long_cid(&self) -> bool {
        self.dcid.len() > 20 || self.scid.as_ref().is_some_and(|scid| scid.len() > 20)
    }
}

/// A host of a datagram that sakuya's header operations read from.
///
/// Byte slices read synchronously; [`crate::hosts::Waiting`] waits before
/// every read. Both hand out chunks of the datagram, so the results have the
/// same type.
pub trait Source<'a> {
    fn long_header(&mut self) -> Result<LongHeader, ReadLongHeaderError<Infallible>>;
    fn short_header(
        &mut self,
        dcid_len: ConnectionIdLength,
    ) -> Result<ShortHeader<&'a [u8]>, ReadShortHeaderError<Infallible>>;
    fn version_negotiation(
        &mut self,
        header: LongHeader,
    ) -> Result<VersionNegotiation<&'a [u8]>, ReadVersionNegotiationError<Infallible>>;
    fn long_packet(
        &mut self,
        header: LongHeader,
    ) -> Result<LongPacket<&'a [u8]>, ReadLongPacketError<Infallible>>;
    /// The bytes not yet read.
    fn rest(&self) -> &'a [u8];
}

impl<'a> Source<'a> for &'a [u8] {
    fn long_header(&mut self) -> Result<LongHeader, ReadLongHeaderError<Infallible>> {
        self.sync_read_long_header_unpin()
    }

    fn short_header(
        &mut self,
        dcid_len: ConnectionIdLength,
    ) -> Result<ShortHeader<&'a [u8]>, ReadShortHeaderError<Infallible>> {
        self.sync_read_short_header_unpin(dcid_len)
    }

    fn version_negotiation(
        &mut self,
        header: LongHeader,
    ) -> Result<VersionNegotiation<&'a [u8]>, ReadVersionNegotiationError<Infallible>> {
        self.sync_read_version_negotiation_unpin(header)
    }

    fn long_packet(
        &mut self,
        header: LongHeader,
    ) -> Result<LongPacket<&'a [u8]>, ReadLongPacketError<Infallible>> {
        self.sync_read_long_packet_unpin(header)
    }

    fn rest(&self) -> &'a [u8] {
        self
    }
}

impl<'a> Source<'a> for crate::hosts::Waiting<'a> {
    fn long_header(&mut self) -> Result<LongHeader, ReadLongHeaderError<Infallible>> {
        crate::hosts::run(self.read_long_header_unpin())
    }

    fn short_header(
        &mut self,
        dcid_len: ConnectionIdLength,
    ) -> Result<ShortHeader<&'a [u8]>, ReadShortHeaderError<Infallible>> {
        crate::hosts::run(self.read_short_header_unpin(dcid_len))
    }

    fn version_negotiation(
        &mut self,
        header: LongHeader,
    ) -> Result<VersionNegotiation<&'a [u8]>, ReadVersionNegotiationError<Infallible>> {
        crate::hosts::run(self.read_version_negotiation_unpin(header))
    }

    fn long_packet(
        &mut self,
        header: LongHeader,
    ) -> Result<LongPacket<&'a [u8]>, ReadLongPacketError<Infallible>> {
        crate::hosts::run(self.read_long_packet_unpin(header))
    }

    fn rest(&self) -> &'a [u8] {
        self.source
    }
}

/// The model of a version 1 long packet that sakuya read; `bytes` gives the
/// bytes of a token that `D` holds.
pub fn long_packet_model<D>(packet: &LongPacket<D>, bytes: impl Fn(&D) -> Vec<u8>) -> Packet {
    let mut model = Packet::new(Kind::Initial, packet.dcid().as_bytes());
    model.version = Some(packet.header().version().get());
    model.scid = Some(packet.scid().as_bytes().to_vec());
    model.end = Some(packet.end());
    match packet.fields() {
        TypeFields::Initial { token, bounds, .. } => {
            model.token = Some(bytes(token));
            model.pn_offset = Some(bounds.packet_number_offset());
        }
        TypeFields::ZeroRtt { bounds, .. } => {
            model.kind = Kind::ZeroRtt;
            model.pn_offset = Some(bounds.packet_number_offset());
        }
        TypeFields::Handshake { bounds, .. } => {
            model.kind = Kind::Handshake;
            model.pn_offset = Some(bounds.packet_number_offset());
        }
        TypeFields::Retry {
            token,
            integrity_tag,
            ..
        } => {
            model.kind = Kind::Retry;
            model.token = Some(token.to_vec());
            model.integrity_tag = Some(integrity_tag.to_vec());
        }
    }
    model
}

/// Interprets the packet at the start of `source` with sakuya, layer by
/// layer, leaving `source` after the packet.
pub fn read_sakuya_from<'a>(
    source: &mut impl Source<'a>,
    short_dcid_len: ConnectionIdLength,
) -> Option<Packet> {
    let first = *source.rest().first()?;
    if HeaderForm::of(first) == HeaderForm::Short {
        let short = source.short_header(short_dcid_len).ok()?;
        let mut model = Packet::new(Kind::Short, short.dcid().as_bytes());
        model.pn_offset = Some(short.packet_number_offset());
        model.end = Some(short.end());
        return Some(model);
    }
    let long = source.long_header().ok()?;
    let mut model = Packet::new(Kind::OtherVersion, long.dcid().as_bytes());
    model.scid = Some(long.scid().as_bytes().to_vec());
    model.version = Some(long.version().get());
    match long.version() {
        Version::NEGOTIATION => {
            let start = long.version_specific_offset();
            let negotiation = source.version_negotiation(long).ok()?;
            let versions: &[u8] = negotiation.versions();
            assert!(
                negotiation
                    .supported_versions()
                    .map(Version::to_be_bytes)
                    .eq(versions
                        .chunks(4)
                        .map(|chunk| <[u8; 4]>::try_from(chunk).unwrap())),
                "supported versions differ from the list",
            );
            model.kind = Kind::VersionNegotiation;
            model.end = Some(start + versions.len());
            model.versions = Some(versions.to_vec());
            Some(model)
        }
        v1::VERSION => {
            let packet = source.long_packet(long).ok()?;
            Some(long_packet_model(&packet, |token| token.to_vec()))
        }
        _ => Some(model),
    }
}

/// Interprets the packet at the start of `datagram` with sakuya.
pub fn read_sakuya(datagram: &[u8], short_dcid_len: ConnectionIdLength) -> Option<Packet> {
    read_sakuya_from(&mut &datagram[..], short_dcid_len)
}

/// Interprets the packet at the start of `datagram` with quinn-proto, with
/// the Fixed Bit enforced unless `grease_quic_bit`.
pub fn read_quinn(
    datagram: &[u8],
    short_dcid_len: ConnectionIdLength,
    grease_quic_bit: bool,
) -> Option<Packet> {
    let parser = FixedLengthConnectionIdParser::new(short_dcid_len.get());
    let bytes = BytesMut::from(datagram);
    let (decode, rest) = match PartialDecode::new(bytes, &parser, &[1], grease_quic_bit) {
        Ok(decoded) => decoded,
        Err(PacketDecodeError::UnsupportedVersion {
            src_cid,
            dst_cid,
            version,
        }) => {
            let mut model = Packet::new(Kind::OtherVersion, &dst_cid);
            model.scid = Some(src_cid.to_vec());
            model.version = Some(version);
            return Some(model);
        }
        Err(_) => return None,
    };
    let position = decode.buf.position() as usize;
    let data = decode.data();
    let mut model = Packet::new(Kind::Short, decode.dst_cid());
    model.end = Some(datagram.len() - rest.map_or(0, |rest| rest.len()));
    match &decode.plain_header {
        ProtectedHeader::Initial(header) => {
            model.kind = Kind::Initial;
            model.version = Some(header.version);
            model.scid = Some(header.src_cid.to_vec());
            model.token = Some(data[header.token_pos.clone()].to_vec());
            model.pn_offset = Some(position);
        }
        ProtectedHeader::Long {
            ty,
            src_cid,
            version,
            ..
        } => {
            model.kind = match ty {
                LongType::Handshake => Kind::Handshake,
                LongType::ZeroRtt => Kind::ZeroRtt,
            };
            model.version = Some(*version);
            model.scid = Some(src_cid.to_vec());
            model.pn_offset = Some(position);
        }
        ProtectedHeader::Retry {
            src_cid, version, ..
        } => {
            model.kind = Kind::Retry;
            model.version = Some(*version);
            model.scid = Some(src_cid.to_vec());
            // quinn-proto leaves the token and the tag in the payload; they
            // are only told apart where the tag fits.
            if let Some(tag) = data.len().checked_sub(16).filter(|&tag| tag >= position) {
                model.token = Some(data[position..tag].to_vec());
                model.integrity_tag = Some(data[tag..].to_vec());
            }
        }
        ProtectedHeader::Short { .. } => model.pn_offset = Some(position),
        ProtectedHeader::VersionNegotiate { src_cid, .. } => {
            model.kind = Kind::VersionNegotiation;
            model.version = Some(0);
            model.scid = Some(src_cid.to_vec());
            model.versions = Some(data[position..].to_vec());
        }
    }
    Some(model)
}

/// Decodes the packet at the start of `datagram` with s2n-quic-core: the
/// packet and the number of bytes it took.
pub fn decode_s2n(datagram: &[u8], short_dcid_len: ConnectionIdLength) -> Option<(Packet, usize)> {
    let mut storage = datagram.to_vec();
    let total = storage.len();
    let address = SocketAddress::IpV4(SocketAddressV4::new(IpV4Address::from([127, 0, 0, 1]), 1));
    let info = ConnectionInfo::new(&address);
    let validator = short_dcid_len.get();
    let (packet, rest) =
        ProtectedPacket::decode(DecoderBufferMut::new(&mut storage), &info, &validator).ok()?;
    let end = total - rest.len();
    let mut model = Packet::new(Kind::Short, packet.destination_connection_id());
    model.scid = packet.source_connection_id().map(<[u8]>::to_vec);
    model.version = packet.version();
    model.end = Some(end);
    match &packet {
        ProtectedPacket::Short(_) => {}
        ProtectedPacket::VersionNegotiation(negotiation) => {
            model.kind = Kind::VersionNegotiation;
            // s2n-quic-core identifies the packet by version 0.
            model.version = Some(0);
            model.versions = Some(negotiation.supported_versions.to_vec());
        }
        ProtectedPacket::Initial(initial) => {
            model.kind = Kind::Initial;
            model.token = Some(initial.token().to_vec());
        }
        ProtectedPacket::ZeroRtt(_) => model.kind = Kind::ZeroRtt,
        ProtectedPacket::Handshake(_) => model.kind = Kind::Handshake,
        ProtectedPacket::Retry(retry) => {
            model.kind = Kind::Retry;
            model.token = Some(retry.retry_token().to_vec());
            model.integrity_tag = Some(retry.retry_integrity_tag.to_vec());
        }
    }
    Some((model, end))
}

/// Interprets the packet at the start of `datagram` with s2n-quic-core. It
/// does not state the Packet Number field offset.
pub fn read_s2n(datagram: &[u8], short_dcid_len: ConnectionIdLength) -> Option<Packet> {
    decode_s2n(datagram, short_dcid_len).map(|(packet, _)| packet)
}

/// Compares sakuya against quinn-proto, with the Fixed Bit not enforced on
/// either side: sakuya leaves it to its caller.
pub fn compare_quinn(datagram: &[u8], short_dcid_len: ConnectionIdLength) -> Comparison {
    let ours = read_sakuya(datagram, short_dcid_len);
    let theirs = read_quinn(datagram, short_dcid_len, true);
    match (&ours, &theirs) {
        (Some(a), Some(b)) if a == b => Comparison::Agree,
        (None, None) => Comparison::Agree,
        (Some(a), None)
            if matches!(a.kind, Kind::OtherVersion | Kind::VersionNegotiation) && a.long_cid() =>
        {
            Comparison::Known(
                "connection ID above 20 bytes outside version 1: RFC 8999 5.1 allows 255 and RFC 9000 17.2 asks servers to read them, quinn stops at 20",
            )
        }
        (None, Some(b))
            if b.kind == Kind::VersionNegotiation
                && b.versions.as_ref().is_some_and(|list| list.len() % 4 != 0) =>
        {
            Comparison::Known(
                "Version Negotiation list with a truncated version: RFC 8999 6 has the endpoint ignore it, sakuya rejects while reading, quinn while processing",
            )
        }
        (None, Some(b)) if b.kind == Kind::Retry && b.integrity_tag.is_none() => Comparison::Known(
            "Retry shorter than its integrity tag: RFC 9000 17.2.5 ends it with a 128-bit tag, sakuya rejects while reading, quinn while processing",
        ),
        _ => Comparison::Unclassified,
    }
}

/// Compares sakuya against s2n-quic-core, which states no Packet Number
/// field offset.
pub fn compare_s2n(datagram: &[u8], short_dcid_len: ConnectionIdLength) -> Comparison {
    let ours = read_sakuya(datagram, short_dcid_len);
    let theirs = read_s2n(datagram, short_dcid_len);
    let fixed_bit_unset = datagram.first().is_some_and(|first| first & 0x40 == 0);
    match (&ours, &theirs) {
        (Some(a), Some(b)) => {
            if a.kind == Kind::OtherVersion && a.dcid == b.dcid && a.scid == b.scid {
                return Comparison::Known(
                    "long header of another version: s2n applies its version 1 layout, sakuya only the fields of RFC 8999 5.1",
                );
            }
            let a = Packet {
                pn_offset: None,
                ..a.clone()
            };
            if a == *b {
                Comparison::Agree
            } else {
                Comparison::Unclassified
            }
        }
        (None, None) => Comparison::Agree,
        (Some(a), None) => {
            if a.kind == Kind::OtherVersion {
                return Comparison::Known(
                    "long header of another version: s2n stops where its version 1 layout fails, sakuya keeps the fields of RFC 8999 5.1",
                );
            }
            if a.kind == Kind::VersionNegotiation && a.long_cid() {
                return Comparison::Known(
                    "connection ID above 20 bytes in Version Negotiation: RFC 8999 5.1 allows 255, s2n stops at 20",
                );
            }
            if a.kind == Kind::VersionNegotiation && a.versions.as_ref().is_some_and(Vec::is_empty)
            {
                return Comparison::Known(
                    "empty Version Negotiation list: RFC 8999 6 has the endpoint ignore it, s2n rejects while reading, sakuya leaves it to its caller",
                );
            }
            if a.kind == Kind::Retry && a.token.as_ref().is_some_and(Vec::is_empty) {
                return Comparison::Known(
                    "empty Retry token: RFC 9000 17.2.5.2 has the client discard it, s2n rejects while reading, sakuya leaves it to its caller",
                );
            }
            // With the bit set, s2n has to read the packet as sakuya does.
            let mut fixed = datagram.to_vec();
            fixed[0] |= 0x40;
            if fixed_bit_unset
                && a.kind != Kind::VersionNegotiation
                && compare_s2n(&fixed, short_dcid_len) != Comparison::Unclassified
            {
                return Comparison::Known(
                    "Fixed Bit unset: RFC 9000 17.2 and 17.3.1 have the packet discarded, s2n rejects while reading, sakuya leaves it to its caller",
                );
            }
            Comparison::Unclassified
        }
        (None, Some(b)) if b.kind == Kind::Initial && b.long_cid() => Comparison::Known(
            "version 1 Initial with a connection ID above 20 bytes: RFC 9000 17.2 requires dropping it, sakuya rejects while reading, s2n's Initial decoder reads it",
        ),
        _ => Comparison::Unclassified,
    }
}

/// Compares against both references and tallies the results.
pub fn compare_all(datagram: &[u8], short_dcid_len: ConnectionIdLength) -> [Comparison; 2] {
    let results = [
        ("quinn", compare_quinn(datagram, short_dcid_len)),
        ("s2n", compare_s2n(datagram, short_dcid_len)),
    ];
    for (name, result) in results {
        tally::tally("headers", name, result, || {
            format!(
                "dcid_len={} {} ours={:?} quinn={:?} s2n={:?}",
                short_dcid_len.get(),
                tally::hex(datagram),
                read_sakuya(datagram, short_dcid_len),
                read_quinn(datagram, short_dcid_len, true),
                read_s2n(datagram, short_dcid_len),
            )
        });
    }
    [results[0].1, results[1].1]
}
