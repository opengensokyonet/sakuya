use super::{IntoPacketsError, Packet, PacketBoundaryError, ProtectedPacket, into_packets};
use crate::{
    connection_id::{ConnectionId, ConnectionIdLength},
    v1::encryption_level::EncryptionLevel,
    v1::header::{
        KeyPhase, LongPacketHeader, LongPacketType, ShortPacketHeader, TypeFields,
        codec::{
            ReadLongPacketError, WriteLongPacketHeaderHostExt as _,
            WriteShortPacketHeaderHostExt as _,
        },
    },
    v1::packet_number::PacketNumberLength,
    var_int::{VarInt, VarIntField, VarIntWidth, codec::WriteVarIntFieldHostExt as _},
};
use bytes::{Bytes, BytesMut};

const DCID: [u8; 4] = [1, 2, 3, 4];
const SCID: [u8; 2] = [9, 8];

fn dcid_len(length: usize) -> ConnectionIdLength {
    ConnectionIdLength::new(length).unwrap()
}

fn cid(bytes: &[u8]) -> ConnectionId {
    ConnectionId::new(bytes).unwrap()
}

fn reserved(width: VarIntWidth) -> VarIntField<VarInt> {
    VarIntField::new(VarInt::from(0u8), width).unwrap()
}

/// Fills in the Length of a long header packet whose header `header` and
/// `body` of packet number and payload are written.
fn finish_long(header: &LongPacketHeader, body: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet
        .sync_write_long_packet_header_unpin(header.clone())
        .unwrap();
    packet.extend_from_slice(body);
    let length = VarIntField::new(
        VarInt::try_from(body.len()).unwrap(),
        header.length().width(),
    )
    .unwrap();
    (&mut packet[header.length_offset()..])
        .sync_write_var_int_field_unpin(length)
        .unwrap();
    packet
}

fn initial(dcid: &[u8], token: &'static [u8], body: &[u8]) -> Vec<u8> {
    let header = LongPacketHeader::initial(
        cid(dcid),
        cid(&SCID),
        VarIntWidth::Two,
        Bytes::from_static(token),
        PacketNumberLength::Four,
        reserved(VarIntWidth::Two),
    )
    .unwrap();
    finish_long(&header, body)
}

fn handshake(dcid: &[u8], body: &[u8]) -> Vec<u8> {
    let header = LongPacketHeader::handshake(
        cid(dcid),
        cid(&SCID),
        PacketNumberLength::Two,
        reserved(VarIntWidth::One),
    );
    finish_long(&header, body)
}

fn zero_rtt(dcid: &[u8], body: &[u8]) -> Vec<u8> {
    let header = LongPacketHeader::zero_rtt(
        cid(dcid),
        cid(&SCID),
        PacketNumberLength::One,
        reserved(VarIntWidth::Four),
    );
    finish_long(&header, body)
}

fn one_rtt(dcid: &[u8], body: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet
        .sync_write_short_packet_header_unpin(ShortPacketHeader::new(
            true,
            KeyPhase::Zero,
            PacketNumberLength::Two,
            cid(dcid),
        ))
        .unwrap();
    packet.extend_from_slice(body);
    packet
}

/// The level of a protected packet; `None` for an error and for a packet
/// that is not protected.
fn levels<P>(items: &[Result<Packet<P>, IntoPacketsError>]) -> Vec<Option<EncryptionLevel>> {
    items
        .iter()
        .map(|item| match item {
            Ok(Packet::Protected(packet)) => Some(packet.level()),
            _ => None,
        })
        .collect()
}

/// The protected packet in an item.
fn protected<P>(item: Result<Packet<P>, IntoPacketsError>) -> ProtectedPacket<P> {
    match item.unwrap() {
        Packet::Protected(packet) => packet,
        _ => panic!("not a protected packet"),
    }
}

#[test]
fn a_datagram_of_every_packet_kind_is_cut_in_order() {
    let packets = [
        initial(&DCID, b"tok", &[0x11; 30]),
        zero_rtt(&DCID, &[0x22; 17]),
        handshake(&DCID, &[0x33; 20]),
        one_rtt(&DCID, &[0x44; 25]),
    ];
    let datagram = packets.concat();

    let items: Vec<_> = into_packets(datagram.as_slice(), dcid_len(4)).collect();
    assert_eq!(
        levels(&items),
        [
            Some(EncryptionLevel::Initial),
            Some(EncryptionLevel::ZeroRtt),
            Some(EncryptionLevel::Handshake),
            Some(EncryptionLevel::OneRtt),
        ]
    );
    for (item, expected) in items.iter().zip(&packets) {
        assert_eq!(item.as_ref().unwrap().bytes(), &expected.as_slice());
    }

    // The Initial packet's token and protected bytes are ranges of its own
    // bytes.
    let Ok(Packet::Protected(ProtectedPacket::Initial(initial, bytes))) = &items[0] else {
        panic!("not an Initial packet")
    };
    let TypeFields::Initial {
        token,
        bounds,
        protected,
    } = initial.fields()
    else {
        panic!("not Initial fields")
    };
    assert_eq!(&bytes[token.clone()], b"tok");
    assert_eq!(
        protected.clone(),
        bounds.packet_number_offset()..bytes.len()
    );
    assert_eq!(&bytes[protected.clone()], &[0x11; 30]);
    assert_eq!(initial.end(), bytes.len());

    // The 1-RTT packet's protected bytes follow its connection ID.
    let Ok(Packet::Protected(ProtectedPacket::OneRtt(short, bytes))) = &items[3] else {
        panic!("not a 1-RTT packet")
    };
    assert_eq!(short.dcid().as_bytes(), DCID);
    assert_eq!(short.first_byte(), 0x61);
    assert_eq!(short.packet_number_offset(), 5);
    assert_eq!(short.sample_offset(), 9);
    assert_eq!(short.protected().clone(), 5..bytes.len());
}

#[test]
fn the_pieces_of_a_bytes_mut_share_its_storage() {
    let datagram = [handshake(&DCID, &[0x33; 20]), one_rtt(&DCID, &[0x44; 25])].concat();
    let mut buffer = BytesMut::from(datagram.as_slice());
    let start = buffer.as_ptr();
    let items: Vec<_> = into_packets(buffer.split(), dcid_len(4)).collect();
    assert_eq!(items.len(), 2);
    let mut offset = 0;
    for item in items {
        let packet = item.unwrap();
        assert_eq!(packet.bytes().as_ptr(), start.wrapping_add(offset));
        offset += packet.bytes().len();
        let mut bytes = packet.into_bytes();
        // Each piece is writable on its own.
        bytes[0] ^= 0xff;
    }
    assert_eq!(offset, datagram.len());
}

#[test]
fn the_pieces_of_a_bytes_share_its_storage() {
    let datagram = [handshake(&DCID, &[0x33; 20]), one_rtt(&DCID, &[0x44; 25])].concat();
    let buffer = Bytes::from(datagram.clone());
    let start = buffer.as_ptr();
    let items: Vec<_> = into_packets(buffer, dcid_len(4)).collect();
    assert_eq!(items.len(), 2);
    let mut offset = 0;
    for item in items {
        let packet = item.unwrap();
        assert_eq!(packet.bytes().as_ptr(), start.wrapping_add(offset));
        offset += packet.bytes().len();
    }
    assert_eq!(offset, datagram.len());
}

#[test]
fn an_empty_datagram_has_no_packets() {
    assert_eq!(into_packets(&b""[..], dcid_len(4)).count(), 0);
    assert_eq!(into_packets(BytesMut::new(), dcid_len(4)).count(), 0);
}

#[test]
fn a_short_header_packet_takes_the_rest_of_the_datagram() {
    let datagram = one_rtt(&DCID, &[0x44; 25]);
    let mut packets = into_packets(datagram.as_slice(), dcid_len(4));
    let packet = protected(packets.next().unwrap());
    assert_eq!(packet.level(), EncryptionLevel::OneRtt);
    assert_eq!(packet.into_bytes(), datagram.as_slice());
    assert!(packets.next().is_none());
}

#[test]
fn a_packet_for_another_connection_is_reported_and_skipped() {
    let other = [5, 5, 5, 5];
    let datagram = [
        initial(&DCID, b"", &[1; 20]),
        handshake(&other, &[2; 20]),
        handshake(&DCID, &[3; 20]),
        one_rtt(&other, &[4; 20]),
    ]
    .concat();
    let items: Vec<_> = into_packets(datagram.as_slice(), dcid_len(4)).collect();
    assert_eq!(
        levels(&items),
        [
            Some(EncryptionLevel::Initial),
            None,
            Some(EncryptionLevel::Handshake),
            None,
        ]
    );
    for index in [1, 3] {
        assert!(
            matches!(&items[index], Err(IntoPacketsError::DcidDiffersFromFirst)),
            "packet {index} was not reported"
        );
    }
    // The packet after the skipped one is the right one.
    let kept = items[2].as_ref().unwrap();
    assert_eq!(kept.bytes(), &handshake(&DCID, &[3; 20]).as_slice());
}

#[test]
fn a_short_header_of_another_length_differs_from_the_first_packet() {
    let datagram = [
        handshake(&DCID, &[2; 20]),
        // The connection ID of the long header is 4 bytes; read as 2 bytes
        // the short header names another one.
        one_rtt(&DCID, &[4; 20]),
    ]
    .concat();
    let items: Vec<_> = into_packets(datagram.as_slice(), dcid_len(2)).collect();
    assert_eq!(items.len(), 2);
    assert!(matches!(
        &items[1],
        Err(IntoPacketsError::DcidDiffersFromFirst)
    ));
}

#[test]
fn an_unreadable_boundary_ends_the_iteration() {
    let good = handshake(&DCID, &[2; 20]);
    // The Length field states more bytes than the rest of the datagram holds.
    let mut bad = handshake(&DCID, &[3; 20]);
    let length_offset = 1 + 4 + 1 + 4 + 1 + 2;
    bad[length_offset] = 63;
    let datagram = [good.clone(), bad, handshake(&DCID, &[4; 20])].concat();

    let mut packets = into_packets(datagram.as_slice(), dcid_len(4));
    assert_eq!(packets.next().unwrap().unwrap().bytes(), &good.as_slice());
    let Err(IntoPacketsError::UnreadableBoundary {
        source: PacketBoundaryError::LongPacket { source },
    }) = packets.next().unwrap()
    else {
        panic!("not an unreadable boundary")
    };
    assert!(source.is_incomplete());
    assert!(packets.next().is_none());
    assert!(packets.next().is_none());
}

#[test]
fn headers_that_end_early_have_unreadable_boundaries() {
    for truncated in [&[0xe0][..], &[0xe0, 0, 0, 0, 1, 4, 1], &[0x40, 1, 2]] {
        let mut packets = into_packets(truncated, dcid_len(4));
        let item = packets.next().unwrap();
        let error = item.unwrap_err();
        assert!(
            matches!(error, IntoPacketsError::UnreadableBoundary { .. }),
            "{error:?}"
        );
        assert!(packets.next().is_none());
    }
}

#[test]
fn a_version_that_is_neither_zero_nor_v1_has_an_unreadable_boundary() {
    // A version that this crate does not know.
    for version in [0x6b33_43cfu32, 2, 0xff00_001d] {
        let mut datagram = vec![0xc0];
        datagram.extend_from_slice(&version.to_be_bytes());
        datagram.extend_from_slice(&[0, 0, 0, 0, 0, 1, 2, 3]);
        let mut packets = into_packets(datagram.as_slice(), dcid_len(0));
        let Err(IntoPacketsError::UnreadableBoundary {
            source:
                PacketBoundaryError::LongPacket {
                    source: ReadLongPacketError::Version { source },
                },
        }) = packets.next().unwrap()
        else {
            panic!("not a version failure")
        };
        assert_eq!(source.version().get(), version);
        assert!(packets.next().is_none());
    }
}

/// RFC 9001 Appendix A.4: a Retry packet with an empty destination
/// connection ID, an 8-byte source connection ID, the token `token` and the
/// 16-byte integrity tag.
fn rfc_retry() -> Vec<u8> {
    (0..)
        .step_by(2)
        .take(36)
        .map(|index| {
            let text = "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba";
            u8::from_str_radix(&text[index..index + 2], 16).unwrap()
        })
        .collect()
}

/// A Version Negotiation packet offering versions 1 and 0xfaface00, with the
/// given connection IDs.
fn version_negotiation(dcid: &[u8], scid: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x80, 0, 0, 0, 0, dcid.len() as u8];
    packet.extend_from_slice(dcid);
    packet.push(scid.len() as u8);
    packet.extend_from_slice(scid);
    packet.extend_from_slice(&[0, 0, 0, 1, 0xfa, 0xce, 0xfa, 0xce]);
    packet
}

#[test]
fn a_retry_packet_alone_is_one_unprotected_packet() {
    let retry = rfc_retry();
    let mut packets = into_packets(retry.as_slice(), dcid_len(0));
    let Ok(Packet::Retry(packet, bytes)) = packets.next().unwrap() else {
        panic!("not a Retry packet")
    };
    assert_eq!(bytes, retry.as_slice());
    assert_eq!(packet.packet_type(), LongPacketType::Retry);
    assert_eq!(packet.end(), retry.len());
    let TypeFields::Retry {
        token,
        integrity_tag,
        end,
    } = packet.fields()
    else {
        panic!("not Retry fields")
    };
    assert_eq!(&token[..], b"token");
    assert_eq!(integrity_tag[..], retry[retry.len() - 16..]);
    assert_eq!(*end, retry.len());
    assert!(packets.next().is_none());
}

#[test]
fn a_version_negotiation_packet_alone_is_one_unprotected_packet() {
    let datagram = version_negotiation(&DCID, &SCID);
    let mut packets = into_packets(datagram.as_slice(), dcid_len(0));
    let Ok(Packet::VersionNegotiation(packet, bytes)) = packets.next().unwrap() else {
        panic!("not a Version Negotiation packet")
    };
    assert_eq!(bytes, datagram.as_slice());
    assert_eq!(packet.dcid().as_bytes(), DCID);
    assert_eq!(packet.scid().as_bytes(), SCID);
    // The list fills the rest of the packet, after the first byte, the
    // version and the two connection IDs with their lengths.
    let list = packet.versions().clone();
    assert_eq!(list, 1 + 4 + 1 + 4 + 1 + 2..datagram.len());
    assert_eq!(datagram[list], [0, 0, 0, 1, 0xfa, 0xce, 0xfa, 0xce]);
    assert!(packets.next().is_none());
}

#[test]
fn a_retry_packet_ends_the_iteration_after_the_packets_before_it() {
    // The Retry packet of RFC 9001 Appendix A.4 echoes a 0-byte destination
    // connection ID in the long header, which the packet before it shares.
    let initial = initial(&[], b"", &[1; 20]);
    let retry = rfc_retry();
    let datagram = [initial.clone(), retry.clone()].concat();
    let items: Vec<_> = into_packets(datagram.as_slice(), dcid_len(0)).collect();
    assert_eq!(items.len(), 2);
    assert_eq!(levels(&items), [Some(EncryptionLevel::Initial), None]);
    assert_eq!(items[0].as_ref().unwrap().bytes(), &initial.as_slice());
    let Ok(Packet::Retry(_, bytes)) = &items[1] else {
        panic!("not a Retry packet")
    };
    assert_eq!(*bytes, retry.as_slice());
}

#[test]
fn a_retry_or_version_negotiation_packet_for_another_connection_is_reported() {
    let datagram = [
        initial(&DCID, b"", &[1; 20]),
        version_negotiation(&[5; 4], &SCID),
    ]
    .concat();
    let items: Vec<_> = into_packets(datagram.as_slice(), dcid_len(4)).collect();
    assert_eq!(items.len(), 2);
    assert!(matches!(
        &items[1],
        Err(IntoPacketsError::DcidDiffersFromFirst)
    ));

    // The Retry packet's destination connection ID is empty, unlike the
    // Initial packet's.
    let datagram = [initial(&DCID, b"", &[1; 20]), rfc_retry()].concat();
    let items: Vec<_> = into_packets(datagram.as_slice(), dcid_len(4)).collect();
    assert_eq!(items.len(), 2);
    assert!(matches!(
        &items[1],
        Err(IntoPacketsError::DcidDiffersFromFirst)
    ));
}

#[test]
fn a_version_negotiation_packet_with_a_broken_list_has_an_unreadable_boundary() {
    let mut datagram = version_negotiation(&DCID, &SCID);
    datagram.pop();
    let mut packets = into_packets(datagram.as_slice(), dcid_len(0));
    assert!(matches!(
        packets.next().unwrap(),
        Err(IntoPacketsError::UnreadableBoundary {
            source: PacketBoundaryError::VersionNegotiation { .. }
        })
    ));
    assert!(packets.next().is_none());
}

#[test]
fn the_unprotected_packets_of_a_bytes_datagram_share_its_storage() {
    let datagram = Bytes::from([initial(&[], b"", &[1; 20]), rfc_retry()].concat());
    let start = datagram.as_ptr();
    let items: Vec<_> = into_packets(datagram, dcid_len(0)).collect();
    let Ok(Packet::Retry(_, bytes)) = &items[1] else {
        panic!("not a Retry packet")
    };
    assert_eq!(
        bytes.as_ptr(),
        start.wrapping_add(items[0].as_ref().unwrap().bytes().len())
    );
}

#[test]
fn the_packet_types_of_the_read_headers_match_the_levels() {
    let datagram = [
        initial(&DCID, b"", &[1; 20]),
        zero_rtt(&DCID, &[2; 20]),
        handshake(&DCID, &[3; 20]),
    ]
    .concat();
    for item in into_packets(datagram.as_slice(), dcid_len(4)) {
        match protected(item) {
            ProtectedPacket::Initial(packet, _) => {
                assert_eq!(packet.packet_type(), LongPacketType::Initial);
            }
            ProtectedPacket::ZeroRtt(packet, _) => {
                assert_eq!(packet.packet_type(), LongPacketType::ZeroRtt);
            }
            ProtectedPacket::Handshake(packet, _) => {
                assert_eq!(packet.packet_type(), LongPacketType::Handshake);
            }
            ProtectedPacket::OneRtt(..) => panic!("no short header packet"),
        }
    }
}

#[test]
fn zero_length_connection_ids_are_the_same_connection() {
    let datagram = [handshake(&[], &[2; 20]), one_rtt(&[], &[4; 20])].concat();
    let items: Vec<_> = into_packets(datagram.as_slice(), dcid_len(0)).collect();
    assert_eq!(
        levels(&items),
        [
            Some(EncryptionLevel::Handshake),
            Some(EncryptionLevel::OneRtt)
        ]
    );
}
