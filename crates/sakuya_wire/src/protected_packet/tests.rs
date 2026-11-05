use super::{IntoPacketsError, PacketBoundaryError, ProtectedPacket, into_packets};
use crate::{
    connection_id::{ConnectionId, ConnectionIdLength},
    encryption_level::EncryptionLevel,
    header::{
        ShortPacketHeader,
        codec::WriteShortPacketHeaderHostExt as _,
        v1::{
            LongPacketHeader, LongPacketType, TypeFields,
            codec::{ReadLongPacketError, WriteLongPacketHeaderHostExt as _},
        },
    },
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
        0b11,
        cid(dcid),
        cid(&SCID),
        VarIntWidth::Two,
        Bytes::from_static(token),
        reserved(VarIntWidth::Two),
    )
    .unwrap();
    finish_long(&header, body)
}

fn handshake(dcid: &[u8], body: &[u8]) -> Vec<u8> {
    let header =
        LongPacketHeader::handshake(0b01, cid(dcid), cid(&SCID), reserved(VarIntWidth::One))
            .unwrap();
    finish_long(&header, body)
}

fn zero_rtt(dcid: &[u8], body: &[u8]) -> Vec<u8> {
    let header =
        LongPacketHeader::zero_rtt(0, cid(dcid), cid(&SCID), reserved(VarIntWidth::Four)).unwrap();
    finish_long(&header, body)
}

fn one_rtt(dcid: &[u8], body: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet
        .sync_write_short_packet_header_unpin(ShortPacketHeader::new(0b10_0001, cid(dcid)).unwrap())
        .unwrap();
    packet.extend_from_slice(body);
    packet
}

fn levels<P>(
    items: &[Result<ProtectedPacket<P>, IntoPacketsError>],
) -> Vec<Option<EncryptionLevel>> {
    items
        .iter()
        .map(|item| item.as_ref().ok().map(ProtectedPacket::level))
        .collect()
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
    let Ok(ProtectedPacket::Initial(initial, bytes)) = &items[0] else {
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
    let Ok(ProtectedPacket::OneRtt(short, bytes)) = &items[3] else {
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
    let packet = packets.next().unwrap().unwrap();
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
fn a_version_that_is_not_v1_has_an_unreadable_boundary() {
    // Version Negotiation, and a version that this crate does not know.
    for version in [0u32, 0x6b33_43cf] {
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

#[test]
fn a_retry_packet_is_not_a_protected_packet() {
    // RFC 9001 Appendix A.4.
    let retry: Vec<u8> = (0..)
        .step_by(2)
        .take(36)
        .map(|index| {
            let text = "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba";
            u8::from_str_radix(&text[index..index + 2], 16).unwrap()
        })
        .collect();
    let mut packets = into_packets(retry.as_slice(), dcid_len(0));
    assert!(matches!(
        packets.next().unwrap(),
        Err(IntoPacketsError::Retry)
    ));
    assert!(packets.next().is_none());
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
        match item.unwrap() {
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
