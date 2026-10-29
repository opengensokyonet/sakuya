use super::{
    HeaderForm, LongHeader, LongHeaderError, ShortHeader, ShortHeaderError, TruncatedError,
    VersionNegotiation, VersionNegotiationError,
    v1::{self, LongPacket, LongPacketError, LongPacketType, TypeFields},
};
use crate::{
    connection_id::{ConnectionId, ConnectionIdLengthError},
    var_int::VarInt,
};

/// The protected client Initial packet of RFC 9001 Appendix A.2: 1200 bytes,
/// an 8-byte destination connection ID, an empty source connection ID, no
/// token and a Length of 1182.
const CLIENT_INITIAL: &[&str] = &[
    "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11",
    "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399",
    "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c",
    "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212",
    "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5",
    "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208",
    "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec",
    "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3",
    "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db",
    "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c",
    "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8",
    "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556",
    "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74",
    "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a",
    "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00",
    "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632",
    "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964",
    "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd",
    "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff",
    "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198",
    "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd",
    "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73",
    "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f",
    "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e",
    "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade",
    "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047",
    "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2",
    "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4",
    "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0",
    "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e",
    "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0",
    "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400",
    "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab",
    "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9",
    "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4",
    "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064",
    "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241",
    "e221af44860018ab0856972e194cd934",
];

/// The Retry packet of RFC 9001 Appendix A.4.
const RETRY: &str = "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba";

const RFC_DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

fn hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn client_initial() -> Vec<u8> {
    let packet = hex(&CLIENT_INITIAL.concat());
    assert_eq!(packet.len(), 1200);
    packet
}

fn truncated(required: usize, available: usize) -> TruncatedError {
    TruncatedError {
        required,
        available,
    }
}

/// A version 1 long header packet with a Length field; `length` covers the
/// packet number and payload bytes in `rest`.
fn long_packet(
    first_byte: u8,
    dcid: &[u8],
    scid: &[u8],
    token: Option<&[u8]>,
    rest: &[u8],
) -> Vec<u8> {
    let mut packet = vec![first_byte, 0, 0, 0, 1, dcid.len() as u8];
    packet.extend_from_slice(dcid);
    packet.push(scid.len() as u8);
    packet.extend_from_slice(scid);
    if let Some(token) = token {
        VarInt::try_from(token.len())
            .unwrap()
            .encode(&mut packet)
            .unwrap();
        packet.extend_from_slice(token);
    }
    VarInt::try_from(rest.len())
        .unwrap()
        .encode(&mut packet)
        .unwrap();
    packet.extend_from_slice(rest);
    packet
}

fn v1_packet(input: &[u8]) -> Result<LongPacket<'_>, LongPacketError> {
    LongPacket::try_from(LongHeader::parse(input).unwrap())
}

#[test]
fn header_form_is_the_most_significant_bit() {
    assert_eq!(HeaderForm::of(0xc0), HeaderForm::Long);
    assert_eq!(HeaderForm::of(0x80), HeaderForm::Long);
    assert_eq!(HeaderForm::of(0x7f), HeaderForm::Short);
    assert_eq!(HeaderForm::of(0x00), HeaderForm::Short);
}

#[test]
fn rfc_client_initial() {
    let datagram = client_initial();
    let header = LongHeader::parse(&datagram).unwrap();
    assert_eq!(header.first_byte(), 0xc0);
    assert_eq!(header.version(), v1::VERSION);
    assert_eq!(header.dcid(), RFC_DCID);
    assert_eq!(header.scid(), []);
    assert_eq!(header.version_specific_offset(), 15);
    assert_eq!(header.input(), datagram);

    let packet = LongPacket::try_from(header).unwrap();
    assert_eq!(packet.packet_type(), LongPacketType::Initial);
    assert_eq!(packet.dcid(), &ConnectionId::new(&RFC_DCID).unwrap());
    assert_eq!(packet.scid(), &ConnectionId::EMPTY);
    assert!(packet.fixed_bit());
    let TypeFields::Initial { token, bounds } = *packet.fields() else {
        panic!("expected Initial fields, got {:?}", packet.fields());
    };
    assert_eq!(token, []);
    assert_eq!(bounds.length(), VarInt::from(1182u16));
    assert_eq!(bounds.packet_number_offset(), 18);
    assert_eq!(bounds.end(), 1200);
    assert_eq!(packet.end(), 1200);
    assert_eq!(packet.packet(), datagram);
    assert!(packet.remainder().is_empty());
}

#[test]
fn rfc_retry() {
    let datagram = hex(RETRY);
    let header = LongHeader::parse(&datagram).unwrap();
    assert_eq!(header.version(), v1::VERSION);
    assert_eq!(header.dcid(), []);
    assert_eq!(header.scid(), hex("f067a5502a4262b5"));

    let packet = LongPacket::try_from(header).unwrap();
    assert_eq!(packet.packet_type(), LongPacketType::Retry);
    assert_eq!(packet.dcid(), &ConnectionId::EMPTY);
    assert_eq!(packet.scid().as_bytes(), hex("f067a5502a4262b5"));
    let TypeFields::Retry {
        token,
        integrity_tag,
    } = *packet.fields()
    else {
        panic!("expected Retry fields, got {:?}", packet.fields());
    };
    assert_eq!(token, b"token");
    assert_eq!(integrity_tag[..], hex("04a265ba2eff4d829058fb3f0f2496ba"));
    assert_eq!(packet.end(), datagram.len());
    assert!(packet.remainder().is_empty());
}

#[test]
fn empty_input() {
    assert_eq!(LongHeader::parse(&[]), Err(LongHeaderError::Empty));
    assert_eq!(ShortHeader::parse(&[], 0), Err(ShortHeaderError::Empty));
}

#[test]
fn wrong_header_form() {
    assert_eq!(
        LongHeader::parse(&[0x40, 0, 0]),
        Err(LongHeaderError::ShortForm)
    );
    assert_eq!(
        ShortHeader::parse(&[0xc0, 0, 0], 0),
        Err(ShortHeaderError::LongForm)
    );
}

#[test]
fn truncated_version_independent_fields() {
    let datagram = client_initial();
    // First byte, version (1..5), DCID length (5), DCID (6..14), SCID length (14).
    let required = [5, 5, 5, 5, 6, 14, 14, 14, 14, 14, 14, 14, 14, 15];
    for (end, required) in (1..15).zip(required) {
        assert_eq!(
            LongHeader::parse(&datagram[..end]),
            Err(LongHeaderError::Truncated {
                source: truncated(required, end)
            }),
            "input of {end} bytes"
        );
    }
    assert!(LongHeader::parse(&datagram[..15]).is_ok());
}

#[test]
fn truncated_initial_fields() {
    let datagram = client_initial();
    assert_eq!(
        v1_packet(&datagram[..15]),
        Err(LongPacketError::TokenLength {
            source: truncated(16, 15)
        })
    );
    assert_eq!(
        v1_packet(&datagram[..16]),
        Err(LongPacketError::Length {
            source: truncated(17, 16)
        })
    );
    // The Length field 0x449e takes two bytes.
    assert_eq!(
        v1_packet(&datagram[..17]),
        Err(LongPacketError::Length {
            source: truncated(18, 17)
        })
    );
    for end in [18, 19, 1199] {
        assert_eq!(
            v1_packet(&datagram[..end]),
            Err(LongPacketError::LengthOutOfBounds {
                length: VarInt::from(1182u16),
                available: end - 18
            }),
            "input of {end} bytes"
        );
    }
}

#[test]
fn initial_with_token() {
    let packet = long_packet(0xc1, &[7; 4], &[9; 3], Some(b"abc"), &[0xee; 21]);
    let parsed = v1_packet(&packet).unwrap();
    assert_eq!(parsed.scid().as_bytes(), [9; 3]);
    let TypeFields::Initial { token, bounds } = *parsed.fields() else {
        panic!("expected Initial fields, got {:?}", parsed.fields());
    };
    assert_eq!(token, b"abc");
    // 1 + 4 + 1 + 4 + 1 + 3 header bytes, 1 + 3 token bytes, 1 Length byte.
    assert_eq!(bounds.packet_number_offset(), 19);
    assert_eq!(bounds.end(), packet.len());

    // The token occupies bytes 15 to 17; the input ends within it.
    assert_eq!(
        v1_packet(&packet[..17]),
        Err(LongPacketError::Token {
            source: truncated(18, 17)
        })
    );
}

#[test]
fn zero_rtt_and_handshake() {
    for (first_byte, packet_type) in [
        (0xd0, LongPacketType::ZeroRtt),
        (0xe0, LongPacketType::Handshake),
    ] {
        let packet = long_packet(first_byte, &[1; 8], &[2; 8], None, &[0xee; 30]);
        let parsed = v1_packet(&packet).unwrap();
        assert_eq!(parsed.packet_type(), packet_type);
        let bounds = match *parsed.fields() {
            TypeFields::ZeroRtt { bounds } | TypeFields::Handshake { bounds } => bounds,
            fields => panic!("expected bounded fields, got {fields:?}"),
        };
        assert_eq!(bounds.packet_number_offset(), 1 + 4 + 1 + 8 + 1 + 8 + 1);
        assert_eq!(bounds.length(), VarInt::from(30u8));
        assert_eq!(parsed.end(), packet.len());
    }
}

#[test]
fn connection_id_lengths() {
    for dcid_len in [0, 1, 8, 20] {
        let packet = long_packet(0xe0, &vec![0xaa; dcid_len], &[0xbb; 20], None, &[0; 20]);
        let parsed = v1_packet(&packet).unwrap();
        assert_eq!(parsed.dcid().len(), dcid_len);
        assert_eq!(parsed.scid().len(), 20);
    }

    // Longer connection IDs are readable without a version, but not in version 1.
    for dcid_len in [21, 255] {
        let packet = long_packet(0xe0, &vec![0xaa; dcid_len], &[], None, &[0; 20]);
        let header = LongHeader::parse(&packet).unwrap();
        assert_eq!(header.dcid().len(), dcid_len);
        assert_eq!(
            LongPacket::try_from(header),
            Err(LongPacketError::DcidLength {
                source: ConnectionIdLengthError { length: dcid_len }
            })
        );
    }
    let packet = long_packet(0xe0, &[], &[0xbb; 21], None, &[0; 20]);
    assert_eq!(
        v1_packet(&packet),
        Err(LongPacketError::ScidLength {
            source: ConnectionIdLengthError { length: 21 }
        })
    );
}

#[test]
fn short_header_with_caller_supplied_lengths() {
    let datagram = [0x41, 1, 2, 3, 4, 5, 6, 7, 8, 0xee, 0xee, 0xee];
    for dcid_len in [0, 1, 8, 11] {
        let header = ShortHeader::parse(&datagram, dcid_len).unwrap();
        assert_eq!(header.first_byte(), 0x41);
        assert_eq!(header.dcid(), &datagram[1..1 + dcid_len]);
        assert_eq!(header.packet_number_offset(), 1 + dcid_len);
        assert_eq!(header.input(), datagram);
    }
    assert_eq!(
        ShortHeader::parse(&datagram, 12),
        Err(ShortHeaderError::Truncated {
            source: truncated(13, 12)
        })
    );
    assert_eq!(
        ShortHeader::parse(&datagram[..1], 20),
        Err(ShortHeaderError::Truncated {
            source: truncated(21, 1)
        })
    );
    assert_eq!(
        ShortHeader::parse(&datagram, usize::MAX),
        Err(ShortHeaderError::Truncated {
            source: truncated(usize::MAX, 12)
        })
    );
}

fn version_negotiation_packet(dcid: &[u8], scid: &[u8], versions: &[u8]) -> Vec<u8> {
    let mut packet = vec![0xaa, 0, 0, 0, 0, dcid.len() as u8];
    packet.extend_from_slice(dcid);
    packet.push(scid.len() as u8);
    packet.extend_from_slice(scid);
    packet.extend_from_slice(versions);
    packet
}

#[test]
fn version_negotiation() {
    let packet = version_negotiation_packet(
        &[1; 5],
        &RFC_DCID,
        &[0, 0, 0, 1, 0x6b, 0x33, 0x43, 0xcf, 0x1a, 0x2a, 0x3a, 0x4a],
    );
    let header = LongHeader::parse(&packet).unwrap();
    assert_eq!(header.version(), VersionNegotiation::VERSION);
    let negotiation = VersionNegotiation::try_from(header).unwrap();
    assert_eq!(negotiation.dcid(), [1; 5]);
    assert_eq!(negotiation.scid(), RFC_DCID);
    assert_eq!(negotiation.header(), &header);
    let versions = negotiation.supported_versions();
    assert_eq!(versions.len(), 3);
    assert_eq!(versions.collect::<Vec<_>>(), [1, 0x6b33_43cf, 0x1a2a_3a4a]);
    assert_eq!(
        negotiation.supported_versions().next_back(),
        Some(0x1a2a_3a4a)
    );
    // Version negotiation is not a version 1 packet.
    assert_eq!(
        LongPacket::try_from(header),
        Err(LongPacketError::Version { version: 0 })
    );
}

#[test]
fn version_negotiation_reads_long_connection_ids() {
    let packet = version_negotiation_packet(&[1; 255], &[2; 255], &[0, 0, 0, 1]);
    let negotiation = VersionNegotiation::try_from(LongHeader::parse(&packet).unwrap()).unwrap();
    assert_eq!(negotiation.dcid().len(), 255);
    assert_eq!(negotiation.scid().len(), 255);
    assert_eq!(negotiation.supported_versions().collect::<Vec<_>>(), [1]);
}

#[test]
fn version_negotiation_list_shapes() {
    let packet = version_negotiation_packet(&[], &[], &[]);
    let negotiation = VersionNegotiation::try_from(LongHeader::parse(&packet).unwrap()).unwrap();
    assert_eq!(negotiation.supported_versions().len(), 0);

    let packet = version_negotiation_packet(&[], &[], &[0, 0, 0, 1, 0, 0]);
    assert_eq!(
        VersionNegotiation::try_from(LongHeader::parse(&packet).unwrap()),
        Err(VersionNegotiationError::VersionList { length: 6 })
    );
}

#[test]
fn unsupported_version_keeps_version_independent_fields() {
    let mut packet = vec![0xc5, 0x6b, 0x33, 0x43, 0xcf, 30];
    packet.extend_from_slice(&[3; 30]);
    packet.push(0);
    packet.extend_from_slice(&[0xee; 40]);
    let header = LongHeader::parse(&packet).unwrap();
    assert_eq!(header.version(), 0x6b33_43cf);
    assert_eq!(header.dcid(), [3; 30]);
    assert_eq!(header.scid(), []);
    assert_eq!(header.version_specific(), [0xee; 40]);
    assert_eq!(
        LongPacket::try_from(header),
        Err(LongPacketError::Version {
            version: 0x6b33_43cf
        })
    );
    assert_eq!(
        VersionNegotiation::try_from(header),
        Err(VersionNegotiationError::Version {
            version: 0x6b33_43cf
        })
    );
}

#[test]
fn coalesced_packets() {
    let initial = client_initial();
    let handshake = long_packet(0xe2, &RFC_DCID, &[], None, &[0xee; 40]);
    let short = [
        0x43, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0xee, 0xee,
    ];
    let datagram = [&initial[..], &handshake, &short].concat();

    let first = v1_packet(&datagram).unwrap();
    assert_eq!(first.packet_type(), LongPacketType::Initial);
    assert_eq!(first.packet(), initial);
    assert_eq!(first.end(), 1200);

    let second = v1_packet(first.remainder()).unwrap();
    assert_eq!(second.packet_type(), LongPacketType::Handshake);
    assert_eq!(second.packet(), handshake);
    let TypeFields::Handshake { bounds } = *second.fields() else {
        panic!("expected Handshake fields, got {:?}", second.fields());
    };
    assert_eq!(bounds.length(), VarInt::from(40u8));
    assert_eq!(bounds.packet_number_offset(), handshake.len() - 40);
    assert_eq!(bounds.end(), handshake.len());

    let rest = second.remainder();
    assert_eq!(HeaderForm::of(rest[0]), HeaderForm::Short);
    let third = ShortHeader::parse(rest, RFC_DCID.len()).unwrap();
    assert_eq!(third.dcid(), RFC_DCID);
    assert_eq!(third.packet_number_offset(), 9);
}

#[test]
fn coalesced_packet_with_a_corrupt_length() {
    let initial = client_initial();
    let mut handshake = long_packet(0xe2, &RFC_DCID, &[], None, &[0xee; 40]);
    // Claim 41 bytes after the Length field, one more than the datagram holds.
    let length_offset = handshake.len() - 40 - 1;
    handshake[length_offset] = 41;
    let datagram = [&initial[..], &handshake].concat();

    let first = v1_packet(&datagram).unwrap();
    assert_eq!(
        v1_packet(first.remainder()),
        Err(LongPacketError::LengthOutOfBounds {
            length: VarInt::from(41u8),
            available: 40
        })
    );
}

#[test]
fn retry_lengths() {
    let header = [0xf0, 0, 0, 0, 1, 0, 2, 0xab, 0xcd];
    let packet = [&header[..], &[0x11; 16]].concat();
    let parsed = v1_packet(&packet).unwrap();
    let TypeFields::Retry {
        token,
        integrity_tag,
    } = *parsed.fields()
    else {
        panic!("expected Retry fields, got {:?}", parsed.fields());
    };
    assert_eq!(token, []);
    assert_eq!(integrity_tag, &[0x11; 16]);

    let packet = [&header[..], &[0x11; 15]].concat();
    assert_eq!(
        v1_packet(&packet),
        Err(LongPacketError::RetryIntegrityTag {
            source: truncated(header.len() + 16, packet.len())
        })
    );
}

#[test]
fn errors_describe_the_layer() {
    assert_eq!(
        LongHeaderError::from(truncated(14, 9)).to_string(),
        "header needs 14 bytes, but the input has 9"
    );
    assert_eq!(
        LongPacketError::LengthOutOfBounds {
            length: VarInt::from(1182u16),
            available: 1
        }
        .to_string(),
        "Length field 1182 exceeds the 1 bytes after it"
    );
    assert_eq!(
        VersionNegotiationError::Version { version: 1 }.to_string(),
        "version 0x00000001 is not version negotiation"
    );
}
