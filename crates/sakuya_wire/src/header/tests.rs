use super::{
    HeaderForm, LongHeader, SAMPLE_DISTANCE,
    codec::{
        ReadLongHeaderError, ReadLongHeaderHostExt as _, ReadShortHeaderError,
        ReadShortHeaderHostExt as _, ReadVersionNegotiationError,
        ReadVersionNegotiationHostExt as _,
    },
    v1::{
        self, LongPacket, LongPacketType, TypeFields,
        codec::{ReadLongPacketError, ReadLongPacketHostExt as _},
    },
};
use crate::{
    connection_id::{ConnectionId, ConnectionIdLength},
    packet_number::PacketNumberLength,
    payload::ReadPayloadError,
    var_int::{VarInt, codec::WriteVarIntHostExt as _},
    version::Version,
};
use bytes::Bytes;

const PN_LENGTHS: [PacketNumberLength; 4] = [
    PacketNumberLength::One,
    PacketNumberLength::Two,
    PacketNumberLength::Three,
    PacketNumberLength::Four,
];

fn dcid_len(length: usize) -> ConnectionIdLength {
    ConnectionIdLength::new(length).unwrap()
}

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
        packet
            .sync_write_var_int_unpin(VarInt::try_from(token.len()).unwrap())
            .unwrap();
        packet.extend_from_slice(token);
    }
    packet
        .sync_write_var_int_unpin(VarInt::try_from(rest.len()).unwrap())
        .unwrap();
    packet.extend_from_slice(rest);
    packet
}

fn long_header(input: &mut &[u8]) -> LongHeader {
    input.sync_read_long_header_unpin().unwrap()
}

/// Reads a version 1 long packet from the start of `input`, advancing it.
fn v1_packet<'a>(
    input: &mut &'a [u8],
) -> Result<LongPacket<&'a [u8]>, ReadLongPacketError<core::convert::Infallible>> {
    let header = long_header(input);
    input.sync_read_long_packet_unpin(header)
}

fn v1_of(
    packet: &[u8],
) -> Result<LongPacket<&[u8]>, ReadLongPacketError<core::convert::Infallible>> {
    let mut input = packet;
    v1_packet(&mut input)
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
    let mut input = datagram.as_slice();
    let header = long_header(&mut input);
    assert_eq!(header.first_byte(), 0xc0);
    assert_eq!(header.version(), v1::VERSION);
    assert_eq!(header.dcid().as_bytes(), RFC_DCID);
    assert!(header.scid().is_empty());
    assert_eq!(header.version_specific_offset(), 15);
    assert_eq!(input.len(), datagram.len() - 15);

    let packet = input.sync_read_long_packet_unpin(header).unwrap();
    assert_eq!(packet.packet_type(), LongPacketType::Initial);
    assert_eq!(packet.dcid(), &ConnectionId::new(&RFC_DCID).unwrap());
    assert_eq!(packet.scid(), &ConnectionId::EMPTY);
    assert!(packet.fixed_bit());
    let TypeFields::Initial {
        token,
        bounds,
        protected,
    } = *packet.fields()
    else {
        panic!("expected Initial fields, got {:?}", packet.fields());
    };
    assert!(token.is_empty());
    assert_eq!(bounds.length(), VarInt::from(1182u16));
    assert_eq!(bounds.packet_number_offset(), 18);
    assert_eq!(bounds.sample_offset(), 18 + SAMPLE_DISTANCE);
    assert_eq!(bounds.end(), 1200);
    assert_eq!(packet.end(), 1200);
    assert_eq!(protected, &datagram[18..]);
    assert!(input.is_empty());
}

#[test]
fn rfc_client_initial_from_bytes_shares_storage() {
    let datagram = Bytes::from(client_initial());
    let mut input = datagram.clone();
    let header = input.sync_read_long_header_unpin().unwrap();
    let packet = input.sync_read_long_packet_unpin(header).unwrap();
    let TypeFields::Initial { protected, .. } = packet.into_fields() else {
        panic!("expected Initial fields");
    };
    assert_eq!(protected, datagram.slice(18..));
    assert_eq!(protected.as_ptr(), datagram[18..].as_ptr());
}

#[test]
fn rfc_retry() {
    let datagram = hex(RETRY);
    let mut input = datagram.as_slice();
    let header = long_header(&mut input);
    assert_eq!(header.version(), v1::VERSION);
    assert!(header.dcid().is_empty());
    assert_eq!(header.scid().as_bytes(), hex("f067a5502a4262b5"));

    let packet = input.sync_read_long_packet_unpin(header).unwrap();
    assert_eq!(packet.packet_type(), LongPacketType::Retry);
    assert_eq!(packet.dcid(), &ConnectionId::EMPTY);
    assert_eq!(packet.scid().as_bytes(), hex("f067a5502a4262b5"));
    let TypeFields::Retry {
        token,
        integrity_tag,
        end,
    } = packet.fields()
    else {
        panic!("expected Retry fields, got {:?}", packet.fields());
    };
    assert_eq!(token, &b"token"[..]);
    assert_eq!(integrity_tag[..], hex("04a265ba2eff4d829058fb3f0f2496ba"));
    assert_eq!(*end, datagram.len());
    assert_eq!(packet.end(), datagram.len());
    assert!(input.is_empty());
}

#[test]
fn empty_input() {
    let mut input = &[][..];
    let error = input.sync_read_long_header_unpin().unwrap_err();
    assert!(matches!(error, ReadLongHeaderError::FirstByte { .. }));
    assert!(error.is_incomplete());
    let error = input
        .sync_read_short_header_unpin(ConnectionIdLength::ZERO)
        .unwrap_err();
    assert!(matches!(error, ReadShortHeaderError::FirstByte { .. }));
    assert!(error.is_incomplete());
}

#[test]
fn wrong_header_form() {
    let mut input = &[0x40, 0, 0][..];
    assert!(matches!(
        input.sync_read_long_header_unpin(),
        Err(ReadLongHeaderError::ShortForm)
    ));
    let mut input = &[0xc0, 0, 0][..];
    assert!(matches!(
        input.sync_read_short_header_unpin(ConnectionIdLength::ZERO),
        Err(ReadShortHeaderError::LongForm)
    ));
}

#[test]
fn truncated_version_independent_fields() {
    let datagram = client_initial();
    // First byte (0), version (1..5), DCID length (5), DCID (6..14), SCID length (14).
    for end in 1..15 {
        let mut input = &datagram[..end];
        let error = input.sync_read_long_header_unpin().unwrap_err();
        assert!(error.is_incomplete(), "input of {end} bytes: {error:?}");
        let expected = match end {
            1..5 => matches!(error, ReadLongHeaderError::Version { .. }),
            5..14 => matches!(error, ReadLongHeaderError::Dcid { .. }),
            _ => matches!(error, ReadLongHeaderError::Scid { .. }),
        };
        assert!(expected, "input of {end} bytes: {error:?}");
    }
    let mut input = &datagram[..15];
    assert!(input.sync_read_long_header_unpin().is_ok());
}

#[test]
fn truncated_initial_fields() {
    let datagram = client_initial();
    let error = v1_of(&datagram[..15]).unwrap_err();
    assert!(matches!(error, ReadLongPacketError::TokenLength { .. }));
    assert!(error.is_incomplete());
    let error = v1_of(&datagram[..16]).unwrap_err();
    assert!(matches!(error, ReadLongPacketError::Length { .. }));
    // The Length field 0x449e takes two bytes.
    let error = v1_of(&datagram[..17]).unwrap_err();
    assert!(matches!(error, ReadLongPacketError::Length { .. }));
    for end in [18, 19, 1199] {
        let error = v1_of(&datagram[..end]).unwrap_err();
        let ReadLongPacketError::Protected {
            length,
            source: ReadPayloadError::Incomplete { source },
        } = &error
        else {
            panic!("input of {end} bytes: {error:?}");
        };
        assert_eq!(*length, VarInt::from(1182u16));
        assert_eq!((source.expected(), source.completed()), (1182, end - 18));
    }
}

#[test]
fn initial_with_token() {
    let packet = long_packet(0xc1, &[7; 4], &[9; 3], Some(b"abc"), &[0xee; 21]);
    let parsed = v1_of(&packet).unwrap();
    assert_eq!(parsed.scid().as_bytes(), [9; 3]);
    let TypeFields::Initial { token, bounds, .. } = *parsed.fields() else {
        panic!("expected Initial fields, got {:?}", parsed.fields());
    };
    assert_eq!(token, b"abc");
    // 1 + 4 + 1 + 4 + 1 + 3 header bytes, 1 + 3 token bytes, 1 Length byte.
    assert_eq!(bounds.packet_number_offset(), 19);
    assert_eq!(bounds.end(), packet.len());

    // The token occupies bytes 15 to 17; the input ends within it.
    let error = v1_of(&packet[..17]).unwrap_err();
    let ReadLongPacketError::Token {
        source: ReadPayloadError::Incomplete { source },
    } = &error
    else {
        panic!("{error:?}");
    };
    assert_eq!((source.expected(), source.completed()), (3, 2));
}

#[test]
fn zero_rtt_and_handshake() {
    for (first_byte, packet_type) in [
        (0xd0, LongPacketType::ZeroRtt),
        (0xe0, LongPacketType::Handshake),
    ] {
        let packet = long_packet(first_byte, &[1; 8], &[2; 8], None, &[0xee; 30]);
        let parsed = v1_of(&packet).unwrap();
        assert_eq!(parsed.packet_type(), packet_type);
        let (bounds, protected) = match *parsed.fields() {
            TypeFields::ZeroRtt { bounds, protected }
            | TypeFields::Handshake { bounds, protected } => (bounds, protected),
            ref fields => panic!("expected bounded fields, got {fields:?}"),
        };
        assert_eq!(bounds.packet_number_offset(), 1 + 4 + 1 + 8 + 1 + 8 + 1);
        assert_eq!(bounds.length(), VarInt::from(30u8));
        assert_eq!(protected, [0xee; 30]);
        assert_eq!(parsed.end(), packet.len());
    }
}

#[test]
fn connection_id_lengths() {
    for dcid_len in [0, 1, 8, 20] {
        let packet = long_packet(0xe0, &vec![0xaa; dcid_len], &[0xbb; 20], None, &[0; 20]);
        let parsed = v1_of(&packet).unwrap();
        assert_eq!(parsed.dcid().len(), dcid_len);
        assert_eq!(parsed.scid().len(), 20);
    }

    // Longer connection IDs are readable without a version, but not in version 1.
    for dcid_len in [21, 255] {
        let packet = long_packet(0xe0, &vec![0xaa; dcid_len], &[], None, &[0; 20]);
        let mut input = packet.as_slice();
        let header = long_header(&mut input);
        assert_eq!(header.dcid().len(), dcid_len);
        assert!(matches!(
            input.sync_read_long_packet_unpin(header),
            Err(ReadLongPacketError::DcidLength { source }) if source.length() == dcid_len
        ));
    }
    let packet = long_packet(0xe0, &[], &[0xbb; 21], None, &[0; 20]);
    assert!(matches!(
        v1_of(&packet),
        Err(ReadLongPacketError::ScidLength { source }) if source.length() == 21
    ));
}

#[test]
fn short_header_with_caller_supplied_lengths() {
    let datagram = [0x41, 1, 2, 3, 4, 5, 6, 7, 8, 0xee, 0xee, 0xee];
    for length in [0, 1, 8, 11] {
        let mut input = &datagram[..];
        let header = input
            .sync_read_short_header_unpin(dcid_len(length))
            .unwrap();
        let dcid_len = length;
        assert_eq!(header.first_byte(), 0x41);
        assert_eq!(header.dcid().as_bytes(), &datagram[1..1 + dcid_len]);
        assert_eq!(header.packet_number_offset(), 1 + dcid_len);
        assert_eq!(header.sample_offset(), 1 + dcid_len + SAMPLE_DISTANCE);
        assert_eq!(*header.protected(), &datagram[1 + dcid_len..]);
        assert_eq!(header.end(), datagram.len());
        assert!(input.is_empty());
    }
    for (input, length) in [(&datagram[..], 12), (&datagram[..1], 20)] {
        let mut input = input;
        let error = input
            .sync_read_short_header_unpin(dcid_len(length))
            .unwrap_err();
        assert!(
            matches!(error, ReadShortHeaderError::Dcid { .. }),
            "{error:?}"
        );
        assert!(error.is_incomplete());
    }
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
    let mut input = packet.as_slice();
    let header = long_header(&mut input);
    assert_eq!(header.version(), Version::NEGOTIATION);
    let negotiation = input.sync_read_version_negotiation_unpin(header).unwrap();
    assert_eq!(negotiation.dcid().as_bytes(), [1; 5]);
    assert_eq!(negotiation.scid().as_bytes(), RFC_DCID);
    assert_eq!(negotiation.header(), &header);
    let versions = negotiation.supported_versions();
    assert_eq!(versions.len(), 3);
    assert_eq!(
        versions.collect::<Vec<_>>(),
        [1, 0x6b33_43cf, 0x1a2a_3a4a].map(Version::new)
    );
    assert!(Version::new(0x1a2a_3a4a).is_reserved());
    // Version negotiation is not a version 1 packet.
    let mut input = packet.as_slice();
    let header = long_header(&mut input);
    assert!(matches!(
        input.sync_read_long_packet_unpin(header),
        Err(ReadLongPacketError::Version { source }) if source.version() == Version::NEGOTIATION
    ));
}

#[test]
fn version_negotiation_reads_long_connection_ids() {
    let packet = version_negotiation_packet(&[1; 255], &[2; 255], &[0, 0, 0, 1]);
    let mut input = packet.as_slice();
    let header = long_header(&mut input);
    let negotiation = input.sync_read_version_negotiation_unpin(header).unwrap();
    assert_eq!(negotiation.dcid().len(), 255);
    assert_eq!(negotiation.scid().len(), 255);
    assert_eq!(
        negotiation.supported_versions().collect::<Vec<_>>(),
        [Version::V1]
    );
}

#[test]
fn version_negotiation_list_shapes() {
    let packet = version_negotiation_packet(&[], &[], &[]);
    let mut input = packet.as_slice();
    let header = long_header(&mut input);
    let negotiation = input.sync_read_version_negotiation_unpin(header).unwrap();
    assert_eq!(negotiation.supported_versions().len(), 0);

    let packet = version_negotiation_packet(&[], &[], &[0, 0, 0, 1, 0, 0]);
    let mut input = packet.as_slice();
    let header = long_header(&mut input);
    assert!(matches!(
        input.sync_read_version_negotiation_unpin(header),
        Err(ReadVersionNegotiationError::VersionList { source }) if source.length() == 6
    ));
}

#[test]
fn unsupported_version_keeps_version_independent_fields() {
    let mut packet = vec![0xc5, 0x6b, 0x33, 0x43, 0xcf, 30];
    packet.extend_from_slice(&[3; 30]);
    packet.push(0);
    packet.extend_from_slice(&[0xee; 40]);
    let mut input = packet.as_slice();
    let header = long_header(&mut input);
    assert_eq!(header.version(), Version::new(0x6b33_43cf));
    assert_eq!(header.dcid().as_bytes(), [3; 30]);
    assert!(header.scid().is_empty());
    assert_eq!(input, [0xee; 40]);
    let Err(ReadLongPacketError::Version { source }) = input.sync_read_long_packet_unpin(header)
    else {
        panic!()
    };
    assert_eq!(source.version(), Version::new(0x6b33_43cf));
    assert_eq!(
        source.to_string(),
        "version 0x6b3343cf is not QUIC version 1"
    );
    let Err(ReadVersionNegotiationError::Version { source }) =
        input.sync_read_version_negotiation_unpin(header)
    else {
        panic!()
    };
    assert_eq!(source.version(), Version::new(0x6b33_43cf));
    assert_eq!(
        source.to_string(),
        "version 0x6b3343cf is not version negotiation"
    );
    // Neither failure read anything.
    assert_eq!(input, [0xee; 40]);
}

#[test]
fn version_errors_hold_only_other_versions() {
    // A Retry packet with empty connection IDs and an integrity tag, so that
    // version 1 reads it.
    let packet_of = |version: Version| {
        let mut packet = vec![0xf0];
        packet.extend_from_slice(&version.to_be_bytes());
        packet.extend_from_slice(&[0, 0]);
        packet.extend_from_slice(&[0xee; 16]);
        packet
    };
    for value in [1, 2, 0x6b33_43cf, u32::MAX] {
        let version = Version::new(value);
        let packet = packet_of(version);
        let mut input = packet.as_slice();
        let header = long_header(&mut input);
        let Err(ReadVersionNegotiationError::Version { source }) =
            input.sync_read_version_negotiation_unpin(header)
        else {
            panic!("{version}")
        };
        assert_eq!(source.version(), version);
    }
    for value in [0, 2, 0x6b33_43cf, u32::MAX] {
        let version = Version::new(value);
        let packet = packet_of(version);
        let mut input = packet.as_slice();
        let header = long_header(&mut input);
        let Err(ReadLongPacketError::Version { source }) =
            input.sync_read_long_packet_unpin(header)
        else {
            panic!("{version}")
        };
        assert_eq!(source.version(), version);
    }
    // The versions the checks accept read.
    let packet = packet_of(Version::NEGOTIATION);
    let mut input = packet.as_slice();
    let header = long_header(&mut input);
    assert!(input.sync_read_version_negotiation_unpin(header).is_ok());
    let packet = packet_of(Version::V1);
    let mut input = packet.as_slice();
    let header = long_header(&mut input);
    assert!(input.sync_read_long_packet_unpin(header).is_ok());
}

#[test]
fn coalesced_packets() {
    let initial = client_initial();
    let handshake = long_packet(0xe2, &RFC_DCID, &[], None, &[0xee; 40]);
    let short = [
        0x43, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0xee, 0xee,
    ];
    let datagram = [&initial[..], &handshake, &short].concat();
    let mut input = datagram.as_slice();

    let first = v1_packet(&mut input).unwrap();
    assert_eq!(first.packet_type(), LongPacketType::Initial);
    assert_eq!(first.end(), 1200);
    assert_eq!(input.len(), datagram.len() - 1200);

    let second = v1_packet(&mut input).unwrap();
    assert_eq!(second.packet_type(), LongPacketType::Handshake);
    assert_eq!(second.end(), handshake.len());
    let TypeFields::Handshake { bounds, .. } = *second.fields() else {
        panic!("expected Handshake fields, got {:?}", second.fields());
    };
    assert_eq!(bounds.length(), VarInt::from(40u8));
    assert_eq!(bounds.packet_number_offset(), handshake.len() - 40);
    assert_eq!(bounds.end(), handshake.len());

    assert_eq!(HeaderForm::of(input[0]), HeaderForm::Short);
    let third = input
        .sync_read_short_header_unpin(dcid_len(RFC_DCID.len()))
        .unwrap();
    assert_eq!(third.dcid().as_bytes(), RFC_DCID);
    assert_eq!(third.packet_number_offset(), 9);
    assert_eq!(third.end(), short.len());
}

#[test]
fn coalesced_packet_with_a_corrupt_length() {
    let initial = client_initial();
    let mut handshake = long_packet(0xe2, &RFC_DCID, &[], None, &[0xee; 40]);
    // Claim 41 bytes after the Length field, one more than the datagram holds.
    let length_offset = handshake.len() - 40 - 1;
    handshake[length_offset] = 41;
    let datagram = [&initial[..], &handshake].concat();
    let mut input = datagram.as_slice();

    v1_packet(&mut input).unwrap();
    let error = v1_packet(&mut input).unwrap_err();
    let ReadLongPacketError::Protected {
        length,
        source: ReadPayloadError::Incomplete { source },
    } = &error
    else {
        panic!("{error:?}");
    };
    assert_eq!(*length, VarInt::from(41u8));
    assert_eq!((source.expected(), source.completed()), (41, 40));
}

#[test]
fn retry_lengths() {
    let header = [0xf0, 0, 0, 0, 1, 0, 2, 0xab, 0xcd];
    let packet = [&header[..], &[0x11; 16]].concat();
    let parsed = v1_of(&packet).unwrap();
    let TypeFields::Retry {
        token,
        integrity_tag,
        ..
    } = parsed.fields()
    else {
        panic!("expected Retry fields, got {:?}", parsed.fields());
    };
    assert!(token.is_empty());
    assert_eq!(integrity_tag, &[0x11; 16]);

    let packet = [&header[..], &[0x11; 15]].concat();
    assert!(matches!(
        v1_of(&packet),
        Err(ReadLongPacketError::RetryIntegrityTag { source }) if source.length() == 15
    ));
}

#[test]
fn errors_describe_the_layer() {
    let mut input = &[0xc0, 0, 0][..];
    assert_eq!(
        input.sync_read_long_header_unpin().unwrap_err().to_string(),
        "version read failed"
    );
    let datagram = client_initial();
    assert_eq!(
        v1_of(&datagram[..19]).unwrap_err().to_string(),
        "the Length field range of 1182 bytes read failed"
    );
    let mut input = &[0xaa, 0, 0, 0, 1, 0, 0][..];
    let header = long_header(&mut input);
    assert_eq!(
        input
            .sync_read_version_negotiation_unpin(header)
            .unwrap_err()
            .to_string(),
        "version 0x00000001 is not version negotiation"
    );
}

/// Writes `header` with its reserved Length, appends `body` bytes for the
/// packet number and payload, and writes the final Length over the reserved
/// field at the width the header chose.
fn written_long_packet(header: &v1::LongPacketHeader, body: &[u8]) -> Vec<u8> {
    use crate::var_int::{VarIntField, codec::WriteVarIntFieldHostExt as _};
    use v1::codec::WriteLongPacketHeaderHostExt as _;

    let mut packet = Vec::new();
    packet
        .sync_write_long_packet_header_unpin(header.clone())
        .unwrap();
    assert_eq!(packet.len(), header.packet_number_offset());
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

fn reserved(width: crate::var_int::VarIntWidth) -> crate::var_int::VarIntField<VarInt> {
    crate::var_int::VarIntField::new(VarInt::ZERO, width).unwrap()
}

#[test]
fn rfc_client_initial_header_is_written_as_in_the_appendix() {
    use crate::var_int::{VarIntField, VarIntWidth};

    // RFC 9001 Appendix A.2: the header before header protection, with the
    // four-byte packet number 2 (low bits 0b0011).
    let header = v1::LongPacketHeader::initial(
        ConnectionId::new(&RFC_DCID).unwrap(),
        ConnectionId::EMPTY,
        VarIntWidth::One,
        Bytes::new(),
        PacketNumberLength::Four,
        VarIntField::new(VarInt::from(1182u32), VarIntWidth::Two).unwrap(),
    )
    .unwrap();
    assert_eq!(header.first_byte(), 0xc3);
    assert_eq!(header.length_offset(), 16);
    assert_eq!(header.packet_number_offset(), 18);
    let mut written = Vec::new();
    {
        use v1::codec::WriteLongPacketHeaderHostExt as _;
        written.sync_write_long_packet_header_unpin(header).unwrap();
    }
    assert_eq!(written, hex("c300000001088394c8f03e5157080000449e"));
    // The protected packet starts with the same bytes but the first.
    assert_eq!(written[1..], client_initial()[1..written.len()]);
}

#[test]
fn written_long_headers_read_back_as_the_same_fields() {
    use crate::var_int::VarIntWidth;

    let dcid = ConnectionId::new(&[1, 2, 3]).unwrap();
    let scid = ConnectionId::new(&[9; 20]).unwrap();
    for width in VarIntWidth::ALL {
        for pn_length in PN_LENGTHS {
            let body = [0x5a; 40];
            let token = Bytes::from_static(b"token");
            let initial = v1::LongPacketHeader::initial(
                dcid,
                scid,
                width,
                token.clone(),
                pn_length,
                reserved(width),
            )
            .unwrap();
            assert_eq!(initial.pn_length(), pn_length);
            // The reserved bits are zero.
            assert_eq!(initial.first_byte() & 0x0f, pn_length.first_byte_bits());
            let packet = written_long_packet(&initial, &body);
            let read = v1_of(&packet).unwrap();
            assert_eq!(read.packet_type(), LongPacketType::Initial);
            assert_eq!(read.header().first_byte(), initial.first_byte());
            assert_eq!((read.dcid(), read.scid()), (&dcid, &scid));
            let TypeFields::Initial {
                token: read_token,
                bounds,
                protected,
            } = read.fields()
            else {
                panic!("not an Initial packet")
            };
            assert_eq!(*read_token, &token[..]);
            assert_eq!(
                bounds.packet_number_offset(),
                initial.packet_number_offset()
            );
            assert_eq!(bounds.end(), packet.len());
            assert_eq!(bounds.length(), VarInt::from(40u8));
            assert_eq!(*protected, &body[..]);
            assert_eq!(initial.token(), Some(&token));
            assert_eq!(initial.token_length_width(), Some(width));

            let zero_rtt = v1::LongPacketHeader::zero_rtt(dcid, scid, pn_length, reserved(width));
            let handshake = v1::LongPacketHeader::handshake(dcid, scid, pn_length, reserved(width));
            for (header, packet_type) in [
                (zero_rtt, LongPacketType::ZeroRtt),
                (handshake, LongPacketType::Handshake),
            ] {
                let packet = written_long_packet(&header, &body);
                let read = v1_of(&packet).unwrap();
                assert_eq!(read.packet_type(), packet_type);
                assert_eq!(header.packet_type(), packet_type);
                assert_eq!(read.header().first_byte(), header.first_byte());
                assert_eq!(header.pn_length(), pn_length);
                assert_eq!(
                    read.header().first_byte() & 0x0f,
                    pn_length.first_byte_bits()
                );
                let (TypeFields::ZeroRtt { bounds, protected }
                | TypeFields::Handshake { bounds, protected }) = read.fields()
                else {
                    panic!("not a 0-RTT or Handshake packet")
                };
                assert_eq!(bounds.packet_number_offset(), header.packet_number_offset());
                assert_eq!(bounds.end(), packet.len());
                assert_eq!(*protected, &body[..]);
                assert_eq!(header.token(), None);
                assert_eq!(header.token_length_width(), None);
            }
        }
    }
}

#[test]
fn written_long_headers_keep_the_width_of_the_token_length() {
    use crate::var_int::VarIntWidth;

    let header = v1::LongPacketHeader::initial(
        ConnectionId::EMPTY,
        ConnectionId::EMPTY,
        VarIntWidth::Four,
        Bytes::new(),
        PacketNumberLength::One,
        reserved(VarIntWidth::Eight),
    )
    .unwrap();
    // First byte, version, two length bytes, a four-byte Token Length and an
    // eight-byte Length.
    assert_eq!(header.length_offset(), 1 + 4 + 1 + 1 + 4);
    assert_eq!(header.packet_number_offset(), 11 + 8);
    let packet = written_long_packet(&header, &[1, 2]);
    assert_eq!(
        packet,
        [
            &[0xc0, 0, 0, 0, 1, 0, 0][..],
            &[0x80, 0, 0, 0],
            &[0xc0, 0, 0, 0, 0, 0, 0, 2],
            &[1, 2],
        ]
        .concat()
    );
}

#[test]
fn an_initial_header_checks_the_width_of_the_token_length() {
    use crate::{frame::LengthError, var_int::VarIntWidth};

    let cid = ConnectionId::EMPTY;
    let initial = |width, token: &[u8]| {
        v1::LongPacketHeader::initial(
            cid,
            cid,
            width,
            Bytes::copy_from_slice(token),
            PacketNumberLength::One,
            reserved(VarIntWidth::One),
        )
    };
    let long_token = [0; 64];
    assert_eq!(
        initial(VarIntWidth::One, &long_token),
        Err(LengthError::check(64, VarIntWidth::One).unwrap_err())
    );
    assert!(initial(VarIntWidth::One, &long_token[..63]).is_ok());
    assert!(initial(VarIntWidth::Two, &long_token).is_ok());
}

#[test]
fn written_short_headers_read_back_as_the_same_fields() {
    use super::codec::WriteShortPacketHeaderHostExt as _;
    use super::{KeyPhase, ShortPacketHeader};

    let dcid = ConnectionId::new(&[7; 8]).unwrap();
    for spin in [false, true] {
        for (key_phase, key_phase_bit) in [(KeyPhase::Zero, 0), (KeyPhase::One, 0x04)] {
            for pn_length in PN_LENGTHS {
                let header = ShortPacketHeader::new(spin, key_phase, pn_length, dcid);
                // The form bit is clear, the Fixed Bit is set and the reserved
                // bits (0x18) are zero.
                assert_eq!(
                    header.first_byte(),
                    0x40 | (u8::from(spin) << 5) | key_phase_bit | pn_length.first_byte_bits()
                );
                assert_eq!(header.first_byte() & 0x18, 0);
                assert_eq!(
                    (header.spin(), header.key_phase(), header.pn_length()),
                    (spin, key_phase, pn_length)
                );
                assert_eq!(header.dcid(), &dcid);
                assert_eq!(header.packet_number_offset(), 9);
                let mut packet = Vec::new();
                packet.sync_write_short_packet_header_unpin(header).unwrap();
                assert_eq!(packet.len(), header.packet_number_offset());
                packet.extend_from_slice(&[0x33; 30]);
                let mut input = packet.as_slice();
                let read = input.sync_read_short_header_unpin(dcid_len(8)).unwrap();
                assert_eq!(read.first_byte(), header.first_byte());
                assert_eq!(read.dcid().as_bytes(), dcid.as_bytes());
                assert_eq!(read.packet_number_offset(), header.packet_number_offset());
                assert_eq!(*read.protected(), &[0x33; 30][..]);
            }
        }
    }
}

#[test]
fn write_failures_report_the_receiver() {
    use super::codec::WriteShortPacketHeaderHostExt as _;
    use super::{KeyPhase, ShortPacketHeader};
    use nitori_io::calls::WriteAllError;

    let header = ShortPacketHeader::new(
        false,
        KeyPhase::Zero,
        PacketNumberLength::One,
        ConnectionId::new(&[1, 2, 3]).unwrap(),
    );
    let mut room = [0; 2];
    let mut sink = &mut room[..];
    let error = sink
        .sync_write_short_packet_header_unpin(header)
        .unwrap_err();
    assert!(matches!(error, WriteAllError::WriteZero { .. }));
    assert_eq!(error.completed(), 2);
}
