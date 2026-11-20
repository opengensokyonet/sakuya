use super::{
    HeaderForm, LongHeader, SAMPLE_DISTANCE,
    codec::{
        ReadLongHeaderError, ReadShortHeaderError, ReadVersionNegotiationError, read_long_header,
        read_short_header, read_version_negotiation,
    },
};
use crate::{connection_id::ConnectionIdLength, version::Version};

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

fn long_header(input: &mut &[u8]) -> LongHeader {
    read_long_header(input).unwrap()
}

#[test]
fn header_form_is_the_most_significant_bit() {
    assert_eq!(HeaderForm::of(0xc0), HeaderForm::Long);
    assert_eq!(HeaderForm::of(0x80), HeaderForm::Long);
    assert_eq!(HeaderForm::of(0x7f), HeaderForm::Short);
    assert_eq!(HeaderForm::of(0x00), HeaderForm::Short);
}

#[test]
fn empty_input() {
    let mut input = &[][..];
    let error = read_long_header(&mut input).unwrap_err();
    assert!(matches!(error, ReadLongHeaderError::FirstByte { .. }));
    assert!(error.is_incomplete());
    let error = read_short_header(&mut input, ConnectionIdLength::ZERO).unwrap_err();
    assert!(matches!(error, ReadShortHeaderError::FirstByte { .. }));
    assert!(error.is_incomplete());
}

#[test]
fn wrong_header_form() {
    let mut input = &[0x40, 0, 0][..];
    assert!(matches!(
        read_long_header(&mut input),
        Err(ReadLongHeaderError::ShortForm)
    ));
    let mut input = &[0xc0, 0, 0][..];
    assert!(matches!(
        read_short_header(&mut input, ConnectionIdLength::ZERO),
        Err(ReadShortHeaderError::LongForm)
    ));
}

#[test]
fn truncated_version_independent_fields() {
    let datagram = client_initial();
    // First byte (0), version (1..5), DCID length (5), DCID (6..14), SCID length (14).
    for end in 1..15 {
        let mut input = &datagram[..end];
        let error = read_long_header(&mut input).unwrap_err();
        assert!(error.is_incomplete(), "input of {end} bytes: {error:?}");
        let expected = match end {
            1..5 => matches!(error, ReadLongHeaderError::Version { .. }),
            5..14 => matches!(error, ReadLongHeaderError::Dcid { .. }),
            _ => matches!(error, ReadLongHeaderError::Scid { .. }),
        };
        assert!(expected, "input of {end} bytes: {error:?}");
    }
    let mut input = &datagram[..15];
    assert!(read_long_header(&mut input).is_ok());
}

#[test]
fn short_header_with_caller_supplied_lengths() {
    let datagram = [0x41, 1, 2, 3, 4, 5, 6, 7, 8, 0xee, 0xee, 0xee];
    for length in [0, 1, 8, 11] {
        let mut input = &datagram[..];
        let header = read_short_header(&mut input, dcid_len(length)).unwrap();
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
        let error = read_short_header(&mut input, dcid_len(length)).unwrap_err();
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
fn version_negotiation_reads_long_connection_ids() {
    let packet = version_negotiation_packet(&[1; 255], &[2; 255], &[0, 0, 0, 1]);
    let mut input = packet.as_slice();
    let header = long_header(&mut input);
    let negotiation = read_version_negotiation(&mut input, header).unwrap();
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
    let negotiation = read_version_negotiation(&mut input, header).unwrap();
    assert_eq!(negotiation.supported_versions().len(), 0);

    let packet = version_negotiation_packet(&[], &[], &[0, 0, 0, 1, 0, 0]);
    let mut input = packet.as_slice();
    let header = long_header(&mut input);
    assert!(matches!(
        read_version_negotiation(&mut input, header),
        Err(ReadVersionNegotiationError::VersionList { source }) if source.length() == 6
    ));
}

#[test]
fn written_version_negotiation_reads_back_as_the_same_fields() {
    use super::codec::write_version_negotiation;
    use crate::connection_id::RawConnectionId;

    let long = RawConnectionId::new(&[3; 255]).unwrap();
    let short = RawConnectionId::new(&RFC_DCID).unwrap();
    let versions = [
        Version::V1,
        Version::new(0x6b33_43cf),
        Version::new(0x1a2a_3a4a),
    ];
    for (unused, dcid, scid, versions) in [
        (0x40, long, short, &versions[..]),
        (0x7f, short, RawConnectionId::EMPTY, &versions[..1]),
        (0x00, RawConnectionId::EMPTY, long, &[][..]),
    ] {
        let mut packet = Vec::new();
        write_version_negotiation(&mut packet, unused, &dcid, &scid, versions);
        assert_eq!(packet[0], 0x80 | unused);
        assert_eq!(
            packet.len(),
            1 + 4 + 1 + dcid.len() + 1 + scid.len() + 4 * versions.len()
        );
        let mut input = packet.as_slice();
        let header = long_header(&mut input);
        assert_eq!(header.first_byte(), 0x80 | unused);
        assert_eq!(header.version(), Version::NEGOTIATION);
        let negotiation = read_version_negotiation(&mut input, header).unwrap();
        assert_eq!(negotiation.dcid(), &dcid);
        assert_eq!(negotiation.scid(), &scid);
        assert_eq!(
            negotiation.supported_versions().collect::<Vec<_>>(),
            versions
        );
        assert!(input.is_empty());
    }
}

#[test]
fn written_version_negotiation_keeps_the_header_form() {
    use super::codec::write_version_negotiation;
    use crate::connection_id::RawConnectionId;

    let mut packet = Vec::new();
    write_version_negotiation(
        &mut packet,
        0xff,
        &RawConnectionId::EMPTY,
        &RawConnectionId::EMPTY,
        &[Version::V1],
    );
    assert_eq!(packet, [0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
}
