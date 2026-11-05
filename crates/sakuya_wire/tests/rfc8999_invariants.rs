//! The version-independent properties of QUIC (RFC 8999), through the public
//! interface.
use sakuya_wire::{
    connection_id::ConnectionIdLength,
    header::{
        HeaderForm,
        codec::{
            ReadLongHeaderError, ReadLongHeaderHostExt as _, ReadShortHeaderError,
            ReadShortHeaderHostExt as _, ReadVersionNegotiationHostExt as _,
        },
        v1::{
            self,
            codec::{ReadLongPacketError, ReadLongPacketHostExt as _},
        },
    },
    version::Version,
};

fn long(first: u8, version: u32, dcid: &[u8], scid: &[u8], rest: &[u8]) -> Vec<u8> {
    let mut bytes = vec![first];
    bytes.extend(version.to_be_bytes());
    bytes.push(dcid.len() as u8);
    bytes.extend(dcid);
    bytes.push(scid.len() as u8);
    bytes.extend(scid);
    bytes.extend(rest);
    bytes
}

/// RFC 8999 §5.1: the most significant bit of the first byte alone tells the
/// header form.
#[test]
fn the_top_bit_alone_tells_the_form() {
    for byte in 0..=255u8 {
        let expected = if byte >= 0x80 {
            HeaderForm::Long
        } else {
            HeaderForm::Short
        };
        assert_eq!(HeaderForm::of(byte), expected);
    }
}

/// RFC 8999 §5.1: the other seven bits and everything after the Source
/// Connection ID belong to the version.
#[test]
fn long_header_fields_do_not_depend_on_the_version_specific_bits() {
    for first in 0x80..=0xffu8 {
        for version in [0x6b33_43cf, 0x0a0a_0a0a, 0xffff_ffff, 2] {
            let bytes = long(first, version, &[1, 2, 3], &[4], &[0xee, 0xef]);
            let mut input = bytes.as_slice();
            let header = input.sync_read_long_header_unpin().unwrap();
            assert_eq!(header.first_byte(), first);
            assert_eq!(header.version(), Version::new(version));
            assert_eq!(header.dcid().as_bytes(), [1, 2, 3]);
            assert_eq!(header.scid().as_bytes(), [4]);
            assert_eq!(header.version_specific_offset(), 11);
            assert_eq!(input, [0xee, 0xef]);
        }
    }
}

/// RFC 8999 §5.1: connection IDs of a long header take 0 to 255 bytes.
#[test]
fn long_header_connection_ids_take_any_length_a_byte_states() {
    for dcid_len in [0, 1, 20, 21, 254, 255] {
        for scid_len in [0, 21, 255] {
            let dcid = vec![0xd0; dcid_len];
            let scid = vec![0x50; scid_len];
            let bytes = long(0xc0, 0x6b33_43cf, &dcid, &scid, &[]);
            let mut input = bytes.as_slice();
            let header = input.sync_read_long_header_unpin().unwrap();
            assert_eq!(header.dcid().as_bytes(), dcid);
            assert_eq!(header.scid().as_bytes(), scid);
            assert!(input.is_empty());
            // Version 1 restricts them; only its layer refuses them.
            if dcid_len > 20 || scid_len > 20 {
                let bytes = long(0xc0, 1, &dcid, &scid, &[]);
                let mut input = bytes.as_slice();
                let header = input.sync_read_long_header_unpin().unwrap();
                assert!(matches!(
                    input.sync_read_long_packet_unpin(header),
                    Err(ReadLongPacketError::DcidLength { .. }
                        | ReadLongPacketError::ScidLength { .. })
                ));
            }
        }
    }
}

/// RFC 8999 §5.2: a short header states no length, and its other seven bits
/// belong to the version.
#[test]
fn short_headers_read_with_the_length_the_caller_knows() {
    for first in 0x00..=0x7fu8 {
        let bytes = [first, 1, 2, 3, 4, 5];
        for length in 0..=5 {
            let mut input = bytes.as_slice();
            let header = input
                .sync_read_short_header_unpin(ConnectionIdLength::new(length).unwrap())
                .unwrap();
            assert_eq!(header.first_byte(), first);
            assert_eq!(header.dcid().len(), length);
            assert_eq!(header.packet_number_offset(), 1 + length);
            assert_eq!(header.end(), bytes.len());
        }
        let mut input = bytes.as_slice();
        let error = input
            .sync_read_short_header_unpin(ConnectionIdLength::new(6).unwrap())
            .unwrap_err();
        assert!(error.is_incomplete());
    }
    let mut input = &[0x80, 0, 0][..];
    assert!(matches!(
        input.sync_read_short_header_unpin(ConnectionIdLength::ZERO),
        Err(ReadShortHeaderError::LongForm)
    ));
}

/// RFC 8999 §6: version zero makes a Version Negotiation packet whatever the
/// other bits of the first byte hold.
#[test]
fn version_negotiation_does_not_depend_on_the_first_byte() {
    let list = [0, 0, 0, 1, 0xfa, 0xfa, 0xfa, 0xfa];
    for first in 0x80..=0xffu8 {
        let bytes = long(first, 0, &[1; 255], &[2; 255], &list);
        let mut input = bytes.as_slice();
        let header = input.sync_read_long_header_unpin().unwrap();
        assert_eq!(header.version(), Version::NEGOTIATION);
        let packet = input.sync_read_version_negotiation_unpin(header).unwrap();
        let versions: Vec<_> = packet.supported_versions().collect();
        assert_eq!(versions, [Version::V1, Version::new(0xfafa_fafa)]);
        assert!(versions[1].is_reserved());
        assert_eq!(packet.dcid().len(), 255);
        assert_eq!(packet.scid().len(), 255);
    }
}

#[test]
fn version_negotiation_lists_are_whole_versions() {
    for length in 0..=9 {
        let bytes = long(0x80, 0, &[], &[], &vec![0xab; length]);
        let mut input = bytes.as_slice();
        let header = input.sync_read_long_header_unpin().unwrap();
        let result = input.sync_read_version_negotiation_unpin(header);
        assert_eq!(result.is_ok(), length % 4 == 0, "{length}");
        if let Ok(packet) = result {
            assert_eq!(packet.supported_versions().len(), length / 4);
        }
    }
}

/// Version-specific layouts apply only to their version.
#[test]
fn version_1_layout_refuses_other_versions_without_reading() {
    for version in [0, 2, 0x6b33_43cf] {
        let bytes = long(0xc0, version, &[1], &[2], &[0xff; 8]);
        let mut input = bytes.as_slice();
        let header = input.sync_read_long_header_unpin().unwrap();
        let before = input.len();
        assert!(matches!(
            input.sync_read_long_packet_unpin(header),
            Err(ReadLongPacketError::Version { .. })
        ));
        assert_eq!(input.len(), before);
    }
    assert_eq!(v1::VERSION, Version::new(1));
}

/// RFC 8999 §5.1 fields cut short.
#[test]
fn every_prefix_of_the_long_header_fields_is_incomplete() {
    let bytes = long(0xc0, 1, &[1, 2], &[3, 4], &[]);
    for cut in 0..bytes.len() {
        let mut input = &bytes[..cut];
        let error = input.sync_read_long_header_unpin().unwrap_err();
        assert!(error.is_incomplete(), "{cut}: {error}");
    }
    let mut input = &[0x40, 0, 0][..];
    assert!(matches!(
        input.sync_read_long_header_unpin(),
        Err(ReadLongHeaderError::ShortForm)
    ));
}
