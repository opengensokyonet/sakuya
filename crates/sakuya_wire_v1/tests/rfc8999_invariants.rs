//! The version-independent properties of QUIC (RFC 8999) that need the layout of
//! version 1, through the public interface.
use sakuya_wire::{header::codec::read_long_header, version::Version};
use sakuya_wire_v1::header::{
    self as v1,
    codec::{ReadLongPacketError, read_long_packet},
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

/// RFC 8999 §5.1: connection IDs of a long header take 0 to 255 bytes.
#[test]
fn long_header_connection_ids_take_any_length_a_byte_states() {
    for dcid_len in [0, 1, 20, 21, 254, 255] {
        for scid_len in [0, 21, 255] {
            let dcid = vec![0xd0; dcid_len];
            let scid = vec![0x50; scid_len];
            let bytes = long(0xc0, 0x6b33_43cf, &dcid, &scid, &[]);
            let mut input = bytes.as_slice();
            let header = read_long_header(&mut input).unwrap();
            assert_eq!(header.dcid().as_bytes(), dcid);
            assert_eq!(header.scid().as_bytes(), scid);
            assert!(input.is_empty());
            // Version 1 restricts them; only its layer refuses them.
            if dcid_len > 20 || scid_len > 20 {
                let bytes = long(0xc0, 1, &dcid, &scid, &[]);
                let mut input = bytes.as_slice();
                let header = read_long_header(&mut input).unwrap();
                assert!(matches!(
                    read_long_packet(&mut input, header),
                    Err(ReadLongPacketError::DcidLength { .. }
                        | ReadLongPacketError::ScidLength { .. })
                ));
            }
        }
    }
}

/// Version-specific layouts apply only to their version.
#[test]
fn version_1_layout_refuses_other_versions_without_reading() {
    for version in [0, 2, 0x6b33_43cf] {
        let bytes = long(0xc0, version, &[1], &[2], &[0xff; 8]);
        let mut input = bytes.as_slice();
        let header = read_long_header(&mut input).unwrap();
        let before = input.len();
        assert!(matches!(
            read_long_packet(&mut input, header),
            Err(ReadLongPacketError::Version { .. })
        ));
        assert_eq!(input.len(), before);
    }
    assert_eq!(v1::VERSION, Version::new(1));
}
