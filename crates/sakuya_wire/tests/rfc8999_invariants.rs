//! The version-independent properties of QUIC (RFC 8999), through the public
//! interface.
use sakuya_wire::{
    header::{
        HeaderForm,
        codec::{
            ReadLongHeaderError, ReadShortHeaderError, read_long_header, read_short_header,
            read_version_negotiation,
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
            let header = read_long_header(&mut input).unwrap();
            assert_eq!(header.first_byte(), first);
            assert_eq!(header.version(), Version::new(version));
            assert_eq!(header.dcid().as_bytes(), [1, 2, 3]);
            assert_eq!(header.scid().as_bytes(), [4]);
            assert_eq!(header.version_specific_offset(), 11);
            assert_eq!(input, [0xee, 0xef]);
        }
    }
}

/// RFC 8999 §5.2: a short header states no length, and its other seven bits
/// belong to the version.
#[test]
fn short_headers_read_with_the_length_the_caller_knows() {
    for first in 0x00..=0x7fu8 {
        let bytes = [first, 1, 2, 3, 4, 5];
        for length in 0..=5u8 {
            let mut input = bytes.as_slice();
            let header = read_short_header(&mut input, length).unwrap();
            assert_eq!(header.first_byte(), first);
            assert_eq!(header.dcid().len(), usize::from(length));
            assert_eq!(header.version_specific_offset(), 1 + usize::from(length));
            assert_eq!(header.end(), bytes.len());
        }
        let mut input = bytes.as_slice();
        let error = read_short_header(&mut input, 6).unwrap_err();
        assert!(error.is_incomplete());
    }
    let mut input = &[0x80, 0, 0][..];
    assert!(matches!(
        read_short_header(&mut input, 0),
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
        let header = read_long_header(&mut input).unwrap();
        assert_eq!(header.version(), Version::NEGOTIATION);
        let packet = read_version_negotiation(&mut input, header).unwrap();
        let versions: Vec<_> = packet.supported_versions().collect();
        assert_eq!(versions, [Version::new(1), Version::new(0xfafa_fafa)]);
        assert_eq!(packet.dcid().len(), 255);
        assert_eq!(packet.scid().len(), 255);
    }
}

#[test]
fn version_negotiation_lists_are_whole_versions() {
    for length in 0..=9 {
        let bytes = long(0x80, 0, &[], &[], &vec![0xab; length]);
        let mut input = bytes.as_slice();
        let header = read_long_header(&mut input).unwrap();
        let result = read_version_negotiation(&mut input, header);
        assert_eq!(result.is_ok(), length % 4 == 0, "{length}");
        if let Ok(packet) = result {
            assert_eq!(packet.supported_versions().len(), length / 4);
        }
    }
}

/// RFC 8999 §5.1 fields cut short.
#[test]
fn every_prefix_of_the_long_header_fields_is_incomplete() {
    let bytes = long(0xc0, 1, &[1, 2], &[3, 4], &[]);
    for cut in 0..bytes.len() {
        let mut input = &bytes[..cut];
        let error = read_long_header(&mut input).unwrap_err();
        assert!(error.is_incomplete(), "{cut}: {error}");
    }
    let mut input = &[0x40, 0, 0][..];
    assert!(matches!(
        read_long_header(&mut input),
        Err(ReadLongHeaderError::ShortForm)
    ));
}
