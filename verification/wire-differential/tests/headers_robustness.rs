//! sakuya's header readers on any input: no panic, the failures the RFCs
//! name, incomplete exactly where the source ends early, and the same
//! results on every kind of source.
use proptest::{collection::vec, prelude::*};
use sakuya_wire::{
    connection_id::{ConnectionId, ConnectionIdLength, RawConnectionId},
    header::{
        HeaderForm,
        codec::{
            read_long_header, read_short_header, read_version_negotiation,
            write_version_negotiation,
        },
    },
    version::Version,
};
use sakuya_wire_v1::{
    header::{
        LongPacketType, VERSION,
        codec::{ReadLongPacketError, read_long_packet, write_retry_packet_without_tag},
    },
    protected_packet::{IntoPacketsError, PacketBoundaryError, into_packets},
};
use wire_differential::{
    cases,
    headers::{
        generate::{coalesced, datagram, retry_input, version_negotiation_input},
        split::{Item, split_sakuya},
    },
    tally::hex,
};

fn any_input() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        3 => datagram().prop_map(|(bytes, _)| bytes),
        1 => coalesced().prop_map(|(bytes, _)| bytes),
        1 => vec(any::<u8>(), 0..64),
    ]
}

fn dcid_len() -> impl Strategy<Value = ConnectionIdLength> {
    (0usize..=20).prop_map(|length| ConnectionIdLength::new(length).unwrap())
}

/// Whether the failure of cutting a packet is an early end of the datagram.
fn boundary_incomplete(error: &IntoPacketsError) -> bool {
    match error {
        IntoPacketsError::UnreadableBoundary { source } => match source {
            PacketBoundaryError::LongHeader { source } => source.is_incomplete(),
            PacketBoundaryError::LongPacket { source } => source.is_incomplete(),
            PacketBoundaryError::VersionNegotiation { .. } => false,
            PacketBoundaryError::ShortHeader { source } => source.is_incomplete(),
        },
        IntoPacketsError::DcidDiffersFromFirst => false,
    }
}

proptest! {
    #![proptest_config(cases::config(50_000))]

    #[test]
    fn headers_read_any_input(bytes in any_input(), short_len in dcid_len()) {
        let mut input = bytes.as_slice();
        match read_short_header(&mut input, short_len) {
            Ok(short) => {
                prop_assert_eq!(short.end(), bytes.len());
                prop_assert_eq!(short.packet_number_offset(), 1 + short_len.get());
            }
            Err(error) => prop_assert_eq!(
                error.is_incomplete(),
                bytes.first().is_none_or(|&first| HeaderForm::of(first) == HeaderForm::Short),
                "{}", hex(&bytes)
            ),
        }
        let mut input = bytes.as_slice();
        let Ok(header) = read_long_header(&mut input) else { return Ok(()) };
        prop_assert_eq!(header.version_specific_offset(), bytes.len() - input.len());
        let rest = input;

        let mut versions = rest;
        let negotiation = read_version_negotiation(&mut versions, header);
        prop_assert_eq!(
            negotiation.is_ok(),
            header.version() == Version::NEGOTIATION && rest.len() % 4 == 0
        );

        let mut packet = rest;
        match read_long_packet(&mut packet, header) {
            Ok(parsed) => {
                prop_assert_eq!(parsed.end(), bytes.len() - packet.len(), "{}", hex(&bytes));
                prop_assert_eq!(header.version(), VERSION);
                prop_assert!(parsed.dcid().len() <= 20 && parsed.scid().len() <= 20);
                prop_assert_eq!(parsed.fixed_bit(), bytes[0] & 0x40 != 0);
                prop_assert_eq!(parsed.packet_type(), LongPacketType::of(bytes[0]));
            }
            Err(error) => {
                match error {
                    ReadLongPacketError::Version { .. } => prop_assert_ne!(header.version(), VERSION),
                    ReadLongPacketError::DcidLength { .. } => prop_assert!(header.dcid().len() > 20),
                    ReadLongPacketError::ScidLength { .. } => prop_assert!(header.scid().len() > 20),
                    // The rest are failures of the source, which ends early.
                    error => prop_assert!(error.is_incomplete(), "{}: {}", hex(&bytes), error),
                }
            }
        }
    }

    /// Every prefix of a version 1 long packet that ends before the packet
    /// does fails as incomplete, alone and when cut from a datagram.
    #[test]
    fn truncated_long_packets_are_incomplete(bytes in any_input()) {
        let mut input = bytes.as_slice();
        let Ok(header) = read_long_header(&mut input) else { return Ok(()) };
        let mut rest = input;
        let Ok(packet) = read_long_packet(&mut rest, header) else { return Ok(()) };
        // A Retry packet extends to the end of the source: its prefixes
        // still holding the tag are shorter Retry packets.
        let end = if packet.packet_type() == LongPacketType::Retry {
            header.version_specific_offset() + 16
        } else {
            packet.end()
        };
        for cut in 0..end {
            let prefix = &bytes[..cut];
            let mut input = prefix;
            match read_long_header(&mut input) {
                Err(error) => prop_assert!(error.is_incomplete(), "cut {} of {}", cut, hex(&bytes)),
                Ok(header) => {
                    let error = read_long_packet(&mut input, header).unwrap_err();
                    prop_assert!(error.is_incomplete(), "cut {} of {}: {}", cut, hex(&bytes), error);
                }
            }
            if let Some(item) = into_packets(prefix, ConnectionIdLength::ZERO).next() {
                let error = item.unwrap_err();
                prop_assert!(boundary_incomplete(&error), "cut {} of {}: {}", cut, hex(&bytes), error);
            }
        }
    }

    /// Any datagram cuts into packets that tile it up to where cutting
    /// stopped; each packet holds what reading its bytes gives.
    #[test]
    fn any_datagram_cuts_cleanly(bytes in any_input(), short_len in dcid_len()) {
        let split = split_sakuya(&bytes, short_len);
        let mut offset = 0;
        for item in &split.items {
            let range = match item {
                Item::Packet { range, .. } | Item::Ignored { range } => range,
            };
            prop_assert_eq!(range.start, offset);
            prop_assert!(range.end > range.start);
            offset = range.end;
        }
        prop_assert_eq!(split.stopped_at.unwrap_or(bytes.len()), offset);
    }
}

proptest! {
    #![proptest_config(cases::config(20_000))]

    /// Writing into a buffer with exactly the room the packet takes writes
    /// the bytes a growing buffer gets.
    #[test]
    fn writes_fill_the_room_they_have(
        retry in retry_input(),
        negotiation in version_negotiation_input(),
    ) {
        let (dcid, scid) = (ConnectionId::new(&retry.dcid).unwrap(), ConnectionId::new(&retry.scid).unwrap());
        let mut expected = Vec::new();
        write_retry_packet_without_tag(&mut expected, retry.unused, dcid, scid, &retry.token);
        let mut buffer = vec![0; expected.len()];
        write_retry_packet_without_tag(&mut &mut buffer[..], retry.unused, dcid, scid, &retry.token);
        prop_assert_eq!(&buffer, &expected);

        let dcid = RawConnectionId::new(&negotiation.dcid).unwrap();
        let scid = RawConnectionId::new(&negotiation.scid).unwrap();
        let versions: Vec<Version> = negotiation.versions.iter().copied().map(Version::new).collect();
        let mut expected = Vec::new();
        write_version_negotiation(&mut expected, negotiation.unused, &dcid, &scid, &versions);
        let mut buffer = vec![0; expected.len()];
        write_version_negotiation(&mut &mut buffer[..], negotiation.unused, &dcid, &scid, &versions);
        prop_assert_eq!(&buffer, &expected);
    }
}
