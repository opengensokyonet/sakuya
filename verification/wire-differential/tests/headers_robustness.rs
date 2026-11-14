//! sakuya's header readers on any input: no panic, the failures the RFCs
//! name, incomplete exactly where the source ends early, and the same
//! results on every kind of source.
use proptest::{collection::vec, prelude::*};
use sakuya_wire::{
    connection_id::{ConnectionId, ConnectionIdLength, RawConnectionId},
    header::{
        HeaderForm,
        codec::{
            ReadLongHeaderHostExt as _, ReadShortHeaderHostExt as _,
            ReadVersionNegotiationHostExt as _, WriteVersionNegotiationHostExt as _,
        },
    },
    v1::{
        header::{
            LongPacketType, VERSION,
            codec::{
                ReadLongPacketError, ReadLongPacketHostExt as _,
                WriteRetryPacketWithoutTagHostExt as _,
            },
        },
        protected_packet::{IntoPacketsError, PacketBoundaryError, into_packets},
    },
    version::Version,
};
use wire_differential::{
    cases,
    headers::{
        generate::{coalesced, datagram, retry_input, version_negotiation_input},
        read_sakuya, read_sakuya_from,
        split::{Item, split_sakuya},
    },
    hosts::{Failing, Waiting, run},
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
        match input.sync_read_short_header_unpin(short_len) {
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
        let Ok(header) = input.sync_read_long_header_unpin() else { return Ok(()) };
        prop_assert_eq!(header.version_specific_offset(), bytes.len() - input.len());
        let rest = input;

        let mut versions = rest;
        let negotiation = versions.sync_read_version_negotiation_unpin(header);
        prop_assert_eq!(
            negotiation.is_ok(),
            header.version() == Version::NEGOTIATION && rest.len() % 4 == 0
        );

        let mut packet = rest;
        match packet.sync_read_long_packet_unpin(header) {
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
        let Ok(header) = input.sync_read_long_header_unpin() else { return Ok(()) };
        let mut rest = input;
        let Ok(packet) = rest.sync_read_long_packet_unpin(header) else { return Ok(()) };
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
            match input.sync_read_long_header_unpin() {
                Err(error) => prop_assert!(error.is_incomplete(), "cut {} of {}", cut, hex(&bytes)),
                Ok(header) => {
                    let error = input.sync_read_long_packet_unpin(header).unwrap_err();
                    prop_assert!(error.is_incomplete(), "cut {} of {}: {}", cut, hex(&bytes), error);
                }
            }
            if let Some(item) = into_packets(prefix, ConnectionIdLength::ZERO).next() {
                let error = item.unwrap_err();
                prop_assert!(boundary_incomplete(&error), "cut {} of {}: {}", cut, hex(&bytes), error);
            }
        }
    }

    /// A source that waits before every byte reads as a byte slice does.
    #[test]
    fn headers_read_the_same_from_a_waiting_source(bytes in any_input(), short_len in dcid_len()) {
        let mut slice = bytes.as_slice();
        let mut waiting = Waiting::new(&bytes);
        let expected = read_sakuya_from(&mut slice, short_len);
        prop_assert_eq!(read_sakuya_from(&mut waiting, short_len), expected.clone());
        if expected.is_some() {
            prop_assert_eq!(waiting.source, slice);
        }
        prop_assert_eq!(read_sakuya(&bytes, short_len), expected);
    }

    /// A source that fails after `limit` bytes gives what a byte slice gives
    /// while the reader needs no more; past that it reports its failure, not
    /// an early end.
    #[test]
    fn receiver_failures_are_not_truncations(bytes in any_input(), limit in 0usize..48, short_len in dcid_len()) {
        let mut slice = bytes.as_slice();
        let expected = slice.sync_read_long_header_unpin();
        let needed = bytes.len() - slice.len();
        let mut failing = Failing::new(&bytes, limit);
        let actual = run(failing.read_long_header_unpin());
        match (&expected, &actual) {
            (Ok(a), Ok(b)) => prop_assert!(a == b && needed <= limit),
            (Ok(_), Err(error)) => prop_assert!(needed > limit && !error.is_incomplete(), "{}", error),
            (Err(a), Err(b)) if bytes.len() < limit || (!a.is_incomplete() && limit > 0) => {
                prop_assert_eq!(a.is_incomplete(), b.is_incomplete());
            }
            (Err(_), Err(error)) => prop_assert!(!error.is_incomplete(), "{}", error),
            (Err(_), Ok(_)) => prop_assert!(false, "a failing source reads more"),
        }

        // A short header reads to the end of the source.
        let mut slice = bytes.as_slice();
        let expected = slice.sync_read_short_header_unpin(short_len);
        let mut failing = Failing::new(&bytes, limit);
        let actual = run(failing.read_short_header_unpin(short_len));
        let long_form = bytes.first().is_some_and(|&first| HeaderForm::of(first) == HeaderForm::Long);
        if bytes.len() < limit || (long_form && limit > 0) {
            prop_assert_eq!(expected.map_err(|e| e.is_incomplete()), actual.map_err(|e| e.is_incomplete()));
        } else {
            prop_assert!(actual.is_err_and(|error| !error.is_incomplete()));
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

    /// Writing into a buffer with room for `room` bytes succeeds exactly when
    /// the packet fits; otherwise it fails, and the bytes that fit are the
    /// packet's first bytes.
    #[test]
    fn writes_fill_the_room_they_have(
        retry in retry_input(),
        negotiation in version_negotiation_input(),
        room in 0usize..600,
    ) {
        let (dcid, scid) = (ConnectionId::new(&retry.dcid).unwrap(), ConnectionId::new(&retry.scid).unwrap());
        let mut expected = Vec::new();
        expected.sync_write_retry_packet_without_tag_unpin(retry.unused, dcid, scid, &retry.token).unwrap();
        let mut buffer = vec![0; room];
        let result = (&mut buffer[..]).sync_write_retry_packet_without_tag_unpin(retry.unused, dcid, scid, &retry.token);
        prop_assert_eq!(result.is_ok(), room >= expected.len());
        let fitted = room.min(expected.len());
        prop_assert_eq!(&buffer[..fitted], &expected[..fitted]);

        let dcid = RawConnectionId::new(&negotiation.dcid).unwrap();
        let scid = RawConnectionId::new(&negotiation.scid).unwrap();
        let versions: Vec<Version> = negotiation.versions.iter().copied().map(Version::new).collect();
        let mut expected = Vec::new();
        expected.sync_write_version_negotiation_unpin(negotiation.unused, &dcid, &scid, &versions).unwrap();
        let mut buffer = vec![0; room];
        let result = (&mut buffer[..]).sync_write_version_negotiation_unpin(negotiation.unused, &dcid, &scid, &versions);
        prop_assert_eq!(result.is_ok(), room >= expected.len());
        let fitted = room.min(expected.len());
        prop_assert_eq!(&buffer[..fitted], &expected[..fitted]);
    }
}
