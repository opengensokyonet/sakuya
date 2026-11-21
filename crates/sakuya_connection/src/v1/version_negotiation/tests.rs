use bytes::Bytes;
use sakuya_wire_v1::connection_id::ConnectionIdLength;
use sakuya_wire_v1::protected_packet::{Packet, into_packets};

use super::*;

const FIRST_DESTINATION: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const CLIENT_SOURCE: [u8; 4] = [9, 9, 9, 9];

/// A Version Negotiation packet answering the client's first Initial
/// packet, with `scid` as its Source Connection ID and `versions`.
fn packet(scid: &[u8], versions: &[u32]) -> Vec<u8> {
    let mut bytes = vec![0x80, 0, 0, 0, 0];
    bytes.push(CLIENT_SOURCE.len() as u8);
    bytes.extend_from_slice(&CLIENT_SOURCE);
    bytes.push(scid.len() as u8);
    bytes.extend_from_slice(scid);
    for version in versions {
        bytes.extend_from_slice(&version.to_be_bytes());
    }
    bytes
}

fn check(datagram: &[u8], answered: bool) -> Result<Arc<[Version]>, VersionNegotiationDropReason> {
    let mut packets = into_packets(
        Bytes::copy_from_slice(datagram),
        ConnectionIdLength::new(CLIENT_SOURCE.len()).unwrap(),
    );
    let Some(Ok(Packet::VersionNegotiation(read, bytes))) = packets.next() else {
        panic!("a Version Negotiation packet")
    };
    check_version_negotiation(
        &read,
        &bytes,
        &ConnectionId::new(&FIRST_DESTINATION).unwrap(),
        answered,
    )
}

#[test]
fn a_valid_packet_gives_the_versions_in_order() {
    let versions = check(
        &packet(&FIRST_DESTINATION, &[0x6b33_43cf, 0x1a2a_3a4a]),
        false,
    )
    .unwrap();
    assert_eq!(
        &versions[..],
        &[Version::new(0x6b33_43cf), Version::new(0x1a2a_3a4a)]
    );
}

#[test]
fn a_packet_listing_version_1_is_dropped() {
    assert!(matches!(
        check(&packet(&FIRST_DESTINATION, &[0x6b33_43cf, 1]), false),
        Err(VersionNegotiationDropReason::ListsOwnVersion)
    ));
}

#[test]
fn an_empty_list_is_dropped() {
    assert!(matches!(
        check(&packet(&FIRST_DESTINATION, &[]), false),
        Err(VersionNegotiationDropReason::NoVersions)
    ));
}

#[test]
fn a_packet_after_one_from_the_server_is_dropped() {
    assert!(matches!(
        check(&packet(&FIRST_DESTINATION, &[0x6b33_43cf]), true),
        Err(VersionNegotiationDropReason::AfterServerPacket)
    ));
}

#[test]
fn a_packet_that_does_not_echo_the_first_destination_is_dropped() {
    assert!(matches!(
        check(&packet(&[8, 7, 6, 5, 4, 3, 2, 1], &[0x6b33_43cf]), false),
        Err(VersionNegotiationDropReason::OtherSourceConnectionId)
    ));
}
