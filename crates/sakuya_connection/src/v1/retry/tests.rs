use bytes::Bytes;
use sakuya_packet_protection_v1::backend::ring::RingBackend;
use sakuya_wire_v1::connection_id::{ConnectionId, ConnectionIdLength};
use sakuya_wire_v1::protected_packet::{Packet, into_packets};

use super::*;

/// The Destination Connection ID of the client's first Initial packet in
/// RFC 9001 Appendix A.
const FIRST_DESTINATION: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

/// The Retry packet of RFC 9001 Appendix A.4: token "token", Source
/// Connection ID f067a5502a4262b5.
const RETRY: [u8; 36] = [
    0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74,
    0x6f, 0x6b, 0x65, 0x6e, 0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f,
    0x0f, 0x24, 0x96, 0xba,
];

fn id(bytes: &[u8]) -> ConnectionId {
    ConnectionId::new(bytes).unwrap()
}

/// The Retry packet in `datagram`, as the receiving loop cuts it.
fn cut(datagram: &[u8]) -> (LongPacket<Range<usize>>, Bytes) {
    let mut packets = into_packets(Bytes::copy_from_slice(datagram), ConnectionIdLength::ZERO);
    match packets.next() {
        Some(Ok(Packet::Retry(packet, bytes))) => (packet, bytes),
        other => panic!("a Retry packet, not {other:?}"),
    }
}

fn check(datagram: &[u8], first: &[u8], answered: bool) -> Result<ValidRetry, RetryDropReason> {
    let (packet, bytes) = cut(datagram);
    check_retry(&RingBackend, &packet, &bytes, &id(first), answered)
}

#[test]
fn a_valid_retry_gives_its_source_and_token() {
    let retry = check(&RETRY, &FIRST_DESTINATION, false).unwrap();
    assert_eq!(
        retry.source(),
        id(&[0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5])
    );
    assert_eq!(&retry.token()[..], b"token");
    let received = retry.received(Some(Duration::from_millis(30)));
    assert_eq!(received.token_len(), 5);
    assert_eq!(received.source(), retry.source());
    assert_eq!(
        received.since_first_initial(),
        Some(Duration::from_millis(30))
    );
}

#[test]
fn a_retry_after_a_packet_from_the_server_is_dropped() {
    assert!(matches!(
        check(&RETRY, &FIRST_DESTINATION, true),
        Err(RetryDropReason::AfterServerPacket)
    ));
}

#[test]
fn a_retry_whose_tag_does_not_verify_is_dropped() {
    // the tag is over the first Destination Connection ID: another one
    // fails it
    assert!(matches!(
        check(&RETRY, &[0; 8], false),
        Err(RetryDropReason::IntegrityTag { .. })
    ));
    let mut corrupted = RETRY;
    corrupted[16] ^= 1;
    assert!(matches!(
        check(&corrupted, &FIRST_DESTINATION, false),
        Err(RetryDropReason::IntegrityTag { .. })
    ));
}

#[test]
fn a_retry_from_the_first_destination_is_dropped() {
    let source = [0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5];
    assert!(matches!(
        check(&RETRY, &source, false),
        Err(RetryDropReason::SourceIsFirstDestination)
    ));
}

#[test]
fn a_retry_without_a_token_is_dropped() {
    // the header of the Appendix A.4 Retry without its token, and any tag
    let mut empty = RETRY[..15].to_vec();
    empty.extend_from_slice(&RETRY[RETRY.len() - 16..]);
    assert!(matches!(
        check(&empty, &FIRST_DESTINATION, false),
        Err(RetryDropReason::EmptyToken)
    ));
}

#[test]
fn the_default_policy_goes_on() {
    let retry = ReceivedRetry::new(id(&[1; 8]), 5, None);
    assert_eq!(ContinueOnRetry.decide(&retry), RetryDecision::Continue);
}

#[test]
fn the_keys_after_a_retry_are_derived_from_its_source() {
    let source = id(&[0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5]);
    let after = retry_initial_keys(&RingBackend, &source);
    let secrets = InitialSecrets::derive(&RingBackend, &source);
    let expected = DirectionKeys::derive(&RingBackend, INITIAL_AEAD, &secrets.client);
    assert_eq!(format!("{:?}", after.send), format!("{expected:?}"));
}
