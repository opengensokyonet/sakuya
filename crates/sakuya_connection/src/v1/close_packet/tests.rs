use sakuya_link::MIN_DATAGRAM_SIZE;
use sakuya_packet_protection::{
    backend::ring::RingBackend,
    initial::{INITIAL_AEAD, InitialSecrets},
};
use sakuya_stream::connection::ApplicationImmediateClose;
use sakuya_wire::v1::application_error::ApplicationErrorCode;

use super::*;

fn cid(byte: u8) -> ConnectionId {
    ConnectionId::new(&[byte; 8]).unwrap()
}

/// The server's keys of the Initial secret, which the tests seal Initial
/// and Handshake packets with alike.
fn keys() -> DirectionKeys<RingBackend> {
    let secrets = InitialSecrets::derive(&RingBackend, &cid(0x83));
    DirectionKeys::derive(&RingBackend, INITIAL_AEAD, &secrets.server)
}

fn transport(phrase: &[u8]) -> ImmediateClose {
    ImmediateClose::Transport(TransportImmediateClose {
        code: TransportErrorCode::PROTOCOL_VIOLATION,
        frame_type: Some(VarInt::from_u32(0x1e)),
        reason_phrase: Bytes::copy_from_slice(phrase),
    })
}

fn application(phrase: &[u8]) -> ImmediateClose {
    ImmediateClose::Application(ApplicationImmediateClose {
        code: ApplicationErrorCode::new(VarInt::from_u32(7)),
        reason_phrase: Bytes::copy_from_slice(phrase),
    })
}

fn number(n: u64) -> PacketNumber {
    PacketNumber::new(n).unwrap()
}

fn level<'k>(
    keys: ClosePacketKeys<'k, RingBackend>,
    n: u64,
    close: ImmediateClose,
) -> ClosePacketLevel<'k, RingBackend> {
    ClosePacketLevel {
        keys,
        number: number(n),
        largest_acked: None,
        close,
    }
}

fn shape(role: Role, max_len: usize, budget: usize) -> ClosePacketShape {
    ClosePacketShape {
        dcid: cid(0xc5),
        scid: cid(0x5e),
        role,
        max_len,
        budget,
    }
}

/// A long header packet at the start of `datagram`, sealed with `keys`,
/// opened: its packet number, its payload and its length.
fn open_long(datagram: &[u8], keys: &DirectionKeys<RingBackend>) -> (u64, Vec<u8>, usize) {
    let initial = (datagram[0] >> 4) & 0b11 == 0;
    let mut at = 5;
    at += 1 + usize::from(datagram[at]);
    at += 1 + usize::from(datagram[at]);
    if initial {
        assert_eq!(datagram[at], 0, "an empty token");
        at += 1;
    }
    let width = 1 << (datagram[at] >> 6);
    let length = datagram[at + 1..at + width]
        .iter()
        .fold(usize::from(datagram[at] & 0x3f), |value, byte| {
            (value << 8) | usize::from(*byte)
        });
    let pn_offset = at + width;
    let len = pn_offset + length;
    let mut packet = datagram[..len].to_vec();
    let truncated = keys.header.remove(&mut packet, pn_offset).unwrap();
    let header_len = pn_offset + truncated.encoded_len().get();
    let number = truncated.decode(None);
    let payload = keys
        .packet
        .open(number, &mut packet, header_len)
        .unwrap()
        .to_vec();
    (number.get(), payload, len)
}

/// The reason phrase of the CONNECTION_CLOSE frame at the start of
/// `payload`, of type 0x1c with one-byte fields.
fn transport_phrase(payload: &[u8]) -> &[u8] {
    assert_eq!(payload[..3], [0x1c, 0x0a, 0x1e], "{payload:?}");
    let width = 1 << (payload[3] >> 6);
    let len = payload[4..3 + width]
        .iter()
        .fold(usize::from(payload[3] & 0x3f), |value, byte| {
            (value << 8) | usize::from(*byte)
        });
    &payload[3 + width..3 + width + len]
}

#[test]
fn an_application_close_becomes_application_error_in_initial_and_handshake_packets() {
    let expected = ImmediateClose::Transport(TransportImmediateClose {
        code: TransportErrorCode::APPLICATION_ERROR,
        frame_type: None,
        reason_phrase: Bytes::new(),
    });
    for level in [EncryptionLevel::Initial, EncryptionLevel::Handshake] {
        assert_eq!(close_at_level(application(b"bye"), level), expected);
        // a transport close keeps its reason phrase
        assert_eq!(close_at_level(transport(b"bad"), level), transport(b"bad"));
    }
    assert_eq!(
        close_at_level(application(b"bye"), EncryptionLevel::OneRtt),
        application(b"bye")
    );
}

#[test]
fn a_reason_phrase_is_cut_to_what_fits_at_a_character_boundary() {
    // the type, the two one-byte fields and the one-byte length: 4 bytes
    let fits = close_frame(&transport(b"abcdef"), 4 + 6);
    assert_eq!(fits.reason_phrase().as_ref(), b"abcdef");
    let cut = close_frame(&transport(b"abcdef"), 4 + 3);
    assert_eq!(cut.reason_phrase().as_ref(), b"abc");
    assert_eq!(cut.encoded_len(), 7);
    // "é" is two bytes: a cut never splits it
    let text = "aé".repeat(3);
    let cut = close_frame(&transport(text.as_bytes()), 4 + 5);
    assert_eq!(cut.reason_phrase().as_ref(), "aéa".as_bytes());
    // bytes that are not UTF-8 are cut at a byte
    let cut = close_frame(&transport(&[0xff; 6]), 4 + 5);
    assert_eq!(cut.reason_phrase().as_ref(), [0xff; 5]);
    // with no room for an empty phrase, the frame has none and is longer
    let none = close_frame(&transport(b"abc"), 2);
    assert!(none.reason_phrase().is_empty());
    assert_eq!(none.encoded_len(), 4);
}

#[test]
fn a_longer_reason_phrase_takes_a_wider_length_field() {
    let phrase = [b'x'; 100];
    // 63 bytes fit a one-byte length; 64 take two
    let frame = close_frame(&transport(&phrase), 3 + 1 + 63);
    assert_eq!(frame.reason_phrase().len(), 63);
    let frame = close_frame(&transport(&phrase), 3 + 1 + 64);
    assert_eq!(frame.reason_phrase().len(), 63, "64 would need two bytes");
    let frame = close_frame(&transport(&phrase), 3 + 2 + 64);
    assert_eq!(frame.reason_phrase().len(), 64);
    assert_eq!(frame.encoded_len(), 3 + 2 + 64);
}

#[test]
fn levels_fill_from_the_lowest_leaving_the_later_ones_their_error_codes() {
    let keys = keys();
    let long = [b'a'; 2000];
    let levels = vec![
        level(ClosePacketKeys::Initial(&keys), 1, transport(&long)),
        level(ClosePacketKeys::Handshake(&keys), 0, transport(&long)),
    ];
    let mut usage = AeadUsage::new();
    let sealed = write_close_datagram(levels, shape(Role::Server, 1200, 1200), &mut usage)
        .expect("both fit");
    let datagram = sealed.datagram();
    assert!(datagram.len() <= 1200, "{}", datagram.len());
    let (initial, payload, len) = open_long(datagram, &keys);
    assert_eq!(initial, 1);
    let first = transport_phrase(&payload);
    // the Initial frame takes what the Handshake one leaves without a
    // phrase
    assert!(first.len() > 1000, "{}", first.len());
    let (handshake, payload, rest) = open_long(&datagram[len..], &keys);
    assert_eq!(handshake, 0);
    // the Handshake frame takes what is left: little, as the Initial one
    // left only the least it needs, estimated from above
    let second = transport_phrase(&payload);
    assert!(second.len() < 16, "{}", second.len());
    assert!(second.iter().all(|byte| *byte == b'a'));
    assert_eq!(len + rest, datagram.len(), "two packets and nothing else");
    assert!(
        datagram.len() > 1200 - 8,
        "the room is used: {}",
        datagram.len()
    );
    assert_eq!(
        sealed.packet_number(PacketNumberSpaceKind::Initial),
        Some(number(1))
    );
    assert_eq!(
        sealed.packet_number(PacketNumberSpaceKind::Handshake),
        Some(number(0))
    );
    assert_eq!(
        sealed.packet_number(PacketNumberSpaceKind::ApplicationData),
        None
    );
}

#[test]
fn reason_phrases_keep_within_the_credit() {
    let keys = keys();
    let levels = vec![level(
        ClosePacketKeys::Initial(&keys),
        0,
        transport(&[b'a'; 2000]),
    )];
    let mut usage = AeadUsage::new();
    let sealed =
        write_close_datagram(levels, shape(Role::Server, 1200, 300), &mut usage).expect("it fits");
    assert!(
        sealed.datagram().len() <= 300,
        "{}",
        sealed.datagram().len()
    );
    assert!(sealed.datagram().len() > 290, "{}", sealed.datagram().len());
    // with less credit than the frame without a phrase, the frame still goes
    // in: the credit holds the datagram back when it is sent
    let levels = vec![level(
        ClosePacketKeys::Initial(&keys),
        0,
        transport(&[b'a'; 2000]),
    )];
    let sealed = write_close_datagram(levels, shape(Role::Server, 1200, 10), &mut usage)
        .expect("the error code goes");
    let (_, payload, _) = open_long(sealed.datagram(), &keys);
    assert_eq!(transport_phrase(&payload), b"");
}

#[test]
fn a_client_pads_its_close_packet_with_an_initial_packet_to_1200_bytes() {
    let keys = keys();
    let levels = vec![
        level(ClosePacketKeys::Initial(&keys), 3, transport(b"")),
        level(ClosePacketKeys::Handshake(&keys), 0, transport(b"")),
    ];
    let mut usage = AeadUsage::new();
    let sealed =
        write_close_datagram(levels, shape(Role::Client, 1200, 1200), &mut usage).expect("it fits");
    assert_eq!(sealed.datagram().len(), MIN_DATAGRAM_SIZE);
    // a server's is not: CONNECTION_CLOSE elicits no acknowledgment
    let levels = vec![level(ClosePacketKeys::Initial(&keys), 3, transport(b""))];
    let sealed =
        write_close_datagram(levels, shape(Role::Server, 1200, 1200), &mut usage).expect("it fits");
    assert!(sealed.datagram().len() < 100);
}

#[test]
fn nothing_is_sealed_without_a_level() {
    let mut usage = AeadUsage::new();
    assert!(
        write_close_datagram::<RingBackend>(
            Vec::new(),
            shape(Role::Server, 1200, 1200),
            &mut usage
        )
        .is_none()
    );
}
