//! The packets of RFC 9001 Appendix A read end to end: header interpretation
//! gives the offsets, header protection and the AEAD are removed, and the
//! payload is read as frames.

#![cfg(feature = "ring")]

use core::marker::PhantomData;
use sakuya_packet_protection::backend::AeadAlgorithm;
use sakuya_packet_protection::backend::KdfAlgorithm;
use sakuya_packet_protection::backend::ring::RingBackend;
use sakuya_packet_protection::header_protection::HeaderProtectionKey;
use sakuya_packet_protection::initial::{INITIAL_AEAD, InitialSecrets};
use sakuya_packet_protection::packet_key::PacketKey;
use sakuya_packet_protection::retry::verify_retry_integrity_tag;
use sakuya_packet_protection::secret::TrafficSecret;
use sakuya_wire::connection_id::{ConnectionId, ConnectionIdLength};
use sakuya_wire::header::codec::{ReadLongHeaderHostExt as _, ReadShortHeaderHostExt as _};
use sakuya_wire::parts::HList;
use sakuya_wire::v1::header::codec::ReadLongPacketHostExt as _;
use sakuya_wire::v1::header::{LongPacketType, TypeFields};
use sakuya_wire::v1::packet_number::PacketNumber;
use sakuya_wire::v1::role::Role;
use sakuya_wire::v1::stream_count::StreamCount;
use sakuya_wire::v1::transport_parameters::{
    codec::ReadTransportParametersHostExt as _,
    connection_id::InitialSourceConnectionId,
    integer::{
        InitialMaxData, InitialMaxStreamDataBidiLocal, InitialMaxStreamDataBidiRemote,
        InitialMaxStreamDataUni, InitialMaxStreamsBidi, InitialMaxStreamsUni, MaxIdleTimeout,
    },
};
use sakuya_wire::v1::{
    self,
    frame::{FrameRun, set::Frames},
};
use sakuya_wire::var_int::VarInt;

/// The next run of a payload read with the frame set of version 1 alone: a
/// frame, or a run of PADDING frames.
fn next_frame<'a>(frames: &mut Frames<&'a [u8], HList![v1::Part]>) -> Option<FrameRun<&'a [u8]>> {
    frames.next().map(|frame| frame.unwrap().extract())
}

fn hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

const CLIENT_DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

/// RFC 9001 Appendix A.2, the protected packet.
const CLIENT_PACKET: &str = include_str!("data/rfc9001_a2_client_initial.hex");

/// Reads the Initial packet in `protected` and removes its protection with
/// the keys of `secret`, returning the payload.
fn open_initial(protected: &[u8], secret: &TrafficSecret, expected_pn: u64) -> Vec<u8> {
    let mut input = protected;
    let header = input.sync_read_long_header_unpin().unwrap();
    let packet = input.sync_read_long_packet_unpin(header).unwrap();
    assert_eq!(packet.packet_type(), LongPacketType::Initial);
    assert!(packet.fixed_bit());
    assert!(input.is_empty(), "the datagram holds one packet");
    let end = packet.end();
    assert_eq!(end, protected.len());
    let TypeFields::Initial { token, bounds, .. } = packet.fields() else {
        panic!()
    };
    assert!(token.is_empty());
    assert_eq!(bounds.packet_number_offset(), 18);
    assert_eq!(bounds.sample_offset(), 22);

    let key = PacketKey::derive(&RingBackend, INITIAL_AEAD, secret);
    let hp = HeaderProtectionKey::derive(&RingBackend, INITIAL_AEAD, secret);
    let mut private = protected.to_vec();
    let truncated = hp
        .remove(&mut private, bounds.packet_number_offset())
        .unwrap();
    let number = truncated.decode(None);
    assert_eq!(number, PacketNumber::new(expected_pn).unwrap());
    let header_len = bounds.packet_number_offset() + truncated.encoded_len().get();
    key.open(number, &mut private, header_len).unwrap().to_vec()
}

#[test]
fn a2_client_initial_end_to_end() {
    let protected = hex(CLIENT_PACKET);
    assert_eq!(protected.len(), 1200);
    let dcid = ConnectionId::new(&CLIENT_DCID).unwrap();
    let secrets = InitialSecrets::derive(&RingBackend, &dcid);
    let payload = open_initial(&protected, &secrets.client, 2);
    assert_eq!(payload.len(), 1162);

    let mut frames = Frames::new(payload.as_slice(), PhantomData::<HList![v1::Part]>);
    let Some(FrameRun::Crypto(crypto)) = next_frame(&mut frames) else {
        panic!("the payload starts with a CRYPTO frame")
    };
    assert_eq!(crypto.offset().get(), VarInt::ZERO);
    assert_eq!(crypto.data().len(), 241);
    assert_eq!(crypto.data()[..4], [0x01, 0x00, 0x00, 0xed]);
    let Some(FrameRun::Padding(padding)) = next_frame(&mut frames) else {
        panic!("padding follows")
    };
    assert_eq!(padding.len().get(), 1162 - 245);
    assert!(next_frame(&mut frames).is_none());

    // The ClientHello ends with the quic_transport_parameters extension.
    let extension = &crypto.data()[crypto.data().len() - 0x32..];
    assert_eq!(
        crypto.data()[crypto.data().len() - 0x36..][..4],
        [0, 0x39, 0, 0x32]
    );
    let mut input = extension;
    let parameters = input
        .sync_read_transport_parameters_unpin(Role::Client, PhantomData::<HList![v1::Part]>)
        .unwrap();
    let initial_max_data = parameters.get::<InitialMaxData, _>().unwrap();
    assert_eq!(initial_max_data.get(), VarInt::MAX);
    let limit = VarInt::from(65535u16);
    let bidi_local = parameters
        .get::<InitialMaxStreamDataBidiLocal, _>()
        .unwrap();
    assert_eq!(bidi_local.get(), limit);
    let bidi_remote = parameters
        .get::<InitialMaxStreamDataBidiRemote, _>()
        .unwrap();
    assert_eq!(bidi_remote.get(), limit);
    let uni = parameters.get::<InitialMaxStreamDataUni, _>().unwrap();
    assert_eq!(uni.get(), limit);
    let streams = StreamCount::new(16).unwrap();
    let streams_bidi = parameters.get::<InitialMaxStreamsBidi, _>().unwrap();
    assert_eq!(streams_bidi.get(), streams);
    let streams_uni = parameters.get::<InitialMaxStreamsUni, _>().unwrap();
    assert_eq!(streams_uni.get(), streams);
    let max_idle_timeout = parameters.get::<MaxIdleTimeout, _>().unwrap();
    assert_eq!(max_idle_timeout.get(), VarInt::from(30000u16));
    let source_connection_id = parameters.get::<InitialSourceConnectionId, _>().unwrap();
    assert_eq!(source_connection_id.get(), dcid);
    assert!(parameters.unknown.is_empty());
}

#[test]
fn a3_server_initial_end_to_end() {
    let protected = hex("
        cf000000010008f067a5502a4262b500 4075c0d95a482cd0991cd25b0aac406a
        5816b6394100f37a1c69797554780bb3 8cc5a99f5ede4cf73c3ec2493a1839b3
        dbcba3f6ea46c5b7684df3548e7ddeb9 c3bf9c73cc3f3bded74b562bfb19fb84
        022f8ef4cdd93795d77d06edbb7aaf2f 58891850abbdca3d20398c276456cbc4
        2158407dd074ee");
    let dcid = ConnectionId::new(&CLIENT_DCID).unwrap();
    let secrets = InitialSecrets::derive(&RingBackend, &dcid);
    let payload = open_initial(&protected, &secrets.server, 1);

    let mut frames = Frames::new(payload.as_slice(), PhantomData::<HList![v1::Part]>);
    let Some(FrameRun::Ack(ack)) = next_frame(&mut frames) else {
        panic!("the payload starts with an ACK frame")
    };
    assert_eq!(ack.largest_acknowledged().get(), PacketNumber::ZERO);
    assert_eq!(ack.packet_ranges().count(), 1);
    assert_eq!(ack.ecn_counts(), None);
    let Some(FrameRun::Crypto(crypto)) = next_frame(&mut frames) else {
        panic!("a CRYPTO frame follows")
    };
    assert_eq!(crypto.data().len(), 90);
    assert_eq!(crypto.data()[0], 0x02, "a ServerHello");
    assert!(next_frame(&mut frames).is_none());
}

#[test]
fn a4_retry_end_to_end() {
    let packet = hex("
        ff000000010008f067a5502a4262b574 6f6b656e04a265ba2eff4d829058fb3f
        0f2496ba");
    let mut input = packet.as_slice();
    let header = input.sync_read_long_header_unpin().unwrap();
    let parsed = input.sync_read_long_packet_unpin(header).unwrap();
    assert_eq!(parsed.packet_type(), LongPacketType::Retry);
    assert!(parsed.dcid().is_empty());
    assert_eq!(parsed.scid().as_bytes(), hex("f067a5502a4262b5"));
    assert_eq!(parsed.end(), packet.len());
    let TypeFields::Retry {
        token,
        integrity_tag,
        ..
    } = parsed.fields()
    else {
        panic!()
    };
    assert_eq!(&token[..], b"token");
    assert_eq!(integrity_tag, &packet[packet.len() - 16..]);
    let odcid = ConnectionId::new(&CLIENT_DCID).unwrap();
    verify_retry_integrity_tag(&RingBackend, &odcid, &packet).unwrap();
}

#[test]
fn a5_short_header_end_to_end() {
    let protected = hex("4cfe4189655e5cd55c41f69080575d7999c25a5bfb");
    let secret = TrafficSecret::new(
        KdfAlgorithm::HkdfSha256,
        &hex("9ac312a7f877468ebe69422748ad00a1 5443f18203a07d6060f688f30f21632b"),
    )
    .unwrap();
    let aead = AeadAlgorithm::ChaCha20Poly1305;
    let key = PacketKey::derive(&RingBackend, aead, &secret);
    let hp = HeaderProtectionKey::derive(&RingBackend, aead, &secret);

    let mut input = protected.as_slice();
    let header = input
        .sync_read_short_header_unpin(ConnectionIdLength::ZERO)
        .unwrap();
    assert_eq!(header.packet_number_offset(), 1);
    assert_eq!(header.sample_offset(), 5);
    assert_eq!(header.end(), protected.len());

    let mut private = protected.clone();
    let truncated = hp
        .remove(&mut private, header.packet_number_offset())
        .unwrap();
    let largest = PacketNumber::new(654_360_563).unwrap();
    let number = truncated.decode(Some(largest));
    assert_eq!(number.get(), 654_360_564);
    let header_len = header.packet_number_offset() + truncated.encoded_len().get();
    let payload = key.open(number, &mut private, header_len).unwrap();
    let mut frames = Frames::new(&*payload, PhantomData::<HList![v1::Part]>);
    assert!(matches!(next_frame(&mut frames), Some(FrameRun::Ping(_))));
    assert!(next_frame(&mut frames).is_none());
}
