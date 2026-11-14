//! Packet protection of every AEAD against vectors from an independent
//! implementation (see `tools/gen_suite_vectors.py`), and the Retry
//! Integrity Tag against RFC 9001 Appendix A.4.
use sakuya_packet_protection::{
    backend::{AeadAlgorithm, KdfAlgorithm, ring::RingBackend},
    header_protection::HeaderProtectionKey,
    packet_key::PacketKey,
    retry::{compute_retry_integrity_tag, verify_retry_integrity_tag},
    secret::TrafficSecret,
};
use sakuya_wire::{
    connection_id::{ConnectionId, ConnectionIdLength},
    v1::{
        header::TypeFields,
        packet_number::PacketNumber,
        protected_packet::{Packet, into_packets},
    },
};
use wire_differential::protection::retry::QuinnRetry;

fn unhex(text: &str) -> Vec<u8> {
    let text: String = text.split_whitespace().collect();
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

#[test]
fn every_suite_matches_the_independent_vectors() {
    let vectors = include_str!("data/suites.txt");
    let mut counts = std::collections::BTreeMap::new();
    for line in vectors.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let aead = match f[0] {
            "aes128" => AeadAlgorithm::Aes128Gcm,
            "aes256" => AeadAlgorithm::Aes256Gcm,
            "chacha20" => AeadAlgorithm::ChaCha20Poly1305,
            other => panic!("unknown AEAD {other}"),
        };
        let kdf = match f[1] {
            "sha256" => KdfAlgorithm::HkdfSha256,
            "sha384" => KdfAlgorithm::HkdfSha384,
            other => panic!("unknown KDF {other}"),
        };
        let secret = TrafficSecret::new(kdf, &unhex(f[2])).unwrap();
        assert_eq!(secret.next(&RingBackend).as_bytes(), unhex(f[3]), "{line}");
        let number = PacketNumber::new(f[4].parse().unwrap()).unwrap();
        let pn_offset: usize = f[5].parse().unwrap();
        let (header, payload, protected) = (unhex(f[6]), unhex(f[7]), unhex(f[8]));

        let key = PacketKey::derive(&RingBackend, aead, &secret);
        let hp = HeaderProtectionKey::derive(&RingBackend, aead, &secret);
        let mut packet = [header.as_slice(), &payload, &[0; 16]].concat();
        key.seal(number, &mut packet, header.len()).unwrap();
        hp.apply(&mut packet, pn_offset).unwrap();
        assert_eq!(packet, protected, "{line}");

        let truncated = hp.remove(&mut packet, pn_offset).unwrap();
        assert_eq!(pn_offset + truncated.encoded_len().get(), header.len());
        assert_eq!(packet[..header.len()], header);
        assert_eq!(
            key.open(number, &mut packet, header.len()).unwrap(),
            payload,
            "{line}"
        );
        *counts.entry(f[0]).or_insert(0) += 1;
    }
    assert_eq!(counts.values().sum::<usize>(), 1200);
    println!("vectors checked: {counts:?}");
}

/// RFC 9001 Appendix A.4: the Retry packet a server sends in response to
/// the client Initial of Appendix A.2, whose Destination Connection ID is
/// 0x8394c8f03e515708.
#[test]
fn retry_tag_matches_rfc_9001_a_4() {
    let odcid = unhex("8394c8f03e515708");
    let packet = unhex(
        "ff000000010008f067a5502a4262b574 6f6b656e04a265ba2eff4d829058fb3f
         0f2496ba",
    );
    let (without_tag, tag) = packet.split_at(packet.len() - 16);
    let odcid_cid = ConnectionId::new(&odcid).unwrap();
    assert_eq!(
        compute_retry_integrity_tag(&RingBackend, &odcid_cid, without_tag),
        tag
    );
    verify_retry_integrity_tag(&RingBackend, &odcid_cid, &packet).unwrap();
    assert!(verify_retry_integrity_tag(&RingBackend, &ConnectionId::EMPTY, &packet).is_err());

    // s2n-quic-core carries the same vector.
    use s2n_quic_core::crypto::retry::example;
    assert_eq!(packet, example::PACKET);
    assert_eq!(odcid, example::ODCID);
    assert_eq!(tag, example::EXPECTED_TAG);

    let quinn = QuinnRetry::new();
    assert_eq!(quinn.tag(&odcid, without_tag), tag);
    assert!(quinn.is_valid(&odcid, &packet, 15));

    // The packet cut from a datagram is a Retry packet with the token
    // "token" and this tag.
    let packets: Vec<_> = into_packets(&packet[..], ConnectionIdLength::ZERO)
        .collect::<Result<_, _>>()
        .unwrap();
    let [Packet::Retry(header, bytes)] = &packets[..] else {
        panic!("{packets:?}")
    };
    assert_eq!(*bytes, &packet[..]);
    let TypeFields::Retry {
        token,
        integrity_tag,
        end,
    } = header.fields()
    else {
        panic!("{header:?}")
    };
    assert_eq!(&token[..], b"token");
    assert_eq!(integrity_tag, tag);
    assert_eq!(*end, packet.len());
}
