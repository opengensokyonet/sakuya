//! sakuya's packet protection on any input: errors instead of panics, the
//! buffer unchanged where an operation fails before writing, and every
//! recovered packet number in range.
use proptest::{collection::vec, option, prelude::*};
use sakuya_packet_protection::{
    backend::{AeadAlgorithm, KdfAlgorithm, ring::RingBackend},
    header_protection::HeaderProtectionKey,
    packet_key::{OpenPacketError, PacketKey},
    packet_number::{PacketNumberLength, TruncatedPacketNumber},
    retry::verify_retry_integrity_tag,
    secret::TrafficSecret,
};
use sakuya_wire::{connection_id::ConnectionId, v1::packet_number::PacketNumber};
use wire_differential::cases;

fn suite(index: u8) -> (AeadAlgorithm, KdfAlgorithm, usize) {
    match index {
        0 => (AeadAlgorithm::Aes128Gcm, KdfAlgorithm::HkdfSha256, 32),
        1 => (AeadAlgorithm::Aes256Gcm, KdfAlgorithm::HkdfSha384, 48),
        _ => (
            AeadAlgorithm::ChaCha20Poly1305,
            KdfAlgorithm::HkdfSha256,
            32,
        ),
    }
}

proptest! {
    #![proptest_config(cases::config(50_000))]

    #[test]
    fn protection_takes_any_input(
        packet in vec(any::<u8>(), 0..96),
        offset in prop_oneof![0usize..96, Just(usize::MAX), Just(usize::MAX - 3)],
        header_len in prop_oneof![0usize..96, Just(usize::MAX)],
        number in 0u64..=PacketNumber::MAX.get(),
        suite_index in 0u8..3,
        secret_byte in any::<u8>(),
    ) {
        let (aead, kdf, size) = suite(suite_index);
        let secret = TrafficSecret::new(kdf, &vec![secret_byte; size]).unwrap();
        let hp = HeaderProtectionKey::derive(&RingBackend, aead, &secret);
        let key = PacketKey::derive(&RingBackend, aead, &secret);
        let number = PacketNumber::new(number).unwrap();

        // RFC 9001 §5.4.2: the sample is 16 bytes at the Packet Number field
        // offset plus 4.
        let sampled = offset > 0 && offset.checked_add(20).is_some_and(|end| end <= packet.len());
        let mut buffer = packet.clone();
        let removed = hp.remove(&mut buffer, offset);
        prop_assert_eq!(removed.is_ok(), sampled);
        if removed.is_err() {
            prop_assert_eq!(&buffer, &packet);
        }
        let mut buffer = packet.clone();
        let applied = hp.apply(&mut buffer, offset);
        prop_assert_eq!(applied.is_ok(), sampled);
        if applied.is_ok() {
            // Only the first byte and the Packet Number field change, and
            // removing with the same key restores them.
            prop_assert_eq!(&buffer[offset + 4..], &packet[offset + 4..]);
            prop_assert_eq!(&buffer[1..offset], &packet[1..offset]);
            let truncated = hp.remove(&mut buffer, offset).unwrap();
            prop_assert_eq!(&buffer, &packet);
            prop_assert_eq!(truncated.as_bytes(), &packet[offset..offset + truncated.encoded_len().get()]);
        } else {
            prop_assert_eq!(&buffer, &packet);
        }

        let fits = header_len.checked_add(16).is_some_and(|end| end <= packet.len());
        let mut buffer = packet.clone();
        let sealed = key.seal(number, &mut buffer, header_len);
        prop_assert_eq!(sealed.is_ok(), fits);
        if fits {
            prop_assert_eq!(&buffer[..header_len], &packet[..header_len]);
            let opened = key.open(number, &mut buffer, header_len).unwrap();
            prop_assert_eq!(&*opened, &packet[header_len..packet.len() - 16]);
            // Another packet number is another nonce.
            let mut again = packet.clone();
            key.seal(number, &mut again, header_len).unwrap();
            let other = PacketNumber::new(number.get() ^ 1).unwrap();
            prop_assert!(key.open(other, &mut again, header_len).is_err());
        } else {
            prop_assert_eq!(&buffer, &packet);
        }

        let mut buffer = packet.clone();
        match key.open(number, &mut buffer, header_len) {
            Ok(_) => prop_assert!(false, "random bytes authenticate"),
            Err(OpenPacketError::PacketTooShort { .. }) => {
                prop_assert!(!fits);
                prop_assert_eq!(&buffer, &packet);
            }
            Err(error) => {
                prop_assert!(fits, "{}", error);
                // Only the payload may be overwritten.
                prop_assert_eq!(&buffer[..header_len], &packet[..header_len]);
            }
        }
    }

    #[test]
    fn retry_tags_take_any_input(
        packet in vec(any::<u8>(), 0..64),
        odcid in vec(any::<u8>(), 0..=20),
    ) {
        let odcid = ConnectionId::new(&odcid).unwrap();
        prop_assert!(verify_retry_integrity_tag(&RingBackend, &odcid, &packet).is_err());
    }
}

proptest! {
    #![proptest_config(cases::config(200_000))]

    #[test]
    fn packet_numbers_take_any_input(
        full in 0u64..=PacketNumber::MAX.get(),
        largest in option::of(0u64..=PacketNumber::MAX.get()),
        field in any::<u32>(),
        bytes in 1usize..=4,
    ) {
        let full = PacketNumber::new(full).unwrap();
        let largest = largest.map(|v| PacketNumber::new(v).unwrap());
        match TruncatedPacketNumber::encode(full, largest) {
            Ok(encoded) => {
                prop_assert!(largest.is_none_or(|largest| full > largest));
                prop_assert_eq!(encoded.decode(largest), full);
            }
            Err(_) => {
                let num_unacked = largest.map_or(full.get() + 1, |v| full.get().saturating_sub(v.get()));
                prop_assert!(num_unacked == 0 || num_unacked >= 1 << 31);
            }
        }
        let len = PacketNumberLength::new(bytes).unwrap();
        match TruncatedPacketNumber::new(field, len) {
            Ok(field) => {
                let decoded = field.decode(largest);
                prop_assert!(decoded <= PacketNumber::MAX);
                let mask = (1u64 << (8 * bytes)) - 1;
                prop_assert_eq!(decoded.get() & mask, u64::from(field.value()));
                prop_assert_eq!(field.encoded_len(), len);
            }
            Err(_) => prop_assert!(bytes < 4 && u64::from(field) >> (8 * bytes) != 0),
        }
    }
}
