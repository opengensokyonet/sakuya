//! Initial packet protection and the Retry Integrity Tag against the rustls
//! based implementation quinn-proto uses, and the Packet Number field
//! against quinn-proto and the pseudocode of RFC 9000 Appendix A.
use proptest::{collection::vec, option, prelude::*};
use quinn_proto::packet::PacketNumber as QPacketNumber;
use sakuya_packet_protection::packet_number::TruncatedPacketNumber;
use sakuya_wire::v1::packet_number::PacketNumber;
use wire_differential::{
    cases,
    protection::{
        generate::{initial, pn_value, side},
        open_quinn, open_sakuya,
        packet_number::{compare_decode_quinn, compare_decode_rfc, compare_encode_rfc, field},
        retry::{QuinnRetry, is_valid_sakuya, tag_sakuya},
    },
    tally::{self, Comparison},
};

fn assert_classified(
    area: &str,
    result: Comparison,
    sample: impl Fn() -> String,
) -> Result<(), TestCaseError> {
    tally::tally(area, "rfc-or-quinn", result, &sample);
    if !cases::exploring() {
        prop_assert_ne!(result, Comparison::Unclassified, "{}", sample());
    }
    Ok(())
}

proptest! {
    #![proptest_config(cases::config(10_000))]

    #[test]
    fn protection_is_byte_identical(packet in initial(), side in side()) {
        let ours = packet.protect_sakuya(side);
        prop_assert!(ours.is_some(), "{:?}", packet);
        prop_assert_eq!(&ours, &packet.protect_quinn(side));
        tally::agree("initial/identical-protection");
    }

    /// Each opens what the other protects, also with bytes after the packet
    /// in the datagram, and recovers what was protected.
    #[test]
    fn each_opens_what_the_other_protects(
        packet in initial(),
        side in side(),
        trailing in vec(any::<u8>(), 0..40),
    ) {
        let theirs = packet.protect_quinn(side).unwrap();
        let mut datagram = theirs.clone();
        datagram.extend(&trailing);
        let largest = packet.largest_acked;
        let ours = open_sakuya(&datagram, &packet.dcid, side, largest);
        prop_assert_eq!(&ours, &open_quinn(&datagram, &packet.dcid, side, largest));
        let opened = ours.map_err(TestCaseError::fail)?;
        prop_assert_eq!(opened.packet_number, packet.packet_number);
        prop_assert_eq!(&opened.payload, &packet.payload);
        prop_assert_eq!(&opened.token, &packet.token);
        prop_assert_eq!(&opened.scid, &packet.scid);
        prop_assert_eq!(opened.first_byte, packet.plain().unwrap().bytes[0]);
        tally::agree("initial/opened-by-both");
    }

    /// A flipped bit anywhere in the packet fails in both, and so do the
    /// keys of the other direction.
    #[test]
    fn corruption_fails_in_both(
        packet in initial(),
        side in side(),
        at in any::<prop::sample::Index>(),
        bit in 0u8..8,
    ) {
        let mut protected = packet.protect_sakuya(side).unwrap();
        let other = match side {
            rustls::Side::Client => rustls::Side::Server,
            rustls::Side::Server => rustls::Side::Client,
        };
        let largest = packet.largest_acked;
        prop_assert!(open_sakuya(&protected, &packet.dcid, other, largest).is_err());
        prop_assert!(open_quinn(&protected, &packet.dcid, other, largest).is_err());
        let at = at.index(protected.len());
        protected[at] ^= 1 << bit;
        let ours = open_sakuya(&protected, &packet.dcid, side, largest);
        let theirs = open_quinn(&protected, &packet.dcid, side, largest);
        prop_assert!(ours.is_err() && theirs.is_err(), "byte {} bit {}: {:?} {:?}", at, bit, ours, theirs);
        tally::agree("initial/corruption-refused-by-both");
    }

    /// The Retry Integrity Tag of any packet is the same in both, and each
    /// accepts exactly the tags the other computes.
    #[test]
    fn retry_tags_agree(
        odcid in vec(any::<u8>(), 0..=20),
        packet in vec(any::<u8>(), 0..80),
        header_len in any::<prop::sample::Index>(),
        damage in option::of((any::<prop::sample::Index>(), 0u8..8)),
    ) {
        let quinn = QuinnRetry::new();
        let tag = tag_sakuya(&odcid, &packet);
        prop_assert_eq!(tag, quinn.tag(&odcid, &packet));
        let mut retry = [packet.as_slice(), &tag].concat();
        if let Some((at, bit)) = damage {
            let at = at.index(retry.len());
            retry[at] ^= 1 << bit;
        }
        let header_len = header_len.index(retry.len() - 15);
        let valid = is_valid_sakuya(&odcid, &retry);
        prop_assert_eq!(valid, quinn.is_valid(&odcid, &retry, header_len));
        prop_assert_eq!(valid, damage.is_none());
        // A tag for another original Destination Connection ID fails.
        let mut other = odcid.clone();
        match other.first_mut() {
            Some(byte) => *byte ^= 1,
            None => other.push(0),
        }
        if other.len() <= 20 {
            prop_assert!(!is_valid_sakuya(&other, &retry));
        }
        tally::agree("retry/tags-agree");
    }
}

proptest! {
    #![proptest_config(cases::config(200_000))]

    #[test]
    fn decode_follows_the_pseudocode(
        largest in option::of(pn_value()),
        truncated in any::<u32>(),
        bytes in 1usize..=4,
    ) {
        let field = field(truncated, bytes);
        assert_classified("packet-number/decode", compare_decode_rfc(largest, field), || {
            format!("largest={largest:?} field={field:?}")
        })?;
    }

    #[test]
    fn decode_against_quinn(largest in pn_value(), truncated in any::<u32>(), bytes in 1usize..=4) {
        let field = field(truncated, bytes);
        assert_classified("packet-number/decode", compare_decode_quinn(largest, field), || {
            format!("largest={largest} field={field:?}")
        })?;
    }

    /// The field length follows the A.2 pseudocode where it represents more
    /// than twice the range, as RFC 9000 §17.1 requires; without an
    /// acknowledgment it holds the whole packet number.
    #[test]
    fn encode_follows_the_pseudocode(number in pn_value(), gap in prop_oneof![0u64..(1 << 33), select_power()]) {
        let largest = number.checked_sub(gap + 1);
        let acked = largest.map(|v| PacketNumber::new(v).unwrap());
        let full = PacketNumber::new(number).unwrap();
        assert_classified("packet-number/encode", compare_encode_rfc(number, largest), || {
            format!("number={number} largest={largest:?}")
        })?;
        let Ok(encoded) = TruncatedPacketNumber::encode(full, acked) else { return Ok(()) };
        let range = largest.map_or(u128::from(number) + 1, |v| u128::from(number - v));
        let window = 1u128 << (8 * encoded.encoded_len().get());
        prop_assert!(window > 2 * range, "number {} largest {:?}", number, largest);
        prop_assert_eq!(encoded.decode(acked), full);
        if let Some(acked) = largest
            && (number - acked) * 2 < 1 << 32
        {
            prop_assert_eq!(QPacketNumber::new(number, acked).len(), encoded.encoded_len().get());
            tally::agree("packet-number/encode-quinn");
        }
    }
}

/// A gap that makes the number of unacknowledged packets a power of two.
fn select_power() -> impl Strategy<Value = u64> {
    (0u32..34).prop_map(|bits| (1u64 << bits) - 1)
}

/// After the largest packet number, the pseudocode's closest value lies
/// above the range; sakuya returns the closest one within it.
#[test]
fn decode_after_the_largest_packet_number() {
    let max = PacketNumber::MAX.get();
    for bytes in 1..=4 {
        for truncated in [0, 1, 0x7f, 0x80, 0xff, 0x7fff, 0xffff, 0x7f_ffff, u32::MAX] {
            let field = field(truncated, bytes);
            let result = compare_decode_rfc(Some(max), field);
            tally::tally("packet-number/decode", "rfc", result, String::new);
            assert_ne!(result, Comparison::Unclassified, "{field:?}");
            let decoded =
                wire_differential::protection::packet_number::decode_sakuya(Some(max), field);
            assert!(decoded <= max);
            assert_eq!(decoded & ((1 << (8 * bytes)) - 1), u64::from(field.value()));
        }
    }
}

#[test]
fn zz_report() {
    tally::report("initial protection");
}
