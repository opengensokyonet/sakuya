//! Packet header interpretation, datagram cutting and header writing against
//! quinn-proto and s2n-quic-core.
use proptest::prelude::*;
use wire_differential::{
    cases,
    headers::{
        Kind, compare_all,
        generate::{
            coalesced, datagram, long_header_input, retry_input, short_header_input,
            version_negotiation_input,
        },
        read_quinn, read_sakuya, split,
        write::{check_long, check_retry, check_short, check_version_negotiation},
    },
    tally::{self, Comparison},
};

fn assert_classified(results: [Comparison; 2], bytes: &[u8]) -> Result<(), TestCaseError> {
    if !cases::exploring() {
        prop_assert!(
            !results.contains(&Comparison::Unclassified),
            "{:?} {}",
            results,
            tally::hex(bytes)
        );
    }
    Ok(())
}

proptest! {
    #![proptest_config(cases::config(50_000))]

    #[test]
    fn readers_agree((bytes, short_len) in datagram()) {
        assert_classified(compare_all(&bytes, short_len), &bytes)?;
    }

    #[test]
    fn splits_agree((bytes, short_len) in prop_oneof![coalesced(), datagram()]) {
        assert_classified(split::compare_all(&bytes, short_len), &bytes)?;
    }

    /// sakuya reads a version 1 or short header packet the same whether the
    /// Fixed Bit is set or not, and leaves the check to its caller; quinn-proto
    /// enforcing the bit accepts only the packet with the bit set, and reads it
    /// as sakuya does.
    #[test]
    fn fixed_bit_is_for_the_caller((bytes, short_len) in datagram()) {
        let Some(ours) = read_sakuya(&bytes, short_len) else { return Ok(()) };
        if matches!(ours.kind, Kind::OtherVersion | Kind::VersionNegotiation) {
            return Ok(());
        }
        let mut flipped = bytes.clone();
        flipped[0] ^= 0x40;
        prop_assert_eq!(read_sakuya(&flipped, short_len), Some(ours.clone()));
        let (set, unset) = if bytes[0] & 0x40 != 0 { (&bytes, &flipped) } else { (&flipped, &bytes) };
        prop_assert_eq!(read_quinn(unset, short_len, false), None);
        prop_assert_eq!(read_quinn(set, short_len, false), read_quinn(set, short_len, true));
        tally::agree("headers/fixed-bit-for-the-caller");
    }
}

proptest! {
    #![proptest_config(cases::config(20_000))]

    #[test]
    fn long_headers_write_as_the_references_read(input in long_header_input()) {
        check_long(&input).map_err(TestCaseError::fail)?;
    }

    #[test]
    fn short_headers_write_as_the_references_read(input in short_header_input()) {
        check_short(&input).map_err(TestCaseError::fail)?;
    }

    #[test]
    fn retry_packets_write_as_the_references_read(input in retry_input()) {
        check_retry(&input).map_err(TestCaseError::fail)?;
    }

    #[test]
    fn version_negotiation_writes_as_the_references_read(input in version_negotiation_input()) {
        check_version_negotiation(&input).map_err(TestCaseError::fail)?;
    }
}

#[test]
fn zz_report() {
    tally::report("headers");
}
