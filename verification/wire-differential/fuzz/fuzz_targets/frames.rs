//! Any payload: sakuya reads what quinn-proto and s2n-quic-core read, or the
//! divergence has a verdict; every run sakuya reads writes back to its
//! bytes; and a failure has the transport error code of RFC 9000 §12.4.
#![no_main]
use libfuzzer_sys::fuzz_target;
use wire_differential::{
    frames::{
        classify::compare_all,
        frame_type_at,
        sakuya::{self, Failure},
        shortest_width,
    },
    tally::{Comparison, hex},
};

/// PROTOCOL_VIOLATION for a Frame Type encoded longer than necessary, and
/// FRAME_ENCODING_ERROR for every other failure, the types of extensions a
/// set does not have among them.
fn expected_code(payload: &[u8], failure: &Failure) -> u64 {
    let longer = frame_type_at(&payload[failure.offset..])
        .is_some_and(|(value, width)| width > shortest_width(value));
    if longer { 0x0a } else { 0x07 }
}

fuzz_target!(|payload: &[u8]| {
    let results = compare_all(payload);
    assert!(
        !results.contains(&Comparison::Unclassified),
        "{results:?} on {}",
        hex(payload)
    );
    for read in [sakuya::read(payload), sakuya::read_v1(payload)] {
        assert_eq!(read.rewrite_mismatch(payload), None);
        if let Some(failure) = &read.failure {
            assert_eq!(failure.code, expected_code(payload, failure), "{failure:?}");
        }
    }
});
