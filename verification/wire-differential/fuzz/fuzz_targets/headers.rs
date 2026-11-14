//! Any datagram, the first byte giving the destination connection ID length
//! of short headers: sakuya reads the first packet and cuts the datagram as
//! quinn-proto and s2n-quic-core do, or the divergence has a verdict; the
//! cut packets tile the datagram and hold what reading them gives.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sakuya_wire::connection_id::ConnectionIdLength;
use wire_differential::{
    headers::{compare_all, split},
    tally::{Comparison, hex},
};

fuzz_target!(|input: &[u8]| {
    let Some((&short_len, datagram)) = input.split_first() else {
        return;
    };
    // Version 1 connection IDs are at most 20 bytes.
    let short_len = ConnectionIdLength::new(usize::from(short_len % 21)).unwrap();
    let results = compare_all(datagram, short_len);
    assert!(
        !results.contains(&Comparison::Unclassified),
        "headers {results:?} on {}",
        hex(datagram)
    );
    let results = split::compare_all(datagram, short_len);
    assert!(
        !results.contains(&Comparison::Unclassified),
        "split {results:?} on {}",
        hex(datagram)
    );
});
