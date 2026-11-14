//! Transport parameters from any input, sent by a client and by a server:
//! every divergence from quinn-proto and s2n-quic-core is classified, and
//! what sakuya writes for what it reads reads in quinn-proto to the same
//! values, but for the extensions only quinn-proto implements.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sakuya_wire::v1::role::Role;
use wire_differential::{
    parameters::{compare_all, quinn, sakuya_written},
    tally::Comparison,
};

fuzz_target!(|bytes: &[u8]| {
    for sender in [Role::Client, Role::Server] {
        let results = compare_all("parameters", bytes, sender);
        assert!(
            !results.contains(&Comparison::Unclassified),
            "{results:?} from {sender:?}"
        );
        if let Some(written) = sakuya_written(bytes, sender) {
            assert!(
                !written.contains(&Comparison::Unclassified),
                "{written:?} from {sender:?}"
            );
            assert!(
                matches!(
                    written[0],
                    Comparison::Agree | Comparison::Known(quinn::EXTENSION)
                ),
                "{written:?} from {sender:?}"
            );
        }
    }
});
