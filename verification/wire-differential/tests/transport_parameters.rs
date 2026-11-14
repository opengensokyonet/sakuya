//! Transport parameters against quinn-proto and s2n-quic-core.
use proptest::prelude::*;
use sakuya_wire::v1::role::Role;
use wire_differential::{
    cases,
    parameters::{
        DUPLICATE, RESET_STREAM_AT_VALUE, classify, compare_all, generate::parameters, quinn, s2n,
        sakuya_written,
    },
    tally::{self, Comparison},
};

fn role() -> impl Strategy<Value = Role> {
    prop_oneof![Just(Role::Client), Just(Role::Server)]
}

fn no_unclassified(
    results: &[Comparison],
    bytes: &[u8],
    sender: Role,
) -> Result<(), TestCaseError> {
    if !cases::exploring() {
        prop_assert!(
            !results.contains(&Comparison::Unclassified),
            "{:?} from {:?}: {}",
            results,
            sender,
            tally::hex(bytes)
        );
    }
    Ok(())
}

proptest! {
    #![proptest_config(cases::config(50_000))]

    #[test]
    fn readers_agree(bytes in parameters(), sender in role()) {
        let results = compare_all("parameters", &bytes, sender);
        no_unclassified(&results, &bytes, sender)?;
    }

    /// What sakuya writes for parameters it reads, the unknown ones
    /// included, reads in each reference to the same values, but for the
    /// extensions only a reference implements.
    #[test]
    fn sakuya_writes_what_references_read(bytes in parameters(), sender in role()) {
        if let Some(results) = sakuya_written(&bytes, sender) {
            no_unclassified(&results, &bytes, sender)?;
            let [quinn, s2n] = results;
            prop_assert!(
                matches!(quinn, Comparison::Agree | Comparison::Known(quinn::EXTENSION)),
                "quinn {:?} from {:?}: {}", quinn, sender, tally::hex(&bytes)
            );
            prop_assert!(
                matches!(
                    s2n,
                    Comparison::Agree
                        | Comparison::Known(s2n::EXTENSION | s2n::LARGE_UDP_PAYLOAD | s2n::SHORT_CONNECTION_ID)
                ),
                "s2n {:?} from {:?}: {}", s2n, sender, tally::hex(&bytes)
            );
        }
    }

    /// What quinn-proto writes for parameters it reads sakuya reads to the
    /// same values.
    #[test]
    fn quinn_writes_what_sakuya_reads(bytes in parameters(), sender in role()) {
        if let Some(written) = quinn::rewrite(&bytes, sender) {
            let result = classify(&quinn::REFERENCE, &written, sender);
            tally::tally("parameters/quinn-written", "quinn", result, || tally::hex(&bytes));
            prop_assert_eq!(result, Comparison::Agree, "from {:?}: {}", sender, tally::hex(&bytes));
        }
    }

    /// What s2n-quic-core writes for parameters it reads sakuya reads to the
    /// same values, unless s2n-quic-core accepted a value RFC 9000 makes
    /// invalid.
    #[test]
    fn s2n_writes_what_sakuya_reads(bytes in parameters(), sender in role()) {
        if let Some(written) = s2n::rewrite(&bytes, sender) {
            let result = classify(&s2n::REFERENCE, &written, sender);
            tally::tally("parameters/s2n-written", "s2n", result, || tally::hex(&bytes));
            prop_assert!(
                matches!(
                    result,
                    Comparison::Agree
                        | Comparison::Known(s2n::MAX_ACK_DELAY_LIMIT | s2n::EMPTY_PREFERRED_CONNECTION_ID)
                ),
                "{:?} from {:?}: {}", result, sender, tally::hex(&bytes)
            );
        }
    }
}

/// The parameter `id` with `value`, ID and Length in one byte each.
fn tlv(id: u8, value: &[u8]) -> Vec<u8> {
    [&[id, value.len() as u8][..], value].concat()
}

/// A preferred_address value with an IPv4 address and a connection ID of
/// `cid` bytes.
fn preferred(cid: usize) -> Vec<u8> {
    let mut value = vec![192, 0, 2, 1, 1, 187];
    value.extend([0; 18]);
    value.push(cid as u8);
    value.extend(vec![7; cid]);
    value.extend([9; 16]);
    value
}

fn check(bytes: &[u8], sender: Role, expected: [Comparison; 2]) {
    let results = [
        classify(&quinn::REFERENCE, bytes, sender),
        classify(&s2n::REFERENCE, bytes, sender),
    ];
    assert_eq!(results, expected, "{}", tally::hex(bytes));
}

/// One input for each known category, and inputs that every implementation
/// treats alike.
#[test]
fn categories_have_examples() {
    use Comparison::{Agree, Known};
    // initial_max_data 5 in two bytes.
    check(
        &tlv(0x04, &[0x40, 0x05]),
        Role::Client,
        [Known(quinn::LONG_INTEGER), Agree],
    );
    // ack_delay_exponent 3 in two bytes.
    check(
        &tlv(0x0a, &[0x40, 0x03]),
        Role::Client,
        [
            Known(quinn::LONG_INTEGER),
            Known(s2n::ACK_DELAY_EXPONENT_WIDTH),
        ],
    );
    // max_datagram_frame_size 5 in two bytes: quinn reads any width there.
    check(&tlv(0x20, &[0x40, 0x05]), Role::Client, [Agree, Agree]);
    // grease_quic_bit with a value.
    check(
        &[0x80, 0x00, 0x2a, 0xb2, 0x01, 0x00],
        Role::Client,
        [Known(quinn::EXTENSION), Agree],
    );
    // mtu_probing_complete_support with a value.
    check(
        &[0x80, 0xdc, 0x00, 0x02, 0x01, 0x00],
        Role::Client,
        [Agree, Known(s2n::EXTENSION)],
    );
    // max_udp_payload_size 65528.
    check(
        &tlv(0x03, &[0x80, 0x00, 0xff, 0xf8]),
        Role::Client,
        [Agree, Known(s2n::LARGE_UDP_PAYLOAD)],
    );
    // original_destination_connection_id of 4 bytes, retry_source_connection_id of 3.
    check(
        &tlv(0x00, &[1; 4]),
        Role::Server,
        [Agree, Known(s2n::SHORT_CONNECTION_ID)],
    );
    check(
        &tlv(0x10, &[1; 3]),
        Role::Server,
        [Agree, Known(s2n::SHORT_CONNECTION_ID)],
    );
    // max_ack_delay of 2^14.
    check(
        &tlv(0x0b, &[0x80, 0x00, 0x40, 0x00]),
        Role::Client,
        [Agree, Known(s2n::MAX_ACK_DELAY_LIMIT)],
    );
    // preferred_address with an empty connection ID.
    check(
        &tlv(0x0d, &preferred(0)),
        Role::Server,
        [Agree, Known(s2n::EMPTY_PREFERRED_CONNECTION_ID)],
    );
    check(&tlv(0x0d, &preferred(4)), Role::Server, [Agree, Agree]);
    // A reserved parameter twice.
    check(
        &[tlv(0x1b, &[]), tlv(0x1b, &[1])].concat(),
        Role::Client,
        [Known(DUPLICATE), Known(DUPLICATE)],
    );
    // reset_stream_at twice, and with a value.
    check(
        &[tlv(0x1d, &[]), tlv(0x1d, &[])].concat(),
        Role::Client,
        [Known(DUPLICATE), Known(DUPLICATE)],
    );
    check(
        &tlv(0x1d, &[0]),
        Role::Client,
        [Known(RESET_STREAM_AT_VALUE), Known(RESET_STREAM_AT_VALUE)],
    );
    // max_datagram_frame_size twice: everyone rejects it.
    check(
        &[tlv(0x20, &[1]), tlv(0x20, &[1])].concat(),
        Role::Client,
        [Agree, Agree],
    );
    // A preferred address with neither family: everyone rejects it.
    let mut neither = preferred(4);
    neither[..6].fill(0);
    check(&tlv(0x0d, &neither), Role::Server, [Agree, Agree]);
    // A server-only parameter from a client: everyone rejects it.
    check(&tlv(0x02, &[0; 16]), Role::Client, [Agree, Agree]);
}

#[test]
fn zz_report() {
    tally::report("transport parameters");
}
