//! Frame readers and writers of sakuya against quinn-proto and s2n-quic-core.
use proptest::{collection::vec, prelude::*};
use wire_differential::{
    cases,
    frames::{
        Decoded, Frame,
        classify::{self, compare_all},
        generate::{frame, frames, layout, payload},
        quinn, s2n,
        sakuya::{self, Layout},
    },
    generate::var_int_as,
    tally::{self, Comparison},
};

fn assert_no_unclassified(results: [Comparison; 2], payload: &[u8]) -> Result<(), TestCaseError> {
    if cases::exploring() {
        return Ok(());
    }
    prop_assert!(
        !results.contains(&Comparison::Unclassified),
        "{results:?}\npayload {}\nsakuya {:?}\nquinn {:?}\ns2n {:?}",
        tally::hex(payload),
        sakuya::read(payload),
        quinn::read(payload),
        s2n::read(payload),
    );
    Ok(())
}

/// What a reference that does not implement RESET_STREAM_AT reads from
/// `frames`: the frames before the first RESET_STREAM_AT, and a failure at
/// it.
fn without_reset_stream_at(frames: &[Frame]) -> Decoded {
    let end = frames
        .iter()
        .position(|frame| matches!(frame, Frame::ResetStreamAt { .. }));
    Decoded {
        frames: frames[..end.unwrap_or(frames.len())].to_vec(),
        failed: end.is_some(),
    }
}

proptest! {
    #![proptest_config(cases::config(20_000))]

    /// On any byte string, sakuya reads what each reference reads, or the
    /// divergence has a verdict.
    #[test]
    fn readers_agree_on_any_payload(payload in payload()) {
        assert_no_unclassified(compare_all(&payload), &payload)?;
    }

    #[test]
    fn readers_agree_on_random_bytes(payload in vec(any::<u8>(), 0..64)) {
        assert_no_unclassified(compare_all(&payload), &payload)?;
    }

    /// Frames sakuya writes, in any widths, read back as the same values
    /// with all three readers; a reference stops at RESET_STREAM_AT.
    #[test]
    fn sakuya_writes_what_every_reader_reads(frames in frames(), mut layout in layout()) {
        let bytes = sakuya::write(&frames, &mut layout).expect("valid frames build");
        let expected = Decoded { frames: frames.clone(), failed: false };
        let ours = sakuya::read(&bytes);
        prop_assert_eq!(ours.decoded(), expected, "{}", tally::hex(&bytes));
        prop_assert_eq!(ours.rewrite_mismatch(&bytes), None);
        let expected = without_reset_stream_at(&frames);
        prop_assert_eq!(s2n::read(&bytes), expected.clone(), "{}", tally::hex(&bytes));
        prop_assert_eq!(
            quinn::read(&bytes).without_lengths(),
            expected.without_lengths(),
            "{}",
            tally::hex(&bytes)
        );
    }

    /// What a reference writes, sakuya writes byte for byte in the shortest
    /// encodings, and reads back to the same frame.
    #[test]
    fn reference_encodings_are_sakuya_encodings(frame in frame()) {
        let ours = sakuya::write(std::slice::from_ref(&frame), &mut Layout::shortest())
            .expect("a valid frame builds");
        for (name, bytes) in [("s2n", s2n::write(&frame)), ("quinn", quinn::write(&frame))] {
            let Some(bytes) = bytes else { continue };
            prop_assert_eq!(&bytes, &ours, "{} encoding of {:?}", name, frame);
            let read = sakuya::read(&bytes);
            prop_assert_eq!(&read.decoded().frames, &vec![frame.clone()]);
            prop_assert_eq!(read.failure, None);
            tally::agree(&format!("frames/encoding/{name}"));
        }
    }
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// One input of each category, with the category it gets against each
/// reference.
#[test]
fn each_category_has_an_example() {
    let reset_stream_at = hex("2404010905");
    let mut max_streams = vec![0x12];
    max_streams.extend(var_int_as((1 << 60) + 1, 8));
    let mut stream_end = vec![0x0e, 0x00];
    stream_end.extend(var_int_as((1 << 62) - 2, 8));
    stream_end.extend([0x02, 0xaa, 0xbb]);
    let examples: [(&str, Vec<u8>, Comparison, Comparison); 9] = [
        (
            "PING in two bytes",
            hex("4001"),
            Comparison::Known(classify::LONGER_TYPE),
            Comparison::Agree,
        ),
        (
            "empty NEW_TOKEN",
            hex("0700"),
            Comparison::Known(classify::EMPTY_TOKEN),
            Comparison::Known(classify::EMPTY_TOKEN),
        ),
        (
            "MAX_STREAMS of 2^60 + 1",
            max_streams,
            Comparison::Known(classify::STREAM_COUNT),
            Comparison::Agree,
        ),
        (
            "STREAM data ending at 2^62",
            stream_end,
            Comparison::Known(classify::DATA_END),
            Comparison::Known(classify::DATA_END),
        ),
        (
            "RESET_STREAM_AT",
            reset_stream_at,
            Comparison::Known(classify::RESET_STREAM_AT),
            Comparison::Known(classify::RESET_STREAM_AT),
        ),
        (
            "IMMEDIATE_ACK",
            hex("1f"),
            Comparison::Known(classify::REFERENCE_ONLY),
            Comparison::Agree,
        ),
        (
            "ACK_FREQUENCY",
            hex("40af00000000"),
            Comparison::Known(classify::REFERENCE_ONLY),
            Comparison::Agree,
        ),
        (
            "MTU_PROBING_COMPLETE",
            hex("80dc000205dc"),
            Comparison::Agree,
            Comparison::Known(classify::REFERENCE_ONLY),
        ),
        (
            "DATAGRAM with a Length field",
            hex("310268690100"),
            Comparison::Agree,
            Comparison::Agree,
        ),
    ];
    for (name, bytes, quinn, s2n) in examples {
        assert_eq!(
            classify::compare_quinn(&bytes),
            quinn,
            "{name} against quinn"
        );
        assert_eq!(classify::compare_s2n(&bytes), s2n, "{name} against s2n");
    }
}

/// Prints the counts of each comparison; run with `--nocapture` and
/// `--test-threads=1` after the other tests to see them.
#[test]
fn zz_report() {
    tally::report("frames");
}
