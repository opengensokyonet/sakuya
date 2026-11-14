//! The comparison of what sakuya reads from a payload with what a reference
//! reads, and the categories of the divergences that have a verdict.
//!
//! Each category names the RFC text that decides it; a divergence outside
//! them is unclassified and fails the tests.
use super::{
    Decoded, Frame, frame_type_at, quinn, s2n,
    sakuya::{self, Failure, FailureKind},
    shortest_width,
};
use crate::{
    generate::VAR_MAX,
    tally::{self, Comparison},
};

/// The reference reads a frame of an extension that sakuya does not
/// implement; no part of sakuya's set claims its type, which is an unknown
/// type.
pub const REFERENCE_ONLY: &str = "extension frame only the reference implements: \
     an unknown type for sakuya, FRAME_ENCODING_ERROR (RFC 9000 §12.4)";

/// The reference reads a Frame Type encoded longer than necessary.
pub const LONGER_TYPE: &str = "Frame Type encoded longer than necessary: sakuya rejects it as \
     PROTOCOL_VIOLATION, which RFC 9000 §12.4 permits (MAY), and the reference reads it";

/// The reference reads a NEW_TOKEN frame with an empty token.
pub const EMPTY_TOKEN: &str = "empty NEW_TOKEN token: sakuya rejects it as RFC 9000 §19.7 \
     requires (MUST, FRAME_ENCODING_ERROR), and the reference reads it";

/// The reference reads a MAX_STREAMS or STREAMS_BLOCKED frame with a count
/// above 2<sup>60</sup>.
pub const STREAM_COUNT: &str = "stream count above 2^60: sakuya rejects it as RFC 9000 §19.11 \
     and §19.14 require (MUST, FRAME_ENCODING_ERROR), and the reference reads it";

/// The reference reads a STREAM or CRYPTO frame whose data ends beyond
/// 2<sup>62</sup> − 1.
pub const DATA_END: &str = "data ending beyond 2^62-1: sakuya rejects it as RFC 9000 §19.6 \
     and §19.8 require (MUST, FRAME_ENCODING_ERROR), and the reference reads it";

/// sakuya reads RESET_STREAM_AT, which the reference does not implement.
pub const RESET_STREAM_AT: &str = "RESET_STREAM_AT, which only sakuya implements \
     (draft-ietf-quic-reliable-stream-reset-11 §4): an unknown type for the reference \
     (RFC 9000 §12.4)";

/// Every category, for reports.
pub const CATEGORIES: [&str; 6] = [
    REFERENCE_ONLY,
    LONGER_TYPE,
    EMPTY_TOKEN,
    STREAM_COUNT,
    DATA_END,
    RESET_STREAM_AT,
];

const FRAME_ENCODING_ERROR: u64 = 0x07;
const PROTOCOL_VIOLATION: u64 = 0x0a;

/// Whether sakuya's full set claims the Frame Type value `value`.
fn claimed(value: u64) -> bool {
    matches!(value, 0x00..=0x1e | 0x24 | 0x30 | 0x31)
}

/// Compares what sakuya read from `payload`, `ours`, with what a reference
/// read, `theirs`; `states_length` tells whether the reference states the
/// presence of Length fields.
pub fn compare(
    payload: &[u8],
    ours: &sakuya::Read<&[u8]>,
    theirs: &Decoded,
    states_length: bool,
) -> Comparison {
    let (mine, theirs) = if states_length {
        (ours.decoded(), theirs.clone())
    } else {
        (ours.decoded().without_lengths(), theirs.without_lengths())
    };
    if mine == theirs {
        return Comparison::Agree;
    }
    let index = mine
        .frames
        .iter()
        .zip(&theirs.frames)
        .position(|(a, b)| a != b)
        .unwrap_or(mine.frames.len().min(theirs.frames.len()));
    match (
        mine.frames.get(index),
        theirs.frames.get(index),
        &ours.failure,
    ) {
        (None, Some(frame), Some(failure)) => sakuya_rejected(payload, failure, frame),
        (Some(frame), None, _) if theirs.failed => reference_rejected(frame),
        _ => Comparison::Unclassified,
    }
}

/// sakuya stopped with `failure` where the reference read `frame`.
fn sakuya_rejected(payload: &[u8], failure: &Failure, frame: &Frame) -> Comparison {
    let at = payload.get(failure.offset..).unwrap_or_default();
    let longer = frame_type_at(at).is_some_and(|(value, width)| width > shortest_width(value));
    // The error sakuya must report for the category.
    let expect = |kind: FailureKind, code: u64, category: &'static str| {
        if failure.kind == kind && failure.code == code && !failure.incomplete {
            Comparison::Known(category)
        } else {
            Comparison::Unclassified
        }
    };
    if longer {
        let category = if matches!(frame, Frame::ReferenceOnly(_)) {
            REFERENCE_ONLY
        } else {
            LONGER_TYPE
        };
        return expect(
            FailureKind::LongerTypeEncoding,
            PROTOCOL_VIOLATION,
            category,
        );
    }
    let data_end = |offset: u64, data: &[u8]| offset.saturating_add(data.len() as u64) > VAR_MAX;
    match frame {
        Frame::ReferenceOnly(_) if frame_type_at(at).is_some_and(|(value, _)| !claimed(value)) => {
            expect(
                FailureKind::UnknownType,
                FRAME_ENCODING_ERROR,
                REFERENCE_ONLY,
            )
        }
        Frame::NewToken { token } if token.is_empty() => {
            expect(FailureKind::Fields, FRAME_ENCODING_ERROR, EMPTY_TOKEN)
        }
        Frame::MaxStreams { count, .. } | Frame::StreamsBlocked { count, .. }
            if *count > 1 << 60 =>
        {
            expect(FailureKind::Fields, FRAME_ENCODING_ERROR, STREAM_COUNT)
        }
        Frame::Stream { offset, data, .. } | Frame::Crypto { offset, data }
            if data_end(*offset, data) =>
        {
            expect(FailureKind::Fields, FRAME_ENCODING_ERROR, DATA_END)
        }
        _ => Comparison::Unclassified,
    }
}

/// The reference stopped where sakuya read `frame`.
fn reference_rejected(frame: &Frame) -> Comparison {
    match frame {
        Frame::ResetStreamAt { .. } => Comparison::Known(RESET_STREAM_AT),
        _ => Comparison::Unclassified,
    }
}

/// Compares sakuya with quinn-proto on `payload`.
pub fn compare_quinn(payload: &[u8]) -> Comparison {
    compare(
        payload,
        &sakuya::read(payload),
        &quinn::read(payload),
        false,
    )
}

/// Compares sakuya with s2n-quic-core on `payload`.
pub fn compare_s2n(payload: &[u8]) -> Comparison {
    compare(payload, &sakuya::read(payload), &s2n::read(payload), true)
}

/// Compares sakuya with both references on `payload` and tallies the
/// results under `frames/quinn` and `frames/s2n`.
pub fn compare_all(payload: &[u8]) -> [Comparison; 2] {
    let ours = sakuya::read(payload);
    let results = [
        (
            "quinn",
            compare(payload, &ours, &quinn::read(payload), false),
        ),
        ("s2n", compare(payload, &ours, &s2n::read(payload), true)),
    ];
    for (reference, result) in results {
        tally::tally("frames", reference, result, || tally::hex(payload));
    }
    [results[0].1, results[1].1]
}
