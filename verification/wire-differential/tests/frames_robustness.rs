//! Frame reading and writing of sakuya alone: any input reads without panic
//! to the errors the RFCs name, what is read writes back to the same bytes,
//! frame sets read only the types of their parts, and every source and sink
//! gives the results of byte slices.
use bytes::Bytes;
use either::Either;
use nitori_io::{bridge::Std, calls::WriteAllError};
use proptest::{collection::vec, prelude::*, sample::Index};
use sakuya_wire::{
    connection_id::{NonEmptyCid, StatelessResetToken},
    datagram::{DatagramFrame, codec::WriteDatagramFrameHostExt as _},
    parts::HList,
    reset_stream_at::{ResetStreamAtFrame, codec::WriteResetStreamAtFrameHostExt as _},
    v1::{
        self,
        application_error::ApplicationErrorCode,
        frame::{
            Frame as V1Frame, FrameTypeValue,
            ack::{AckFrame, AckRange, AckRanges},
            codec::{ReadFieldsHostExt as _, WriteFrameRunHostExt as _},
            connection_close::{CloseErrorCode, ConnectionCloseFrame},
            crypto::CryptoFrame,
            new_connection_id::NewConnectionIdFrame,
            new_token::NewTokenFrame,
            set::{FrameFieldsError, Frames, codec::ReadFrameTypeHostExt as _},
            stream::StreamFrame,
        },
        packet_number::PacketNumber,
        stream_count::StreamCount,
        stream_id::StreamId,
    },
    var_int::{VarInt, VarIntField, VarIntWidth},
};
use std::marker::PhantomData;
use wire_differential::{
    cases,
    frames::{
        Frame, frame_type_at,
        generate::{frames, layout, payload, violation_of_a_rule},
        sakuya::{self, Failure, FailureKind, Full, Read, Run, V1Only},
        shortest_width,
    },
    hosts::{Failing, OneByte, Waiting, WaitingSink, run},
    tally::hex,
};

const FRAME_ENCODING_ERROR: u64 = 0x07;
const PROTOCOL_VIOLATION: u64 = 0x0a;

/// The Frame Type values that RFC 9000 defines.
fn v1_type(value: u64) -> bool {
    value <= 0x1e
}

/// The Frame Type values of the extensions in [`Full`].
fn extension_type(value: u64) -> bool {
    matches!(value, 0x24 | 0x30 | 0x31)
}

/// Checks `failure` against the bytes at its offset: the step that failed
/// and the transport error code follow from the Frame Type found there.
fn check_failure(
    payload: &[u8],
    failure: &Failure,
    claimed: fn(u64) -> bool,
) -> Result<(), TestCaseError> {
    let at = &payload[failure.offset..];
    prop_assert!(!failure.message.is_empty());
    let Some((value, width)) = frame_type_at(at) else {
        prop_assert_eq!(failure.kind, FailureKind::FrameType);
        prop_assert!(failure.incomplete);
        prop_assert_eq!(failure.frame_type, None);
        prop_assert_eq!(failure.code, FRAME_ENCODING_ERROR);
        return Ok(());
    };
    prop_assert_eq!(failure.frame_type, Some(value), "{:?}", failure);
    if width > shortest_width(value) {
        // RFC 9000 §12.4: MAY treat as PROTOCOL_VIOLATION, which sakuya does
        // for every longer encoding, known type or not.
        prop_assert_eq!(failure.kind, FailureKind::LongerTypeEncoding);
        prop_assert_eq!(failure.code, PROTOCOL_VIOLATION);
        prop_assert!(!failure.incomplete);
    } else if !claimed(value) {
        // RFC 9000 §12.4: an unknown type is a FRAME_ENCODING_ERROR,
        // including the type of an extension the set does not have.
        prop_assert_eq!(failure.kind, FailureKind::UnknownType);
        prop_assert_eq!(failure.code, FRAME_ENCODING_ERROR);
        prop_assert!(!failure.incomplete);
    } else {
        prop_assert_eq!(failure.kind, FailureKind::Fields);
        prop_assert_eq!(failure.code, FRAME_ENCODING_ERROR);
    }
    Ok(())
}

/// Checks a walk of `payload`: the runs cover the payload from its start,
/// each writes back to the bytes it was read from, and a failure is where
/// the runs end and has the error of the bytes there.
fn check_read<D: bytes::Buf + Clone + std::fmt::Debug>(
    payload: &[u8],
    read: &Read<D>,
    claimed: fn(u64) -> bool,
) -> Result<(), TestCaseError> {
    let mut end = 0;
    for (range, _) in &read.runs {
        prop_assert_eq!(range.start, end);
        prop_assert!(range.end > range.start);
        end = range.end;
    }
    prop_assert_eq!(read.rewrite_mismatch(payload), None, "{}", hex(payload));
    match &read.failure {
        None => prop_assert_eq!(end, payload.len()),
        Some(failure) => {
            prop_assert_eq!(failure.offset, end);
            check_failure(payload, failure, claimed)?;
        }
    }
    Ok(())
}

fn full_claims(value: u64) -> bool {
    v1_type(value) || extension_type(value)
}

/// Reads `payload` from a byte slice and from `Bytes` with both frame sets,
/// and checks each walk.
fn check_payload(payload: &[u8]) -> Result<(), TestCaseError> {
    let full = sakuya::read(payload);
    check_read(payload, &full, full_claims)?;
    let shared = sakuya::read_with::<Full, _>(Bytes::copy_from_slice(payload));
    prop_assert_eq!(shared.decoded(), full.decoded());
    prop_assert_eq!(&shared.failure, &full.failure);
    let v1 = sakuya::read_v1(payload);
    check_read(payload, &v1, v1_type)?;
    let shared = sakuya::read_with::<V1Only, _>(Bytes::copy_from_slice(payload));
    prop_assert_eq!(shared.decoded(), v1.decoded());
    prop_assert_eq!(&shared.failure, &v1.failure);
    Ok(())
}

/// Writes a [`Run`] to a host with the host methods of the operations, the
/// synchronous ones or, with `async`, the asynchronous ones run to the end.
macro_rules! write_run {
    (@async $host:expr, $run:expr) => {
        match $run {
            Run::V1(item) => run($host.write_frame_run_unpin(item)),
            Run::Datagram(item) => run($host.write_datagram_frame_unpin(item)),
            Run::ResetStreamAt(item) => run($host.write_reset_stream_at_frame_unpin(item)),
        }
    };
    ($host:expr, $run:expr) => {
        match $run {
            Run::V1(item) => $host.sync_write_frame_run_unpin(item),
            Run::Datagram(item) => $host.sync_write_datagram_frame_unpin(item),
            Run::ResetStreamAt(item) => $host.sync_write_reset_stream_at_frame_unpin(item),
        }
    };
}

proptest! {
    #![proptest_config(cases::config(100_000))]

    /// Any structured input reads without panic; every run writes back to
    /// its bytes, and every failure has the code of RFC 9000 §12.4 for what
    /// stands at its offset.
    #[test]
    fn structured_input_reads_and_writes_back(payload in payload()) {
        check_payload(&payload)?;
    }

    #[test]
    fn random_bytes_read_and_write_back(payload in vec(any::<u8>(), 0..256)) {
        check_payload(&payload)?;
    }

    /// A set of version 1 alone reads every frame of version 1 as the full
    /// set does, and the types of DATAGRAM and RESET_STREAM_AT as unknown.
    #[test]
    fn extensions_only_change_extension_frames(payload in payload()) {
        let full = sakuya::read(&payload);
        let v1 = sakuya::read_v1(&payload);
        let extension = full
            .runs
            .iter()
            .position(|(_, run)| !matches!(run, Run::V1(_)));
        let shared = extension.unwrap_or(full.runs.len());
        prop_assert_eq!(&v1.runs[..], &full.runs[..shared], "{}", hex(&payload));
        let failure = v1.failure.as_ref();
        match (extension, &full.failure) {
            (Some(index), _) => {
                let failure = failure.expect("the set of version 1 stops at the extension");
                prop_assert_eq!(failure.offset, full.runs[index].0.start);
                prop_assert_eq!(failure.kind, FailureKind::UnknownType);
                prop_assert_eq!(failure.code, FRAME_ENCODING_ERROR);
                prop_assert!(failure.frame_type.is_some_and(extension_type));
            }
            (None, Some(expected)) => {
                let failure = failure.expect("the set of version 1 fails where the full set does");
                prop_assert_eq!(failure.offset, expected.offset);
                if expected.kind == FailureKind::Fields
                    && expected.frame_type.is_some_and(extension_type)
                {
                    prop_assert_eq!(failure.kind, FailureKind::UnknownType);
                    prop_assert_eq!(failure.code, FRAME_ENCODING_ERROR);
                    prop_assert!(!failure.incomplete);
                    prop_assert_eq!(failure.frame_type, expected.frame_type);
                } else {
                    prop_assert_eq!(failure, expected);
                }
            }
            (None, None) => prop_assert_eq!(failure, None),
        }
    }

    /// Every proper prefix of valid frames ends between frames, or fails as
    /// incomplete with FRAME_ENCODING_ERROR, or is a frame without a Length
    /// field cut short, which reads to the end of the prefix.
    #[test]
    fn truncated_frames_are_incomplete(frames in frames(), mut layout in layout()) {
        let pieces: Vec<Vec<u8>> = frames
            .iter()
            .map(|frame| sakuya::build(frame, &mut layout).expect("a valid frame builds").to_bytes())
            .collect();
        let bytes = pieces.concat();
        let ends: Vec<usize> = pieces
            .iter()
            .scan(0, |sum, piece| {
                *sum += piece.len();
                Some(*sum)
            })
            .collect();
        let open_end = matches!(
            frames.last(),
            Some(Frame::Stream { has_length: false, .. } | Frame::Datagram { has_length: false, .. })
        );
        let last_start = bytes.len() - pieces.last().map_or(0, Vec::len);
        for cut in 0..bytes.len() {
            let read = sakuya::read(&bytes[..cut]);
            let complete = ends.iter().position(|&end| end == cut).map_or(0, |index| index + 1);
            if cut == 0 || ends.contains(&cut) {
                prop_assert_eq!(&read.failure, &None, "cut {} of {}", cut, hex(&bytes));
                prop_assert_eq!(&read.decoded().frames[..], &frames[..complete]);
            } else if let Some(failure) = &read.failure {
                prop_assert!(failure.incomplete, "cut {} of {}: {:?}", cut, hex(&bytes), failure);
                prop_assert_eq!(failure.code, FRAME_ENCODING_ERROR);
            } else {
                prop_assert!(open_end && cut > last_start, "cut {} of {}", cut, hex(&bytes));
            }
        }
    }

    /// Reading the Frame Type and the fields of version 1 frames from a
    /// source that waits between bytes gives what a byte slice gives.
    #[test]
    fn frames_read_the_same_from_a_waiting_source(payload in payload()) {
        let full = PhantomData::<Full>;
        let v1 = PhantomData::<V1Only>;
        let mut slice = payload.as_slice();
        let mut source = Waiting::new(&payload);
        while !slice.is_empty() {
            let mut ahead = slice;
            let expected = ahead.sync_read_frame_type_unpin(full);
            let actual = run(Waiting::new(slice).read_frame_type_unpin(full));
            match (&expected, &actual) {
                (Ok(a), Ok(b)) => prop_assert_eq!(a, b),
                (Err(a), Err(b)) => {
                    prop_assert_eq!(a.is_incomplete(), b.is_incomplete());
                    prop_assert_eq!(a.frame_type(), b.frame_type());
                    prop_assert_eq!(a.transport_error_code(), b.transport_error_code());
                }
                (a, b) => prop_assert!(false, "{:?} {:?} on {}", a, b, hex(&payload)),
            }
            let expected = slice.sync_read_frame_type_unpin(v1);
            let actual = run(source.read_frame_type_unpin(v1));
            let frame_type: FrameTypeValue = match (expected, actual) {
                (Ok(a), Ok(b)) => {
                    prop_assert_eq!(a, b);
                    a.extract()
                }
                (Err(a), Err(b)) => {
                    prop_assert_eq!(a.is_incomplete(), b.is_incomplete());
                    prop_assert_eq!(a.frame_type(), b.frame_type());
                    prop_assert_eq!(a.transport_error_code(), b.transport_error_code());
                    break;
                }
                (a, b) => {
                    return Err(TestCaseError::fail(format!("{a:?} {b:?} on {}", hex(&payload))));
                }
            };
            prop_assert_eq!(source.source, slice);
            let expected = slice.sync_read_fields_unpin(frame_type);
            let actual = run(source.read_fields_unpin(frame_type));
            match (expected, actual) {
                (Ok(a), Ok(b)) => {
                    prop_assert_eq!(a, b);
                    prop_assert_eq!(source.source, slice);
                }
                (Err(a), Err(b)) => {
                    prop_assert_eq!(a.is_incomplete(), b.is_incomplete());
                    prop_assert_eq!(a.frame_type(), b.frame_type());
                    prop_assert_eq!(a.transport_error_code(), b.transport_error_code());
                    break;
                }
                (a, b) => prop_assert!(false, "{:?} {:?} on {}", a, b, hex(&payload)),
            }
        }
    }

    /// A source that fails within a frame fails the read as that source, not
    /// as a frame cut short.
    #[test]
    fn source_failures_are_not_truncations(payload in payload(), limit in 0usize..32) {
        let v1 = PhantomData::<V1Only>;
        let mut slice = payload.as_slice();
        let Ok(frame_type) = slice.sync_read_frame_type_unpin(v1) else { return Ok(()) };
        if slice.sync_read_fields_unpin(frame_type.extract()).is_err() {
            return Ok(());
        }
        let consumed = payload.len() - slice.len();
        if limit >= consumed {
            return Ok(());
        }
        let mut source = Failing::new(&payload, limit);
        match source.sync_read_frame_type_unpin(v1) {
            Err(error) => {
                prop_assert!(!error.is_incomplete(), "{}: {:?}", hex(&payload), error);
            }
            Ok(frame_type) => {
                let error = source
                    .sync_read_fields_unpin(frame_type.extract())
                    .expect_err("the source failed within the frame");
                prop_assert!(!error.is_incomplete(), "{}: {:?}", hex(&payload), error);
            }
        }
    }

    /// Every run writes the same bytes to a sink that takes one byte at a
    /// time and to one that waits between bytes; a sink that fills up keeps
    /// the bytes it took, and the error counts them.
    #[test]
    fn runs_write_the_same_to_every_sink(payload in payload(), room in any::<Index>()) {
        for (_, item) in sakuya::read(&payload).runs {
            let direct = item.clone().to_bytes();
            prop_assert_eq!(direct.len(), item.encoded_len());
            let mut slow = Std::new(OneByte::default());
            write_run!(slow, item.clone()).expect("the sink takes every byte");
            prop_assert_eq!(&slow.into_inner().0, &direct);
            let mut waiting = WaitingSink::default();
            write_run!(@async waiting, item.clone()).expect("the sink takes every byte");
            prop_assert_eq!(&waiting.written, &direct);
            let room = room.index(direct.len() + 1);
            let mut storage = vec![0xee; room];
            let mut full = storage.as_mut_slice();
            let result = write_run!(full, item);
            if room < direct.len() {
                match result {
                    Err(WriteAllError::WriteZero { source }) => {
                        prop_assert_eq!(source.completed, room);
                    }
                    other => prop_assert!(false, "{:?}", other),
                }
            } else {
                prop_assert!(result.is_ok());
            }
            prop_assert_eq!(&storage[..], &direct[..room]);
        }
    }

    /// An encoding that breaks a rule of its frame fails at once, not as
    /// incomplete, with the code the rule calls for; a set of version 1
    /// alone reads RESET_STREAM_AT as unknown.
    #[test]
    fn broken_rules_fail_with_their_codes(violation in violation_of_a_rule()) {
        let bytes = &violation.bytes;
        let full = sakuya::read(bytes);
        prop_assert!(full.runs.is_empty(), "{}: {}", violation.rule, hex(bytes));
        let failure = full.failure.expect("the rule is broken");
        prop_assert_eq!(failure.offset, 0);
        prop_assert!(!failure.incomplete, "{}: {} {:?}", violation.rule, hex(bytes), failure);
        prop_assert_eq!(failure.code, violation.code, "{}: {}", violation.rule, hex(bytes));
        prop_assert_eq!(failure.frame_type, Some(violation.frame_type));
        let v1 = sakuya::read_v1(bytes).failure.expect("the set of version 1 fails too");
        prop_assert_eq!(v1.code, violation.code);
        prop_assert!(!v1.incomplete);
        if violation.frame_type == 0x24 && failure.kind == FailureKind::Fields {
            prop_assert_eq!(v1.kind, FailureKind::UnknownType);
        } else {
            prop_assert_eq!(v1.kind, failure.kind);
        }
    }
}

/// After a failure the iterator yields nothing more, and what it left
/// unread is the end of the payload.
#[test]
fn a_failure_ends_the_iteration() {
    // PING, then MAX_DATA cut short.
    let payload = [0x01, 0x10, 0x40];
    let mut frames = Frames::new(&payload[..], PhantomData::<HList![v1::Part]>);
    assert!(frames.next().unwrap().is_ok());
    let error = frames.next().unwrap().unwrap_err();
    assert!(error.is_incomplete());
    assert_eq!(frames.offset(), 1);
    assert!(payload.ends_with(frames.remainder()));
    assert!(frames.next().is_none());
    assert!(frames.next().is_none());
}

fn var(value: u64) -> VarInt {
    VarInt::new(value).unwrap()
}

fn field(value: u64) -> VarIntField<VarInt> {
    VarIntField::shortest(var(value))
}

fn stream(value: u64) -> VarIntField<StreamId> {
    VarIntField::shortest(StreamId::from_var_int(var(value)))
}

/// The constructors reject the fields that reading rejects, so a frame that
/// was constructed writes an encoding that reads back.
#[test]
fn constructors_reject_broken_rules() {
    let long = [0u8; 64];
    // RFC 9000 §19.7: the token MUST NOT be empty.
    assert!(NewTokenFrame::new(VarIntWidth::One, &[][..]).is_err());
    // A Length field too narrow for its payload.
    assert!(NewTokenFrame::new(VarIntWidth::One, &long[..]).is_err());
    assert!(NewTokenFrame::new(VarIntWidth::Two, &long[..]).is_ok());
    assert!(StreamFrame::with_length(stream(0), None, VarIntWidth::One, &long[..], false).is_err());
    assert!(CryptoFrame::new(field(0), VarIntWidth::One, &long[..]).is_err());
    assert!(DatagramFrame::with_length(VarIntWidth::One, &long[..]).is_err());
    let close = CloseErrorCode::Application {
        code: VarIntField::shortest(ApplicationErrorCode::new(var(0))),
    };
    assert!(ConnectionCloseFrame::new(close, VarIntWidth::One, &long[..]).is_err());
    // RFC 9000 §19.6, §19.8: data ends at most at 2^62 - 1.
    let near_end = field((1 << 62) - 2);
    assert!(
        StreamFrame::with_length(
            stream(0),
            Some(near_end),
            VarIntWidth::One,
            &[1u8][..],
            false
        )
        .is_ok()
    );
    assert!(
        StreamFrame::with_length(
            stream(0),
            Some(near_end),
            VarIntWidth::One,
            &[1u8, 2][..],
            false
        )
        .is_err()
    );
    assert!(StreamFrame::without_length(stream(0), Some(near_end), &[1u8, 2][..], false).is_err());
    assert!(CryptoFrame::new(near_end, VarIntWidth::One, &[1u8, 2][..]).is_err());
    // RFC 9000 §19.15: Retire Prior To does not exceed Sequence Number.
    let cid = NonEmptyCid::try_from(&[1u8, 2, 3][..]).unwrap();
    let token = StatelessResetToken::new([7; 16]);
    assert!(NewConnectionIdFrame::new(field(3), field(3), cid, token).is_ok());
    assert!(NewConnectionIdFrame::new(field(3), field(4), cid, token).is_err());
    // RFC 9000 §19.11, §19.14: a stream count is at most 2^60.
    assert!(StreamCount::new(1 << 60).is_ok());
    assert!(StreamCount::new((1 << 60) + 1).is_err());
    // RFC 9000 §19.3.1: no range of an ACK frame is below packet number 0,
    // and the ACK Range Count field holds the number of ranges.
    let largest = VarIntField::shortest(PacketNumber::new(5).unwrap());
    let ranges = |gaps: &[u64]| -> AckRanges {
        gaps.iter()
            .map(|&gap| AckRange {
                gap: field(gap),
                ack_range_length: field(0),
            })
            .collect()
    };
    let ack = |first: u64, gaps: &[u64], width| {
        AckFrame::new(largest, field(0), width, field(first), ranges(gaps), None)
    };
    assert!(ack(5, &[], VarIntWidth::One).is_ok());
    assert!(ack(6, &[], VarIntWidth::One).is_err());
    assert!(ack(0, &[3], VarIntWidth::One).is_ok());
    assert!(ack(0, &[4], VarIntWidth::One).is_err());
    let many = vec![0; 64];
    let largest = VarIntField::shortest(PacketNumber::new(1000).unwrap());
    let many_ranges = AckFrame::new(
        largest,
        field(0),
        VarIntWidth::One,
        field(0),
        ranges(&many),
        None,
    );
    assert!(many_ranges.is_err());
    // draft-ietf-quic-reliable-stream-reset-11 §4: Reliable Size does not
    // exceed Final Size.
    let code = VarIntField::shortest(ApplicationErrorCode::new(var(0)));
    assert!(ResetStreamAtFrame::new(stream(0), code, field(5), field(5)).is_ok());
    assert!(ResetStreamAtFrame::new(stream(0), code, field(5), field(6)).is_err());
}

/// The widths of fields that were read are kept: a frame read from an
/// encoding with a longer field than necessary is written back with it.
#[test]
fn field_widths_are_kept() {
    // STREAM with OFF and LEN: Stream ID 4 in eight bytes, Offset 0 in two,
    // Length 2 in four, then the data.
    let mut payload = vec![0x0e];
    payload.extend([
        0xc0, 0, 0, 0, 0, 0, 0, 4, 0x40, 0x00, 0x80, 0, 0, 2, b'h', b'i',
    ]);
    let read = sakuya::read(&payload);
    assert_eq!(read.failure, None);
    assert_eq!(read.rewrite_mismatch(&payload), None);
    let Run::V1(v1::frame::FrameRun::Stream(frame)) = &read.runs[0].1 else {
        panic!("{read:?}")
    };
    assert_eq!(frame.stream_id().width(), VarIntWidth::Eight);
    assert_eq!(
        frame.offset().map(|offset| offset.width()),
        Some(VarIntWidth::Two)
    );
    assert_eq!(frame.length(), Either::Right(VarIntWidth::Four));
    // A STREAM frame with offset 0 and an Offset field differs from one
    // without.
    let without = sakuya::read(&[0x0a, 0x04, 0x00]);
    let with = sakuya::read(&[0x0e, 0x04, 0x00, 0x00]);
    assert_eq!(without.decoded(), with.decoded());
    assert_ne!(without.runs[0].1, with.runs[0].1);
    // The frame of version 1 that `read_fields` gives for these bytes is the
    // same.
    let mut source = &payload[1..];
    let frame_type = FrameTypeValue::of(var(0x0e)).unwrap();
    let V1Frame::Stream(alone) = source.sync_read_fields_unpin(frame_type).unwrap() else {
        panic!()
    };
    assert_eq!(&alone, frame);
}
