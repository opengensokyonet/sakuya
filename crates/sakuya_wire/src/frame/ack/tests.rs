// ACK ranges are written as arrays of inclusive ranges, some deliberately
// empty or reversed.
#![allow(clippy::single_range_in_vec_init, clippy::reversed_empty_ranges)]

use super::{
    Ack, AckBelowZeroError, AckRange, AckRanges, EcnCounts, InvalidAckError, PacketRangesError,
    RangeCountError,
    codec::{ReadAckEcnError, ReadAckError, WriteAckHostExt as _},
};
use crate::{
    frame::{
        Extensions, Frame,
        codec::{ReadFrameError, ReadFrameHostExt as _},
        tests::{assert_round_trip, read_ack, short, vi, wide},
    },
    packet_number::PacketNumber,
    var_int::{VarInt, VarIntField, VarIntWidth},
};
use core::{convert::Infallible, num::NonZeroUsize, ops::RangeInclusive};

fn pn(value: u64) -> PacketNumber {
    PacketNumber::new(value).unwrap()
}

fn ranges(ranges: &[RangeInclusive<u64>]) -> Vec<RangeInclusive<PacketNumber>> {
    ranges
        .iter()
        .map(|range| pn(*range.start())..=pn(*range.end()))
        .collect()
}

fn ack_range(gap: u64, ack_range_length: u64) -> AckRange {
    AckRange {
        gap: short(vi(gap)),
        ack_range_length: short(vi(ack_range_length)),
    }
}

/// The ACK frame with Largest Acknowledged `largest`, no delay, a one-byte
/// ACK Range Count, First ACK Range `first` and `ranges`.
fn ack(largest: u64, first: u64, ranges: Vec<AckRange>) -> Result<Ack, InvalidAckError> {
    Ack::new(
        short(pn(largest)),
        short(VarInt::ZERO),
        VarIntWidth::One,
        short(vi(first)),
        AckRanges::from(ranges),
        None,
    )
}

/// Writes `frame` with [`codec::write_ack`](super::codec::write_ack).
fn write(frame: Ack) -> Vec<u8> {
    let mut written = Vec::new();
    written.sync_write_ack_unpin(frame).unwrap();
    written
}

/// The failure of reading the ACK frame `encoding`, of either type, and what
/// it left unread.
fn read_frame_error(encoding: &[u8]) -> (ReadFrameError<Infallible>, &[u8]) {
    let mut input = encoding;
    let error = input.sync_read_frame_unpin(Extensions::NONE).unwrap_err();
    assert_eq!(error.frame_type(), Some(vi(u64::from(encoding[0]))));
    (error, input)
}

/// The failure of reading the ACK frame `encoding` before any ECN count,
/// and what it left unread.
fn read_error(encoding: &[u8]) -> (ReadAckError<Infallible>, &[u8]) {
    let (error, input) = read_frame_error(encoding);
    match error {
        ReadFrameError::Ack { source } if encoding[0] == 0x02 => (source, input),
        ReadFrameError::AckEcn {
            source: ReadAckEcnError::Ack { source },
        } if encoding[0] == 0x03 => (source, input),
        error => panic!("{encoding:02x?}: {error:?}"),
    }
}

#[test]
fn several_ranges_and_ecn_counts() {
    // Largest 100, delay 5, two more ranges; ranges 97..=100, gap 1 then 90..=94,
    // gap 0 then 88..=88; ECN counts 1, 2, 3.
    let encoding = [
        0x03, 0x40, 100, 0x05, 0x02, 0x03, 0x01, 0x04, 0x00, 0x00, 0x01, 0x02, 0x03,
    ];
    let expected = ranges(&[97..=100, 90..=94, 88..=88]);
    let frame = read_ack(&encoding);
    let Frame::Ack(ack) = &frame else {
        unreachable!()
    };
    let ecn_counts = EcnCounts {
        ect0: short(vi(1)),
        ect1: short(vi(2)),
        ce: short(vi(3)),
    };
    assert_eq!(ack.largest_acknowledged(), wide(pn(100), VarIntWidth::Two));
    assert_eq!(ack.ack_delay(), short(vi(5)));
    assert_eq!(ack.ack_range_count_width(), VarIntWidth::One);
    assert_eq!(ack.first_ack_range(), short(vi(3)));
    assert_eq!(ack.ranges().as_slice(), [ack_range(1, 4), ack_range(0, 0)]);
    assert_eq!(ack.ecn_counts(), Some(ecn_counts));
    assert_eq!(
        *ack,
        Ack::new(
            wide(pn(100), VarIntWidth::Two),
            short(vi(5)),
            VarIntWidth::One,
            short(vi(3)),
            AckRanges::from(vec![ack_range(1, 4), ack_range(0, 0)]),
            Some(ecn_counts),
        )
        .unwrap()
    );
    assert_eq!(ack.ranges().len(), 2);
    assert_eq!(
        ack.ranges().iter().collect::<Vec<_>>(),
        ack.ranges().as_slice()
    );
    assert_eq!(ack.packet_ranges().collect::<Vec<_>>(), expected);
    assert!(!frame.is_ack_eliciting());
    assert!(!frame.counts_in_flight());

    // The same frame from its packet number ranges, in the shortest
    // encodings: Largest Acknowledged takes two bytes either way.
    let built = Ack::from_packet_ranges(expected.clone(), short(vi(5)), Some(ecn_counts)).unwrap();
    assert_eq!(built, *ack);
    assert_eq!(built.packet_ranges().collect::<Vec<_>>(), expected);
    assert_eq!(built.encoded_len(), encoding.len());
    assert_eq!(write(built), encoding);
    assert_eq!(assert_round_trip(frame), encoding);
}

#[test]
fn single_packet_and_ranges_reaching_the_largest_packet_number() {
    let single = ranges(&[0..=0]);
    let built = Ack::from_packet_ranges(single.clone(), short(VarInt::ZERO), None).unwrap();
    let encoding = write(built);
    assert_eq!(encoding, [0x02, 0x00, 0x00, 0x00, 0x00]);
    let frame = read_ack(&encoding);
    let Frame::Ack(ack) = &frame else {
        unreachable!()
    };
    assert_eq!(ack.packet_ranges().collect::<Vec<_>>(), single);
    assert!(ack.ranges().is_empty());
    assert_round_trip(frame);

    let max = PacketNumber::MAX.get();
    let wide_ranges = ranges(&[max - 10..=max, 0..=max - 12]);
    let built = Ack::from_packet_ranges(wide_ranges.clone(), short(vi(1)), None).unwrap();
    let encoding = write(built);
    let frame = read_ack(&encoding);
    let Frame::Ack(ack) = &frame else {
        unreachable!()
    };
    assert_eq!(ack.packet_ranges().collect::<Vec<_>>(), wide_ranges);
    assert_eq!(ack.largest_acknowledged().get(), PacketNumber::MAX);
    assert_eq!(
        ack.ranges().as_slice(),
        [ack_range(0, max - 12)],
        "the second range starts at 0 after a gap of one packet number"
    );
    assert_round_trip(frame);
}

#[test]
fn widths_of_every_field_are_kept() {
    // Largest 5, delay 0, count 1 and first range 1 in two bytes each; gap
    // 0 in eight bytes, range length 0 in four.
    let encoding = [
        0x02, 0x40, 0x05, 0x40, 0x00, 0x40, 0x01, 0x40, 0x01, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0,
        0, 0,
    ];
    let frame = read_ack(&encoding);
    let Frame::Ack(ack) = &frame else {
        unreachable!()
    };
    assert_eq!(ack.largest_acknowledged(), wide(pn(5), VarIntWidth::Two));
    assert_eq!(ack.ack_delay(), wide(VarInt::ZERO, VarIntWidth::Two));
    assert_eq!(ack.ack_range_count_width(), VarIntWidth::Two);
    assert_eq!(ack.first_ack_range(), wide(vi(1), VarIntWidth::Two));
    assert_eq!(
        ack.ranges().as_slice(),
        [AckRange {
            gap: wide(VarInt::ZERO, VarIntWidth::Eight),
            ack_range_length: wide(VarInt::ZERO, VarIntWidth::Four),
        }]
    );
    assert_eq!(
        ack.packet_ranges().collect::<Vec<_>>(),
        ranges(&[4..=5, 2..=2])
    );
    assert_eq!(assert_round_trip(frame), encoding);
}

#[test]
fn reading_rejects_ranges_below_zero_where_they_are_read() {
    let cases: [(&[u8], usize, &[u8]); 4] = [
        // First ACK Range 6 below Largest Acknowledged 5; the ACK Range that
        // follows stays unread.
        (
            &[0x02, 0x05, 0x00, 0x01, 0x06, 0x00, 0x00],
            0,
            &[0x00, 0x00],
        ),
        // 3..=5, then a gap of 2 reaches below 0.
        (&[0x02, 0x05, 0x00, 0x01, 0x02, 0x02, 0x00], 1, &[]),
        // 3..=5, gap 0 gives largest 1, length 2 reaches below 0; the second
        // ACK Range and the ECN counts stay unread.
        (
            &[
                0x03, 0x05, 0x00, 0x02, 0x02, 0x00, 0x02, 0x00, 0x00, 1, 2, 3,
            ],
            1,
            &[0x00, 0x00, 1, 2, 3],
        ),
        // 3..=5, then 1..=1, then a third range below 0.
        (
            &[
                0x02, 0x05, 0x00, 0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            2,
            &[0x00, 0x00],
        ),
    ];
    for (encoding, index, unread) in cases {
        let (error, rest) = read_error(encoding);
        assert!(
            matches!(
                error,
                ReadAckError::BelowZero {
                    source: AckBelowZeroError { index: rejected },
                } if rejected == index
            ),
            "{encoding:02x?}: {error:?}"
        );
        assert_eq!(rest, unread, "{encoding:02x?}");
        let mut input = encoding;
        let error = input.sync_read_frame_unpin(Extensions::NONE).unwrap_err();
        assert!(!error.is_incomplete());
    }
}

#[test]
fn reading_reports_the_field_that_is_cut_short() {
    let full = [
        0x03, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
    ];
    // Each field is one byte; a cut before field `n` reports field `n`, in
    // the failure of the frame type that has the field.
    let fields: [fn(&ReadAckError<Infallible>) -> bool; 8] = [
        |error| matches!(error, ReadAckError::LargestAcknowledged { .. }),
        |error| matches!(error, ReadAckError::AckDelay { .. }),
        |error| matches!(error, ReadAckError::AckRangeCount { .. }),
        |error| matches!(error, ReadAckError::FirstAckRange { .. }),
        |error| matches!(error, ReadAckError::Gap { index: 1, .. }),
        |error| matches!(error, ReadAckError::AckRangeLength { index: 1, .. }),
        |error| matches!(error, ReadAckError::Gap { index: 2, .. }),
        |error| matches!(error, ReadAckError::AckRangeLength { index: 2, .. }),
    ];
    let without_ecn: Vec<u8> = [0x02].iter().chain(&full[1..9]).copied().collect();
    for (cut, expected) in (1..).zip(fields) {
        for encoding in [&full[..cut], &without_ecn[..cut]] {
            let (error, rest) = read_error(encoding);
            assert!(expected(&error), "{encoding:02x?}: {error:?}");
            assert!(rest.is_empty());
            let (error, _) = read_frame_error(encoding);
            assert!(error.is_incomplete());
        }
    }
    let ecn_fields: [fn(&ReadAckEcnError<Infallible>) -> bool; 3] = [
        |error| matches!(error, ReadAckEcnError::Ect0Count { .. }),
        |error| matches!(error, ReadAckEcnError::Ect1Count { .. }),
        |error| matches!(error, ReadAckEcnError::EcnCeCount { .. }),
    ];
    for (cut, expected) in (9..).zip(ecn_fields) {
        let encoding = &full[..cut];
        let (error, rest) = read_frame_error(encoding);
        assert!(error.is_incomplete());
        assert!(rest.is_empty());
        let ReadFrameError::AckEcn { source } = error else {
            panic!("{encoding:02x?}: {error:?}")
        };
        assert!(expected(&source), "{encoding:02x?}: {source:?}");
    }
    // Type 0x02 ends before the ECN counts.
    assert_round_trip(read_ack(&without_ecn));
    let (error, _) = read_error(&full[..6]);
    assert_eq!(
        error.to_string(),
        "ACK Range Length of ACK Range 1 read failed"
    );
    let (error, _) = read_frame_error(&full[..10]);
    assert_eq!(error.to_string(), "ACK frame with ECN counts read failed");
    let source = std::error::Error::source(&error).map(ToString::to_string);
    assert_eq!(source.as_deref(), Some("ECT1 Count read failed"));
    // The whole encoding reads.
    assert_round_trip(read_ack(&full));
}

#[test]
fn construction_rejects_ranges_below_zero_and_narrow_counts() {
    assert_eq!(
        ack(5, 6, vec![]),
        Err(InvalidAckError::BelowZero {
            source: AckBelowZeroError { index: 0 }
        })
    );
    // 3..=5, 1..=1, then a range below 0.
    assert_eq!(
        ack(5, 2, vec![ack_range(0, 0), ack_range(0, 0)]),
        Err(InvalidAckError::BelowZero {
            source: AckBelowZeroError { index: 2 }
        })
    );
    let sixty_four = || (0..64).map(|_| ack_range(0, 0)).collect::<AckRanges>();
    let max = PacketNumber::MAX.get();
    assert_eq!(
        ack(max, 0, sixty_four().as_slice().to_vec()),
        Err(InvalidAckError::RangeCount {
            source: RangeCountError::check(64, VarIntWidth::One).unwrap_err()
        })
    );
    let error = RangeCountError::check(64, VarIntWidth::One).unwrap_err();
    assert_eq!((error.count(), error.width()), (64, VarIntWidth::One));
    assert_eq!(RangeCountError::check(63, VarIntWidth::One), Ok(()));
    // 64 ranges fit a two-byte count.
    let frame = Ack::new(
        short(PacketNumber::MAX),
        short(VarInt::ZERO),
        VarIntWidth::Two,
        short(VarInt::ZERO),
        sixty_four(),
        None,
    )
    .unwrap();
    assert_eq!(frame.packet_ranges().count(), 65);
    assert_round_trip(Frame::Ack(frame));
    // Ranges that end exactly at packet number 0 are accepted.
    let frame = ack(5, 2, vec![ack_range(0, 1)]).unwrap();
    assert_eq!(
        frame.packet_ranges().collect::<Vec<_>>(),
        ranges(&[3..=5, 0..=1])
    );
}

#[test]
fn building_rejects_unordered_ranges() {
    let cases: [(&[RangeInclusive<u64>], PacketRangesError); 7] = [
        (&[], PacketRangesError::NoRanges),
        (&[5..=3], PacketRangesError::EmptyRange { index: 0 }),
        (
            &[1..=1, 5..=6],
            PacketRangesError::NotBelowPrevious {
                index: NonZeroUsize::MIN,
            },
        ),
        // Adjacent ranges have no packet number between them.
        (
            &[5..=6, 3..=4],
            PacketRangesError::NotBelowPrevious {
                index: NonZeroUsize::MIN,
            },
        ),
        (
            &[5..=6, 3..=5],
            PacketRangesError::NotBelowPrevious {
                index: NonZeroUsize::MIN,
            },
        ),
        // An empty range is reported as empty, wherever it lies.
        (
            &[9..=9, 5..=6, 4..=2],
            PacketRangesError::EmptyRange { index: 2 },
        ),
        (
            &[9..=9, 12..=10],
            PacketRangesError::EmptyRange { index: 1 },
        ),
    ];
    for (ranges_in, error) in cases {
        let ranges_in = ranges(ranges_in);
        assert_eq!(
            Ack::from_packet_ranges(ranges_in.clone(), short(VarInt::ZERO), None),
            Err(error),
            "{ranges_in:?}"
        );
    }
    // One packet number between ranges is enough.
    let ranges_in = ranges(&[5..=6, 3..=3]);
    let ack = Ack::from_packet_ranges(ranges_in.clone(), short(VarInt::ZERO), None).unwrap();
    assert_eq!(ack.packet_ranges().collect::<Vec<_>>(), ranges_in);
}

#[test]
fn building_takes_the_ranges_in_one_pass() {
    // An iterator that cannot be cloned or restarted.
    let mut next = 20u64;
    let once = core::iter::from_fn(|| {
        let largest = next.checked_sub(3)?;
        next = largest.checked_sub(2)?;
        Some(pn(largest - 1)..=pn(largest))
    });
    let ack = Ack::from_packet_ranges(once, short(VarInt::ZERO), None).unwrap();
    let expected = ranges(&[16..=17, 11..=12, 6..=7, 1..=2]);
    assert_eq!(ack.packet_ranges().collect::<Vec<_>>(), expected);
    assert_eq!(ack.ranges().as_slice(), [ack_range(2, 1); 3]);
    let encoding = assert_round_trip(Frame::Ack(ack.clone()));
    let Frame::Ack(read) = read_ack(&encoding) else {
        unreachable!()
    };
    assert_eq!(read, ack);
}

#[test]
fn built_frames_use_the_shortest_widths() {
    // Ranges whose fields fall at the edges of each width.
    let max = PacketNumber::MAX.get();
    let cases = [
        ranges(&[63..=63]),
        ranges(&[64..=64]),
        ranges(&[0..=16_383]),
        ranges(&[0..=16_384]),
        ranges(&[max..=max, (max - 65)..=(max - 2)]),
        ranges(&[max..=max, 0..=(1 << 30)]),
    ];
    for ranges_in in cases {
        let ack = Ack::from_packet_ranges(ranges_in.clone(), short(vi(1 << 30)), None).unwrap();
        let shortest = |field: VarIntField<VarInt>| VarIntWidth::shortest(field.get());
        assert_eq!(
            ack.largest_acknowledged().width(),
            VarIntWidth::shortest(ack.largest_acknowledged().to_var_int())
        );
        assert_eq!(
            ack.first_ack_range().width(),
            shortest(ack.first_ack_range())
        );
        let count = VarInt::try_from(ack.ranges().len()).unwrap();
        assert_eq!(ack.ack_range_count_width(), VarIntWidth::shortest(count));
        for range in ack.ranges() {
            assert_eq!(range.gap.width(), shortest(range.gap));
            assert_eq!(
                range.ack_range_length.width(),
                shortest(range.ack_range_length)
            );
        }
        let encoding = write(ack.clone());
        let frame = read_ack(&encoding);
        let Frame::Ack(read) = &frame else {
            unreachable!()
        };
        assert_eq!(read.packet_ranges().collect::<Vec<_>>(), ranges_in);
        assert_eq!(*read, ack);
        assert_round_trip(frame);
    }
}
