// ACK ranges are written as arrays of inclusive ranges, some deliberately
// empty or reversed.
#![allow(clippy::single_range_in_vec_init, clippy::reversed_empty_ranges)]

use super::{
    Ack, AckRange, AckRanges, EcnCounts, InvalidAckError, PacketRangesError,
    codec::{ReadAckError, WriteAckError, WriteAckHostExt as _},
};
use crate::{
    frame::{
        Extensions, Frame,
        codec::{ReadFrameError, ReadFrameHostExt as _},
        tests::{assert_round_trip, read_ack, short, vi, wide},
    },
    packet_number::PacketNumber,
    var_int::{VarInt, VarIntWidth},
};
use core::ops::RangeInclusive;

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

/// Writes `frame` with [`codec::write_ack`](super::codec::write_ack).
fn write<R: Iterator<Item = AckRange> + Clone>(frame: Ack<R>) -> Vec<u8> {
    let mut written = Vec::new();
    written.sync_write_ack_unpin(frame).unwrap();
    written
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
    assert_eq!(
        *ack,
        Ack {
            largest_acknowledged: short(pn(100)),
            ack_delay: short(vi(5)),
            ack_range_count_width: VarIntWidth::One,
            first_ack_range: short(vi(3)),
            ranges: AckRanges::from(vec![ack_range(1, 4), ack_range(0, 0)]),
            ecn_counts: Some(ecn_counts),
        }
    );
    assert_eq!(ack.ranges.len(), 2);
    assert_eq!(ack.ranges.iter().collect::<Vec<_>>(), ack.ranges.as_slice());
    assert_eq!(ack.packet_ranges().collect::<Vec<_>>(), expected);
    assert!(!frame.is_ack_eliciting());
    assert!(!frame.counts_in_flight());

    // The same frame from its packet number ranges.
    let built =
        Ack::from_packet_ranges(expected.iter().cloned(), short(vi(5)), Some(ecn_counts)).unwrap();
    assert_eq!(built.largest_acknowledged, ack.largest_acknowledged);
    assert_eq!(built.first_ack_range, ack.first_ack_range);
    assert_eq!(
        built.ranges.clone().collect::<Vec<_>>(),
        ack.ranges.as_slice()
    );
    assert_eq!(built.packet_ranges().collect::<Vec<_>>(), expected);
    assert_eq!(built.encoded_len(), encoding.len());
    assert_eq!(write(built), encoding);
    assert_eq!(assert_round_trip(frame), encoding);
}

#[test]
fn single_packet_and_ranges_reaching_the_largest_packet_number() {
    let single = ranges(&[0..=0]);
    let built = Ack::from_packet_ranges(single.iter().cloned(), short(VarInt::ZERO), None).unwrap();
    let encoding = write(built);
    assert_eq!(encoding, [0x02, 0x00, 0x00, 0x00, 0x00]);
    let frame = read_ack(&encoding);
    let Frame::Ack(ack) = &frame else {
        unreachable!()
    };
    assert_eq!(ack.packet_ranges().collect::<Vec<_>>(), single);
    assert!(ack.ranges.is_empty());
    assert_round_trip(frame);

    let max = PacketNumber::MAX.get();
    let wide_ranges = ranges(&[max - 10..=max, 0..=max - 12]);
    let built = Ack::from_packet_ranges(wide_ranges.iter().cloned(), short(vi(1)), None).unwrap();
    let encoding = write(built);
    let frame = read_ack(&encoding);
    let Frame::Ack(ack) = &frame else {
        unreachable!()
    };
    assert_eq!(ack.packet_ranges().collect::<Vec<_>>(), wide_ranges);
    assert_eq!(ack.largest_acknowledged.get(), PacketNumber::MAX);
    assert_eq!(
        ack.ranges.as_slice(),
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
    assert_eq!(ack.largest_acknowledged, wide(pn(5), VarIntWidth::Two));
    assert_eq!(ack.ack_delay, wide(VarInt::ZERO, VarIntWidth::Two));
    assert_eq!(ack.ack_range_count_width, VarIntWidth::Two);
    assert_eq!(ack.first_ack_range, wide(vi(1), VarIntWidth::Two));
    assert_eq!(
        ack.ranges.as_slice(),
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
fn ranges_below_zero_are_rejected() {
    let cases: [(&[u8], u64); 3] = [
        // First ACK Range 6 below Largest Acknowledged 5.
        (&[0x02, 0x05, 0x00, 0x00, 0x06], 0),
        // 3..=5, then a gap of 2 reaches below 0.
        (&[0x02, 0x05, 0x00, 0x01, 0x02, 0x02, 0x00], 1),
        // 3..=5, gap 0 gives largest 1, length 2 reaches below 0.
        (&[0x02, 0x05, 0x00, 0x01, 0x02, 0x00, 0x02], 1),
    ];
    for (encoding, index) in cases {
        let mut input = encoding;
        let error = input.sync_read_frame_unpin(Extensions::NONE).unwrap_err();
        assert!(
            matches!(
                error,
                ReadFrameError::Ack {
                    source: ReadAckError::Range { index: rejected },
                    ..
                } if rejected == index
            ),
            "{encoding:02x?}: {error:?}"
        );
        assert_eq!(error.frame_type(), Some(vi(2)));
        assert!(!error.is_incomplete());
    }
}

#[test]
fn writing_rejects_ranges_below_zero_and_narrow_counts() {
    let base = Ack {
        largest_acknowledged: short(pn(5)),
        ack_delay: short(VarInt::ZERO),
        ack_range_count_width: VarIntWidth::One,
        first_ack_range: short(vi(2)),
        ranges: AckRanges::default(),
        ecn_counts: None,
    };
    let cases = [
        (
            Ack {
                first_ack_range: short(vi(6)),
                ..base.clone()
            },
            InvalidAckError::BelowZero { index: 0 },
        ),
        (
            Ack {
                ranges: AckRanges::from(vec![ack_range(0, 0), ack_range(0, 0)]),
                ..base.clone()
            },
            InvalidAckError::BelowZero { index: 2 },
        ),
        (
            Ack {
                ranges: (0..64).map(|_| ack_range(0, 0)).collect(),
                largest_acknowledged: short(PacketNumber::MAX),
                ..base.clone()
            },
            InvalidAckError::RangeCount {
                count: 64,
                width: VarIntWidth::One,
            },
        ),
    ];
    for (ack, error) in cases {
        assert_eq!(ack.validate(), Err(error), "{ack:?}");
        // Iteration stops before the range below zero.
        if let InvalidAckError::BelowZero { index } = error {
            assert_eq!(ack.packet_ranges().count(), index);
        }
        let mut written = Vec::new();
        assert!(matches!(
            written.sync_write_ack_unpin(ack.as_iter()),
            Err(WriteAckError::Invalid { source }) if source == error
        ));
        assert!(written.is_empty());
    }
    // 64 ranges fit a two-byte count.
    let ack = Ack {
        ranges: (0..64).map(|_| ack_range(0, 0)).collect(),
        largest_acknowledged: short(PacketNumber::MAX),
        ack_range_count_width: VarIntWidth::Two,
        ..base
    };
    assert_eq!(ack.validate(), Ok(()));
    assert_round_trip(Frame::Ack(ack));
}

#[test]
fn building_rejects_unordered_ranges() {
    let cases: [(&[RangeInclusive<u64>], PacketRangesError); 5] = [
        (&[], PacketRangesError::NoRange),
        (&[5..=3], PacketRangesError::Range { index: 0 }),
        (&[1..=1, 5..=6], PacketRangesError::Range { index: 1 }),
        // Adjacent ranges have no packet number between them.
        (&[5..=6, 3..=4], PacketRangesError::Range { index: 1 }),
        (&[5..=6, 3..=5], PacketRangesError::Range { index: 1 }),
    ];
    for (ranges_in, error) in cases {
        let ranges_in = ranges(ranges_in);
        assert_eq!(
            Ack::from_packet_ranges(ranges_in.iter().cloned(), short(VarInt::ZERO), None)
                .map(|_| ())
                .unwrap_err(),
            error,
            "{ranges_in:?}"
        );
    }
    // One packet number between ranges is enough.
    let ranges_in = ranges(&[5..=6, 3..=3]);
    let ack =
        Ack::from_packet_ranges(ranges_in.iter().cloned(), short(VarInt::ZERO), None).unwrap();
    assert_eq!(ack.validate(), Ok(()));
    assert_eq!(ack.packet_ranges().collect::<Vec<_>>(), ranges_in);
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
        let ack =
            Ack::from_packet_ranges(ranges_in.iter().cloned(), short(vi(1 << 30)), None).unwrap();
        let fields = [
            ack.largest_acknowledged.width(),
            ack.first_ack_range.width(),
        ];
        assert_eq!(
            fields,
            [
                VarIntWidth::shortest(ack.largest_acknowledged.to_var_int()),
                VarIntWidth::shortest(ack.first_ack_range.get()),
            ]
        );
        for range in ack.ranges.clone() {
            assert_eq!(range.gap, short(range.gap.get()));
            assert_eq!(range.ack_range_length, short(range.ack_range_length.get()));
        }
        let encoding = write(ack.clone());
        let frame = read_ack(&encoding);
        let Frame::Ack(read) = &frame else {
            unreachable!()
        };
        assert_eq!(read.packet_ranges().collect::<Vec<_>>(), ranges_in);
        assert_eq!(read.ranges.as_slice(), ack.ranges.collect::<Vec<_>>());
        assert_round_trip(frame);
    }
}
