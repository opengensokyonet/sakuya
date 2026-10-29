// ACK ranges are written as arrays of inclusive ranges, some deliberately
// empty or reversed.
#![allow(clippy::single_range_in_vec_init, clippy::reversed_empty_ranges)]

use super::{
    Ack, EcnCounts, InvalidAckError,
    codec::{ReadAckError, WriteAckError, WriteAckHostExt as _},
};
use crate::{
    frame::{
        Extensions, Frame,
        codec::{ReadFrameError, ReadFrameHostExt as _},
        tests::{assert_round_trip, read_ack, vi},
    },
    packet_number::PacketNumber,
    var_int::VarInt,
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
    assert_eq!(ack.ack_delay, vi(5));
    assert_eq!(ack.largest_acknowledged(), pn(100));
    assert_eq!(ack.ranges.len(), 3);
    assert_eq!(ack.ranges.as_slice(), expected);
    assert_eq!(ack.ranges.iter().collect::<Vec<_>>(), expected);
    assert_eq!(
        ack.ecn_counts,
        Some(EcnCounts {
            ect0: vi(1),
            ect1: vi(2),
            ce: vi(3),
        })
    );
    assert!(!frame.is_ack_eliciting());
    assert!(!frame.counts_in_flight());

    let built = Ack {
        ack_delay: vi(5),
        ranges: expected.iter().cloned(),
        ecn_counts: ack.ecn_counts,
    };
    assert_eq!(built.largest_acknowledged(), Some(pn(100)));
    let mut written = Vec::new();
    written.sync_write_ack_unpin(built.clone()).unwrap();
    assert_eq!(written, encoding);
    assert_eq!(built.encoded_len(), encoding.len());
    assert_eq!(assert_round_trip(frame), encoding);
}

#[test]
fn single_packet_and_ranges_reaching_the_largest_packet_number() {
    let single = ranges(&[0..=0]);
    let built = Ack {
        ack_delay: VarInt::ZERO,
        ranges: single.iter().cloned(),
        ecn_counts: None,
    };
    let mut encoding = Vec::new();
    encoding.sync_write_ack_unpin(built).unwrap();
    assert_eq!(encoding, [0x02, 0x00, 0x00, 0x00, 0x00]);
    let frame = read_ack(&encoding);
    let Frame::Ack(ack) = &frame else {
        unreachable!()
    };
    assert_eq!(ack.ranges.as_slice(), single);
    assert_round_trip(frame);

    let max = PacketNumber::MAX.get();
    let wide = ranges(&[max - 10..=max, 0..=max - 12]);
    let built = Ack {
        ack_delay: vi(1),
        ranges: wide.iter().cloned(),
        ecn_counts: None,
    };
    let mut encoding = Vec::new();
    encoding.sync_write_ack_unpin(built).unwrap();
    let frame = read_ack(&encoding);
    let Frame::Ack(ack) = &frame else {
        unreachable!()
    };
    assert_eq!(ack.ranges.as_slice(), wide);
    assert_eq!(ack.largest_acknowledged(), PacketNumber::MAX);
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
fn writing_rejects_unordered_ranges() {
    let cases: [(&[RangeInclusive<u64>], InvalidAckError); 5] = [
        (&[], InvalidAckError::NoRange),
        (&[5..=3], InvalidAckError::Range { index: 0 }),
        (&[1..=1, 5..=6], InvalidAckError::Range { index: 1 }),
        // Adjacent ranges have no packet number between them.
        (&[5..=6, 3..=4], InvalidAckError::Range { index: 1 }),
        (&[5..=6, 3..=5], InvalidAckError::Range { index: 1 }),
    ];
    for (ranges_in, error) in cases {
        let ranges_in = ranges(ranges_in);
        let ack = Ack {
            ack_delay: VarInt::ZERO,
            ranges: ranges_in.iter().cloned(),
            ecn_counts: None,
        };
        assert_eq!(ack.validate(), Err(error), "{ranges_in:?}");
        let mut written = Vec::new();
        assert!(matches!(
            written.sync_write_ack_unpin(ack),
            Err(WriteAckError::Invalid { source }) if source == error
        ));
        assert!(written.is_empty());
    }
    // One packet number between ranges is enough.
    let ranges_in = ranges(&[5..=6, 3..=3]);
    let ack = Ack {
        ack_delay: VarInt::ZERO,
        ranges: ranges_in.iter().cloned(),
        ecn_counts: None,
    };
    assert_eq!(ack.validate(), Ok(()));
}
