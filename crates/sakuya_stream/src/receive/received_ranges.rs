//! The ranges of stream offsets that frames have stated.
use core::ops::Range;
use sakuya_wire::var_int::VarInt;
use std::collections::BTreeMap;

/// The union of the `[offset, end)` ranges of the STREAM frames of one stream.
///
/// The ranges come from frame metadata only. Whether a payload was kept,
/// trimmed at the data acceptance limit, delivered, released or destroyed does
/// not matter: a byte the peer sent is received. Entries are non-empty,
/// disjoint and not adjacent, keyed by their start; a range of one entry
/// reaching from zero is the received prefix.
#[derive(Debug, Default)]
pub(super) struct ReceivedRanges {
    ranges: BTreeMap<VarInt, VarInt>,
}

impl ReceivedRanges {
    /// Records `[start, end)`, merging it with every range it overlaps or
    /// touches. An empty range records nothing.
    pub(super) fn insert(&mut self, start: VarInt, end: VarInt) {
        if start >= end {
            return;
        }
        let mut start = start;
        let mut end = end;
        // The only range that starts at or before `start` and may reach it.
        if let Some((&key, &key_end)) = self.ranges.range(..=start).next_back()
            && key_end >= start
        {
            start = key;
            end = end.max(key_end);
            self.ranges.remove(&key);
        }
        // Ranges starting inside or right at the end of the new one.
        while let Some((&key, &key_end)) = self.ranges.range(start..=end).next() {
            end = end.max(key_end);
            self.ranges.remove(&key);
        }
        self.ranges.insert(start, end);
    }

    /// Whether every offset of `range` has been recorded. An empty range is
    /// covered.
    pub(super) fn covers(&self, range: Range<VarInt>) -> bool {
        if range.start >= range.end {
            return true;
        }
        self.ranges
            .range(..=range.start)
            .next_back()
            .is_some_and(|(_, &end)| end >= range.end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(value: u64) -> VarInt {
        VarInt::try_from(value).unwrap()
    }

    fn entries(ranges: &ReceivedRanges) -> Vec<(u64, u64)> {
        ranges
            .ranges
            .iter()
            .map(|(start, end)| (start.get(), end.get()))
            .collect()
    }

    #[test]
    fn disjoint_ranges_stay_apart() {
        let mut ranges = ReceivedRanges::default();
        ranges.insert(v(10), v(20));
        ranges.insert(v(0), v(5));
        ranges.insert(v(30), v(40));
        assert_eq!(entries(&ranges), [(0, 5), (10, 20), (30, 40)]);
        assert!(ranges.covers(v(10)..v(20)));
        assert!(ranges.covers(v(12)..v(18)));
        assert!(!ranges.covers(v(0)..v(10)));
        assert!(!ranges.covers(v(15)..v(25)));
    }

    #[test]
    fn touching_and_overlapping_ranges_merge() {
        let mut ranges = ReceivedRanges::default();
        ranges.insert(v(0), v(10));
        ranges.insert(v(20), v(30));
        ranges.insert(v(10), v(20));
        assert_eq!(entries(&ranges), [(0, 30)]);
        ranges.insert(v(40), v(50));
        ranges.insert(v(45), v(60));
        ranges.insert(v(35), v(41));
        assert_eq!(entries(&ranges), [(0, 30), (35, 60)]);
        ranges.insert(v(25), v(100));
        assert_eq!(entries(&ranges), [(0, 100)]);
    }

    #[test]
    fn contained_and_duplicate_ranges_change_nothing() {
        let mut ranges = ReceivedRanges::default();
        ranges.insert(v(0), v(100));
        ranges.insert(v(10), v(20));
        ranges.insert(v(0), v(100));
        ranges.insert(v(0), v(50));
        assert_eq!(entries(&ranges), [(0, 100)]);
    }

    #[test]
    fn empty_ranges_are_covered_and_record_nothing() {
        let mut ranges = ReceivedRanges::default();
        assert!(ranges.covers(v(7)..v(7)));
        ranges.insert(v(7), v(7));
        assert!(entries(&ranges).is_empty());
        assert!(!ranges.covers(v(0)..v(1)));
    }
}
