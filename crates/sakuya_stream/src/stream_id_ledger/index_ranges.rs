//! Sets of stream indices kept as ranges.
use std::collections::BTreeMap;

/// A set of stream indices of one stream type, kept as ranges.
///
/// Entries map the start of a range to its end, `[start, end)`; they are
/// non-empty, disjoint and not adjacent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct IndexRanges {
    ranges: BTreeMap<u64, u64>,
}

impl IndexRanges {
    /// Adds every index of `[start, end)`, merging with the ranges it
    /// overlaps or touches. An empty range adds nothing.
    pub(super) fn insert_range(&mut self, start: u64, end: u64) {
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

    /// Adds `index`.
    pub(super) fn insert(&mut self, index: u64) {
        // invariant: a stream index is below 2^60, so `index + 1` does not
        // overflow.
        self.insert_range(index, index + 1);
    }

    /// Whether `index` is in the set.
    pub(super) fn contains(&self, index: u64) -> bool {
        self.ranges
            .range(..=index)
            .next_back()
            .is_some_and(|(_, &end)| index < end)
    }

    /// Removes `index`; returns whether it was in the set.
    pub(super) fn remove(&mut self, index: u64) -> bool {
        let Some((&start, &end)) = self.ranges.range(..=index).next_back() else {
            return false;
        };
        if index >= end {
            return false;
        }
        self.ranges.remove(&start);
        if start < index {
            self.ranges.insert(start, index);
        }
        if index + 1 < end {
            self.ranges.insert(index + 1, end);
        }
        true
    }

    /// The number of ranges kept.
    #[cfg(test)]
    pub(super) fn range_count(&self) -> usize {
        self.ranges.len()
    }
}

#[cfg(test)]
mod tests {
    use super::IndexRanges;

    #[test]
    fn ranges_merge_and_split() {
        let mut set = IndexRanges::default();
        set.insert(3);
        set.insert(1);
        assert_eq!(set.range_count(), 2);
        set.insert(2);
        assert_eq!(set.range_count(), 1);
        assert!((1..4).all(|index| set.contains(index)));
        assert!(!set.contains(0) && !set.contains(4));
        assert!(set.remove(2));
        assert!(!set.remove(2));
        assert_eq!(set.range_count(), 2);
        assert!(set.contains(1) && !set.contains(2) && set.contains(3));
        set.insert_range(0, 10);
        assert_eq!(set.range_count(), 1);
        assert!(set.remove(0) && set.remove(9));
        assert!((1..9).all(|index| set.contains(index)));
        assert!(!set.contains(0) && !set.contains(9));
        set.insert_range(5, 5);
        assert_eq!(set.range_count(), 1);
    }
}
