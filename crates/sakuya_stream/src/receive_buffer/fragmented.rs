//! A receive buffer holding received data as non-overlapping fragments in a
//! `BTreeMap`.
use super::{ReceiveBuffer, StreamDataInput, offset_add, span};
use bytes::{BufMut, Bytes};
use core::ops::Range;
use sakuya_wire::var_int::VarInt;
use std::collections::BTreeMap;

/// A [`ReceiveBuffer`] that holds received data as fragments keyed by offset.
///
/// Each entry of the map holds the bytes of `[key, key + len)`. Entries are
/// non-empty and never overlap, and delivered data is not held; adjacent
/// entries are not merged. An input keeps only the parts of its payload that
/// no entry covers and that lie at or above the read position, so a shorter
/// duplicate starting at the same offset never replaces a longer entry.
///
/// Besides the map the buffer keeps scalars that outlive the data: the read
/// position (which tells "never received" from "all delivered" when the map is
/// empty and filters old duplicates), the accounted end, the final size, and
/// the end of the received prefix `[0, n)`, so that completeness can still be
/// answered after data has been released.
///
/// Status: basic implementation; the design has not chosen a default receive
/// buffer.
#[derive(Debug, Default)]
pub struct FragmentedReceiveBuffer {
    fragments: BTreeMap<VarInt, Bytes>,
    delivered: VarInt,
    received_prefix: VarInt,
    accounted_end: VarInt,
    final_size: Option<VarInt>,
    destroyed: bool,
}

impl FragmentedReceiveBuffer {
    /// Creates an empty buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of payload bytes currently held.
    pub fn held_len(&self) -> usize {
        self.fragments.values().map(Bytes::len).sum()
    }

    /// Whether the buffer has been destroyed.
    pub fn is_destroyed(&self) -> bool {
        self.destroyed
    }

    fn fragment_end(key: VarInt, bytes: &Bytes) -> VarInt {
        offset_add(key, bytes.len()).expect("fragment ends are variable-length integers")
    }

    /// Stores the parts of `payload`, which starts at `offset`, that no
    /// fragment covers and that have not been delivered.
    fn insert(&mut self, offset: VarInt, payload: Bytes) {
        let Some(end) = offset_add(offset, payload.len()) else {
            return;
        };
        let mut start = offset.max(self.delivered);
        if let Some((&key, bytes)) = self.fragments.range(..start).next_back() {
            start = start.max(Self::fragment_end(key, bytes));
        }
        if start >= end {
            return;
        }
        let mut pieces = Vec::new();
        let mut cursor = start;
        for (&key, bytes) in self.fragments.range(start..end) {
            if key > cursor {
                pieces.push((cursor, key));
            }
            cursor = cursor.max(Self::fragment_end(key, bytes));
        }
        if cursor < end {
            pieces.push((cursor, end));
        }
        for (from, to) in pieces {
            let piece = payload.slice(span(offset, from)..span(offset, to));
            self.fragments.insert(from, piece);
        }
    }

    /// The end of the fragment covering `at`, if one does.
    fn covering_end(&self, at: VarInt) -> Option<VarInt> {
        let (&key, bytes) = self.fragments.range(..=at).next_back()?;
        let end = Self::fragment_end(key, bytes);
        (end > at).then_some(end)
    }

    fn advance_prefix(&mut self) {
        let mut prefix = self.received_prefix.max(self.delivered);
        while let Some(end) = self.covering_end(prefix) {
            prefix = end;
        }
        self.received_prefix = prefix;
    }
}

impl ReceiveBuffer for FragmentedReceiveBuffer {
    type Chunk = Bytes;

    fn receive_data(&mut self, input: StreamDataInput) {
        let (offset, end, fin, payload) = input.into_parts();
        self.accounted_end = self.accounted_end.max(end);
        if fin && self.final_size.is_none() {
            self.final_size = Some(end);
        }
        if self.destroyed || payload.is_empty() {
            return;
        }
        self.insert(offset, payload);
        self.advance_prefix();
    }

    fn receive_final_size(&mut self, final_size: VarInt) {
        self.accounted_end = self.accounted_end.max(final_size);
        if self.final_size.is_none() {
            self.final_size = Some(final_size);
        }
    }

    fn accounted_end(&self) -> VarInt {
        self.accounted_end
    }

    fn final_size(&self) -> Option<VarInt> {
        self.final_size
    }

    fn delivered_end(&self) -> VarInt {
        self.delivered
    }

    fn is_received(&self, range: Range<VarInt>) -> bool {
        let mut cursor = range.start.max(self.received_prefix);
        while cursor < range.end {
            match self.covering_end(cursor) {
                Some(end) => cursor = end,
                None => return false,
            }
        }
        true
    }

    fn read_chunk(&mut self, limit: VarInt) -> Option<Bytes> {
        let mut entry = self.fragments.first_entry()?;
        if *entry.key() != self.delivered || self.delivered >= limit {
            return None;
        }
        let room = span(self.delivered, limit);
        let chunk = if entry.get().len() > room {
            let chunk = entry.get_mut().split_to(room);
            let rest = entry.remove();
            self.fragments.insert(
                offset_add(self.delivered, room).expect("below the fragment end"),
                rest,
            );
            chunk
        } else {
            entry.remove()
        };
        self.delivered = offset_add(self.delivered, chunk.len()).expect("below the fragment end");
        Some(chunk)
    }

    fn read_into<T: BufMut + ?Sized>(&mut self, limit: VarInt, target: &mut T) -> usize {
        let mut copied = 0;
        while target.remaining_mut() > 0 && self.delivered < limit {
            let Some(mut entry) = self.fragments.first_entry() else {
                break;
            };
            if *entry.key() != self.delivered {
                break;
            }
            let count = entry
                .get()
                .len()
                .min(target.remaining_mut())
                .min(span(self.delivered, limit));
            target.put_slice(&entry.get()[..count]);
            if count == entry.get().len() {
                entry.remove();
            } else {
                let rest = entry.get_mut().split_off(count);
                entry.remove();
                self.fragments.insert(
                    offset_add(self.delivered, count).expect("below the fragment end"),
                    rest,
                );
            }
            self.delivered = offset_add(self.delivered, count).expect("below the fragment end");
            copied += count;
        }
        copied
    }

    fn release_from(&mut self, end: VarInt) {
        let end = end.max(self.delivered);
        drop(self.fragments.split_off(&end));
        if let Some((&key, bytes)) = self.fragments.range_mut(..end).next_back()
            && Self::fragment_end(key, bytes) > end
        {
            bytes.truncate(span(key, end));
        }
    }

    fn destroy(&mut self) {
        self.fragments.clear();
        self.destroyed = true;
    }
}
