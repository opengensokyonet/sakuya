//! A receive buffer holding received data as non-overlapping fragments in a
//! `BTreeMap`.
use super::{StreamDataInput, StreamReceiveBuffer, offset_add, span};
use bytes::{BufMut, Bytes};
use core::ops::Range;
use sakuya_wire::var_int::VarInt;
use std::collections::BTreeMap;

/// A [`StreamReceiveBuffer`] that holds received data as fragments keyed by offset.
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
#[derive(Debug, Default)]
pub struct FragmentedStreamReceiveBuffer {
    storage: Storage,
    delivered: VarInt,
    received_prefix: VarInt,
    accounted_end: VarInt,
    final_size: Option<VarInt>,
}

/// Whether the buffer still holds payload.
///
/// ```text
///            destroy
///   Holding ─────────▶ Destroyed
/// ```
#[derive(Debug)]
enum Storage {
    /// Payload is kept, as fragments keyed by their offset.
    Holding(BTreeMap<VarInt, Fragment>),
    /// All payload was released and new payload is not kept.
    Destroyed,
}

impl Default for Storage {
    fn default() -> Self {
        Self::Holding(BTreeMap::new())
    }
}

/// The bytes of `[key, end)`.
#[derive(Debug)]
struct Fragment {
    end: VarInt,
    bytes: Bytes,
}

impl FragmentedStreamReceiveBuffer {
    /// Creates an empty buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of payload bytes currently held.
    pub fn held_len(&self) -> usize {
        match &self.storage {
            Storage::Holding(fragments) => fragments.values().map(|f| f.bytes.len()).sum(),
            Storage::Destroyed => 0,
        }
    }

    /// Whether the buffer has been destroyed.
    pub fn is_destroyed(&self) -> bool {
        matches!(self.storage, Storage::Destroyed)
    }

    /// The end of the fragment covering `at`, if one does.
    fn covering_end(&self, at: VarInt) -> Option<VarInt> {
        let Storage::Holding(fragments) = &self.storage else {
            return None;
        };
        let (_, fragment) = fragments.range(..=at).next_back()?;
        (fragment.end > at).then_some(fragment.end)
    }

    fn advance_prefix(&mut self) {
        let mut prefix = self.received_prefix.max(self.delivered);
        while let Some(end) = self.covering_end(prefix) {
            prefix = end;
        }
        self.received_prefix = prefix;
    }
}

/// Stores the parts of `payload`, which covers `[offset, end)`, that no
/// fragment covers and that lie at or above `delivered`.
fn insert(
    fragments: &mut BTreeMap<VarInt, Fragment>,
    delivered: VarInt,
    offset: VarInt,
    end: VarInt,
    payload: &Bytes,
) {
    let mut start = offset.max(delivered);
    if let Some((_, fragment)) = fragments.range(..start).next_back() {
        start = start.max(fragment.end);
    }
    if start >= end {
        return;
    }
    let mut pieces = Vec::new();
    let mut cursor = start;
    for (&key, fragment) in fragments.range(start..end) {
        if key > cursor {
            pieces.push((cursor, key));
        }
        cursor = cursor.max(fragment.end);
    }
    if cursor < end {
        pieces.push((cursor, end));
    }
    for (from, to) in pieces {
        let bytes = payload.slice(span(offset, from)..span(offset, to));
        fragments.insert(from, Fragment { end: to, bytes });
    }
}

/// The offset `count` bytes into the fragment `[start, end)`, for a `count`
/// below the fragment's length.
fn offset_into(start: VarInt, end: VarInt, count: usize) -> VarInt {
    // invariant: `count` is below the fragment's length, so the offset lies
    // below `end`, a `VarInt`; the fallback is never taken.
    offset_add(start, count).map_or(end, |offset| offset.min(end))
}

impl StreamReceiveBuffer for FragmentedStreamReceiveBuffer {
    type Chunk = Bytes;

    fn receive_data(&mut self, input: StreamDataInput) {
        let payload_end = input.payload_end();
        let (offset, end, fin, payload) = input.into_parts();
        self.accounted_end = self.accounted_end.max(end);
        if fin && self.final_size.is_none() {
            self.final_size = Some(end);
        }
        let Storage::Holding(fragments) = &mut self.storage else {
            return;
        };
        if payload.is_empty() {
            return;
        }
        insert(fragments, self.delivered, offset, payload_end, &payload);
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
        let Storage::Holding(fragments) = &mut self.storage else {
            return None;
        };
        let mut entry = fragments.first_entry()?;
        if *entry.key() != self.delivered || self.delivered >= limit {
            return None;
        }
        let room = span(self.delivered, limit);
        if entry.get().bytes.len() > room {
            // The fragment is longer than `room`, so `room` did not saturate
            // and the rest starts exactly at `limit`.
            let chunk = entry.get_mut().bytes.split_to(room);
            let rest = entry.remove();
            fragments.insert(limit, rest);
            self.delivered = limit;
            Some(chunk)
        } else {
            let fragment = entry.remove();
            self.delivered = fragment.end;
            Some(fragment.bytes)
        }
    }

    fn read_into<T: BufMut + ?Sized>(&mut self, limit: VarInt, target: &mut T) -> usize {
        let Storage::Holding(fragments) = &mut self.storage else {
            return 0;
        };
        let mut copied = 0;
        while target.remaining_mut() > 0 && self.delivered < limit {
            let Some(mut entry) = fragments.first_entry() else {
                break;
            };
            if *entry.key() != self.delivered {
                break;
            }
            let fragment = entry.get_mut();
            let count = fragment
                .bytes
                .len()
                .min(target.remaining_mut())
                .min(span(self.delivered, limit));
            target.put_slice(&fragment.bytes[..count]);
            if count == fragment.bytes.len() {
                self.delivered = entry.remove().end;
            } else {
                let start = offset_into(self.delivered, fragment.end, count);
                let rest = Fragment {
                    end: fragment.end,
                    bytes: fragment.bytes.split_off(count),
                };
                entry.remove();
                fragments.insert(start, rest);
                self.delivered = start;
            }
            copied += count;
        }
        copied
    }

    fn release_from(&mut self, end: VarInt) {
        let Storage::Holding(fragments) = &mut self.storage else {
            return;
        };
        let end = end.max(self.delivered);
        drop(fragments.split_off(&end));
        if let Some((&key, fragment)) = fragments.range_mut(..end).next_back()
            && fragment.end > end
        {
            fragment.bytes.truncate(span(key, end));
            fragment.end = end;
        }
    }

    fn destroy(&mut self) {
        self.storage = Storage::Destroyed;
    }
}
