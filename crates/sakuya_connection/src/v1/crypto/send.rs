//! Sending CRYPTO data: the bytes of the TLS handshake that this endpoint's
//! handshake engine writes, kept for each encryption level until the peer
//! acknowledges them.
//!
//! The handshake engine writes the bytes of the level it is at, and moves
//! to a later level as a step of its own (RFC 9001 §4.1.3). Writing never
//! waits and has no bound of its own: how much there is to send is up to
//! this endpoint's engine. The bytes of each level form a byte stream of
//! their own, with offsets counted from 0 (RFC 9000 §19.6), kept in a
//! [`CryptoSendBuffer`].
//!
//! Each byte of a level is in one of three states: unsent, in flight, or
//! acknowledged. A byte written is unsent; a CRYPTO frame written into a
//! packet takes the earliest unsent bytes of its level and puts them in
//! flight; when the packet is acknowledged they are acknowledged, and their
//! data can go; when it is lost they are unsent again, and are sent again
//! at the same offsets (RFC 9000 §13.3). Bytes in flight are not sent again
//! as a probe (RFC 9002 §6.2.4 allows it; this endpoint does not).
//!
//! When the keys of a level are discarded, the level's bytes go with them:
//! nothing of it is sent any more, and its packets are no longer settled
//! (RFC 9001 §4.9).

use core::{
    ops::Range,
    pin::Pin,
    task::{Context, Poll},
};
use std::collections::BTreeMap;

use bytes::{Buf, Bytes};
use nitori_call::{BorrowedReceiver, family_receiver};
use nitori_io::Write;
use sakuya_tls::engine::{CryptoLevel, CryptoOutput};
use sakuya_wire::{
    v1::frame::crypto::CryptoFrame,
    var_int::{VarInt, VarIntField, VarIntWidth},
};
use snafu::{Snafu, ensure};

use crate::{
    v1::feedback::CryptoSummary,
    write::{InFlightClass, OpenPacket, PacketPosition, PacketWriting, SummaryOf},
};

family_receiver!(impl [B: CryptoSendBuffer + Unpin + 'static] for CryptoSender<B>);

/// The handshake engine writes at the level it is at, as
/// [`CryptoSender::write`] does: the whole input is taken at once, and
/// writing never waits.
impl<B: CryptoSendBuffer + Unpin + 'static> Write for CryptoSender<B> {
    type Error = CryptoDataEndError;

    fn poll_write<'v, Input: Buf + ?Sized>(
        host: Pin<&mut BorrowedReceiver<'v, Self>>,
        _: &mut Context<'_>,
        input: &mut Input,
    ) -> Poll<Result<usize, CryptoDataEndError>>
    where
        Self: 'v,
    {
        let this = host.get_pin_mut().get_mut();
        let len = input.remaining();
        this.check_room(len)?;
        let data = input.copy_to_bytes(len);
        this.append_checked(data);
        Poll::Ready(Ok(len))
    }
}

/// The handshake engine moves the level it writes as
/// [`CryptoSender::move_output_to`] does.
impl<B: CryptoSendBuffer + Unpin + 'static> CryptoOutput for CryptoSender<B> {
    fn move_output_to<'v>(view: Pin<&mut BorrowedReceiver<'v, Self>>, level: CryptoLevel)
    where
        Self: 'v,
    {
        view.get_pin_mut().get_mut().move_output_to(level);
    }
}

/// The store of the CRYPTO data this endpoint sends at one encryption
/// level, with the state of each byte: unsent, in flight or acknowledged.
///
/// # Contract
///
/// - [`append`](Self::append) adds unsent bytes at the written end; the
///   caller never appends past [`VarInt::MAX`].
/// - [`take_unsent`](Self::take_unsent) hands out bytes of the earliest
///   unsent range, starting at its first byte, never more than it is asked
///   for and never none, and puts them in flight.
/// - [`acknowledged`](Self::acknowledged) makes every byte of the range
///   acknowledged, whether it was in flight or unsent again; the data of
///   bytes acknowledged may go. Acknowledged bytes stay acknowledged.
/// - [`lost`](Self::lost) makes the bytes of the range that are in flight
///   unsent again; acknowledged bytes stay acknowledged.
/// - Offsets of a range not written, or already acknowledged and gone, are
///   ignored.
pub trait CryptoSendBuffer {
    /// Adds `data` at the written end, unsent.
    fn append(&mut self, data: Bytes);

    /// The written end: the end of all data appended.
    fn written_end(&self) -> VarInt;

    /// The offset of the first unsent byte, if there is one.
    fn first_unsent(&self) -> Option<VarInt>;

    /// Hands out at most `max_len` bytes from the first unsent byte, with
    /// their offset, and puts them in flight; `None` if nothing is unsent
    /// or `max_len` is zero.
    fn take_unsent(&mut self, max_len: usize) -> Option<(VarInt, Bytes)>;

    /// The `len` bytes from `offset`, sent in a packet that was
    /// acknowledged, are acknowledged.
    fn acknowledged(&mut self, offset: VarInt, len: usize);

    /// The `len` bytes from `offset`, sent in a packet that was lost, are
    /// unsent again where they are in flight.
    fn lost(&mut self, offset: VarInt, len: usize);
}

/// A [`CryptoSendBuffer`] that keeps the data not acknowledged as blocks
/// keyed by their offset, and the unsent and acknowledged bytes as ranges.
#[derive(Debug, Default)]
pub struct OffsetMapCryptoSendBuffer {
    /// The blocks of data from `released_end` on, by offset; the first may
    /// start below `released_end`.
    blocks: BTreeMap<u64, Bytes>,
    written_end: u64,
    /// Every byte below it is acknowledged, and its data is gone.
    released_end: u64,
    unsent: RangeSet,
    /// The acknowledged bytes at or above `released_end`.
    acknowledged: RangeSet,
}

impl OffsetMapCryptoSendBuffer {
    /// An empty buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// The range of `len` bytes from `offset` within what is written and
    /// not released; `None` if none of it is.
    fn kept(&self, offset: VarInt, len: usize) -> Option<Range<u64>> {
        let start = offset.get().max(self.released_end);
        let end = offset
            .get()
            .saturating_add(len as u64)
            .min(self.written_end);
        (start < end).then_some(start..end)
    }

    /// Releases the data below the first byte not acknowledged.
    fn release(&mut self) {
        while let Some(first) = self.acknowledged.first()
            && first.start <= self.released_end
        {
            self.released_end = self.released_end.max(first.end);
            self.acknowledged.remove(first);
        }
        let released = self.released_end;
        while let Some(entry) = self.blocks.first_entry() {
            let start = *entry.key();
            let end = start + entry.get().len() as u64;
            if end <= released {
                entry.remove();
            } else {
                if start < released {
                    let block = entry.remove();
                    let kept = block.slice((released - start) as usize..);
                    self.blocks.insert(released, kept);
                }
                break;
            }
        }
    }
}

impl CryptoSendBuffer for OffsetMapCryptoSendBuffer {
    fn append(&mut self, data: Bytes) {
        if data.is_empty() {
            return;
        }
        let start = self.written_end;
        let end = start + data.len() as u64;
        self.blocks.insert(start, data);
        self.unsent.insert(start..end);
        self.written_end = end;
    }

    fn written_end(&self) -> VarInt {
        // invariant: the sender never appends past `VarInt::MAX`
        VarInt::try_from(self.written_end).unwrap_or(VarInt::MAX)
    }

    fn first_unsent(&self) -> Option<VarInt> {
        let first = self.unsent.first()?;
        // invariant: unsent bytes are written, below `VarInt::MAX`
        VarInt::try_from(first.start).ok()
    }

    fn take_unsent(&mut self, max_len: usize) -> Option<(VarInt, Bytes)> {
        let first = self.unsent.first()?;
        let (&block_start, block) = self.blocks.range(..=first.start).next_back()?;
        let block_end = block_start + block.len() as u64;
        let end = first
            .end
            .min(block_end)
            .min(first.start.saturating_add(max_len as u64));
        if end <= first.start {
            return None;
        }
        let from = (first.start - block_start) as usize;
        let data = block.slice(from..from + (end - first.start) as usize);
        self.unsent.remove(first.start..end);
        let offset = VarInt::try_from(first.start).ok()?;
        Some((offset, data))
    }

    fn acknowledged(&mut self, offset: VarInt, len: usize) {
        let Some(range) = self.kept(offset, len) else {
            return;
        };
        self.unsent.remove(range.clone());
        self.acknowledged.insert(range);
        self.release();
    }

    fn lost(&mut self, offset: VarInt, len: usize) {
        let Some(range) = self.kept(offset, len) else {
            return;
        };
        for gap in self.acknowledged.gaps_within(range) {
            self.unsent.insert(gap);
        }
    }
}

/// Disjoint, non-adjacent ranges of offsets, by their start.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct RangeSet(BTreeMap<u64, u64>);

impl RangeSet {
    /// The range with the lowest offsets.
    fn first(&self) -> Option<Range<u64>> {
        self.0.first_key_value().map(|(&start, &end)| start..end)
    }

    /// Adds `range`, joining what it overlaps or touches.
    fn insert(&mut self, range: Range<u64>) {
        if range.is_empty() {
            return;
        }
        let (mut start, mut end) = (range.start, range.end);
        let touching: Vec<u64> = self
            .0
            .range(..=end)
            .rev()
            .take_while(|&(_, &e)| e >= start)
            .map(|(&s, _)| s)
            .collect();
        for s in touching {
            let e = self.0.remove(&s).unwrap_or(s);
            start = start.min(s);
            end = end.max(e);
        }
        self.0.insert(start, end);
    }

    /// Takes `range` out, splitting what it cuts through.
    fn remove(&mut self, range: Range<u64>) {
        if range.is_empty() {
            return;
        }
        let overlapping: Vec<(u64, u64)> = self
            .0
            .range(..range.end)
            .rev()
            .take_while(|&(_, &e)| e > range.start)
            .map(|(&s, &e)| (s, e))
            .collect();
        for (s, e) in overlapping {
            self.0.remove(&s);
            if s < range.start {
                self.0.insert(s, range.start);
            }
            if e > range.end {
                self.0.insert(range.end, e);
            }
        }
    }

    /// The parts of `range` that no range of the set covers, in order.
    fn gaps_within(&self, range: Range<u64>) -> Vec<Range<u64>> {
        let mut gaps = Vec::new();
        let mut at = range.start;
        let first = self
            .0
            .range(..=range.start)
            .next_back()
            .map_or(range.start, |(&s, _)| s);
        for (&s, &e) in self.0.range(first..range.end) {
            if e <= at {
                continue;
            }
            if s > at {
                gaps.push(at..s);
            }
            at = at.max(e);
        }
        if at < range.end {
            gaps.push(at..range.end);
        }
        gaps
    }
}

/// CRYPTO data that would end beyond 2<sup>62</sup> − 1, the largest
/// offset a CRYPTO frame can carry (RFC 9000 §19.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("CRYPTO data at the {level:?} level would end beyond the largest offset"))]
pub struct CryptoDataEndError {
    /// The level written.
    pub level: CryptoLevel,
}

/// What is kept of one encryption level of the output.
#[derive(Debug)]
enum LevelOutput<B> {
    /// The level's bytes, while its keys are there.
    Kept(B),
    /// The level's keys were discarded, and its bytes with them.
    Discarded,
}

/// The CRYPTO output of a connection at all three encryption levels.
///
/// See the [module documentation](self) for the states of the bytes.
#[derive(Debug)]
pub struct CryptoSender<B> {
    writing: CryptoLevel,
    initial: LevelOutput<B>,
    handshake: LevelOutput<B>,
    one_rtt: LevelOutput<B>,
}

impl<B: CryptoSendBuffer + Default> Default for CryptoSender<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: CryptoSendBuffer> CryptoSender<B> {
    /// The output with an empty buffer at each level, writing Initial.
    pub fn new() -> Self
    where
        B: Default,
    {
        Self {
            writing: CryptoLevel::Initial,
            initial: LevelOutput::Kept(B::default()),
            handshake: LevelOutput::Kept(B::default()),
            one_rtt: LevelOutput::Kept(B::default()),
        }
    }

    /// The level the engine writes.
    pub fn writing(&self) -> CryptoLevel {
        self.writing
    }

    /// Appends `data` at the level the engine writes, unsent; at a level
    /// whose keys were discarded it is dropped.
    ///
    /// # Errors
    ///
    /// [`CryptoDataEndError`] if the data of the level would end beyond
    /// [`VarInt::MAX`]; nothing is taken then.
    pub fn write(&mut self, data: Bytes) -> Result<(), CryptoDataEndError> {
        self.check_room(data.len())?;
        self.append_checked(data);
        Ok(())
    }

    /// Moves the engine's writing to `level`. What was written before stays
    /// at its level. A level that is not after the one written leaves the
    /// writing where it is: the engine only moves forward.
    pub fn move_output_to(&mut self, level: CryptoLevel) {
        self.writing = self.writing.max(level);
    }

    /// Whether `level` has bytes to send: written and neither in flight
    /// nor acknowledged.
    pub fn has_unsent(&self, level: CryptoLevel) -> bool {
        self.first_unsent(level).is_some()
    }

    /// The offset of the first unsent byte of `level`, if there is one.
    pub fn first_unsent(&self, level: CryptoLevel) -> Option<VarInt> {
        match self.output(level) {
            LevelOutput::Kept(buffer) => buffer.first_unsent(),
            LevelOutput::Discarded => None,
        }
    }

    /// Whether the bytes of `level` were discarded with its keys.
    pub fn is_discarded(&self, level: CryptoLevel) -> bool {
        matches!(self.output(level), LevelOutput::Discarded)
    }

    /// Drops the bytes of `level`, whose keys were discarded: nothing of it
    /// is sent again, and what comes back of its packets is ignored.
    pub fn discard(&mut self, level: CryptoLevel) {
        *self.output_mut(level) = LevelOutput::Discarded;
    }

    /// The `len` bytes of `level` from `offset` were acknowledged.
    pub fn acknowledged(&mut self, level: CryptoLevel, offset: VarInt, len: usize) {
        if let LevelOutput::Kept(buffer) = self.output_mut(level) {
            buffer.acknowledged(offset, len);
        }
    }

    /// The `len` bytes of `level` from `offset` were lost: they are sent
    /// again where they are still in flight.
    pub fn lost(&mut self, level: CryptoLevel, offset: VarInt, len: usize) {
        if let LevelOutput::Kept(buffer) = self.output_mut(level) {
            buffer.lost(offset, len);
        }
    }

    /// Writes CRYPTO frames of the unsent bytes of `level` into `packet`,
    /// the earliest first, as many as its room takes, each with its
    /// summary; returns whether it wrote any.
    pub(crate) fn write_frames<W, P>(
        &mut self,
        level: CryptoLevel,
        packet: &mut OpenPacket<W, InFlightClass, P>,
    ) -> bool
    where
        W: PacketWriting,
        SummaryOf<W>: From<CryptoSummary>,
        P: PacketPosition,
    {
        let LevelOutput::Kept(buffer) = self.output_mut(level) else {
            return false;
        };
        let mut wrote = false;
        while let Some(offset) = buffer.first_unsent() {
            let offset_field = VarIntField::shortest(offset);
            let Some(max_len) =
                CryptoFrame::<Bytes>::max_data_len(offset_field, packet.remaining())
                    .filter(|&max_len| max_len > 0)
            else {
                break;
            };
            let Some((offset, data)) = buffer.take_unsent(max_len) else {
                break;
            };
            let len = data.len();
            // invariant: `max_data_len` measured the frame with the shortest
            // Length field against the room and the largest offset
            let width = VarIntWidth::shortest(VarInt::try_from(len).unwrap_or(VarInt::MAX));
            let frame = CryptoFrame::new(VarIntField::shortest(offset), width, data)
                .expect("the data was measured to fit the frame");
            let written = packet.write_frame(frame, CryptoSummary { level, offset, len });
            debug_assert!(written.is_ok(), "the frame was measured against the room");
            wrote = true;
        }
        wrote
    }

    /// Whether `len` more bytes fit the level written.
    fn check_room(&self, len: usize) -> Result<(), CryptoDataEndError> {
        let level = self.writing;
        let fits = match self.output(level) {
            LevelOutput::Kept(buffer) => VarInt::try_from(len)
                .ok()
                .and_then(|len| buffer.written_end().checked_add(len))
                .is_some(),
            LevelOutput::Discarded => true,
        };
        ensure!(fits, CryptoDataEndSnafu { level });
        Ok(())
    }

    /// Appends `data`, which [`check_room`](Self::check_room) let in.
    fn append_checked(&mut self, data: Bytes) {
        if let LevelOutput::Kept(buffer) = self.output_mut(self.writing) {
            buffer.append(data);
        }
    }

    fn output(&self, level: CryptoLevel) -> &LevelOutput<B> {
        match level {
            CryptoLevel::Initial => &self.initial,
            CryptoLevel::Handshake => &self.handshake,
            CryptoLevel::OneRtt => &self.one_rtt,
        }
    }

    fn output_mut(&mut self, level: CryptoLevel) -> &mut LevelOutput<B> {
        match level {
            CryptoLevel::Initial => &mut self.initial,
            CryptoLevel::Handshake => &mut self.handshake,
            CryptoLevel::OneRtt => &mut self.one_rtt,
        }
    }
}

#[cfg(test)]
mod tests;
