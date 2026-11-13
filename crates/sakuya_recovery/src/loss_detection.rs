//! The loss detection state of a link path in one packet number space
//! (RFC 9002 §6.1 and Appendix A.10).
//!
//! A packet enters it when the link accepts the datagram that carries it,
//! with the next consecutive sequence number of this link path in this
//! space; a packet the link never accepted never enters and takes no
//! number. The packet threshold compares these sequence numbers, so packet
//! numbers that the send journals skipped, or that other link paths of the
//! same space used, do not count. Every packet enters, including those with
//! only ACK frames: Appendix A.10 looks at every packet sent.
//!
//! On one link path in one space the packet numbers, the sequence numbers
//! and the send times grow together. A packet sent before the largest
//! acknowledged packet number of the space that is not acknowledged is
//! lost once it was sent at least the loss delay ago, or once a packet at
//! least the packet threshold later on this link path was acknowledged; so
//! the lost packets are always the oldest ones, and detection is
//! recomputed from nothing each time, as Appendix A.10 does.
//!
//! The packets declared lost at once are a batch, handed out one by one.
//! Those that count for congestion are kept as they are handed out, with
//! the value the controller gives for the batch, until a late
//! acknowledgment hands them back or the batch's retention ends.
//!
//! The state also keeps, for the probe timeout, when the last
//! ack-eliciting packet was sent and how many are outstanding (Appendix
//! A.8).
use core::{
    ops::{Add, RangeInclusive},
    time::Duration,
};

use std::collections::{VecDeque, vec_deque::Drain};

use core::iter::FusedIterator;

use sakuya_wire::v1::packet_number::PacketNumber;

use crate::{congestion::SpuriouslyLostPacket, loss::PacketThreshold};

/// A packet the link accepted, neither acknowledged nor declared lost yet.
///
/// `I` is the type of instants, `S` the congestion controller's
/// [`SentState`](crate::congestion::CongestionController::SentState).
#[derive(Debug, PartialEq, Eq)]
pub struct Outstanding<I, S> {
    /// Its consecutive sequence number on this link path, in this space.
    pub seq: u64,
    /// Its packet number.
    pub number: PacketNumber,
    /// When the link accepted it.
    pub sent_at: I,
    /// Whether it is ack-eliciting.
    pub ack_eliciting: bool,
    /// What it counts in the bytes in flight; `None` for a packet with only
    /// ACK frames, which does not count.
    pub in_flight: Option<InFlightCharge<S>>,
}

/// What a packet that counts as in flight carries for congestion control.
#[derive(Debug, PartialEq, Eq)]
pub struct InFlightCharge<S> {
    /// Its size in bytes.
    pub bytes: usize,
    /// Whether the link path was limited by the application when the
    /// packet was sealed.
    pub app_limited: bool,
    /// What the congestion controller gave for it when it was sealed.
    pub sent_state: S,
}

/// A packet declared lost that counted for congestion, kept to recognize a
/// late acknowledgment of it.
///
/// `Ls` is the congestion controller's
/// [`LossState`](crate::congestion::CongestionController::LossState) for the
/// batch it was declared lost in.
#[derive(Debug, PartialEq, Eq)]
pub struct DeclaredLost<I, Ls> {
    /// Its packet number.
    pub number: PacketNumber,
    /// When the link accepted it.
    pub sent_at: I,
    /// Its size in bytes.
    pub bytes: usize,
    /// Until when it is kept.
    pub retain_until: I,
    /// What the controller gave for the batch.
    pub loss: Ls,
}

/// A kept packet: the batch it belongs to gives its controller value and
/// its retention.
#[derive(Debug)]
struct KeptPacket<I> {
    number: PacketNumber,
    sent_at: I,
    bytes: usize,
    batch: u64,
}

/// A batch with kept packets.
#[derive(Debug)]
struct KeptBatch<I, Ls> {
    id: u64,
    retain_until: I,
    loss: Ls,
}

/// The loss detection state of a link path in one packet number space.
///
/// `I` is the type of instants; `S` and `Ls` are the congestion
/// controller's `SentState` and `LossState`.
#[derive(Debug)]
pub struct LossDetectionState<I, S, Ls> {
    outstanding: VecDeque<Outstanding<I, S>>,
    next_seq: u64,
    largest_acked_seq: Option<u64>,
    loss_time: Option<I>,
    last_ack_eliciting_sent_at: Option<I>,
    ack_eliciting_outstanding: usize,
    kept: VecDeque<KeptPacket<I>>,
    batches: VecDeque<KeptBatch<I, Ls>>,
    next_batch: u64,
}

impl<I, S, Ls> Default for LossDetectionState<I, S, Ls> {
    fn default() -> Self {
        Self {
            outstanding: VecDeque::new(),
            next_seq: 0,
            largest_acked_seq: None,
            loss_time: None,
            last_ack_eliciting_sent_at: None,
            ack_eliciting_outstanding: 0,
            kept: VecDeque::new(),
            batches: VecDeque::new(),
            next_batch: 0,
        }
    }
}

impl<I: Ord + Copy + Add<Duration, Output = I>, S, Ls> LossDetectionState<I, S, Ls> {
    /// Nothing sent yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// The link accepted the packet `number` at `sent_at`: it is appended
    /// with the next sequence number.
    ///
    /// The packet numbers and the send times of one link path in one space
    /// only grow.
    pub fn accept(
        &mut self,
        number: PacketNumber,
        sent_at: I,
        ack_eliciting: bool,
        in_flight: Option<InFlightCharge<S>>,
    ) {
        debug_assert!(
            self.outstanding
                .back()
                .is_none_or(|last| last.number < number && last.sent_at <= sent_at),
            "packets enter in the order of their numbers and send times"
        );
        self.outstanding.push_back(Outstanding {
            seq: self.next_seq,
            number,
            sent_at,
            ack_eliciting,
            in_flight,
        });
        self.next_seq += 1;
        if ack_eliciting {
            self.ack_eliciting_outstanding += 1;
            self.last_ack_eliciting_sent_at = Some(sent_at);
        }
    }

    /// The outstanding packets, oldest first.
    pub fn outstanding(&self) -> impl ExactSizeIterator<Item = &Outstanding<I, S>> {
        self.outstanding.iter()
    }

    /// The instant the time threshold declares the next packet lost, if
    /// one is waiting for it.
    pub fn loss_time(&self) -> Option<I> {
        self.loss_time
    }

    /// When the last ack-eliciting packet was sent, still outstanding or
    /// not; `None` before the first.
    pub fn last_ack_eliciting_sent_at(&self) -> Option<I> {
        self.last_ack_eliciting_sent_at
    }

    /// Whether ack-eliciting packets are outstanding.
    pub fn has_ack_eliciting_outstanding(&self) -> bool {
        self.ack_eliciting_outstanding > 0
    }

    /// The largest sequence number acknowledged on this link path in this
    /// space.
    pub fn largest_acked_seq(&self) -> Option<u64> {
        self.largest_acked_seq
    }

    /// The indices of the outstanding packets whose numbers are in `range`.
    fn indices(&self, range: &RangeInclusive<PacketNumber>) -> core::ops::Range<usize> {
        let start = self
            .outstanding
            .partition_point(|p| p.number < *range.start());
        let end = self
            .outstanding
            .partition_point(|p| p.number <= *range.end());
        start..end.max(start)
    }

    /// Take out the outstanding packets acknowledged by `range`, oldest
    /// first.
    pub fn take_acknowledged(
        &mut self,
        range: &RangeInclusive<PacketNumber>,
    ) -> Drain<'_, Outstanding<I, S>> {
        let indices = self.indices(range);
        let mut eliciting = 0;
        for packet in self.outstanding.range(indices.clone()) {
            eliciting += usize::from(packet.ack_eliciting);
            self.largest_acked_seq = Some(
                self.largest_acked_seq
                    .map_or(packet.seq, |s| s.max(packet.seq)),
            );
        }
        self.ack_eliciting_outstanding -= eliciting;
        self.outstanding.drain(indices)
    }

    /// Detect losses at `now`: `largest_acked` is the largest acknowledged
    /// packet number of the space, `delay` the [`loss_delay`] of this link
    /// path. The lost packets are the batch, oldest first; the loss time is
    /// set from what is left.
    ///
    /// [`loss_delay`]: crate::loss::loss_delay
    pub fn detect_lost(
        &mut self,
        now: I,
        largest_acked: PacketNumber,
        delay: Duration,
        packet_threshold: PacketThreshold,
    ) -> LostBatch<'_, I, S, Ls> {
        self.loss_time = None;
        let largest_acked_seq = self.largest_acked_seq;
        let lost = |p: &Outstanding<I, S>| {
            p.sent_at + delay <= now
                || largest_acked_seq
                    .is_some_and(|acked| acked >= p.seq.saturating_add(packet_threshold.get()))
        };
        let eligible = self
            .outstanding
            .partition_point(|p| p.number < largest_acked);
        let count = self
            .outstanding
            .range(..eligible)
            .take_while(|p| lost(p))
            .count();
        // send times grow, so the next eligible packet is the earliest
        self.loss_time = self
            .outstanding
            .range(count..eligible)
            .next()
            .map(|p| p.sent_at + delay);
        self.batch_of_front(count)
    }

    /// Every outstanding packet is the batch, oldest first, and the loss
    /// time is cleared: when the probe timeout declares them lost, and when
    /// the space is discarded.
    pub fn take_all(&mut self) -> LostBatch<'_, I, S, Ls> {
        self.loss_time = None;
        let count = self.outstanding.len();
        self.batch_of_front(count)
    }

    fn batch_of_front(&mut self, count: usize) -> LostBatch<'_, I, S, Ls> {
        let eliciting = self
            .outstanding
            .range(..count)
            .filter(|p| p.ack_eliciting)
            .count();
        self.ack_eliciting_outstanding -= eliciting;
        let id = self.next_batch;
        self.next_batch += 1;
        LostBatch {
            kept_from: self.kept.len(),
            state: self,
            remaining: count,
            id,
            finished: false,
        }
    }

    /// The kept lost packets, oldest first.
    pub fn declared_lost(&self) -> impl Iterator<Item = DeclaredLost<I, &Ls>> {
        self.kept.iter().filter_map(|packet| {
            let batch = self.batch(packet.batch)?;
            Some(DeclaredLost {
                number: packet.number,
                sent_at: packet.sent_at,
                bytes: packet.bytes,
                retain_until: batch.retain_until,
                loss: &batch.loss,
            })
        })
    }

    fn batch(&self, id: u64) -> Option<&KeptBatch<I, Ls>> {
        let index = self.batches.binary_search_by_key(&id, |b| b.id).ok()?;
        self.batches.get(index)
    }

    /// Take out the kept lost packets acknowledged by `range`, oldest
    /// first, each with the value of its batch.
    pub fn take_spuriously_lost(
        &mut self,
        range: &RangeInclusive<PacketNumber>,
    ) -> impl Iterator<Item = DeclaredLost<I, Ls>>
    where
        Ls: Clone,
    {
        let start = self.kept.partition_point(|p| p.number < *range.start());
        let end = self.kept.partition_point(|p| p.number <= *range.end());
        let batches = &self.batches;
        self.kept.drain(start..end.max(start)).filter_map(|packet| {
            let index = batches.binary_search_by_key(&packet.batch, |b| b.id).ok()?;
            let batch = batches.get(index)?;
            Some(DeclaredLost {
                number: packet.number,
                sent_at: packet.sent_at,
                bytes: packet.bytes,
                retain_until: batch.retain_until,
                loss: batch.loss.clone(),
            })
        })
    }

    /// Take out the kept lost packets that any of `ranges` acknowledges,
    /// batch by batch: each batch with such packets comes once, with its
    /// value and those packets, oldest first, as
    /// [`on_spurious_loss`](crate::congestion::CongestionController::on_spurious_loss)
    /// takes them.
    pub fn take_spuriously_lost_batches(
        &mut self,
        ranges: &[RangeInclusive<PacketNumber>],
    ) -> Vec<(Ls, Vec<SpuriouslyLostPacket<I>>)>
    where
        Ls: Clone,
    {
        let mut taken: Vec<(u64, Ls, Vec<SpuriouslyLostPacket<I>>)> = Vec::new();
        let batches = &self.batches;
        // kept packets are in the order of their numbers, and a batch's
        // packets come after an earlier batch's: the oldest go first
        self.kept.retain(|packet| {
            if !ranges.iter().any(|range| range.contains(&packet.number)) {
                return true;
            }
            let lost = SpuriouslyLostPacket {
                bytes: packet.bytes,
                sent_at: packet.sent_at,
            };
            match taken.last_mut() {
                Some((batch, _, packets)) if *batch == packet.batch => packets.push(lost),
                _ => {
                    if let Ok(index) = batches.binary_search_by_key(&packet.batch, |b| b.id) {
                        taken.push((packet.batch, batches[index].loss.clone(), vec![lost]));
                    }
                }
            }
            false
        });
        taken
            .into_iter()
            .map(|(_, loss, packets)| (loss, packets))
            .collect()
    }

    /// Drop the kept lost packets whose batch's retention ended by `now`.
    pub fn discard_expired(&mut self, now: I) {
        self.batches.retain(|b| b.retain_until > now);
        let batches = &self.batches;
        self.kept
            .retain(|p| batches.binary_search_by_key(&p.batch, |b| b.id).is_ok());
        // a batch whose packets were all acknowledged late has nothing left
        let kept = &self.kept;
        self.batches
            .retain(|b| kept.binary_search_by_key(&b.id, |p| p.batch).is_ok());
    }
}

/// The packets declared lost at once on a link path in one space: they
/// left the outstanding packets, and are handed out oldest first.
///
/// Those that counted for congestion are kept as they are handed out
/// ([`keep`](Self::keep)); [`finish`](Self::finish) gives the batch the
/// value the controller gave for it and how long its packets are kept.
/// Packets not handed out are dropped with the batch; packets kept by a
/// batch dropped without `finish` are not kept.
#[derive(Debug)]
pub struct LostBatch<'a, I, S, Ls> {
    state: &'a mut LossDetectionState<I, S, Ls>,
    remaining: usize,
    id: u64,
    kept_from: usize,
    finished: bool,
}

impl<I: Copy, S, Ls> LostBatch<'_, I, S, Ls> {
    /// The packets of the batch not handed out yet, oldest first.
    pub fn packets(&self) -> impl ExactSizeIterator<Item = &Outstanding<I, S>> {
        self.state.outstanding.range(..self.remaining)
    }

    /// Hand out the next packet if `take` says so.
    pub fn next_if(
        &mut self,
        take: impl FnOnce(&Outstanding<I, S>) -> bool,
    ) -> Option<Outstanding<I, S>> {
        if self.remaining == 0 || !take(self.state.outstanding.front()?) {
            return None;
        }
        self.next()
    }

    /// Keep the packet `number` of this batch, just handed out, which
    /// counted for congestion: `bytes` bytes, accepted at `sent_at`.
    pub fn keep(&mut self, number: PacketNumber, sent_at: I, bytes: usize) {
        debug_assert!(
            self.state
                .kept
                .back()
                .is_none_or(|last| last.number < number),
            "lost packets are kept in the order of their numbers"
        );
        self.state.kept.push_back(KeptPacket {
            number,
            sent_at,
            bytes,
            batch: self.id,
        });
    }

    /// The controller gave `loss` for the batch: its kept packets are kept
    /// until `retain_until`.
    pub fn finish(mut self, loss: Ls, retain_until: I) {
        self.finished = true;
        if self.state.kept.len() > self.kept_from {
            self.state.batches.push_back(KeptBatch {
                id: self.id,
                retain_until,
                loss,
            });
        }
    }
}

impl<I, S, Ls> Iterator for LostBatch<'_, I, S, Ls> {
    type Item = Outstanding<I, S>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        self.state.outstanding.pop_front()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<I, S, Ls> ExactSizeIterator for LostBatch<'_, I, S, Ls> {}

impl<I, S, Ls> FusedIterator for LostBatch<'_, I, S, Ls> {}

impl<I, S, Ls> Drop for LostBatch<'_, I, S, Ls> {
    fn drop(&mut self) {
        self.state.outstanding.drain(..self.remaining);
        if !self.finished {
            self.state.kept.truncate(self.kept_from);
        }
    }
}

#[cfg(test)]
mod tests;
