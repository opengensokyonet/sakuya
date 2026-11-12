//! What one packet number space of a logical path has sent: one record for
//! each packet, from sealing until it is acknowledged, or declared lost
//! and its retention ended.
//!
//! Sending a packet goes through a [`PacketSendAttempt`]: it gets the packet
//! number the packet will have if a frame is written, takes the summary of
//! each frame, and is sealed into the journals' `SealedPacket` once the
//! packet is protected. A sealed packet borrows nothing, so it can wait in
//! a batch for the link; it ends only by being handed back, when the link
//! accepted it ([`SendJournals::sent`]) or its send result is unknown
//! ([`SendJournals::send_result_unknown`]).
//!
//! Each record carries the link path it was sent on. When a link path
//! ends, the records of its packets not settled yet are taken out
//! ([`SendJournals::take_link_path`]) and handed back as lost.
//!
//! The journals are replaceable; [`DequeSendJournals`] keeps the records in
//! a deque in the order of their packet numbers.
use core::ops::RangeInclusive;
use std::collections::{VecDeque, vec_deque::Drain};

use sakuya_wire::v1::packet_number::PacketNumber;

/// Where a sent packet stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SentPacketState<I> {
    /// Sealed; the link has not accepted it yet.
    Sealed,
    /// The link accepted it at this instant; neither acknowledged nor
    /// declared lost.
    Sent(I),
    /// Declared lost, or its send result is unknown; kept until the
    /// instant to recognize a late acknowledgment. The send time is `None`
    /// when the link never accepted it.
    Lost {
        /// When the link accepted it, if it did.
        sent_at: Option<I>,
        /// Until when the record is kept.
        retain_until: I,
    },
}

/// The record of one sent packet.
///
/// `I` is the type of instants, `S` the summary of a frame, `P` what
/// identifies a link path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentPacketRecord<I, S, P> {
    /// Its packet number.
    pub number: PacketNumber,
    /// The link path it was sent on.
    pub link_path: P,
    /// Where it stands.
    pub state: SentPacketState<I>,
    /// Its size in bytes, after protection.
    pub bytes: usize,
    /// Whether it is ack-eliciting.
    pub ack_eliciting: bool,
    /// Whether it counts in the bytes in flight: it has a frame other than
    /// ACK (RFC 9002 §2).
    pub in_flight: bool,
    /// The summary of each frame, in the order they were written.
    pub summaries: Vec<S>,
}

/// One packet being written: what the send journals give for it.
pub trait PacketSendAttempt {
    /// The summary of one frame.
    type Summary;
    /// The packet once sealed.
    type Sealed;

    /// The packet number the packet gets if a frame is written.
    fn packet_number(&self) -> PacketNumber;

    /// A frame was written: its summary, whether it is ack-eliciting, and
    /// whether it makes the packet count in the bytes in flight.
    fn record_frame(&mut self, summary: Self::Summary, ack_eliciting: bool, in_flight: bool);

    /// The packet was protected; `packet_len` is its size in bytes. With a
    /// frame written, the packet number is used and the record made, and
    /// the sealed packet is handed out; without one, `None` and nothing
    /// happened.
    fn seal(self, packet_len: usize) -> Option<Self::Sealed>;
}

/// The packets one packet number space of a logical path has sent.
///
/// `S` is the summary of a frame, `I` the type of instants, `P` what
/// identifies a link path.
pub trait SendJournals<S, I, P> {
    /// One packet being written.
    type Attempt<'a>: PacketSendAttempt<Sealed = Self::SealedPacket, Summary = S>
    where
        Self: 'a;
    /// A packet sealed and recorded, which the link has not accepted yet.
    /// Only the journals make one, and it can only be handed back to them.
    type SealedPacket;
    /// The records an acknowledged range takes out.
    type Acknowledged<'a>: Iterator<Item = SentPacketRecord<I, S, P>>
    where
        Self: 'a;
    /// The records an ending link path takes out.
    type LinkPathPackets<'a>: Iterator<Item = SentPacketRecord<I, S, P>>
    where
        Self: 'a;

    /// Start writing a packet on `link_path`.
    fn start_attempt(&mut self, link_path: P) -> Self::Attempt<'_>;

    /// The packet number the next packet gets: an acknowledgment of it or
    /// of a larger one acknowledges a packet never sent.
    fn next_packet_number(&self) -> PacketNumber;

    /// The link accepted `packet` at `at`. Returns its record.
    fn sent(&mut self, packet: Self::SealedPacket, at: I) -> &SentPacketRecord<I, S, P>;

    /// The send result of `packet` is unknown: it counts as declared lost
    /// and is kept until `retain_until`. Returns its record.
    fn send_result_unknown(
        &mut self,
        packet: Self::SealedPacket,
        retain_until: I,
    ) -> &SentPacketRecord<I, S, P>;

    /// Take out the records of `range`, acknowledged: the ones still sent
    /// are newly acknowledged, the ones lost are acknowledged late.
    fn take_acknowledged(&mut self, range: &RangeInclusive<PacketNumber>)
    -> Self::Acknowledged<'_>;

    /// The packet `number`, sent, was declared lost: keep its record until
    /// `retain_until`. Returns its record; `None` if there is no sent
    /// packet with that number.
    fn declare_lost(
        &mut self,
        number: PacketNumber,
        retain_until: I,
    ) -> Option<&SentPacketRecord<I, S, P>>;

    /// Take out the records of `link_path` not acknowledged and not
    /// declared lost: the link path ends, and they are handed back as
    /// lost. The kept records of its lost packets are dropped.
    fn take_link_path(&mut self, link_path: &P) -> Self::LinkPathPackets<'_>;

    /// Drop the records of lost packets whose retention ended by `now`.
    fn discard_expired(&mut self, now: I);
}

/// Send journals that keep the records in a deque, in the order of their
/// packet numbers, and number packets one after the other.
#[derive(Debug)]
pub struct DequeSendJournals<I, S, P> {
    records: VecDeque<SentPacketRecord<I, S, P>>,
    next: PacketNumber,
}

impl<I, S, P> Default for DequeSendJournals<I, S, P> {
    fn default() -> Self {
        Self {
            records: VecDeque::new(),
            next: PacketNumber::ZERO,
        }
    }
}

impl<I, S, P> DequeSendJournals<I, S, P> {
    /// Nothing sent; the first packet number is 0.
    pub fn new() -> Self {
        Self::default()
    }

    fn index(&self, number: PacketNumber) -> Option<usize> {
        self.records
            .binary_search_by_key(&number, |r| r.number)
            .ok()
    }

    fn range(&self, range: &RangeInclusive<PacketNumber>) -> core::ops::Range<usize> {
        let start = self.records.partition_point(|r| r.number < *range.start());
        let end = self.records.partition_point(|r| r.number <= *range.end());
        start..end.max(start)
    }
}

/// One packet being written into [`DequeSendJournals`].
#[derive(Debug)]
pub struct DequeSendAttempt<'a, I, S, P> {
    journals: &'a mut DequeSendJournals<I, S, P>,
    link_path: P,
    ack_eliciting: bool,
    in_flight: bool,
    summaries: Vec<S>,
}

/// A packet sealed into [`DequeSendJournals`].
#[derive(Debug, PartialEq, Eq)]
pub struct DequeSealedPacket {
    number: PacketNumber,
}

impl<'a, I, S, P> PacketSendAttempt for DequeSendAttempt<'a, I, S, P> {
    type Summary = S;
    type Sealed = DequeSealedPacket;

    fn packet_number(&self) -> PacketNumber {
        self.journals.next
    }

    fn record_frame(&mut self, summary: S, ack_eliciting: bool, in_flight: bool) {
        self.summaries.push(summary);
        self.ack_eliciting |= ack_eliciting;
        self.in_flight |= in_flight;
    }

    fn seal(self, packet_len: usize) -> Option<DequeSealedPacket> {
        if self.summaries.is_empty() {
            return None;
        }
        let number = self.journals.next;
        // invariant: 2^62 packets cannot be sent on one connection
        self.journals.next = number
            .checked_add(1)
            .expect("packet numbers are not exhausted");
        self.journals.records.push_back(SentPacketRecord {
            number,
            link_path: self.link_path,
            state: SentPacketState::Sealed,
            bytes: packet_len,
            ack_eliciting: self.ack_eliciting,
            in_flight: self.in_flight,
            summaries: self.summaries,
        });
        Some(DequeSealedPacket { number })
    }
}

/// The records of one link path taken out of [`DequeSendJournals`].
#[derive(Debug)]
pub struct DequeLinkPathPackets<I, S, P> {
    taken: std::vec::IntoIter<SentPacketRecord<I, S, P>>,
}

impl<I, S, P> Iterator for DequeLinkPathPackets<I, S, P> {
    type Item = SentPacketRecord<I, S, P>;
    fn next(&mut self) -> Option<Self::Item> {
        self.taken.next()
    }
}

impl<I: Ord + Copy, S, P: PartialEq> SendJournals<S, I, P> for DequeSendJournals<I, S, P> {
    type Attempt<'a>
        = DequeSendAttempt<'a, I, S, P>
    where
        Self: 'a;
    type SealedPacket = DequeSealedPacket;
    type Acknowledged<'a>
        = Drain<'a, SentPacketRecord<I, S, P>>
    where
        Self: 'a;
    type LinkPathPackets<'a>
        = DequeLinkPathPackets<I, S, P>
    where
        Self: 'a;

    fn start_attempt(&mut self, link_path: P) -> DequeSendAttempt<'_, I, S, P> {
        DequeSendAttempt {
            journals: self,
            link_path,
            ack_eliciting: false,
            in_flight: false,
            summaries: Vec::new(),
        }
    }

    fn next_packet_number(&self) -> PacketNumber {
        self.next
    }

    fn sent(&mut self, packet: DequeSealedPacket, at: I) -> &SentPacketRecord<I, S, P> {
        // invariant: a sealed packet is handed back once, and only the end of
        // its link path takes its record out before that
        let index = self
            .index(packet.number)
            .expect("a sealed packet's record is kept until it is handed back");
        let record = &mut self.records[index];
        record.state = SentPacketState::Sent(at);
        record
    }

    fn send_result_unknown(
        &mut self,
        packet: DequeSealedPacket,
        retain_until: I,
    ) -> &SentPacketRecord<I, S, P> {
        let index = self
            .index(packet.number)
            .expect("a sealed packet's record is kept until it is handed back");
        let record = &mut self.records[index];
        record.state = SentPacketState::Lost {
            sent_at: None,
            retain_until,
        };
        record
    }

    fn take_acknowledged(
        &mut self,
        range: &RangeInclusive<PacketNumber>,
    ) -> Drain<'_, SentPacketRecord<I, S, P>> {
        let indices = self.range(range);
        self.records.drain(indices)
    }

    fn declare_lost(
        &mut self,
        number: PacketNumber,
        retain_until: I,
    ) -> Option<&SentPacketRecord<I, S, P>> {
        let index = self.index(number)?;
        let record = &mut self.records[index];
        let SentPacketState::Sent(sent_at) = record.state else {
            return None;
        };
        record.state = SentPacketState::Lost {
            sent_at: Some(sent_at),
            retain_until,
        };
        Some(record)
    }

    fn take_link_path(&mut self, link_path: &P) -> DequeLinkPathPackets<I, S, P> {
        let mut taken = Vec::new();
        let mut kept = VecDeque::with_capacity(self.records.len());
        for record in self.records.drain(..) {
            if record.link_path != *link_path {
                kept.push_back(record);
            } else if !matches!(record.state, SentPacketState::Lost { .. }) {
                taken.push(record);
            }
            // a lost record of the link path is dropped: a late
            // acknowledgment after the link path ended is ignored
        }
        self.records = kept;
        DequeLinkPathPackets {
            taken: taken.into_iter(),
        }
    }

    fn discard_expired(&mut self, now: I) {
        self.records.retain(|r| match r.state {
            SentPacketState::Lost { retain_until, .. } => retain_until > now,
            SentPacketState::Sealed | SentPacketState::Sent(_) => true,
        });
    }
}

#[cfg(test)]
mod tests;
