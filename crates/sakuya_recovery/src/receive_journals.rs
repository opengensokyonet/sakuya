//! What one packet number space has received: which packet numbers were
//! processed, the ranges an ACK frame reports, and the ECN counts (RFC 9000
//! §12.3, §13.2.3, §13.4.1).
//!
//! One structure answers both whether a packet is a duplicate and what to
//! acknowledge. Below a floor every packet number counts as processed: the
//! floor rises when this side's ACK that reported a range is itself
//! acknowledged (§13.2.4), or when there are more ranges than the
//! configured limit and the oldest is dropped. A packet that arrives late
//! below the floor is dropped as a duplicate; the peer declares it lost and
//! sends its content again.
//!
//! Receiving one packet takes three steps: [`ReceiveJournals::admit`] after
//! the packet is unprotected, which hands out an [`Admission`] unless the
//! packet is a duplicate; processing the frames; and
//! [`ReceiveJournals::record`] with the admission once every frame was
//! processed (§13.1). The admission does not borrow the journals, because
//! an ACK frame in the same packet may raise the floor.
use core::{num::NonZeroUsize, ops::RangeInclusive};

use sakuya_link::EcnCodepoint;
use sakuya_wire::v1::packet_number::PacketNumber;
use smallvec::SmallVec;

/// How many ACK ranges the receive journals of one space keep at most.
///
/// RFC 9000 §13.2.3 asks to limit them without giving a number. The peer,
/// or whoever can reorder packets on the path, makes the gaps; past the
/// limit the oldest range is dropped and the floor rises.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MaxAckRanges(NonZeroUsize);

impl MaxAckRanges {
    /// 32 ranges: about 16 bytes each, about 1.5 KB for the three spaces.
    pub const DEFAULT: Self = Self(NonZeroUsize::new(32).expect("32 is not zero"));

    /// At most `ranges` ranges.
    pub const fn new(ranges: NonZeroUsize) -> Self {
        Self(ranges)
    }

    /// The number of ranges.
    pub const fn get(self) -> NonZeroUsize {
        self.0
    }
}

impl Default for MaxAckRanges {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The ECN counts of one packet number space: how many processed packets
/// arrived with each codepoint (RFC 9000 §13.4.1). They only grow.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ReceivedEcnCounts {
    /// Packets that arrived with ECT(0).
    pub ect0: u64,
    /// Packets that arrived with ECT(1).
    pub ect1: u64,
    /// Packets that arrived with CE.
    pub ce: u64,
}

impl ReceivedEcnCounts {
    /// Count one packet that arrived with `codepoint`; Not-ECT counts
    /// nothing.
    pub fn add(&mut self, codepoint: EcnCodepoint) {
        let count = match codepoint {
            EcnCodepoint::NotEct => return,
            EcnCodepoint::Ect0 => &mut self.ect0,
            EcnCodepoint::Ect1 => &mut self.ect1,
            EcnCodepoint::Ce => &mut self.ce,
        };
        *count = count.saturating_add(1);
    }
}

/// A packet admitted to be processed: not a duplicate when it was
/// admitted.
///
/// Only [`ReceiveJournals::admit`] makes one. Give it back to
/// [`ReceiveJournals::record`] once every frame of the packet was processed;
/// drop it when processing failed, and the packet is not recorded.
#[derive(Debug, PartialEq, Eq)]
pub struct Admission {
    number: PacketNumber,
}

impl Admission {
    /// The packet number.
    pub const fn number(&self) -> PacketNumber {
        self.number
    }
}

/// The packet numbers one packet number space processed, for duplicate
/// detection and for ACK frames, and its ECN counts.
///
/// `I` is the type of instants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiveJournals<I> {
    /// Every packet number below it counts as processed.
    below: PacketNumber,
    /// The processed packet numbers at or above `below`: largest first,
    /// disjoint, with at least one packet number between two ranges.
    ranges: SmallVec<[RangeInclusive<PacketNumber>; 4]>,
    largest: Option<(PacketNumber, I)>,
    ecn: Option<ReceivedEcnCounts>,
    unreported_from: Option<PacketNumber>,
}

impl<I> Default for ReceiveJournals<I> {
    fn default() -> Self {
        Self {
            below: PacketNumber::ZERO,
            ranges: SmallVec::new(),
            largest: None,
            ecn: None,
            unreported_from: None,
        }
    }
}

impl<I: Copy> ReceiveJournals<I> {
    /// Nothing received yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the packet `number` may be processed: `None` if it was
    /// processed already or is below the floor (RFC 9000 §12.3, MUST
    /// discard).
    pub fn admit(&self, number: PacketNumber) -> Option<Admission> {
        let processed = number < self.below || self.ranges.iter().any(|r| r.contains(&number));
        (!processed).then_some(Admission { number })
    }

    /// Every frame of the admitted packet was processed; it arrived at `at`
    /// with `ecn`, `None` when the link cannot read ECN.
    ///
    /// The ECN counts start at the first packet with `Some`; `None` counts
    /// nothing. A packet below the floor by now (an ACK frame in the same
    /// packet raised it) counts as processed through the floor already.
    pub fn record(&mut self, admission: Admission, at: I, ecn: Option<EcnCodepoint>) {
        let number = admission.number;
        if let Some(codepoint) = ecn {
            self.ecn.get_or_insert_default().add(codepoint);
        }
        if self.largest.is_none_or(|(largest, _)| number > largest) {
            self.largest = Some((number, at));
        }
        if number < self.below {
            return;
        }
        self.insert(number);
        self.unreported_from = Some(self.unreported_from.map_or(number, |from| from.min(number)));
    }

    /// Insert `number`, which no range contains.
    fn insert(&mut self, number: PacketNumber) {
        // ranges before `at` lie entirely above `number`; the one at `at`,
        // if any, lies entirely below it
        let at = self
            .ranges
            .iter()
            .position(|r| *r.start() <= number)
            .unwrap_or(self.ranges.len());
        let joins_above = at
            .checked_sub(1)
            .is_some_and(|above| self.ranges[above].start().checked_sub(1) == Some(number));
        let joins_below = self
            .ranges
            .get(at)
            .is_some_and(|below| below.end().checked_add(1) == Some(number));
        match (joins_above, joins_below) {
            (true, true) => {
                let below = self.ranges.remove(at);
                let above = &mut self.ranges[at - 1];
                *above = *below.start()..=*above.end();
            }
            (true, false) => {
                let above = &mut self.ranges[at - 1];
                *above = number..=*above.end();
            }
            (false, true) => {
                let below = &mut self.ranges[at];
                *below = *below.start()..=number;
            }
            (false, false) => self.ranges.insert(at, number..=number),
        }
    }

    /// The processed packet numbers at or above the floor, largest first;
    /// an ACK frame that cannot hold them all leaves out the last ones.
    pub fn ranges(&self) -> &[RangeInclusive<PacketNumber>] {
        &self.ranges
    }

    /// The largest packet number processed and when it arrived: packet
    /// number decoding (RFC 9000 §17.1) and the ACK Delay (§13.2.5) use it.
    pub fn largest(&self) -> Option<(PacketNumber, I)> {
        self.largest
    }

    /// The ECN counts; `None` until a packet arrived over a link that reads
    /// ECN. When `Some`, an ACK frame carries them (RFC 9000 §13.4.1).
    pub fn ecn_counts(&self) -> Option<&ReceivedEcnCounts> {
        self.ecn.as_ref()
    }

    /// An ACK frame with the current ranges was written into a packet.
    pub fn on_ack_written(&mut self) {
        self.unreported_from = None;
    }

    /// The peer acknowledged a packet of this side that carried an ACK
    /// frame whose Largest Acknowledged was `number` (RFC 9000 §13.2.4):
    /// the floor rises to it, but not to a packet number processed after
    /// the last ACK frame was written, which no ACK frame reported yet.
    pub fn acknowledged_up_to(&mut self, number: PacketNumber) {
        let through = match self.unreported_from {
            Some(from) => match from.checked_sub(1) {
                Some(before) => number.min(before),
                None => return,
            },
            None => number,
        };
        self.raise_floor_through(through);
    }

    fn raise_floor_through(&mut self, through: PacketNumber) {
        let Some(below) = through.checked_add(1) else {
            return;
        };
        if below <= self.below {
            return;
        }
        self.below = below;
        while let Some(last) = self.ranges.last_mut() {
            if *last.end() < below {
                self.ranges.pop();
            } else {
                if *last.start() < below {
                    *last = below..=*last.end();
                }
                break;
            }
        }
    }

    /// Where the run of processed packet numbers that ends at `number − 1`
    /// starts; numbers below the floor count as processed. `None` if
    /// `number − 1` was not processed, or `number` is zero.
    ///
    /// The acknowledgment obligation tells from it whether packets are
    /// missing below an ack-eliciting packet (RFC 9000 §13.2.1).
    pub fn received_run_below(&self, number: PacketNumber) -> Option<PacketNumber> {
        let before = number.checked_sub(1)?;
        if before < self.below {
            return Some(PacketNumber::ZERO);
        }
        let range = self.ranges.iter().find(|r| r.contains(&before))?;
        if *range.start() == self.below {
            Some(PacketNumber::ZERO)
        } else {
            Some(*range.start())
        }
    }

    /// Keep at most `max` ranges: the oldest are dropped and the floor
    /// rises above them.
    pub fn limit(&mut self, max: MaxAckRanges) {
        while self.ranges.len() > max.get().get() {
            if let Some(oldest) = self.ranges.pop() {
                self.below = oldest.end().checked_add(1).unwrap_or(PacketNumber::MAX);
            }
        }
    }
}

#[cfg(test)]
mod tests;
