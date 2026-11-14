//! What a logical path knows of the packet numbers of the 1-RTT key
//! generations (RFC 9001 §6).
//!
//! A 1-RTT packet is opened once, with the one receiving generation its Key
//! Phase and packet number select (§6.5): the current generation for the
//! current Key Phase; for the other, the previous generation when the
//! packet number is lower than every one this logical path received with
//! the current generation in the Application Data space, which holds when
//! it received none, and the next generation otherwise, as it is when the
//! previous one is discarded. No other generation is tried when the
//! selected one fails: the selection is a comparison of numbers, and no
//! second attempt reveals through its timing whether the Key Phase bit was
//! valid (§6.5, §9.5).
//!
//! The previous generation therefore opens no packet with a higher number
//! than one opened with the current generation, and while the level still
//! sends, the next generation becomes current with the first packet it
//! opens. A packet that uses older keys than a lower-numbered one (§6.4) is
//! tried with the next generation, fails authentication and is dropped: the
//! rule of §6.4, which applies to a packet the old keys opened, never meets
//! one.
//!
//! The numbers this logical path sent are kept by sending generation, which
//! is the receiving one or, after this side initiated a key update, one
//! ahead of it: the lowest number sent with each of the last two sending
//! generations the logical path sealed with. Since a later packet never
//! has older keys (§6.4), every number from the lowest one of a generation
//! up was sealed with that generation or a later one.

use sakuya_wire::v1::packet_number::PacketNumber;

/// The packet numbers of the Application Data space of one logical path
/// that the 1-RTT key generations have seen: for the current receiving
/// generation, the lowest number received and the packet that made the
/// generation current; for the last two sending generations the logical
/// path sealed with, the lowest number sent.
///
/// The received numbers belong to the receiving generation they were noted
/// for. When the connection's current receiving generation has moved on,
/// they are as good as none: another logical path promoted it, and this one
/// only learns of it when it next reads the generation. Each method takes
/// the generation it asks about; a write for another receiving generation
/// starts the received numbers afresh, and leaves the sent ones.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeyPhaseNumbers {
    generation: u64,
    lowest_received: Option<PacketNumber>,
    trigger: Option<(PacketNumber, bool)>,
    lowest_sent: Option<LowestSent>,
    lowest_sent_before: Option<LowestSent>,
}

/// The lowest packet number a logical path sent with one sending
/// generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LowestSent {
    generation: u64,
    number: PacketNumber,
}

impl KeyPhaseNumbers {
    /// Nothing noted for generation 0.
    pub fn new() -> Self {
        Self::default()
    }

    /// The lowest packet number received with `generation`, if any.
    pub fn lowest_received(&self, generation: u64) -> Option<PacketNumber> {
        self.of(generation)?.lowest_received
    }

    /// The lowest packet number sent with the sending generation
    /// `generation`, if it is one of the last two this logical path sealed
    /// with.
    pub fn lowest_sent(&self, generation: u64) -> Option<PacketNumber> {
        [self.lowest_sent, self.lowest_sent_before]
            .into_iter()
            .flatten()
            .find(|sent| sent.generation == generation)
            .map(|sent| sent.number)
    }

    /// The lowest packet number sent with a sending generation later than
    /// `generation`, as far as the last two this logical path sealed with
    /// tell; every number from it up was sealed with keys newer than those
    /// of `generation`.
    pub fn lowest_sent_after(&self, generation: u64) -> Option<PacketNumber> {
        [self.lowest_sent_before, self.lowest_sent]
            .into_iter()
            .flatten()
            .find(|sent| sent.generation > generation)
            .map(|sent| sent.number)
    }

    /// The packet that made `generation` current on this logical path, and
    /// whether an ACK frame for it has been sent with the keys of that
    /// generation; `None` when the generation was current from the start or
    /// another logical path promoted it.
    pub fn trigger(&self, generation: u64) -> Option<(PacketNumber, bool)> {
        self.of(generation)?.trigger
    }

    /// A packet numbered `number` was opened with `generation`, the
    /// current one.
    pub fn received(&mut self, generation: u64, number: PacketNumber) {
        let numbers = self.at(generation);
        numbers.lowest_received = Some(
            numbers
                .lowest_received
                .map_or(number, |lowest| lowest.min(number)),
        );
    }

    /// A packet numbered `number` was opened with the next receiving
    /// generation, which made it `generation`, the current one.
    pub fn promoted(&mut self, generation: u64, number: PacketNumber) {
        *self = Self {
            generation,
            lowest_received: Some(number),
            trigger: Some((number, false)),
            ..*self
        };
    }

    /// A packet numbered `number` is sealed with the sending generation
    /// `generation`.
    ///
    /// Sending generations only move forward, and so do the numbers sent
    /// with them; a number noted for an older generation than the last one
    /// is ignored.
    pub fn sent(&mut self, generation: u64, number: PacketNumber) {
        match self.lowest_sent {
            Some(last) if last.generation == generation => {
                self.lowest_sent = Some(LowestSent {
                    generation,
                    number: last.number.min(number),
                });
            }
            Some(last) if last.generation > generation => {}
            last => {
                self.lowest_sent_before = last;
                self.lowest_sent = Some(LowestSent { generation, number });
            }
        }
    }

    /// An ACK frame whose Largest Acknowledged is `largest` is sent in a
    /// 1-RTT packet. The packet is sealed with the current sending
    /// generation, which is never behind the receiving one: when `largest`
    /// is at least the packet that made the current receiving generation
    /// current, that packet is acknowledged with the keys it updated to
    /// (RFC 9001 §6.2).
    pub fn ack_frame_sent(&mut self, largest: PacketNumber) {
        if let Some((trigger, acknowledged @ false)) = &mut self.trigger
            && largest >= *trigger
        {
            *acknowledged = true;
        }
    }

    /// The numbers when they are of `generation`.
    fn of(&self, generation: u64) -> Option<&Self> {
        (self.generation == generation).then_some(self)
    }

    /// The numbers of `generation`, the received ones emptied first when
    /// they were of another.
    fn at(&mut self, generation: u64) -> &mut Self {
        if self.generation != generation {
            *self = Self {
                generation,
                lowest_received: None,
                trigger: None,
                ..*self
            };
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pn(number: u64) -> PacketNumber {
        PacketNumber::new(number).unwrap()
    }

    #[test]
    fn the_numbers_of_another_generation_are_none() {
        let mut numbers = KeyPhaseNumbers::new();
        numbers.received(0, pn(5));
        numbers.received(0, pn(3));
        numbers.received(0, pn(4));
        assert_eq!(numbers.lowest_received(0), Some(pn(3)));
        assert_eq!(numbers.trigger(0), None);
        numbers.promoted(1, pn(9));
        assert_eq!(numbers.lowest_received(0), None);
        assert_eq!(numbers.lowest_received(1), Some(pn(9)));
        assert_eq!(numbers.trigger(1), Some((pn(9), false)));
        // another logical path promoted generation 2
        assert_eq!(numbers.lowest_received(2), None);
        numbers.received(2, pn(12));
        assert_eq!(numbers.lowest_received(2), Some(pn(12)));
        assert_eq!(numbers.trigger(2), None);
        assert_eq!(numbers.lowest_sent(2), None);
    }

    #[test]
    fn the_sent_numbers_keep_their_own_generations() {
        let mut numbers = KeyPhaseNumbers::new();
        numbers.sent(0, pn(0));
        numbers.sent(0, pn(1));
        // this side initiated: it sends with generation 1 and still
        // receives with generation 0
        numbers.sent(1, pn(7));
        numbers.sent(1, pn(8));
        numbers.received(0, pn(4));
        assert_eq!(numbers.lowest_sent(0), Some(pn(0)));
        assert_eq!(numbers.lowest_sent(1), Some(pn(7)));
        // the peer's answer promotes generation 1; what was sent stays
        numbers.promoted(1, pn(5));
        assert_eq!(
            (numbers.lowest_sent(0), numbers.lowest_sent(1)),
            (Some(pn(0)), Some(pn(7)))
        );
        assert_eq!(numbers.lowest_sent_after(0), Some(pn(7)));
        assert_eq!(numbers.lowest_sent_after(1), None);
        // another logical path promoted generation 2
        numbers.received(2, pn(20));
        assert_eq!(numbers.lowest_sent(1), Some(pn(7)));
        // only the last two sending generations are kept
        numbers.sent(2, pn(30));
        assert_eq!(numbers.lowest_sent(0), None);
        assert_eq!(numbers.lowest_sent_after(0), Some(pn(7)));
        assert_eq!(numbers.lowest_sent_after(1), Some(pn(30)));
        // an older generation than the last one is not noted
        numbers.sent(1, pn(31));
        assert_eq!(numbers.lowest_sent(1), Some(pn(7)));
        assert_eq!(numbers.lowest_sent(2), Some(pn(30)));
    }

    #[test]
    fn a_generation_this_path_skipped_leaves_the_one_before() {
        let mut numbers = KeyPhaseNumbers::new();
        numbers.sent(0, pn(3));
        // generation 1 came and went while this logical path sent nothing
        numbers.sent(2, pn(9));
        assert_eq!(numbers.lowest_sent(1), None);
        assert_eq!(numbers.lowest_sent_after(0), Some(pn(9)));
        assert_eq!(numbers.lowest_sent_after(1), Some(pn(9)));
    }

    #[test]
    fn an_ack_frame_from_the_trigger_up_acknowledges_it() {
        let mut numbers = KeyPhaseNumbers::new();
        // no trigger: generation 0 was current from the start
        numbers.ack_frame_sent(pn(4));
        assert_eq!(numbers.trigger(0), None);
        numbers.promoted(1, pn(9));
        numbers.ack_frame_sent(pn(8));
        assert_eq!(numbers.trigger(1), Some((pn(9), false)));
        numbers.ack_frame_sent(pn(10));
        assert_eq!(numbers.trigger(1), Some((pn(9), true)));
        // a later, lower Largest Acknowledged does not take it back
        numbers.ack_frame_sent(pn(2));
        assert_eq!(numbers.trigger(1), Some((pn(9), true)));
    }
}
