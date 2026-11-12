//! What a logical path knows of the packet numbers of a 1-RTT key
//! generation (RFC 9001 §6).
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

use sakuya_wire::v1::packet_number::PacketNumber;

/// The packet numbers of the Application Data space of one logical path
/// that the current receiving generation of the 1-RTT keys has seen: the
/// lowest one received, the lowest one sent, and the packet that made the
/// generation current.
///
/// The numbers belong to the generation they were noted for. When the
/// connection's current receiving generation has moved on, they are as
/// good as none: another logical path promoted it, and this one only learns
/// of it when it next reads the generation. Each method takes the current
/// generation; a write for another generation starts afresh.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeyPhaseNumbers {
    generation: u64,
    lowest_received: Option<PacketNumber>,
    lowest_sent: Option<PacketNumber>,
    trigger: Option<(PacketNumber, bool)>,
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

    /// The lowest packet number sent with `generation`, if any.
    pub fn lowest_sent(&self, generation: u64) -> Option<PacketNumber> {
        self.of(generation)?.lowest_sent
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
            lowest_sent: None,
            trigger: Some((number, false)),
        };
    }

    /// The numbers when they are of `generation`.
    fn of(&self, generation: u64) -> Option<&Self> {
        (self.generation == generation).then_some(self)
    }

    /// The numbers of `generation`, emptied first when they were of
    /// another.
    fn at(&mut self, generation: u64) -> &mut Self {
        if self.generation != generation {
            *self = Self {
                generation,
                ..Self::default()
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
}
