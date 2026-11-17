//! The random numbers of the impairments: SplitMix64, seeded per datagram.

/// The SplitMix64 generator (Steele, Lea and Flood, "Fast splittable
/// pseudorandom number generators", 2014): a 64-bit state advanced by a
/// constant and mixed on output.
///
/// It is not for cryptography: it only makes the fate of each datagram a
/// function of a seed.
#[derive(Debug, Clone)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// A generator whose first output follows from `seed`.
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// The next 64-bit output.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// An output below `bound`, which is above zero; the slight bias of a
    /// remainder does not matter here.
    pub fn below(&mut self, bound: u64) -> u64 {
        debug_assert!(bound > 0, "a bound above zero");
        self.next_u64() % bound
    }
}

#[cfg(test)]
mod tests {
    use super::SplitMix64;

    #[test]
    fn the_outputs_of_seed_zero_are_those_of_the_reference() {
        // the reference implementation's first outputs for seed 0
        let mut random = SplitMix64::new(0);
        assert_eq!(random.next_u64(), 0xe220_a839_7b1d_cdaf);
        assert_eq!(random.next_u64(), 0x6e78_9e6a_a1b9_65f4);
        assert_eq!(random.next_u64(), 0x06c4_5d18_8009_454f);
    }
}
