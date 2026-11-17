//! What the network does to the datagrams of one direction, and the fate of
//! each.
//!
//! The kinds follow the scenarios of the QUIC network simulator that the
//! interop runner uses (drop by number, drop at a rate with a cap on
//! consecutive drops, corruption of a byte near the start, periodic
//! blackholes), with duplication and reordering added; a datagram's fate
//! depends only on the seed, its direction, its number and the drops just
//! before it, so a run that sends the same datagrams meets the same fates.

use core::time::Duration;

use super::random::SplitMix64;

/// The direction of a datagram: towards the server's address, or away from
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// To the server.
    ToServer,
    /// To the client.
    ToClient,
}

impl Direction {
    fn seed_mix(self) -> u64 {
        match self {
            Self::ToServer => 0x5345_5256_4552_0000,
            Self::ToClient => 0x434c_4945_4e54_0000,
        }
    }
}

/// A probability, in millionths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Probability(u32);

impl Probability {
    /// Never.
    pub const NEVER: Self = Self(0);

    /// `percent` in a hundred; above a hundred counts as a hundred.
    pub const fn percent(percent: u32) -> Self {
        Self::per_million(percent.saturating_mul(10_000))
    }

    /// `per_mille` in a thousand; above a thousand counts as a thousand.
    pub const fn per_mille(per_mille: u32) -> Self {
        Self::per_million(per_mille.saturating_mul(1_000))
    }

    /// `per_million` in a million; above a million counts as a million.
    pub const fn per_million(per_million: u32) -> Self {
        if per_million > 1_000_000 {
            Self(1_000_000)
        } else {
            Self(per_million)
        }
    }

    fn happens(self, random: &mut SplitMix64) -> bool {
        // one draw whatever the probability, so that later draws keep their
        // values
        random.below(1_000_000) < u64::from(self.0)
    }
}

/// Dropping at a rate, at most `burst` in a row: the drop-rate scenario of
/// the network simulator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomLoss {
    /// How likely each datagram is dropped.
    pub rate: Probability,
    /// How many datagrams in a row may be dropped at most; zero drops none.
    pub burst: u32,
}

/// Delaying some datagrams further, so that later ones overtake them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reorder {
    /// How likely each datagram is held back.
    pub rate: Probability,
    /// How much longer a held back datagram takes.
    pub delay: Duration,
}

/// Periods in which every datagram is dropped: the blackhole scenario of
/// the network simulator. From the network's start, the path carries for
/// `on`, drops for `off`, and so on, `repeat` times; then it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Blackhole {
    /// How long the path carries before each blackhole.
    pub on: Duration,
    /// How long each blackhole lasts.
    pub off: Duration,
    /// How many blackholes there are.
    pub repeat: u32,
}

impl Blackhole {
    fn drops_at(&self, since_start: Duration) -> bool {
        let period = self.on + self.off;
        if period.is_zero() {
            return false;
        }
        let period_nanos = period.as_nanos();
        let number = since_start.as_nanos() / period_nanos;
        if number >= u128::from(self.repeat) {
            return false;
        }
        since_start.as_nanos() % period_nanos >= self.on.as_nanos()
    }
}

/// What the network does to the datagrams of one direction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DirectionImpairments {
    /// How long every datagram takes to cross.
    pub delay: Duration,
    /// The numbers of the datagrams to drop, counted from one as they come
    /// to the network: the droplist scenario of the network simulator.
    pub drop_list: Vec<u64>,
    /// Dropping at a rate.
    pub loss: Option<RandomLoss>,
    /// How likely a datagram has one of its first 50 bytes replaced by
    /// another value, as the corrupt-rate scenario of the network simulator
    /// does.
    pub corrupt: Probability,
    /// How likely a datagram arrives twice.
    pub duplicate: Probability,
    /// Holding some datagrams back.
    pub reorder: Option<Reorder>,
    /// Periods of dropping everything.
    pub blackhole: Option<Blackhole>,
    /// The largest datagram the path carries, silently dropping larger
    /// ones; `None` carries any. It can be changed while running
    /// ([`MemoryNetwork::set_path_mtu`](super::MemoryNetwork::set_path_mtu)).
    pub path_mtu: Option<usize>,
}

/// What the network does to the datagrams of each direction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Impairments {
    /// To the server.
    pub to_server: DirectionImpairments,
    /// To the client.
    pub to_client: DirectionImpairments,
}

impl Impairments {
    /// The same impairments in both directions.
    pub fn both(impairments: DirectionImpairments) -> Self {
        Self {
            to_server: impairments.clone(),
            to_client: impairments,
        }
    }

    pub(super) fn of(&self, direction: Direction) -> &DirectionImpairments {
        match direction {
            Direction::ToServer => &self.to_server,
            Direction::ToClient => &self.to_client,
        }
    }

    pub(super) fn of_mut(&mut self, direction: Direction) -> &mut DirectionImpairments {
        match direction {
            Direction::ToServer => &mut self.to_server,
            Direction::ToClient => &mut self.to_client,
        }
    }
}

/// Why the network dropped a datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DropCause {
    /// Its number is in the drop list.
    Listed,
    /// It fell in a blackhole.
    Blackhole,
    /// It is larger than the path carries.
    PathMtu,
    /// It was dropped at the loss rate.
    Random,
    /// Its destination is the address a client had before it was rebound,
    /// or no binding has it.
    NoDestination,
    /// The destination binding holds as many links not yet accepted as it
    /// may.
    AcceptBacklog,
}

/// What happened to one datagram that came to the network.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DatagramFate {
    /// Its number in its direction, from one.
    pub number: u64,
    /// Its length.
    pub len: usize,
    /// Why it was dropped, if it was.
    pub dropped: Option<DropCause>,
    /// The offset of the byte replaced, if one was.
    pub corrupted: Option<usize>,
    /// Whether it arrives twice.
    pub duplicated: bool,
    /// Whether it was held back to be reordered.
    pub reordered: bool,
}

/// The counters of one direction.
#[derive(Debug, Default)]
pub(super) struct DirectionCount {
    numbered: u64,
    random_drops_in_a_row: u32,
}

/// What the network does with one datagram: drop it, or deliver it, maybe
/// changed, maybe twice, after a delay.
pub(super) enum Verdict {
    Drop,
    Deliver {
        delay: Duration,
        corrupt: Option<(usize, u8)>,
        duplicate: bool,
    },
}

/// The fate of the next datagram of `direction`, of `len` bytes,
/// `since_start` after the network's start.
pub(super) fn decide(
    seed: u64,
    direction: Direction,
    impairments: &DirectionImpairments,
    count: &mut DirectionCount,
    len: usize,
    since_start: Duration,
) -> (Verdict, DatagramFate) {
    count.numbered += 1;
    let number = count.numbered;
    let mut random = SplitMix64::new(seed ^ direction.seed_mix() ^ number.rotate_left(17));
    // every draw is made whatever the impairments, in a fixed order, so the
    // values for one datagram never depend on another's fate
    let lost = impairments
        .loss
        .is_some_and(|loss| loss.rate.happens(&mut random));
    let corrupted = impairments.corrupt.happens(&mut random);
    let offset_draw = random.next_u64();
    let value_draw = random.next_u64();
    let duplicated = impairments.duplicate.happens(&mut random);
    let reordered = impairments
        .reorder
        .is_some_and(|reorder| reorder.rate.happens(&mut random));

    let mut fate = DatagramFate {
        number,
        len,
        dropped: None,
        corrupted: None,
        duplicated: false,
        reordered: false,
    };
    let dropped = if impairments.drop_list.contains(&number) {
        Some(DropCause::Listed)
    } else if impairments
        .blackhole
        .is_some_and(|blackhole| blackhole.drops_at(since_start))
    {
        Some(DropCause::Blackhole)
    } else if impairments.path_mtu.is_some_and(|mtu| len > mtu) {
        Some(DropCause::PathMtu)
    } else if lost
        && impairments
            .loss
            .is_some_and(|loss| count.random_drops_in_a_row < loss.burst)
    {
        Some(DropCause::Random)
    } else {
        None
    };
    if dropped == Some(DropCause::Random) {
        count.random_drops_in_a_row += 1;
    } else {
        count.random_drops_in_a_row = 0;
    }
    if let Some(cause) = dropped {
        fate.dropped = Some(cause);
        return (Verdict::Drop, fate);
    }
    let corrupt = (corrupted && len > 0).then(|| {
        let window = len.min(50) as u64;
        // invariant: the window holds at most 50 bytes
        let offset = usize::try_from(offset_draw % window).expect("below 50");
        // another value than the byte has: added below 256, never zero
        let change = u8::try_from(1 + value_draw % 255).expect("below 256");
        (offset, change)
    });
    fate.corrupted = corrupt.map(|(offset, _)| offset);
    fate.duplicated = duplicated;
    fate.reordered = reordered;
    let delay = impairments.delay
        + impairments
            .reorder
            .filter(|_| reordered)
            .map_or(Duration::ZERO, |reorder| reorder.delay);
    (
        Verdict::Deliver {
            delay,
            corrupt,
            duplicate: duplicated,
        },
        fate,
    )
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use super::{
        Blackhole, Direction, DirectionCount, DirectionImpairments, DropCause, Probability,
        RandomLoss, decide,
    };

    fn fates(impairments: &DirectionImpairments, seed: u64, n: u64) -> Vec<Option<DropCause>> {
        let mut count = DirectionCount::default();
        (0..n)
            .map(|_| {
                decide(
                    seed,
                    Direction::ToServer,
                    impairments,
                    &mut count,
                    1200,
                    Duration::ZERO,
                )
                .1
                .dropped
            })
            .collect()
    }

    #[test]
    fn the_same_seed_drops_the_same_datagrams_and_no_more_in_a_row_than_the_burst() {
        let impairments = DirectionImpairments {
            loss: Some(RandomLoss {
                rate: Probability::percent(30),
                burst: 3,
            }),
            ..DirectionImpairments::default()
        };
        let first = fates(&impairments, 42, 2000);
        assert_eq!(first, fates(&impairments, 42, 2000));
        assert_ne!(first, fates(&impairments, 43, 2000));
        let dropped = first.iter().filter(|fate| fate.is_some()).count();
        // about 30%, a little less for the cap
        assert!((400..700).contains(&dropped), "{dropped} of 2000 dropped");
        let mut in_a_row = 0;
        for fate in &first {
            in_a_row = if fate.is_some() { in_a_row + 1 } else { 0 };
            assert!(in_a_row <= 3);
        }
    }

    #[test]
    fn the_listed_numbers_are_dropped_counting_from_one() {
        let impairments = DirectionImpairments {
            drop_list: vec![2, 3],
            ..DirectionImpairments::default()
        };
        assert_eq!(
            fates(&impairments, 0, 4),
            [None, Some(DropCause::Listed), Some(DropCause::Listed), None]
        );
    }

    #[test]
    fn a_blackhole_drops_in_its_periods_only() {
        let blackhole = Blackhole {
            on: Duration::from_secs(5),
            off: Duration::from_secs(2),
            repeat: 2,
        };
        let at = |s| blackhole.drops_at(Duration::from_millis(s));
        assert!(!at(0) && !at(4_999) && at(5_000) && at(6_999) && !at(7_000));
        assert!(at(12_000) && !at(14_000) && !at(19_000) && !at(20_000));
    }

    #[test]
    fn a_corrupted_datagram_has_one_of_its_first_fifty_bytes_changed() {
        let impairments = DirectionImpairments {
            corrupt: Probability::percent(100),
            ..DirectionImpairments::default()
        };
        let mut count = DirectionCount::default();
        for _ in 0..200 {
            let (_, fate) = decide(
                7,
                Direction::ToClient,
                &impairments,
                &mut count,
                1200,
                Duration::ZERO,
            );
            assert!(fate.corrupted.is_some_and(|offset| offset < 50));
        }
    }
}
