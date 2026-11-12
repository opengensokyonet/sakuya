//! Datagram size probing (RFC 9000 §14.3 and §14.4).
//!
//! The size a link path sends at is the smallest of the conclusion of its
//! [`PmtuPolicy`], the peer's `max_udp_payload_size`, and the link's limit
//! raised to [`MIN_DATAGRAM_SIZE`]; the caller computes it. What is
//! replaceable is the policy: how it searches with datagram size probes,
//! when it searches again, and how it detects that the current size stopped
//! getting through. A policy's conclusion is shared through the [`Link`]:
//! all link paths over the same logical link, on any connection, can read
//! it. [`BinarySearchPmtuPolicy`] is the policy sakuya provides.
use core::{
    num::{NonZeroU8, NonZeroU32, NonZeroUsize},
    ops::Add,
    time::Duration,
};
use sakuya_link::{Link, LinkId, MIN_DATAGRAM_SIZE};
use snafu::{Snafu, ensure};

/// The datagram size probing policy of a link path.
///
/// It sees the sizes and results of the packets of its link path, the
/// link's limit and shared conclusion, and the peer's limit through the
/// ceiling; it does not see the congestion state or other link paths.
pub trait PmtuPolicy<L: Link> {
    /// The size this policy has concluded works.
    fn conclusion(&self) -> usize;

    /// The start of a datagram. `ceiling` is the smaller of the link's limit
    /// and the peer's `max_udp_payload_size`; `None` when the link's limit
    /// cannot be told, and then nothing is probed.
    ///
    /// It is the only place the policy gets the link, so a conclusion
    /// reached on an ACK reaches the link at the next datagram.
    fn on_datagram_start(&mut self, link: &L, ceiling: Option<usize>);

    /// The size of the datagram size probe to send, if any; read right
    /// after [`on_datagram_start`](Self::on_datagram_start), once the
    /// handshake is complete, on the active link path only. It is not above
    /// that ceiling.
    fn probe_size(&self) -> Option<usize>;

    /// A probe of `size` bytes was acknowledged, also after it was declared
    /// lost.
    fn on_probe_acked(&mut self, size: usize, now: L::Instant);

    /// A probe of `size` bytes was not acknowledged.
    fn on_probe_failed(&mut self, size: usize, cause: PmtuProbeFailure, now: L::Instant);

    /// The sizes of the other packets an ACK acknowledged and declared
    /// lost, for detecting that the current size stopped getting through.
    fn on_packets(
        &mut self,
        acked: impl Iterator<Item = usize>,
        lost: impl Iterator<Item = usize>,
        now: L::Instant,
    );

    /// The policy's own deadline. After [`on_deadline`](Self::on_deadline)
    /// at `now`, it is `None` or later than `now`.
    fn next_deadline(&self) -> Option<L::Instant> {
        None
    }

    /// The deadline passed.
    fn on_deadline(&mut self, now: L::Instant) {
        let _ = now;
    }
}

/// Why a datagram size probe was not acknowledged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PmtuProbeFailure {
    /// It was declared lost.
    Lost,
    /// The link did not accept it: its send result is unknown. It says
    /// nothing about the network path.
    Unsent,
}

/// The constants of [`BinarySearchPmtuPolicy`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BinarySearchPmtuPolicyConfig {
    initial_size: usize,
    max_probe_failures: NonZeroU8,
    min_step: NonZeroUsize,
    raise_interval: Duration,
    black_hole_batches: NonZeroU32,
}

impl BinarySearchPmtuPolicyConfig {
    /// Start at 1200 bytes; give up a size after it was lost 3 times; stop
    /// when the search range is narrower than 20 bytes; search upward again
    /// 600 s after a search ends below the ceiling; detect a black hole
    /// after 3 batches of losses without a large packet acknowledged.
    pub const RECOMMENDED: Self = Self {
        initial_size: MIN_DATAGRAM_SIZE,
        max_probe_failures: NonZeroU8::new(3).unwrap(),
        min_step: NonZeroUsize::new(20).unwrap(),
        raise_interval: Duration::from_secs(600),
        black_hole_batches: NonZeroU32::new(3).unwrap(),
    };

    /// The constants given.
    ///
    /// `initial_size` is what a link path sends at before any probing,
    /// `max_probe_failures` how often a size may be lost before it is given
    /// up, `min_step` the narrowest range the search still halves,
    /// `raise_interval` how long after a search to search upward again,
    /// and `black_hole_batches` how many batches of losses with packets
    /// above [`MIN_DATAGRAM_SIZE`], without one of them acknowledged in
    /// between, make a black hole.
    ///
    /// # Errors
    ///
    /// [`InitialSizeBelowMinimumError`] if `initial_size` is below
    /// [`MIN_DATAGRAM_SIZE`]: smaller datagrams do not interoperate with
    /// QUIC version 1 (RFC 9000 §14).
    pub fn new(
        initial_size: usize,
        max_probe_failures: NonZeroU8,
        min_step: NonZeroUsize,
        raise_interval: Duration,
        black_hole_batches: NonZeroU32,
    ) -> Result<Self, InitialSizeBelowMinimumError> {
        ensure!(
            initial_size >= MIN_DATAGRAM_SIZE,
            InitialSizeBelowMinimumSnafu { initial_size }
        );
        Ok(Self {
            initial_size,
            max_probe_failures,
            min_step,
            raise_interval,
            black_hole_batches,
        })
    }
}

/// The initial datagram size is below 1200 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("initial datagram size {initial_size} is below {MIN_DATAGRAM_SIZE}"))]
pub struct InitialSizeBelowMinimumError {
    initial_size: usize,
}

impl InitialSizeBelowMinimumError {
    /// The rejected size, below [`MIN_DATAGRAM_SIZE`].
    pub const fn initial_size(&self) -> usize {
        self.initial_size
    }
}

/// A probing policy that halves the range between its conclusion and the
/// ceiling.
///
/// - **Search.** It probes the middle of the range from its conclusion to
///   the ceiling, below the smallest size it gave up. A probe acknowledged
///   raises the conclusion to its size; a size lost
///   `max_probe_failures` times is given up and lowers the top of the
///   range. The search ends when the range is narrower than `min_step`; if
///   the ceiling is then at least `min_step` above the conclusion, because
///   sizes were given up or the ceiling rose, it searches again
///   `raise_interval` later.
/// - **Black holes.** It counts the batches of losses that had packets
///   above [`MIN_DATAGRAM_SIZE`] since such a packet was last
///   acknowledged. At `black_hole_batches` its conclusion goes back to
///   [`MIN_DATAGRAM_SIZE`] and it searches again at once. Ordinary
///   congestion loses only part of the packets, so a large one is
///   acknowledged in between; a link that stopped carrying anything is
///   taken for a black hole too, which is harmless. It does not judge
///   [`MIN_DATAGRAM_SIZE`] a black hole: its conclusion never goes below.
/// - **Sharing.** It hands its conclusions to the link at the next datagram:
///   a confirmed size as raised, a black hole as lowered. It adopts the
///   link's shared conclusion when that changes, up or down, and on the
///   first link it starts from the larger of the shared conclusion and its
///   initial size. When the link path moves to another logical link (only
///   the port changed), it hands its conclusion to the new link.
///
/// `I` is the link's instant, and `Local` and `Peer` the types of its two
/// ends, which the identity of the last link seen carries.
#[derive(Clone, Debug)]
pub struct BinarySearchPmtuPolicy<I, Local, Peer> {
    config: BinarySearchPmtuPolicyConfig,
    conclusion: usize,
    ceiling: Option<usize>,
    /// The link last seen and its shared conclusion then.
    link: Option<(LinkId<Local, Peer>, usize)>,
    /// What to hand to the link at the next datagram.
    record: Option<ConclusionRecord>,
    search: Search<I>,
    /// Batches of losses with large packets since one was acknowledged.
    black_hole_batches: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConclusionRecord {
    Confirmed(usize),
    Lowered,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Search<I> {
    Running {
        /// The smallest size given up.
        given_up: Option<usize>,
        /// The size being probed and how often it was lost.
        failures: Option<(usize, u8)>,
    },
    Ended {
        /// When to search upward again.
        raise_at: Option<I>,
        /// The ceiling rose above the conclusion after the search ended,
        /// and no instant has been seen since to set `raise_at` from.
        raise_wanted: bool,
    },
}

impl<I> Search<I> {
    const START: Self = Self::Running {
        given_up: None,
        failures: None,
    };
}

impl<I, Local, Peer> BinarySearchPmtuPolicy<I, Local, Peer> {
    /// A policy that has not seen a link yet.
    pub const fn new(config: BinarySearchPmtuPolicyConfig) -> Self {
        Self {
            config,
            conclusion: config.initial_size,
            ceiling: None,
            link: None,
            record: None,
            search: Search::START,
            black_hole_batches: 0,
        }
    }

    /// The top of the search range: below the smallest size given up, and
    /// not above the ceiling.
    fn top(&self, given_up: Option<usize>) -> Option<usize> {
        let ceiling = self.ceiling?;
        Some(given_up.map_or(ceiling, |size| ceiling.min(size.saturating_sub(1))))
    }

    fn candidate(&self) -> Option<usize> {
        let Search::Running { given_up, .. } = self.search else {
            return None;
        };
        let top = self.top(given_up)?;
        let range = top.checked_sub(self.conclusion)?;
        (range >= self.config.min_step.get()).then(|| self.conclusion + range.div_ceil(2))
    }

    /// Whether the ceiling leaves a range the search would halve.
    fn room_above(&self) -> bool {
        self.ceiling
            .and_then(|ceiling| ceiling.checked_sub(self.conclusion))
            .is_some_and(|range| range >= self.config.min_step.get())
    }

    fn adopt(&mut self, shared: usize) {
        if shared < self.conclusion {
            self.search = Search::START;
        }
        self.conclusion = shared;
    }
}

impl<I: Copy + Add<Duration, Output = I>, Local, Peer> BinarySearchPmtuPolicy<I, Local, Peer> {
    /// Ends the search if nothing is left to probe.
    fn settle(&mut self, now: I) {
        let raise_at = Some(now + self.config.raise_interval);
        match self.search {
            Search::Running { .. } if self.candidate().is_none() => {
                self.search = Search::Ended {
                    raise_at: if self.room_above() { raise_at } else { None },
                    raise_wanted: false,
                };
            }
            Search::Ended {
                raise_wanted: true, ..
            } => {
                self.search = Search::Ended {
                    raise_at,
                    raise_wanted: false,
                };
            }
            Search::Running { .. } | Search::Ended { .. } => {}
        }
    }
}

impl<L> PmtuPolicy<L> for BinarySearchPmtuPolicy<L::Instant, L::Local, L::Peer>
where
    L: Link,
    L::Instant: Copy + Add<Duration, Output = L::Instant>,
{
    fn conclusion(&self) -> usize {
        self.conclusion
    }

    fn on_datagram_start(&mut self, link: &L, ceiling: Option<usize>) {
        let raised = match (self.ceiling, ceiling) {
            (_, None) => false,
            (None, Some(_)) => true,
            (Some(old), Some(new)) => new > old,
        };
        self.ceiling = ceiling;
        if raised
            && self.room_above()
            && let Search::Ended {
                raise_at: None,
                raise_wanted,
            } = &mut self.search
        {
            *raise_wanted = true;
        }

        match self.link.take() {
            None => {
                let shared = link.datagram_size_conclusion();
                self.conclusion = self.conclusion.max(shared);
            }
            Some((id, _)) if id != *link.id() => {
                // The port changed: the path behind it is the same.
                link.record_datagram_size_confirmed(self.conclusion);
                self.record = None;
            }
            Some((_, seen)) => {
                match self.record.take() {
                    Some(ConclusionRecord::Confirmed(size)) => {
                        link.record_datagram_size_confirmed(size);
                    }
                    Some(ConclusionRecord::Lowered) => {
                        link.record_datagram_size_lowered(MIN_DATAGRAM_SIZE);
                    }
                    None => {}
                }
                let shared = link.datagram_size_conclusion();
                if shared != seen {
                    self.adopt(shared);
                }
            }
        }
        self.link = Some((link.id().clone(), link.datagram_size_conclusion()));
    }

    fn probe_size(&self) -> Option<usize> {
        self.candidate()
    }

    fn on_probe_acked(&mut self, size: usize, now: L::Instant) {
        self.black_hole_batches = 0;
        if size > self.conclusion {
            self.conclusion = size;
            self.record = Some(ConclusionRecord::Confirmed(size));
        }
        if let Search::Running { failures, .. } = &mut self.search
            && failures.is_some_and(|(probed, _)| probed == size)
        {
            *failures = None;
        }
        self.settle(now);
    }

    fn on_probe_failed(&mut self, size: usize, cause: PmtuProbeFailure, now: L::Instant) {
        if cause == PmtuProbeFailure::Unsent {
            return;
        }
        let max_failures = self.config.max_probe_failures.get();
        if let Search::Running { given_up, failures } = &mut self.search {
            let count = match *failures {
                Some((probed, count)) if probed == size => count.saturating_add(1),
                _ => 1,
            };
            if count >= max_failures {
                *given_up = Some(given_up.map_or(size, |smallest| smallest.min(size)));
                *failures = None;
            } else {
                *failures = Some((size, count));
            }
        }
        self.settle(now);
    }

    fn on_packets(
        &mut self,
        mut acked: impl Iterator<Item = usize>,
        mut lost: impl Iterator<Item = usize>,
        now: L::Instant,
    ) {
        if acked.any(|size| size > MIN_DATAGRAM_SIZE) {
            self.black_hole_batches = 0;
        } else if lost.any(|size| size > MIN_DATAGRAM_SIZE) {
            self.black_hole_batches = self.black_hole_batches.saturating_add(1);
            if self.black_hole_batches >= self.config.black_hole_batches.get()
                && self.conclusion > MIN_DATAGRAM_SIZE
            {
                self.conclusion = MIN_DATAGRAM_SIZE;
                self.record = Some(ConclusionRecord::Lowered);
                self.search = Search::START;
                self.black_hole_batches = 0;
            }
        }
        self.settle(now);
    }

    fn next_deadline(&self) -> Option<L::Instant> {
        match self.search {
            Search::Ended { raise_at, .. } => raise_at,
            Search::Running { .. } => None,
        }
    }

    fn on_deadline(&mut self, _now: L::Instant) {
        if let Search::Ended { .. } = self.search {
            self.search = Search::START;
        }
    }
}

#[cfg(test)]
mod tests;
