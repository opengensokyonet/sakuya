//! HyStart++ ([RFC 9406]): when to leave the initial slow start before a
//! loss.
//!
//! Rounds are counted by the order packets were sealed in: a round ends
//! when a packet sealed after it started is acknowledged (windowEnd,
//! §4.2). While at least [`RTT_SAMPLES`] samples of a round are in, a
//! minimum RTT at least a threshold above the previous round's moves slow
//! start to Conservative Slow Start, which grows a quarter as fast; a
//! minimum below the RTT that triggered it moves back. After
//! [`CSS_ROUNDS`] rounds of Conservative Slow Start, congestion avoidance
//! starts. It is only for the initial slow start (§4.3, SHOULD): any
//! congestion event ends it. The constants are those §4.3 recommends; the
//! window is paced, so the growth per acknowledgment is not limited
//! (`L` = infinity).
//!
//! [RFC 9406]: https://www.rfc-editor.org/rfc/rfc9406.html
use core::time::Duration;

/// `MIN_RTT_THRESH`.
const MIN_RTT_THRESHOLD: Duration = Duration::from_millis(4);
/// `MAX_RTT_THRESH`.
const MAX_RTT_THRESHOLD: Duration = Duration::from_millis(16);
/// `MIN_RTT_DIVISOR`.
const MIN_RTT_DIVISOR: u32 = 8;
/// `N_RTT_SAMPLE`: the samples a round needs before its minimum is used.
pub(crate) const RTT_SAMPLES: u32 = 8;
/// `CSS_GROWTH_DIVISOR`.
pub(crate) const CSS_GROWTH_DIVISOR: usize = 4;
/// `CSS_ROUNDS`.
pub(crate) const CSS_ROUNDS: u32 = 5;

/// The position of a packet in the order packets were sealed in.
pub(crate) type SendSequence = u64;

/// Where the initial slow start stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    /// Standard slow start, watching for a delay increase.
    SlowStart,
    /// Conservative Slow Start since the round minimum reached
    /// `baseline_min_rtt`; `rounds` rounds ended in it.
    Conservative {
        baseline_min_rtt: Duration,
        rounds: u32,
    },
    /// HyStart++ is off, or the initial slow start is over.
    Finished,
}

/// The state of HyStart++ for one congestion controller.
#[derive(Clone, Debug)]
pub(crate) struct HyStartPlusPlus {
    phase: Phase,
    next_sequence: SendSequence,
    /// `windowEnd`; `None` before the first round starts.
    window_end: Option<SendSequence>,
    last_round_min_rtt: Option<Duration>,
    current_round_min_rtt: Option<Duration>,
    rtt_samples: u32,
}

impl HyStartPlusPlus {
    /// In standard slow start when `enabled`, finished otherwise.
    pub(crate) const fn new(enabled: bool) -> Self {
        Self {
            phase: if enabled {
                Phase::SlowStart
            } else {
                Phase::Finished
            },
            next_sequence: 0,
            window_end: None,
            last_round_min_rtt: None,
            current_round_min_rtt: None,
            rtt_samples: 0,
        }
    }

    pub(crate) const fn phase(&self) -> Phase {
        self.phase
    }

    /// The sequence of a packet sealed now.
    pub(crate) fn on_sealed(&mut self) -> SendSequence {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        sequence
    }

    /// The divisor of slow start growth: 4 in Conservative Slow Start.
    pub(crate) const fn growth_divisor(&self) -> usize {
        match self.phase {
            Phase::Conservative { .. } => CSS_GROWTH_DIVISOR,
            Phase::SlowStart | Phase::Finished => 1,
        }
    }

    /// Back to `phase`, as it was before a congestion event that turned
    /// out spurious.
    pub(crate) fn restore(&mut self, phase: Phase) {
        self.phase = phase;
    }

    /// A congestion event: the initial slow start is over.
    pub(crate) fn finish(&mut self) {
        self.phase = Phase::Finished;
    }

    /// An acknowledgment in slow start, after its growth: `largest` is the
    /// largest sequence it acknowledges, `rtt_sample` the RTT it sampled.
    /// `true` when congestion avoidance starts now.
    pub(crate) fn on_ack(
        &mut self,
        largest: Option<SendSequence>,
        rtt_sample: Option<Duration>,
    ) -> bool {
        if self.phase == Phase::Finished {
            return false;
        }
        let round_ended = match (self.window_end, largest) {
            (None, _) => true,
            (Some(end), Some(largest)) => largest >= end,
            (Some(_), None) => false,
        };
        if round_ended {
            if let Phase::Conservative { rounds, .. } = &mut self.phase {
                *rounds += 1;
                if *rounds >= CSS_ROUNDS {
                    self.phase = Phase::Finished;
                    return true;
                }
            }
            self.window_end = Some(self.next_sequence);
            self.last_round_min_rtt = self.current_round_min_rtt.take();
            self.rtt_samples = 0;
        }
        if let Some(rtt) = rtt_sample {
            self.current_round_min_rtt =
                Some(self.current_round_min_rtt.map_or(rtt, |min| min.min(rtt)));
            self.rtt_samples = self.rtt_samples.saturating_add(1);
        }
        if self.rtt_samples < RTT_SAMPLES {
            return false;
        }
        let Some(current) = self.current_round_min_rtt else {
            return false;
        };
        match self.phase {
            Phase::SlowStart => {
                if let Some(last) = self.last_round_min_rtt {
                    let threshold =
                        (last / MIN_RTT_DIVISOR).clamp(MIN_RTT_THRESHOLD, MAX_RTT_THRESHOLD);
                    if current >= last.saturating_add(threshold) {
                        self.phase = Phase::Conservative {
                            baseline_min_rtt: current,
                            rounds: 0,
                        };
                    }
                }
            }
            Phase::Conservative {
                baseline_min_rtt, ..
            } => {
                if current < baseline_min_rtt {
                    self.phase = Phase::SlowStart;
                }
            }
            Phase::Finished => {}
        }
        false
    }
}

#[cfg(test)]
mod tests;
