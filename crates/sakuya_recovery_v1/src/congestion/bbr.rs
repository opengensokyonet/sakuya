//! BBRv3 ([draft-ietf-ccwg-bbr-07]).
//!
//! BBR builds a model of the path from delivery rate samples (§4.1) and
//! RTT samples: the maximum bandwidth `max_bw`, the minimum RTT `min_rtt`,
//! the degree of ACK aggregation, and bounds on the data in flight learned
//! from losses. Its pacing rate, send quantum and congestion window follow
//! that model and the state it is in (§5.6): [`Startup`] doubles the
//! sending rate each round until the bandwidth stops growing or losses are
//! too high, [`Drain`] empties the queue Startup built, the four ProbeBW
//! states ([`ProbeBwDown`], [`ProbeBwCruise`], [`ProbeBwRefill`],
//! [`ProbeBwUp`]) cycle through sending slower than, as fast as and faster
//! than the path delivers, and [`ProbeRtt`] holds the data in flight low
//! to measure the minimum RTT again when it has not been refreshed for
//! 10 s.
//!
//! [`Bbr`] is its own pacer: it implements [`Pacer`] with its pacing rate
//! and ignores the window and RTT of [`PacingInput`]. Its bucket holds what
//! the pacing rate sends in two timer granularities, as
//! [`TokenBucketPacer`](crate::pacing::TokenBucketPacer)'s does, not the
//! send quantum: the draft's send quantum bounds one aggregate of a pacer
//! that releases at any instant, and this one releases at most once per
//! timer granularity.
//!
//! # The events of the trait
//!
//! - [`on_packet_sealed`](CongestionController::on_packet_sealed) is
//!   OnTransmit (HandleRestartFromIdle, §5.4) and OnPacketSent (§4.1.2.2);
//!   a packet sealed while the link path was limited by the application
//!   first marks the bubble of §4.1.2.4 (MarkConnectionAppLimited). The
//!   packet's [`BbrDeliverySnapshot`] is its per-packet state.
//! - [`on_lost`](CongestionController::on_lost) is HandleLostPacket for
//!   each packet (§5.5.10.2); the first loss after the end of a loss
//!   recovery starts one (§5.6.4.4).
//! - [`on_acked`](CongestionController::on_acked) is UpdateRateSample for
//!   each packet and UpdateOnACK (§5.2.3). The recovery ends when a packet
//!   sent after it started is acknowledged, as in RFC 9002 §7.3.2.
//! - [`on_spurious_loss`](CongestionController::on_spurious_loss) counts
//!   the bytes as delivered (§2.2, SHOULD), and once every packet of the
//!   latest loss episode turned out to have arrived it undoes that episode
//!   (HandleSpuriousLossDetection, §5.5.11).
//! - [`on_ce`](CongestionController::on_ce) treats CE marks as congestion
//!   (§3.7, MUST): each mark counts as a lost maximum datagram in the loss
//!   signals of the round. The episode it falls in can no longer be undone.
//! - [`on_persistent_congestion`](CongestionController::on_persistent_congestion)
//!   is the retransmission timeout of §5.6.4.4: it saves the window and
//!   takes it to the minimum window (RFC 9002 §7.6.2, MUST); the next ACK
//!   raises it to `MinPipeCwnd` (§5.6.4.6), and the end of the recovery
//!   restores the saved window.
//!
//! Volumes are in bytes, with the maximum datagram size as `C.SMSS`; rates
//! are in bytes per second. The random choices of ProbeBW come from a
//! deterministic generator seeded by [`BbrConfig`].
//!
//! [draft-ietf-ccwg-bbr-07]: https://datatracker.ietf.org/doc/html/draft-ietf-ccwg-bbr-07
//! [`Startup`]: BbrState::Startup
//! [`Drain`]: BbrState::Drain
//! [`ProbeBwDown`]: BbrState::ProbeBwDown
//! [`ProbeBwCruise`]: BbrState::ProbeBwCruise
//! [`ProbeBwRefill`]: BbrState::ProbeBwRefill
//! [`ProbeBwUp`]: BbrState::ProbeBwUp
//! [`ProbeRtt`]: BbrState::ProbeRtt
use super::{
    CongestionContext, CongestionController, CongestionWindowConfig, InFlightPacket, RemovedPacket,
    SealedPacket, SpuriouslyLostPacket,
    delivery_rate::{DeliveryRateSampler, DeliverySnapshot, RateSample, RateSampleBuilder, volume},
};
use crate::{
    checked_duration_since,
    ecn::{EcnContext, EcnPolicy, ect0_testing_marking},
    pacing::{Pacer, PacingInput},
    pto::PtoPolicy,
};
use core::{
    num::{NonZeroU64, NonZeroUsize},
    ops::{Add, Sub},
    time::Duration,
};
use sakuya_link::EcnMarking;
use snafu::{OptionExt, Snafu, ensure};

/// `BBR.StartupPacingGain`, about 4 × ln 2 (§2.5).
const STARTUP_PACING_GAIN: f64 = 2.77;
/// `BBR.DrainPacingGain` (§2.5).
const DRAIN_PACING_GAIN: f64 = 0.5;
/// The pacing gain of ProbeBW_DOWN (§5.3.3.1).
const PROBE_BW_DOWN_PACING_GAIN: f64 = 0.9;
/// The pacing gain of ProbeBW_UP (§5.3.3.5).
const PROBE_BW_UP_PACING_GAIN: f64 = 1.25;
/// `BBR.DefaultCwndGain` (§2.6).
const DEFAULT_CWND_GAIN: f64 = 2.0;
/// The window gain of ProbeBW_UP (§5.3.3.5).
const PROBE_BW_UP_CWND_GAIN: f64 = 2.25;
/// `BBR.ProbeRTTCwndGain` (§2.16.2).
const PROBE_RTT_CWND_GAIN: f64 = 0.5;
/// `BBR.PacingMarginPercent` (§2.5).
const PACING_MARGIN_PERCENT: f64 = 1.0;
/// `BBR.LossThresh` (§2.8).
const LOSS_THRESH: f64 = 0.02;
/// `BBR.Beta` (§2.8).
const BETA: f64 = 0.7;
/// `BBR.Headroom` (§2.8).
const HEADROOM: f64 = 0.15;
/// `BBR.MinPipeCwnd`, in maximum datagrams (§2.8).
const MIN_PIPE_CWND_DATAGRAMS: usize = 4;
/// `BBR.ExtraAckedFilterLen`, in rounds (§2.12).
const EXTRA_ACKED_FILTER_LEN: u64 = 10;
/// `BBR.StartupFullLossCnt` (§2.13).
const STARTUP_FULL_LOSS_COUNT: u64 = 6;
/// The growth below which a round counts towards a full pipe (§5.3.1.2).
const FULL_BW_GROWTH: f64 = 1.25;
/// The rounds without that growth that make a full pipe (§5.3.1.2).
const FULL_BW_ROUNDS: u32 = 3;
/// `BBR.MinRTTFilterLen` (§2.16.1); every flow MUST use it (§5.3.4.2).
const MIN_RTT_FILTER_LEN: Duration = Duration::from_secs(10);
/// `BBR.ProbeRTTDuration` (§2.16.2).
const PROBE_RTT_DURATION: Duration = Duration::from_millis(200);
/// The upper bound of the send quantum (§5.6.3).
const MAX_SEND_QUANTUM: usize = 64 * 1024;
/// The interval of the send quantum (§5.6.3).
const SEND_QUANTUM_INTERVAL: Duration = Duration::from_millis(1);
/// The upper bound of the rounds of the Reno coexistence time scale
/// (§5.3.3.8.3).
const RENO_ROUNDS_BOUND: u64 = 63;
/// The bound on `BBR.bw_probe_up_rounds` (§5.3.3.9).
const PROBE_UP_ROUNDS_BOUND: u32 = 30;
/// The least time between bandwidth probes (`T_bbr`, §5.3.3.8.2).
const PROBE_WAIT_BASE: Duration = Duration::from_secs(2);
/// A volume without bound: `Infinity` of the pseudocode.
const UNBOUNDED: usize = usize::MAX;
/// The seed of [`BbrConfig::recommended`].
const RECOMMENDED_SEED: NonZeroU64 = NonZeroU64::new(0x9e37_79b9_7f4a_7c15).unwrap();

/// The constants of [`Bbr`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BbrConfig {
    window: CongestionWindowConfig,
    timer_granularity: Duration,
    max_burst_datagrams: NonZeroUsize,
    seed: NonZeroU64,
}

impl BbrConfig {
    /// The constants given: the initial and minimum windows, the precision
    /// of the clock's timers, the most datagrams the pacer lets go at once,
    /// and the seed of the random choices.
    ///
    /// The pacer's burst is what the pacing rate sends in two timer
    /// granularities, at least the initial window and at most
    /// `max_burst_datagrams` datagrams, the burst limit of
    /// [`TokenBucketPacer`](crate::pacing::TokenBucketPacer).
    ///
    /// # Errors
    ///
    /// - [`BbrConfigError::MaxBurstBelowInitialWindow`] if
    ///   `max_burst_datagrams` is fewer datagrams than the initial window.
    /// - [`BbrConfigError::ZeroSeed`] if `seed` is zero: the generator
    ///   would give only zeros.
    pub fn new(
        window: CongestionWindowConfig,
        timer_granularity: Duration,
        max_burst_datagrams: NonZeroUsize,
        seed: u64,
    ) -> Result<Self, BbrConfigError> {
        let initial_window_datagrams = window.initial_window().datagrams();
        ensure!(
            max_burst_datagrams.get() >= initial_window_datagrams,
            MaxBurstBelowInitialWindowSnafu {
                max_burst_datagrams,
                initial_window_datagrams,
            }
        );
        let seed = NonZeroU64::new(seed).context(ZeroSeedSnafu)?;
        Ok(Self {
            window,
            timer_granularity,
            max_burst_datagrams,
            seed,
        })
    }

    /// The defaults for a clock whose timers fire with a precision of
    /// `timer_granularity`: the windows of
    /// [`CongestionWindowConfig::RECOMMENDED`], a burst of at most
    /// [`DEFAULT_MAX_BURST_DATAGRAMS`](crate::pacing::DEFAULT_MAX_BURST_DATAGRAMS)
    /// and a fixed seed.
    pub const fn recommended(timer_granularity: Duration) -> Self {
        Self {
            window: CongestionWindowConfig::RECOMMENDED,
            timer_granularity,
            max_burst_datagrams: crate::pacing::DEFAULT_MAX_BURST_DATAGRAMS,
            seed: RECOMMENDED_SEED,
        }
    }

    /// The initial and minimum windows.
    pub const fn window(&self) -> CongestionWindowConfig {
        self.window
    }

    /// The precision of the clock's timers.
    pub const fn timer_granularity(&self) -> Duration {
        self.timer_granularity
    }

    /// The most datagrams the pacer lets go at once.
    pub const fn max_burst_datagrams(&self) -> NonZeroUsize {
        self.max_burst_datagrams
    }

    /// The seed of the random choices, above zero.
    pub const fn seed(&self) -> u64 {
        self.seed.get()
    }

    /// The same constants with another seed.
    pub(crate) const fn with_seed(self, seed: NonZeroU64) -> Self {
        Self { seed, ..self }
    }
}

/// A [`BbrConfig`] breaks a rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
pub enum BbrConfigError {
    /// The burst limit holds fewer datagrams than the initial window.
    #[snafu(display(
        "burst limit of {max_burst_datagrams} datagrams is below the initial window of {initial_window_datagrams}"
    ))]
    MaxBurstBelowInitialWindow {
        /// The rejected limit.
        max_burst_datagrams: NonZeroUsize,
        /// The datagrams of the initial window, above the limit.
        initial_window_datagrams: usize,
    },
    /// The seed of the random choices is zero.
    #[snafu(display("random seed is zero"))]
    ZeroSeed,
}

/// The state of [`Bbr`] in its state machine (§5.1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BbrState {
    /// The sending rate doubles each round, until the bandwidth stops
    /// growing or losses are too high (§5.3.1).
    Startup,
    /// The queue Startup built drains (§5.3.2).
    Drain,
    /// Sending slower than the path delivers, to leave headroom
    /// (§5.3.3.1).
    ProbeBwDown,
    /// Sending as fast as the path delivers (§5.3.3.2).
    ProbeBwCruise,
    /// Refilling the pipe for one round before probing (§5.3.3.3).
    ProbeBwRefill,
    /// Sending faster than the path delivers, to probe for more bandwidth
    /// (§5.3.3.4).
    ProbeBwUp,
    /// Holding the data in flight low to measure the minimum RTT
    /// (§5.3.4).
    ProbeRtt,
}

impl BbrState {
    /// IsInAProbeBWState.
    const fn is_probe_bw(self) -> bool {
        matches!(
            self,
            Self::ProbeBwDown | Self::ProbeBwCruise | Self::ProbeBwRefill | Self::ProbeBwUp
        )
    }

    /// IsProbingBW.
    const fn is_probing_bw(self) -> bool {
        matches!(self, Self::Startup | Self::ProbeBwRefill | Self::ProbeBwUp)
    }

    /// `BBR.pacing_gain` in this state (§5.6.1).
    const fn pacing_gain(self) -> f64 {
        match self {
            Self::Startup => STARTUP_PACING_GAIN,
            Self::Drain => DRAIN_PACING_GAIN,
            Self::ProbeBwDown => PROBE_BW_DOWN_PACING_GAIN,
            Self::ProbeBwCruise | Self::ProbeBwRefill | Self::ProbeRtt => 1.0,
            Self::ProbeBwUp => PROBE_BW_UP_PACING_GAIN,
        }
    }

    /// `BBR.cwnd_gain` in this state (§5.6.1).
    const fn cwnd_gain(self) -> f64 {
        match self {
            Self::ProbeBwUp => PROBE_BW_UP_CWND_GAIN,
            Self::ProbeRtt => PROBE_RTT_CWND_GAIN,
            _ => DEFAULT_CWND_GAIN,
        }
    }
}

/// The delivery state of the link path when a packet was sealed (the
/// per-packet state of §4.1.2.1.2): what [`Bbr`] keeps for each packet in
/// flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BbrDeliverySnapshot<I>(DeliverySnapshot<I>);

/// Which loss episode a packet counted as lost belongs to: what [`Bbr`]
/// keeps for each batch of losses, to undo the episode if all its losses
/// turn out to be spurious (§5.5.11).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BbrLossEpisode(u64);

/// The BBRv3 congestion controller and pacer, with the default probe
/// timeout and ECN policies, those of [`NewReno`](super::new_reno::NewReno).
#[derive(Clone, Debug)]
pub struct Bbr<I> {
    config: BbrConfig,
    /// `C.SMSS`.
    max_datagram_size: usize,
    /// `C.cwnd`.
    cwnd: usize,
    /// `C.pacing_rate`, in bytes per second.
    pacing_rate: f64,
    /// `C.send_quantum`.
    send_quantum: usize,
    bucket: PacingBucket<I>,
    rate_sampler: DeliveryRateSampler<I>,
    state: BbrState,
    random: Xorshift64,
    /// Whether an ACK gave an RTT sample yet: the first one sets the
    /// initial pacing rate again from the smoothed RTT (§5.6.2).
    rtt_seen: bool,

    // rounds (§5.5.1)
    round_count: u64,
    round_start: bool,
    next_round_delivered: u64,
    rounds_since_probe_up: u64,
    /// Whether the window was full in this round and in the one before:
    /// `C.is_cwnd_limited` is either.
    cwnd_limited_this_round: bool,
    cwnd_limited_last_round: bool,
    idle_restart: bool,
    drain_start_round: u64,

    // the model (§2.9, §5.5)
    /// The two slots of the `BBR.max_bw` filter: the cycle of
    /// `cycle_count` and the one before.
    max_bw_slots: [f64; 2],
    cycle_count: u64,
    max_bw: f64,
    bw_shortterm: f64,
    bw: f64,
    min_rtt: Option<MinRtt<I>>,
    min_rtt_expired: bool,
    extra_acked: usize,
    extra_acked_filter: WindowedMax,
    extra_acked_interval_start: Option<I>,
    extra_acked_delivered: usize,
    max_inflight: usize,
    inflight_longterm: usize,
    inflight_shortterm: usize,
    bw_latest: f64,
    inflight_latest: usize,

    // congestion signals (§5.5.10)
    loss_round_delivered: u64,
    loss_round_start: bool,
    is_loss_in_round: bool,
    loss_events_in_round: u64,
    /// When the current loss recovery started; `None` outside one.
    recovery_start: Option<I>,

    // Startup (§2.13)
    full_bw_reached: bool,
    full_bw_now: bool,
    full_bw: f64,
    full_bw_count: u32,

    // ProbeBW (§2.14)
    is_bw_probe_stopping: bool,
    check_probe_loss: bool,
    bw_probe_up_acked: usize,
    probe_up_acked_per_inc: usize,
    bw_probe_up_rounds: u32,
    bw_probe_wait: Duration,
    cycle_stamp: Option<I>,
    prev_probe_too_high: bool,
    prev_probe_precautionary: bool,

    // ProbeRTT (§2.16)
    probe_rtt_done_stamp: Option<I>,
    probe_rtt_round_done: bool,
    probe_rtt_cwnd: usize,
    prior_cwnd: usize,

    // undo (§2.15)
    undo_state: Option<BbrState>,
    undo_bw_shortterm: f64,
    undo_inflight_shortterm: usize,
    undo_inflight_longterm: usize,
    loss_episode: LossEpisode,

    duplicate_initial_crypto_answered: bool,
}

/// `BBR.min_rtt` and `BBR.min_rtt_stamp`.
#[derive(Clone, Copy, Debug)]
struct MinRtt<I> {
    value: Duration,
    stamp: I,
}

/// The latest loss episode: from one SaveStateUponLoss to the next.
#[derive(Clone, Copy, Debug)]
struct LossEpisode {
    id: u64,
    /// The packets it counted as lost and not acknowledged since.
    outstanding: usize,
    /// Whether it can still be undone: not after a CE mark, nor twice.
    undoable: bool,
}

/// What one ACK gives the steps of UpdateOnACK.
#[derive(Clone, Copy, Debug)]
struct Ack<I> {
    now: I,
    /// `C.inflight`, after the ACK.
    bytes_in_flight: usize,
    rs: RateSample,
    /// `RS.rtt`.
    rtt: Option<Duration>,
}

/// The bucket of the pacer: the bytes the pacing rate has earned, up to
/// the burst limit.
#[derive(Clone, Copy, Debug)]
struct PacingBucket<I> {
    tokens: usize,
    /// The instant the tokens are counted up to, and the maximum datagram
    /// size of that refill; `None` before the first.
    refilled: Option<(I, usize)>,
}

/// A windowed max filter of three samples (Kathleen Nichols' algorithm,
/// §5.5.5), over a time counted in rounds.
#[derive(Clone, Copy, Debug)]
struct WindowedMax {
    samples: [(u64, usize); 3],
}

impl WindowedMax {
    const fn new() -> Self {
        Self {
            samples: [(0, 0); 3],
        }
    }

    /// Takes `value` at `time` and gives the maximum over the last
    /// `window`.
    fn update(&mut self, time: u64, value: usize, window: u64) -> usize {
        let sample = (time, value);
        let s = &mut self.samples;
        if value >= s[0].1 || time.saturating_sub(s[2].0) > window {
            *s = [sample; 3];
            return value;
        }
        if value >= s[1].1 {
            s[1] = sample;
            s[2] = sample;
        } else if value >= s[2].1 {
            s[2] = sample;
        }
        let elapsed = time.saturating_sub(s[0].0);
        if elapsed > window {
            s[0] = s[1];
            s[1] = s[2];
            s[2] = sample;
            if time.saturating_sub(s[0].0) > window {
                s[0] = s[1];
                s[1] = s[2];
                s[2] = sample;
            }
        } else if s[1].0 == s[0].0 && elapsed > window / 4 {
            s[1] = sample;
            s[2] = sample;
        } else if s[2].0 == s[1].0 && elapsed > window / 2 {
            s[2] = sample;
        }
        s[0].1
    }
}

/// A xorshift64 generator for the random choices of ProbeBW.
#[derive(Clone, Copy, Debug)]
struct Xorshift64(NonZeroU64);

impl Xorshift64 {
    fn next(&mut self) -> u64 {
        let mut x = self.0.get();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        // invariant: xorshift maps a nonzero state to a nonzero state.
        self.0 = NonZeroU64::new(x).unwrap_or(RECOMMENDED_SEED);
        x
    }

    /// 0 or 1.
    fn bit(&mut self) -> u64 {
        self.next() >> 63
    }

    /// A fraction in `[0, 1)`.
    fn fraction(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

impl<I> Bbr<I> {
    /// A controller in Startup, with the initial window for
    /// `max_datagram_size` (OnInit, §5.2.1).
    ///
    /// Before an RTT sample the initial pacing rate assumes an RTT of
    /// 1 ms (§5.6.2).
    pub fn new(config: BbrConfig, max_datagram_size: usize) -> Self {
        let cwnd = config.window.initial_bytes(max_datagram_size);
        let mut bbr = Self {
            config,
            max_datagram_size,
            cwnd,
            pacing_rate: 0.0,
            send_quantum: 0,
            bucket: PacingBucket {
                tokens: 0,
                refilled: None,
            },
            rate_sampler: DeliveryRateSampler::new(),
            state: BbrState::Startup,
            random: Xorshift64(config.seed),
            rtt_seen: false,
            round_count: 0,
            round_start: false,
            next_round_delivered: 0,
            rounds_since_probe_up: 0,
            cwnd_limited_this_round: false,
            cwnd_limited_last_round: false,
            idle_restart: false,
            drain_start_round: 0,
            max_bw_slots: [0.0; 2],
            cycle_count: 0,
            max_bw: 0.0,
            bw_shortterm: f64::INFINITY,
            bw: 0.0,
            min_rtt: None,
            min_rtt_expired: false,
            extra_acked: 0,
            extra_acked_filter: WindowedMax::new(),
            extra_acked_interval_start: None,
            extra_acked_delivered: 0,
            max_inflight: cwnd,
            inflight_longterm: UNBOUNDED,
            inflight_shortterm: UNBOUNDED,
            bw_latest: 0.0,
            inflight_latest: 0,
            loss_round_delivered: 0,
            loss_round_start: false,
            is_loss_in_round: false,
            loss_events_in_round: 0,
            recovery_start: None,
            full_bw_reached: false,
            full_bw_now: false,
            full_bw: 0.0,
            full_bw_count: 0,
            is_bw_probe_stopping: false,
            check_probe_loss: false,
            bw_probe_up_acked: 0,
            probe_up_acked_per_inc: UNBOUNDED,
            bw_probe_up_rounds: 0,
            bw_probe_wait: Duration::ZERO,
            cycle_stamp: None,
            prev_probe_too_high: false,
            prev_probe_precautionary: false,
            probe_rtt_done_stamp: None,
            probe_rtt_round_done: false,
            probe_rtt_cwnd: UNBOUNDED,
            prior_cwnd: 0,
            undo_state: None,
            undo_bw_shortterm: 0.0,
            undo_inflight_shortterm: 0,
            undo_inflight_longterm: 0,
            loss_episode: LossEpisode {
                id: 0,
                outstanding: 0,
                undoable: false,
            },
            duplicate_initial_crypto_answered: false,
        };
        bbr.init_pacing_rate(Duration::from_millis(1));
        bbr
    }

    /// The state in the state machine.
    pub const fn state(&self) -> BbrState {
        self.state
    }

    /// The pacing rate, in bytes per second.
    pub const fn pacing_rate(&self) -> f64 {
        self.pacing_rate
    }

    /// The send quantum `C.send_quantum`, in bytes (§5.6.3): the offload
    /// budget of the window's quantization budget. The pacer's burst limit
    /// does not follow it.
    pub const fn send_quantum(&self) -> usize {
        self.send_quantum
    }

    /// The estimated maximum bandwidth `BBR.max_bw`, in bytes per second;
    /// zero before the first sample.
    pub const fn max_bw(&self) -> f64 {
        self.max_bw
    }

    /// The estimated minimum RTT `BBR.min_rtt`; `None` before the first
    /// sample.
    pub fn min_rtt(&self) -> Option<Duration> {
        self.min_rtt.as_ref().map(|min_rtt| min_rtt.value)
    }

    /// `C.InitialCwnd`.
    fn initial_cwnd(&self) -> usize {
        self.config.window.initial_bytes(self.max_datagram_size)
    }

    /// `BBR.MinPipeCwnd`.
    fn min_pipe_cwnd(&self) -> usize {
        MIN_PIPE_CWND_DATAGRAMS.saturating_mul(self.max_datagram_size)
    }

    /// InitPacingRate (§5.6.2) for a smoothed RTT of `smoothed_rtt`.
    fn init_pacing_rate(&mut self, smoothed_rtt: Duration) {
        let smoothed_rtt = smoothed_rtt.max(Duration::from_nanos(1)).as_secs_f64();
        let nominal_bandwidth = self.initial_cwnd() as f64 / smoothed_rtt;
        self.pacing_rate = STARTUP_PACING_GAIN * nominal_bandwidth;
        self.set_send_quantum();
    }

    /// SetPacingRateWithGain (§5.6.2). A rate of zero is not taken: it
    /// would never release anything.
    fn set_pacing_rate_with_gain(&mut self, pacing_gain: f64) {
        let rate = pacing_gain * self.bw * (100.0 - PACING_MARGIN_PERCENT) / 100.0;
        if rate > 0.0 && (self.full_bw_reached || rate > self.pacing_rate) {
            self.pacing_rate = rate;
        }
    }

    /// SetSendQuantum (§5.6.3).
    fn set_send_quantum(&mut self) {
        let interval = SEND_QUANTUM_INTERVAL.as_secs_f64();
        self.send_quantum = ((self.pacing_rate * interval) as usize)
            .min(MAX_SEND_QUANTUM)
            .max(self.max_datagram_size.saturating_mul(2));
    }

    /// The bucket's capacity, for a refill with `max_datagram_size`: what
    /// the pacing rate sends in two timer granularities, at least the
    /// initial window and at most the configured burst, as the burst limit
    /// of [`TokenBucketPacer`](crate::pacing::TokenBucketPacer) (RFC 9002
    /// §7.7: bursts SHOULD stay within the initial window, and MAY be
    /// larger where the path is known to absorb them).
    fn bucket_capacity(&self, max_datagram_size: usize) -> usize {
        let two_granularities = self.config.timer_granularity.saturating_mul(2);
        let from_rate = (self.pacing_rate * two_granularities.as_secs_f64()) as usize;
        from_rate
            .max(self.config.window.initial_bytes(max_datagram_size))
            .min(
                self.config
                    .max_burst_datagrams
                    .get()
                    .saturating_mul(max_datagram_size),
            )
    }

    /// `C.is_cwnd_limited`.
    const fn is_cwnd_limited(&self) -> bool {
        self.cwnd_limited_this_round || self.cwnd_limited_last_round
    }

    /// BDPMultiple (§5.6.4.2) for the bandwidth `bw`.
    fn bdp_multiple(&self, bw: f64, gain: f64) -> usize {
        match &self.min_rtt {
            None => self.initial_cwnd(),
            Some(min_rtt) => (gain * bw * min_rtt.value.as_secs_f64()) as usize,
        }
    }

    /// `BBR.bdp`: zero before the first RTT sample.
    fn bdp(&self) -> usize {
        self.min_rtt.as_ref().map_or(0, |min_rtt| {
            (self.bw * min_rtt.value.as_secs_f64()) as usize
        })
    }

    /// QuantizationBudget (§5.6.4.2), with the QUIC offload budget of
    /// §5.5.8.2.
    fn quantization_budget(&self, inflight_cap: usize) -> usize {
        let cap = inflight_cap
            .max(self.send_quantum)
            .max(self.min_pipe_cwnd());
        if self.state == BbrState::ProbeBwUp {
            cap.saturating_add(self.max_datagram_size.saturating_mul(2))
        } else {
            cap
        }
    }

    /// Inflight (§5.6.4.2) for the bandwidth `bw`.
    fn inflight(&self, bw: f64, gain: f64) -> usize {
        self.quantization_budget(self.bdp_multiple(bw, gain))
    }

    /// TargetInflight (§5.3.3.8.3).
    fn target_inflight(&self) -> usize {
        self.bdp().min(self.cwnd)
    }

    /// InflightWithHeadroom (§5.3.3.9).
    fn inflight_with_headroom(&self) -> usize {
        if self.inflight_longterm == UNBOUNDED {
            return UNBOUNDED;
        }
        let headroom =
            ((HEADROOM * self.inflight_longterm as f64) as usize).max(self.max_datagram_size);
        self.inflight_longterm
            .saturating_sub(headroom)
            .max(self.min_pipe_cwnd())
    }

    /// ProbeRTTCwnd (§5.6.4.5).
    fn probe_rtt_cwnd(&self) -> usize {
        self.bdp_multiple(self.bw, PROBE_RTT_CWND_GAIN)
            .min(self.probe_rtt_cwnd)
            .max(self.min_pipe_cwnd())
    }

    /// SaveCwnd (§5.6.4.4).
    fn save_cwnd(&mut self) {
        if self.recovery_start.is_none() && self.state != BbrState::ProbeRtt {
            self.prior_cwnd = self.cwnd;
        } else {
            self.prior_cwnd = self.prior_cwnd.max(self.cwnd);
        }
    }

    /// RestoreCwnd (§5.6.4.4).
    fn restore_cwnd(&mut self) {
        self.cwnd = self.cwnd.max(self.prior_cwnd);
    }

    /// SaveStateUponLoss (§5.5.11.1): a new loss episode starts.
    fn save_state_upon_loss(&mut self) {
        self.save_cwnd();
        self.undo_state = None;
        self.undo_bw_shortterm = self.bw_shortterm;
        self.undo_inflight_shortterm = self.inflight_shortterm;
        self.undo_inflight_longterm = self.inflight_longterm;
        self.loss_episode = LossEpisode {
            id: self.loss_episode.id.wrapping_add(1),
            outstanding: 0,
            undoable: true,
        };
    }

    /// NoteLoss (§5.5.10.2) for `events` losses; `saved` tells whether
    /// this batch already saved the state.
    fn note_loss(&mut self, events: u64, saved: &mut bool) {
        if !self.is_loss_in_round {
            self.loss_round_delivered = self.rate_sampler.delivered();
            if !*saved {
                self.save_state_upon_loss();
                *saved = true;
            }
        }
        self.is_loss_in_round = true;
        self.loss_events_in_round = self.loss_events_in_round.saturating_add(events);
    }

    /// EnterStartup (§5.3.1.1).
    fn enter_startup(&mut self) {
        self.state = BbrState::Startup;
    }

    /// EnterDrain (§5.3.2).
    fn enter_drain(&mut self) {
        self.state = BbrState::Drain;
        self.drain_start_round = self.round_count;
    }

    /// StartRound (§5.5.1).
    fn start_round(&mut self) {
        self.next_round_delivered = self.rate_sampler.delivered();
    }

    /// StartProbeBW_CRUISE (§5.3.3.9).
    fn start_probe_bw_cruise(&mut self) {
        self.state = BbrState::ProbeBwCruise;
    }

    /// StartProbeBW_REFILL (§5.3.3.9).
    fn start_probe_bw_refill(&mut self) {
        self.reset_short_term_model();
        self.bw_probe_up_rounds = 0;
        self.bw_probe_up_acked = 0;
        self.prev_probe_precautionary = false;
        self.is_bw_probe_stopping = false;
        self.start_round();
        self.state = BbrState::ProbeBwRefill;
    }

    /// StartProbeBW_UP (§5.3.3.9).
    fn start_probe_bw_up(&mut self, rs: &RateSample) {
        self.start_round();
        self.reset_full_bw();
        self.full_bw = rs.delivery_rate;
        self.state = BbrState::ProbeBwUp;
        self.raise_inflight_longterm_slope();
    }

    /// PickProbeWait (§5.3.3.8.3).
    fn pick_probe_wait(&mut self) {
        self.rounds_since_probe_up = self.random.bit();
        self.bw_probe_wait =
            PROBE_WAIT_BASE.saturating_add(Duration::from_secs_f64(self.random.fraction()));
    }

    /// IsRenoCoexistenceProbeTime (§5.3.3.8.3), with TargetInflight in
    /// maximum datagrams.
    fn is_reno_coexistence_probe_time(&self) -> bool {
        let reno_rounds = self
            .target_inflight()
            .checked_div(self.max_datagram_size)
            .unwrap_or(0) as u64;
        self.rounds_since_probe_up >= reno_rounds.min(RENO_ROUNDS_BOUND)
    }

    /// RaiseInflightLongtermSlope (§5.3.3.9).
    fn raise_inflight_longterm_slope(&mut self) {
        let growth_this_round = 1usize << self.bw_probe_up_rounds;
        self.bw_probe_up_rounds = (self.bw_probe_up_rounds + 1).min(PROBE_UP_ROUNDS_BOUND);
        self.probe_up_acked_per_inc = (self.cwnd / growth_this_round).max(self.max_datagram_size);
    }

    /// ProbeInflightLongtermUpward (§5.3.3.9).
    fn probe_inflight_longterm_upward(&mut self, rs: &RateSample) {
        if !self.is_cwnd_limited() || self.cwnd < self.inflight_longterm {
            return;
        }
        self.bw_probe_up_acked = self.bw_probe_up_acked.saturating_add(rs.newly_acked);
        if self.bw_probe_up_acked >= self.probe_up_acked_per_inc
            && let Some(delta) = self
                .bw_probe_up_acked
                .checked_div(self.probe_up_acked_per_inc)
        {
            self.bw_probe_up_acked -= delta * self.probe_up_acked_per_inc;
            self.inflight_longterm = self
                .inflight_longterm
                .saturating_add(delta.saturating_mul(self.max_datagram_size));
        }
        if self.round_start {
            self.raise_inflight_longterm_slope();
        }
    }

    /// ResetCongestionSignals (§5.5.10.3).
    fn reset_congestion_signals(&mut self) {
        self.is_loss_in_round = false;
        self.loss_events_in_round = 0;
        self.bw_latest = 0.0;
        self.inflight_latest = 0;
    }

    /// ResetShortTermModel (§5.5.10.3).
    fn reset_short_term_model(&mut self) {
        self.bw_shortterm = f64::INFINITY;
        self.inflight_shortterm = UNBOUNDED;
    }

    /// ResetFullBW (§5.3.1.2).
    fn reset_full_bw(&mut self) {
        self.full_bw = 0.0;
        self.full_bw_count = 0;
        self.full_bw_now = false;
    }

    /// The slot of the `BBR.max_bw` filter for `BBR.cycle_count`.
    const fn max_bw_slot(&self) -> usize {
        (self.cycle_count % 2) as usize
    }

    /// AdvanceMaxBwFilter (§5.5.6): the slot of two cycles ago is
    /// forgotten.
    fn advance_max_bw_filter(&mut self) {
        self.cycle_count = self.cycle_count.wrapping_add(1);
        let slot = self.max_bw_slot();
        self.max_bw_slots[slot] = 0.0;
        self.max_bw = self.max_bw_slots[0].max(self.max_bw_slots[1]);
    }

    /// AdaptLowerBoundsFromCongestion (§5.5.10.3).
    fn adapt_lower_bounds_from_congestion(&mut self) {
        if self.state.is_probing_bw() || !self.is_loss_in_round {
            return;
        }
        // InitLowerBounds
        if self.bw_shortterm.is_infinite() {
            self.bw_shortterm = self.max_bw;
        }
        if self.inflight_shortterm == UNBOUNDED {
            self.inflight_shortterm = self.cwnd;
        }
        // LossLowerBounds
        self.bw_shortterm = self.bw_latest.max(BETA * self.bw_shortterm);
        self.inflight_shortterm = self
            .inflight_latest
            .max((BETA * self.inflight_shortterm as f64) as usize);
    }

    /// IsInflightTooHigh (§5.5.10.2); QUIC has selective acknowledgments.
    fn is_inflight_too_high(lost: usize, tx_in_flight: usize) -> bool {
        lost as f64 > tx_in_flight as f64 * LOSS_THRESH
    }

    /// InflightAtLoss (§5.5.10.2) for a packet of `bytes` sent with
    /// `tx_in_flight` in flight, `lost` lost since.
    fn inflight_at_loss(bytes: usize, tx_in_flight: usize, lost: usize) -> usize {
        let inflight_prev = tx_in_flight.saturating_sub(bytes);
        let lost_prev = lost.saturating_sub(bytes);
        let lost_prefix =
            (LOSS_THRESH * inflight_prev as f64 - lost_prev as f64) / (1.0 - LOSS_THRESH);
        inflight_prev.saturating_add(lost_prefix.max(0.0) as usize)
    }

    /// BoundBWForModel (§5.5.10.3).
    fn bound_bw_for_model(&mut self) {
        self.bw = self.max_bw.min(self.bw_shortterm);
    }

    /// SetCwnd (§5.6.4.6), with UpdateMaxInflight, BoundCwndForProbeRTT
    /// and BoundCwndForModel.
    fn set_cwnd(&mut self, rs: &RateSample) {
        let inflight_cap = self
            .bdp_multiple(self.bw, self.state.cwnd_gain())
            .saturating_add(self.extra_acked);
        self.max_inflight = self.quantization_budget(inflight_cap);
        if self.full_bw_reached {
            self.cwnd = self
                .cwnd
                .saturating_add(rs.newly_acked)
                .min(self.max_inflight);
        } else if self.cwnd < self.max_inflight
            || self.rate_sampler.delivered() < super::delivery_rate::total(self.initial_cwnd())
        {
            self.cwnd = self.cwnd.saturating_add(rs.newly_acked);
        }
        self.cwnd = self.cwnd.max(self.min_pipe_cwnd());
        if self.state == BbrState::ProbeRtt {
            self.cwnd = self.cwnd.min(self.probe_rtt_cwnd());
        }
        let cap = if self.state.is_probe_bw() && self.state != BbrState::ProbeBwCruise {
            self.inflight_longterm
        } else if matches!(self.state, BbrState::ProbeRtt | BbrState::ProbeBwCruise) {
            self.inflight_with_headroom()
        } else {
            UNBOUNDED
        };
        let cap = cap.min(self.inflight_shortterm).max(self.min_pipe_cwnd());
        self.cwnd = self.cwnd.min(cap);
    }
}

impl<I: Ord + Copy + Add<Duration, Output = I> + Sub<Output = Duration>> Bbr<I> {
    /// Earns the tokens of the pacing rate up to `at`, for refills with
    /// `max_datagram_size`. The first refill fills the bucket; one that
    /// earns less than a byte keeps the time it covered for the next.
    fn earn(&mut self, at: I, max_datagram_size: usize) {
        let capacity = self.bucket_capacity(max_datagram_size);
        let Some((refilled_at, _)) = self.bucket.refilled else {
            self.bucket = PacingBucket {
                tokens: capacity,
                refilled: Some((at, max_datagram_size)),
            };
            return;
        };
        let elapsed = checked_duration_since(at, refilled_at).unwrap_or(Duration::ZERO);
        let earned = (elapsed.as_secs_f64() * self.pacing_rate) as usize;
        self.bucket.tokens = self.bucket.tokens.saturating_add(earned).min(capacity);
        let refilled_at = if earned == 0 { refilled_at } else { at };
        self.bucket.refilled = Some((refilled_at, max_datagram_size));
    }

    /// Earns the tokens up to `at` at the current rate, before the rate
    /// changes; nothing before the first refill.
    fn settle_bucket(&mut self, at: I) {
        if let Some((_, max_datagram_size)) = self.bucket.refilled {
            self.earn(at, max_datagram_size);
        }
    }

    /// HasElapsedInPhase (§5.3.3.9).
    fn has_elapsed_in_phase(&self, interval: Duration, now: I) -> bool {
        self.cycle_stamp
            .is_some_and(|cycle_stamp| now > cycle_stamp + interval)
    }

    /// StartProbeBW_DOWN (§5.3.3.9); EnterProbeBW is the same, the window
    /// gain following the state.
    fn start_probe_bw_down(&mut self, now: I) {
        self.reset_congestion_signals();
        self.probe_up_acked_per_inc = UNBOUNDED;
        self.pick_probe_wait();
        self.cycle_stamp = Some(now);
        self.is_bw_probe_stopping = true;
        self.start_round();
        self.state = BbrState::ProbeBwDown;
    }

    /// IsTimeToProbeBW (§5.3.3.8.3).
    fn is_time_to_probe_bw(&mut self, now: I) -> bool {
        if self.has_elapsed_in_phase(self.bw_probe_wait, now)
            || self.is_reno_coexistence_probe_time()
        {
            self.start_probe_bw_refill();
            return true;
        }
        false
    }

    /// IsTimeToCruise (§5.3.3.9).
    fn is_time_to_cruise(&self, bytes_in_flight: usize) -> bool {
        bytes_in_flight <= self.inflight_with_headroom()
            && bytes_in_flight <= self.inflight(self.max_bw, 1.0)
    }

    /// IsTimeToGoDown (§5.3.3.9).
    fn is_time_to_go_down(&mut self, ack: &Ack<I>) -> bool {
        if self.prev_probe_too_high && ack.bytes_in_flight >= self.inflight_longterm {
            self.prev_probe_precautionary = true;
            return true;
        }
        if self.is_cwnd_limited() && self.cwnd >= self.inflight_longterm {
            self.reset_full_bw();
            self.full_bw = ack.rs.delivery_rate;
        } else if self.full_bw_now {
            return true;
        }
        false
    }

    /// HandleInflightTooHigh (§5.5.10.2).
    fn handle_inflight_too_high(&mut self, tx_in_flight: usize, is_app_limited: bool, now: I) {
        self.prev_probe_too_high = true;
        self.check_probe_loss = false;
        if !is_app_limited {
            self.inflight_longterm =
                tx_in_flight.max((self.target_inflight() as f64 * BETA) as usize);
        }
        if self.state == BbrState::ProbeBwUp {
            self.undo_state = Some(BbrState::ProbeBwUp);
            self.start_probe_bw_down(now);
        }
    }

    /// HandleLostPacket (§5.5.10.2) for a packet of `bytes`; `C.lost`
    /// already counts it.
    fn handle_lost_packet(
        &mut self,
        snapshot: &DeliverySnapshot<I>,
        bytes: usize,
        now: I,
        saved: &mut bool,
    ) {
        self.note_loss(1, saved);
        if !self.check_probe_loss {
            return;
        }
        let lost = volume(self.rate_sampler.lost().saturating_sub(snapshot.lost));
        if Self::is_inflight_too_high(lost, snapshot.tx_in_flight) {
            let inflight_at_loss = Self::inflight_at_loss(bytes, snapshot.tx_in_flight, lost);
            self.handle_inflight_too_high(inflight_at_loss, snapshot.is_app_limited, now);
        }
    }

    /// HandleSpuriousLossDetection (§5.5.11.2).
    fn handle_spurious_loss_detection(&mut self) {
        self.restore_cwnd();
        self.is_loss_in_round = false;
        self.loss_events_in_round = 0;
        self.reset_full_bw();
        self.bw_shortterm = self.bw_shortterm.max(self.undo_bw_shortterm);
        self.inflight_shortterm = self.inflight_shortterm.max(self.undo_inflight_shortterm);
        self.inflight_longterm = self.inflight_longterm.max(self.undo_inflight_longterm);
        match self.undo_state {
            Some(BbrState::Startup) if self.state != BbrState::Startup => {
                self.full_bw_reached = false;
                if self.state != BbrState::ProbeRtt {
                    self.enter_startup();
                }
            }
            Some(BbrState::ProbeBwUp)
                if !matches!(self.state, BbrState::ProbeBwUp | BbrState::ProbeRtt) =>
            {
                self.start_probe_bw_refill();
            }
            _ => {}
        }
        self.undo_state = None;
    }

    /// CheckProbeRTTDone (§5.3.4.3), with ExitProbeRTT (§5.3.4.4).
    fn check_probe_rtt_done(&mut self, now: I) {
        if !self
            .probe_rtt_done_stamp
            .is_some_and(|done_stamp| now > done_stamp)
        {
            return;
        }
        // schedule the next ProbeRTT
        if let Some(min_rtt) = self.min_rtt.as_mut() {
            min_rtt.stamp = now;
        }
        self.restore_cwnd();
        self.reset_short_term_model();
        if self.full_bw_reached {
            self.start_probe_bw_down(now);
            self.start_probe_bw_cruise();
        } else {
            self.enter_startup();
        }
    }

    /// UpdateModelAndState (§5.2.3).
    fn update_model_and_state(&mut self, ack: &Ack<I>) {
        let rs = &ack.rs;
        // UpdateLatestDeliverySignals
        self.loss_round_start = false;
        self.bw_latest = self.bw_latest.max(rs.delivery_rate);
        self.inflight_latest = self.inflight_latest.max(rs.delivered);
        if rs.prior_delivered >= self.loss_round_delivered {
            self.loss_round_delivered = self.rate_sampler.delivered();
            self.loss_round_start = true;
        }
        self.update_congestion_signals(rs);
        self.update_ack_aggregation(ack);
        self.check_full_bw_reached(rs);
        // CheckStartupDone
        self.check_startup_high_loss(rs);
        if self.state == BbrState::Startup && self.full_bw_reached {
            self.enter_drain();
        }
        // CheckDrainDone
        if self.state == BbrState::Drain
            && (ack.bytes_in_flight <= self.inflight(self.bw, 1.0)
                || self.round_count > self.drain_start_round.saturating_add(3))
        {
            self.start_probe_bw_down(ack.now);
        }
        self.update_probe_bw_cycle_phase(ack);
        self.update_min_rtt(ack);
        self.check_probe_rtt(ack);
        // AdvanceLatestDeliverySignals
        if self.loss_round_start {
            self.bw_latest = rs.delivery_rate;
            self.inflight_latest = rs.delivered;
            self.loss_events_in_round = 0;
        }
        self.bound_bw_for_model();
    }

    /// UpdateCongestionSignals (§5.5.10.3), with UpdateMaxBw (§5.5.5) and
    /// UpdateRound (§5.5.1).
    fn update_congestion_signals(&mut self, rs: &RateSample) {
        if rs.prior_delivered >= self.next_round_delivered {
            self.start_round();
            self.round_count = self.round_count.saturating_add(1);
            self.rounds_since_probe_up = self.rounds_since_probe_up.saturating_add(1);
            self.round_start = true;
            self.cwnd_limited_last_round = self.cwnd_limited_this_round;
            self.cwnd_limited_this_round = false;
        } else {
            self.round_start = false;
        }
        if rs.delivery_rate > 0.0 && (rs.delivery_rate >= self.max_bw || !rs.is_app_limited) {
            let slot = self.max_bw_slot();
            self.max_bw_slots[slot] = self.max_bw_slots[slot].max(rs.delivery_rate);
            self.max_bw = self.max_bw_slots[0].max(self.max_bw_slots[1]);
        }
        if !self.loss_round_start {
            return;
        }
        self.adapt_lower_bounds_from_congestion();
        self.is_loss_in_round = false;
    }

    /// UpdateACKAggregation (§5.5.9).
    fn update_ack_aggregation(&mut self, ack: &Ack<I>) {
        let interval = self
            .extra_acked_interval_start
            .and_then(|start| checked_duration_since(ack.now, start))
            .unwrap_or(Duration::ZERO);
        let mut expected_delivered = (self.bw * interval.as_secs_f64()) as usize;
        if self.extra_acked_delivered <= expected_delivered {
            self.extra_acked_delivered = 0;
            self.extra_acked_interval_start = Some(ack.now);
            expected_delivered = 0;
        }
        self.extra_acked_delivered = self
            .extra_acked_delivered
            .saturating_add(ack.rs.newly_acked);
        let extra = self
            .extra_acked_delivered
            .saturating_sub(expected_delivered)
            .min(self.cwnd);
        let filter_len = if self.full_bw_reached {
            EXTRA_ACKED_FILTER_LEN
        } else {
            1
        };
        self.extra_acked = self
            .extra_acked_filter
            .update(self.round_count, extra, filter_len);
    }

    /// CheckFullBWReached (§5.3.1.2).
    fn check_full_bw_reached(&mut self, rs: &RateSample) {
        if self.full_bw_now || !self.round_start || rs.is_app_limited {
            return;
        }
        if rs.delivery_rate >= self.full_bw * FULL_BW_GROWTH {
            self.reset_full_bw();
            self.full_bw = rs.delivery_rate;
            return;
        }
        self.full_bw_count += 1;
        self.full_bw_now = self.full_bw_count >= FULL_BW_ROUNDS;
        if self.full_bw_now {
            self.full_bw_reached = true;
        }
    }

    /// CheckStartupHighLoss (§5.3.1.3).
    fn check_startup_high_loss(&mut self, rs: &RateSample) {
        if self.full_bw_reached || !self.loss_round_start || self.recovery_start.is_none() {
            return;
        }
        if self.loss_events_in_round < STARTUP_FULL_LOSS_COUNT {
            return;
        }
        if !Self::is_inflight_too_high(rs.lost, rs.tx_in_flight) {
            return;
        }
        self.undo_state = Some(BbrState::Startup);
        self.full_bw_reached = true;
        self.inflight_longterm = self.bdp().max(self.inflight_latest);
    }

    /// UpdateProbeBWCyclePhase (§5.3.3.9).
    fn update_probe_bw_cycle_phase(&mut self, ack: &Ack<I>) {
        if !self.full_bw_reached || self.adapt_long_term_model(&ack.rs) {
            return;
        }
        match self.state {
            BbrState::ProbeBwDown => {
                if self.is_time_to_probe_bw(ack.now) {
                    return;
                }
                if self.is_time_to_cruise(ack.bytes_in_flight) {
                    self.start_probe_bw_cruise();
                }
            }
            BbrState::ProbeBwCruise => {
                self.is_time_to_probe_bw(ack.now);
            }
            BbrState::ProbeBwRefill => {
                // after one round of REFILL, start UP
                if self.round_start {
                    self.check_probe_loss = true;
                    self.start_probe_bw_up(&ack.rs);
                }
            }
            BbrState::ProbeBwUp => {
                if self.is_time_to_go_down(ack) {
                    self.prev_probe_too_high = false;
                    self.start_probe_bw_down(ack.now);
                }
            }
            BbrState::Startup | BbrState::Drain | BbrState::ProbeRtt => {}
        }
    }

    /// AdaptLongTermModel (§5.3.3.9): whether it decided a transition.
    fn adapt_long_term_model(&mut self, rs: &RateSample) -> bool {
        if self.is_bw_probe_stopping && self.round_start {
            // the end of the samples from the bandwidth probe
            self.check_probe_loss = false;
            self.is_bw_probe_stopping = false;
            if self.state.is_probe_bw() && !rs.is_app_limited {
                self.advance_max_bw_filter();
            }
            if self.state.is_probe_bw()
                && self.prev_probe_precautionary
                && !self.prev_probe_too_high
            {
                self.start_probe_bw_refill();
                return true;
            }
        }
        if !Self::is_inflight_too_high(rs.lost, rs.tx_in_flight) {
            if self.inflight_longterm == UNBOUNDED {
                return false;
            }
            if rs.tx_in_flight > self.inflight_longterm {
                self.inflight_longterm = rs.tx_in_flight;
            }
            if self.state == BbrState::ProbeBwUp {
                self.probe_inflight_longterm_upward(rs);
            }
        }
        false
    }

    /// UpdateMinRTT (§5.3.4.3).
    fn update_min_rtt(&mut self, ack: &Ack<I>) {
        self.min_rtt_expired = self
            .min_rtt
            .is_some_and(|min_rtt| ack.now > min_rtt.stamp + MIN_RTT_FILTER_LEN);
        if self.min_rtt_expired {
            self.probe_rtt_cwnd = self.bdp_multiple(self.bw, PROBE_RTT_CWND_GAIN);
        }
        if let Some(rtt) = ack.rtt
            && (self.min_rtt_expired || self.min_rtt.is_none_or(|min_rtt| rtt < min_rtt.value))
        {
            self.min_rtt = Some(MinRtt {
                value: rtt,
                stamp: ack.now,
            });
        }
    }

    /// CheckProbeRTT (§5.3.4.3), with HandleProbeRTT.
    fn check_probe_rtt(&mut self, ack: &Ack<I>) {
        if self.state != BbrState::ProbeRtt && self.min_rtt_expired && !self.idle_restart {
            self.save_cwnd();
            self.state = BbrState::ProbeRtt;
            self.probe_rtt_done_stamp = None;
            self.is_bw_probe_stopping = true;
            self.start_round();
        }
        if self.state == BbrState::ProbeRtt {
            // ignore the low rate samples of ProbeRTT
            self.rate_sampler.mark_app_limited(ack.bytes_in_flight);
            if self.probe_rtt_done_stamp.is_none() && ack.bytes_in_flight <= self.probe_rtt_cwnd() {
                // wait for at least ProbeRTTDuration and one round
                self.probe_rtt_done_stamp = Some(ack.now + PROBE_RTT_DURATION);
                self.probe_rtt_round_done = false;
                self.start_round();
            } else if self.probe_rtt_done_stamp.is_some() {
                if self.round_start {
                    self.probe_rtt_round_done = true;
                }
                if self.probe_rtt_round_done {
                    self.check_probe_rtt_done(ack.now);
                }
            }
        }
        if ack.rs.delivered > 0 {
            self.idle_restart = false;
        }
    }
}

impl<I: Ord + Copy + Add<Duration, Output = I> + Sub<Output = Duration>> CongestionController<I>
    for Bbr<I>
{
    type SentState = BbrDeliverySnapshot<I>;
    type LossState = BbrLossEpisode;

    fn window(&self) -> usize {
        self.cwnd
    }

    /// HandleRestartFromIdle (§5.4.1) and OnPacketSent (§4.1.2.2). The
    /// window counts as full in this round when what it leaves is less
    /// than a maximum datagram.
    fn on_packet_sealed(&mut self, packet: &SealedPacket<I>) -> BbrDeliverySnapshot<I> {
        let in_flight_before = packet.bytes_in_flight.saturating_sub(packet.bytes);
        if packet.app_limited {
            self.rate_sampler.mark_app_limited(in_flight_before);
        }
        if in_flight_before == 0 && self.rate_sampler.is_app_limited() {
            self.idle_restart = true;
            self.extra_acked_interval_start = Some(packet.now);
            if self.state.is_probe_bw() {
                self.settle_bucket(packet.now);
                self.set_pacing_rate_with_gain(1.0);
            } else if self.state == BbrState::ProbeRtt {
                self.check_probe_rtt_done(packet.now);
            }
        }
        if self.cwnd.saturating_sub(packet.bytes_in_flight) < self.max_datagram_size {
            self.cwnd_limited_this_round = true;
        }
        BbrDeliverySnapshot(self.rate_sampler.on_sent(
            packet.bytes,
            packet.bytes_in_flight,
            packet.now,
        ))
    }

    /// The bytes count as delivered; once every packet the latest loss
    /// episode counted as lost has arrived, the episode is undone
    /// (§5.5.11.2) and its loss recovery ends. An earlier episode is not
    /// undone.
    fn on_spurious_loss(
        &mut self,
        loss: BbrLossEpisode,
        packets: impl Iterator<Item = SpuriouslyLostPacket<I>>,
        context: &CongestionContext<I>,
    ) {
        let (count, bytes) = packets.fold((0usize, 0usize), |(count, bytes), packet| {
            (count + 1, bytes.saturating_add(packet.bytes))
        });
        self.rate_sampler.on_spuriously_lost(bytes, context.now);
        let episode = &mut self.loss_episode;
        if episode.id != loss.0 || !episode.undoable {
            return;
        }
        episode.outstanding = episode.outstanding.saturating_sub(count);
        if episode.outstanding > 0 {
            return;
        }
        episode.undoable = false;
        self.recovery_start = None;
        self.handle_spurious_loss_detection();
    }

    /// Each CE mark counts as a lost maximum datagram, in `C.lost` and in
    /// the loss events of the round (§3.7: CE marks MUST be treated as
    /// congestion; the draft leaves the response open). The latest loss
    /// episode can no longer be undone.
    fn on_ce(&mut self, increase: u64, _reference_sent_at: I, _context: &CongestionContext<I>) {
        let bytes = usize::try_from(increase)
            .unwrap_or(usize::MAX)
            .saturating_mul(self.max_datagram_size);
        self.rate_sampler.on_lost(bytes);
        let mut saved = false;
        self.note_loss(increase, &mut saved);
        self.loss_episode.undoable = false;
    }

    /// HandleLostPacket for each packet (§5.5.10.2); the first loss outside
    /// a loss recovery starts one, saving the state (OnEnterFastRecovery,
    /// §5.6.4.4).
    fn on_lost(
        &mut self,
        packets: impl Iterator<Item = InFlightPacket<I, BbrDeliverySnapshot<I>>>,
        context: &CongestionContext<I>,
    ) -> BbrLossEpisode {
        let mut saved = false;
        let mut count = 0usize;
        for packet in packets {
            if count == 0 && self.recovery_start.is_none() {
                self.save_state_upon_loss();
                saved = true;
                self.recovery_start = Some(context.now);
            }
            count += 1;
            self.rate_sampler.on_lost(packet.bytes);
            self.handle_lost_packet(&packet.sent_state.0, packet.bytes, context.now, &mut saved);
        }
        let episode = &mut self.loss_episode;
        if episode.undoable {
            episode.outstanding = episode.outstanding.saturating_add(count);
        }
        BbrLossEpisode(episode.id)
    }

    /// The retransmission timeout of §5.6.4.4 (OnEnterRTO): the window is
    /// saved and goes down to the minimum window (RFC 9002 §7.6.2), not
    /// to `C.inflight + 1`. The state of the batch's loss episode was
    /// already saved by [`on_lost`](CongestionController::on_lost), so the
    /// episode can still be undone.
    fn on_persistent_congestion(&mut self, _context: &CongestionContext<I>) {
        self.save_cwnd();
        self.cwnd = self.config.window.minimum_bytes(self.max_datagram_size);
    }

    /// BBR sends no datagram beyond the window at a congestion event.
    fn wants_recovery_send(&mut self) -> bool {
        false
    }

    /// UpdateRateSample for each packet and UpdateOnACK (§5.2.3). The
    /// first ACK with an RTT sample sets the initial pacing rate again
    /// from the smoothed RTT (§5.6.2); `RS.rtt` is the latest RTT sample
    /// of the link path.
    fn on_acked(
        &mut self,
        packets: impl Iterator<Item = InFlightPacket<I, BbrDeliverySnapshot<I>>>,
        context: &CongestionContext<I>,
    ) {
        let now = context.now;
        let mut sample = RateSampleBuilder::new();
        let mut newest_sent_at = None;
        for packet in packets {
            self.rate_sampler
                .on_acked(&mut sample, &packet.sent_state.0, packet.bytes, now);
            newest_sent_at = newest_sent_at.max(Some(packet.sent_at));
        }
        let Some(rs) = self.rate_sampler.generate(sample, now, context.rtt.min) else {
            return;
        };
        if let Some(start) = self.recovery_start
            && newest_sent_at.is_some_and(|sent_at| sent_at > start)
        {
            // the loss recovery ends (§5.6.4.4)
            self.recovery_start = None;
            self.restore_cwnd();
        }
        self.settle_bucket(now);
        let rtt = context.rtt_sampled.then_some(context.rtt.latest);
        if rtt.is_some() && !core::mem::replace(&mut self.rtt_seen, true) {
            self.init_pacing_rate(context.rtt.smoothed);
        }
        let ack = Ack {
            now,
            bytes_in_flight: context.bytes_in_flight,
            rs,
            rtt,
        };
        self.update_model_and_state(&ack);
        // UpdateControlParameters
        self.set_pacing_rate_with_gain(self.state.pacing_gain());
        self.set_send_quantum();
        self.set_cwnd(&ack.rs);
    }

    fn on_removed(
        &mut self,
        _packets: impl Iterator<Item = RemovedPacket<BbrDeliverySnapshot<I>>>,
        _context: &CongestionContext<I>,
    ) {
    }

    /// As NewReno's: while the window is still the initial window of the
    /// old size, it becomes the initial window of the new one; a size that
    /// shrinks before the handshake is confirmed sets the window to the new
    /// initial window (RFC 9002 §7.2); otherwise only the minimum window
    /// changes.
    fn on_max_datagram_size_changed(
        &mut self,
        new: usize,
        handshake_confirmed: bool,
        _context: &CongestionContext<I>,
    ) {
        let old_initial = self.initial_cwnd();
        let shrinks = new < self.max_datagram_size;
        self.max_datagram_size = new;
        if self.cwnd == old_initial || (shrinks && !handshake_confirmed) {
            self.cwnd = self.initial_cwnd();
        } else {
            self.cwnd = self.cwnd.max(self.config.window.minimum_bytes(new));
        }
        self.set_send_quantum();
    }
}

/// A token bucket refilled at the pacing rate (§5.6.2) up to the burst
/// limit of [`BbrConfig::new`]; the window and RTT of the input are not
/// used.
///
/// The bucket is full at the first refill. A refill that earns less than a
/// byte keeps the time it covered for the next one. It holds nothing back
/// while it has a maximum datagram's worth; below that,
/// [`next_release`](Pacer::next_release) is when it will have it again.
impl<I: Ord + Copy + Add<Duration, Output = I> + Sub<Output = Duration>> Pacer<I> for Bbr<I> {
    fn next_release(&self) -> Option<I> {
        let (refilled_at, max_datagram_size) = self.bucket.refilled?;
        let wanted = max_datagram_size.min(self.bucket_capacity(max_datagram_size));
        let missing = wanted
            .checked_sub(self.bucket.tokens)
            .filter(|bytes| *bytes > 0)?;
        // the time to earn `missing` bytes, rounded up
        let nanos = (missing as f64 * 1e9 / self.pacing_rate).ceil();
        (nanos.is_finite() && nanos < u64::MAX as f64)
            .then(|| refilled_at + Duration::from_nanos(nanos as u64))
    }

    fn allowance(&self) -> usize {
        self.bucket.tokens
    }

    fn refill(&mut self, at: I, input: PacingInput) -> bool {
        let before = (self.bucket.tokens, self.next_release());
        self.earn(at, input.max_datagram_size);
        before != (self.bucket.tokens, self.next_release())
    }

    fn on_charged(&mut self, bytes: usize) {
        self.bucket.tokens = self.bucket.tokens.saturating_sub(bytes);
    }
}

impl<I> PtoPolicy<I> for Bbr<I> {
    fn on_duplicate_initial_crypto(&mut self) -> bool {
        !core::mem::replace(&mut self.duplicate_initial_crypto_answered, true)
    }
}

impl<I: Ord + Copy + Sub<Output = Duration>> EcnPolicy<I> for Bbr<I> {
    fn marking(&mut self, context: &EcnContext<I>) -> EcnMarking {
        ect0_testing_marking(context)
    }

    fn wants_revalidation(&mut self, _context: &EcnContext<I>) -> bool {
        false
    }
}

#[cfg(test)]
mod tests;
