//! CUBIC ([RFC 9438]).
//!
//! The window starts in slow start, as NewReno's does. A congestion event
//! starts a recovery period, as in RFC 9002 §7.3.2: it remembers the
//! window as `W_max` (reduced further by fast convergence, §4.7), multiplies
//! the window by `β_cubic` and makes that the slow start threshold, and
//! starts a congestion avoidance stage. During that stage the window
//! follows the cubic function `W_cubic(t) = C × (t − K)³ + W_max` of the
//! time since the stage started (§4.2), and at least the window Reno would
//! have reached in the same time (`W_est`, §4.3). It does not grow while a
//! recovery period lasts, nor for packets sealed while the link path was
//! limited by the application; the time the stage counts leaves out the
//! periods with nothing in flight and those whose acknowledgments only
//! carried packets sealed while limited by the application (§4.2, §5.8).
//!
//! When every packet of the latest congestion event that counted as lost
//! turns out to have arrived, it restores the state from before that event
//! (§4.9.2). Persistent congestion takes the window to the minimum window;
//! the next congestion avoidance stage starts at that window with `K = 0`
//! (§4.8). The initial slow start ends early with HyStart++ (§4.10, SHOULD;
//! [RFC 9406]), which can be turned off for Reno's slow start; later slow
//! starts are Reno's (RFC 9406 §4.3).
//!
//! Windows are in bytes; `C` is in maximum datagrams per second cubed, as
//! RFC 9438 states it in segments.
//!
//! [RFC 9438]: https://www.rfc-editor.org/rfc/rfc9438.html
//! [RFC 9406]: https://www.rfc-editor.org/rfc/rfc9406.html
use super::{
    CongestionContext, CongestionController, CongestionWindowConfig, InFlightPacket, RemovedPacket,
    SealedPacket, SpuriouslyLostPacket,
    hystart_plus_plus::{self, HyStartPlusPlus},
};
use crate::{
    checked_duration_since,
    ecn::{EcnContext, EcnPolicy, ect0_testing_marking},
    pto::PtoPolicy,
    ratio::Ratio,
};
use core::{
    ops::{Add, Sub},
    time::Duration,
};
use sakuya_link::EcnMarking;
use snafu::{Snafu, ensure};

/// The constants of [`Cubic`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CubicConfig {
    window: CongestionWindowConfig,
    beta: Ratio,
    aggressiveness: Ratio,
    fast_convergence: bool,
    hystart_plus_plus: bool,
}

impl CubicConfig {
    /// The values RFC 9438 recommends: the windows of
    /// [`CongestionWindowConfig::RECOMMENDED`], `β_cubic` of 0.7 (§4.6),
    /// `C` of 0.4 (§5.1), fast convergence (§4.7), and HyStart++ (§4.10).
    pub const RECOMMENDED: Self = Self {
        window: CongestionWindowConfig::RECOMMENDED,
        beta: Ratio::literal(7, 10),
        aggressiveness: Ratio::literal(2, 5),
        fast_convergence: true,
        hystart_plus_plus: true,
    };

    /// The constants given: the windows, the multiplicative decrease
    /// factor `β_cubic`, the constant `C` that sets how fast the window
    /// grows away from `W_max`, whether fast convergence is on, and whether
    /// the initial slow start uses HyStart++.
    ///
    /// # Errors
    ///
    /// - [`CubicConfigError::BetaOutOfRange`] if `beta` is not between 0
    ///   and 1, both excluded;
    /// - [`CubicConfigError::ZeroAggressiveness`] if `aggressiveness` is
    ///   zero.
    pub fn new(
        window: CongestionWindowConfig,
        beta: Ratio,
        aggressiveness: Ratio,
        fast_convergence: bool,
        hystart_plus_plus: bool,
    ) -> Result<Self, CubicConfigError> {
        ensure!(
            beta.numerator() > 0 && beta.is_below_one(),
            BetaOutOfRangeSnafu { beta }
        );
        ensure!(aggressiveness.numerator() > 0, ZeroAggressivenessSnafu);
        Ok(Self {
            window,
            beta,
            aggressiveness,
            fast_convergence,
            hystart_plus_plus,
        })
    }

    /// The initial and minimum windows.
    pub const fn window(&self) -> CongestionWindowConfig {
        self.window
    }

    /// The multiplicative decrease factor `β_cubic`.
    pub const fn beta(&self) -> Ratio {
        self.beta
    }

    /// The constant `C`, in maximum datagrams per second cubed.
    pub const fn aggressiveness(&self) -> Ratio {
        self.aggressiveness
    }

    /// Whether fast convergence is on. RFC 9438 §4.7 recommends it, and
    /// recommends it off for a network with a single CUBIC flow.
    pub const fn fast_convergence(&self) -> bool {
        self.fast_convergence
    }

    /// Whether the initial slow start uses HyStart++ (RFC 9438 §4.10,
    /// SHOULD); without it, slow start is Reno's.
    pub const fn hystart_plus_plus(&self) -> bool {
        self.hystart_plus_plus
    }

    /// `α_cubic = 3 × (1 − β_cubic) / (1 + β_cubic)` (§4.3).
    fn alpha(&self) -> f64 {
        let beta = ratio_value(self.beta);
        3.0 * (1.0 - beta) / (1.0 + beta)
    }
}

/// A [`CubicConfig`] breaks a rule of the algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
pub enum CubicConfigError {
    /// `β_cubic` does not reduce the window, or reduces it to nothing.
    #[snafu(display("multiplicative decrease factor {beta:?} is not between 0 and 1"))]
    BetaOutOfRange {
        /// The rejected factor.
        beta: Ratio,
    },
    /// `C` is zero: the window would not grow away from `W_max`.
    #[snafu(display("cubic constant is zero"))]
    ZeroAggressiveness,
}

/// Which congestion event a packet counted as lost belongs to: what
/// [`Cubic`] keeps for each batch of losses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CubicCongestionEvent(u64);

/// The position of a packet in the order a [`Cubic`] saw packets sealed:
/// what it keeps for each packet in flight, to count rounds for HyStart++.
/// The default is the first packet's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CubicSendSequence(u64);

/// The CUBIC congestion controller, with the default probe timeout and ECN
/// policies, those of [`NewReno`](super::new_reno::NewReno).
#[derive(Clone, Debug)]
pub struct Cubic<I> {
    config: CubicConfig,
    max_datagram_size: usize,
    window: usize,
    /// The fraction of a byte of growth carried over.
    growth_remainder: f64,
    slow_start_threshold: usize,
    /// `cwnd_prior`: the window before the latest congestion event.
    window_prior: usize,
    /// `W_max`, in bytes; zero before the first congestion event.
    window_max: f64,
    /// The current congestion avoidance stage; `None` in slow start and
    /// after persistent congestion until the next stage starts.
    stage: Option<AvoidanceStage<I>>,
    recovery_start: Option<I>,
    recovery_send: bool,
    /// The latest congestion event that can be undone.
    undo: Option<Undo<I>>,
    events: u64,
    /// Whether the latest event left nothing in flight, and no packet was
    /// sealed since.
    drained: bool,
    slow_start: HyStartPlusPlus,
    duplicate_initial_crypto_answered: bool,
}

/// One congestion avoidance stage.
#[derive(Clone, Copy, Debug)]
struct AvoidanceStage<I> {
    /// `t_epoch`, moved later by the periods left out of the time.
    start: I,
    /// The instant up to which the time since `start` is accounted for:
    /// counted or left out.
    accounted_until: I,
    /// `K`, in seconds.
    k: f64,
    /// `C` in bytes per second cubed, with the maximum datagram size of
    /// the start of the stage.
    scale: f64,
    /// `W_max` of this stage, in bytes.
    window_max: f64,
    /// `W_est`, in bytes.
    reno_estimate: f64,
}

impl<I: Ord + Copy + Add<Duration, Output = I> + Sub<Output = Duration>> AvoidanceStage<I> {
    /// `W_cubic(elapsed)`, in bytes.
    fn cubic_window(&self, elapsed: f64) -> f64 {
        self.scale * (elapsed - self.k).powi(3) + self.window_max
    }

    /// The time since `start`, in seconds.
    fn elapsed(&self, now: I) -> f64 {
        checked_duration_since(now, self.start).map_or(0.0, |elapsed| elapsed.as_secs_f64())
    }

    /// The time from `accounted_until` to `now` is not counted.
    fn leave_out_until(&mut self, now: I) {
        if let Some(left_out) = checked_duration_since(now, self.accounted_until) {
            self.start = self.start + left_out;
            self.accounted_until = now;
        }
    }

    /// The time from `accounted_until` to `now` is counted.
    fn count_until(&mut self, now: I) {
        if now > self.accounted_until {
            self.accounted_until = now;
        }
    }
}

/// What a congestion event changed, to restore it if every packet it
/// counted as lost arrives (§4.9.2).
#[derive(Clone, Copy, Debug)]
struct Undo<I> {
    event: CubicCongestionEvent,
    /// The packets of the event counted as lost and not yet acknowledged.
    outstanding: usize,
    window: usize,
    window_prior: usize,
    slow_start_threshold: usize,
    window_max: f64,
    stage: Option<AvoidanceStage<I>>,
    recovery_start: Option<I>,
    slow_start: hystart_plus_plus::Phase,
}

impl<I> Cubic<I> {
    /// A controller in slow start, with the initial window for
    /// `max_datagram_size`.
    pub fn new(config: CubicConfig, max_datagram_size: usize) -> Self {
        let window = config.window.initial_bytes(max_datagram_size);
        Self {
            config,
            max_datagram_size,
            window,
            growth_remainder: 0.0,
            slow_start_threshold: usize::MAX,
            window_prior: window,
            window_max: 0.0,
            stage: None,
            recovery_start: None,
            recovery_send: false,
            undo: None,
            events: 0,
            drained: false,
            slow_start: HyStartPlusPlus::new(config.hystart_plus_plus),
            duplicate_initial_crypto_answered: false,
        }
    }

    /// The slow start threshold, in bytes; [`usize::MAX`] until the first
    /// congestion event.
    pub const fn slow_start_threshold(&self) -> usize {
        self.slow_start_threshold
    }

    /// The minimum window, in bytes.
    pub fn minimum_window(&self) -> usize {
        self.config.window.minimum_bytes(self.max_datagram_size)
    }

    /// `W_max`, in bytes: the window before the latest congestion event,
    /// reduced by fast convergence; zero before the first.
    pub fn window_max(&self) -> usize {
        self.window_max as usize
    }

    /// Adds `growth` bytes, keeping the fraction.
    fn grow(&mut self, growth: f64) {
        let total = growth.max(0.0) + self.growth_remainder;
        let whole = total.floor();
        self.growth_remainder = total - whole;
        self.window = self.window.saturating_add(whole as usize);
    }
}

impl<I: Ord + Copy + Add<Duration, Output = I> + Sub<Output = Duration>> Cubic<I> {
    /// Whether a packet sent at `sent_at` belongs to the recovery period.
    fn in_recovery(&self, sent_at: I) -> bool {
        self.recovery_start.is_some_and(|start| sent_at <= start)
    }

    /// A congestion event for a packet sent at `sent_at` (§4.6, §4.7);
    /// `undoable` keeps what it changes for `packets` packets counted as
    /// lost. The event the packet belongs to, if one can be undone.
    fn on_congestion_event(
        &mut self,
        sent_at: I,
        now: I,
        undoable: Option<usize>,
    ) -> CubicCongestionEvent {
        if self.in_recovery(sent_at) {
            // the losses of the event already started
            let current = CubicCongestionEvent(self.events);
            if let Some(undo) = self.undo.as_mut().filter(|undo| undo.event == current) {
                undo.outstanding = undo.outstanding.saturating_add(undoable.unwrap_or(0));
            }
            return current;
        }
        self.events += 1;
        let event = CubicCongestionEvent(self.events);
        self.undo = undoable.map(|outstanding| Undo {
            event,
            outstanding,
            window: self.window,
            window_prior: self.window_prior,
            slow_start_threshold: self.slow_start_threshold,
            window_max: self.window_max,
            stage: self.stage,
            recovery_start: self.recovery_start,
            slow_start: self.slow_start.phase(),
        });
        self.slow_start.finish();
        let window = self.window as f64;
        self.window_max = if self.config.fast_convergence && window < self.window_max {
            window * (1.0 + ratio_value(self.config.beta)) / 2.0
        } else {
            window
        };
        self.window_prior = self.window;
        self.slow_start_threshold = self
            .config
            .beta
            .of_bytes(self.window)
            .max(self.minimum_window());
        self.window = self.slow_start_threshold;
        self.growth_remainder = 0.0;
        self.recovery_start = Some(now);
        self.recovery_send = true;
        self.start_stage(now, self.window_max);
        event
    }

    /// A congestion avoidance stage starts at `now` from the current
    /// window, towards `window_max` (Figure 2).
    fn start_stage(&mut self, now: I, window_max: f64) {
        let scale = ratio_value(self.config.aggressiveness) * self.max_datagram_size as f64;
        let window = self.window as f64;
        self.stage = Some(AvoidanceStage {
            start: now,
            accounted_until: now,
            k: ((window_max - window).max(0.0) / scale).cbrt(),
            scale,
            window_max,
            reno_estimate: window,
        });
    }

    /// Growth in congestion avoidance for `bytes` acknowledged at `now`
    /// (§4.2 to §4.5).
    fn grow_in_avoidance(&mut self, bytes: usize, now: I, smoothed_rtt: Duration) {
        if self.stage.is_none() {
            // the first stage after persistent congestion (§4.8)
            self.window_max = self.window as f64;
            self.start_stage(now, self.window_max);
        }
        let Some(stage) = self.stage.as_mut() else {
            return;
        };
        let window = self.window as f64;
        let max_datagram_size = self.max_datagram_size as f64;
        let alpha = if stage.reno_estimate >= self.window_prior as f64 {
            1.0
        } else {
            self.config.alpha()
        };
        stage.reno_estimate += alpha * max_datagram_size * bytes as f64 / window;
        let elapsed = stage.elapsed(now);
        let cubic = stage.cubic_window(elapsed);
        let growth = if cubic < stage.reno_estimate {
            // the Reno-friendly region (§4.3)
            stage.reno_estimate - window - self.growth_remainder
        } else {
            // the concave and convex regions (§4.4, §4.5)
            let target = stage
                .cubic_window(elapsed + smoothed_rtt.as_secs_f64())
                .clamp(window, 1.5 * window);
            (target - window) * bytes as f64 / window
        };
        self.grow(growth);
    }
}

/// The value of `ratio`.
fn ratio_value(ratio: Ratio) -> f64 {
    f64::from(ratio.numerator()) / f64::from(ratio.denominator())
}

impl<I: Ord + Copy + Add<Duration, Output = I> + Sub<Output = Duration>> CongestionController<I>
    for Cubic<I>
{
    type SentState = CubicSendSequence;
    type LossState = CubicCongestionEvent;

    fn window(&self) -> usize {
        self.window
    }

    /// The first packet after nothing was in flight leaves the idle time
    /// out of the stage.
    fn on_packet_sealed(&mut self, packet: &SealedPacket<I>) -> CubicSendSequence {
        if core::mem::take(&mut self.drained)
            && let Some(stage) = self.stage.as_mut()
        {
            stage.leave_out_until(packet.now);
        }
        CubicSendSequence(self.slow_start.on_sealed())
    }

    /// Restores the state from before the latest congestion event once
    /// every packet it counted as lost arrived, if the window is still
    /// below the window before it (§4.9.2). An earlier event is not
    /// undone.
    fn on_spurious_loss(
        &mut self,
        loss: CubicCongestionEvent,
        packets: impl Iterator<Item = SpuriouslyLostPacket<I>>,
        _context: &CongestionContext<I>,
    ) {
        let Some(undo) = self.undo.as_mut().filter(|undo| undo.event == loss) else {
            return;
        };
        undo.outstanding = undo.outstanding.saturating_sub(packets.count());
        if undo.outstanding > 0 {
            return;
        }
        let Some(undo) = self.undo.take() else {
            return;
        };
        if self.window < self.window_prior {
            self.window = undo.window;
            self.window_prior = undo.window_prior;
            self.slow_start_threshold = undo.slow_start_threshold;
            self.window_max = undo.window_max;
            self.stage = undo.stage;
            self.recovery_start = undo.recovery_start;
            self.slow_start.restore(undo.slow_start);
            self.growth_remainder = 0.0;
        }
    }

    /// A congestion event that cannot be undone, and that the latest one
    /// can no longer be undone either: the network marked congestion. The
    /// minimum window is the same as for a loss (RFC 9002 §7.2).
    fn on_ce(&mut self, _increase: u64, reference_sent_at: I, context: &CongestionContext<I>) {
        self.undo = None;
        self.on_congestion_event(reference_sent_at, context.now, None);
    }

    fn on_lost(
        &mut self,
        packets: impl Iterator<Item = InFlightPacket<I, CubicSendSequence>>,
        context: &CongestionContext<I>,
    ) -> CubicCongestionEvent {
        // one event, for the last packet sent
        let (count, last_sent_at) = packets.fold((0, None), |(count, last), packet| {
            (count + 1, last.max(Some(packet.sent_at)))
        });
        self.drained |= context.bytes_in_flight == 0;
        match last_sent_at {
            Some(sent_at) => self.on_congestion_event(sent_at, context.now, Some(count)),
            None => CubicCongestionEvent(self.events),
        }
    }

    fn on_persistent_congestion(&mut self, _context: &CongestionContext<I>) {
        self.window = self.minimum_window();
        self.growth_remainder = 0.0;
        self.recovery_start = None;
        self.stage = None;
    }

    fn wants_recovery_send(&mut self) -> bool {
        core::mem::take(&mut self.recovery_send)
    }

    fn on_acked(
        &mut self,
        packets: impl Iterator<Item = InFlightPacket<I, CubicSendSequence>>,
        context: &CongestionContext<I>,
    ) {
        let now = context.now;
        let (mut grew, mut application_limited) = (false, false);
        let mut largest = None;
        for packet in packets {
            largest = largest.max(Some(packet.sent_state.0));
            if self.in_recovery(packet.sent_at) {
                continue;
            }
            if packet.app_limited {
                application_limited = true;
                continue;
            }
            grew = true;
            if self.window < self.slow_start_threshold {
                let divisor = self.slow_start.growth_divisor();
                self.grow(packet.bytes as f64 / divisor as f64);
            } else {
                self.grow_in_avoidance(packet.bytes, now, context.rtt.smoothed);
            }
        }
        if self.window < self.slow_start_threshold {
            let sample = context.rtt_sampled.then_some(context.rtt.latest);
            if self.slow_start.on_ack(largest, sample) {
                // HyStart++ ends the initial slow start without a loss
                // (RFC 9438 §4.10)
                self.slow_start_threshold = self.window;
                self.window_prior = self.window;
                self.window_max = self.window as f64;
                self.start_stage(now, self.window_max);
            }
        }
        if let Some(stage) = self.stage.as_mut() {
            if application_limited && !grew {
                stage.leave_out_until(now);
            } else {
                stage.count_until(now);
            }
        }
        self.drained |= context.bytes_in_flight == 0;
    }

    fn on_removed(
        &mut self,
        _packets: impl Iterator<Item = RemovedPacket<CubicSendSequence>>,
        context: &CongestionContext<I>,
    ) {
        self.drained |= context.bytes_in_flight == 0;
    }

    /// As NewReno's: while the window is still the initial window of the
    /// old size, it becomes the initial window of the new one; a size that
    /// shrinks before the handshake is confirmed sets the window to the new
    /// initial window (RFC 9002 §7.2); otherwise only the minimum window
    /// changes. A congestion avoidance stage keeps the size it started
    /// with.
    fn on_max_datagram_size_changed(
        &mut self,
        new: usize,
        handshake_confirmed: bool,
        _context: &CongestionContext<I>,
    ) {
        let window = self.config.window;
        let old_initial = window.initial_bytes(self.max_datagram_size);
        let shrinks = new < self.max_datagram_size;
        self.max_datagram_size = new;
        if self.window == old_initial || (shrinks && !handshake_confirmed) {
            self.window = window.initial_bytes(new);
            self.growth_remainder = 0.0;
        } else {
            self.window = self.window.max(self.minimum_window());
        }
    }
}

impl<I> PtoPolicy<I> for Cubic<I> {
    fn on_duplicate_initial_crypto(&mut self) -> bool {
        !core::mem::replace(&mut self.duplicate_initial_crypto_answered, true)
    }
}

impl<I: Ord + Copy + Sub<Output = Duration>> EcnPolicy<I> for Cubic<I> {
    fn marking(&mut self, context: &EcnContext<I>) -> EcnMarking {
        ect0_testing_marking(context)
    }

    fn wants_revalidation(&mut self, _context: &EcnContext<I>) -> bool {
        false
    }
}

#[cfg(test)]
mod tests;
