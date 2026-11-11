//! Pacing ([RFC 9002 §7.7]).
//!
//! A [`Pacer`] keeps how many bytes may go out now. The caller refills it
//! whenever it has an instant (the start of each datagram, an ACK, an
//! expiry), reads the allowance, and charges it when a datagram ends. A
//! congestion controller that only gives a window gets a pacer with
//! [`PacedCongestionController`]; one whose window and pacing go together
//! implements both traits itself. [`TokenBucketPacer`] is the pacer sakuya
//! provides.
//!
//! [RFC 9002 §7.7]: https://www.rfc-editor.org/rfc/rfc9002.html#section-7.7
use crate::{
    checked_duration_since,
    congestion::{
        CongestionContext, CongestionController, InFlightPacket, InitialWindow, RemovedPacket,
        SpuriouslyLostPacket,
    },
    ecn::{EcnContext, EcnPolicy},
    pto::{PtoAction, PtoExpiry, PtoPolicy},
    ratio::Ratio,
};
use core::{
    num::NonZeroUsize,
    ops::{Add, Sub},
    time::Duration,
};
use sakuya_link::EcnMarking;
use snafu::{Snafu, ensure};

/// The pacer of a link path.
pub trait Pacer<I> {
    /// When pacing next lets a datagram go, or `None` if pacing does not
    /// hold anything back. It is the pacer's own state, read after each
    /// lend; after a refill at `at`, it is `None` or later than `at`.
    fn next_release(&self) -> Option<I>;

    /// The bytes that may go out, as of the latest refill.
    fn allowance(&self) -> usize;

    /// Refills up to `at`.
    fn refill(&mut self, at: I, input: PacingInput);

    /// A datagram ended with `bytes` that count as in flight; probes are
    /// charged too.
    fn on_charged(&mut self, bytes: usize);
}

impl<I, T: Pacer<I> + ?Sized> Pacer<I> for &mut T {
    fn next_release(&self) -> Option<I> {
        (**self).next_release()
    }

    fn allowance(&self) -> usize {
        (**self).allowance()
    }

    fn refill(&mut self, at: I, input: PacingInput) {
        (**self).refill(at, input);
    }

    fn on_charged(&mut self, bytes: usize) {
        (**self).on_charged(bytes);
    }
}

/// What the caller gives a pacer at each refill.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacingInput {
    /// The congestion window.
    pub window: usize,
    /// The smoothed RTT of the link path.
    pub smoothed_rtt: Duration,
    /// The maximum datagram size in use.
    pub max_datagram_size: usize,
}

/// A congestion controller that only gives a window, paired with a pacer.
///
/// It is a congestion controller, a probe timeout policy and an ECN policy
/// through `C`, and a pacer through `P`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacedCongestionController<C, P> {
    /// The congestion controller.
    pub congestion_controller: C,
    /// The pacer.
    pub pacer: P,
}

impl<C, P> PacedCongestionController<C, P> {
    /// Pairs `congestion_controller` with `pacer`.
    pub const fn new(congestion_controller: C, pacer: P) -> Self {
        Self {
            congestion_controller,
            pacer,
        }
    }
}

impl<I, C: CongestionController<I>, P> CongestionController<I> for PacedCongestionController<C, P> {
    type SentState = C::SentState;
    type LossState = C::LossState;

    fn window(&self) -> usize {
        self.congestion_controller.window()
    }

    fn on_packet_sealed(&mut self, bytes: usize, app_limited: bool, now: I) -> Self::SentState {
        self.congestion_controller
            .on_packet_sealed(bytes, app_limited, now)
    }

    fn on_spurious_loss(
        &mut self,
        loss: Self::LossState,
        packets: impl Iterator<Item = SpuriouslyLostPacket<I>>,
        context: &CongestionContext<I>,
    ) {
        self.congestion_controller
            .on_spurious_loss(loss, packets, context);
    }

    fn on_ce(&mut self, increase: u64, reference_sent_at: I, context: &CongestionContext<I>) {
        self.congestion_controller
            .on_ce(increase, reference_sent_at, context);
    }

    fn on_lost(
        &mut self,
        packets: impl Iterator<Item = InFlightPacket<I, Self::SentState>>,
        context: &CongestionContext<I>,
    ) -> Self::LossState {
        self.congestion_controller.on_lost(packets, context)
    }

    fn on_persistent_congestion(&mut self, context: &CongestionContext<I>) {
        self.congestion_controller.on_persistent_congestion(context);
    }

    fn wants_recovery_send(&mut self) -> bool {
        self.congestion_controller.wants_recovery_send()
    }

    fn on_acked(
        &mut self,
        packets: impl Iterator<Item = InFlightPacket<I, Self::SentState>>,
        context: &CongestionContext<I>,
    ) {
        self.congestion_controller.on_acked(packets, context);
    }

    fn on_removed(
        &mut self,
        packets: impl Iterator<Item = RemovedPacket<Self::SentState>>,
        context: &CongestionContext<I>,
    ) {
        self.congestion_controller.on_removed(packets, context);
    }

    fn on_max_datagram_size_changed(
        &mut self,
        new: usize,
        handshake_confirmed: bool,
        context: &CongestionContext<I>,
    ) {
        self.congestion_controller
            .on_max_datagram_size_changed(new, handshake_confirmed, context);
    }
}

impl<I, C, P: Pacer<I>> Pacer<I> for PacedCongestionController<C, P> {
    fn next_release(&self) -> Option<I> {
        self.pacer.next_release()
    }

    fn allowance(&self) -> usize {
        self.pacer.allowance()
    }

    fn refill(&mut self, at: I, input: PacingInput) {
        self.pacer.refill(at, input);
    }

    fn on_charged(&mut self, bytes: usize) {
        self.pacer.on_charged(bytes);
    }
}

impl<I, C: PtoPolicy<I>, P> PtoPolicy<I> for PacedCongestionController<C, P> {
    fn on_pto_expired(&mut self, expiry: &PtoExpiry<I>) -> PtoAction {
        self.congestion_controller.on_pto_expired(expiry)
    }

    fn on_duplicate_initial_crypto(&mut self) -> bool {
        self.congestion_controller.on_duplicate_initial_crypto()
    }
}

impl<I, C: EcnPolicy<I>, P> EcnPolicy<I> for PacedCongestionController<C, P> {
    fn marking(&mut self, context: &EcnContext<I>) -> EcnMarking {
        self.congestion_controller.marking(context)
    }

    fn wants_revalidation(&mut self, context: &EcnContext<I>) -> bool {
        self.congestion_controller.wants_revalidation(context)
    }
}

/// The multiple of the window paced out per smoothed RTT that RFC 9002
/// §7.7 gives as an example of `N`: 5/4.
pub const RECOMMENDED_PACING_GAIN: Ratio = Ratio::literal(5, 4);

/// The burst limit of [`TokenBucketPacer`] in datagrams, by default.
pub const DEFAULT_MAX_BURST_DATAGRAMS: NonZeroUsize = NonZeroUsize::new(256).unwrap();

/// The constants of [`TokenBucketPacer`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenBucketPacerConfig {
    timer_granularity: Duration,
    initial_window: InitialWindow,
    max_burst_datagrams: NonZeroUsize,
    gain: Ratio,
}

impl TokenBucketPacerConfig {
    /// The constants given.
    ///
    /// `timer_granularity` is the precision of the clock's timers;
    /// `initial_window` is the controller's, the least burst the pacer
    /// allows; `max_burst_datagrams` the most; `gain` the multiple of the
    /// window paced out per smoothed RTT.
    ///
    /// # Errors
    ///
    /// - [`TokenBucketPacerConfigError::GainBelowOne`] if `gain` is below
    ///   1: RFC 9002 §7.7 asks for at least 1, so that variation in the
    ///   RTT does not leave the window unused.
    /// - [`TokenBucketPacerConfigError::MaxBurstBelowInitialWindow`] if
    ///   `max_burst_datagrams` is fewer datagrams than the initial window.
    pub fn new(
        timer_granularity: Duration,
        initial_window: InitialWindow,
        max_burst_datagrams: NonZeroUsize,
        gain: Ratio,
    ) -> Result<Self, TokenBucketPacerConfigError> {
        ensure!(
            gain.numerator() >= gain.denominator(),
            GainBelowOneSnafu { gain }
        );
        ensure!(
            max_burst_datagrams.get() >= initial_window.datagrams(),
            MaxBurstBelowInitialWindowSnafu {
                max_burst_datagrams,
                initial_window_datagrams: initial_window.datagrams(),
            }
        );
        Ok(Self {
            timer_granularity,
            initial_window,
            max_burst_datagrams,
            gain,
        })
    }

    /// The defaults for a clock whose timers fire with a precision of
    /// `timer_granularity`: the initial window RFC 9002 recommends, a
    /// burst of at most [`DEFAULT_MAX_BURST_DATAGRAMS`], and a gain of
    /// [`RECOMMENDED_PACING_GAIN`].
    pub fn recommended(timer_granularity: Duration) -> Self {
        Self {
            timer_granularity,
            initial_window: InitialWindow::RECOMMENDED,
            max_burst_datagrams: DEFAULT_MAX_BURST_DATAGRAMS,
            gain: RECOMMENDED_PACING_GAIN,
        }
    }

    /// The initial window, the least burst allowed.
    pub const fn initial_window(&self) -> InitialWindow {
        self.initial_window
    }

    /// The burst limit for `input`: what the rate sends in two timer
    /// granularities, at least the initial window and at most
    /// `max_burst_datagrams` datagrams (RFC 9002 §7.7: bursts SHOULD stay
    /// within the initial window, and MAY be larger where the path is
    /// known to absorb them).
    fn burst_limit(&self, input: &PacingInput) -> usize {
        let paced_window = self.gain.of_bytes(input.window);
        let two_granularities = self.timer_granularity.saturating_mul(2).as_nanos();
        let from_rate = (paced_window as u128 * two_granularities)
            .checked_div(input.smoothed_rtt.as_nanos())
            .map_or(usize::MAX, |bytes| {
                usize::try_from(bytes).unwrap_or(usize::MAX)
            });
        from_rate
            .max(self.initial_window.bytes(input.max_datagram_size))
            .min(
                self.max_burst_datagrams
                    .get()
                    .saturating_mul(input.max_datagram_size),
            )
    }
}

/// A [`TokenBucketPacerConfig`] breaks a rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
pub enum TokenBucketPacerConfigError {
    /// The gain is below 1.
    #[snafu(display("pacing gain {gain:?} is below 1"))]
    GainBelowOne {
        /// The rejected gain.
        gain: Ratio,
    },
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
}

/// A pacer that refills a bucket of bytes at `gain × window /
/// smoothed_rtt` (RFC 9002 §7.7), up to a burst limit that follows the
/// rate.
///
/// The bucket is full at the first refill. A refill that earns less than a
/// byte keeps the time it covered for the next one. Charging more than the
/// bucket holds empties it. It holds nothing back while it has a maximum
/// datagram's worth; below that, [`next_release`](Pacer::next_release) is
/// when it will have it again.
#[derive(Clone, Debug)]
pub struct TokenBucketPacer<I> {
    config: TokenBucketPacerConfig,
    tokens: usize,
    /// The instant the tokens are counted up to, and the input of that
    /// refill; `None` before the first.
    refilled: Option<(I, PacingInput)>,
}

impl<I> TokenBucketPacer<I> {
    /// A pacer that has not been refilled yet.
    pub const fn new(config: TokenBucketPacerConfig) -> Self {
        Self {
            config,
            tokens: 0,
            refilled: None,
        }
    }
}

impl<I> Pacer<I> for TokenBucketPacer<I>
where
    I: Ord + Copy + Add<Duration, Output = I> + Sub<Output = Duration>,
{
    fn next_release(&self) -> Option<I> {
        let (refilled_at, input) = self.refilled?;
        let wanted = input.max_datagram_size.min(self.config.burst_limit(&input));
        let missing = wanted.checked_sub(self.tokens).filter(|bytes| *bytes > 0)?;
        let rate_window = self.config.gain.of_bytes(input.window) as u128;
        // The time to earn `missing` bytes, rounded up:
        // missing × smoothed_rtt / (gain × window).
        let nanos = (missing as u128 * input.smoothed_rtt.as_nanos())
            .checked_add(rate_window.checked_sub(1)?)?
            .checked_div(rate_window)?;
        let wait = Duration::from_nanos(u64::try_from(nanos).ok()?);
        Some(refilled_at + wait)
    }

    fn allowance(&self) -> usize {
        self.tokens
    }

    fn refill(&mut self, at: I, input: PacingInput) {
        let capacity = self.config.burst_limit(&input);
        let Some((refilled_at, _)) = self.refilled else {
            self.tokens = capacity;
            self.refilled = Some((at, input));
            return;
        };
        let elapsed = checked_duration_since(at, refilled_at).unwrap_or(Duration::ZERO);
        let earned = (elapsed.as_nanos() * self.config.gain.of_bytes(input.window) as u128)
            .checked_div(input.smoothed_rtt.as_nanos())
            .map_or(usize::MAX, |bytes| {
                usize::try_from(bytes).unwrap_or(usize::MAX)
            });
        if earned == 0 {
            // The fraction of a byte stays with the time since the last
            // refill; so does an instant before it, such as the arrival of
            // an ACK read after a later poll.
            self.tokens = self.tokens.min(capacity);
            self.refilled = Some((refilled_at, input));
            return;
        }
        self.tokens = self.tokens.saturating_add(earned).min(capacity);
        self.refilled = Some((at, input));
    }

    fn on_charged(&mut self, bytes: usize) {
        self.tokens = self.tokens.saturating_sub(bytes);
    }
}

#[cfg(test)]
mod tests;
