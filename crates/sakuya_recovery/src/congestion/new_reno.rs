//! NewReno ([RFC 9002 §7] and Appendix B).
//!
//! The window starts in slow start, where it grows by the bytes
//! acknowledged. A congestion event starts a recovery period, multiplies
//! the window by the loss reduction factor and makes that the slow start
//! threshold; above the threshold the window is in congestion avoidance and
//! grows by about one maximum datagram per window acknowledged. The window
//! does not grow while a recovery period lasts, which is until a packet
//! sent after it started is acknowledged, nor for packets sealed while the
//! link path was limited by the application. NewReno does not undo
//! spurious losses.
//!
//! [RFC 9002 §7]: https://www.rfc-editor.org/rfc/rfc9002.html#section-7
use super::{
    CongestionContext, CongestionController, InFlightPacket, InitialWindow, RemovedPacket,
    SpuriouslyLostPacket,
};
use crate::{
    ecn::{EcnContext, EcnPolicy, ect0_testing_marking},
    pto::PtoPolicy,
    ratio::Ratio,
};
use core::{ops::Sub, time::Duration};
use sakuya_link::EcnMarking;
use snafu::{Snafu, ensure};

/// The constants of [`NewReno`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NewRenoConfig {
    initial_window: InitialWindow,
    minimum_window_datagrams: usize,
    loss_reduction: Ratio,
}

impl NewRenoConfig {
    /// The values RFC 9002 recommends: the initial window of
    /// [`InitialWindow::RECOMMENDED`], a minimum window of two datagrams,
    /// and a loss reduction factor of 1/2.
    pub const RECOMMENDED: Self = Self {
        initial_window: InitialWindow::RECOMMENDED,
        minimum_window_datagrams: 2,
        loss_reduction: Ratio::literal(1, 2),
    };

    /// The constants given.
    ///
    /// # Errors
    ///
    /// - [`NewRenoConfigError::ZeroMinimumWindow`] if the minimum window is
    ///   no datagram;
    /// - [`NewRenoConfigError::InitialWindowBelowMinimum`] if the initial
    ///   window has fewer datagrams than the minimum window;
    /// - [`NewRenoConfigError::LossReductionOutOfRange`] if the loss
    ///   reduction factor is not between 0 and 1, both excluded.
    pub fn new(
        initial_window: InitialWindow,
        minimum_window_datagrams: usize,
        loss_reduction: Ratio,
    ) -> Result<Self, NewRenoConfigError> {
        ensure!(minimum_window_datagrams > 0, ZeroMinimumWindowSnafu);
        ensure!(
            initial_window.datagrams() >= minimum_window_datagrams,
            InitialWindowBelowMinimumSnafu {
                initial_window_datagrams: initial_window.datagrams(),
                minimum_window_datagrams,
            }
        );
        ensure!(
            loss_reduction.numerator() > 0 && loss_reduction.is_below_one(),
            LossReductionOutOfRangeSnafu { loss_reduction }
        );
        Ok(Self {
            initial_window,
            minimum_window_datagrams,
            loss_reduction,
        })
    }

    /// The initial window.
    pub const fn initial_window(&self) -> InitialWindow {
        self.initial_window
    }

    /// The minimum window, in datagrams.
    pub const fn minimum_window_datagrams(&self) -> usize {
        self.minimum_window_datagrams
    }

    /// The loss reduction factor.
    pub const fn loss_reduction(&self) -> Ratio {
        self.loss_reduction
    }
}

/// A [`NewRenoConfig`] breaks a rule of the algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
pub enum NewRenoConfigError {
    /// The minimum window holds no datagram.
    #[snafu(display("minimum window is zero datagrams"))]
    ZeroMinimumWindow,
    /// The initial window is smaller than the minimum window.
    #[snafu(display(
        "initial window of {initial_window_datagrams} datagrams is below the minimum of {minimum_window_datagrams}"
    ))]
    InitialWindowBelowMinimum {
        /// The datagrams of the initial window.
        initial_window_datagrams: usize,
        /// The datagrams of the minimum window, above those of the initial
        /// window.
        minimum_window_datagrams: usize,
    },
    /// The loss reduction factor does not reduce the window, or reduces it
    /// to nothing.
    #[snafu(display("loss reduction factor {loss_reduction:?} is not between 0 and 1"))]
    LossReductionOutOfRange {
        /// The rejected factor.
        loss_reduction: Ratio,
    },
}

/// The NewReno congestion controller, with the default probe timeout and
/// ECN policies.
///
/// - At an expiry of the probe timeout it sends two probe datagrams in
///   every space with packets in flight (the default of [`PtoPolicy`]).
/// - It answers `true` to the first duplicate Initial CRYPTO of the
///   connection only: once is enough to recover from one lost packet (RFC
///   9002 §6.2.3).
/// - It tests ECN with ECT(0) ([`ect0_testing_marking`]) and does not
///   validate again after a failure.
#[derive(Clone, Debug)]
pub struct NewReno<I> {
    config: NewRenoConfig,
    max_datagram_size: usize,
    window: usize,
    slow_start_threshold: usize,
    /// The fraction of a byte of congestion avoidance growth carried over,
    /// as a numerator over the window.
    growth_remainder: usize,
    /// When the current recovery period started.
    recovery_start: Option<I>,
    recovery_send: bool,
    duplicate_initial_crypto_answered: bool,
}

impl<I> NewReno<I> {
    /// A controller in slow start, with the initial window for
    /// `max_datagram_size`.
    pub fn new(config: NewRenoConfig, max_datagram_size: usize) -> Self {
        Self {
            config,
            max_datagram_size,
            window: initial_window(&config, max_datagram_size),
            slow_start_threshold: usize::MAX,
            growth_remainder: 0,
            recovery_start: None,
            recovery_send: false,
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
        minimum_window(&self.config, self.max_datagram_size)
    }

    /// `window += max_datagram_size × bytes / window`, keeping the fraction.
    fn grow_in_congestion_avoidance(&mut self, bytes: usize) {
        let scaled = self.max_datagram_size as u128 * bytes as u128 + self.growth_remainder as u128;
        let window = self.window as u128;
        let (Some(growth), Some(remainder)) =
            (scaled.checked_div(window), scaled.checked_rem(window))
        else {
            return;
        };
        // invariant: a remainder is below its divisor, which is a `usize`.
        self.growth_remainder = usize::try_from(remainder).unwrap_or(0);
        self.window = self
            .window
            .saturating_add(usize::try_from(growth).unwrap_or(usize::MAX));
    }
}

impl<I: Ord + Copy> NewReno<I> {
    /// Whether a packet sent at `sent_at` belongs to the recovery period.
    fn in_recovery(&self, sent_at: I) -> bool {
        self.recovery_start.is_some_and(|start| sent_at <= start)
    }

    /// A congestion event for a packet sent at `sent_at` (Appendix B.6).
    fn on_congestion_event(&mut self, sent_at: I, now: I) {
        if self.in_recovery(sent_at) {
            return;
        }
        self.recovery_start = Some(now);
        self.slow_start_threshold = self.config.loss_reduction.of_bytes(self.window);
        self.window = self.slow_start_threshold.max(self.minimum_window());
        self.growth_remainder = 0;
        self.recovery_send = true;
    }
}

fn minimum_window(config: &NewRenoConfig, max_datagram_size: usize) -> usize {
    config
        .minimum_window_datagrams
        .saturating_mul(max_datagram_size)
}

/// The initial window, at least the minimum window: for a large datagram
/// the limit of two datagrams can be below a minimum of more than two.
fn initial_window(config: &NewRenoConfig, max_datagram_size: usize) -> usize {
    config
        .initial_window
        .bytes(max_datagram_size)
        .max(minimum_window(config, max_datagram_size))
}

impl<I: Ord + Copy> CongestionController<I> for NewReno<I> {
    type SentState = ();
    type LossState = ();

    fn window(&self) -> usize {
        self.window
    }

    fn on_packet_sealed(&mut self, _bytes: usize, _app_limited: bool, _now: I) {}

    fn on_spurious_loss(
        &mut self,
        _loss: (),
        _packets: impl Iterator<Item = SpuriouslyLostPacket<I>>,
        _context: &CongestionContext<I>,
    ) {
    }

    fn on_ce(&mut self, _increase: u64, reference_sent_at: I, context: &CongestionContext<I>) {
        // Appendix B.7.
        self.on_congestion_event(reference_sent_at, context.now);
    }

    fn on_lost(
        &mut self,
        packets: impl Iterator<Item = InFlightPacket<I, ()>>,
        context: &CongestionContext<I>,
    ) {
        // Appendix B.8: one event, for the last packet sent.
        if let Some(last_sent_at) = packets.map(|packet| packet.sent_at).max() {
            self.on_congestion_event(last_sent_at, context.now);
        }
    }

    fn on_persistent_congestion(&mut self, _context: &CongestionContext<I>) {
        self.window = self.minimum_window();
        self.recovery_start = None;
        self.growth_remainder = 0;
    }

    fn wants_recovery_send(&mut self) -> bool {
        core::mem::take(&mut self.recovery_send)
    }

    fn on_acked(
        &mut self,
        packets: impl Iterator<Item = InFlightPacket<I, ()>>,
        _context: &CongestionContext<I>,
    ) {
        // Appendix B.5.
        for packet in packets {
            if self.in_recovery(packet.sent_at) || packet.app_limited {
                continue;
            }
            if self.window < self.slow_start_threshold {
                self.window = self.window.saturating_add(packet.bytes);
            } else {
                self.grow_in_congestion_avoidance(packet.bytes);
            }
        }
    }

    fn on_removed(
        &mut self,
        _packets: impl Iterator<Item = RemovedPacket<()>>,
        _context: &CongestionContext<I>,
    ) {
    }

    /// While the window is still the initial window of the old size, it
    /// becomes the initial window of the new one. A size that shrinks
    /// before the handshake is confirmed sets the window to the new initial
    /// window (§7.2: to complete the handshake). Otherwise only the minimum
    /// window changes, and the window stays at least that.
    fn on_max_datagram_size_changed(
        &mut self,
        new: usize,
        handshake_confirmed: bool,
        _context: &CongestionContext<I>,
    ) {
        let old_initial = initial_window(&self.config, self.max_datagram_size);
        let shrinks = new < self.max_datagram_size;
        self.max_datagram_size = new;
        let new_initial = initial_window(&self.config, new);
        if self.window == old_initial || (shrinks && !handshake_confirmed) {
            self.window = new_initial;
            self.growth_remainder = 0;
        } else {
            self.window = self.window.max(self.minimum_window());
        }
    }
}

impl<I> PtoPolicy<I> for NewReno<I> {
    fn on_duplicate_initial_crypto(&mut self) -> bool {
        !core::mem::replace(&mut self.duplicate_initial_crypto_answered, true)
    }
}

impl<I: Ord + Copy + Sub<Output = Duration>> EcnPolicy<I> for NewReno<I> {
    fn marking(&mut self, context: &EcnContext<I>) -> EcnMarking {
        ect0_testing_marking(context)
    }

    fn wants_revalidation(&mut self, _context: &EcnContext<I>) -> bool {
        false
    }
}

#[cfg(test)]
mod tests;
