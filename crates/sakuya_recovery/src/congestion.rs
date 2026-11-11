//! Congestion control ([RFC 9002 §7]).
//!
//! The caller keeps the bytes in flight, decides which packets are lost or
//! acknowledged, tests for persistent congestion, and lets probes exceed
//! the window. What is replaceable is the [`CongestionController`]: the
//! window and how it reacts to the events below. [`new_reno`] holds NewReno
//! (RFC 9002 Appendix B).
//!
//! # Events of one ACK
//!
//! For each link path, in this order: [`on_spurious_loss`] for packets
//! declared lost earlier and now acknowledged, [`on_ce`] if the CE count
//! grew, [`on_lost`] for the packets this ACK declares lost and then
//! [`on_persistent_congestion`] if they establish it, and [`on_acked`] for
//! the packets it newly acknowledges; after each congestion event the
//! caller asks [`wants_recovery_send`]. The time threshold has only the loss
//! steps; an ACK without new acknowledgments only the first.
//!
//! # Leaving the bytes in flight
//!
//! Each packet that counts as in flight leaves exactly once, and gives back
//! its [`SentState`](CongestionController::SentState) when it does: by
//! [`on_acked`], by [`on_lost`], or by [`on_removed`] when it leaves without
//! a signal (its send result is unknown, its loss does not count for
//! congestion, or its packet number space is discarded). Generic code
//! cannot copy a state, so it cannot give one back twice:
//!
//! ```compile_fail,E0382
//! use sakuya_recovery::congestion::{CongestionContext, CongestionController, RemovedPacket};
//!
//! fn given_back_twice<I, C: CongestionController<I>>(
//!     controller: &mut C,
//!     sent_state: C::SentState,
//!     context: &CongestionContext<I>,
//! ) {
//!     let packet = RemovedPacket { bytes: 1200, sent_state };
//!     controller.on_removed([packet].into_iter(), context);
//!     controller.on_removed([packet].into_iter(), context);
//! }
//! ```
//!
//! [RFC 9002 §7]: https://www.rfc-editor.org/rfc/rfc9002.html#section-7
//! [`on_spurious_loss`]: CongestionController::on_spurious_loss
//! [`on_ce`]: CongestionController::on_ce
//! [`on_lost`]: CongestionController::on_lost
//! [`on_persistent_congestion`]: CongestionController::on_persistent_congestion
//! [`on_acked`]: CongestionController::on_acked
//! [`on_removed`]: CongestionController::on_removed
//! [`wants_recovery_send`]: CongestionController::wants_recovery_send
use crate::rtt::RttEstimate;

pub mod new_reno;

/// The congestion controller of a link path.
///
/// `I` is the type of instants. Packets are given as iterators, so the
/// trait is not object safe; a controller that can be swapped at run time
/// is itself one controller.
pub trait CongestionController<I> {
    /// What the controller keeps for each packet in flight: given when the
    /// packet is sealed, stored with it, and given back when it leaves the
    /// bytes in flight.
    type SentState;

    /// What the controller keeps for one batch of losses that counts as a
    /// congestion event: stored with each lost packet of the batch, and
    /// given back if one turns out to have arrived, so that the controller
    /// can undo that event.
    type LossState: Clone;

    /// The congestion window, in bytes.
    fn window(&self) -> usize;

    /// A packet of `bytes` bytes that counts as in flight was sealed at
    /// `now`, the instant of the poll; `app_limited` is whether the link
    /// path was limited by the application then.
    fn on_packet_sealed(&mut self, bytes: usize, app_limited: bool, now: I) -> Self::SentState;

    /// Packets of the batch that `loss` was given for were acknowledged
    /// after all.
    fn on_spurious_loss(
        &mut self,
        loss: Self::LossState,
        packets: impl Iterator<Item = SpuriouslyLostPacket<I>>,
        context: &CongestionContext<I>,
    );

    /// The CE count grew by `increase`; `reference_sent_at` is when the
    /// largest packet the ACK acknowledges was sent.
    fn on_ce(&mut self, increase: u64, reference_sent_at: I, context: &CongestionContext<I>);

    /// A batch of packets was declared lost: a congestion event.
    fn on_lost(
        &mut self,
        packets: impl Iterator<Item = InFlightPacket<I, Self::SentState>>,
        context: &CongestionContext<I>,
    ) -> Self::LossState;

    /// The batch just given to [`on_lost`](Self::on_lost) establishes
    /// persistent congestion. The window MUST go down to the minimum
    /// window (RFC 9002 §7.6.2).
    fn on_persistent_congestion(&mut self, context: &CongestionContext<I>);

    /// Asked after each congestion event: `true` lets one datagram exceed
    /// the window, to send before the window comes down (RFC 9002 §7.3.2,
    /// MAY).
    fn wants_recovery_send(&mut self) -> bool;

    /// Packets were newly acknowledged.
    fn on_acked(
        &mut self,
        packets: impl Iterator<Item = InFlightPacket<I, Self::SentState>>,
        context: &CongestionContext<I>,
    );

    /// Packets left the bytes in flight without a signal.
    fn on_removed(
        &mut self,
        packets: impl Iterator<Item = RemovedPacket<Self::SentState>>,
        context: &CongestionContext<I>,
    );

    /// The maximum datagram size in use changed to `new` (RFC 9002 §7.2).
    fn on_max_datagram_size_changed(
        &mut self,
        new: usize,
        handshake_confirmed: bool,
        context: &CongestionContext<I>,
    );
}

impl<I, T: CongestionController<I> + ?Sized> CongestionController<I> for &mut T {
    type SentState = T::SentState;
    type LossState = T::LossState;

    fn window(&self) -> usize {
        (**self).window()
    }

    fn on_packet_sealed(&mut self, bytes: usize, app_limited: bool, now: I) -> Self::SentState {
        (**self).on_packet_sealed(bytes, app_limited, now)
    }

    fn on_spurious_loss(
        &mut self,
        loss: Self::LossState,
        packets: impl Iterator<Item = SpuriouslyLostPacket<I>>,
        context: &CongestionContext<I>,
    ) {
        (**self).on_spurious_loss(loss, packets, context);
    }

    fn on_ce(&mut self, increase: u64, reference_sent_at: I, context: &CongestionContext<I>) {
        (**self).on_ce(increase, reference_sent_at, context);
    }

    fn on_lost(
        &mut self,
        packets: impl Iterator<Item = InFlightPacket<I, Self::SentState>>,
        context: &CongestionContext<I>,
    ) -> Self::LossState {
        (**self).on_lost(packets, context)
    }

    fn on_persistent_congestion(&mut self, context: &CongestionContext<I>) {
        (**self).on_persistent_congestion(context);
    }

    fn wants_recovery_send(&mut self) -> bool {
        (**self).wants_recovery_send()
    }

    fn on_acked(
        &mut self,
        packets: impl Iterator<Item = InFlightPacket<I, Self::SentState>>,
        context: &CongestionContext<I>,
    ) {
        (**self).on_acked(packets, context);
    }

    fn on_removed(
        &mut self,
        packets: impl Iterator<Item = RemovedPacket<Self::SentState>>,
        context: &CongestionContext<I>,
    ) {
        (**self).on_removed(packets, context);
    }

    fn on_max_datagram_size_changed(
        &mut self,
        new: usize,
        handshake_confirmed: bool,
        context: &CongestionContext<I>,
    ) {
        (**self).on_max_datagram_size_changed(new, handshake_confirmed, context);
    }
}

/// The facts of the link path that come with each event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CongestionContext<I> {
    /// When the event happened: the arrival of the ACK, or the instant of
    /// the poll for an expiry.
    pub now: I,
    /// The bytes in flight, after this event is accounted for.
    pub bytes_in_flight: usize,
    /// The RTT estimate of the link path.
    pub rtt: RttEstimate,
    /// Whether this ACK gave the link path a new RTT sample; `false` for
    /// an expiry.
    pub rtt_sampled: bool,
    /// The maximum datagram size in use.
    pub max_datagram_size: usize,
}

/// A packet that counted as in flight, acknowledged or declared lost.
#[derive(Debug, PartialEq, Eq)]
pub struct InFlightPacket<I, S> {
    /// Its size in bytes.
    pub bytes: usize,
    /// When the link accepted it.
    pub sent_at: I,
    /// Whether the link path was limited by the application when it was
    /// sealed.
    pub app_limited: bool,
    /// What the controller gave for it.
    pub sent_state: S,
}

/// A packet that left the bytes in flight without a signal. A packet whose
/// send result is unknown has no send time.
#[derive(Debug, PartialEq, Eq)]
pub struct RemovedPacket<S> {
    /// Its size in bytes.
    pub bytes: usize,
    /// What the controller gave for it.
    pub sent_state: S,
}

/// A packet declared lost earlier and now acknowledged. Its
/// [`SentState`](CongestionController::SentState) was given back at the
/// loss.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpuriouslyLostPacket<I> {
    /// Its size in bytes.
    pub bytes: usize,
    /// When the link accepted it.
    pub sent_at: I,
}

/// The initial congestion window (RFC 9002 §7.2): `datagrams` maximum
/// datagrams, limited to the larger of `limit` bytes and two datagrams.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InitialWindow {
    datagrams: usize,
    limit: usize,
}

impl InitialWindow {
    /// Ten datagrams, limited to the larger of 14720 bytes and two
    /// datagrams, as RFC 9002 §7.2 recommends.
    pub const RECOMMENDED: Self = Self {
        datagrams: 10,
        limit: 14720,
    };

    /// `datagrams` maximum datagrams, limited to the larger of `limit`
    /// bytes and two datagrams.
    pub const fn new(datagrams: usize, limit: usize) -> Self {
        Self { datagrams, limit }
    }

    /// The number of datagrams before the limit.
    pub const fn datagrams(self) -> usize {
        self.datagrams
    }

    /// The initial window in bytes for `max_datagram_size`.
    pub fn bytes(self, max_datagram_size: usize) -> usize {
        self.datagrams
            .saturating_mul(max_datagram_size)
            .min(self.limit.max(max_datagram_size.saturating_mul(2)))
    }
}

#[cfg(test)]
mod tests;
