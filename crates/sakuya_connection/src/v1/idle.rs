//! The idle timeout of a connection (RFC 9000 §10.1).

use core::{ops::Add, time::Duration};

/// When the connection ends silently for having been idle.
///
/// Each side advertises a maximum idle timeout, or none. The timeout in
/// effect is the smaller of the two when both advertise one, the one
/// advertised when only one does, and none when neither does; before the
/// peer's is known, this side's own. It is never shorter than three probe
/// timeouts, so that several probes can expire before the connection
/// ends. The timer restarts when a packet from the peer is processed, and
/// when an ack-eliciting packet is sent if none was sent since the last
/// packet processed. It starts at the first of these: before it, the
/// connection has nothing to be idle from and there is no deadline.
///
/// `I` is the instant of the connection's clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdleTimeout<I> {
    local: Option<Duration>,
    peer: Option<Duration>,
    probe_timeout: Duration,
    restarted_at: Option<I>,
    sent_since_received: bool,
}

impl<I: Ord + Copy + Add<Duration, Output = I>> IdleTimeout<I> {
    /// This side advertises `local` (`None`, or zero, for no idle timeout);
    /// the timer has not started.
    pub fn new(local: Option<Duration>) -> Self {
        Self {
            local: local.filter(|timeout| !timeout.is_zero()),
            peer: None,
            probe_timeout: Duration::ZERO,
            restarted_at: None,
            sent_since_received: false,
        }
    }

    /// This side's maximum idle timeout is now `local`, as it was sent:
    /// `None`, or zero, for none.
    pub fn set_local(&mut self, local: Option<Duration>) {
        self.local = local.filter(|timeout| !timeout.is_zero());
    }

    /// This side's advertised maximum idle timeout, `None` for none.
    pub fn local(&self) -> Option<Duration> {
        self.local
    }

    /// The peer's advertised maximum idle timeout, `None` for none or not
    /// known yet.
    pub fn peer(&self) -> Option<Duration> {
        self.peer
    }

    /// The peer's advertised maximum idle timeout is known: `None`, or
    /// zero, when it advertised none.
    pub fn set_peer(&mut self, peer: Option<Duration>) {
        self.peer = peer.filter(|timeout| !timeout.is_zero());
    }

    /// The current probe timeout is `pto`: the timeout in effect is at
    /// least three times it.
    pub fn set_probe_timeout(&mut self, pto: Duration) {
        self.probe_timeout = pto;
    }

    /// The current probe timeout, zero before one is set.
    pub fn probe_timeout(&self) -> Duration {
        self.probe_timeout
    }

    /// The timeout in effect, or `None` when neither side advertises one.
    pub fn timeout(&self) -> Option<Duration> {
        let advertised = match (self.local, self.peer) {
            (Some(local), Some(peer)) => local.min(peer),
            (Some(timeout), None) | (None, Some(timeout)) => timeout,
            (None, None) => return None,
        };
        Some(advertised.max(self.probe_timeout.saturating_mul(3)))
    }

    /// The instant the connection ends for having been idle, if it can.
    pub fn deadline(&self) -> Option<I> {
        Some(self.restarted_at? + self.timeout()?)
    }

    /// A packet from the peer that arrived at `now` was processed.
    ///
    /// A packet can be processed after one that arrived later, for example
    /// when it waited for its keys; the timer only moves forward, so a
    /// restart later than `now` stays, and so does whether an ack-eliciting
    /// packet was sent since it.
    pub fn packet_processed(&mut self, now: I) {
        if self.restarted_at.is_some_and(|restarted| restarted > now) {
            return;
        }
        self.restarted_at = Some(now);
        self.sent_since_received = false;
    }

    /// An ack-eliciting packet was sent at `now`.
    pub fn ack_eliciting_sent(&mut self, now: I) {
        if !self.sent_since_received {
            self.restarted_at = Some(now);
            self.sent_since_received = true;
        }
    }
}
