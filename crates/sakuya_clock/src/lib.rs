//! The monotonic clock and timer sakuya reads.
//!
//! A connection's driver reads a [`MonotonicClock`] once at the start of
//! each poll and sleeps on it until its next deadline; a link reports the
//! instants of its arrivals and sends on the same clock. Which clock that is
//! is chosen when an endpoint is composed: each runtime provides its own
//! implementation, and the code that composes an endpoint hands the same
//! clock to the endpoint and to the link bindings it adds.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use core::{
    future::Future,
    ops::{Add, Sub},
    time::Duration,
};

/// A monotonic clock and its timer.
///
/// Chosen when an endpoint is composed; its `Instant` is also the instant
/// of a link's arrivals and sends. It is not calendar time.
///
/// A clone is another handle to the same clock: the code that composes an
/// endpoint gives one to the endpoint and one to each link binding.
pub trait MonotonicClock: Clone {
    /// A point in time.
    ///
    /// Subtracting gives the time between two instants. It is used only
    /// after comparing them, never where the result would be below zero,
    /// so what a type does there (`std::time::Instant` saturates,
    /// `Duration` panics) does not matter. Adding is checked where the
    /// duration has no bound, so that a deadline past the last instant the
    /// type can represent is none rather than a panic.
    type Instant: Ord
        + Copy
        + Add<Duration, Output = Self::Instant>
        + CheckedAdd<Duration>
        + Sub<Output = Duration>
        + core::fmt::Debug;
    /// A timer that ends at an instant; it need not be resettable.
    type Sleep: Future<Output = ()>;
    /// The current instant.
    fn now(&self) -> Self::Instant;
    /// A timer that ends at `at`.
    fn sleep_until(&self, at: Self::Instant) -> Self::Sleep;
    /// The precision `sleep_until` achieves (RFC 9002's timer granularity).
    fn timer_granularity(&self) -> Duration;
}

/// Addition that tells when the result cannot be represented, as the
/// `checked_add` of the standard library's time types.
pub trait CheckedAdd<Rhs = Duration>: Sized {
    /// `self` plus `rhs`, or `None` when the sum cannot be represented.
    fn checked_add(self, rhs: Rhs) -> Option<Self>;
}

impl CheckedAdd<Duration> for std::time::Instant {
    fn checked_add(self, rhs: Duration) -> Option<Self> {
        std::time::Instant::checked_add(&self, rhs)
    }
}

impl CheckedAdd<Duration> for Duration {
    fn checked_add(self, rhs: Duration) -> Option<Self> {
        Duration::checked_add(self, rhs)
    }
}
