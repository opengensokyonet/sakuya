//! Time: the clock a connection reads and sleeps on.
//!
//! Only the driver reads the clock: once at the start of each poll. That
//! instant is the "now" of everything the poll does; components keep
//! deadlines in their state and are handed the instant as an argument.
use core::{future::Future, ops::Add, time::Duration};

/// A monotonic clock and its timer.
///
/// Chosen when an endpoint is composed; its `Instant` is also the instant
/// of a link's arrivals and sends. It is not calendar time.
pub trait MonotonicClock {
    /// A point in time.
    type Instant: Ord + Copy + Add<Duration, Output = Self::Instant> + core::fmt::Debug;
    /// A timer that ends at an instant; it need not be resettable.
    type Sleep: Future<Output = ()>;
    /// The current instant.
    fn now(&self) -> Self::Instant;
    /// A timer that ends at `at`.
    fn sleep_until(&self, at: Self::Instant) -> Self::Sleep;
    /// The precision `sleep_until` achieves (RFC 9002's timer granularity).
    fn timer_granularity(&self) -> Duration;
}

/// The choices of a composition that belong to no part: the types every
/// part uses.
pub trait ConnectionChoices: 'static {
    /// The clock.
    type Clock: MonotonicClock;
}

/// A point in time of the choices `T`.
pub type InstantOf<T> = <<T as ConnectionChoices>::Clock as MonotonicClock>::Instant;
