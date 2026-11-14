//! The monotonic clock of a tokio runtime, for sakuya: [`TokioClock`].
//!
//! It reads tokio's time and sleeps on tokio's timer, so it follows the
//! runtime it is used in, including a runtime whose time is paused.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use core::time::Duration;
use std::time::Instant;

use sakuya_clock::MonotonicClock;

/// The clock of the tokio runtime it is used in.
///
/// Its instants are the standard library's, converted from tokio's own, so
/// that they take part in arithmetic everywhere sakuya needs it. It is read
/// and slept on from inside the runtime: an endpoint's and a connection's
/// drivers, and the links that report instants, run on it.
///
/// [`sleep_until`](MonotonicClock::sleep_until) panics outside a tokio
/// runtime, or in one without its time driver enabled, as
/// [`tokio::time::sleep_until`] does.
#[derive(Clone, Copy, Debug, Default)]
pub struct TokioClock;

impl MonotonicClock for TokioClock {
    type Instant = Instant;
    type Sleep = tokio::time::Sleep;

    fn now(&self) -> Instant {
        tokio::time::Instant::now().into_std()
    }

    fn sleep_until(&self, at: Instant) -> tokio::time::Sleep {
        tokio::time::sleep_until(tokio::time::Instant::from_std(at))
    }

    /// One millisecond: tokio's timer runs at millisecond granularity.
    fn timer_granularity(&self) -> Duration {
        Duration::from_millis(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("a runtime with time builds")
    }

    #[test]
    fn a_sleep_ends_no_earlier_than_its_instant() {
        runtime().block_on(async {
            let clock = TokioClock;
            let start = clock.now();
            let at = start + Duration::from_millis(5);
            clock.sleep_until(at).await;
            assert!(clock.now() >= at);
        });
    }

    #[test]
    fn a_sleep_until_the_past_ends_at_once() {
        runtime().block_on(async {
            let clock = TokioClock;
            let now = clock.now();
            clock.sleep_until(now).await;
            assert!(clock.now() >= now);
        });
    }
}
