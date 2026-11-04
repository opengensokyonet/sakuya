//! The current time, as a capability.
//!
//! Ticket lifetimes and certificate validity depend on the time, which
//! comes from a [`Clock`] given when an endpoint is built: [`SystemClock`]
//! reads the system's clock, and [`ManualClock`] holds a time that is set
//! by hand, so that tests and recorded traces can fix it.

use std::{
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, SystemTime},
};

/// A source of the current time.
pub trait Clock {
    /// The current time.
    fn now(&self) -> SystemTime;
}

impl<K: Clock + ?Sized> Clock for &K {
    fn now(&self) -> SystemTime {
        (**self).now()
    }
}

impl<K: Clock + ?Sized> Clock for Arc<K> {
    fn now(&self) -> SystemTime {
        (**self).now()
    }
}

/// The system's clock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// A clock whose time moves only when it is set or advanced.
#[derive(Debug)]
pub struct ManualClock {
    time: Mutex<SystemTime>,
}

impl ManualClock {
    /// A clock that reads `time`.
    pub fn new(time: SystemTime) -> Self {
        Self {
            time: Mutex::new(time),
        }
    }

    /// Sets the time to `time`.
    pub fn set(&self, time: SystemTime) {
        *self.time.lock().unwrap_or_else(PoisonError::into_inner) = time;
    }

    /// Moves the time forward by `by`.
    pub fn advance(&self, by: Duration) {
        let mut time = self.time.lock().unwrap_or_else(PoisonError::into_inner);
        *time += by;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> SystemTime {
        *self.time.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::{Clock, ManualClock, SystemClock};
    use std::time::{Duration, SystemTime};

    #[test]
    fn a_manual_clock_moves_when_told() {
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let clock = ManualClock::new(start);
        assert_eq!(clock.now(), start);
        clock.advance(Duration::from_secs(5));
        assert_eq!(Clock::now(&&clock), start + Duration::from_secs(5));
        clock.set(start);
        assert_eq!(clock.now(), start);
        assert!(SystemClock.now() > SystemTime::UNIX_EPOCH);
    }
}
