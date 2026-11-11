//! A clock, an outer waker and a log for the tests, all on the test's thread.
#![allow(dead_code)]
use std::{
    cell::{Cell, RefCell},
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
    time::Duration,
};

use sakuya_connection::clock::{Clock, ConnectionChoices};

pub mod parts;

thread_local! {
    static NOW: Cell<Duration> = const { Cell::new(Duration::ZERO) };
    static SLEEPERS: RefCell<Vec<(Duration, Waker)>> = const { RefCell::new(Vec::new()) };
    static LOG: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// The test's clock: time moves only when the test says so.
#[derive(Clone, Debug, Default)]
pub struct TestClock;

/// A sleep of the test's clock.
pub struct TestSleep(Duration);

impl Future for TestSleep {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if now() >= self.0 {
            Poll::Ready(())
        } else {
            SLEEPERS.with(|s| s.borrow_mut().push((self.0, cx.waker().clone())));
            Poll::Pending
        }
    }
}

impl Clock for TestClock {
    type Instant = Duration;
    type Sleep = TestSleep;
    fn now(&self) -> Duration {
        now()
    }
    fn sleep_until(&self, at: Duration) -> TestSleep {
        TestSleep(at)
    }
    fn timer_granularity(&self) -> Duration {
        Duration::from_millis(1)
    }
}

/// The choices of the tests' compositions.
pub struct Mine;
impl ConnectionChoices for Mine {
    type Clock = TestClock;
}

pub fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

pub fn now() -> Duration {
    NOW.with(Cell::get)
}

/// Move the clock to `at` and wake the sleeps that ended.
pub fn advance_to(at: Duration) {
    NOW.with(|n| n.set(at));
    let due: Vec<Waker> = SLEEPERS.with(|s| {
        let mut sleepers = s.borrow_mut();
        let (due, waiting) = std::mem::take(&mut *sleepers)
            .into_iter()
            .partition(|(end, _)| *end <= at);
        *sleepers = waiting;
        due.into_iter().map(|(_, waker)| waker).collect()
    });
    for waker in due {
        waker.wake();
    }
}

pub fn log(line: impl Into<String>) {
    LOG.with(|l| l.borrow_mut().push(line.into()));
}

pub fn take_log() -> Vec<String> {
    LOG.with(|l| std::mem::take(&mut *l.borrow_mut()))
}

/// An outer waker that counts its wakes.
#[derive(Default)]
pub struct Counter(AtomicUsize);
impl Wake for Counter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

pub struct Outer {
    counter: Arc<Counter>,
    waker: Waker,
}

impl Outer {
    pub fn new() -> Self {
        let counter = Arc::new(Counter::default());
        Self {
            waker: Waker::from(counter.clone()),
            counter,
        }
    }
    pub fn wakes(&self) -> usize {
        self.counter.0.load(Ordering::SeqCst)
    }
    pub fn poll<F: Future + Unpin>(&self, future: &mut F) -> Poll<F::Output> {
        Pin::new(future).poll(&mut Context::from_waker(&self.waker))
    }
}
