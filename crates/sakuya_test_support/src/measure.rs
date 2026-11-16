//! Counters for measuring a run: heap allocations of a thread, and the
//! polls and wakes of a task.
//!
//! Allocations are counted only in a program that installs
//! [`CountingAllocator`] as its global allocator:
//!
//! ```ignore
//! #[global_allocator]
//! static ALLOCATOR: sakuya_test_support::measure::CountingAllocator =
//!     sakuya_test_support::measure::CountingAllocator;
//! ```
//!
//! The counts are per thread, so that tests running beside one another on
//! other threads do not add to them; a run measured this way keeps its work
//! on one thread, such as a current-thread tokio runtime.

use core::{
    cell::Cell,
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll, Waker},
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::{Arc, Mutex, PoisonError},
    task::Wake,
};

/// How many heap operations a thread made, and how many bytes it asked
/// for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AllocationCounts {
    /// Allocations, zeroed or not.
    pub allocations: u64,
    /// Reallocations.
    pub reallocations: u64,
    /// Deallocations.
    pub deallocations: u64,
    /// Bytes asked for by allocations, and by reallocations beyond the
    /// size they had.
    pub bytes: u64,
}

impl AllocationCounts {
    /// What happened from `earlier` to `self`.
    #[must_use]
    pub fn since(self, earlier: Self) -> Self {
        Self {
            allocations: self.allocations - earlier.allocations,
            reallocations: self.reallocations - earlier.reallocations,
            deallocations: self.deallocations - earlier.deallocations,
            bytes: self.bytes - earlier.bytes,
        }
    }
}

thread_local! {
    static COUNTS: Cell<AllocationCounts> = const {
        Cell::new(AllocationCounts {
            allocations: 0,
            reallocations: 0,
            deallocations: 0,
            bytes: 0,
        })
    };
}

fn count(change: impl FnOnce(&mut AllocationCounts)) {
    // a thread being torn down has no counts left to add to
    let _ = COUNTS.try_with(|counts| {
        let mut now = counts.get();
        change(&mut now);
        counts.set(now);
    });
}

/// The counts of the current thread so far; zero without
/// [`CountingAllocator`].
pub fn allocation_counts() -> AllocationCounts {
    COUNTS.try_with(Cell::get).unwrap_or_default()
}

/// The system allocator, counting each thread's operations.
#[derive(Clone, Copy, Debug, Default)]
pub struct CountingAllocator;

// SAFETY: every operation is forwarded unchanged to `System`, which upholds
// the contract of `GlobalAlloc`; the counting touches only a const-initialised
// thread-local `Cell` of a `Copy` type, which neither allocates nor
// registers a destructor.
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count(|c| {
            c.allocations += 1;
            c.bytes += layout.size() as u64;
        });
        // SAFETY: the caller upholds `alloc`'s contract, passed on as is.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count(|c| {
            c.allocations += 1;
            c.bytes += layout.size() as u64;
        });
        // SAFETY: as in `alloc`.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        count(|c| c.deallocations += 1);
        // SAFETY: the caller upholds `dealloc`'s contract, passed on as is.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count(|c| {
            c.reallocations += 1;
            c.bytes += new_size.saturating_sub(layout.size()) as u64;
        });
        // SAFETY: the caller upholds `realloc`'s contract, passed on as is.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

/// How often a task was polled and woken.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WakeCounts {
    /// Polls of the task.
    pub polls: u64,
    /// Wakes of a waker the task was given, by value or by reference.
    pub wakes: u64,
}

impl WakeCounts {
    /// What happened from `earlier` to `self`.
    #[must_use]
    pub fn since(self, earlier: Self) -> Self {
        Self {
            polls: self.polls - earlier.polls,
            wakes: self.wakes - earlier.wakes,
        }
    }
}

/// The waker a counted task is polled with: it counts each wake and passes
/// it on to the executor's waker of the latest poll.
#[derive(Debug, Default)]
struct WakeCounter {
    polls: AtomicU64,
    wakes: AtomicU64,
    executor: Mutex<Option<Waker>>,
}

impl Wake for WakeCounter {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::Relaxed);
        let executor = self
            .executor
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(waker) = executor {
            waker.wake();
        }
    }
}

/// Reads the counts of a [`Counted`] task, also after it ended.
#[derive(Clone, Debug)]
pub struct WakeCountReader(Arc<WakeCounter>);

impl WakeCountReader {
    /// The counts so far.
    pub fn counts(&self) -> WakeCounts {
        WakeCounts {
            polls: self.0.polls.load(Ordering::Relaxed),
            wakes: self.0.wakes.load(Ordering::Relaxed),
        }
    }
}

/// A future whose polls and wakes are counted.
#[derive(Debug)]
pub struct Counted<F> {
    future: Pin<Box<F>>,
    counter: Arc<WakeCounter>,
}

impl<F: Future> Counted<F> {
    /// `future`, counted, and the reader of its counts.
    pub fn new(future: F) -> (Self, WakeCountReader) {
        let counter = Arc::new(WakeCounter::default());
        (
            Self {
                future: Box::pin(future),
                counter: Arc::clone(&counter),
            },
            WakeCountReader(counter),
        )
    }
}

impl<F: Future> Future for Counted<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let this = self.get_mut();
        this.counter.polls.fetch_add(1, Ordering::Relaxed);
        {
            let mut executor = this
                .counter
                .executor
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if !executor
                .as_ref()
                .is_some_and(|waker| waker.will_wake(cx.waker()))
            {
                *executor = Some(cx.waker().clone());
            }
        }
        let waker = Waker::from(Arc::clone(&this.counter));
        this.future.as_mut().poll(&mut Context::from_waker(&waker))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_counted_future_counts_its_polls_and_wakes() {
        let mut woken = false;
        let (mut counted, reader) = Counted::new(core::future::poll_fn(|cx| {
            if woken {
                Poll::Ready(())
            } else {
                woken = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(Pin::new(&mut counted).poll(&mut cx).is_pending());
        assert!(Pin::new(&mut counted).poll(&mut cx).is_ready());
        assert_eq!(reader.counts(), WakeCounts { polls: 2, wakes: 1 });
    }
}
