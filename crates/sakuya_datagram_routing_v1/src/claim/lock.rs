//! The lock of the datagram the candidates of one round compete for
//!
//! Every candidate of a datagram waits for the same access before its
//! synchronous judgment runs ([`try_exclusive`]); the access is a lock around
//! the datagram's slot, held only during that judgment and never across an
//! await. Which lock it is follows how the routing domain is synchronized: the
//! index of a domain names it ([`RouteIndex::ClaimLock`]), and every candidate,
//! delivery and deliverer of the domain names the same one. This module gives
//! the lock of a domain on one thread, [`RefCellDatagramClaimLock`]; a crate
//! with the locks of a runtime gives the one whose candidates move between
//! threads.
//!
//! [`try_exclusive`]: super::candidate::DatagramClaimCandidate::try_exclusive
//! [`RouteIndex::ClaimLock`]: crate::route::index::RouteIndex::ClaimLock

use alloc::vec::Vec;
use core::cell::{RefCell, RefMut};
use core::fmt;
use core::future::{Future, poll_fn};
use core::ops::{Deref, DerefMut};
use core::task::{Poll, Waker};

/// A kind of asynchronous lock, which the datagram of one claim is kept in
/// (`DatagramClaimLock`).
///
/// It is a family of lock types, one for each kind of value. The claim
/// mechanism holds a lock only while one synchronous operation runs on the
/// value, never across an await, and gets the value without locking once the
/// last candidate is gone. A lock is `Send` and `Sync` exactly as its
/// implementation makes it, and the candidates of a datagram follow.
pub trait DatagramClaimLock {
    /// A lock around a value of type `T`.
    type Lock<T>;

    /// A lock around `value`, not held.
    fn new<T>(value: T) -> Self::Lock<T>;

    /// Waits until the lock is free, then runs `op` on the value while
    /// holding it, and releases it before the future completes, also when
    /// `op` panics.
    ///
    /// Dropping the future while it waits withdraws the wait, and `op` does
    /// not run.
    fn with<T, R>(lock: &Self::Lock<T>, op: impl FnOnce(&mut T) -> R) -> impl Future<Output = R>;

    /// Runs `op` on the value if the lock is free now, holding it while `op`
    /// runs; `None`, without running `op`, when it is held.
    fn try_with<T, R>(lock: &Self::Lock<T>, op: impl FnOnce(&mut T) -> R) -> Option<R>;

    /// The value, through exclusive access to the lock, without locking.
    fn get_mut<T>(lock: &mut Self::Lock<T>) -> &mut T;
}

/// The lock of a routing domain on one thread (`RefCellDatagramClaimLock`):
/// a cell, and the tasks waiting for it.
///
/// Its locks are neither `Send` nor `Sync`. An operation on the value is
/// synchronous, so on one thread the lock is only ever found held by an
/// operation that polls an attempt of the same datagram, which waits until
/// it ends.
#[derive(Debug)]
pub enum RefCellDatagramClaimLock {}

impl DatagramClaimLock for RefCellDatagramClaimLock {
    type Lock<T> = RefCellAsyncLock<T>;

    fn new<T>(value: T) -> RefCellAsyncLock<T> {
        RefCellAsyncLock {
            value: RefCell::new(value),
            waiters: RefCell::new(Vec::new()),
        }
    }

    fn with<T, R>(
        lock: &RefCellAsyncLock<T>,
        op: impl FnOnce(&mut T) -> R,
    ) -> impl Future<Output = R> {
        let mut op = Some(op);
        poll_fn(move |cx| match lock.hold() {
            Some(mut held) => {
                // invariant: the future is not polled after it completed.
                let op = op.take().expect("the operation runs once");
                Poll::Ready(op(&mut held))
            }
            None => {
                let mut waiters = lock.waiters.borrow_mut();
                if !waiters.iter().any(|waiter| waiter.will_wake(cx.waker())) {
                    waiters.push(cx.waker().clone());
                }
                Poll::Pending
            }
        })
    }

    fn try_with<T, R>(lock: &RefCellAsyncLock<T>, op: impl FnOnce(&mut T) -> R) -> Option<R> {
        let mut held = lock.hold()?;
        Some(op(&mut held))
    }

    fn get_mut<T>(lock: &mut RefCellAsyncLock<T>) -> &mut T {
        lock.value.get_mut()
    }
}

/// An asynchronous lock for one thread (`RefCellAsyncLock`): the value in a
/// cell, and the wakers of the tasks waiting for it, all woken when it is
/// released.
pub struct RefCellAsyncLock<T> {
    value: RefCell<T>,
    waiters: RefCell<Vec<Waker>>,
}

impl<T> RefCellAsyncLock<T> {
    /// Holds the lock, if it is free.
    fn hold(&self) -> Option<Held<'_, T>> {
        let value = self.value.try_borrow_mut().ok()?;
        Some(Held {
            value: Some(value),
            waiters: &self.waiters,
        })
    }
}

impl<T> fmt::Debug for RefCellAsyncLock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefCellAsyncLock")
            .field("held", &self.value.try_borrow_mut().is_err())
            .finish_non_exhaustive()
    }
}

/// A [`RefCellAsyncLock`] while it is held; dropping it, also while a panic
/// unwinds, releases the lock and wakes the waiting tasks.
struct Held<'a, T> {
    /// `None` only while it is dropped.
    value: Option<RefMut<'a, T>>,
    waiters: &'a RefCell<Vec<Waker>>,
}

impl<T> Deref for Held<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // invariant: the value is only taken in `drop`.
        self.value.as_deref().expect("the lock is held")
    }
}

impl<T> DerefMut for Held<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // invariant: the value is only taken in `drop`.
        self.value.as_deref_mut().expect("the lock is held")
    }
}

impl<T> Drop for Held<'_, T> {
    fn drop(&mut self) {
        // The value is released before the waiters are woken.
        drop(self.value.take());
        let waiters = core::mem::take(&mut *self.waiters.borrow_mut());
        for waiter in waiters {
            waiter.wake();
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::rc::Rc;
    use core::cell::Cell;
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};

    use super::{DatagramClaimLock, RefCellDatagramClaimLock};

    type Lock = RefCellDatagramClaimLock;

    #[test]
    fn an_operation_runs_at_once_on_a_free_lock() {
        let lock = Lock::new(1);
        assert_eq!(Lock::try_with(&lock, |value| *value + 1), Some(2));
        let mut cx = Context::from_waker(Waker::noop());
        let mut added = pin!(Lock::with(&lock, |value| {
            *value += 1;
            *value
        }));
        assert_eq!(added.as_mut().poll(&mut cx), Poll::Ready(2));
    }

    #[test]
    fn a_held_lock_defers_others_until_it_is_released() {
        let lock = Lock::new(0);
        let ran = Rc::new(Cell::new(false));
        let mut cx = Context::from_waker(Waker::noop());
        let waited = Lock::try_with(&lock, |_| {
            // Inside an operation, the lock is held.
            assert!(Lock::try_with(&lock, |_| ()).is_none());
            let mut inner = pin!(Lock::with(&lock, |_| ran.set(true)));
            assert!(inner.as_mut().poll(&mut cx).is_pending());
            assert!(!ran.get());
        });
        assert_eq!(waited, Some(()));
        let mut later = pin!(Lock::with(&lock, |value| *value + 7));
        assert_eq!(later.as_mut().poll(&mut cx), Poll::Ready(7));
    }

    #[test]
    fn a_panicking_operation_releases_the_lock() {
        let lock = Lock::new(0);
        let unwound = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
            Lock::try_with(&lock, |_| panic!("simulated"));
        }));
        assert!(unwound.is_err());
        assert_eq!(Lock::try_with(&lock, |value| *value), Some(0));
    }
}
