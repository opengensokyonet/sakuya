//! A delivery queue for queue-style deliverers
//!
//! A queue-style deliverer passes each delivery to its datagram receiver
//! through a queue instead of processing it on the dispatch stack. The
//! deliverer belongs to its route entry, and route entries and query
//! snapshots may keep it alive after the receiver is gone; the receiver's
//! queue must not live as long as that. So the receiver owns the queue,
//! [`DatagramDeliveryQueue`], which holds the only long-lived reference to
//! the queued items, and the deliverer holds a [`DatagramDeliveryPoster`],
//! which reaches them through a standard library [`Weak`] and upgrades it
//! only for the duration of one post.
//!
//! Closing is dropping the queue. Posting and closing meet at the queue's
//! lock: a successful upgrade does not mean the queue still accepts, and a
//! post after the queue closed drops the item at once. An item queued just
//! before the close goes with the closed queue, so a late post never keeps
//! the receiver's authorization alive. The receiver remains responsible for
//! revoking its route registrations when it closes; the weak reference does
//! not do that.
//!
//! The items lie in a deque that grows as they come, up to the capacity;
//! nothing is set aside in advance. Once the receiver has taken every item,
//! a deque grown past four slots shrinks back to four, so a receiver that
//! saw a burst does not keep the room for it.
//!
//! A deliverer built on this module, and a receiver that judges the queued
//! candidates itself:
//!
//! ```
//! use std::num::NonZeroUsize;
//! use std::sync::Arc;
//!
//! use sakuya_datagram_routing::claim::candidate::{DatagramClaimAttempt, DatagramClaimOutcome};
//! use sakuya_datagram_routing::claim::deliverer::DatagramDeliverer;
//! use sakuya_datagram_routing::claim::delivery::DatagramDelivery;
//! use sakuya_datagram_routing::claim::finish::ReleaseUnclaimed;
//! use sakuya_datagram_routing::claim::queue::{DatagramDeliveryPoster, DatagramDeliveryQueue};
//!
//! type Delivery = DatagramDelivery<Vec<u8>, (), ReleaseUnclaimed>;
//!
//! /// Queues every delivery for its receiver.
//! struct Queued {
//!     poster: DatagramDeliveryPoster<Delivery>,
//! }
//!
//! impl DatagramDeliverer<Vec<u8>, ()> for Queued {
//!     fn deliver(&self, delivery: Delivery) {
//!         // After the receiver closed, this takes the delivery and drops it.
//!         self.poster.post(delivery);
//!     }
//! }
//!
//! /// What the receiver does with one queued delivery.
//! async fn receive(delivery: Delivery, first_byte: u8) -> Option<Vec<u8>> {
//!     let exclusive = match delivery {
//!         DatagramDelivery::Exclusive(exclusive) => exclusive,
//!         DatagramDelivery::Competing(candidate) => {
//!             let attempt = candidate.try_exclusive(|access, _route| {
//!                 if access.bytes().first() == Some(&first_byte) {
//!                     DatagramClaimOutcome::Claimed(access.into_exclusive(), ())
//!                 } else {
//!                     DatagramClaimOutcome::Abandoned(())
//!                 }
//!             });
//!             match attempt.await {
//!                 DatagramClaimAttempt::Claimed(exclusive, ())
//!                 | DatagramClaimAttempt::Exclusive(exclusive) => exclusive,
//!                 DatagramClaimAttempt::Unclaimed(_)
//!                 | DatagramClaimAttempt::Abandoned(())
//!                 | DatagramClaimAttempt::ClaimedElsewhere => return None,
//!             }
//!         }
//!     };
//!     Some(exclusive.consume().0.into_inner())
//! }
//!
//! let mut queue = DatagramDeliveryQueue::new(NonZeroUsize::new(64).unwrap()).unwrap();
//! let deliverer = Arc::new(Queued { poster: queue.poster() });
//! assert!(queue.try_recv().is_none());
//! drop(queue);
//! assert!(deliverer.poster.is_closed());
//! ```

use std::collections::VecDeque;
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Poll, Waker};

use snafu::{Snafu, ensure};
use tokio::sync::Semaphore;

/// The slots a queue keeps once the receiver has taken every item.
const SLOTS_KEPT_WHEN_EMPTY: usize = 4;

/// What the queue and its posters share: the items, behind one lock.
struct Shared<T> {
    state: Mutex<State<T>>,
    capacity: usize,
}

struct State<T> {
    items: VecDeque<T>,
    /// The queue was dropped: nothing is queued any more.
    closed: bool,
    /// The receiver waiting for an item.
    waker: Option<Waker>,
}

impl<T> Shared<T> {
    fn lock(&self) -> MutexGuard<'_, State<T>> {
        // the state holds no invariant a panic could break midway
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queues `item`, unless the queue is closed or full: then the item
    /// comes back.
    fn try_post(&self, item: T) -> Result<(), T> {
        let waker = {
            let mut state = self.lock();
            if state.closed || state.items.len() >= self.capacity {
                return Err(item);
            }
            state.items.push_back(item);
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        Ok(())
    }
}

impl<T> State<T> {
    /// Takes the next item; once the last is taken, a deque grown past
    /// [`SLOTS_KEPT_WHEN_EMPTY`] shrinks back.
    fn take(&mut self) -> Option<T> {
        let item = self.items.pop_front();
        if self.items.is_empty() && self.items.capacity() > SLOTS_KEPT_WHEN_EMPTY {
            self.items.shrink_to(SLOTS_KEPT_WHEN_EMPTY);
        }
        item
    }
}

/// The receiving end of a delivery queue, owned by a datagram receiver.
///
/// It holds the only long-lived reference to the queued items. Dropping it
/// closes the queue and drops the items still queued.
pub struct DatagramDeliveryQueue<T> {
    shared: Arc<Shared<T>>,
}

impl<T> DatagramDeliveryQueue<T> {
    /// The largest capacity a queue can have.
    pub const MAX_CAPACITY: usize = Semaphore::MAX_PERMITS;

    /// Creates a queue that holds at most `capacity` items.
    ///
    /// # Errors
    ///
    /// [`QueueCapacityError`] if `capacity` exceeds
    /// [`MAX_CAPACITY`](Self::MAX_CAPACITY).
    pub fn new(capacity: NonZeroUsize) -> Result<Self, QueueCapacityError> {
        ensure!(
            capacity.get() <= Self::MAX_CAPACITY,
            QueueCapacitySnafu { capacity }
        );
        Ok(Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    items: VecDeque::new(),
                    closed: false,
                    waker: None,
                }),
                capacity: capacity.get(),
            }),
        })
    }

    /// Returns a poster for a deliverer that feeds this queue.
    pub fn poster(&self) -> DatagramDeliveryPoster<T> {
        DatagramDeliveryPoster {
            shared: Arc::downgrade(&self.shared),
        }
    }

    /// Takes the next queued item, if any, without waiting.
    pub fn try_recv(&mut self) -> Option<T> {
        self.shared.lock().take()
    }

    /// Polls for the next queued item.
    ///
    /// The queue never reports an end while it is alive; it stays pending
    /// until an item arrives.
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<T> {
        let mut state = self.shared.lock();
        if let Some(item) = state.take() {
            return Poll::Ready(item);
        }
        match &mut state.waker {
            Some(waker) if waker.will_wake(cx.waker()) => {}
            waker => *waker = Some(cx.waker().clone()),
        }
        Poll::Pending
    }

    /// Waits for the next queued item.
    ///
    /// Cancelling the wait loses no item.
    pub async fn recv(&mut self) -> T {
        std::future::poll_fn(|cx| self.poll_recv(cx)).await
    }
}

impl<T> Drop for DatagramDeliveryQueue<T> {
    fn drop(&mut self) {
        let (items, waker) = {
            let mut state = self.shared.lock();
            state.closed = true;
            (core::mem::take(&mut state.items), state.waker.take())
        };
        // the items and the waker go outside the lock: dropping them may
        // run code that posts again
        drop(items);
        drop(waker);
    }
}

/// A queue capacity exceeds [`DatagramDeliveryQueue::MAX_CAPACITY`].
///
/// Only [`DatagramDeliveryQueue::new`] constructs it, for a capacity it
/// refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "queue capacity of {capacity} items exceeds the maximum of {} items",
    DatagramDeliveryQueue::<()>::MAX_CAPACITY
))]
pub struct QueueCapacityError {
    capacity: NonZeroUsize,
}

impl QueueCapacityError {
    /// The rejected capacity, above
    /// [`DatagramDeliveryQueue::MAX_CAPACITY`].
    pub const fn capacity(self) -> NonZeroUsize {
        self.capacity
    }
}

impl<T> fmt::Debug for DatagramDeliveryQueue<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramDeliveryQueue")
            .field("queued", &self.shared.lock().items.len())
            .finish_non_exhaustive()
    }
}

/// The deliverer's handle for posting into a [`DatagramDeliveryQueue`].
///
/// It does not keep the queue open: it holds only a weak reference to the
/// queued items.
pub struct DatagramDeliveryPoster<T> {
    shared: Weak<Shared<T>>,
}

impl<T> DatagramDeliveryPoster<T> {
    /// Posts one item, or drops it if the queue cannot take it.
    ///
    /// The item is dropped when the queue is closed or full; a full queue is
    /// the receiver's admission limit, and the post neither waits nor retries.
    /// There is no failure to report: like
    /// [`DatagramDeliverer::deliver`](super::deliverer::DatagramDeliverer::deliver), a
    /// post always takes the item over.
    pub fn post(&self, item: T) {
        if let Some(shared) = self.shared.upgrade() {
            // A closed or full queue hands the item back, dropped here.
            drop(shared.try_post(item));
        }
    }

    /// Whether the queue is known to be closed.
    ///
    /// `true` is final. `false` does not promise that the next post will be
    /// queued, because the queue may close at any time.
    pub fn is_closed(&self) -> bool {
        self.shared
            .upgrade()
            .is_none_or(|shared| shared.lock().closed)
    }
}

impl<T> Clone for DatagramDeliveryPoster<T> {
    fn clone(&self) -> Self {
        Self {
            shared: Weak::clone(&self.shared),
        }
    }
}

impl<T> fmt::Debug for DatagramDeliveryPoster<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramDeliveryPoster")
            .field("closed", &self.is_closed())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::num::NonZeroUsize;
    use std::rc::Rc;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    use super::DatagramDeliveryQueue;

    struct Tracked(Rc<Cell<usize>>);

    impl Drop for Tracked {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    fn with_capacity<T>(capacity: usize) -> DatagramDeliveryQueue<T> {
        DatagramDeliveryQueue::new(NonZeroUsize::new(capacity).unwrap()).unwrap()
    }

    #[test]
    fn capacity_beyond_the_maximum_is_rejected() {
        let largest = NonZeroUsize::new(DatagramDeliveryQueue::<()>::MAX_CAPACITY).unwrap();
        let too_large = largest.checked_add(1).unwrap();
        assert_eq!(
            DatagramDeliveryQueue::<()>::new(too_large)
                .unwrap_err()
                .capacity(),
            too_large
        );
        assert!(DatagramDeliveryQueue::<()>::new(NonZeroUsize::MIN).is_ok());
    }

    #[test]
    fn queued_items_arrive_in_order() {
        let mut queue = with_capacity(2);
        let poster = queue.poster();
        poster.post(1);
        poster.post(2);
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(queue.poll_recv(&mut cx), Poll::Ready(1));
        assert_eq!(queue.try_recv(), Some(2));
        assert!(queue.poll_recv(&mut cx).is_pending());
    }

    #[test]
    fn a_posted_item_wakes_the_waiting_receiver() {
        struct Count(AtomicUsize);
        impl Wake for Count {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let count = Arc::new(Count(AtomicUsize::new(0)));
        let waker = Waker::from(count.clone());
        let mut cx = Context::from_waker(&waker);
        let mut queue = with_capacity(1);
        let poster = queue.poster();
        assert!(queue.poll_recv(&mut cx).is_pending());
        poster.post(7);
        assert_eq!(count.0.load(Ordering::Relaxed), 1);
        assert_eq!(queue.poll_recv(&mut cx), Poll::Ready(7));
    }

    #[test]
    fn the_queue_grows_as_items_come_and_keeps_four_slots_once_emptied() {
        let mut queue = with_capacity(64);
        assert_eq!(queue.shared.lock().items.capacity(), 0);
        let poster = queue.poster();
        for item in 0..32 {
            poster.post(item);
        }
        assert!(queue.shared.lock().items.capacity() >= 32);
        for item in 0..32 {
            assert_eq!(queue.try_recv(), Some(item));
        }
        assert_eq!(queue.shared.lock().items.capacity(), 4);
        // a queue that never grew past four keeps what it has
        poster.post(0);
        assert_eq!(queue.try_recv(), Some(0));
        assert_eq!(queue.shared.lock().items.capacity(), 4);
    }

    #[test]
    fn post_after_close_drops_the_item_at_once() {
        let drops = Rc::new(Cell::new(0));
        let queue = with_capacity(1);
        let poster = queue.poster();
        drop(queue);
        assert!(poster.is_closed());
        poster.post(Tracked(drops.clone()));
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn full_queue_drops_the_item_without_retrying() {
        let drops = Rc::new(Cell::new(0));
        let queue = with_capacity(1);
        let poster = queue.poster();
        poster.post(Tracked(drops.clone()));
        poster.post(Tracked(drops.clone()));
        assert_eq!(drops.get(), 1);
        drop(queue);
        assert_eq!(drops.get(), 2);
    }

    #[test]
    fn close_racing_with_a_post_does_not_retain_the_item() {
        // The interleaving a concurrent post can produce: the poster upgrades,
        // the receiver closes, then the poster sends.
        let drops = Rc::new(Cell::new(0));
        let queue = with_capacity(1);
        let poster = queue.poster();
        let temporary = poster.shared.upgrade().unwrap();
        drop(queue);
        assert!(poster.is_closed());
        drop(temporary.try_post(Tracked(drops.clone())));
        assert_eq!(drops.get(), 1);
        drop(temporary);
        assert!(poster.shared.upgrade().is_none());
    }

    #[test]
    fn item_sent_before_close_is_released_by_the_close() {
        let drops = Rc::new(Cell::new(0));
        let queue = with_capacity(1);
        let poster = queue.poster();
        let temporary = poster.shared.upgrade().unwrap();
        temporary.try_post(Tracked(drops.clone())).ok().unwrap();
        drop(queue);
        // The poster's temporary reference is still alive, yet the queued
        // item went with the closed queue.
        assert_eq!(drops.get(), 1);
        drop(temporary);
        assert_eq!(drops.get(), 1);
    }
}
