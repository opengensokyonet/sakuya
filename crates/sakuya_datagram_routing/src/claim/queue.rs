//! A delivery queue for queue-style deliverers
//!
//! A queue-style deliverer passes each delivery to its datagram receiver
//! through a queue instead of processing it on the dispatch stack. The
//! deliverer belongs to its route entry, and route entries and query
//! snapshots may keep it alive after the receiver is gone; the receiver's
//! queue must not live as long as that. So the receiver owns the queue, a
//! [`DatagramDeliveryQueue`], which holds the only long-lived reference to
//! the queued items, and the deliverer holds its
//! [`Poster`](DatagramDeliveryQueue::Poster), which reaches them through a
//! weak reference and upgrades it only for the duration of one post.
//!
//! Closing is dropping the queue. Posting and closing meet where the queue
//! synchronizes its state: a successful upgrade does not mean the queue still
//! accepts, and a post after the queue closed drops the item at once. An item
//! queued just before the close goes with the closed queue, so a late post
//! never keeps the receiver's authorization alive. The receiver remains
//! responsible for revoking its route registrations when it closes; the weak
//! reference does not do that.
//!
//! The queue is a trait because how its state is synchronized is a property
//! of the queue, not of the receiver: [`RefCellDatagramDeliveryQueue`] is the
//! queue of a receiver on one thread, and a crate with the locks of `std`
//! gives the one whose deliverers post from other threads. The state itself,
//! and what posting and receiving do to it, is the same for every queue
//! ([`DatagramDeliveryQueueState`]).
//!
//! The items lie in a deque that grows as they come, up to the capacity;
//! nothing is set aside in advance. Each time the receiver has taken every
//! item, the deque shrinks to the room the stretch just taken needed: its
//! deepest length rounded up to a power of two, and at least four slots.
//! A steady stream keeps its room instead of growing it again after every
//! stretch, and once the bursts end, the next shallow stretch gives the
//! room back.
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
//! use sakuya_datagram_routing::claim::queue::{
//!     DatagramDeliveryPoster, DatagramDeliveryQueue, RefCellDatagramDeliveryPoster,
//!     RefCellDatagramDeliveryQueue,
//! };
//!
//! type Delivery = DatagramDelivery<Vec<u8>, (), ReleaseUnclaimed>;
//!
//! /// Queues every delivery for its receiver.
//! struct Queued {
//!     poster: RefCellDatagramDeliveryPoster<Delivery>,
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
//! let mut queue = RefCellDatagramDeliveryQueue::new(NonZeroUsize::new(64).unwrap()).unwrap();
//! let deliverer = Arc::new(Queued { poster: queue.poster() });
//! assert!(queue.try_recv().is_none());
//! drop(queue);
//! assert!(deliverer.poster.is_closed());
//! ```

use alloc::collections::VecDeque;
use alloc::rc::{Rc, Weak};
use core::cell::RefCell;
use core::fmt;
use core::future::{Future, poll_fn};
use core::num::NonZeroUsize;
use core::task::{Context, Poll, Waker};

use snafu::{Snafu, ensure};

/// The fewest slots a queue keeps once the receiver has taken every item.
const MIN_SLOTS_KEPT_WHEN_EMPTY: usize = 4;

/// The receiving end of a delivery queue, owned by a datagram receiver
/// (`DatagramDeliveryQueue`).
///
/// It holds the only long-lived reference to the queued items; its poster
/// reaches them only for the duration of one post. Dropping it closes the
/// queue and drops the items still queued, outside the queue's
/// synchronization, since dropping them may post again. Every
/// implementation keeps a [`DatagramDeliveryQueueState`] and does to it what
/// its methods say; only how the receiver and the posters reach the state
/// differs.
pub trait DatagramDeliveryQueue<T>: Sized {
    /// The deliverer's handle for posting into the queue.
    type Poster: DatagramDeliveryPoster<T>;

    /// Creates a queue that holds at most `capacity` items.
    ///
    /// # Errors
    ///
    /// [`QueueCapacityError`] if `capacity` exceeds
    /// [`DatagramDeliveryQueueState::MAX_CAPACITY`].
    fn new(capacity: NonZeroUsize) -> Result<Self, QueueCapacityError>;

    /// Returns a poster for a deliverer that feeds this queue.
    fn poster(&self) -> Self::Poster;

    /// Takes the next queued item, if any, without waiting.
    fn try_recv(&mut self) -> Option<T>;

    /// Polls for the next queued item.
    ///
    /// The queue never reports an end while it is alive; it stays pending
    /// until an item arrives.
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<T>;

    /// Waits for the next queued item.
    ///
    /// Cancelling the wait loses no item.
    fn recv(&mut self) -> impl Future<Output = T> {
        poll_fn(move |cx| self.poll_recv(cx))
    }
}

/// The deliverer's handle for posting into a [`DatagramDeliveryQueue`]
/// (`DatagramDeliveryPoster`).
///
/// It does not keep the queue open: it reaches the queued items only through
/// a weak reference.
pub trait DatagramDeliveryPoster<T>: Clone {
    /// Posts one item, or drops it if the queue cannot take it.
    ///
    /// The item is dropped when the queue is closed or full; a full queue is
    /// the receiver's admission limit, and the post neither waits nor retries.
    /// There is no failure to report: like
    /// [`DatagramDeliverer::deliver`](super::deliverer::DatagramDeliverer::deliver), a
    /// post always takes the item over.
    fn post(&self, item: T);

    /// Whether the queue is known to be closed.
    ///
    /// `true` is final. `false` does not promise that the next post will be
    /// queued, because the queue may close at any time.
    fn is_closed(&self) -> bool;
}

/// What a delivery queue and its posters share: the items, the receiver
/// waiting for one, and whether the queue was closed
/// (`DatagramDeliveryQueueState`).
///
/// A queue keeps it behind its own synchronization; none of its methods
/// drops an item or wakes a task, so that a queue can do both after it lets
/// go of the state.
pub struct DatagramDeliveryQueueState<T> {
    items: VecDeque<T>,
    /// The most items queued at once since the deque was last emptied.
    deepest: usize,
    /// The queue was dropped: nothing is queued any more.
    closed: bool,
    /// The receiver waiting for an item.
    waker: Option<Waker>,
    capacity: usize,
}

impl<T> DatagramDeliveryQueueState<T> {
    /// The largest capacity a queue can have.
    pub const MAX_CAPACITY: usize = usize::MAX >> 3;

    /// The state of an open, empty queue that holds at most `capacity`
    /// items.
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
            items: VecDeque::new(),
            deepest: 0,
            closed: false,
            waker: None,
            capacity: capacity.get(),
        })
    }

    /// Queues `item`, unless the queue is closed or full: then the item
    /// comes back. On success, the waker of the receiver that waited, which
    /// the caller wakes.
    ///
    /// # Errors
    ///
    /// The item, when the queue is closed or full.
    pub fn try_post(&mut self, item: T) -> Result<Option<Waker>, T> {
        if self.closed || self.items.len() >= self.capacity {
            return Err(item);
        }
        self.items.push_back(item);
        self.deepest = self.deepest.max(self.items.len());
        Ok(self.waker.take())
    }

    /// Takes the next item; once the last is taken, the deque shrinks to the
    /// room the stretch just taken needed.
    pub fn try_recv(&mut self) -> Option<T> {
        let item = self.items.pop_front();
        if item.is_some() && self.items.is_empty() {
            let needed = self
                .deepest
                .checked_next_power_of_two()
                .unwrap_or(usize::MAX)
                .max(MIN_SLOTS_KEPT_WHEN_EMPTY);
            if self.items.capacity() > needed {
                self.items.shrink_to(needed);
            }
            self.deepest = 0;
        }
        item
    }

    /// Takes the next item, or arranges for the task of `cx` to be woken
    /// when one is posted.
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<T> {
        if let Some(item) = self.try_recv() {
            return Poll::Ready(item);
        }
        match &mut self.waker {
            Some(waker) if waker.will_wake(cx.waker()) => {}
            waker => *waker = Some(cx.waker().clone()),
        }
        Poll::Pending
    }

    /// Closes the queue: nothing is queued any more. The items still queued
    /// and the waker of the receiver come back, for the caller to drop.
    pub fn close(&mut self) -> (VecDeque<T>, Option<Waker>) {
        self.closed = true;
        (core::mem::take(&mut self.items), self.waker.take())
    }

    /// Whether the queue was closed.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// How many items are queued.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether no item is queued.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// The room the deque has now.
    #[cfg(test)]
    pub(crate) fn room(&self) -> usize {
        self.items.capacity()
    }
}

impl<T> fmt::Debug for DatagramDeliveryQueueState<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramDeliveryQueueState")
            .field("queued", &self.items.len())
            .field("capacity", &self.capacity)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

/// A queue capacity exceeds [`DatagramDeliveryQueueState::MAX_CAPACITY`].
///
/// Only [`DatagramDeliveryQueueState::new`] constructs it, for a capacity it
/// refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "queue capacity of {capacity} items exceeds the maximum of {} items",
    DatagramDeliveryQueueState::<()>::MAX_CAPACITY
))]
pub struct QueueCapacityError {
    capacity: NonZeroUsize,
}

impl QueueCapacityError {
    /// The rejected capacity, above
    /// [`DatagramDeliveryQueueState::MAX_CAPACITY`].
    pub const fn capacity(self) -> NonZeroUsize {
        self.capacity
    }
}

/// The delivery queue of a receiver on one thread
/// (`RefCellDatagramDeliveryQueue`): its state in a cell, which the queue
/// holds through an `Rc` and its posters through a weak one.
///
/// It is neither `Send` nor `Sync`, and nor are its posters.
pub struct RefCellDatagramDeliveryQueue<T> {
    shared: Rc<RefCell<DatagramDeliveryQueueState<T>>>,
}

impl<T> DatagramDeliveryQueue<T> for RefCellDatagramDeliveryQueue<T> {
    type Poster = RefCellDatagramDeliveryPoster<T>;

    fn new(capacity: NonZeroUsize) -> Result<Self, QueueCapacityError> {
        Ok(Self {
            shared: Rc::new(RefCell::new(DatagramDeliveryQueueState::new(capacity)?)),
        })
    }

    fn poster(&self) -> RefCellDatagramDeliveryPoster<T> {
        RefCellDatagramDeliveryPoster {
            shared: Rc::downgrade(&self.shared),
        }
    }

    fn try_recv(&mut self) -> Option<T> {
        self.shared.borrow_mut().try_recv()
    }

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<T> {
        self.shared.borrow_mut().poll_recv(cx)
    }
}

impl<T> Drop for RefCellDatagramDeliveryQueue<T> {
    fn drop(&mut self) {
        let closed = self.shared.borrow_mut().close();
        // the items and the waker go outside the cell: dropping them may
        // run code that posts again
        drop(closed);
    }
}

impl<T> fmt::Debug for RefCellDatagramDeliveryQueue<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefCellDatagramDeliveryQueue")
            .field("queued", &self.shared.borrow().len())
            .finish_non_exhaustive()
    }
}

/// The poster of a [`RefCellDatagramDeliveryQueue`].
pub struct RefCellDatagramDeliveryPoster<T> {
    shared: Weak<RefCell<DatagramDeliveryQueueState<T>>>,
}

impl<T> DatagramDeliveryPoster<T> for RefCellDatagramDeliveryPoster<T> {
    fn post(&self, item: T) {
        let Some(shared) = self.shared.upgrade() else {
            return;
        };
        let posted = shared.borrow_mut().try_post(item);
        // A closed or full queue hands the item back, dropped here, outside
        // the cell.
        if let Ok(Some(waker)) = posted {
            waker.wake();
        }
    }

    fn is_closed(&self) -> bool {
        self.shared
            .upgrade()
            .is_none_or(|shared| shared.borrow().is_closed())
    }
}

impl<T> Clone for RefCellDatagramDeliveryPoster<T> {
    fn clone(&self) -> Self {
        Self {
            shared: Weak::clone(&self.shared),
        }
    }
}

impl<T> fmt::Debug for RefCellDatagramDeliveryPoster<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefCellDatagramDeliveryPoster")
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

    use super::{
        DatagramDeliveryPoster, DatagramDeliveryQueue, DatagramDeliveryQueueState,
        RefCellDatagramDeliveryQueue,
    };

    struct Tracked(Rc<Cell<usize>>);

    impl Drop for Tracked {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    fn with_capacity<T>(capacity: usize) -> RefCellDatagramDeliveryQueue<T> {
        RefCellDatagramDeliveryQueue::new(NonZeroUsize::new(capacity).unwrap()).unwrap()
    }

    #[test]
    fn capacity_beyond_the_maximum_is_rejected() {
        let largest = NonZeroUsize::new(DatagramDeliveryQueueState::<()>::MAX_CAPACITY).unwrap();
        let too_large = largest.checked_add(1).unwrap();
        assert_eq!(
            RefCellDatagramDeliveryQueue::<()>::new(too_large)
                .unwrap_err()
                .capacity(),
            too_large
        );
        assert!(RefCellDatagramDeliveryQueue::<()>::new(NonZeroUsize::MIN).is_ok());
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
    fn an_emptied_queue_keeps_the_room_its_last_stretch_needed() {
        let mut queue = with_capacity(64);
        assert_eq!(queue.shared.borrow().room(), 0);
        let poster = queue.poster();
        let stretch = |queue: &mut RefCellDatagramDeliveryQueue<usize>, depth: usize| {
            for item in 0..depth {
                poster.post(item);
            }
            for item in 0..depth {
                assert_eq!(queue.try_recv(), Some(item));
            }
            assert_eq!(queue.try_recv(), None);
            queue.shared.borrow().room()
        };
        // a deep stretch keeps its room for the next one
        assert!(stretch(&mut queue, 20) >= 32);
        assert!(stretch(&mut queue, 30) >= 32);
        // a shallow stretch gives it back, down to four slots
        assert_eq!(stretch(&mut queue, 1), 4);
        assert_eq!(stretch(&mut queue, 3), 4);
        // between four and eight, eight
        assert_eq!(stretch(&mut queue, 6), 8);
        assert_eq!(stretch(&mut queue, 2), 4);
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
        drop(temporary.borrow_mut().try_post(Tracked(drops.clone())));
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
        temporary
            .borrow_mut()
            .try_post(Tracked(drops.clone()))
            .ok()
            .unwrap();
        drop(queue);
        // The poster's temporary reference is still alive, yet the queued
        // item went with the closed queue.
        assert_eq!(drops.get(), 1);
        drop(temporary);
        assert_eq!(drops.get(), 1);
    }
}
