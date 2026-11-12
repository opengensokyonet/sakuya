//! A delivery queue for queue-style deliverers
//!
//! A queue-style deliverer passes each delivery to its datagram receiver
//! through a queue instead of processing it on the dispatch stack. The
//! deliverer belongs to its route entry, and route entries and query
//! snapshots may keep it alive after the receiver is gone; the receiver's
//! queue must not live as long as that. So the receiver owns the queue,
//! [`DatagramDeliveryQueue`], together with the only long-lived sender, and
//! the deliverer holds a [`DatagramDeliveryPoster`], which reaches the sender
//! through a standard library [`Weak`] and upgrades it only for the duration
//! of one send.
//!
//! Closing is dropping the queue. Sending and closing meet at the queue's own
//! synchronization: a successful upgrade does not mean the queue still
//! accepts, and a post after the queue closed drops the item at once. An item
//! that races with the close is released no later than the poster's temporary
//! sender, so a late post never keeps the receiver's authorization alive. The
//! receiver remains responsible for revoking its route registrations when it
//! closes; the weak reference does not do that.
//!
//! Tokio's `WeakSender` is not used: with it, a queue whose receiver is gone
//! can still retain a sent item for as long as another sender exists.
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

use std::fmt;
use std::num::NonZeroUsize;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};

use snafu::{Snafu, ensure};
use tokio::sync::{Semaphore, mpsc};

/// The receiving end of a delivery queue, owned by a datagram receiver.
///
/// It holds the queue and its only long-lived sender. Dropping it closes the
/// queue and drops the items still queued.
pub struct DatagramDeliveryQueue<T> {
    // Field order is drop order: the queue closes before the sender goes.
    receiver: mpsc::Receiver<T>,
    sender: Arc<mpsc::Sender<T>>,
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
        let (sender, receiver) = mpsc::channel(capacity.get());
        Ok(Self {
            receiver,
            sender: Arc::new(sender),
        })
    }

    /// Returns a poster for a deliverer that feeds this queue.
    pub fn poster(&self) -> DatagramDeliveryPoster<T> {
        DatagramDeliveryPoster {
            sender: Arc::downgrade(&self.sender),
        }
    }

    /// Takes the next queued item, if any, without waiting.
    pub fn try_recv(&mut self) -> Option<T> {
        self.receiver.try_recv().ok()
    }

    /// Polls for the next queued item.
    ///
    /// The queue holds its own sender, so it never reports an end; it stays
    /// pending until an item arrives.
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<T> {
        match self.receiver.poll_recv(cx) {
            Poll::Ready(Some(item)) => Poll::Ready(item),
            // invariant: the queue owns a sender for as long as it owns the
            // receiver, so the channel never reports that every sender is gone.
            Poll::Ready(None) => {
                unreachable!("the queue keeps its own sender, so the channel stays open")
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// Waits for the next queued item.
    ///
    /// Cancelling the wait loses no item.
    pub async fn recv(&mut self) -> T {
        std::future::poll_fn(|cx| self.poll_recv(cx)).await
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
            .field("queued", &self.receiver.len())
            .finish_non_exhaustive()
    }
}

/// The deliverer's handle for posting into a [`DatagramDeliveryQueue`].
///
/// It does not keep the queue open: it holds only a weak reference to the
/// queue's sender.
pub struct DatagramDeliveryPoster<T> {
    sender: Weak<mpsc::Sender<T>>,
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
        if let Some(sender) = self.sender.upgrade() {
            // A closed or full queue hands the item back inside the error,
            // which is dropped here.
            drop(sender.try_send(item));
        }
    }

    /// Whether the queue is known to be closed.
    ///
    /// `true` is final. `false` does not promise that the next post will be
    /// queued, because the queue may close at any time.
    pub fn is_closed(&self) -> bool {
        self.sender
            .upgrade()
            .is_none_or(|sender| sender.is_closed())
    }
}

impl<T> Clone for DatagramDeliveryPoster<T> {
    fn clone(&self) -> Self {
        Self {
            sender: Weak::clone(&self.sender),
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
    use std::task::{Context, Poll, Waker};

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
        let temporary = poster.sender.upgrade().unwrap();
        drop(queue);
        assert!(poster.is_closed());
        drop(temporary.try_send(Tracked(drops.clone())));
        assert_eq!(drops.get(), 1);
        drop(temporary);
        assert!(poster.sender.upgrade().is_none());
    }

    #[test]
    fn item_sent_before_close_is_released_by_the_close() {
        let drops = Rc::new(Cell::new(0));
        let queue = with_capacity(1);
        let poster = queue.poster();
        let temporary = poster.sender.upgrade().unwrap();
        temporary.try_send(Tracked(drops.clone())).ok().unwrap();
        drop(queue);
        // The poster's temporary sender is still alive, yet the queued item
        // went with the closed queue.
        assert_eq!(drops.get(), 1);
        drop(temporary);
        assert_eq!(drops.get(), 1);
    }
}
