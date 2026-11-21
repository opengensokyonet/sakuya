//! The delivery queue of a receiver whose deliverers post from other
//! threads.

use std::fmt;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Poll};

use sakuya_connection::v1::input::LogicalPathDatagramReceiver;
use sakuya_datagram_routing_v1::claim::delivery::DatagramDelivery;
use sakuya_datagram_routing_v1::claim::finish::UnclaimedHandoff;
use sakuya_datagram_routing_v1::claim::lock::DatagramClaimLock;
use sakuya_datagram_routing_v1::claim::queue::{
    DatagramDeliveryPoster, DatagramDeliveryQueue, DatagramDeliveryQueueState, QueueCapacityError,
};
use sakuya_datagram_routing_v1::route::acceptance::{ReflowProvider, UnclaimedWork};
use sakuya_link::{Link, ReceivedDatagram};

/// The state of a queue behind its mutex.
type Shared<T> = Mutex<DatagramDeliveryQueueState<T>>;

/// Locks `shared`, taking a lock a panic poisoned as it is: the state holds
/// no invariant a panic could break midway, and the queue is closed while a
/// panic unwinds.
fn lock<T>(shared: &Shared<T>) -> MutexGuard<'_, DatagramDeliveryQueueState<T>> {
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The delivery queue of a receiver whose deliverers post from other
/// threads (`MutexDatagramDeliveryQueue`): its state behind a mutex of std,
/// which the queue holds through an `Arc` and its posters through a weak
/// one.
///
/// It and its posters are `Send` and `Sync` when the items are `Send`.
pub struct MutexDatagramDeliveryQueue<T> {
    shared: Arc<Shared<T>>,
}

impl<T> DatagramDeliveryQueue<T> for MutexDatagramDeliveryQueue<T> {
    type Poster = MutexDatagramDeliveryPoster<T>;

    fn new(capacity: NonZeroUsize) -> Result<Self, QueueCapacityError> {
        Ok(Self {
            shared: Arc::new(Mutex::new(DatagramDeliveryQueueState::new(capacity)?)),
        })
    }

    fn poster(&self) -> MutexDatagramDeliveryPoster<T> {
        MutexDatagramDeliveryPoster {
            shared: Arc::downgrade(&self.shared),
        }
    }

    fn try_recv(&mut self) -> Option<T> {
        lock(&self.shared).try_recv()
    }

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<T> {
        lock(&self.shared).poll_recv(cx)
    }
}

impl<T> Drop for MutexDatagramDeliveryQueue<T> {
    fn drop(&mut self) {
        let closed = lock(&self.shared).close();
        // the items and the waker go outside the lock: dropping them may
        // run code that posts again
        drop(closed);
    }
}

impl<T> fmt::Debug for MutexDatagramDeliveryQueue<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MutexDatagramDeliveryQueue")
            .field("queued", &lock(&self.shared).len())
            .finish_non_exhaustive()
    }
}

/// A delivery queue whose deliverers post from other threads is a receiver
/// of a logical path.
impl<Lk, H, C> LogicalPathDatagramReceiver<Lk>
    for MutexDatagramDeliveryQueue<
        DatagramDelivery<ReceivedDatagram<Lk::Payload, Lk>, Lk::Local, H, C>,
    >
where
    Lk: Link,
    H: UnclaimedHandoff<ReceivedDatagram<Lk::Payload, Lk>>,
    C: DatagramClaimLock,
{
    type Handoff = H;
    type ClaimLock = C;

    fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<DatagramDelivery<ReceivedDatagram<Lk::Payload, Lk>, Lk::Local, H, C>> {
        self.poll_recv(cx)
    }
}

/// The poster of a [`MutexDatagramDeliveryQueue`].
pub struct MutexDatagramDeliveryPoster<T> {
    shared: Weak<Shared<T>>,
}

impl<T> DatagramDeliveryPoster<T> for MutexDatagramDeliveryPoster<T> {
    fn post(&self, item: T) {
        let Some(shared) = self.shared.upgrade() else {
            return;
        };
        let posted = lock(&shared).try_post(item);
        // A closed or full queue hands the item back, dropped here, outside
        // the lock.
        if let Ok(Some(waker)) = posted {
            waker.wake();
        }
    }

    fn is_closed(&self) -> bool {
        self.shared
            .upgrade()
            .is_none_or(|shared| lock(&shared).is_closed())
    }
}

impl<T> Clone for MutexDatagramDeliveryPoster<T> {
    fn clone(&self) -> Self {
        Self {
            shared: Weak::clone(&self.shared),
        }
    }
}

impl<T> fmt::Debug for MutexDatagramDeliveryPoster<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MutexDatagramDeliveryPoster")
            .field("closed", &self.is_closed())
            .finish()
    }
}

/// Queues reflow work for the outer layer to resume later, as the queue of
/// one thread does.
impl<Payload, L: Link> ReflowProvider<Payload, L>
    for MutexDatagramDeliveryPoster<UnclaimedWork<Payload, L>>
{
    fn hand_off(&self, work: UnclaimedWork<Payload, L>) {
        self.post(work);
    }
}
