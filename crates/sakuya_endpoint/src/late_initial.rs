//! The Initials that arrive late, for an incoming connection born from
//! 0-RTT: they go back to the reflow driver, which checks them as it checks
//! the first datagram of every other incoming connection, so the stateless
//! steps and the record of used NEW_TOKEN tokens stay in one place.

use core::{
    fmt,
    future::poll_fn,
    num::NonZeroUsize,
    task::{Context, Poll},
};
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

use futures_util::task::AtomicWaker;

use crate::{
    choices::{DatagramOf, EndpointChoices},
    stateless_check::ReturnedToken,
};

/// The queue of late Initials the reflow driver checks.
pub(crate) struct LateInitials<E: EndpointChoices> {
    queue: Mutex<VecDeque<LateInitial<E>>>,
    capacity: NonZeroUsize,
    /// The reflow driver's waker.
    waker: AtomicWaker,
    /// How many were dropped because the queue was full.
    dropped: AtomicU64,
}

/// A late Initial waiting to be checked, with where the answer goes.
pub(crate) struct LateInitial<E: EndpointChoices> {
    pub(crate) datagram: DatagramOf<E>,
    pub(crate) reply: Arc<LateReply<E>>,
}

/// What the reflow driver answers for one late Initial: the token it
/// returned and the datagram, when it may go to the connection; `None` when
/// it is dropped.
pub(crate) type Answer<E> = Option<(ReturnedToken, DatagramOf<E>)>;

/// The answer to one late Initial: the token it returned and the datagram,
/// when it may go to the connection.
pub(crate) struct LateReply<E: EndpointChoices> {
    slot: Mutex<Option<Answer<E>>>,
    waker: AtomicWaker,
}

impl<E: EndpointChoices> LateReply<E> {
    /// Answers: `Some` lets the datagram go to the connection with the
    /// token it returned; `None` drops it.
    pub(crate) fn answer(&self, answer: Answer<E>) {
        *lock(&self.slot) = Some(answer);
        self.waker.wake();
    }

    fn poll_answer(&self, cx: &mut Context<'_>) -> Poll<Answer<E>> {
        if let Some(answer) = lock(&self.slot).take() {
            return Poll::Ready(answer);
        }
        self.waker.register(cx.waker());
        match lock(&self.slot).take() {
            Some(answer) => Poll::Ready(answer),
            None => Poll::Pending,
        }
    }
}

impl<E: EndpointChoices> LateInitials<E> {
    pub(crate) fn new(capacity: NonZeroUsize) -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            capacity,
            waker: AtomicWaker::new(),
            dropped: AtomicU64::new(0),
        }
    }

    /// Has the reflow driver check `datagram`, and waits for its answer;
    /// `None` when the datagram was dropped: the queue was full, the check
    /// failed, or the attempt was closed.
    pub(crate) async fn check(&self, datagram: DatagramOf<E>) -> Answer<E> {
        let reply = Arc::new(LateReply {
            slot: Mutex::new(None),
            waker: AtomicWaker::new(),
        });
        {
            let mut queue = lock(&self.queue);
            if queue.len() >= self.capacity.get() {
                drop(queue);
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            queue.push_back(LateInitial {
                datagram,
                reply: Arc::clone(&reply),
            });
        }
        self.waker.wake();
        poll_fn(|cx| reply.poll_answer(cx)).await
    }

    /// The oldest late Initial, or `Pending` until one is queued.
    pub(crate) fn poll_pop(&self, cx: &mut Context<'_>) -> Poll<LateInitial<E>> {
        if let Some(late) = lock(&self.queue).pop_front() {
            return Poll::Ready(late);
        }
        self.waker.register(cx.waker());
        match lock(&self.queue).pop_front() {
            Some(late) => Poll::Ready(late),
            None => Poll::Pending,
        }
    }

    /// How many late Initials were dropped because the queue was full.
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl<E: EndpointChoices> fmt::Debug for LateInitials<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LateInitials")
            .field("waiting", &lock(&self.queue).len())
            .field("dropped", &self.dropped())
            .finish_non_exhaustive()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
