//! The Initials that arrive late, for an incoming connection born from
//! 0-RTT: they go back to the reflow driver, which checks them as it checks
//! the first datagram of every other incoming connection, so the stateless
//! steps and the record of used NEW_TOKEN tokens stay in one place.

use alloc::{
    collections::VecDeque,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    fmt,
    future::poll_fn,
    num::NonZeroUsize,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
};

use futures_util::task::AtomicWaker;

use crate::{
    choices::{DatagramOf, EndpointChoices, SharedStateOf, SynchronizationOf},
    stateless_check::ReturnedToken,
};
use nitori_sync::{SharedState as _, Synchronization as _};

/// The queue of late Initials the reflow driver checks.
pub(crate) struct LateInitials<E: EndpointChoices> {
    /// The queued late Initials, in the wrapper the host chose.
    queue: SharedStateOf<E, LateQueue<E>>,
    capacity: NonZeroUsize,
    /// The reflow driver's waker.
    waker: AtomicWaker,
    /// How many were dropped because the queue was full.
    dropped: AtomicU64,
}

/// The queued late Initials, whether the reflow driver is gone, after
/// which none is queued, and the wakers of the incoming connections waiting
/// for an Initial, woken when it goes.
struct LateQueue<E: EndpointChoices> {
    waiting: VecDeque<LateInitial<E>>,
    closed: bool,
    /// Listed by [`GoneWatch`]es; one whose watch was dropped is pruned
    /// before the list grows.
    watches: Vec<Weak<AtomicWaker>>,
}

/// What an incoming connection waiting for its Initial watches the reflow
/// driver with, to be woken when it goes.
#[derive(Debug, Default)]
pub(crate) struct GoneWatch {
    waker: Arc<AtomicWaker>,
    listed: bool,
}

/// What [`LateInitials::check`] did with a datagram.
enum Push<E: EndpointChoices> {
    Queued,
    /// The queue was full.
    Full(DatagramOf<E>),
    /// The reflow driver is gone.
    Closed(DatagramOf<E>),
}

/// A late Initial waiting to be checked, with where the answer goes.
pub(crate) struct LateInitial<E: EndpointChoices> {
    pub(crate) datagram: DatagramOf<E>,
    pub(crate) reply: Arc<LateReply<E>>,
}

/// What the reflow driver answers for one late Initial.
pub(crate) enum Answer<E: EndpointChoices> {
    /// The datagram may go to the connection, with the token it returned.
    Admitted(ReturnedToken, DatagramOf<E>),
    /// The datagram was dropped: the queue was full, or the check failed.
    Dropped,
    /// The reflow driver is gone, and nothing checks a late Initial.
    Gone,
}

/// The answer to one late Initial: the token it returned and the datagram,
/// when it may go to the connection.
pub(crate) struct LateReply<E: EndpointChoices> {
    /// The answer, in the wrapper the host chose.
    slot: SharedStateOf<E, Option<Answer<E>>>,
    waker: AtomicWaker,
}

impl<E: EndpointChoices> LateReply<E> {
    /// Answers the late Initial.
    pub(crate) fn answer(&self, answer: Answer<E>) {
        // Only the reflow driver answers, once.
        let earlier = self.slot.with(|slot| slot.replace(answer));
        drop(earlier);
        self.waker.wake();
    }

    fn poll_answer(&self, cx: &mut Context<'_>) -> Poll<Answer<E>> {
        if let Some(answer) = self.slot.with(Option::take) {
            return Poll::Ready(answer);
        }
        self.waker.register(cx.waker());
        match self.slot.with(Option::take) {
            Some(answer) => Poll::Ready(answer),
            None => Poll::Pending,
        }
    }
}

impl<E: EndpointChoices> LateInitials<E> {
    pub(crate) fn new(capacity: NonZeroUsize) -> Self {
        Self {
            queue: SynchronizationOf::<E>::share(LateQueue {
                waiting: VecDeque::new(),
                closed: false,
                watches: Vec::new(),
            }),
            capacity,
            waker: AtomicWaker::new(),
            dropped: AtomicU64::new(0),
        }
    }

    /// Has the reflow driver check `datagram`, and waits for its answer.
    pub(crate) async fn check(&self, datagram: DatagramOf<E>) -> Answer<E> {
        let reply = Arc::new(LateReply {
            slot: SynchronizationOf::<E>::share(None),
            waker: AtomicWaker::new(),
        });
        let queued = self.queue.with(|queue| {
            if queue.closed {
                return Push::<E>::Closed(datagram);
            }
            if queue.waiting.len() >= self.capacity.get() {
                return Push::Full(datagram);
            }
            queue.waiting.push_back(LateInitial {
                datagram,
                reply: Arc::clone(&reply),
            });
            Push::Queued
        });
        match queued {
            Push::Queued => {}
            Push::Full(datagram) => {
                drop(datagram);
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return Answer::Dropped;
            }
            Push::Closed(datagram) => {
                drop(datagram);
                return Answer::Gone;
            }
        }
        self.waker.wake();
        poll_fn(|cx| reply.poll_answer(cx)).await
    }

    /// The oldest late Initial, or `Pending` until one is queued.
    pub(crate) fn poll_pop(&self, cx: &mut Context<'_>) -> Poll<LateInitial<E>> {
        if let Some(late) = self.queue.with(|queue| queue.waiting.pop_front()) {
            return Poll::Ready(late);
        }
        self.waker.register(cx.waker());
        match self.queue.with(|queue| queue.waiting.pop_front()) {
            Some(late) => Poll::Ready(late),
            None => Poll::Pending,
        }
    }

    /// Ready once the reflow driver is gone; otherwise arranges for the
    /// task of `cx` to be woken when it goes.
    pub(crate) fn poll_gone(&self, watch: &mut GoneWatch, cx: &mut Context<'_>) -> Poll<()> {
        watch.waker.register(cx.waker());
        let gone = self.queue.with(|queue| {
            if queue.closed {
                return true;
            }
            if !watch.listed {
                let watches = &mut queue.watches;
                if watches.len() == watches.capacity() {
                    watches.retain(|listed| listed.strong_count() > 0);
                    // room for as many again, so that pruning stays
                    // amortized when most of the listed still wait
                    watches.reserve(watches.len());
                }
                watches.push(Arc::downgrade(&watch.waker));
                watch.listed = true;
            }
            false
        });
        if gone { Poll::Ready(()) } else { Poll::Pending }
    }

    /// The reflow driver is gone: the queued late Initials are dropped and
    /// answered [`Answer::Gone`], later ones are dropped at once, and the
    /// incoming connections watching for it are woken.
    pub(crate) fn close(&self) {
        let (waiting, watches) = self.queue.with(|queue| {
            queue.closed = true;
            (
                core::mem::take(&mut queue.waiting),
                core::mem::take(&mut queue.watches),
            )
        });
        for late in waiting {
            drop(late.datagram);
            late.reply.answer(Answer::Gone);
        }
        for watch in watches.iter().filter_map(Weak::upgrade) {
            watch.wake();
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
            .field("waiting", &self.queue.with(|queue| queue.waiting.len()))
            .field("dropped", &self.dropped())
            .finish_non_exhaustive()
    }
}
