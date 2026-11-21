//! A bounded set of sends in progress.
//!
//! An endpoint sends some responses without any connection: Version
//! Negotiation packets, stateless Retry packets, and the Initial packets that
//! close an attempt with INVALID_TOKEN. Sending on a link returns a future
//! that waits for the link to take the datagram. The endpoint does not wait
//! for each one in turn, which would stop it from handling new connections
//! while a link pushes back; it keeps the futures in a [`BoundedSendSet`]
//! and drives them together, and when the set is full it does not send the
//! new response.

use core::{
    fmt,
    future::Future,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll, Waker},
};

use futures_util::{Stream, StreamExt, stream::FuturesUnordered};

/// Sends in progress, at most a fixed number at a time.
///
/// Polling the set as a [`Stream`] drives every send in it and yields the
/// output of each one that completes; a completed send leaves the set, which
/// frees its place. The stream never ends: when the set is empty it is
/// pending until [`try_push`](Self::try_push) adds a send.
///
/// A send dropped before it completes, by dropping the set or otherwise,
/// may or may not have sent its datagram. The responses an endpoint keeps
/// here can be lost on the path anyway, so either outcome is harmless.
pub struct BoundedSendSet<F> {
    capacity: NonZeroUsize,
    sends: FuturesUnordered<F>,
    /// The waker of the last poll, woken when a send is added: the inner set
    /// does not wake its poller when a future is pushed into it.
    waker: Option<Waker>,
}

impl<F: Future> BoundedSendSet<F> {
    /// An empty set of at most `capacity` sends.
    #[must_use]
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            capacity,
            sends: FuturesUnordered::new(),
            waker: None,
        }
    }

    /// Adds `send` to the set.
    ///
    /// # Errors
    ///
    /// Returns `send` back when the set is full. The caller drops it, and so
    /// does not send that response.
    pub fn try_push(&mut self, send: F) -> Result<(), F> {
        if self.sends.len() >= self.capacity.get() {
            return Err(send);
        }
        self.sends.push(send);
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
        Ok(())
    }

    /// The number of sends in progress.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sends.len()
    }

    /// Whether no send is in progress.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sends.is_empty()
    }

    /// The most sends the set holds at a time.
    #[must_use]
    pub fn capacity(&self) -> NonZeroUsize {
        self.capacity
    }
}

impl<F: Future> Stream for BoundedSendSet<F> {
    type Item = F::Output;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match &mut this.waker {
            Some(waker) => waker.clone_from(cx.waker()),
            None => this.waker = Some(cx.waker().clone()),
        }
        match this.sends.poll_next_unpin(cx) {
            Poll::Ready(Some(output)) => Poll::Ready(Some(output)),
            // The inner set reports an empty set as ended; this set waits
            // for the next send instead.
            Poll::Ready(None) | Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.sends.len(), None)
    }
}

impl<F> fmt::Debug for BoundedSendSet<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedSendSet")
            .field("capacity", &self.capacity)
            .field("len", &self.sends.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::BoundedSendSet;
    use core::{
        future::{Future, poll_fn},
        num::NonZeroUsize,
        task::{Context, Poll, Waker},
    };
    use futures_util::StreamExt;
    use std::{
        cell::{Cell, RefCell},
        rc::Rc,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::Wake,
    };

    /// What lets the test sends complete.
    #[derive(Default)]
    struct Gate {
        open: Cell<bool>,
        wakers: RefCell<Vec<Waker>>,
    }

    impl Gate {
        fn open(&self) {
            self.open.set(true);
            self.wakers.take().into_iter().for_each(Waker::wake);
        }
    }

    /// A send that completes with `id` once `gate` is open.
    fn send(id: u8, gate: &Rc<Gate>) -> impl Future<Output = u8> + use<> {
        let gate = Rc::clone(gate);
        poll_fn(move |cx| {
            if gate.open.get() {
                Poll::Ready(id)
            } else {
                gate.wakers.borrow_mut().push(cx.waker().clone());
                Poll::Pending
            }
        })
    }

    fn capacity(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).unwrap()
    }

    struct CountingWaker(AtomicUsize);

    impl Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn a_full_set_returns_the_send() {
        let gate = Rc::default();
        let mut set = BoundedSendSet::new(capacity(2));
        assert!(set.try_push(send(1, &gate)).is_ok());
        assert!(set.try_push(send(2, &gate)).is_ok());
        assert_eq!(set.len(), 2);
        assert!(set.try_push(send(3, &gate)).is_err());
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn a_completed_send_frees_its_place() {
        let first = Rc::default();
        let second = Rc::default();
        let mut set = BoundedSendSet::new(capacity(2));
        assert!(set.try_push(send(1, &first)).is_ok());
        assert!(set.try_push(send(2, &second)).is_ok());
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(set.poll_next_unpin(&mut cx), Poll::Pending);
        assert!(set.try_push(send(3, &first)).is_err());

        second.open();
        assert_eq!(set.poll_next_unpin(&mut cx), Poll::Ready(Some(2)));
        assert_eq!(set.len(), 1);
        assert!(set.try_push(send(3, &second)).is_ok());
        assert_eq!(set.poll_next_unpin(&mut cx), Poll::Ready(Some(3)));
        assert_eq!(set.poll_next_unpin(&mut cx), Poll::Pending);

        first.open();
        assert_eq!(set.poll_next_unpin(&mut cx), Poll::Ready(Some(1)));
        assert!(set.is_empty());
        assert_eq!(set.poll_next_unpin(&mut cx), Poll::Pending);
    }

    #[test]
    fn an_empty_set_waits_and_a_push_wakes_it() {
        let wakes = Arc::new(CountingWaker(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wakes));
        let mut cx = Context::from_waker(&waker);
        let gate = Rc::new(Gate::default());
        gate.open();
        let mut set = BoundedSendSet::new(capacity(1));
        assert_eq!(set.poll_next_unpin(&mut cx), Poll::Pending);

        assert!(set.try_push(send(1, &gate)).is_ok());
        assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
        assert_eq!(set.poll_next_unpin(&mut cx), Poll::Ready(Some(1)));
        assert_eq!(set.capacity(), capacity(1));
    }
}
