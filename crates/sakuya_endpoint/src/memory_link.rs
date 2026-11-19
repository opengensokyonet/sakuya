//! Links and link bindings in memory, for tests.
//!
//! A [`MemoryLink`] receives what its [`MemoryPeer`] sends it and ends when
//! the peer ends it; it never sends. Its type parameter tells link types
//! apart, so that a sum of two members can be built from it. A
//! [`MemoryBinding`] gives the links it is offered when accepting, and a
//! [`DialingBinding`] gives none: it only connects, which tests stand for by
//! admitting links themselves.

use core::{
    future::{Future, Pending, poll_fn},
    marker::PhantomData,
    task::{Poll, Waker},
    time::Duration,
};
use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
};

use sakuya_link::{
    AcceptingLinkBinding, ArrivalFacts, BindingId, Link, LinkBinding, LinkId, MIN_DATAGRAM_SIZE,
    OutgoingDatagram, ReceivedDatagram, SendAcceptance,
};

/// What a link and its peer share.
#[derive(Default)]
struct Wire {
    state: Mutex<WireState>,
    conclusion: AtomicUsize,
}

#[derive(Default)]
struct WireState {
    queue: VecDeque<Vec<u8>>,
    ended: bool,
    receiver: Option<Waker>,
}

impl Wire {
    fn state(&self) -> std::sync::MutexGuard<'_, WireState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A link in memory whose local end is a port number and whose peer is an
/// address; `T` names the link type.
pub(crate) struct MemoryLink<T: 'static = ()> {
    id: Arc<LinkId<u16, SocketAddr>>,
    wire: Arc<Wire>,
    kind: PhantomData<fn() -> T>,
}

impl<T: 'static> Clone for MemoryLink<T> {
    fn clone(&self) -> Self {
        Self {
            id: Arc::clone(&self.id),
            wire: Arc::clone(&self.wire),
            kind: PhantomData,
        }
    }
}

impl<T: 'static> core::fmt::Debug for MemoryLink<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("MemoryLink").field(&self.id).finish()
    }
}

/// The far end of a [`MemoryLink`].
pub(crate) struct MemoryPeer {
    wire: Arc<Wire>,
}

impl MemoryPeer {
    /// Sends `payload` to the link.
    pub(crate) fn send(&self, payload: &[u8]) {
        let mut state = self.wire.state();
        state.queue.push_back(payload.to_vec());
        let receiver = state.receiver.take();
        drop(state);
        receiver.into_iter().for_each(Waker::wake);
    }

    /// Ends the link.
    pub(crate) fn end(&self) {
        let mut state = self.wire.state();
        state.ended = true;
        let receiver = state.receiver.take();
        drop(state);
        receiver.into_iter().for_each(Waker::wake);
    }

    /// How many clones of the link exist: none once it is closed.
    pub(crate) fn link_clones(&self) -> usize {
        Arc::strong_count(&self.wire) - 1
    }
}

impl<T: 'static> MemoryLink<T> {
    /// A new link of the binding `binding` and its far end.
    pub(crate) fn new(local: u16, peer: SocketAddr, binding: &BindingId) -> (Self, MemoryPeer) {
        let wire = Arc::new(Wire {
            conclusion: AtomicUsize::new(MIN_DATAGRAM_SIZE),
            ..Wire::default()
        });
        let link = Self {
            id: Arc::new(LinkId::new::<Self>(local, peer, binding)),
            wire: Arc::clone(&wire),
            kind: PhantomData,
        };
        (link, MemoryPeer { wire })
    }
}

impl<T: 'static> Link for MemoryLink<T> {
    type Local = u16;
    type Peer = SocketAddr;
    type Payload = Vec<u8>;
    type Instant = Duration;
    type RecvError = ();
    type Recv<'a>
        = impl Future<Output = Result<ReceivedDatagram<Vec<u8>, Self>, ()>> + 'a
    where
        Self: 'a;
    type Ended = Pending<()>;
    type MaxDatagramSizeError = ();
    type SendError = ();
    type Send<'a> = Pending<Result<SendAcceptance<Duration>, ()>>;
    type MaxDatagramSizeChanged = Pending<()>;

    fn id(&self) -> &LinkId<u16, SocketAddr> {
        &self.id
    }

    fn may_mark_ecn(&self) -> bool {
        false
    }

    fn max_datagram_size(&self) -> Result<usize, ()> {
        Ok(1452)
    }

    fn recv(&self) -> Self::Recv<'_> {
        poll_fn(move |cx| {
            let mut state = self.wire.state();
            if state.ended {
                return Poll::Ready(Err(()));
            }
            match state.queue.pop_front() {
                Some(payload) => Poll::Ready(Ok(ReceivedDatagram::new(
                    payload,
                    ArrivalFacts::new(self.clone(), Duration::ZERO, None),
                ))),
                None => {
                    state.receiver = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
        })
    }

    fn ended(&self) -> Pending<()> {
        core::future::pending()
    }

    fn send<'a>(&self, _batch: &'a [OutgoingDatagram]) -> Self::Send<'a> {
        core::future::pending()
    }

    fn max_datagram_size_changed(&self) -> Pending<()> {
        core::future::pending()
    }

    fn datagram_size_conclusion(&self) -> usize {
        self.wire.conclusion.load(Ordering::Relaxed)
    }

    fn record_datagram_size_confirmed(&self, size: usize) {
        self.wire.conclusion.fetch_max(size, Ordering::Relaxed);
    }
}

/// What a memory binding and its clones share.
#[derive(Default)]
struct Offers {
    links: VecDeque<MemoryLink>,
    failed: bool,
    accepts: usize,
    acceptor: Option<Waker>,
}

/// A binding that accepts the links it is offered, until it fails; its
/// clones share it.
#[derive(Clone)]
pub(crate) struct MemoryBinding {
    id: Arc<BindingId>,
    offers: Arc<Mutex<Offers>>,
}

impl MemoryBinding {
    pub(crate) fn new() -> Self {
        Self {
            id: Arc::new(BindingId::new()),
            offers: Arc::default(),
        }
    }

    fn offers(&self) -> std::sync::MutexGuard<'_, Offers> {
        self.offers.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Lets the next accept give `link`.
    pub(crate) fn offer(&self, link: MemoryLink) {
        let mut offers = self.offers();
        offers.links.push_back(link);
        let acceptor = offers.acceptor.take();
        drop(offers);
        acceptor.into_iter().for_each(Waker::wake);
    }

    /// Makes accept fail once the links offered are taken.
    pub(crate) fn fail(&self) {
        let mut offers = self.offers();
        offers.failed = true;
        let acceptor = offers.acceptor.take();
        drop(offers);
        acceptor.into_iter().for_each(Waker::wake);
    }

    /// How many accepts were made.
    pub(crate) fn accepts(&self) -> usize {
        self.offers().accepts
    }
}

impl LinkBinding for MemoryBinding {
    type Link = MemoryLink;

    fn id(&self) -> &BindingId {
        &self.id
    }

    /// A port no link of the tests has: the links offered bring their own.
    fn local(&self) -> &u16 {
        &0
    }
}

impl AcceptingLinkBinding for MemoryBinding {
    type AcceptError = ();
    type Accept<'a> = impl Future<Output = Result<MemoryLink, ()>> + 'a;

    fn accept(&self) -> Self::Accept<'_> {
        self.offers().accepts += 1;
        poll_fn(move |cx| {
            let mut offers = self.offers();
            if let Some(link) = offers.links.pop_front() {
                return Poll::Ready(Ok(link));
            }
            if offers.failed {
                return Poll::Ready(Err(()));
            }
            offers.acceptor = Some(cx.waker().clone());
            Poll::Pending
        })
    }
}

/// A binding that only connects: it cannot accept.
pub(crate) struct DialingBinding {
    id: BindingId,
}

impl DialingBinding {
    pub(crate) fn new() -> Self {
        Self {
            id: BindingId::new(),
        }
    }
}

impl LinkBinding for DialingBinding {
    type Link = MemoryLink;

    fn id(&self) -> &BindingId {
        &self.id
    }

    /// A port no link of the tests has.
    fn local(&self) -> &u16 {
        &0
    }
}
