use alloc::{collections::VecDeque, sync::Arc};
use core::{
    fmt,
    num::NonZeroUsize,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
};

use futures_util::task::AtomicWaker;
use nitori_sync::SharedState as _;
use sakuya_datagram_routing::route::router::VersionService;
use sakuya_link::{Link, MIN_DATAGRAM_SIZE, ReceivedDatagram};
use sakuya_wire::{
    connection_id::RawConnectionId, header::codec::read_long_header, version::Version,
};

use crate::synchronization::EndpointSynchronization;

/// What the endpoint keeps of a datagram of an unsupported version to answer
/// it with a Version Negotiation packet.
///
/// The datagram itself is released as soon as these are taken from it.
#[derive(Clone, Debug)]
pub struct PendingVersionNegotiation<L> {
    /// The destination connection ID of the client's packet, up to 255
    /// bytes.
    pub client_dcid: RawConnectionId,
    /// The source connection ID of the client's packet, up to 255 bytes.
    pub client_scid: RawConnectionId,
    /// The version the client's packet used.
    pub client_version: Version,
    /// The link the datagram arrived on, to send the response on.
    pub link: L,
}

/// The version service a server endpoint gives its routing.
///
/// Routing calls it on the receiving link's stack with a datagram whose
/// first packet has a version other than 0 and the supported ones. It does
/// three things there: it drops a datagram smaller than 1200 bytes
/// ([RFC 9000 §5.2.2]), takes what a response needs, and puts that in the
/// endpoint's [`VersionNegotiationQueue`], waking the reflow driver, which
/// encodes and sends the response. When the queue is full the new response
/// is not sent, which the protocol allows ([RFC 9000 §6.1]); the queue
/// counts it. A flood of datagrams with made-up versions thus only crowds
/// out Version Negotiation responses. The queued responses are in the
/// wrapper of the synchronization `Y` the host chose.
///
/// [RFC 9000 §5.2.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-5.2.2
/// [RFC 9000 §6.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-6.1
pub struct NegotiatingVersionService<L, Y: EndpointSynchronization> {
    shared: Arc<Shared<L, Y>>,
}

/// The responses a [`NegotiatingVersionService`] queued for the reflow
/// driver to send.
///
/// Each queued response holds the link it is to be sent on. Dropped, the
/// queue releases them and the service queues nothing more, so a link is
/// not kept by responses no one will send.
pub struct VersionNegotiationQueue<L, Y: EndpointSynchronization> {
    shared: Arc<Shared<L, Y>>,
}

impl<L, Y: EndpointSynchronization> NegotiatingVersionService<L, Y> {
    /// A service and the queue it fills, which holds at most `capacity`
    /// responses.
    #[must_use]
    pub fn new(capacity: NonZeroUsize) -> (Self, VersionNegotiationQueue<L, Y>) {
        let shared = Arc::new(Shared {
            pending: Y::share(Pending {
                queue: VecDeque::new(),
                ended: false,
            }),
            capacity,
            waker: AtomicWaker::new(),
            dropped: AtomicU64::new(0),
        });
        (
            Self {
                shared: Arc::clone(&shared),
            },
            VersionNegotiationQueue { shared },
        )
    }
}

impl<P: AsRef<[u8]>, L: Link, Y: EndpointSynchronization> VersionService<P, L>
    for NegotiatingVersionService<L, Y>
{
    fn unsupported_version(&self, version: Version, datagram: ReceivedDatagram<P, L>) {
        let mut bytes = datagram.payload().as_ref();
        if bytes.len() < MIN_DATAGRAM_SIZE {
            return;
        }
        // The longest version-independent long header is 517 bytes, so a
        // datagram of at least 1200 bytes always holds one; the arm that
        // releases the datagram is not reached.
        let Ok(header) = read_long_header(&mut bytes) else {
            return;
        };
        let pending = PendingVersionNegotiation {
            client_dcid: *header.dcid(),
            client_scid: *header.scid(),
            client_version: version,
            link: datagram.link().clone(),
        };
        drop(datagram);
        self.shared.push(pending);
    }
}

impl<L, Y: EndpointSynchronization> VersionNegotiationQueue<L, Y> {
    /// The oldest queued response, or `Pending` until one is queued.
    pub fn poll_pop(&self, cx: &mut Context<'_>) -> Poll<PendingVersionNegotiation<L>> {
        if let Some(pending) = self.shared.pop() {
            return Poll::Ready(pending);
        }
        self.shared.waker.register(cx.waker());
        // A response queued between the first look and the registration
        // woke no one; look again.
        match self.shared.pop() {
            Some(pending) => Poll::Ready(pending),
            None => Poll::Pending,
        }
    }

    /// How many responses are queued.
    #[must_use]
    pub fn len(&self) -> usize {
        self.shared.pending.with(|pending| pending.queue.len())
    }

    /// Whether no response is queued.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.shared.pending.with(|pending| pending.queue.is_empty())
    }

    /// How many responses were not queued because the queue was full; it only
    /// grows.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.shared.dropped.load(Ordering::Relaxed)
    }
}

impl<L, Y: EndpointSynchronization> Drop for VersionNegotiationQueue<L, Y> {
    fn drop(&mut self) {
        let released = self.shared.pending.with(|pending| {
            pending.ended = true;
            core::mem::take(&mut pending.queue)
        });
        // Outside the wrapper: releasing a link's last use wakes its receive
        // loop.
        drop(released);
    }
}

impl<L, Y: EndpointSynchronization> fmt::Debug for NegotiatingVersionService<L, Y> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NegotiatingVersionService")
            .field("capacity", &self.shared.capacity)
            .finish_non_exhaustive()
    }
}

impl<L, Y: EndpointSynchronization> fmt::Debug for VersionNegotiationQueue<L, Y> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VersionNegotiationQueue")
            .field("capacity", &self.shared.capacity)
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

/// What the service and the queue share.
struct Shared<L, Y: EndpointSynchronization> {
    /// The queued responses, in the wrapper the host chose.
    pending: Y::SharedState<Pending<L>>,
    capacity: NonZeroUsize,
    waker: AtomicWaker,
    dropped: AtomicU64,
}

/// The queued responses, and whether the queue was dropped.
struct Pending<L> {
    queue: VecDeque<PendingVersionNegotiation<L>>,
    ended: bool,
}

/// What pushing a response did.
enum Pushed<L> {
    Queued,
    /// The queue was dropped: the response is dropped outside the wrapper.
    Ended(PendingVersionNegotiation<L>),
    /// The queue was full: the response is dropped outside the wrapper and
    /// counted.
    Full(PendingVersionNegotiation<L>),
}

impl<L, Y: EndpointSynchronization> Shared<L, Y> {
    fn push(&self, pending: PendingVersionNegotiation<L>) {
        // The wrapper is also borrowed while a link's receive loop unwinds;
        // the host's wrapper takes a poisoned lock as it is.
        let pushed = self.pending.with(|queued| {
            if queued.ended {
                return Pushed::Ended(pending);
            }
            if queued.queue.len() >= self.capacity.get() {
                return Pushed::Full(pending);
            }
            queued.queue.push_back(pending);
            Pushed::Queued
        });
        match pushed {
            Pushed::Queued => self.waker.wake(),
            Pushed::Ended(pending) => drop(pending),
            Pushed::Full(pending) => {
                drop(pending);
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// The oldest queued response.
    fn pop(&self) -> Option<PendingVersionNegotiation<L>> {
        self.pending.with(|pending| pending.queue.pop_front())
    }
}

#[cfg(test)]
mod tests;
