use std::{
    collections::VecDeque,
    fmt,
    num::NonZeroUsize,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use futures_util::task::AtomicWaker;
use sakuya_datagram_routing::route::router::VersionService;
use sakuya_link::{Link, MIN_DATAGRAM_SIZE, ReceivedDatagram};
use sakuya_wire::{
    connection_id::RawConnectionId, header::codec::ReadLongHeaderHostExt as _, version::Version,
};

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
/// out Version Negotiation responses.
///
/// [RFC 9000 §5.2.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-5.2.2
/// [RFC 9000 §6.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-6.1
pub struct NegotiatingVersionService<L> {
    shared: Arc<Shared<L>>,
}

/// The responses a [`NegotiatingVersionService`] queued for the reflow
/// driver to send.
pub struct VersionNegotiationQueue<L> {
    shared: Arc<Shared<L>>,
}

impl<L> NegotiatingVersionService<L> {
    /// A service and the queue it fills, which holds at most `capacity`
    /// responses.
    #[must_use]
    pub fn new(capacity: NonZeroUsize) -> (Self, VersionNegotiationQueue<L>) {
        let shared = Arc::new(Shared {
            pending: Mutex::new(VecDeque::new()),
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

impl<P: AsRef<[u8]>, L: Link> VersionService<P, L> for NegotiatingVersionService<L> {
    fn unsupported_version(&self, version: Version, datagram: ReceivedDatagram<P, L>) {
        let mut bytes = datagram.payload().as_ref();
        if bytes.len() < MIN_DATAGRAM_SIZE {
            return;
        }
        // The longest version-independent long header is 517 bytes, so a
        // datagram of at least 1200 bytes always holds one; the arm that
        // releases the datagram is not reached.
        let Ok(header) = bytes.sync_read_long_header_unpin() else {
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

impl<L> VersionNegotiationQueue<L> {
    /// The oldest queued response, or `Pending` until one is queued.
    pub fn poll_pop(&self, cx: &mut Context<'_>) -> Poll<PendingVersionNegotiation<L>> {
        if let Some(pending) = self.shared.lock().pop_front() {
            return Poll::Ready(pending);
        }
        self.shared.waker.register(cx.waker());
        // A response queued between the first look and the registration
        // woke no one; look again.
        match self.shared.lock().pop_front() {
            Some(pending) => Poll::Ready(pending),
            None => Poll::Pending,
        }
    }

    /// How many responses are queued.
    #[must_use]
    pub fn len(&self) -> usize {
        self.shared.lock().len()
    }

    /// Whether no response is queued.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.shared.lock().is_empty()
    }

    /// How many responses were not queued because the queue was full; it only
    /// grows.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.shared.dropped.load(Ordering::Relaxed)
    }
}

impl<L> fmt::Debug for NegotiatingVersionService<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NegotiatingVersionService")
            .field("capacity", &self.shared.capacity)
            .finish_non_exhaustive()
    }
}

impl<L> fmt::Debug for VersionNegotiationQueue<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VersionNegotiationQueue")
            .field("capacity", &self.shared.capacity)
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

/// What the service and the queue share.
struct Shared<L> {
    pending: Mutex<VecDeque<PendingVersionNegotiation<L>>>,
    capacity: NonZeroUsize,
    waker: AtomicWaker,
    dropped: AtomicU64,
}

impl<L> Shared<L> {
    fn push(&self, pending: PendingVersionNegotiation<L>) {
        {
            let mut queue = self.lock();
            if queue.len() >= self.capacity.get() {
                drop(queue);
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
            queue.push_back(pending);
        }
        self.waker.wake();
    }

    /// The lock is also taken while a link's receive loop unwinds; a
    /// poisoned lock is used as it is, since a second panic would abort.
    fn lock(&self) -> MutexGuard<'_, VecDeque<PendingVersionNegotiation<L>>> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests;
