//! What a binding and its links share: the socket, the table that routes
//! what arrives to each link, and the reading of the socket by whichever
//! of them holds the reader permit.

use core::{
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize},
    task::{Context, Poll},
    time::Duration,
};
use std::{
    collections::{HashMap, VecDeque},
    io,
    os::fd::AsFd,
    sync::{Arc, Mutex, MutexGuard, OnceLock},
};

use bytes::BytesMut;
use nix::errno::Errno;
use sakuya_clock::MonotonicClock;
use sakuya_link::{BindingId, EcnCodepoint, LinkId};
use tokio::{io::Interest, sync::Notify, sync::Semaphore};

use crate::{SocketFailedError, UdpBindingConfig, UdpLink, UdpLocal, sys};

/// How many receives the reader makes before it lets its task do other
/// work.
const RECEIVES_PER_TURN: usize = 32;

/// The first wait after a transient receive error; each further one
/// doubles, up to [`MAX_BACKOFF`].
const FIRST_BACKOFF: Duration = Duration::from_millis(1);
const MAX_BACKOFF: Duration = Duration::from_millis(100);

/// The bytes of a fresh receive buffer: several receives share one
/// allocation.
const BUFFER_SIZE: usize = 4 * sys::RECEIVE_SIZE;

/// Where a link's datagrams go: this side's IP address and the peer.
pub(crate) type Key = (IpAddr, SocketAddr);

/// A datagram waiting in its link's queue. It holds no clone of the link:
/// a queued datagram does not keep its link open.
pub(crate) struct Arrived<I> {
    pub(crate) payload: BytesMut,
    pub(crate) at: I,
    pub(crate) ecn: Option<EcnCodepoint>,
}

/// One link: its identity, the datagrams that arrived for it, and how many
/// clones of it exist.
pub(crate) struct LinkEntry<I> {
    pub(crate) id: LinkId<UdpLocal, SocketAddr>,
    pub(crate) queue: Mutex<VecDeque<Arrived<I>>>,
    /// Notified once for each datagram queued, and for all waiters when the
    /// socket fails.
    pub(crate) arrived: Notify,
    pub(crate) clones: AtomicUsize,
    pub(crate) conclusion: AtomicUsize,
}

impl<I> LinkEntry<I> {
    pub(crate) fn key(&self) -> Key {
        (self.id.local.address().ip(), self.id.peer)
    }

    pub(crate) fn pop(&self) -> Option<Arrived<I>> {
        lock(&self.queue).pop_front()
    }

    fn has_queued(&self) -> bool {
        !lock(&self.queue).is_empty()
    }
}

pub(crate) struct Demux<C: MonotonicClock + 'static> {
    pub(crate) links: HashMap<Key, Arc<LinkEntry<C::Instant>>>,
    /// Links made for new peers and not yet taken by `accept`.
    pub(crate) unaccepted: VecDeque<UdpLink<C>>,
    /// Whether new peers get links: off when the binding is told not to
    /// take them, or has been dropped.
    pub(crate) accepting: bool,
}

/// The buffers of the reader, used only by the holder of the reader
/// permit.
struct ReadBuffers {
    pool: BytesMut,
    control: Vec<u8>,
}

pub(crate) struct Shared<C: MonotonicClock + 'static> {
    pub(crate) socket: tokio::net::UdpSocket,
    pub(crate) clock: C,
    pub(crate) id: BindingId,
    pub(crate) bound: SocketAddr,
    pub(crate) config: UdpBindingConfig,
    pub(crate) no_fragment_v4: bool,
    pub(crate) no_fragment_v6: bool,
    pub(crate) may_mark_ecn: AtomicBool,
    pub(crate) gso: AtomicBool,
    /// One permit: whoever holds it reads the socket for everyone.
    pub(crate) reader: Semaphore,
    buffers: Mutex<ReadBuffers>,
    pub(crate) demux: Mutex<Demux<C>>,
    pub(crate) new_link: Notify,
    pub(crate) ended: Arc<Notify>,
    pub(crate) end: OnceLock<SocketFailedError>,
}

impl<C: MonotonicClock + 'static> Shared<C> {
    pub(crate) fn new(opened: sys::Opened, config: UdpBindingConfig, clock: C) -> io::Result<Self> {
        let accepting = config.accept_new_peers;
        Ok(Self {
            socket: tokio::net::UdpSocket::from_std(opened.socket)?,
            clock,
            id: BindingId::new(),
            bound: opened.local,
            config,
            no_fragment_v4: opened.no_fragment_v4,
            no_fragment_v6: opened.no_fragment_v6,
            may_mark_ecn: AtomicBool::new(true),
            gso: AtomicBool::new(true),
            reader: Semaphore::new(1),
            buffers: Mutex::new(ReadBuffers {
                pool: BytesMut::new(),
                control: sys::control_space(),
            }),
            demux: Mutex::new(Demux {
                links: HashMap::new(),
                unaccepted: VecDeque::new(),
                accepting,
            }),
            new_link: Notify::new(),
            ended: Arc::new(Notify::new()),
            end: OnceLock::new(),
        })
    }

    /// Whether the socket is on the unspecified address, so that each
    /// datagram says which local address it arrived at.
    pub(crate) fn unspecified(&self) -> bool {
        self.bound.ip().is_unspecified()
    }

    pub(crate) fn demux(&self) -> MutexGuard<'_, Demux<C>> {
        lock(&self.demux)
    }

    /// The socket failed: every link and the binding end with `errno`.
    pub(crate) fn fail(&self, errno: Errno) {
        if self.end.set(SocketFailedError { source: errno }).is_err() {
            return;
        }
        self.reader.close();
        let demux = self.demux();
        for entry in demux.links.values() {
            entry.arrived.notify_waiters();
        }
        drop(demux);
        self.new_link.notify_waiters();
        self.ended.notify_waiters();
    }

    /// Reads the socket until `own` has a datagram queued (for a link's
    /// receive), until a link waits to be accepted (for `accept`, with
    /// `own` `None`), or until the socket fails. The caller holds the
    /// reader permit.
    pub(crate) async fn read(self: &Arc<Self>, own: Option<&LinkEntry<C::Instant>>) {
        let mut backoff = FIRST_BACKOFF;
        let mut turn = 0;
        loop {
            let done = match own {
                Some(entry) => entry.has_queued(),
                None => !self.demux().unaccepted.is_empty(),
            };
            if done || self.end.get().is_some() {
                return;
            }
            if turn == RECEIVES_PER_TURN {
                turn = 0;
                YieldOnce(false).await;
            }
            if let Err(error) = self.socket.readable().await {
                self.fail(error.raw_os_error().map_or(Errno::EBADF, Errno::from_raw));
                return;
            }
            turn += 1;
            match self.socket.try_io(Interest::READABLE, || {
                self.receive_once().map_err(io::Error::from)
            }) {
                Ok(()) => backoff = FIRST_BACKOFF,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => {
                    let errno = error.raw_os_error().map_or(Errno::EIO, Errno::from_raw);
                    if errno == Errno::EINTR {
                        continue;
                    }
                    if sys::is_fatal(errno) {
                        self.fail(errno);
                        return;
                    }
                    self.clock.sleep_until(self.clock.now() + backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
    }

    /// One receive, and the routing of its datagrams to their links.
    fn receive_once(self: &Arc<Self>) -> Result<(), Errno> {
        let mut buffers = lock(&self.buffers);
        let ReadBuffers { pool, control } = &mut *buffers;
        if pool.len() < sys::RECEIVE_SIZE {
            *pool = BytesMut::zeroed(BUFFER_SIZE);
        }
        let received = sys::receive(self.socket.as_fd(), &mut pool[..sys::RECEIVE_SIZE], control)?;
        let at = self.clock.now();
        let mut batch = pool.split_to(received.len);
        drop(buffers);
        let local_ip = match received.local_ip {
            Some(ip) if self.unspecified() => ip,
            _ => self.bound.ip(),
        };
        let key = (local_ip, received.peer);
        let mut demux = self.demux();
        let entry = match demux.links.get(&key) {
            Some(entry) => Arc::clone(entry),
            None if demux.accepting
                && demux.unaccepted.len() < self.config.max_unaccepted_links =>
            {
                let local = UdpLocal::new(
                    self.id.clone(),
                    SocketAddr::new(local_ip, self.bound.port()),
                );
                let entry = new_entry::<C>(local, received.peer, &self.id);
                demux.links.insert(key, Arc::clone(&entry));
                demux
                    .unaccepted
                    .push_back(UdpLink::from_entry(Arc::clone(&entry), self));
                self.new_link.notify_one();
                entry
            }
            None => return Ok(()),
        };
        drop(demux);
        let mut queue = lock(&entry.queue);
        // A datagram of zero bytes is a message too: it is one segment.
        loop {
            let payload = batch.split_to(received.stride.min(batch.len()));
            if queue.len() < self.config.max_queued_datagrams {
                queue.push_back(Arrived {
                    payload,
                    at,
                    ecn: received.ecn,
                });
                entry.arrived.notify_one();
            }
            if batch.is_empty() {
                return Ok(());
            }
        }
    }
}

/// A new link's entry, with one clone counted: the caller makes that
/// clone.
pub(crate) fn new_entry<C: MonotonicClock + 'static>(
    local: UdpLocal,
    peer: SocketAddr,
    binding: &BindingId,
) -> Arc<LinkEntry<C::Instant>> {
    Arc::new(LinkEntry {
        id: LinkId::new::<UdpLink<C>>(local, peer, binding),
        queue: Mutex::new(VecDeque::new()),
        arrived: Notify::new(),
        clones: AtomicUsize::new(0),
        conclusion: AtomicUsize::new(sakuya_link::MIN_DATAGRAM_SIZE),
    })
}

/// Locks a mutex whose data no panic can leave inconsistent: each holder
/// only pushes, pops or replaces whole values.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Returns `Pending` once, waking its task first.
struct YieldOnce(bool);

impl Future for YieldOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            Poll::Ready(())
        } else {
            self.0 = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}
