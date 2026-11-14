//! The link: one peer on a binding's socket, from one local address.

use core::{
    fmt,
    future::{Future, Pending},
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    pin::pin,
    sync::atomic::Ordering,
};
use std::{io, io::IoSlice, os::fd::AsFd, sync::Arc};

use bytes::BytesMut;
use futures_util::future::{Either, select};
use nix::errno::Errno;
use sakuya_clock::MonotonicClock;
use sakuya_link::{
    ArrivalFacts, BindingId, EcnMarking, Link, LinkId, MIN_DATAGRAM_SIZE, OutgoingDatagram,
    ReceivedDatagram, SendAcceptance,
};
use snafu::Snafu;
use tokio::io::Interest;

use crate::shared::{LinkEntry, Shared};
use crate::sys;

/// This side's end of a UDP link: the socket, named by its binding, and
/// the local address.
///
/// On a socket bound to the unspecified address, the local address is the
/// one each datagram arrived at, so one socket has links from several
/// local addresses.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct UdpLocal {
    binding: BindingId,
    address: SocketAddr,
}

impl UdpLocal {
    pub(crate) fn new(binding: BindingId, address: SocketAddr) -> Self {
        Self { binding, address }
    }

    /// The local address and port.
    #[must_use]
    pub fn address(&self) -> SocketAddr {
        self.address
    }
}

/// The socket of a UDP link failed: why the link, its binding and all of
/// the binding's other links ended.
#[derive(Debug, Clone, Snafu)]
#[snafu(display("the socket failed"))]
pub struct SocketFailedError {
    /// The error of the socket call that failed.
    pub(crate) source: Errno,
}

/// Why [`UdpLink::send`](Link::send) gave up the first datagram it had not
/// sent.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SendDatagramError {
    /// The kernel refused the datagram, for example because it is larger
    /// than the interface allows.
    #[snafu(display("the datagram was not sent"))]
    Refused {
        /// The error of `sendmsg`.
        source: Errno,
    },
    /// The socket failed; the link has ended.
    #[snafu(display("the link has ended"), context(false))]
    Ended {
        /// Why the socket failed.
        source: SocketFailedError,
    },
}

/// Why [`UdpLink::max_datagram_size`](Link::max_datagram_size) cannot be
/// told: the link has ended.
#[derive(Debug, Snafu)]
#[snafu(display("the link has ended"))]
pub struct LinkEndedError {
    source: SocketFailedError,
}

/// A link to one peer over a [`UdpBinding`](crate::UdpBinding)'s socket.
///
/// Its clones share the link; when the last one is dropped the link is
/// closed, and later datagrams from the peer make a new link.
///
/// The socket is read by whichever of its binding's receives and accepts
/// holds the reader's turn, for all of them; the others wait for their own
/// datagrams. So every task that receives on links of one binding must be
/// polled when woken: while the reader's task is not, no link of the binding
/// receives. Several receives on one link may be pending at once; each
/// datagram goes to one of them.
pub struct UdpLink<C: MonotonicClock + 'static> {
    entry: Arc<LinkEntry<C::Instant>>,
    shared: Arc<Shared<C>>,
}

impl<C: MonotonicClock + 'static> UdpLink<C> {
    /// A new clone of the link of `entry`.
    pub(crate) fn from_entry(entry: Arc<LinkEntry<C::Instant>>, shared: &Arc<Shared<C>>) -> Self {
        entry.clones.fetch_add(1, Ordering::Relaxed);
        Self {
            entry,
            shared: Arc::clone(shared),
        }
    }

    fn arrived(
        &self,
        arrived: crate::shared::Arrived<C::Instant>,
    ) -> ReceivedDatagram<BytesMut, Self> {
        ReceivedDatagram::new(
            arrived.payload,
            ArrivalFacts::new(self.clone(), arrived.at, arrived.ecn),
        )
    }

    async fn receive(&self) -> Result<ReceivedDatagram<BytesMut, Self>, SocketFailedError> {
        let shared = &self.shared;
        let entry = &*self.entry;
        loop {
            let arrived = pin!(entry.arrived.notified());
            if let Some(end) = shared.end.get() {
                return Err(end.clone());
            }
            if let Some(datagram) = entry.pop() {
                return Ok(self.arrived(datagram));
            }
            let turn = pin!(shared.reader.acquire());
            if let Either::Right((Ok(permit), _)) = select(arrived, turn).await {
                shared.read(Some(entry)).await;
                drop(permit);
            }
        }
    }

    async fn send_batch(
        shared: Arc<Shared<C>>,
        entry: Arc<LinkEntry<C::Instant>>,
        batch: &[OutgoingDatagram],
    ) -> Result<SendAcceptance<C::Instant>, SendDatagramError> {
        let peer = entry.id.peer;
        let local_ip = shared.unspecified().then(|| entry.id.local.address.ip());
        loop {
            if let Some(end) = shared.end.get() {
                return Err(end.clone().into());
            }
            let first = &batch[0];
            // A GSO batch names its datagrams' size; one too large for that
            // goes alone.
            let size = u16::try_from(first.payload.len()).ok();
            let count = match size {
                Some(_) => gso_prefix(batch, shared.gso.load(Ordering::Relaxed)),
                None => 1,
            };
            let segment = size.filter(|_| count > 1);
            let ecn = (shared.may_mark_ecn.load(Ordering::Relaxed)
                && first.ecn != EcnMarking::NotEct)
                .then(|| ecn_bits(first.ecn));
            let slices: Vec<IoSlice<'_>> = batch[..count]
                .iter()
                .map(|d| IoSlice::new(&d.payload))
                .collect();
            let send = sys::Send {
                payloads: &slices,
                peer,
                ecn,
                local_ip,
                segment,
                ipv6_socket: shared.bound.is_ipv6(),
            };
            let outcome = shared.socket.try_io(Interest::WRITABLE, || {
                sys::send(shared.socket.as_fd(), &send).map_err(io::Error::from)
            });
            let errno = match outcome {
                Ok(()) => {
                    let count = NonZeroUsize::new(count).expect("a batch is not empty");
                    return Ok(SendAcceptance {
                        count,
                        at: shared.clock.now(),
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if let Err(error) = shared.socket.writable().await {
                        shared.fail(error.raw_os_error().map_or(Errno::EBADF, Errno::from_raw));
                    }
                    continue;
                }
                Err(error) => error.raw_os_error().map_or(Errno::EIO, Errno::from_raw),
            };
            match errno {
                Errno::EINTR => {}
                // A kernel or driver that cannot segment refuses GSO with
                // EIO or EINVAL: send one at a time from now on.
                Errno::EIO | Errno::EINVAL if segment.is_some() => {
                    shared.gso.store(false, Ordering::Relaxed);
                }
                // One that refuses the ECN control message: send unmarked.
                Errno::EINVAL if ecn.is_some() => {
                    shared.may_mark_ecn.store(false, Ordering::Relaxed);
                }
                errno if sys::is_fatal(errno) => shared.fail(errno),
                errno => return Err(SendDatagramError::Refused { source: errno }),
            }
        }
    }
}

/// How many datagrams from the start of `batch` one send carries: with GSO,
/// those of the first one's size and ECN marking, the last of them possibly
/// shorter, within the kernel's limits.
fn gso_prefix(batch: &[OutgoingDatagram], gso: bool) -> usize {
    let first = &batch[0];
    let size = first.payload.len();
    if !gso || size == 0 {
        return 1;
    }
    let mut count = 1;
    let mut total = size;
    for datagram in &batch[1..] {
        let len = datagram.payload.len();
        if count == sys::MAX_GSO_SEGMENTS
            || datagram.ecn != first.ecn
            || len > size
            || len == 0
            || total + len > sys::MAX_GSO_BYTES
        {
            break;
        }
        count += 1;
        total += len;
        if len < size {
            break;
        }
    }
    count
}

fn ecn_bits(marking: EcnMarking) -> u8 {
    match marking {
        EcnMarking::NotEct => 0b00,
        EcnMarking::Ect1 => 0b01,
        EcnMarking::Ect0 => 0b10,
    }
}

impl<C: MonotonicClock + 'static> Clone for UdpLink<C> {
    fn clone(&self) -> Self {
        Self::from_entry(Arc::clone(&self.entry), &self.shared)
    }
}

impl<C: MonotonicClock + 'static> Drop for UdpLink<C> {
    fn drop(&mut self) {
        if self.entry.clones.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }
        // The last clone: close the link, unless a connect found it in the
        // table and made a clone in the meantime.
        let mut demux = self.shared.demux();
        if self.entry.clones.load(Ordering::Acquire) == 0 {
            let key = self.entry.key();
            if demux
                .links
                .get(&key)
                .is_some_and(|entry| Arc::ptr_eq(entry, &self.entry))
            {
                demux.links.remove(&key);
            }
        }
    }
}

impl<C: MonotonicClock + 'static> fmt::Debug for UdpLink<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpLink")
            .field("id", &self.entry.id)
            .field("local", &self.entry.id.local.address)
            .field("peer", &self.entry.id.peer)
            .finish()
    }
}

impl<C: MonotonicClock + 'static> Link for UdpLink<C> {
    type Local = UdpLocal;
    type Peer = SocketAddr;
    type Payload = BytesMut;
    type Instant = C::Instant;
    type RecvError = SocketFailedError;
    type Recv<'a>
        = impl Future<Output = Result<ReceivedDatagram<BytesMut, Self>, SocketFailedError>> + 'a
    where
        Self: 'a;
    type Ended = impl Future<Output = SocketFailedError>;
    type MaxDatagramSizeError = LinkEndedError;
    type SendError = SendDatagramError;
    type Send<'a> =
        impl Future<Output = Result<SendAcceptance<C::Instant>, SendDatagramError>> + 'a;
    type MaxDatagramSizeChanged = Pending<()>;

    fn id(&self) -> &LinkId<UdpLocal, SocketAddr> {
        &self.entry.id
    }

    fn may_mark_ecn(&self) -> bool {
        self.shared.may_mark_ecn.load(Ordering::Relaxed)
    }

    /// The interface MTU of the binding's configuration less the IP and UDP
    /// headers, or [`MIN_DATAGRAM_SIZE`] when the socket could not be kept
    /// from fragmenting this peer's IP version.
    fn max_datagram_size(&self) -> Result<usize, LinkEndedError> {
        if let Some(end) = self.shared.end.get() {
            return Err(LinkEndedError {
                source: end.clone(),
            });
        }
        let mtu = self.shared.config.interface_mtu;
        let (headers, no_fragment) = match self.entry.id.peer.ip() {
            IpAddr::V4(_) => (28, self.shared.no_fragment_v4),
            IpAddr::V6(_) => (48, self.shared.no_fragment_v6),
        };
        Ok(if no_fragment {
            mtu.saturating_sub(headers)
        } else {
            MIN_DATAGRAM_SIZE
        })
    }

    fn recv(&self) -> Self::Recv<'_> {
        self.receive()
    }

    fn ended(&self) -> Self::Ended {
        let shared = Arc::clone(&self.shared);
        async move {
            loop {
                let ended = Arc::clone(&shared.ended).notified_owned();
                if let Some(end) = shared.end.get() {
                    return end.clone();
                }
                ended.await;
            }
        }
    }

    fn send<'a>(&self, batch: &'a [OutgoingDatagram]) -> Self::Send<'a> {
        Self::send_batch(Arc::clone(&self.shared), Arc::clone(&self.entry), batch)
    }

    /// Never ready: the limit comes from the configuration and does not
    /// change.
    fn max_datagram_size_changed(&self) -> Pending<()> {
        core::future::pending()
    }

    fn datagram_size_conclusion(&self) -> usize {
        self.entry.conclusion.load(Ordering::Relaxed)
    }

    fn record_datagram_size_confirmed(&self, size: usize) {
        self.entry.conclusion.fetch_max(size, Ordering::Relaxed);
    }

    fn record_datagram_size_lowered(&self, size: usize) {
        self.entry
            .conclusion
            .fetch_min(size.max(MIN_DATAGRAM_SIZE), Ordering::Relaxed);
    }
}
