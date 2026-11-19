//! A network in memory between a server's address and its clients', with
//! impairments that follow from a seed.
//!
//! A [`MemoryNetwork`] has bindings ([`MemoryBinding`]), one for each
//! address, that accept links as datagrams come from new peers and connect
//! links to given peers, as a UDP socket does. Sending on a
//! [`MemoryLink`] hands each datagram to the network, which numbers it in
//! its direction, decides its fate ([`DirectionImpairments`]) and queues
//! it, maybe changed, maybe twice, on the link of the destination binding
//! to the sender's address, to be received once its delay has passed on the
//! network's clock. With tokio's time paused on a current-thread runtime, a
//! run with the same seed sends the same datagrams and meets the same
//! fates.
//!
//! The network can also change while it runs: the limit the links of one
//! address report ([`set_max_datagram_size`](MemoryNetwork::set_max_datagram_size)),
//! the largest datagram the path carries without saying so
//! ([`set_path_mtu`](MemoryNetwork::set_path_mtu)), the address a
//! client's datagrams come from, as a NAT that rebinds
//! ([`rebind`](MemoryNetwork::rebind)), and the address the datagrams sent
//! to one go to instead ([`redirect`](MemoryNetwork::redirect)). It keeps
//! the datagrams sent to each address ([`sent_to`](MemoryNetwork::sent_to)).
//!
//! The server's side is its IP address: the datagrams to any port of it go
//! towards the server, so that a server can have a preferred address on
//! another port. A binding connects only to a peer of its own IP version.
//!
//! Links never end or mark ECN. A link accepts the prefix of a batch
//! within its size limit and gives up a datagram over that limit.

mod impairment;
mod random;

use core::{
    convert::Infallible,
    future::{Future, Ready},
    net::SocketAddr,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc, Mutex, MutexGuard, PoisonError, Weak,
        atomic::{AtomicUsize, Ordering},
    },
};

use bytes::{Bytes, BytesMut};
use sakuya_clock::MonotonicClock;
use sakuya_link::{
    AcceptingLinkBinding, ArrivalFacts, BindingId, ConnectingLinkBinding, Link, LinkBinding,
    LinkId, MIN_DATAGRAM_SIZE, OutgoingDatagram, ReceivedDatagram, SendAcceptance,
};

pub use impairment::{
    Blackhole, DatagramFate, Direction, DirectionImpairments, DropCause, Impairments, Probability,
    RandomLoss, Reorder,
};
pub use random::SplitMix64;

use impairment::{DirectionCount, Verdict, decide};

/// The limit a link reports until it is set: Ethernet's 1500 bytes less
/// the IPv6 and UDP headers.
const DEFAULT_MAX_DATAGRAM_SIZE: usize = 1452;

/// How many links a binding holds that nobody accepted yet.
const ACCEPT_BACKLOG: usize = 16;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A network in memory; its clones share it.
pub struct MemoryNetwork<C: MonotonicClock + 'static> {
    shared: Arc<NetworkShared<C>>,
}

impl<C: MonotonicClock + 'static> Clone for MemoryNetwork<C> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

struct NetworkShared<C: MonotonicClock + 'static> {
    clock: C,
    seed: u64,
    server: SocketAddr,
    start: C::Instant,
    state: Mutex<NetworkState<C>>,
}

struct NetworkState<C: MonotonicClock + 'static> {
    impairments: Impairments,
    to_server: DirectionCount,
    to_client: DirectionCount,
    fates: Vec<(Direction, DatagramFate)>,
    bindings: HashMap<SocketAddr, Arc<BindingShared<C>>>,
    /// The address a client's datagrams come from instead of its binding's,
    /// by its binding's address.
    rebound_from: HashMap<SocketAddr, SocketAddr>,
    /// The binding a rebound address is delivered to, by that address.
    rebound_to: HashMap<SocketAddr, SocketAddr>,
    /// The address the datagrams sent to an address go to instead, by that
    /// address.
    redirected: HashMap<SocketAddr, SocketAddr>,
    /// The datagrams sent to each address, in order.
    sent_to: HashMap<SocketAddr, Vec<Bytes>>,
}

impl<C: MonotonicClock + 'static> MemoryNetwork<C> {
    /// A network whose server is at `server`, impaired as `impairments`
    /// says with fates that follow from `seed`; it starts now on `clock`.
    pub fn new(clock: C, seed: u64, server: SocketAddr, impairments: Impairments) -> Self {
        let start = clock.now();
        Self {
            shared: Arc::new(NetworkShared {
                clock,
                seed,
                server,
                start,
                state: Mutex::new(NetworkState {
                    impairments,
                    to_server: DirectionCount::default(),
                    to_client: DirectionCount::default(),
                    fates: Vec::new(),
                    bindings: HashMap::new(),
                    rebound_from: HashMap::new(),
                    rebound_to: HashMap::new(),
                    redirected: HashMap::new(),
                    sent_to: HashMap::new(),
                }),
            }),
        }
    }

    /// A binding at `local`, which accepts links from new peers and
    /// connects links to given ones.
    ///
    /// # Panics
    ///
    /// When a binding at `local` exists already.
    pub fn bind(&self, local: SocketAddr) -> MemoryBinding<C> {
        let shared = Arc::new(BindingShared {
            id: BindingId::new(),
            local,
            state: Mutex::new(BindingState {
                links: HashMap::new(),
                unaccepted: VecDeque::new(),
                acceptor: None,
                max_datagram_size: DEFAULT_MAX_DATAGRAM_SIZE,
            }),
        });
        let previous = lock(&self.shared.state)
            .bindings
            .insert(local, Arc::clone(&shared));
        assert!(previous.is_none(), "one binding at {local}");
        MemoryBinding {
            network: Arc::clone(&self.shared),
            shared,
        }
    }

    /// The links of the binding at `local` report `size` as their limit
    /// from now on, and each of their
    /// [`max_datagram_size_changed`](Link::max_datagram_size_changed) is
    /// ready.
    pub fn set_max_datagram_size(&self, local: SocketAddr, size: usize) {
        let binding = lock(&self.shared.state).bindings.get(&local).cloned();
        let Some(binding) = binding else { return };
        let links: Vec<_> = {
            let mut state = lock(&binding.state);
            state.max_datagram_size = size;
            state.links.values().filter_map(Weak::upgrade).collect()
        };
        for link in links {
            let wakers = {
                let mut state = lock(&link.state);
                state.max_datagram_size = size;
                state.generation += 1;
                core::mem::take(&mut state.limit_wakers)
            };
            wakers.into_iter().for_each(Waker::wake);
        }
    }

    /// The path of `direction` carries datagrams up to `mtu` bytes from now
    /// on, silently dropping larger ones; `None` carries any.
    pub fn set_path_mtu(&self, direction: Direction, mtu: Option<usize>) {
        lock(&self.shared.state)
            .impairments
            .of_mut(direction)
            .path_mtu = mtu;
    }

    /// The datagrams of the binding at `client` come from `to` from now on,
    /// and those to `to` go to it, as when a NAT rebinds; those to its own
    /// address, or to an address it had before, are dropped.
    pub fn rebind(&self, client: SocketAddr, to: SocketAddr) {
        let mut state = lock(&self.shared.state);
        if let Some(old) = state.rebound_from.insert(client, to) {
            state.rebound_to.remove(&old);
        }
        state.rebound_to.insert(to, client);
    }

    /// The datagrams sent to `to` go to `instead` from now on, until it is
    /// `None`; their fates and their counts are those of `to`.
    pub fn redirect(&self, to: SocketAddr, instead: Option<SocketAddr>) {
        let mut state = lock(&self.shared.state);
        match instead {
            Some(instead) => state.redirected.insert(to, instead),
            None => state.redirected.remove(&to),
        };
    }

    /// The datagrams sent to `to` so far, in the order they were sent, as
    /// they were sent, whatever became of them.
    pub fn sent_to(&self, to: SocketAddr) -> Vec<Bytes> {
        lock(&self.shared.state)
            .sent_to
            .get(&to)
            .cloned()
            .unwrap_or_default()
    }

    /// The fates of the datagrams of `direction` so far, in the order they
    /// came.
    pub fn fates(&self, direction: Direction) -> Vec<DatagramFate> {
        lock(&self.shared.state)
            .fates
            .iter()
            .filter(|(of, _)| *of == direction)
            .map(|(_, fate)| fate.clone())
            .collect()
    }

    /// The numbers of the datagrams of `direction` dropped so far.
    pub fn dropped(&self, direction: Direction) -> Vec<u64> {
        self.fates(direction)
            .into_iter()
            .filter(|fate| fate.dropped.is_some())
            .map(|fate| fate.number)
            .collect()
    }
}

impl<C: MonotonicClock + 'static> NetworkShared<C> {
    /// Takes `payload`, sent from `from` to `to`.
    fn transmit(self: &Arc<Self>, from: SocketAddr, to: SocketAddr, payload: &[u8]) {
        let now = self.clock.now();
        let mut guard = lock(&self.state);
        let source = guard.rebound_from.get(&from).copied().unwrap_or(from);
        let direction = if to.ip() == self.server.ip() {
            Direction::ToServer
        } else {
            Direction::ToClient
        };
        guard
            .sent_to
            .entry(to)
            .or_default()
            .push(Bytes::copy_from_slice(payload));
        let to = guard.redirected.get(&to).copied().unwrap_or(to);
        let since_start = now - self.start;
        let state = &mut *guard;
        let count = match direction {
            Direction::ToServer => &mut state.to_server,
            Direction::ToClient => &mut state.to_client,
        };
        let (verdict, mut fate) = decide(
            self.seed,
            direction,
            state.impairments.of(direction),
            count,
            payload.len(),
            since_start,
        );
        // a rebound client's own address and its earlier ones are gone
        let destination = match state.rebound_to.get(&to) {
            Some(&client) => Some(client),
            None if state.rebound_from.contains_key(&to) => None,
            None => Some(to),
        };
        let binding = destination.and_then(|at| state.bindings.get(&at).cloned());
        let delivery = match (verdict, binding) {
            (Verdict::Drop, _) => None,
            (Verdict::Deliver { .. }, None) => {
                fate.dropped = Some(DropCause::NoDestination);
                fate.corrupted = None;
                fate.duplicated = false;
                fate.reordered = false;
                None
            }
            (
                Verdict::Deliver {
                    delay,
                    corrupt,
                    duplicate,
                },
                Some(binding),
            ) => Some((binding, delay, corrupt, duplicate)),
        };
        let record = state.fates.len();
        state.fates.push((direction, fate));
        drop(guard);
        let Some((binding, delay, corrupt, duplicate)) = delivery else {
            return;
        };
        let mut bytes = BytesMut::from(payload);
        if let Some((offset, change)) = corrupt {
            bytes[offset] = bytes[offset].wrapping_add(change);
        }
        let at = now + delay;
        let copies = if duplicate { 2 } else { 1 };
        if !binding.deliver(self, source, bytes, at, copies) {
            let mut state = lock(&self.state);
            let fate = &mut state.fates[record].1;
            fate.dropped = Some(DropCause::AcceptBacklog);
        }
    }
}

/// A binding of a [`MemoryNetwork`] at one address; its clones share it.
pub struct MemoryBinding<C: MonotonicClock + 'static> {
    network: Arc<NetworkShared<C>>,
    shared: Arc<BindingShared<C>>,
}

impl<C: MonotonicClock + 'static> Clone for MemoryBinding<C> {
    fn clone(&self) -> Self {
        Self {
            network: Arc::clone(&self.network),
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<C: MonotonicClock + 'static> MemoryBinding<C> {
    /// The address of the binding.
    pub fn local_address(&self) -> SocketAddr {
        self.shared.local
    }
}

struct BindingShared<C: MonotonicClock + 'static> {
    id: BindingId,
    local: SocketAddr,
    state: Mutex<BindingState<C>>,
}

struct BindingState<C: MonotonicClock + 'static> {
    /// The live links, by their peers.
    links: HashMap<SocketAddr, Weak<LinkShared<C>>>,
    unaccepted: VecDeque<MemoryLink<C>>,
    acceptor: Option<Waker>,
    max_datagram_size: usize,
}

impl<C: MonotonicClock + 'static> BindingShared<C> {
    /// The live link to `peer`, made if there is none.
    fn link_to(
        self: &Arc<Self>,
        network: &Arc<NetworkShared<C>>,
        state: &mut BindingState<C>,
        peer: SocketAddr,
    ) -> MemoryLink<C> {
        if let Some(shared) = state.links.get(&peer).and_then(Weak::upgrade) {
            return MemoryLink {
                network: Arc::clone(network),
                shared,
            };
        }
        let shared = Arc::new(LinkShared {
            id: LinkId::new::<MemoryLink<C>>(self.local, peer, &self.id),
            local: self.local,
            conclusion: AtomicUsize::new(MIN_DATAGRAM_SIZE),
            state: Mutex::new(LinkState {
                queue: VecDeque::new(),
                receiver: None,
                max_datagram_size: state.max_datagram_size,
                generation: 0,
                limit_wakers: Vec::new(),
            }),
        });
        state.links.insert(peer, Arc::downgrade(&shared));
        MemoryLink {
            network: Arc::clone(network),
            shared,
        }
    }

    /// Queues `copies` of `payload` from `peer`, to be received at `at`;
    /// false when the binding holds too many links not yet accepted to take
    /// a new one.
    fn deliver(
        self: &Arc<Self>,
        network: &Arc<NetworkShared<C>>,
        peer: SocketAddr,
        payload: BytesMut,
        at: C::Instant,
        copies: usize,
    ) -> bool {
        let mut state = lock(&self.state);
        let existing = state.links.get(&peer).and_then(Weak::upgrade);
        let (link, acceptor) = match existing {
            Some(link) => (link, None),
            None => {
                if state.unaccepted.len() >= ACCEPT_BACKLOG {
                    return false;
                }
                let link = self.link_to(network, &mut state, peer);
                let shared = Arc::clone(&link.shared);
                state.unaccepted.push_back(link);
                (shared, state.acceptor.take())
            }
        };
        drop(state);
        let receiver = {
            let mut link_state = lock(&link.state);
            for _ in 0..copies {
                // after every datagram due no later, so that equal delays
                // keep their order
                let position = link_state.queue.partition_point(|(due, _)| *due <= at);
                link_state.queue.insert(position, (at, payload.clone()));
            }
            link_state.receiver.take()
        };
        receiver.into_iter().for_each(Waker::wake);
        acceptor.into_iter().for_each(Waker::wake);
        true
    }
}

impl<C: MonotonicClock + 'static> LinkBinding for MemoryBinding<C> {
    type Link = MemoryLink<C>;

    fn id(&self) -> &BindingId {
        &self.shared.id
    }

    /// The address of the binding, which every link it gives has as its
    /// local end.
    fn local(&self) -> &SocketAddr {
        &self.shared.local
    }
}

impl<C: MonotonicClock + 'static> AcceptingLinkBinding for MemoryBinding<C> {
    type AcceptError = Infallible;
    type Accept<'a>
        = MemoryAccept<'a, C>
    where
        Self: 'a;

    fn accept(&self) -> MemoryAccept<'_, C> {
        MemoryAccept { binding: self }
    }
}

/// The future of [`MemoryBinding::accept`].
pub struct MemoryAccept<'a, C: MonotonicClock + 'static> {
    binding: &'a MemoryBinding<C>,
}

impl<C: MonotonicClock + 'static> Future for MemoryAccept<'_, C> {
    type Output = Result<MemoryLink<C>, Infallible>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = lock(&self.binding.shared.state);
        match state.unaccepted.pop_front() {
            Some(link) => Poll::Ready(Ok(link)),
            None => {
                state.acceptor = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

impl<C: MonotonicClock + 'static> ConnectingLinkBinding for MemoryBinding<C> {
    type Remote = SocketAddr;
    type ConnectError = UnreachablePeerError;
    type Connect<'a>
        = Ready<Result<MemoryLink<C>, UnreachablePeerError>>
    where
        Self: 'a;

    /// The link to `remote`, ready at once; none to a peer of the other IP
    /// version, which a binding at an address of one does not reach.
    fn connect(&self, remote: SocketAddr) -> Self::Connect<'_> {
        if remote.is_ipv4() != self.shared.local.is_ipv4() {
            return core::future::ready(Err(UnreachablePeerError { peer: remote }));
        }
        let mut state = lock(&self.shared.state);
        let link = self.shared.link_to(&self.network, &mut state, remote);
        core::future::ready(Ok(link))
    }
}

/// A [`MemoryBinding`] does not reach the peer: it is of the other IP
/// version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnreachablePeerError {
    /// The peer.
    pub peer: SocketAddr,
}

impl core::fmt::Display for UnreachablePeerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "the binding cannot reach {}", self.peer)
    }
}

impl std::error::Error for UnreachablePeerError {}

/// A link of a [`MemoryNetwork`] between a binding's address and a peer's.
pub struct MemoryLink<C: MonotonicClock + 'static> {
    network: Arc<NetworkShared<C>>,
    shared: Arc<LinkShared<C>>,
}

impl<C: MonotonicClock + 'static> Clone for MemoryLink<C> {
    fn clone(&self) -> Self {
        Self {
            network: Arc::clone(&self.network),
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<C: MonotonicClock + 'static> core::fmt::Debug for MemoryLink<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("MemoryLink").field(&self.shared.id).finish()
    }
}

struct LinkShared<C: MonotonicClock + 'static> {
    id: LinkId<SocketAddr, SocketAddr>,
    local: SocketAddr,
    conclusion: AtomicUsize,
    state: Mutex<LinkState<C>>,
}

struct LinkState<C: MonotonicClock + 'static> {
    /// The datagrams that arrived or are on their way, with when each is
    /// due, in that order.
    queue: VecDeque<(C::Instant, BytesMut)>,
    receiver: Option<Waker>,
    max_datagram_size: usize,
    /// How many times the limit was set.
    generation: u64,
    limit_wakers: Vec<Waker>,
}

impl<C: MonotonicClock + 'static> Link for MemoryLink<C> {
    type Local = SocketAddr;
    type Peer = SocketAddr;
    type Payload = BytesMut;
    type Instant = C::Instant;
    type RecvError = Infallible;
    type Recv<'a>
        = MemoryRecv<'a, C>
    where
        Self: 'a;
    type Ended = core::future::Pending<Infallible>;
    type MaxDatagramSizeError = Infallible;
    type SendError = ();
    type Send<'a> = Ready<Result<SendAcceptance<C::Instant>, Self::SendError>>;
    type MaxDatagramSizeChanged = MemoryLimitChanged<C>;

    fn id(&self) -> &LinkId<SocketAddr, SocketAddr> {
        &self.shared.id
    }

    fn may_mark_ecn(&self) -> bool {
        false
    }

    fn max_datagram_size(&self) -> Result<usize, Infallible> {
        Ok(lock(&self.shared.state).max_datagram_size)
    }

    fn recv(&self) -> MemoryRecv<'_, C> {
        MemoryRecv {
            link: self,
            sleep: None,
        }
    }

    fn ended(&self) -> Self::Ended {
        core::future::pending()
    }

    fn send<'a>(&self, batch: &'a [OutgoingDatagram]) -> Self::Send<'a> {
        let peer = self.shared.id.peer;
        let limit = lock(&self.shared.state).max_datagram_size;
        let accepted = batch.iter().take_while(|d| d.payload.len() <= limit);
        let mut count = 0;
        for datagram in accepted {
            count += 1;
            self.network
                .transmit(self.shared.local, peer, &datagram.payload);
        }
        let Some(count) = NonZeroUsize::new(count) else {
            return core::future::ready(Err(()));
        };
        core::future::ready(Ok(SendAcceptance {
            count,
            at: self.network.clock.now(),
        }))
    }

    fn max_datagram_size_changed(&self) -> MemoryLimitChanged<C> {
        MemoryLimitChanged {
            generation: lock(&self.shared.state).generation,
            link: Arc::clone(&self.shared),
        }
    }

    fn datagram_size_conclusion(&self) -> usize {
        self.shared.conclusion.load(Ordering::Relaxed)
    }

    fn record_datagram_size_confirmed(&self, size: usize) {
        self.shared.conclusion.fetch_max(size, Ordering::Relaxed);
    }

    fn record_datagram_size_lowered(&self, size: usize) {
        self.shared
            .conclusion
            .fetch_min(size.max(MIN_DATAGRAM_SIZE), Ordering::Relaxed);
    }
}

/// The future of [`MemoryLink::recv`]: ready with the first datagram due,
/// sleeping on the network's clock until the first one on its way is.
pub struct MemoryRecv<'a, C: MonotonicClock + 'static> {
    link: &'a MemoryLink<C>,
    sleep: Option<DueSleep<C>>,
}

/// A sleep until the instant it holds.
type DueSleep<C> = (
    <C as MonotonicClock>::Instant,
    Pin<Box<<C as MonotonicClock>::Sleep>>,
);

// nothing of it is pinned in place: the sleep is boxed
impl<C: MonotonicClock + 'static> Unpin for MemoryRecv<'_, C> {}

impl<C: MonotonicClock + 'static> Future for MemoryRecv<'_, C> {
    type Output = Result<ReceivedDatagram<BytesMut, MemoryLink<C>>, Infallible>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        loop {
            let now = this.link.network.clock.now();
            let next = {
                let mut state = lock(&this.link.shared.state);
                let front = state.queue.front().map(|(due, _)| *due);
                if front.is_some_and(|due| due <= now) {
                    // invariant: the front was just looked at
                    let (_, payload) = state.queue.pop_front().expect("a front");
                    return Poll::Ready(Ok(ReceivedDatagram::new(
                        payload,
                        ArrivalFacts::new(this.link.clone(), now, None),
                    )));
                }
                state.receiver = Some(cx.waker().clone());
                front
            };
            let Some(due) = next else {
                this.sleep = None;
                return Poll::Pending;
            };
            if this.sleep.as_ref().is_none_or(|(at, _)| *at != due) {
                this.sleep = Some((due, Box::pin(this.link.network.clock.sleep_until(due))));
            }
            // invariant: set just above
            let (_, sleep) = this.sleep.as_mut().expect("a sleep");
            if sleep.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            this.sleep = None;
        }
    }
}

/// The future of [`MemoryLink::max_datagram_size_changed`].
pub struct MemoryLimitChanged<C: MonotonicClock + 'static> {
    link: Arc<LinkShared<C>>,
    generation: u64,
}

impl<C: MonotonicClock + 'static> Future for MemoryLimitChanged<C> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut state = lock(&self.link.state);
        if state.generation != self.generation {
            return Poll::Ready(());
        }
        // a future polled again while waiting keeps one waker
        if !state
            .limit_wakers
            .iter()
            .any(|waker| waker.will_wake(cx.waker()))
        {
            state.limit_wakers.push(cx.waker().clone());
        }
        Poll::Pending
    }
}
