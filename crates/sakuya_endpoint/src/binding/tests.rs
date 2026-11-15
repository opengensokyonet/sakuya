use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    task::Wake,
};

use frunk_core::{Coprod, coproduct::Coproduct};
use futures_util::task::AtomicWaker;
use sakuya_link::{Link, LinkBinding};

use super::{
    BindingDriver, BindingShared, EndpointDatagram,
    driving::{AcceptMode, Accepting, ConnectOnly, LoopEnd, RouteDatagram, StopSignal},
};
use crate::memory_link::{DialingBinding, MemoryBinding, MemoryLink, MemoryPeer};

type Sum = Coprod![MemoryLink];

/// Routing that keeps every datagram until the test takes them.
#[derive(Clone, Default)]
struct Kept(Arc<Mutex<Vec<EndpointDatagram<Sum>>>>);

impl Kept {
    fn take(&self) -> Vec<EndpointDatagram<Sum>> {
        core::mem::take(&mut *self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }

    fn len(&self) -> usize {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).len()
    }
}

impl RouteDatagram<EndpointDatagram<Sum>> for Kept {
    fn route(&self, datagram: EndpointDatagram<Sum>) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(datagram);
    }
}

/// A stop signal the test raises.
#[derive(Clone, Default)]
struct Stop(Arc<(AtomicBool, AtomicWaker)>);

impl Stop {
    fn raise(&self) {
        self.0.0.store(true, Ordering::SeqCst);
        self.0.1.wake();
    }
}

impl StopSignal for Stop {
    fn poll_stop(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.0.1.register(cx.waker());
        if self.0.0.load(Ordering::SeqCst) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

/// A waker that records that it was woken.
#[derive(Default)]
struct Flag(AtomicBool);

impl Wake for Flag {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// A driver under test, with what it was composed with.
struct Harness<B: LinkBinding<Link = MemoryLink>, A: AcceptMode<B, Sum, Kept>> {
    shared: Arc<BindingShared<B, Sum>>,
    driver: BindingDriver<B, Sum, Kept, Stop, A>,
    routed: Kept,
    stop: Stop,
    woken: Arc<Flag>,
}

impl<B: LinkBinding<Link = MemoryLink>, A: AcceptMode<B, Sum, Kept>> Harness<B, A> {
    fn new(binding: B) -> Self {
        let shared = Arc::new(BindingShared::new(binding));
        let routed = Kept::default();
        let stop = Stop::default();
        let driver = BindingDriver::new(Arc::clone(&shared), routed.clone(), stop.clone());
        Self {
            shared,
            driver,
            routed,
            stop,
            woken: Arc::default(),
        }
    }

    fn poll(&mut self) -> Poll<()> {
        self.woken.0.store(false, Ordering::SeqCst);
        let waker = Waker::from(Arc::clone(&self.woken));
        Pin::new(&mut self.driver).poll(&mut Context::from_waker(&waker))
    }

    /// Whether the driver was woken since it was last polled.
    fn woken(&self) -> bool {
        self.woken.0.load(Ordering::SeqCst)
    }

    /// The accept loop, when it runs, and the receive loops.
    fn loops(&self) -> usize {
        self.driver.loops.len()
    }
}

fn peer() -> SocketAddr {
    SocketAddr::from(([192, 0, 2, 7], 50000))
}

/// A link of `binding` with a datagram waiting in it.
fn link_of(binding: &impl LinkBinding) -> (MemoryLink, MemoryPeer) {
    let (link, far) = MemoryLink::new(4433, peer(), binding.id());
    far.send(b"first");
    (link, far)
}

#[test]
fn an_accepted_link_is_received_on_and_its_datagram_arrives_on_the_endpoint_link() {
    let binding = MemoryBinding::new();
    let (link, far) = link_of(&binding);
    let member_id = link.id().clone();
    binding.offer(link);
    let mut harness = Harness::<_, Accepting>::new(binding.clone());

    assert_eq!(harness.poll(), Poll::Pending);
    assert_eq!(harness.loops(), 2, "the accept loop and one receive loop");
    assert_eq!(harness.shared.dispatched_count(), 1);

    let routed = harness.routed.take();
    let [datagram] = routed.as_slice() else {
        panic!("one datagram is routed, not {}", routed.len());
    };
    assert_eq!(datagram.payload(), b"first");
    let id = datagram.link().id();
    assert_eq!(*id, member_id.map(Coproduct::Inl, Coproduct::Inl));
    assert_eq!(id.local, Coproduct::Inl(4433));
    assert_eq!(id.peer, Coproduct::Inl(peer()));
    assert_eq!(&id.binding, binding.id());
    assert_eq!(
        datagram.link().users(),
        3,
        "the datagram's, the receive loop's and the dispatched one"
    );
    drop(far);
}

#[test]
fn accept_and_connect_giving_one_link_share_its_loop_and_count() {
    let binding = MemoryBinding::new();
    let (link, _far) = link_of(&binding);
    binding.offer(link.clone());
    let mut harness = Harness::<_, Accepting>::new(binding);
    assert_eq!(harness.poll(), Poll::Pending);
    let routed = harness.routed.take();

    // A connect on the handle gives the same link.
    let connected = harness.shared.admit(link);
    assert_eq!(connected.id(), routed[0].link().id());
    assert_eq!(connected.users(), 4);
    assert_eq!(harness.poll(), Poll::Pending);
    assert_eq!(harness.loops(), 2, "no second receive loop");
    assert_eq!(harness.shared.dispatched_count(), 1);

    drop(routed);
    assert_eq!(connected.users(), 3);
    let found = harness
        .shared
        .dispatched_link(connected.id())
        .expect("the link is dispatched");
    assert_eq!(found.users(), 4);
}

#[test]
fn an_unused_link_stops_and_leaves_the_dispatched_set() {
    let binding = MemoryBinding::new();
    let (link, far) = link_of(&binding);
    binding.offer(link);
    let mut harness = Harness::<_, Accepting>::new(binding);
    assert_eq!(harness.poll(), Poll::Pending);
    assert_eq!(harness.routed.len(), 1);
    assert_eq!(far.link_clones(), 3);

    // Routing lets the datagram go: nobody holds the link any more.
    drop(harness.routed.take());
    assert!(harness.woken(), "the receive loop is woken");
    assert_eq!(harness.poll(), Poll::Pending);
    assert_eq!(harness.loops(), 1, "only the accept loop is left");
    assert_eq!(harness.shared.dispatched_count(), 0);
    assert_eq!(far.link_clones(), 0, "the link is closed");
}

#[test]
fn a_link_used_meanwhile_keeps_its_loop() {
    let binding = DialingBinding::new();
    let (link, far) = link_of(&binding);
    let mut harness = Harness::<_, ConnectOnly>::new(binding);

    // A connect admits the link; the receive loop has seen it unused, and
    // before the driver takes it out, another connect takes a clone.
    let connected = harness.shared.admit(link);
    let mut inbox = harness.shared.take_inbox();
    let looped = inbox.pop().expect("the link waits in the inbox");
    assert_eq!(looped.users(), 3);
    harness.driver.loop_ended(LoopEnd::Unused(looped));
    assert_eq!(harness.loops(), 1, "the receive loop starts again");
    assert_eq!(harness.shared.dispatched_count(), 1);

    assert_eq!(harness.poll(), Poll::Pending);
    assert_eq!(harness.routed.len(), 1);
    drop(harness.routed.take());
    assert_eq!(harness.poll(), Poll::Pending);
    assert_eq!(harness.loops(), 1, "the connected clone keeps the loop");

    drop(connected);
    assert!(harness.woken());
    assert_eq!(harness.poll(), Poll::Pending);
    assert_eq!(harness.loops(), 0);
    assert_eq!(harness.shared.dispatched_count(), 0);
    assert_eq!(far.link_clones(), 0);
}

#[test]
fn a_link_seen_unused_and_still_unused_is_taken_out() {
    let binding = DialingBinding::new();
    let (link, far) = link_of(&binding);
    let mut harness = Harness::<_, ConnectOnly>::new(binding);

    drop(harness.shared.admit(link));
    let looped = harness.shared.take_inbox().pop().expect("the link waits");
    assert_eq!(looped.users(), 2);
    harness.driver.loop_ended(LoopEnd::Unused(looped));
    assert_eq!(harness.loops(), 0);
    assert_eq!(harness.shared.dispatched_count(), 0);
    assert_eq!(far.link_clones(), 0);
}

#[test]
fn an_ended_link_leaves_the_dispatched_set_though_it_is_used() {
    let binding = MemoryBinding::new();
    let (link, far) = link_of(&binding);
    binding.offer(link);
    let mut harness = Harness::<_, Accepting>::new(binding);
    assert_eq!(harness.poll(), Poll::Pending);
    let routed = harness.routed.take();

    far.end();
    assert!(harness.woken());
    assert_eq!(harness.poll(), Poll::Pending);
    assert_eq!(harness.loops(), 1, "only the accept loop is left");
    assert_eq!(harness.shared.dispatched_count(), 0);
    assert_eq!(routed[0].link().users(), 1, "only the datagram's is left");
}

#[test]
fn receive_loops_go_on_after_accept_fails() {
    let binding = MemoryBinding::new();
    let (link, far) = link_of(&binding);
    binding.offer(link);
    binding.fail();
    let mut harness = Harness::<_, Accepting>::new(binding.clone());
    assert_eq!(harness.poll(), Poll::Pending);
    assert_eq!(binding.accepts(), 2, "one gave the link, one failed");
    assert_eq!(harness.loops(), 1, "only the receive loop is left");
    let mut kept = harness.routed.take();

    far.send(b"later");
    assert!(harness.woken());
    assert_eq!(harness.poll(), Poll::Pending);
    kept.extend(harness.routed.take());
    let payloads: Vec<&[u8]> = kept.iter().map(|d| d.payload().as_slice()).collect();
    assert_eq!(payloads, [b"first".as_slice(), b"later"]);
    assert_eq!(binding.accepts(), 2, "no accept after the failure");
}

#[test]
fn a_connect_only_driver_receives_on_admitted_links() {
    let binding = DialingBinding::new();
    let (link, _far) = link_of(&binding);
    let mut harness = Harness::<_, ConnectOnly>::new(binding);
    assert_eq!(harness.poll(), Poll::Pending);
    assert_eq!(harness.loops(), 0, "no accept loop");

    let connected = harness.shared.admit(link);
    assert!(harness.woken(), "admitting wakes the driver");
    assert_eq!(harness.poll(), Poll::Pending);
    assert_eq!(harness.loops(), 1);
    let routed = harness.routed.take();
    assert_eq!(routed.len(), 1);
    assert_eq!(routed[0].link().id(), connected.id());
}

#[test]
fn the_driver_ends_when_stopped_and_lets_its_links_go() {
    let binding = MemoryBinding::new();
    let (link, far) = link_of(&binding);
    binding.offer(link);
    let mut harness = Harness::<_, Accepting>::new(binding);
    assert_eq!(harness.poll(), Poll::Pending);
    let connected = harness
        .shared
        .dispatched_link(harness.routed.take()[0].link().id())
        .expect("the link is dispatched");
    assert_eq!(harness.poll(), Poll::Pending);
    assert_eq!(harness.loops(), 2, "the connected clone keeps the loop");

    harness.stop.raise();
    assert!(harness.woken());
    assert_eq!(harness.poll(), Poll::Ready(()));
    assert_eq!(harness.loops(), 0);
    assert_eq!(harness.shared.dispatched_count(), 0);
    assert_eq!(connected.users(), 1);
    drop(connected);
    assert_eq!(far.link_clones(), 0);
}

#[test]
fn dropping_the_driver_lets_its_links_go() {
    let binding = MemoryBinding::new();
    let (link, far) = link_of(&binding);
    binding.offer(link);
    let mut harness = Harness::<_, Accepting>::new(binding);
    assert_eq!(harness.poll(), Poll::Pending);
    drop(harness.routed.take());
    let Harness { shared, driver, .. } = harness;
    drop(driver);
    assert_eq!(shared.dispatched_count(), 0);
    assert_eq!(far.link_clones(), 0);
}

#[test]
fn a_link_that_always_has_a_datagram_lets_the_driver_yield() {
    let binding = MemoryBinding::new();
    let (link, far) = link_of(&binding);
    for _ in 0..4 * super::DATAGRAMS_PER_TURN {
        far.send(b"more");
    }
    binding.offer(link);
    let mut harness = Harness::<_, Accepting>::new(binding.clone());

    assert_eq!(harness.poll(), Poll::Pending);
    let first_poll = harness.routed.len();
    assert!(
        first_poll < 1 + 4 * super::DATAGRAMS_PER_TURN,
        "one poll routed all {first_poll} datagrams"
    );
    assert!(harness.woken(), "the driver is woken to route the rest");
    while harness.routed.len() < 1 + 4 * super::DATAGRAMS_PER_TURN {
        assert!(harness.woken(), "the driver is woken while datagrams wait");
        assert_eq!(harness.poll(), Poll::Pending);
    }
    drop(far);
}
