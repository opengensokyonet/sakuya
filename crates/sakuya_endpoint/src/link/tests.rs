use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::Wake,
};

use frunk_core::{
    Coprod,
    coproduct::{CoprodInjector, Coproduct},
};
use sakuya_link::{BindingId, Link, LinkId};

use super::EndpointLink;
use crate::memory_link::MemoryLink;

struct First;
struct Second;

type Two = Coprod![MemoryLink<First>, MemoryLink<Second>];

/// The identity of a link of `Two`: both members have the same ends.
type TwoId = LinkId<Coprod![u16, u16], Coprod![SocketAddr, SocketAddr]>;

fn peer() -> SocketAddr {
    SocketAddr::from(([192, 0, 2, 7], 50000))
}

fn endpoint_link<L, I>(member: L) -> EndpointLink<Two>
where
    Two: CoprodInjector<L, I>,
{
    EndpointLink::from_member(Two::inject(member))
}

#[derive(Default)]
struct Flag(AtomicBool);

impl Wake for Flag {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

impl Flag {
    fn take(&self) -> bool {
        self.0.swap(false, Ordering::SeqCst)
    }
}

fn poll_once<F: Future>(future: core::pin::Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

#[test]
fn the_identity_is_the_members_with_its_ends_injected() {
    let binding = BindingId::new();
    let (member, _peer) = MemoryLink::<Second>::new(4433, peer(), &binding);
    let expected = member.id().clone();
    let link = endpoint_link(member);

    let id: &TwoId = link.id();
    let expected = expected.map(
        |local| Coproduct::Inr(Coproduct::Inl(local)),
        |peer| Coproduct::Inr(Coproduct::Inl(peer)),
    );
    assert_eq!(*id, expected);
    assert_eq!(id.local, Coproduct::Inr(Coproduct::Inl(4433)));
    assert_eq!(id.peer, Coproduct::Inr(Coproduct::Inl(peer())));
    assert_eq!(id.binding, binding);
    assert_eq!(*link.clone().id(), *id);
}

#[test]
fn two_links_with_the_same_ends_differ() {
    let binding = BindingId::new();
    let (first, _a) = MemoryLink::<First>::new(4433, peer(), &binding);
    let (second, _b) = MemoryLink::<First>::new(4433, peer(), &binding);
    assert_ne!(endpoint_link(first).id(), endpoint_link(second).id());
}

#[test]
fn a_datagram_arrives_on_a_clone_of_the_endpoint_link() {
    let (member, far) = MemoryLink::<Second>::new(4433, peer(), &BindingId::new());
    let link = endpoint_link(member);
    far.send(b"hello");

    let received = poll_once(pin!(link.recv()));
    let Poll::Ready(Ok(datagram)) = received else {
        panic!("a datagram is ready");
    };
    assert_eq!(datagram.payload(), b"hello");
    assert_eq!(datagram.link().id(), link.id());
    assert_eq!(link.users(), 2);
    drop(datagram);
    assert_eq!(link.users(), 1);
}

#[test]
fn the_end_of_a_member_is_injected() {
    let (member, far) = MemoryLink::<Second>::new(4433, peer(), &BindingId::new());
    let link = endpoint_link(member);
    far.end();

    let received = poll_once(pin!(link.recv()));
    assert!(matches!(
        received,
        Poll::Ready(Err(Coproduct::Inr(Coproduct::Inl(()))))
    ));
}

#[test]
fn the_facts_of_the_member_are_its_own() {
    let (member, _far) = MemoryLink::<First>::new(4433, peer(), &BindingId::new());
    let link = endpoint_link(member.clone());
    assert_eq!(link.max_datagram_size(), Ok(1452));
    assert!(!link.may_mark_ecn());
    link.record_datagram_size_confirmed(1400);
    assert_eq!(link.datagram_size_conclusion(), 1400);
    assert_eq!(member.datagram_size_conclusion(), 1400);
}

#[test]
fn clones_count_their_users_and_two_left_is_unused() {
    let (member, far) = MemoryLink::<First>::new(4433, peer(), &BindingId::new());
    let link = endpoint_link(member);
    let kept = link.clone();
    let user = link.clone();
    assert_eq!(link.users(), 3);
    assert_eq!(far.link_clones(), 3);

    let flag = Arc::new(Flag::default());
    let waker = Waker::from(Arc::clone(&flag));
    let mut cx = Context::from_waker(&waker);
    {
        let mut unused = pin!(link.unused());
        assert_eq!(unused.as_mut().poll(&mut cx), Poll::Pending);

        drop(user);
        assert!(flag.take(), "the last user woke the receive loop");
        assert_eq!(unused.as_mut().poll(&mut cx), Poll::Ready(()));
    }
    assert_eq!(kept.users(), 2);

    drop(kept);
    drop(link);
    assert_eq!(far.link_clones(), 0, "every clone of the member is gone");
}
