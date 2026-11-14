//! A link and a binding over in-memory queues, and generic code that
//! receives over them as a link's receiver does.

use core::{
    cell::RefCell,
    convert::Infallible,
    future::{Future, Pending},
    pin::{Pin, pin},
    task::{Context, Poll, Waker},
    time::Duration,
};
use std::{collections::VecDeque, rc::Rc};

use super::*;
use crate::{AcceptingLinkBinding, BindingId, LinkBinding};

/// What the link has: datagrams not yet received, and its end once it has
/// ended.
#[derive(Default)]
struct Queue {
    datagrams: VecDeque<Vec<u8>>,
    end: Option<&'static str>,
}

#[derive(Clone)]
struct QueueLink {
    id: LinkId<(), ()>,
    queue: Rc<RefCell<Queue>>,
}

/// A receive: it borrows the clone it came from.
struct QueueRecv<'a>(&'a QueueLink);

impl Future for QueueRecv<'_> {
    type Output = Result<ReceivedDatagram<Vec<u8>, QueueLink>, &'static str>;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        let mut queue = self.0.queue.borrow_mut();
        match (queue.datagrams.pop_front(), queue.end) {
            (Some(payload), _) => {
                let arrival = ArrivalFacts::new(self.0.clone(), Duration::ZERO, None);
                Poll::Ready(Ok(ReceivedDatagram::new(payload, arrival)))
            }
            (None, Some(end)) => Poll::Ready(Err(end)),
            (None, None) => Poll::Pending,
        }
    }
}

/// The end of a link: it holds a handle to the queue, not the link.
struct QueueEnded(Rc<RefCell<Queue>>);

impl Future for QueueEnded {
    type Output = &'static str;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<&'static str> {
        self.0.borrow().end.map_or(Poll::Pending, Poll::Ready)
    }
}

impl Link for QueueLink {
    type Local = ();
    type Peer = ();
    type Payload = Vec<u8>;
    type Instant = Duration;
    type RecvError = &'static str;
    type Recv<'a> = QueueRecv<'a>;
    type Ended = QueueEnded;
    type MaxDatagramSizeError = Infallible;
    type SendError = Infallible;
    type Send<'a> = Pending<Result<SendAcceptance<Duration>, Infallible>>;
    type MaxDatagramSizeChanged = Pending<()>;

    fn id(&self) -> &LinkId<(), ()> {
        &self.id
    }

    fn may_mark_ecn(&self) -> bool {
        false
    }

    fn max_datagram_size(&self) -> Result<usize, Infallible> {
        Ok(MIN_DATAGRAM_SIZE)
    }

    fn recv(&self) -> QueueRecv<'_> {
        QueueRecv(self)
    }

    fn ended(&self) -> QueueEnded {
        QueueEnded(Rc::clone(&self.queue))
    }

    fn send<'a>(&self, _: &'a [OutgoingDatagram]) -> Self::Send<'a> {
        core::future::pending()
    }

    fn max_datagram_size_changed(&self) -> Pending<()> {
        core::future::pending()
    }
}

/// A binding that gives one link, then waits forever.
struct OneLinkBinding {
    id: BindingId,
    link: RefCell<Option<QueueLink>>,
}

impl LinkBinding for OneLinkBinding {
    type Link = QueueLink;

    fn id(&self) -> &BindingId {
        &self.id
    }
}

impl AcceptingLinkBinding for OneLinkBinding {
    type AcceptError = Infallible;
    type Accept<'a> = core::future::Ready<Result<QueueLink, Infallible>>;

    fn accept(&self) -> Self::Accept<'_> {
        let link = self.link.borrow_mut().take().expect("a test accepts once");
        core::future::ready(Ok(link))
    }
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

/// Receives until the link ends, as a link's receiver does: what it
/// received and why the link ended.
fn receive_all<L: Link>(link: &L) -> (Vec<L::Payload>, L::RecvError) {
    let mut received = Vec::new();
    loop {
        match poll_once(pin!(link.recv())) {
            Poll::Ready(Ok(datagram)) => {
                assert_eq!(datagram.link().id(), link.id());
                received.push(datagram.into_parts().0);
            }
            Poll::Ready(Err(end)) => return (received, end),
            Poll::Pending => panic!("a test's link has datagrams or has ended"),
        }
    }
}

#[test]
fn a_link_from_a_binding_delivers_until_it_ends_and_ended_gives_the_same_reason() {
    let binding_id = BindingId::new();
    let queue = Rc::new(RefCell::new(Queue::default()));
    let link = QueueLink {
        id: LinkId::new::<QueueLink>((), (), &binding_id),
        queue: Rc::clone(&queue),
    };
    let binding = OneLinkBinding {
        id: binding_id,
        link: RefCell::new(Some(link)),
    };
    let Poll::Ready(Ok(link)) = poll_once(pin!(binding.accept())) else {
        panic!("the binding gives its link");
    };
    assert_eq!(&link.id().binding, binding.id());

    // Ended borrows nothing: it is kept while the link's clone is received on.
    let mut ended = pin!(link.ended());
    assert_eq!(poll_once(ended.as_mut()), Poll::Pending);
    queue.borrow_mut().datagrams.extend([vec![1], vec![]]);
    queue.borrow_mut().end = Some("socket failed");

    let (received, end) = receive_all(&link.clone());
    assert_eq!(received, [vec![1], vec![]]);
    assert_eq!(poll_once(ended), Poll::Ready(end));
    assert_eq!(
        poll_once(pin!(link.recv())).map(|r| r.err()),
        Poll::Ready(Some(end))
    );
}
