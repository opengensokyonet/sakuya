//! The binding driver: the reception on one link binding.
//!
//! Each link binding of an endpoint has one [`BindingDriver`], a future the
//! host spawns. It runs the binding's accept loop, when the binding takes new
//! links, and one receive loop for each link of the binding, which is that
//! link's datagram dispatcher: it receives on the link and hands each
//! datagram to routing.
//!
//! New links come from two places that run on different tasks: the accept
//! loop in the driver, and connects made through the binding's handle on the
//! application's tasks. Both admit a link the same way: under the lock of the
//! set of dispatched links, the link is looked up by its [`LinkId`]; a link
//! already dispatched is shared, and a new one is made into a link core, put
//! in the set and in an inbox, and the driver is woken to start its receive
//! loop. So each link has one receive loop, and one count of its uses,
//! however many times the binding gives it.
//!
//! The uses of a link are its [`EndpointLink`]s: the ones connections and
//! incoming and outgoing connections hold, and the one each received
//! datagram carries. The set and the receive loop hold the core, which is
//! not a use. A receive loop ends when its link ends, or when no use of the
//! link is left; a link the binding gave by accepting is kept until it
//! received its first datagram or ended, one of which its transport makes
//! happen in a finite time. The driver then takes the link out of the dispatched set, checking
//! the count again under the lock: if somebody took a use of the link in the
//! meantime, its receive loop starts again.

use core::{
    fmt,
    future::{Future, poll_fn},
    pin::{Pin, pin},
    task::{Context, Poll},
};
use std::sync::Arc;

use futures_util::{
    StreamExt,
    future::{Either, select},
    stream::FuturesUnordered,
};
use sakuya_link::{AcceptingLinkBinding, LinkBinding, LinkId, ReceivedDatagram};

use self::driving::{AcceptMode, FirstDatagram, LoopEnd, RouteDatagram, StopSignal};
use self::shared::{Admitted, BindingShared, NewLink};
use crate::link::{EndpointLink, LinkCore, sum::LinkSum};

pub(crate) mod shared;

pub use self::driving::{Accepting, ConnectOnly};

/// The identity of a link of an endpoint whose links are the sum `M`.
type EndpointLinkId<M> = LinkId<<M as LinkSum>::Local, <M as LinkSum>::Peer>;

/// A datagram received on a link of an endpoint whose links are the sum
/// `M`.
type EndpointDatagram<M> = ReceivedDatagram<<M as LinkSum>::Payload, EndpointLink<M>>;

/// The driver of one link binding: its accept loop and the receive loop of
/// each of its links.
///
/// It is a future the host spawns. Each receive loop is the datagram
/// dispatcher of its link: it receives on the link and hands each datagram,
/// which arrives on the endpoint's link, to routing. A receive loop ends when
/// its link ends, or when no use of the link is left, though not before a
/// link the binding gave by accepting received its first datagram; the
/// endpoint then drops its core, and the transport closes the link once every
/// clone of it is gone.
///
/// The driver of a binding that takes new links runs its accept loop until
/// the binding gives no more: its links keep receiving after that. The driver
/// of a binding added only to connect does not accept, and its binding need
/// not be able to.
///
/// The driver ends when the endpoint has been closed and no registration is
/// left in its routing domain, that is when every connection is over. Its
/// links' receive loops end with it, and dropping it before then stops them
/// as well.
#[must_use = "a binding driver receives nothing unless it is polled"]
pub struct BindingDriver<B, M, R, S, A>
where
    B: LinkBinding,
    M: LinkSum,
    A: AcceptMode<B, M, R>,
{
    shared: Arc<BindingShared<B, M>>,
    route: R,
    stop: S,
    /// The accept loop, if it runs, and the receive loops.
    loops: FuturesUnordered<A::Loop>,
}

impl<B, M, R, S, A> BindingDriver<B, M, R, S, A>
where
    B: LinkBinding,
    M: LinkSum,
    R: RouteDatagram<EndpointDatagram<M>> + Clone,
    A: AcceptMode<B, M, R>,
{
    /// The driver of the binding of `shared`, which hands the datagrams it
    /// receives to `route` and ends on `stop`; it runs the binding's accept
    /// loop when `A` is [`Accepting`](driving::Accepting), and not when it
    /// is [`ConnectOnly`](driving::ConnectOnly).
    pub(crate) fn new(shared: Arc<BindingShared<B, M>>, route: R, stop: S) -> Self {
        let loops = FuturesUnordered::new();
        if let Some(accept) = A::accept_loop(Arc::clone(&shared)) {
            loops.push(accept);
        }
        Self {
            shared,
            route,
            stop,
            loops,
        }
    }

    /// Acts on the end of one loop.
    fn loop_ended(&mut self, end: LoopEnd<M>) {
        match end {
            LoopEnd::AcceptEnded => {}
            LoopEnd::LinkEnded(link) => self.shared.release_ended(link.id()),
            LoopEnd::Unused(link) => {
                if let Some(link) = self.shared.release_unused(link) {
                    self.loops.push(A::receive_loop(
                        link,
                        self.route.clone(),
                        FirstDatagram::Received,
                    ));
                }
            }
        }
    }
}

impl<B, M, R, S, A> Future for BindingDriver<B, M, R, S, A>
where
    B: LinkBinding,
    M: LinkSum,
    R: RouteDatagram<EndpointDatagram<M>> + Clone + Unpin,
    S: StopSignal + Unpin,
    A: AcceptMode<B, M, R>,
{
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if this.stop.poll_stop(cx).is_ready() {
            this.loops.clear();
            this.shared.release_all();
            return Poll::Ready(());
        }
        this.shared.register_driver(cx.waker());
        loop {
            for NewLink { core, admitted } in this.shared.take_inbox() {
                let first = match admitted {
                    Admitted::Accepted => FirstDatagram::Awaited,
                    Admitted::Connected => FirstDatagram::Received,
                };
                this.loops
                    .push(A::receive_loop(core, this.route.clone(), first));
            }
            match this.loops.poll_next_unpin(cx) {
                Poll::Ready(Some(end)) => this.loop_ended(end),
                // The accept loop of this very poll may have admitted links.
                Poll::Ready(None) | Poll::Pending => {
                    if this.shared.inbox_is_empty() {
                        return Poll::Pending;
                    }
                }
            }
        }
    }
}

impl<B, M, R, S, A> Drop for BindingDriver<B, M, R, S, A>
where
    B: LinkBinding,
    M: LinkSum,
    A: AcceptMode<B, M, R>,
{
    fn drop(&mut self) {
        self.loops.clear();
        self.shared.release_all();
    }
}

impl<B, M, R, S, A> fmt::Debug for BindingDriver<B, M, R, S, A>
where
    B: LinkBinding,
    M: LinkSum,
    A: AcceptMode<B, M, R>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BindingDriver")
            .field("shared", &self.shared)
            .field("loops", &self.loops.len())
            .finish_non_exhaustive()
    }
}

/// The accept loop: admits each link the binding gives, until it gives no
/// more.
async fn accept_loop<B, M>(shared: Arc<BindingShared<B, M>>) -> LoopEnd<M>
where
    B: AcceptingLinkBinding,
    M: LinkSum,
{
    while let Ok(member) = shared.binding().accept().await {
        shared.admit_accepted(member);
    }
    LoopEnd::AcceptEnded
}

/// The receive loop of `link`, its datagram dispatcher: receives on it and
/// hands each datagram to `route`, until the link ends or no use of it is
/// left, but not while its first datagram is `Awaited`.
async fn receive_loop<M, R>(link: LinkCore<M>, route: R, mut first: FirstDatagram) -> LoopEnd<M>
where
    M: LinkSum,
    R: RouteDatagram<EndpointDatagram<M>>,
{
    let mut routed = 0;
    loop {
        if routed == DATAGRAMS_PER_TURN {
            routed = 0;
            yield_once().await;
        }
        let woken = match first {
            // Nobody uses a link the binding gave by accepting until its
            // first datagram, which arrives unless the link ends first.
            FirstDatagram::Awaited => match link.recv().await {
                Ok(datagram) => Woken::Received(datagram),
                Err(_) => Woken::Ended,
            },
            // A receive comes first: a datagram ready is received before
            // the link is found unused.
            FirstDatagram::Received => match select(pin!(link.recv()), pin!(link.unused())).await {
                Either::Left((Ok(datagram), _)) => Woken::Received(datagram),
                Either::Left((Err(_), _)) => Woken::Ended,
                Either::Right(((), _)) => Woken::Unused,
            },
        };
        match woken {
            Woken::Received(datagram) => {
                first = FirstDatagram::Received;
                route.route(datagram);
                routed += 1;
            }
            Woken::Ended => return LoopEnd::LinkEnded(link),
            Woken::Unused => return LoopEnd::Unused(link),
        }
    }
}

/// How many datagrams a receive loop routes in a row before it lets the
/// other loops of its driver run: a link that always has a datagram ready
/// would otherwise keep the driver's task to itself.
const DATAGRAMS_PER_TURN: usize = 32;

/// Pending once, with the task woken, then ready.
async fn yield_once() {
    let mut yielded = false;
    poll_fn(|cx| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
}

/// What woke a receive loop.
enum Woken<D> {
    /// A datagram arrived.
    Received(D),
    /// The link has ended.
    Ended,
    /// No use of the link is left.
    Unused,
}

/// What a binding driver is composed with.
pub(crate) mod driving {
    use core::{
        future::Future,
        task::{Context, Poll},
    };
    use std::sync::Arc;

    use sakuya_link::{AcceptingLinkBinding, LinkBinding};

    use super::{BindingShared, EndpointDatagram, accept_loop, receive_loop};
    use crate::link::{LinkCore, sum::LinkSum};

    /// Whether a receive loop waits for its link's first datagram before it
    /// looks at the link's uses.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum FirstDatagram {
        /// The link came from accepting and has received nothing yet.
        Awaited,
        /// The link received a datagram, or came from connecting.
        Received,
    }

    /// How one loop of a binding driver ended.
    pub enum LoopEnd<M: LinkSum> {
        /// The binding gives no more new links.
        AcceptEnded,
        /// The link has ended.
        LinkEnded(LinkCore<M>),
        /// No use of the link was left.
        Unused(LinkCore<M>),
    }

    /// Where a binding driver hands the datagrams it receives.
    pub trait RouteDatagram<D> {
        /// Takes `datagram` over, for its first round of routing.
        fn route(&self, datagram: D);
    }

    /// When a binding driver ends.
    pub trait StopSignal {
        /// Ready when the driver ends; otherwise arranges for the task of
        /// `cx` to be woken when it may.
        fn poll_stop(&self, cx: &mut Context<'_>) -> Poll<()>;
    }

    /// Whether a binding driver runs the binding's accept loop: the type of
    /// its loops.
    pub trait AcceptMode<B: LinkBinding, M: LinkSum, R> {
        /// The future of one loop.
        type Loop: Future<Output = LoopEnd<M>>;

        /// The accept loop of the binding of `shared`, if the driver runs
        /// one.
        fn accept_loop(shared: Arc<BindingShared<B, M>>) -> Option<Self::Loop>;

        /// The receive loop of `link`, which waits for the link's first
        /// datagram when `first` is [`FirstDatagram::Awaited`].
        fn receive_loop(link: LinkCore<M>, route: R, first: FirstDatagram) -> Self::Loop;
    }

    /// The driver runs the binding's accept loop.
    #[derive(Debug)]
    pub enum Accepting {}

    /// The driver does not accept: the binding was added only to connect.
    #[derive(Debug)]
    pub enum ConnectOnly {}

    /// One loop of an accepting driver.
    enum AcceptingLoop<B: LinkBinding, M: LinkSum, R> {
        Accept(Arc<BindingShared<B, M>>),
        Receive(LinkCore<M>, R, FirstDatagram),
    }

    impl<B, M, R> AcceptMode<B, M, R> for Accepting
    where
        B: AcceptingLinkBinding,
        M: LinkSum,
        R: RouteDatagram<EndpointDatagram<M>>,
    {
        type Loop = impl Future<Output = LoopEnd<M>>;

        fn accept_loop(shared: Arc<BindingShared<B, M>>) -> Option<Self::Loop> {
            Some(run::<B, M, R>(AcceptingLoop::Accept(shared)))
        }

        fn receive_loop(link: LinkCore<M>, route: R, first: FirstDatagram) -> Self::Loop {
            run::<B, M, R>(AcceptingLoop::Receive(link, route, first))
        }
    }

    /// Runs one loop of an accepting driver.
    async fn run<B, M, R>(task: AcceptingLoop<B, M, R>) -> LoopEnd<M>
    where
        B: AcceptingLinkBinding,
        M: LinkSum,
        R: RouteDatagram<EndpointDatagram<M>>,
    {
        match task {
            AcceptingLoop::Accept(shared) => accept_loop(shared).await,
            AcceptingLoop::Receive(link, route, first) => receive_loop(link, route, first).await,
        }
    }

    impl<B, M, R> AcceptMode<B, M, R> for ConnectOnly
    where
        B: LinkBinding,
        M: LinkSum,
        R: RouteDatagram<EndpointDatagram<M>>,
    {
        type Loop = impl Future<Output = LoopEnd<M>>;

        fn accept_loop(_shared: Arc<BindingShared<B, M>>) -> Option<Self::Loop> {
            // None, of the type of the receive loop, which is this mode's
            // only loop.
            None::<(LinkCore<M>, R, FirstDatagram)>
                .map(|(link, route, first)| receive_loop(link, route, first))
        }

        fn receive_loop(link: LinkCore<M>, route: R, first: FirstDatagram) -> Self::Loop {
            receive_loop(link, route, first)
        }
    }
}

#[cfg(test)]
mod tests;
#[cfg(all(test, target_os = "linux"))]
mod udp_tests;
