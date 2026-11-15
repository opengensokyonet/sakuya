//! The endpoint's link: the sum of the links of its bindings.
//!
//! An endpoint can have bindings of several transports, each with its own
//! link type. What it hands on, to routing and to connections, is one type
//! for all of them: an [`EndpointLink`], which holds one member link and
//! the member's [`LinkId`] with its two ends injected into the sums of the
//! members' ends. The binding and the identity of the member's `LinkId` are
//! kept, so an `EndpointLink` has the identity of the link it holds.
//!
//! The endpoint makes one `EndpointLink` for each `LinkId`, and every clone
//! of it shares one count of its users. When only the two clones the
//! endpoint itself keeps are left, the one its receiving holds and the one
//! in its set of dispatched links, nobody else can use the link any more,
//! and the endpoint lets it go.

use core::{
    fmt,
    future::{Future, poll_fn},
    task::Poll,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use futures_util::task::AtomicWaker;
use sakuya_link::{ArrivalFacts, Link, LinkId, OutgoingDatagram, ReceivedDatagram};

use self::sum::{Arrived, LinkSum};

/// The clones of an endpoint link that the endpoint keeps while it
/// receives on the link: the receive loop's and the dispatched set's.
pub(crate) const KEPT_BY_THE_ENDPOINT: usize = 2;

/// The link of an endpoint: one link of one of its bindings, as a value of
/// the sum of their link types.
///
/// `M` is the sum of the bindings' link types, a `Coproduct` that ends in
/// `CNil`, such as `Coprod![UdpLink<C>]` for an endpoint with UDP bindings
/// only; two bindings of the same type share one member of the sum. Its
/// [`Local`](Link::Local) and [`Peer`](Link::Peer) are the sums of the
/// members' ends, its errors and futures the sums of theirs, and its
/// [`Payload`](Link::Payload) and [`Instant`](Link::Instant) those of the
/// members, which must all have the same ones.
///
/// Its [`LinkId`] is the member's, with the two ends injected into the
/// sums: it keeps the member's binding and identity, so it equals the
/// identity of no other link. A datagram it receives arrives on a clone of
/// it, not on the member link.
///
/// The endpoint makes one `EndpointLink` per link, however many times a
/// binding gives that link, and all its clones share a count of their
/// users. Cloning one and dropping one add to and take from that count,
/// one atomic operation each. When no clone is left but the endpoint's
/// own, the endpoint stops receiving on the link and drops those too, and
/// the transport closes the link once every clone of the member is gone.
pub struct EndpointLink<M: LinkSum> {
    member: M,
    shared: Arc<Shared<M::Local, M::Peer>>,
}

/// What every clone of an endpoint link shares: its identity and the count
/// of its users.
struct Shared<Local, Peer> {
    id: LinkId<Local, Peer>,
    /// How many clones of the endpoint link exist.
    users: AtomicUsize,
    /// Woken when only the endpoint's own clones are left.
    unused: AtomicWaker,
}

impl<M: LinkSum> EndpointLink<M> {
    /// A new endpoint link, with a count of its own, of `member`: a link of
    /// one of the bindings, injected into the sum.
    pub(crate) fn from_member(member: M) -> Self {
        let id = member.injected_id();
        Self {
            member,
            shared: Arc::new(Shared {
                id,
                users: AtomicUsize::new(1),
                unused: AtomicWaker::new(),
            }),
        }
    }

    /// How many clones of this link exist, this one included.
    ///
    /// It is an observation: clones can be made or dropped right after it
    /// is read.
    pub(crate) fn users(&self) -> usize {
        self.shared.users.load(Ordering::Acquire)
    }

    /// Ready when at most the endpoint's own two clones of this link are
    /// left: the one this future borrows and the one in the dispatched set.
    ///
    /// Being unused is not final: the dispatched set can give out a clone
    /// again, which whoever acts on this future checks under its lock.
    pub(crate) fn unused(&self) -> impl Future<Output = ()> + '_ {
        poll_fn(|cx| {
            if self.users() <= KEPT_BY_THE_ENDPOINT {
                return Poll::Ready(());
            }
            self.shared.unused.register(cx.waker());
            if self.users() <= KEPT_BY_THE_ENDPOINT {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
    }
}

impl<M: LinkSum> Clone for EndpointLink<M> {
    fn clone(&self) -> Self {
        self.shared.users.fetch_add(1, Ordering::AcqRel);
        Self {
            member: self.member.clone(),
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<M: LinkSum> Drop for EndpointLink<M> {
    fn drop(&mut self) {
        if self.shared.users.fetch_sub(1, Ordering::AcqRel) == KEPT_BY_THE_ENDPOINT + 1 {
            self.shared.unused.wake();
        }
    }
}

impl<M: LinkSum> fmt::Debug for EndpointLink<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EndpointLink")
            .field("id", &self.shared.id)
            .finish_non_exhaustive()
    }
}

impl<M: LinkSum> Link for EndpointLink<M> {
    type Local = M::Local;
    type Peer = M::Peer;
    type Payload = M::Payload;
    type Instant = M::Instant;
    type RecvError = M::RecvError;
    type Recv<'a>
        = impl Future<Output = Result<ReceivedDatagram<M::Payload, Self>, M::RecvError>> + 'a
    where
        Self: 'a;
    type Ended = M::Ended;
    type MaxDatagramSizeError = M::MaxDatagramSizeError;
    type SendError = M::SendError;
    type Send<'a> = M::Send<'a>;
    type MaxDatagramSizeChanged = M::MaxDatagramSizeChanged;

    fn id(&self) -> &LinkId<M::Local, M::Peer> {
        &self.shared.id
    }

    fn may_mark_ecn(&self) -> bool {
        self.member.may_mark_ecn()
    }

    fn max_datagram_size(&self) -> Result<usize, M::MaxDatagramSizeError> {
        self.member.max_datagram_size()
    }

    fn recv(&self) -> Self::Recv<'_> {
        async move {
            let Arrived { payload, at, ecn } = self.member.recv().await?;
            Ok(ReceivedDatagram::new(
                payload,
                ArrivalFacts::new(self.clone(), at, ecn),
            ))
        }
    }

    fn ended(&self) -> M::Ended {
        self.member.ended()
    }

    fn send<'a>(&self, batch: &'a [OutgoingDatagram]) -> M::Send<'a> {
        self.member.send(batch)
    }

    fn max_datagram_size_changed(&self) -> M::MaxDatagramSizeChanged {
        self.member.max_datagram_size_changed()
    }

    fn datagram_size_conclusion(&self) -> usize {
        self.member.datagram_size_conclusion()
    }

    fn record_datagram_size_confirmed(&self, size: usize) {
        self.member.record_datagram_size_confirmed(size);
    }

    fn record_datagram_size_lowered(&self, size: usize) {
        self.member.record_datagram_size_lowered(size);
    }
}

/// The sums of link types an endpoint link can hold.
pub(crate) mod sum {
    use core::{future::Future, hash::Hash, ops::Add, time::Duration};

    use frunk_core::coproduct::{CNil, Coproduct};
    use sakuya_link::{EcnCodepoint, Link, LinkId, OutgoingDatagram, SendAcceptance};

    /// A received datagram without the link it arrived on, which the
    /// endpoint link puts back as a clone of itself.
    pub struct Arrived<Payload, Instant> {
        pub payload: Payload,
        pub at: Instant,
        pub ecn: Option<EcnCodepoint>,
    }

    impl<Payload, Instant> Arrived<Payload, Instant> {
        fn of<L: Link<Payload = Payload, Instant = Instant>>(
            datagram: sakuya_link::ReceivedDatagram<Payload, L>,
        ) -> Self {
            let (payload, arrival) = datagram.into_parts();
            Self {
                payload,
                at: arrival.at(),
                ecn: arrival.ecn(),
            }
        }
    }

    /// A sum of link types, a `Coproduct` of links that ends in `CNil`:
    /// what [`Link`] asks of a link, with each type the sum of the members'
    /// types, or, for the payload and the instant, the members' common one.
    pub trait LinkSum: Clone {
        /// The sum of the members' local ends.
        type Local: Clone + Eq + Hash;
        /// The sum of the members' peers.
        type Peer: Clone + Eq + Hash;
        /// The members' payload.
        type Payload;
        /// The members' instant.
        type Instant: Ord + Copy + Add<Duration, Output = Self::Instant>;
        /// The sum of the members' reasons for ending.
        type RecvError: Clone;
        /// The future of one receive.
        type Recv<'a>: Future<Output = Result<Arrived<Self::Payload, Self::Instant>, Self::RecvError>>
            + 'a
        where
            Self: 'a;
        /// The future of the end.
        type Ended: Future<Output = Self::RecvError>;
        /// The sum of the members' reasons for not telling their limits.
        type MaxDatagramSizeError;
        /// The sum of the members' send errors.
        type SendError;
        /// The future of one send.
        type Send<'a>: Future<Output = Result<SendAcceptance<Self::Instant>, Self::SendError>> + 'a;
        /// The future of a change of the limit.
        type MaxDatagramSizeChanged: Future<Output = ()>;

        /// The member's identity with its ends injected into the sums.
        fn injected_id(&self) -> LinkId<Self::Local, Self::Peer>;
        /// [`Link::may_mark_ecn`] of the member.
        fn may_mark_ecn(&self) -> bool;
        /// [`Link::max_datagram_size`] of the member.
        fn max_datagram_size(&self) -> Result<usize, Self::MaxDatagramSizeError>;
        /// [`Link::recv`] of the member.
        fn recv(&self) -> Self::Recv<'_>;
        /// [`Link::ended`] of the member.
        fn ended(&self) -> Self::Ended;
        /// [`Link::send`] of the member.
        fn send<'a>(&self, batch: &'a [OutgoingDatagram]) -> Self::Send<'a>;
        /// [`Link::max_datagram_size_changed`] of the member.
        fn max_datagram_size_changed(&self) -> Self::MaxDatagramSizeChanged;
        /// [`Link::datagram_size_conclusion`] of the member.
        fn datagram_size_conclusion(&self) -> usize;
        /// [`Link::record_datagram_size_confirmed`] of the member.
        fn record_datagram_size_confirmed(&self, size: usize);
        /// [`Link::record_datagram_size_lowered`] of the member.
        fn record_datagram_size_lowered(&self, size: usize);
    }

    /// The sum of one link type: the last member of every sum.
    impl<H: Link> LinkSum for Coproduct<H, CNil> {
        type Local = Coproduct<H::Local, CNil>;
        type Peer = Coproduct<H::Peer, CNil>;
        type Payload = H::Payload;
        type Instant = H::Instant;
        type RecvError = Coproduct<H::RecvError, CNil>;
        type Recv<'a>
            = impl Future<Output = Result<Arrived<H::Payload, H::Instant>, Self::RecvError>> + 'a
        where
            Self: 'a;
        type Ended = impl Future<Output = Self::RecvError>;
        type MaxDatagramSizeError = Coproduct<H::MaxDatagramSizeError, CNil>;
        type SendError = Coproduct<H::SendError, CNil>;
        type Send<'a> =
            impl Future<Output = Result<SendAcceptance<H::Instant>, Self::SendError>> + 'a;
        type MaxDatagramSizeChanged = H::MaxDatagramSizeChanged;

        fn injected_id(&self) -> LinkId<Self::Local, Self::Peer> {
            only(self).id().clone().map(Coproduct::Inl, Coproduct::Inl)
        }

        fn may_mark_ecn(&self) -> bool {
            only(self).may_mark_ecn()
        }

        fn max_datagram_size(&self) -> Result<usize, Self::MaxDatagramSizeError> {
            only(self).max_datagram_size().map_err(Coproduct::Inl)
        }

        fn recv(&self) -> Self::Recv<'_> {
            let member = only(self);
            async move {
                let datagram = member.recv().await.map_err(Coproduct::Inl)?;
                Ok(Arrived::of(datagram))
            }
        }

        fn ended(&self) -> Self::Ended {
            let ended = only(self).ended();
            async move { Coproduct::Inl(ended.await) }
        }

        fn send<'a>(&self, batch: &'a [OutgoingDatagram]) -> Self::Send<'a> {
            let send = only(self).send(batch);
            async move { send.await.map_err(Coproduct::Inl) }
        }

        fn max_datagram_size_changed(&self) -> Self::MaxDatagramSizeChanged {
            only(self).max_datagram_size_changed()
        }

        fn datagram_size_conclusion(&self) -> usize {
            only(self).datagram_size_conclusion()
        }

        fn record_datagram_size_confirmed(&self, size: usize) {
            only(self).record_datagram_size_confirmed(size);
        }

        fn record_datagram_size_lowered(&self, size: usize) {
            only(self).record_datagram_size_lowered(size);
        }
    }

    /// The link a sum of one link type holds: the only value it can.
    fn only<H>(sum: &Coproduct<H, CNil>) -> &H {
        match sum {
            Coproduct::Inl(member) => member,
            Coproduct::Inr(nothing) => match *nothing {},
        }
    }

    /// The sum of a link type and a sum of further ones, whose payload and
    /// instant are the same as its.
    impl<H, H2, T> LinkSum for Coproduct<H, Coproduct<H2, T>>
    where
        H: Link,
        Coproduct<H2, T>: LinkSum<Payload = H::Payload, Instant = H::Instant>,
    {
        type Local = Coproduct<H::Local, <Coproduct<H2, T> as LinkSum>::Local>;
        type Peer = Coproduct<H::Peer, <Coproduct<H2, T> as LinkSum>::Peer>;
        type Payload = H::Payload;
        type Instant = H::Instant;
        type RecvError = Coproduct<H::RecvError, <Coproduct<H2, T> as LinkSum>::RecvError>;
        type Recv<'a>
            = impl Future<Output = Result<Arrived<H::Payload, H::Instant>, Self::RecvError>> + 'a
        where
            Self: 'a;
        type Ended = impl Future<Output = Self::RecvError>;
        type MaxDatagramSizeError =
            Coproduct<H::MaxDatagramSizeError, <Coproduct<H2, T> as LinkSum>::MaxDatagramSizeError>;
        type SendError = Coproduct<H::SendError, <Coproduct<H2, T> as LinkSum>::SendError>;
        type Send<'a> =
            impl Future<Output = Result<SendAcceptance<H::Instant>, Self::SendError>> + 'a;
        type MaxDatagramSizeChanged = impl Future<Output = ()>;

        fn injected_id(&self) -> LinkId<Self::Local, Self::Peer> {
            match self {
                Coproduct::Inl(member) => member.id().clone().map(Coproduct::Inl, Coproduct::Inl),
                Coproduct::Inr(rest) => rest.injected_id().map(Coproduct::Inr, Coproduct::Inr),
            }
        }

        fn may_mark_ecn(&self) -> bool {
            match self {
                Coproduct::Inl(member) => member.may_mark_ecn(),
                Coproduct::Inr(rest) => rest.may_mark_ecn(),
            }
        }

        fn max_datagram_size(&self) -> Result<usize, Self::MaxDatagramSizeError> {
            match self {
                Coproduct::Inl(member) => member.max_datagram_size().map_err(Coproduct::Inl),
                Coproduct::Inr(rest) => rest.max_datagram_size().map_err(Coproduct::Inr),
            }
        }

        fn recv(&self) -> Self::Recv<'_> {
            async move {
                match self {
                    Coproduct::Inl(member) => {
                        let datagram = member.recv().await.map_err(Coproduct::Inl)?;
                        Ok(Arrived::of(datagram))
                    }
                    Coproduct::Inr(rest) => rest.recv().await.map_err(Coproduct::Inr),
                }
            }
        }

        fn ended(&self) -> Self::Ended {
            let ended = match self {
                Coproduct::Inl(member) => Coproduct::Inl(member.ended()),
                Coproduct::Inr(rest) => Coproduct::Inr(rest.ended()),
            };
            async move {
                match ended {
                    Coproduct::Inl(ended) => Coproduct::Inl(ended.await),
                    Coproduct::Inr(ended) => Coproduct::Inr(ended.await),
                }
            }
        }

        fn send<'a>(&self, batch: &'a [OutgoingDatagram]) -> Self::Send<'a> {
            let send = match self {
                Coproduct::Inl(member) => Coproduct::Inl(member.send(batch)),
                Coproduct::Inr(rest) => Coproduct::Inr(rest.send(batch)),
            };
            async move {
                match send {
                    Coproduct::Inl(send) => send.await.map_err(Coproduct::Inl),
                    Coproduct::Inr(send) => send.await.map_err(Coproduct::Inr),
                }
            }
        }

        fn max_datagram_size_changed(&self) -> Self::MaxDatagramSizeChanged {
            let changed = match self {
                Coproduct::Inl(member) => Coproduct::Inl(member.max_datagram_size_changed()),
                Coproduct::Inr(rest) => Coproduct::Inr(rest.max_datagram_size_changed()),
            };
            async move {
                match changed {
                    Coproduct::Inl(changed) => changed.await,
                    Coproduct::Inr(changed) => changed.await,
                }
            }
        }

        fn datagram_size_conclusion(&self) -> usize {
            match self {
                Coproduct::Inl(member) => member.datagram_size_conclusion(),
                Coproduct::Inr(rest) => rest.datagram_size_conclusion(),
            }
        }

        fn record_datagram_size_confirmed(&self, size: usize) {
            match self {
                Coproduct::Inl(member) => member.record_datagram_size_confirmed(size),
                Coproduct::Inr(rest) => rest.record_datagram_size_confirmed(size),
            }
        }

        fn record_datagram_size_lowered(&self, size: usize) {
            match self {
                Coproduct::Inl(member) => member.record_datagram_size_lowered(size),
                Coproduct::Inr(rest) => rest.record_datagram_size_lowered(size),
            }
        }
    }
}

#[cfg(test)]
mod tests;
