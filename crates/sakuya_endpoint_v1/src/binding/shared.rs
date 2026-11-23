//! What the driver of a link binding shares with the binding's handle: the
//! binding, the inbox of new links and the set of dispatched links.

use alloc::vec::Vec;
use core::{fmt, task::Waker};

use frunk_core::coproduct::CoprodInjector;
use hashbrown::HashMap;
use nitori_sync::SharedState as _;
use sakuya_link::{Link, LinkBinding};

use super::EndpointLinkId;
use crate::{
    link::{EndpointLink, LinkCore, sum::LinkSum},
    synchronization::EndpointSynchronization,
};

/// What the driver of a link binding shares with the binding's handle,
/// whose state is synchronized by `Y`.
pub struct BindingShared<B: LinkBinding, M: LinkSum, Y: EndpointSynchronization> {
    binding: B,
    /// The binding's own local end ([`LinkBinding::local`]), in the sum of
    /// the local ends of the endpoint's links.
    local: M::Local,
    /// Puts a link of the binding into the sum of the endpoint's links.
    inject: fn(B::Link) -> M,
    /// The inbox, the dispatched set and the driver's waker, in the wrapper
    /// the host chose; one for each binding.
    links: Y::SharedState<BindingLinks<M, Y::HashBuilder>>,
}

/// The links of one binding that its driver and its handle share; `S`
/// builds the hashers of the dispatched set, whose keys hold the peers' ends
/// of the links.
pub(crate) struct BindingLinks<M: LinkSum, S> {
    /// The links admitted whose receive loops the driver has not started.
    inbox: Vec<NewLink<M>>,
    /// The links with a receive loop, each with a clone of its core, by
    /// identity.
    dispatched: HashMap<EndpointLinkId<M>, LinkCore<M>, S>,
    /// The driver's waker, woken when a link is put in the inbox.
    driver_waker: Option<Waker>,
    /// Whether the driver let go of every link: it starts no receive loop
    /// any more, so no link is admitted.
    ended: bool,
}

/// The driver of the binding let go of every link, so no link is admitted
/// any more.
#[derive(Debug)]
pub(crate) struct DriverEnded;

impl<B: LinkBinding, M: LinkSum, Y: EndpointSynchronization> BindingShared<B, M, Y> {
    /// The shared state of `binding`, whose links are the member of `M` at
    /// `I`.
    pub(crate) fn new<I>(binding: B) -> Self
    where
        M: CoprodInjector<B::Link, I>,
        M::Local: CoprodInjector<<B::Link as Link>::Local, I>,
    {
        let local = M::Local::inject(binding.local().clone());
        Self {
            binding,
            local,
            inject: M::inject,
            links: Y::share(BindingLinks {
                inbox: Vec::new(),
                dispatched: HashMap::with_hasher(Y::HashBuilder::default()),
                driver_waker: None,
                ended: false,
            }),
        }
    }

    /// The binding's own local end, in the sum of the local ends of the
    /// endpoint's links: a link from the local end `x` is taken on the
    /// binding only when this is `x`.
    pub(crate) fn local(&self) -> &M::Local {
        &self.local
    }

    /// The link binding.
    pub(crate) fn binding(&self) -> &B {
        &self.binding
    }

    /// Admits `member`, a link the binding gave by accepting, which is not
    /// let go before it received a datagram.
    ///
    /// When the link is dispatched already, `member` is dropped, which does
    /// not close the link. Otherwise its core is made, put in the dispatched
    /// set and in the inbox, and the driver is woken to start its receive
    /// loop. Once the driver ended, `member` is dropped.
    pub(crate) fn admit_accepted(&self, member: B::Link) {
        drop(self.admit(member, Admitted::Accepted));
    }

    /// Admits `member`, a link the binding gave by connecting, and returns a
    /// use of it.
    ///
    /// When the link is dispatched already, the use is one of the dispatched
    /// link and `member` is dropped, which does not close the link.
    /// Otherwise its core is made as for an accepted link.
    ///
    /// # Errors
    ///
    /// [`DriverEnded`] once the driver let go of every link; `member` is
    /// dropped then.
    pub(crate) fn admit_connected(&self, member: B::Link) -> Result<EndpointLink<M>, DriverEnded> {
        self.admit(member, Admitted::Connected)
    }

    /// Admits `member` and returns a use of it, made within the borrow of
    /// the dispatched set so that the receive loop cannot find it unused
    /// first.
    fn admit(&self, member: B::Link, admitted: Admitted) -> Result<EndpointLink<M>, DriverEnded> {
        let member = (self.inject)(member);
        let id = member.injected_id();
        // The member is dropped, and the driver woken, outside the borrow.
        let (link, unused, waker) = self.links.with(|links| {
            if links.ended {
                return (Err(DriverEnded), Some(member), None);
            }
            if let Some(core) = links.dispatched.get(&id) {
                return (Ok(core.endpoint_link()), Some(member), None);
            }
            let core = LinkCore::from_member(member);
            let link = core.endpoint_link();
            links.dispatched.insert(id, core.clone());
            links.inbox.push(NewLink { core, admitted });
            (Ok(link), None, links.driver_waker.take())
        });
        drop(unused);
        if let Some(waker) = waker {
            waker.wake();
        }
        link
    }

    /// A use of the dispatched link `id`, if it is still dispatched.
    pub(crate) fn dispatched_link(&self, id: &EndpointLinkId<M>) -> Option<EndpointLink<M>> {
        self.links
            .with(|links| links.dispatched.get(id).map(LinkCore::endpoint_link))
    }

    /// Arranges for `waker` to be woken when a link is put in the inbox.
    pub(super) fn register_driver(&self, waker: &Waker) {
        self.links.with(|links| match &mut links.driver_waker {
            Some(registered) if registered.will_wake(waker) => {}
            registered => *registered = Some(waker.clone()),
        });
    }

    /// Whether no link waits in the inbox.
    pub(super) fn inbox_is_empty(&self) -> bool {
        self.links.with(|links| links.inbox.is_empty())
    }

    /// How many links are dispatched.
    #[cfg(test)]
    pub(super) fn dispatched_count(&self) -> usize {
        self.links.with(|links| links.dispatched.len())
    }

    /// Takes the links waiting in the inbox.
    pub(super) fn take_inbox(&self) -> Vec<NewLink<M>> {
        self.links.with(|links| core::mem::take(&mut links.inbox))
    }

    /// Takes the link `id` out of the dispatched set when it ended.
    pub(super) fn release_ended(&self, id: &EndpointLinkId<M>) {
        let removed = self.links.with(|links| links.dispatched.remove(id));
        drop(removed);
    }

    /// Takes the link of a receive loop that saw it unused out of the
    /// dispatched set, unless somebody took a use in the meantime: then the
    /// link is returned, for its receive loop to start again.
    pub(super) fn release_unused(&self, link: LinkCore<M>) -> Option<LinkCore<M>> {
        // Outside the receive loop, uses are made from the dispatched core
        // within this borrow only, so a count of none cannot grow any more.
        let released = self.links.with(|links| {
            if link.uses() > 0 {
                return Err(link);
            }
            let removed = links.dispatched.remove(link.id());
            Ok((link, removed))
        });
        match released {
            Err(link) => Some(link),
            Ok(released) => {
                drop(released);
                None
            }
        }
    }

    /// Lets go of every admitted link: nobody receives on them any more,
    /// and no link is admitted after.
    pub(super) fn release_all(&self) {
        let released = self.links.with(|links| {
            links.ended = true;
            (
                core::mem::take(&mut links.inbox),
                core::mem::take(&mut links.dispatched),
            )
        });
        drop(released);
    }
}

impl<B: LinkBinding, M: LinkSum, Y: EndpointSynchronization> fmt::Debug for BindingShared<B, M, Y> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BindingShared")
            .field("binding", self.binding.id())
            .field(
                "dispatched",
                &self.links.with(|links| links.dispatched.len()),
            )
            .finish_non_exhaustive()
    }
}

/// How a link was first admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Admitted {
    /// The binding gave it by accepting: as a rule because a datagram
    /// arrived, which its first receive delivers. It is not let go before
    /// that datagram, though nobody uses it until then.
    Accepted,
    /// The binding gave it by connecting, to the one that holds its first
    /// use.
    Connected,
}

/// A link admitted whose receive loop has not started.
pub(crate) struct NewLink<M: LinkSum> {
    pub(super) core: LinkCore<M>,
    pub(super) admitted: Admitted,
}
