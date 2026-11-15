//! What the driver of a link binding shares with the binding's handle: the
//! binding, the inbox of new links and the set of dispatched links.

use core::{fmt, task::Waker};
use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard, PoisonError},
};

use frunk_core::coproduct::CoprodInjector;
use futures_util::task::AtomicWaker;
use sakuya_link::{Link, LinkBinding};

use super::EndpointLinkId;
use crate::link::{EndpointLink, KEPT_BY_THE_ENDPOINT, sum::LinkSum};

/// What the driver of a link binding shares with the binding's handle.
pub struct BindingShared<B: LinkBinding, M: LinkSum> {
    binding: B,
    /// Puts a link of the binding into the sum of the endpoint's links.
    inject: fn(B::Link) -> M,
    /// The links admitted whose receive loops the driver has not started.
    inbox: Mutex<Vec<EndpointLink<M>>>,
    /// The links with a receive loop, each with a clone of its endpoint
    /// link, by identity.
    dispatched: Mutex<HashMap<EndpointLinkId<M>, EndpointLink<M>>>,
    /// The driver's waker, woken when a link is put in the inbox.
    driver_waker: AtomicWaker,
}

impl<B: LinkBinding, M: LinkSum> BindingShared<B, M> {
    /// The shared state of `binding`, whose links are the member of `M` at
    /// `I`.
    pub(crate) fn new<I>(binding: B) -> Self
    where
        M: CoprodInjector<B::Link, I>,
    {
        Self {
            binding,
            inject: M::inject,
            inbox: Mutex::new(Vec::new()),
            dispatched: Mutex::new(HashMap::new()),
            driver_waker: AtomicWaker::new(),
        }
    }

    /// The link binding.
    pub(crate) fn binding(&self) -> &B {
        &self.binding
    }

    /// Admits `member`, a link the binding gave by accepting or connecting,
    /// and returns its endpoint link.
    ///
    /// When the link is dispatched already, the endpoint link returned is a
    /// clone of the dispatched one and `member` is dropped, which does not
    /// close the link. Otherwise a new endpoint link is made for it, put in
    /// the dispatched set and in the inbox, and the driver is woken to start
    /// its receive loop.
    pub(crate) fn admit(&self, member: B::Link) -> EndpointLink<M> {
        let member = (self.inject)(member);
        let id = member.injected_id();
        let mut dispatched = lock(&self.dispatched);
        if let Some(link) = dispatched.get(&id) {
            let link = link.clone();
            drop(dispatched);
            return link;
        }
        let link = EndpointLink::from_member(member);
        dispatched.insert(id, link.clone());
        lock(&self.inbox).push(link.clone());
        drop(dispatched);
        self.driver_waker.wake();
        link
    }

    /// A clone of the dispatched link `id`, if it is still dispatched.
    pub(crate) fn dispatched_link(&self, id: &EndpointLinkId<M>) -> Option<EndpointLink<M>> {
        lock(&self.dispatched).get(id).cloned()
    }

    /// Arranges for `waker` to be woken when a link is put in the inbox.
    pub(super) fn register_driver(&self, waker: &Waker) {
        self.driver_waker.register(waker);
    }

    /// Whether no link waits in the inbox.
    pub(super) fn inbox_is_empty(&self) -> bool {
        lock(&self.inbox).is_empty()
    }

    /// How many links are dispatched.
    #[cfg(test)]
    pub(super) fn dispatched_count(&self) -> usize {
        lock(&self.dispatched).len()
    }

    /// Takes the links waiting in the inbox.
    pub(super) fn take_inbox(&self) -> Vec<EndpointLink<M>> {
        core::mem::take(&mut *lock(&self.inbox))
    }

    /// Takes the link `id` out of the dispatched set when it ended.
    pub(super) fn release_ended(&self, id: &EndpointLinkId<M>) {
        let removed = lock(&self.dispatched).remove(id);
        drop(removed);
    }

    /// Takes the link of a receive loop that saw it unused out of the
    /// dispatched set, unless somebody took a clone in the meantime: then
    /// the link is returned, for its receive loop to start again.
    pub(super) fn release_unused(&self, link: EndpointLink<M>) -> Option<EndpointLink<M>> {
        let mut dispatched = lock(&self.dispatched);
        // Clones are made from the dispatched one under this lock only, so
        // a count of the loop's and the set's alone cannot grow any more.
        if link.users() > KEPT_BY_THE_ENDPOINT {
            return Some(link);
        }
        let removed = dispatched.remove(link.id());
        drop(dispatched);
        drop(removed);
        None
    }

    /// Lets go of every admitted link: nobody receives on them any more.
    pub(super) fn release_all(&self) {
        let inbox = self.take_inbox();
        let dispatched = core::mem::take(&mut *lock(&self.dispatched));
        drop(inbox);
        drop(dispatched);
    }
}

impl<B: LinkBinding, M: LinkSum> fmt::Debug for BindingShared<B, M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BindingShared")
            .field("binding", self.binding.id())
            .field("dispatched", &lock(&self.dispatched).len())
            .finish_non_exhaustive()
    }
}

/// Locks `mutex`, using its value as it is when a panic poisoned it: every
/// change under these locks leaves the value consistent.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
