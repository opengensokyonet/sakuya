//! Accepting new Initial receivers through non-inline reflow
//!
//! A supported Initial that the routing domain may accept is routed with the
//! on-unclaimed finish policy. If every candidate exits while the datagram is
//! still present, the last exit hands an [`UnclaimedWork`] to the
//! [`ReflowProvider`], synchronously and exactly once, through the routing
//! domain's [`ReflowHandoff`]. The provider only takes the work over: the next
//! round runs later, outside that call stack, when the outer layer passes the
//! work back to [`DatagramRouter::resume`](super::router::DatagramRouter::resume).
//!
//! Nothing here requires `Send`. A routing domain used on one thread can
//! accept new Initials with local deliverers, datagrams and providers; a
//! domain shared between threads uses a `Send + Sync` provider, which makes
//! its [`ReflowHandoff`] `Send`, so that the candidates of its datagrams can
//! move between threads.
//!
//! Resuming prepares a new receiver with the [`InitialReceiverFactory`]
//! first, outside the index, and then rechecks the key of the Initial within
//! one entry access of the index:
//!
//! - entries that apply and had no chance at this datagram yet, including
//!   ones published since the last round, become the next round of
//!   candidates, again under the on-unclaimed policy;
//! - otherwise the prepared deliverer is published under the Initial
//!   association, and its registration immediately belongs to the prepared
//!   receiver, which receives the datagram exclusively;
//! - otherwise, when nothing could be prepared, the datagram is released.
//!
//! Two datagrams that both found nothing therefore never both create a
//! receiver blindly: whichever rechecks second finds the first one's new
//! entry and offers itself to it first. Unused prepared material is dropped
//! outside the index.

use std::fmt;
use std::sync::Arc;

use super::index::{OfferedRouteHistory, RouteEntryRegistration};
use super::interpretation::RecognizedInitial;
use crate::claim::delivery::ExclusiveDatagram;
use crate::claim::finish::UnclaimedHandoff;
use crate::claim::queue::DatagramDeliveryPoster;
use sakuya_link::ReceivedDatagram;

/// A datagram that every candidate left unclaimed, with what routing needs to
/// continue.
///
/// It holds the original datagram, the route entries and interpretations
/// that already had their chance at it, and the Initial routing recognized.
/// The capabilities to look up, prepare and publish come from the router the
/// work is resumed with. Taking it over only moves ownership; dropping it
/// releases the datagram and its history. It is `Send` when the datagram is.
pub struct UnclaimedWork<Payload, Link: sakuya_link::Link> {
    datagram: ReceivedDatagram<Payload, Link>,
    offered: OfferedRouteHistory,
    initial: RecognizedInitial<Link::Local>,
}

impl<Payload, Link: sakuya_link::Link> UnclaimedWork<Payload, Link> {
    /// The unclaimed datagram.
    pub fn datagram(&self) -> &ReceivedDatagram<Payload, Link> {
        &self.datagram
    }

    /// The Initial routing recognized in the datagram.
    pub fn initial(&self) -> &RecognizedInitial<Link::Local> {
        &self.initial
    }

    /// Returns the datagram, dropping the routing history.
    pub fn into_datagram(self) -> ReceivedDatagram<Payload, Link> {
        self.datagram
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        ReceivedDatagram<Payload, Link>,
        OfferedRouteHistory,
        RecognizedInitial<Link::Local>,
    ) {
        (self.datagram, self.offered, self.initial)
    }

    #[cfg(test)]
    pub(crate) fn offered_len(&self) -> usize {
        self.offered.len()
    }
}

impl<Payload, Link: sakuya_link::Link> fmt::Debug for UnclaimedWork<Payload, Link>
where
    Link::Local: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnclaimedWork")
            .field("initial", &self.initial)
            .field("offered", &self.offered)
            .finish_non_exhaustive()
    }
}

/// The outside capability that takes over unclaimed work.
///
/// [`hand_off`](Self::hand_off) is called synchronously from the last exit of
/// a candidate, which may be anywhere downstream: in a connection loop, in a
/// cancelled future, while a delivery is dropped. It must take the work over
/// and return without continuing the work on that call stack: running the next
/// round inside the call, or from a waker it wakes inline, breaks the
/// contract. Running it later on the same thread, or on another thread even
/// before `hand_off` returns, is fine. It may also drop the work, which
/// releases the datagram. The signature cannot prove any of this; it is the
/// provider's contract.
///
/// The trait requires neither `Send` nor `Sync`. A provider shared by the
/// candidates of a routing domain used across threads must be both, so that
/// the domain's [`ReflowHandoff`] is `Send`.
pub trait ReflowProvider<Payload, Link: sakuya_link::Link> {
    /// Takes over one round of unclaimed work.
    fn hand_off(&self, work: UnclaimedWork<Payload, Link>);
}

/// The unclaimed handoff of a routing domain that accepts new Initials.
///
/// Routing gives every acceptable Initial one of these: it carries the
/// domain's [`ReflowProvider`], the entries that already had a chance at the
/// datagram, and the Initial routing recognized. When every candidate exits,
/// it hands the datagram to the provider as [`UnclaimedWork`]. Only routing
/// creates it; the type appears in the deliverer type of such a domain, as
/// [`DatagramDeliverer::Handoff`](crate::claim::deliverer::DatagramDeliverer::Handoff).
///
/// It is `Send` when the provider is `Send + Sync`.
pub struct ReflowHandoff<Provider, Local> {
    provider: Arc<Provider>,
    offered: OfferedRouteHistory,
    initial: RecognizedInitial<Local>,
}

impl<Provider, Local> ReflowHandoff<Provider, Local> {
    pub(crate) fn new(
        provider: &Arc<Provider>,
        offered: OfferedRouteHistory,
        initial: RecognizedInitial<Local>,
    ) -> Self {
        Self {
            provider: Arc::clone(provider),
            offered,
            initial,
        }
    }
}

impl<Payload, Link: sakuya_link::Link, Provider: ReflowProvider<Payload, Link>>
    UnclaimedHandoff<ReceivedDatagram<Payload, Link>> for ReflowHandoff<Provider, Link::Local>
{
    fn hand_off(self, datagram: ReceivedDatagram<Payload, Link>) {
        self.provider.hand_off(UnclaimedWork {
            datagram,
            offered: self.offered,
            initial: self.initial,
        });
    }
}

impl<Provider, Local: fmt::Debug> fmt::Debug for ReflowHandoff<Provider, Local> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReflowHandoff")
            .field("initial", &self.initial)
            .field("offered", &self.offered)
            .finish_non_exhaustive()
    }
}

/// Builds receivers for Initials that no existing receiver claimed.
///
/// The router calls it outside every index lock.
pub trait InitialReceiverFactory<Payload, Link: sakuya_link::Link, Target: ?Sized> {
    /// The receiver this factory prepares.
    type Receiver: InitialDatagramReceiver<Payload, Link, Target>;

    /// Whether the routing domain may create a receiver for this Initial at
    /// all, for example given the datagram size the protocol requires.
    ///
    /// When it returns `false`, the Initial is still offered to every existing
    /// entry, as any other datagram, and released if they all exit.
    fn admits(
        &self,
        initial: &RecognizedInitial<Link::Local>,
        datagram: &ReceivedDatagram<Payload, Link>,
    ) -> bool;

    /// Prepares a receiver whose deliverer can receive as soon as it is
    /// published; `None` when none can be made now.
    ///
    /// Preparation happens before the recheck and may be wasted when an
    /// existing entry turns out to apply; the prepared receiver is then
    /// dropped.
    fn prepare(
        &self,
        initial: &RecognizedInitial<Link::Local>,
    ) -> Option<PreparedReceiver<Target, Self::Receiver>>;
}

/// A deliverer ready to be published, and the receiver that will hold its
/// registration.
pub struct PreparedReceiver<Target: ?Sized, Receiver> {
    deliverer: Arc<Target>,
    receiver: Receiver,
}

impl<Target: ?Sized, Receiver> PreparedReceiver<Target, Receiver> {
    /// Pairs a deliverer with its receiver.
    ///
    /// The deliverer must already be able to take deliveries: once published,
    /// another datagram may reach it before the first one reaches the
    /// receiver.
    pub fn new(deliverer: Arc<Target>, receiver: Receiver) -> Self {
        Self {
            deliverer,
            receiver,
        }
    }

    pub(crate) fn into_parts(self) -> (Arc<Target>, Receiver) {
        (self.deliverer, self.receiver)
    }
}

impl<Target: ?Sized, Receiver> fmt::Debug for PreparedReceiver<Target, Receiver> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedReceiver").finish_non_exhaustive()
    }
}

/// The datagram receiver of a newly published Initial entry.
pub trait InitialDatagramReceiver<Payload, Link: sakuya_link::Link, Target: ?Sized> {
    /// Takes over the registration of the new entry and the first datagram.
    ///
    /// The receiver now owns the registration and is responsible for revoking
    /// it when it rejects the connection attempt, fails, or closes. The first
    /// datagram is exclusively the receiver's; it was not a candidate of the
    /// new deliverer. Nothing about it is authenticated.
    fn receive_first(
        self,
        registration: RouteEntryRegistration<Target, Link::Local>,
        datagram: ExclusiveDatagram<ReceivedDatagram<Payload, Link>>,
        initial: RecognizedInitial<Link::Local>,
    );
}

/// The capability to accept new Initial receivers: a receiver factory and a
/// reflow provider.
///
/// A router with this acceptance hands unclaimed Initials off through a
/// [`ReflowHandoff`] carrying `Provider`; the deliverers of its routing domain
/// name that handoff as their
/// [`Handoff`](crate::claim::deliverer::DatagramDeliverer::Handoff). Neither
/// the factory nor the provider needs to be `Send`.
pub struct InitialAcceptance<Factory, Provider> {
    factory: Factory,
    provider: Arc<Provider>,
}

impl<Factory, Provider> InitialAcceptance<Factory, Provider> {
    /// Accepts with `factory`, handing unclaimed work to `provider`.
    pub fn new(factory: Factory, provider: Arc<Provider>) -> Self {
        Self { factory, provider }
    }

    pub(crate) fn factory(&self) -> &Factory {
        &self.factory
    }

    pub(crate) fn provider(&self) -> &Arc<Provider> {
        &self.provider
    }
}

impl<Factory, Provider> fmt::Debug for InitialAcceptance<Factory, Provider> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitialAcceptance").finish_non_exhaustive()
    }
}

/// Queues reflow work for the outer layer to resume later.
///
/// Posting never runs the next round: the owner of the matching
/// [`DatagramDeliveryQueue`](crate::claim::queue::DatagramDeliveryQueue)
/// takes the work out and passes it to
/// [`DatagramRouter::resume`](super::router::DatagramRouter::resume), on its
/// own stack. A closed or full queue drops the work, which releases the
/// datagram.
impl<Payload, Link: sakuya_link::Link> ReflowProvider<Payload, Link>
    for DatagramDeliveryPoster<UnclaimedWork<Payload, Link>>
{
    fn hand_off(&self, work: UnclaimedWork<Payload, Link>) {
        self.post(work);
    }
}
