//! What an endpoint is composed with, and the types of its routing domain
//! that follow from it.

use alloc::sync::Arc;
use core::{
    fmt,
    task::{Context, Poll},
};

use frunk_core::{
    coproduct::{CNil, Coproduct},
    hlist::{HCons, HNil},
    indices::{Here, There},
};

use nitori_crypto::Random;
use nitori_sync::Synchronization;
use sakuya_clock::MonotonicClock;
use sakuya_connection::v1::{
    input::LogicalPathDatagramReceiver, stateless_reset::StatelessResetSignal,
};
use sakuya_datagram_routing_v1::{
    claim::{
        deliverer::DatagramDeliverer,
        delivery::DatagramDelivery,
        queue::{DatagramDeliveryPoster, DatagramDeliveryQueue},
    },
    route::{
        acceptance::{ReflowHandoff, UnclaimedWork},
        index::RouteIndex,
        recognizer::{ConnectionIdGenerator, ConnectionIdRecognizer},
    },
};
use sakuya_link::{LinkBinding, ReceivedDatagram};
use sakuya_packet_protection_v1::backend::CryptoBackend;

use crate::{
    binding::shared::BindingShared,
    link::{EndpointLink, sum::LinkSum},
    reflow::UnclaimedWorkPoster,
    synchronization::EndpointSynchronization,
    zero_length::{ZeroLengthLocals, ZeroLengthRegistration},
};

/// What an endpoint is composed with, apart from its two roles.
///
/// A type the host defines implements it, as the choices of a connection
/// are given ([`v1::Choices`](sakuya_connection::v1::Choices)); the values
/// come with the [`EndpointConfig`](crate::config::EndpointConfig).
pub trait EndpointChoices: 'static {
    /// The links of the endpoint's bindings, as a sum: a `Coproduct` of
    /// their link types, such as `Coprod![UdpLink<C>]`.
    type Links: LinkSum<Payload: AsRef<[u8]>>;
    /// The types of the endpoint's bindings, as a list: an `HList` of
    /// them, such as `HList![UdpBinding<C>]`. A binding is added only when
    /// its type is in the list ([`ListedBinding`]); what the endpoint keeps
    /// of each binding is of these types, not erased, so whether it is
    /// `Send` is checked where the endpoint is composed.
    type Bindings: BindingList;
    /// The clock of the endpoint and its connections, whose instants are
    /// those its links report.
    type Clock: MonotonicClock<Instant = <Self::Links as LinkSum>::Instant> + 'static;
    /// The cryptographic backend that protects packets: the connections'
    /// and that of the packets the endpoint sends without a connection.
    type Crypto: CryptoBackend + Clone + 'static;
    /// The random source of the endpoint: the destination connection IDs a
    /// client chooses, and the reserved versions of Version Negotiation
    /// packets.
    type Random: Random;
    /// The calendar clock that address validation tokens are dated by.
    type WallClock: nitori_tls::clock::Clock;
    /// What generates the connection IDs of each connection; the endpoint
    /// keeps its configuration and makes one generator for each
    /// connection.
    type ConnectionIds: ConnectionIdGenerator;
    /// What tells the lengths of the destination connection IDs of short
    /// headers, by the encoding the connection ID generator uses.
    type Recognizer: ConnectionIdRecognizer<LocalOf<Self>, PeerOf<Self>>;
    /// How the endpoint's state is synchronized: the family of its tables,
    /// queues, claim lock and state wrappers, such as
    /// [`RefCellEndpointSynchronization`](crate::synchronization::RefCellEndpointSynchronization)
    /// for an endpoint on one thread.
    type Synchronization: EndpointSynchronization;
}

/// The types of an endpoint's bindings, as a list: an `HList` of link
/// bindings, which ends in `HNil`.
///
/// Only the lists of this crate implement it: `HNil` and `HCons`.
pub trait BindingList: sealed::Sealed + 'static {
    /// What the endpoint keeps of one binding of the list, whose links are
    /// in the sum `M` and whose state is synchronized by `Y`: a `Coproduct`
    /// of the bindings' shared states.
    #[doc(hidden)]
    type Shared<M: LinkSum, Y: EndpointSynchronization>;
}

impl BindingList for HNil {
    type Shared<M: LinkSum, Y: EndpointSynchronization> = CNil;
}

impl<H: LinkBinding + 'static, T: BindingList> BindingList for HCons<H, T> {
    type Shared<M: LinkSum, Y: EndpointSynchronization> =
        Coproduct<Arc<BindingShared<H, M, Y>>, T::Shared<M, Y>>;
}

/// What keeps [`BindingList`] to the lists of this crate.
mod sealed {
    pub trait Sealed {}

    impl Sealed for frunk_core::hlist::HNil {}

    impl<H, T: Sealed> Sealed for frunk_core::hlist::HCons<H, T> {}
}

/// A binding whose type is in the list `L`, at the index `J`, which is
/// inferred.
pub trait ListedBinding<L: BindingList, J>: LinkBinding + Sized {
    /// What the endpoint keeps of the binding, as one of the list's.
    #[doc(hidden)]
    fn listed<M: LinkSum, Y: EndpointSynchronization>(
        shared: Arc<BindingShared<Self, M, Y>>,
    ) -> L::Shared<M, Y>;
}

impl<B: LinkBinding + 'static, T: BindingList> ListedBinding<HCons<B, T>, Here> for B {
    fn listed<M: LinkSum, Y: EndpointSynchronization>(
        shared: Arc<BindingShared<B, M, Y>>,
    ) -> Coproduct<Arc<BindingShared<B, M, Y>>, T::Shared<M, Y>> {
        Coproduct::Inl(shared)
    }
}

impl<B, H, T, J> ListedBinding<HCons<H, T>, There<J>> for B
where
    B: ListedBinding<T, J>,
    H: LinkBinding + 'static,
    T: BindingList,
{
    fn listed<M: LinkSum, Y: EndpointSynchronization>(
        shared: Arc<BindingShared<B, M, Y>>,
    ) -> Coproduct<Arc<BindingShared<H, M, Y>>, T::Shared<M, Y>> {
        Coproduct::Inr(B::listed(shared))
    }
}

/// What an endpoint of the choices `E` keeps of one of its bindings: the
/// binding's shared state, as a member of the sum of its binding types.
pub(crate) type SharedBindingOf<E> = <<E as EndpointChoices>::Bindings as BindingList>::Shared<
    <E as EndpointChoices>::Links,
    <E as EndpointChoices>::Synchronization,
>;

/// How the state of an endpoint of the choices `E` is synchronized.
pub type SynchronizationOf<E> = <E as EndpointChoices>::Synchronization;
/// The lock the candidates of one datagram compete under, in the routing
/// domain of an endpoint of the choices `E`.
pub type ClaimLockOf<E> = <SynchronizationOf<E> as EndpointSynchronization>::ClaimLock;
/// What builds the hashers of the maps of an endpoint of the choices `E`.
pub(crate) type HashBuilderOf<E> = <SynchronizationOf<E> as EndpointSynchronization>::HashBuilder;
/// A wrapper of state of type `T` of an endpoint of the choices `E`.
pub(crate) type SharedStateOf<E, T> = <SynchronizationOf<E> as Synchronization>::SharedState<T>;

/// The link of an endpoint of the choices `E`.
pub type LinkOf<E> = EndpointLink<<E as EndpointChoices>::Links>;
/// This side's end of a link of an endpoint of the choices `E`.
pub type LocalOf<E> = <<E as EndpointChoices>::Links as LinkSum>::Local;
/// The peer's end of a link of an endpoint of the choices `E`.
pub type PeerOf<E> = <<E as EndpointChoices>::Links as LinkSum>::Peer;
/// The payload of a datagram an endpoint of the choices `E` receives.
pub type PayloadOf<E> = <<E as EndpointChoices>::Links as LinkSum>::Payload;
/// A datagram an endpoint of the choices `E` receives.
pub type DatagramOf<E> = ReceivedDatagram<PayloadOf<E>, LinkOf<E>>;
/// A datagram that every candidate left unclaimed, which routing hands to
/// the reflow driver.
pub(crate) type WorkOf<E> = UnclaimedWork<PayloadOf<E>, LinkOf<E>>;
/// Where routing hands unclaimed datagrams over.
pub(crate) type ReflowPosterOf<E> = UnclaimedWorkPoster<E>;
/// What takes over a datagram every candidate left, in the routing domain of
/// an endpoint of the choices `E`.
pub type HandoffOf<E> = ReflowHandoff<ReflowPosterOf<E>, LocalOf<E>>;
/// What routing gives a deliverer of an endpoint of the choices `E`.
pub type DeliveryOf<E> = DatagramDelivery<DatagramOf<E>, LocalOf<E>, HandoffOf<E>, ClaimLockOf<E>>;
/// The index of the route entries of an endpoint of the choices `E`.
pub(crate) type RouteIndexOf<E> =
    <SynchronizationOf<E> as EndpointSynchronization>::RouteIndex<EndpointDeliverer<E>, LocalOf<E>>;
/// A route entry the endpoint registered for a connection.
pub(crate) type RegistrationOf<E> = <RouteIndexOf<E> as RouteIndex<LocalOf<E>>>::Registration;
/// The table of the peers' stateless reset tokens of an endpoint of the
/// choices `E`, shared by its routing, which detects resets, and its
/// connections, which register the tokens.
pub type ResetTokensOf<E> = <SynchronizationOf<E> as EndpointSynchronization>::StatelessResetTokens<
    PeerOf<E>,
    Arc<StatelessResetSignal>,
>;
/// The receive queue of a connection of an endpoint of the choices `E`.
pub(crate) type ReceiveQueueOf<E> =
    <SynchronizationOf<E> as EndpointSynchronization>::DatagramDeliveryQueue<DeliveryOf<E>>;
/// What posts to the receive queue of a connection of an endpoint of the
/// choices `E`.
pub(crate) type ReceivePosterOf<E> =
    <ReceiveQueueOf<E> as DatagramDeliveryQueue<DeliveryOf<E>>>::Poster;
/// The local ends on which a connection of an endpoint of the choices `E`
/// uses zero-length connection IDs.
pub(crate) type ZeroLengthLocalsOf<E> =
    <SynchronizationOf<E> as EndpointSynchronization>::ZeroLengthLocals<LocalOf<E>>;
/// One connection's hold on a local end for zero-length connection IDs, in
/// an endpoint of the choices `E`.
pub(crate) type ZeroLengthOccupancyOf<E> =
    <ZeroLengthLocalsOf<E> as ZeroLengthLocals<LocalOf<E>>>::Occupancy;

/// The deliverer of every route entry of an endpoint: it posts each delivery
/// to the datagram receiver of one connection.
///
/// It holds only a weak poster: once the connection's receiver is gone,
/// deliveries are dropped where they are posted.
#[doc(hidden)]
pub struct EndpointDeliverer<E: EndpointChoices> {
    poster: ReceivePosterOf<E>,
}

impl<E: EndpointChoices> EndpointDeliverer<E> {
    pub(crate) fn new(poster: ReceivePosterOf<E>) -> Self {
        Self { poster }
    }
}

impl<E: EndpointChoices> DatagramDeliverer<DatagramOf<E>, LocalOf<E>> for EndpointDeliverer<E> {
    type Handoff = HandoffOf<E>;
    type ClaimLock = ClaimLockOf<E>;

    fn deliver(&self, delivery: DeliveryOf<E>) {
        self.poster.post(delivery);
    }
}

impl<E: EndpointChoices> fmt::Debug for EndpointDeliverer<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EndpointDeliverer")
            .field("closed", &self.poster.is_closed())
            .finish()
    }
}

/// The datagram receiver of a connection of an endpoint of the choices `E`:
/// the [`Receiver`](sakuya_connection::v1::MakerChoices::Receiver) of its
/// connections' choices.
///
/// It is the delivery queue its route entries post to, and it holds some
/// of those entries: the one under the client's first destination
/// connection ID, for a server, and the entry of a zero-length first local
/// connection ID, registered by its local end. They are revoked when the
/// receiver is dropped, with the connection's first logical path. The
/// entries of the connection IDs that are not empty are kept by the
/// connection's local connection ID strategy.
pub struct ConnectionDatagramReceiver<E: EndpointChoices> {
    queue: ReceiveQueueOf<E>,
    initial: Option<RegistrationOf<E>>,
    first_local: Option<FirstLocalRegistration<E>>,
}

/// The route entry of a connection's zero-length first local connection
/// ID, which its local end is registered for.
pub(crate) enum FirstLocalRegistration<E: EndpointChoices> {
    /// The zero-length one of a generator of zero-length connection IDs,
    /// held for the entry to stay registered.
    Issued(RegistrationOf<E>),
    /// The zero-length connection ID, with the occupancy of its local end.
    ZeroLength(ZeroLengthRegistration<RegistrationOf<E>, ZeroLengthOccupancyOf<E>>),
}

impl<E: EndpointChoices> ConnectionDatagramReceiver<E> {
    pub(crate) fn new(queue: ReceiveQueueOf<E>, initial: Option<RegistrationOf<E>>) -> Self {
        Self {
            queue,
            initial,
            first_local: None,
        }
    }

    /// A poster to the receiver's queue, for the deliverer of a new entry.
    pub(crate) fn poster(&self) -> ReceivePosterOf<E> {
        self.queue.poster()
    }

    /// Keeps the entry of the first local connection ID.
    pub(crate) fn keep_first_local(&mut self, registration: FirstLocalRegistration<E>) {
        self.first_local = Some(registration);
    }
}

impl<E: EndpointChoices> LogicalPathDatagramReceiver<LinkOf<E>> for ConnectionDatagramReceiver<E> {
    type Handoff = HandoffOf<E>;
    type ClaimLock = ClaimLockOf<E>;

    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<DeliveryOf<E>> {
        self.queue.poll_recv(cx)
    }
}

impl<E: EndpointChoices> fmt::Debug for ConnectionDatagramReceiver<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionDatagramReceiver")
            .field("initial", &self.initial.is_some())
            .field("first_local", &self.first_local.is_some())
            .finish()
    }
}
