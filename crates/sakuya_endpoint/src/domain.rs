//! The routing domain of an endpoint: its router, and what its bindings,
//! its reflow driver and its incoming and outgoing connections share.

use core::{
    fmt,
    num::NonZeroUsize,
    task::{Context, Poll, Waker},
};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
};

use sakuya_datagram_routing::{
    claim::{delivery::ExclusiveDatagram, queue::DatagramDeliveryQueue},
    route::{
        acceptance::{
            InitialAcceptance, InitialDatagramReceiver, InitialReceiverFactory, PreparedReceiver,
        },
        association::{MatchAssociation, PacketForms, RouteMatcher},
        interpretation::RecognizedInitial,
        recognizer::ConnectionIdGenerator,
        router::DatagramRouter,
    },
};
use sakuya_link::BindingId;
use sakuya_wire::version::Version;

use crate::{
    binding::driving::{RouteDatagram, StopSignal},
    choices::{
        ConnectionDatagramReceiver, DatagramOf, DeliveryOf, EndpointChoices, EndpointDeliverer,
        LinkOf, LocalOf, PayloadOf, ReflowPosterOf, RegistrationOf, ResetTokensOf,
    },
    config::BindingDeclarations,
    version_negotiation::NegotiatingVersionService,
    zero_length::{ZeroLengthLocalRecognizer, ZeroLengthLocals},
};

/// The router of an endpoint of the choices `E`.
pub(crate) type RouterOf<E> = DatagramRouter<
    PayloadOf<E>,
    LinkOf<E>,
    EndpointDeliverer<E>,
    ZeroLengthLocalRecognizer<<E as EndpointChoices>::Recognizer, LocalOf<E>>,
    ResetTokensOf<E>,
    NegotiatingVersionService<LinkOf<E>>,
    InitialAcceptance<BirthFactory<E>, ReflowPosterOf<E>>,
>;

/// What the bindings, the reflow driver and the incoming and outgoing
/// connections of one endpoint share.
#[doc(hidden)]
pub struct Domain<E: EndpointChoices> {
    pub(crate) router: RouterOf<E>,
    pub(crate) reset_tokens: ResetTokensOf<E>,
    pub(crate) zero_length: Arc<ZeroLengthLocals<LocalOf<E>>>,
    pub(crate) births: Arc<Births<E>>,
    pub(crate) connection_ids: <E::ConnectionIds as ConnectionIdGenerator>::Config,
    pub(crate) crypto: E::Crypto,
    pub(crate) random: E::Random,
    pub(crate) clock: E::Clock,
    pub(crate) wall_clock: E::WallClock,
    /// The versions a server offers on a binding that declares none.
    pub(crate) offered_versions: Vec<Version>,
    closed: AtomicBool,
    close_wakers: Mutex<Vec<Waker>>,
    declarations: Mutex<HashMap<BindingId, BindingDeclarations>>,
}

/// The parts of a domain other than its router and its births.
pub(crate) struct DomainParts<E: EndpointChoices> {
    pub(crate) reset_tokens: ResetTokensOf<E>,
    pub(crate) zero_length: Arc<ZeroLengthLocals<LocalOf<E>>>,
    pub(crate) connection_ids: <E::ConnectionIds as ConnectionIdGenerator>::Config,
    pub(crate) crypto: E::Crypto,
    pub(crate) random: E::Random,
    pub(crate) clock: E::Clock,
    pub(crate) wall_clock: E::WallClock,
    pub(crate) offered_versions: Vec<Version>,
}

impl<E: EndpointChoices> Domain<E> {
    pub(crate) fn new(router: RouterOf<E>, births: Arc<Births<E>>, parts: DomainParts<E>) -> Self {
        Self {
            router,
            reset_tokens: parts.reset_tokens,
            zero_length: parts.zero_length,
            births,
            connection_ids: parts.connection_ids,
            crypto: parts.crypto,
            random: parts.random,
            clock: parts.clock,
            wall_clock: parts.wall_clock,
            offered_versions: parts.offered_versions,
            closed: AtomicBool::new(false),
            close_wakers: Mutex::new(Vec::new()),
            declarations: Mutex::new(HashMap::new()),
        }
    }

    /// Whether the endpoint has been closed.
    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Closes the endpoint: the domain offers no new connection, and every
    /// driver waiting for the close is woken.
    pub(crate) fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.births.stop_offering();
        let wakers = core::mem::take(&mut *lock(&self.close_wakers));
        for waker in wakers {
            waker.wake();
        }
    }

    /// Ready once the endpoint has been closed; otherwise arranges for the
    /// task of `cx` to be woken when it is.
    pub(crate) fn poll_closed(&self, cx: &mut Context<'_>) -> Poll<()> {
        if self.is_closed() {
            return Poll::Ready(());
        }
        {
            let mut wakers = lock(&self.close_wakers);
            if !wakers.iter().any(|waker| waker.will_wake(cx.waker())) {
                wakers.push(cx.waker().clone());
            }
        }
        if self.is_closed() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    /// Records the declarations of the binding `id`.
    pub(crate) fn declare(&self, id: BindingId, declarations: BindingDeclarations) {
        lock(&self.declarations).insert(id, declarations);
    }

    /// Whether the binding `id` declared that its transport validates the
    /// peer's address.
    pub(crate) fn transport_validated(&self, id: &BindingId) -> bool {
        lock(&self.declarations)
            .get(id)
            .is_some_and(|declarations| declarations.transport_validated)
    }

    /// The versions a Version Negotiation packet sent on the binding `id`
    /// lists.
    pub(crate) fn offered_versions(&self, id: &BindingId) -> Vec<Version> {
        lock(&self.declarations)
            .get(id)
            .and_then(|declarations| declarations.offered_versions.clone())
            .unwrap_or_else(|| self.offered_versions.clone())
    }

    /// Registers a route entry of version 1 under `association`, delivering
    /// to `receiver`.
    pub(crate) fn register(
        &self,
        association: MatchAssociation<LocalOf<E>>,
        receiver: &ConnectionDatagramReceiver<E>,
    ) -> RegistrationOf<E> {
        self.router.index().register(
            RouteMatcher::new(association, PacketForms::ALL, Version::V1),
            Arc::new(EndpointDeliverer::new(receiver.poster())),
        )
    }
}

impl<E: EndpointChoices> fmt::Debug for Domain<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Domain")
            .field("closed", &self.is_closed())
            .field("registrations", &self.router.index().registration_count())
            .finish_non_exhaustive()
    }
}

/// A binding driver hands each datagram to the domain's router.
impl<E: EndpointChoices> RouteDatagram<DatagramOf<E>> for Arc<Domain<E>> {
    fn route(&self, datagram: DatagramOf<E>) {
        self.router.route(datagram);
    }
}

/// A binding driver ends once the endpoint has been closed and no
/// registration is left in its domain.
impl<E: EndpointChoices> StopSignal for Arc<Domain<E>> {
    fn poll_stop(&self, cx: &mut Context<'_>) -> Poll<()> {
        match self.poll_closed(cx) {
            Poll::Ready(()) => self.router.index().poll_empty(cx),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// The receivers routing publishes for new connections, as the reflow
/// driver resumes unclaimed work.
#[doc(hidden)]
pub struct Births<E: EndpointChoices> {
    /// Whether the domain offers to create connections.
    offering: AtomicBool,
    /// The capacity of a new receiver's queue.
    receive_queue_capacity: NonZeroUsize,
    /// The receiver routing published in the round being resumed, with its
    /// first datagram.
    born: Mutex<Option<Born<E>>>,
}

/// A receiver routing published for a new connection, with the datagram
/// that made it.
pub(crate) struct Born<E: EndpointChoices> {
    pub(crate) receiver: ConnectionDatagramReceiver<E>,
    pub(crate) datagram: DatagramOf<E>,
    pub(crate) initial: RecognizedInitial<LocalOf<E>>,
}

impl<E: EndpointChoices> Births<E> {
    pub(crate) fn new(receive_queue_capacity: NonZeroUsize) -> Self {
        Self {
            offering: AtomicBool::new(false),
            receive_queue_capacity,
            born: Mutex::new(None),
        }
    }

    /// Whether the domain offers to create connections now.
    pub(crate) fn set_offering(&self, offering: bool) {
        self.offering.store(offering, Ordering::Release);
    }

    pub(crate) fn stop_offering(&self) {
        self.set_offering(false);
    }

    pub(crate) fn is_offering(&self) -> bool {
        self.offering.load(Ordering::Acquire)
    }

    /// The receiver published in the round just resumed, if one was.
    pub(crate) fn take_born(&self) -> Option<Born<E>> {
        lock(&self.born).take()
    }
}

impl<E: EndpointChoices> fmt::Debug for Births<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Births")
            .field("offering", &self.is_offering())
            .finish_non_exhaustive()
    }
}

/// Prepares the receivers of new connections for routing.
#[doc(hidden)]
pub struct BirthFactory<E: EndpointChoices> {
    births: Arc<Births<E>>,
}

impl<E: EndpointChoices> BirthFactory<E> {
    pub(crate) fn new(births: Arc<Births<E>>) -> Self {
        Self { births }
    }
}

impl<E: EndpointChoices> fmt::Debug for BirthFactory<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BirthFactory").finish_non_exhaustive()
    }
}

impl<E: EndpointChoices> InitialReceiverFactory<PayloadOf<E>, LinkOf<E>, EndpointDeliverer<E>>
    for BirthFactory<E>
{
    type Receiver = PreparedBirth<E>;

    /// The checks of the datagram itself are the reflow driver's, which
    /// answers with a Retry or a close where the protocol asks it to.
    fn admits(&self, _: &RecognizedInitial<LocalOf<E>>, _: &DatagramOf<E>) -> bool {
        self.births.is_offering()
    }

    fn prepare(
        &self,
        _: &RecognizedInitial<LocalOf<E>>,
    ) -> Option<PreparedReceiver<EndpointDeliverer<E>, PreparedBirth<E>>> {
        let queue =
            DatagramDeliveryQueue::<DeliveryOf<E>>::new(self.births.receive_queue_capacity).ok()?;
        let deliverer = Arc::new(EndpointDeliverer::new(queue.poster()));
        Some(PreparedReceiver::new(
            deliverer,
            PreparedBirth {
                queue,
                births: Arc::clone(&self.births),
            },
        ))
    }
}

/// The receiver of a new connection before routing published its entry.
#[doc(hidden)]
pub struct PreparedBirth<E: EndpointChoices> {
    queue: DatagramDeliveryQueue<DeliveryOf<E>>,
    births: Arc<Births<E>>,
}

impl<E: EndpointChoices> InitialDatagramReceiver<PayloadOf<E>, LinkOf<E>, EndpointDeliverer<E>>
    for PreparedBirth<E>
{
    fn receive_first(
        self,
        registration: RegistrationOf<E>,
        datagram: ExclusiveDatagram<DatagramOf<E>>,
        initial: RecognizedInitial<LocalOf<E>>,
    ) {
        let born = Born {
            receiver: ConnectionDatagramReceiver::new(self.queue, Some(registration)),
            datagram: datagram.into_inner(),
            initial,
        };
        *lock(&self.births.born) = Some(born);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
