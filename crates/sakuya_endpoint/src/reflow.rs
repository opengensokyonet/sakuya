//! The reflow driver: where the datagrams no connection claims are handled,
//! new connections are born, and the endpoint answers without a connection.

use core::{
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use std::sync::Arc;

use bytes::Bytes;
use futures_util::StreamExt as _;
use sakuya_datagram_routing::claim::queue::DatagramDeliveryQueue;
use sakuya_link::{EcnMarking, Link, OutgoingDatagram};
use sakuya_tls::clock::Clock as _;

use crate::{
    address_token::TokenPeerAddress,
    choices::{EndpointChoices, LinkOf, WorkOf},
    domain::Domain,
    incoming::{IncomingShared, TerminableIncoming},
    late_initial::LateInitial,
    role::{AcceptingServerRole, ServerRole},
    send_set::BoundedSendSet,
    stateless_check::{
        FirstDatagramOutcome, IncomingLoad, LateInitialOutcome, ReleaseReason, StatelessCheck,
    },
    version_negotiation::{
        PendingVersionNegotiation, VersionNegotiationQueue, encode_version_negotiation,
    },
};

/// How many inputs of one kind the reflow driver handles in one poll before
/// it lets its task go on with other work.
const INPUTS_PER_POLL: usize = 64;

/// The reflow driver of an endpoint: it takes the datagrams that no
/// connection claims and that may start one, answers them with a stateless
/// Retry or close where it should, and otherwise makes an incoming
/// connection of them for the application; it answers datagrams of
/// unsupported versions with Version Negotiation packets.
///
/// It is a future the host spawns, made once with the endpoint. It ends when
/// the endpoint has been closed and no registration is left in its routing
/// domain, that is when every connection is over. Dropped before then, the
/// endpoint offers no new connections and answers nothing more, while its
/// connections and bindings go on.
#[must_use = "an endpoint takes no new connections unless its reflow driver is polled"]
pub struct ReflowDriver<E: EndpointChoices, S: ServerRole<E>> {
    domain: Arc<Domain<E>>,
    steps: S::Reflow,
}

impl<E: EndpointChoices, S: ServerRole<E>> ReflowDriver<E, S> {
    pub(crate) fn new(domain: Arc<Domain<E>>, steps: S::Reflow) -> Self {
        Self { domain, steps }
    }
}

/// The driver never pins its steps: it only lends them for each poll.
impl<E: EndpointChoices, S: ServerRole<E>> Unpin for ReflowDriver<E, S> {}

impl<E: EndpointChoices, S: ServerRole<E>> Future for ReflowDriver<E, S> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        this.steps.poll_steps(&this.domain, cx);
        match this.domain.poll_closed(cx) {
            Poll::Ready(()) => this.domain.router.index().poll_empty(cx),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<E: EndpointChoices, S: ServerRole<E>> fmt::Debug for ReflowDriver<E, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReflowDriver")
            .field("domain", &self.domain)
            .finish_non_exhaustive()
    }
}

/// The queues routing fills for the reflow driver.
#[doc(hidden)]
pub struct ReflowQueues<E: EndpointChoices> {
    /// The datagrams no connection claimed that may start one.
    pub(crate) unclaimed: DatagramDeliveryQueue<WorkOf<E>>,
    /// The Version Negotiation responses to send.
    pub(crate) version_negotiation: VersionNegotiationQueue<LinkOf<E>>,
}

impl<E: EndpointChoices> fmt::Debug for ReflowQueues<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReflowQueues").finish_non_exhaustive()
    }
}

/// What the reflow driver does for a server role.
#[doc(hidden)]
pub trait ReflowSteps<E: EndpointChoices> {
    /// Handles what is queued, and arranges for the task of `cx` to be woken
    /// when more is.
    fn poll_steps(&mut self, domain: &Arc<Domain<E>>, cx: &mut Context<'_>);
}

/// The reflow of an endpoint without a server role: it drops what routing
/// queues.
#[doc(hidden)]
pub struct NoServerReflow<E: EndpointChoices> {
    queues: ReflowQueues<E>,
}

impl<E: EndpointChoices> NoServerReflow<E> {
    pub(crate) fn new(queues: ReflowQueues<E>) -> Self {
        Self { queues }
    }
}

impl<E: EndpointChoices> ReflowSteps<E> for NoServerReflow<E> {
    fn poll_steps(&mut self, _: &Arc<Domain<E>>, cx: &mut Context<'_>) {
        // A domain without a server role offers no new connection, so the
        // first queue stays empty; datagrams of unsupported versions are
        // answered by servers only (RFC 9000 §6.1).
        while let Poll::Ready(work) = self.queues.unclaimed.poll_recv(cx) {
            drop(work);
        }
        while let Poll::Ready(pending) = self.queues.version_negotiation.poll_pop(cx) {
            drop(pending);
        }
    }
}

impl<E: EndpointChoices> fmt::Debug for NoServerReflow<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoServerReflow").finish_non_exhaustive()
    }
}

/// Sends one datagram the endpoint answers with, on a link.
#[doc(hidden)]
pub trait Respond<L> {
    /// The send.
    type Send: Future<Output = ()>;

    /// Sends `payload` on `link`; a send that fails or is dropped is lost.
    fn respond(link: L, payload: Bytes) -> Self::Send;
}

/// The responses of an endpoint.
#[doc(hidden)]
#[derive(Debug)]
pub enum Responses {}

impl<L: Link + 'static> Respond<L> for Responses {
    type Send = impl Future<Output = ()>;

    fn respond(link: L, payload: Bytes) -> Self::Send {
        async move {
            let batch = [OutgoingDatagram {
                payload,
                ecn: EcnMarking::NotEct,
            }];
            // A response that is not sent is as if it were lost: the
            // client sends its Initial again.
            let _ = link.send(&batch).await;
        }
    }
}

/// A response being sent on a link of an endpoint of the choices `E`.
type ResponseOf<E> = <Responses as Respond<LinkOf<E>>>::Send;

/// The stateless checks of a server endpoint, with the components of the
/// role `S`.
type CheckOf<E, S> = StatelessCheck<
    <S as AcceptingServerRole<E>>::Tokens,
    <S as AcceptingServerRole<E>>::RetryPolicy,
    <E as EndpointChoices>::Crypto,
    <E as EndpointChoices>::ConnectionIds,
>;

/// The reflow of an endpoint with the server role `S`.
#[doc(hidden)]
pub struct ServerReflow<E: EndpointChoices, S: AcceptingServerRole<E>> {
    shared: Arc<IncomingShared<E, S>>,
    queues: ReflowQueues<E>,
    check: CheckOf<E, S>,
    retry_sends: BoundedSendSet<ResponseOf<E>>,
    version_negotiation_sends: BoundedSendSet<ResponseOf<E>>,
}

impl<E: EndpointChoices, S: AcceptingServerRole<E>> ServerReflow<E, S> {
    pub(crate) fn new(
        shared: Arc<IncomingShared<E, S>>,
        domain: &Arc<Domain<E>>,
        queues: ReflowQueues<E>,
    ) -> Self {
        let config = shared.config();
        let quotas = config.quotas;
        let check = StatelessCheck::new(
            config.tokens.clone(),
            config.retry_policy.clone(),
            domain.crypto.clone(),
            domain.connection_ids.clone(),
            &quotas,
        );
        Self {
            shared,
            queues,
            check,
            retry_sends: BoundedSendSet::new(quotas.retry_send_set_capacity),
            version_negotiation_sends: BoundedSendSet::new(
                quotas.version_negotiation_send_set_capacity,
            ),
        }
    }

    /// Handles one datagram no connection claimed.
    fn unclaimed(&mut self, domain: &Arc<Domain<E>>, work: WorkOf<E>) {
        if !domain.births.is_offering() {
            return;
        }
        let datagram = work.datagram();
        let peer = self
            .check
            .tokens()
            .peer_socket_addr(&datagram.link().id().peer);
        let load = self.shared.load();
        let outcome = self.check.first_datagram(
            datagram.payload().as_ref(),
            peer,
            load,
            domain.wall_clock.now(),
        );
        match outcome {
            FirstDatagramOutcome::Admit(admitted) => {
                if load.waiting >= self.shared.capacity() {
                    self.shared.count_incoming_queue_full();
                    return;
                }
                domain.router.resume(work);
                if let Some(born) = domain.births.take_born() {
                    let half = TerminableIncoming::born(
                        domain,
                        self.shared.config(),
                        self.shared.late(),
                        born,
                        admitted,
                    );
                    self.shared.push(half);
                }
            }
            FirstDatagramOutcome::SendRetry(packet)
            | FirstDatagramOutcome::SendInvalidTokenClose(packet) => {
                let link = work.datagram().link().clone();
                drop(work);
                if self
                    .retry_sends
                    .try_push(Responses::respond(link, packet))
                    .is_err()
                {
                    self.shared.count_retry_send_set_full();
                }
            }
            FirstDatagramOutcome::Release(reason) => {
                if reason == ReleaseReason::ZeroRttIncomingLimitReached {
                    self.shared.count_zero_rtt_incoming_limit_reached();
                }
                drop(work);
            }
        }
    }

    /// Checks an Initial that arrived late for an incoming connection born
    /// from 0-RTT.
    fn late_initial(&mut self, domain: &Arc<Domain<E>>, late: LateInitial<E>) {
        let LateInitial { datagram, reply } = late;
        let peer = self
            .check
            .tokens()
            .peer_socket_addr(&datagram.link().id().peer);
        match self
            .check
            .late_initial(datagram.payload().as_ref(), peer, domain.wall_clock.now())
        {
            LateInitialOutcome::Admit(token) => reply.answer(Some((token, datagram))),
            LateInitialOutcome::SendInvalidTokenClose(packet) => {
                let link = datagram.link().clone();
                drop(datagram);
                reply.answer(None);
                if self
                    .retry_sends
                    .try_push(Responses::respond(link, packet))
                    .is_err()
                {
                    self.shared.count_retry_send_set_full();
                }
            }
            LateInitialOutcome::Release(_) => reply.answer(None),
        }
    }

    /// Answers one datagram of an unsupported version.
    fn version_negotiation(
        &mut self,
        domain: &Arc<Domain<E>>,
        pending: PendingVersionNegotiation<LinkOf<E>>,
    ) {
        let offered = domain.offered_versions(&pending.link.id().binding);
        let Ok(packet) = encode_version_negotiation(
            &pending.client_dcid,
            &pending.client_scid,
            pending.client_version,
            &offered,
            &domain.random,
        ) else {
            // The random source failed: this response is not sent, as if
            // it were lost.
            return;
        };
        if self
            .version_negotiation_sends
            .try_push(Responses::respond(pending.link, packet))
            .is_err()
        {
            self.shared.count_version_negotiation_send_set_full();
        }
    }
}

impl<E: EndpointChoices, S: AcceptingServerRole<E>> ReflowSteps<E> for ServerReflow<E, S> {
    fn poll_steps(&mut self, domain: &Arc<Domain<E>>, cx: &mut Context<'_>) {
        let mut busy = false;
        for handled in 0.. {
            if handled == INPUTS_PER_POLL {
                busy = true;
                break;
            }
            match self.queues.unclaimed.poll_recv(cx) {
                Poll::Ready(work) => self.unclaimed(domain, work),
                Poll::Pending => break,
            }
        }
        for handled in 0.. {
            if handled == INPUTS_PER_POLL {
                busy = true;
                break;
            }
            match self.queues.version_negotiation.poll_pop(cx) {
                Poll::Ready(pending) => self.version_negotiation(domain, pending),
                Poll::Pending => break,
            }
        }
        for handled in 0.. {
            if handled == INPUTS_PER_POLL {
                busy = true;
                break;
            }
            match self.shared.late().poll_pop(cx) {
                Poll::Ready(late) => self.late_initial(domain, late),
                Poll::Pending => break,
            }
        }
        self.shared
            .set_version_negotiation_queue_dropped(self.queues.version_negotiation.dropped());
        while let Poll::Ready(Some(())) = self.retry_sends.poll_next_unpin(cx) {}
        while let Poll::Ready(Some(())) = self.version_negotiation_sends.poll_next_unpin(cx) {}
        if busy {
            cx.waker().wake_by_ref();
        }
    }
}

impl<E: EndpointChoices, S: AcceptingServerRole<E>> Drop for ServerReflow<E, S> {
    /// Without its reflow driver the endpoint offers no new connection, and
    /// the application's incoming streams end.
    fn drop(&mut self) {
        self.shared.end();
    }
}

impl<E: EndpointChoices, S: AcceptingServerRole<E>> fmt::Debug for ServerReflow<E, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerReflow")
            .field("check", &self.check)
            .field("retry_sends", &self.retry_sends)
            .field("version_negotiation_sends", &self.version_negotiation_sends)
            .finish_non_exhaustive()
    }
}

/// The load of the incoming queue, for the stateless Retry policy.
pub(crate) fn load(waiting: usize, waiting_born_from_zero_rtt: usize) -> IncomingLoad {
    IncomingLoad {
        waiting,
        waiting_born_from_zero_rtt,
    }
}
