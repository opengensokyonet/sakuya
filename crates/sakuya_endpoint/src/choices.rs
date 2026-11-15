//! What an endpoint is composed with, and the types of its routing domain
//! that follow from it.

use core::{
    fmt,
    task::{Context, Poll},
};
use std::sync::Arc;

use nitori_crypto::Random;
use sakuya_clock::MonotonicClock;
use sakuya_connection::v1::{
    input::LogicalPathDatagramReceiver, stateless_reset::StatelessResetSignal,
};
use sakuya_datagram_routing::{
    claim::{
        deliverer::DatagramDeliverer,
        delivery::DatagramDelivery,
        queue::{DatagramDeliveryPoster, DatagramDeliveryQueue},
    },
    route::{
        acceptance::{ReflowHandoff, UnclaimedWork},
        index::RouteEntryRegistration,
        recognizer::{ConnectionIdGenerator, ConnectionIdRecognizer},
        reset::StatelessResetTokens,
    },
};
use sakuya_link::ReceivedDatagram;
use sakuya_packet_protection::backend::CryptoBackend;

use crate::{
    link::{EndpointLink, sum::LinkSum},
    zero_length::ZeroLengthRegistration,
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
    type WallClock: sakuya_tls::clock::Clock;
    /// What generates the connection IDs of each connection; the endpoint
    /// keeps its configuration and makes one generator for each
    /// connection.
    type ConnectionIds: ConnectionIdGenerator;
    /// What tells the lengths of the destination connection IDs of short
    /// headers, by the encoding the connection ID generator uses.
    type Recognizer: ConnectionIdRecognizer<LocalOf<Self>, PeerOf<Self>>;
}

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
pub(crate) type ReflowPosterOf<E> = DatagramDeliveryPoster<WorkOf<E>>;
/// What takes over a datagram every candidate left, in the routing domain of
/// an endpoint of the choices `E`.
pub type HandoffOf<E> = ReflowHandoff<ReflowPosterOf<E>, LocalOf<E>>;
/// What routing gives a deliverer of an endpoint of the choices `E`.
pub type DeliveryOf<E> = DatagramDelivery<DatagramOf<E>, LocalOf<E>, HandoffOf<E>>;
/// A route entry the endpoint registered for a connection.
pub(crate) type RegistrationOf<E> = RouteEntryRegistration<EndpointDeliverer<E>, LocalOf<E>>;
/// The table of the peers' stateless reset tokens of an endpoint of the
/// choices `E`, shared by its routing, which detects resets, and its
/// connections, which register the tokens.
pub type ResetTokensOf<E> = Arc<StatelessResetTokens<PeerOf<E>, Arc<StatelessResetSignal>>>;

/// The deliverer of every route entry of an endpoint: it posts each delivery
/// to the datagram receiver of one connection.
///
/// It holds only a weak poster: once the connection's receiver is gone,
/// deliveries are dropped where they are posted.
#[doc(hidden)]
pub struct EndpointDeliverer<E: EndpointChoices> {
    poster: DatagramDeliveryPoster<DeliveryOf<E>>,
}

impl<E: EndpointChoices> EndpointDeliverer<E> {
    pub(crate) fn new(poster: DatagramDeliveryPoster<DeliveryOf<E>>) -> Self {
        Self { poster }
    }
}

impl<E: EndpointChoices> DatagramDeliverer<DatagramOf<E>, LocalOf<E>> for EndpointDeliverer<E> {
    type Handoff = HandoffOf<E>;

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
/// the [`Receiver`](sakuya_connection::v1::Choices::Receiver) of its
/// connections' choices.
///
/// It is the delivery queue its route entries post to, and it holds those
/// entries: the one under the client's first destination connection ID, for
/// a server, and, until the connection has a local connection ID strategy
/// that issues connection IDs and keeps their entries, the entry of the
/// first local connection ID. They are revoked when the receiver is
/// dropped, with the connection's first logical path.
pub struct ConnectionDatagramReceiver<E: EndpointChoices> {
    queue: DatagramDeliveryQueue<DeliveryOf<E>>,
    initial: Option<RegistrationOf<E>>,
    first_local: Option<FirstLocalRegistration<E>>,
}

/// The route entry of a connection's first local connection ID.
pub(crate) enum FirstLocalRegistration<E: EndpointChoices> {
    /// A non-empty connection ID, or the zero-length one of a generator of
    /// zero-length connection IDs.
    Issued(
        #[expect(dead_code, reason = "held for the entry to stay registered")] RegistrationOf<E>,
    ),
    /// The zero-length connection ID, with the occupancy of its local end.
    ZeroLength(ZeroLengthRegistration<RegistrationOf<E>, LocalOf<E>>),
}

impl<E: EndpointChoices> ConnectionDatagramReceiver<E> {
    pub(crate) fn new(
        queue: DatagramDeliveryQueue<DeliveryOf<E>>,
        initial: Option<RegistrationOf<E>>,
    ) -> Self {
        Self {
            queue,
            initial,
            first_local: None,
        }
    }

    /// A poster to the receiver's queue, for the deliverer of a new entry.
    pub(crate) fn poster(&self) -> DatagramDeliveryPoster<DeliveryOf<E>> {
        self.queue.poster()
    }

    /// Keeps the entry of the first local connection ID.
    pub(crate) fn keep_first_local(&mut self, registration: FirstLocalRegistration<E>) {
        self.first_local = Some(registration);
    }
}

impl<E: EndpointChoices> LogicalPathDatagramReceiver<LinkOf<E>> for ConnectionDatagramReceiver<E> {
    type Handoff = HandoffOf<E>;

    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<DeliveryOf<E>> {
        self.queue.poll_recv(cx)
    }
}

impl<E: EndpointChoices> fmt::Debug for ConnectionDatagramReceiver<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionDatagramReceiver")
            .field("queue", &self.queue)
            .field("initial", &self.initial.is_some())
            .field("first_local", &self.first_local.is_some())
            .finish()
    }
}
