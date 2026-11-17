//! What an incoming connection hands off for passthrough forwarding: the
//! server neither accepts it nor answers it, and forwards the client's
//! datagrams to another server as they are.
//!
//! A server that may hand connections off reads each first ClientHello
//! before deciding, with a digest of the first flight kept
//! ([`keep_first_flight_digest`](crate::config::ServerConfig::keep_first_flight_digest)).
//! Reading opens the Initial packets in place, so the datagrams read are not
//! kept: [`PassthroughHandoff`] gives what it takes to build them again
//! instead, and the receiver that takes the client's later datagrams as
//! they arrive. Building them, and forwarding, are the host's.

use core::{fmt, future::poll_fn};
use std::sync::{Arc, Mutex, PoisonError};

use sakuya_connection::v1::{
    first_flight::FirstFlightDigest, input::LogicalPathDatagramReceiver as _,
};
use sakuya_datagram_routing::{
    claim::{
        candidate::{DatagramClaimAttempt, DatagramClaimOutcome},
        delivery::DatagramDelivery,
        queue::DatagramDeliveryPoster,
    },
    route::association::MatchAssociation,
};
use sakuya_link::{Link as _, LinkId};
use sakuya_tls::server::engine::FirstClientHello;
use sakuya_wire::{
    connection_id::{ConnectionId, NonEmptyCid},
    header::codec::read_long_header,
    version::Version,
};

use crate::{
    choices::{
        ConnectionDatagramReceiver, DatagramOf, DeliveryOf, EndpointChoices, LinkOf, LocalOf,
        PayloadOf, PeerOf, RegistrationOf,
    },
    domain::Domain,
};

/// The identity of a link of an endpoint of the choices `E`.
type LinkIdOf<E> = LinkId<LocalOf<E>, PeerOf<E>>;

/// What an incoming connection hands off for passthrough forwarding, from
/// [`TerminableIncoming::into_passthrough_handoff`](crate::incoming::TerminableIncoming::into_passthrough_handoff).
///
/// The first flight was read: its Initial packets are given as the
/// [`digest`](Self::digest), with the first ClientHello their CRYPTO data
/// was, and its 0-RTT packets as they arrived. With the connection IDs and
/// the version, and the Initial keys derived from the client's first
/// destination connection ID (RFC 9001 §5.2), each Initial packet can be
/// built again with the same packet number, size and CRYPTO data.
pub struct PassthroughHandoff<E: EndpointChoices> {
    /// The link the first datagram arrived on, to the client.
    pub link: LinkOf<E>,
    /// The version of the first packet.
    pub version: Version,
    /// The Destination Connection ID of the client's first Initial packet.
    pub client_dcid: ConnectionId,
    /// The client's Source Connection ID.
    pub client_scid: ConnectionId,
    /// The first ClientHello.
    pub client_hello: FirstClientHello,
    /// The digest of the first flight.
    pub digest: FirstFlightDigest,
    /// The 0-RTT packets of the first flight, as they arrived, in the order
    /// the digest gives their indices in.
    pub zero_rtt: Vec<PayloadOf<E>>,
    /// The receiver of the client's later datagrams.
    pub receiver: PassthroughReceiver<E>,
}

impl<E: EndpointChoices> fmt::Debug for PassthroughHandoff<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PassthroughHandoff")
            .field("version", &self.version)
            .field("client_dcid", &self.client_dcid)
            .field("client_scid", &self.client_scid)
            .field("digest", &self.digest)
            .field("zero_rtt", &self.zero_rtt.len())
            .finish_non_exhaustive()
    }
}

/// The receiver of the datagrams of a connection handed off for passthrough
/// forwarding.
///
/// It keeps the registration under the client's first destination
/// connection ID, and those its [`PassthroughRegistrar`] adds; dropping it
/// revokes them all.
pub struct PassthroughReceiver<E: EndpointChoices> {
    receiver: ConnectionDatagramReceiver<E>,
    client: LinkIdOf<E>,
    client_scid: ConnectionId,
    registrar: PassthroughRegistrar<E>,
}

impl<E: EndpointChoices> PassthroughReceiver<E> {
    /// The receiver of the client's datagrams over `client`, whose source
    /// connection ID is `client_scid`.
    pub(crate) fn new(
        domain: Arc<Domain<E>>,
        receiver: ConnectionDatagramReceiver<E>,
        client: LinkIdOf<E>,
        client_scid: ConnectionId,
    ) -> Self {
        let registrar = PassthroughRegistrar {
            domain,
            poster: receiver.poster(),
            registrations: Arc::new(Mutex::new(Some(Vec::new()))),
        };
        Self {
            receiver,
            client,
            client_scid,
            registrar,
        }
    }

    /// What registers more connection IDs for this receiver, while it is
    /// there.
    pub fn registrar(&self) -> PassthroughRegistrar<E> {
        self.registrar.clone()
    }

    /// The next datagram of the connection.
    ///
    /// A datagram routing gives this receiver alone is taken as it is. One
    /// that others may take too, as routing gives each datagram that may
    /// start a connection, is taken only when it came over the client's
    /// link and its first packet is a long header with the client's source
    /// connection ID, as the client's later Initial and 0-RTT packets are;
    /// others are left to the other candidates, and to a new connection.
    pub async fn recv(&mut self) -> DatagramOf<E> {
        loop {
            let candidate = match poll_fn(|cx| self.receiver.poll_next(cx)).await {
                DatagramDelivery::Exclusive(delivery) => return delivery.consume().0.into_inner(),
                DatagramDelivery::Competing(candidate) => candidate,
            };
            let (client, scid) = (&self.client, self.client_scid);
            let attempt = candidate
                .try_exclusive(|access, _| {
                    let datagram = access.datagram();
                    if datagram.link().id() == client
                        && long_header_scid(datagram.payload().as_ref()) == Some(scid)
                    {
                        DatagramClaimOutcome::Claimed(access.into_exclusive(), ())
                    } else {
                        DatagramClaimOutcome::Abandoned(())
                    }
                })
                .await;
            match attempt {
                DatagramClaimAttempt::Claimed(delivery, ())
                | DatagramClaimAttempt::Exclusive(delivery) => {
                    return delivery.consume().0.into_inner();
                }
                _ => {}
            }
        }
    }
}

impl<E: EndpointChoices> Drop for PassthroughReceiver<E> {
    fn drop(&mut self) {
        let registrations = self
            .registrar
            .registrations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        drop(registrations);
    }
}

impl<E: EndpointChoices> fmt::Debug for PassthroughReceiver<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PassthroughReceiver")
            .field("client_scid", &self.client_scid)
            .finish_non_exhaustive()
    }
}

/// What registers connection IDs for a [`PassthroughReceiver`], apart from
/// it, so that registering does not wait for a datagram being received.
pub struct PassthroughRegistrar<E: EndpointChoices> {
    domain: Arc<Domain<E>>,
    poster: DatagramDeliveryPoster<DeliveryOf<E>>,
    /// The registrations, `None` once the receiver was dropped.
    registrations: Arc<Mutex<Option<Vec<RegistrationOf<E>>>>>,
}

impl<E: EndpointChoices> PassthroughRegistrar<E> {
    /// Registers `cid` as a local connection ID for the receiver: the
    /// datagrams sent to it come there, until the receiver is dropped. Once
    /// it was, this does nothing.
    pub fn register(&self, cid: NonEmptyCid) {
        let mut registrations = self
            .registrations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(registrations) = registrations.as_mut() {
            registrations.push(
                self.domain
                    .register_posting(MatchAssociation::LocalCid(cid), self.poster.clone()),
            );
        }
    }
}

impl<E: EndpointChoices> Clone for PassthroughRegistrar<E> {
    fn clone(&self) -> Self {
        Self {
            domain: Arc::clone(&self.domain),
            poster: self.poster.clone(),
            registrations: Arc::clone(&self.registrations),
        }
    }
}

impl<E: EndpointChoices> fmt::Debug for PassthroughRegistrar<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PassthroughRegistrar")
            .finish_non_exhaustive()
    }
}

/// The source connection ID of the first packet of the datagram `bytes`
/// when it is a long header of QUIC version 1.
fn long_header_scid(mut bytes: &[u8]) -> Option<ConnectionId> {
    if bytes.first()? & 0x80 == 0 {
        return None;
    }
    let header = read_long_header(&mut bytes).ok()?;
    if header.version() != Version::V1 {
        return None;
    }
    ConnectionId::try_from(*header.scid()).ok()
}
