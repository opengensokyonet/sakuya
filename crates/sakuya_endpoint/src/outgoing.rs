//! The outgoing connections a client endpoint gives the application.
//!
//! A binding handle's `connect` takes a link and gives an [`Outgoing`]: the
//! link, the name of the server, and a clone of the client configuration,
//! which the application may change. [`Outgoing::start`] then registers the
//! connection's first local connection ID and makes the connection.

use core::fmt;
use std::sync::Arc;

use nitori_crypto::Random as _;
use sakuya_connection::{
    call::{CallPositions, TreeCalls},
    driver::ConnectionDriver,
    share::LineageLists,
    v1::{
        self as connection, advancing::HandshakeStart, amplification::AddressValidation,
        close_request::CloseRequestCell, first_flight::FirstFlight, input::InitialPathReceiver,
        link::LinkFacts,
    },
};
use sakuya_datagram_routing::claim::queue::DatagramDeliveryQueue;
use sakuya_link::Link as _;
use sakuya_wire::connection_id::ConnectionId;
#[cfg(any(test, feature = "test-util"))]
use snafu::Snafu;

use crate::{
    choices::{ConnectionDatagramReceiver, EndpointChoices, LinkOf, LocalOf},
    connection::{make_connection, register_first_local},
    domain::Domain,
    endpoint::EndpointClosedError,
    handle::ConnectionHandle,
    handshake::ClientHandshakeConfig,
    make::MakeConnection,
    part::CoreFacts,
    role::ConnectingClientRole,
    zero_length::{ZeroLengthLocalCidInUseError, ZeroLengthLocalOccupancy},
};

/// The length of the destination connection ID a client chooses for its
/// first Initial: the shortest QUIC version 1 allows (RFC 9000 §7.2).
const INITIAL_DCID_LEN: usize = 8;

/// A connection a client is about to start, over a link it took, before
/// the application starts it or drops it.
pub struct Outgoing<E: EndpointChoices, C: ConnectingClientRole<E>> {
    domain: Arc<Domain<E>>,
    config: C::Config,
    link: LinkOf<E>,
    server_name: <C::Handshake as ClientHandshakeConfig>::ServerName,
    zero_length: Option<ZeroLengthLocalOccupancy<LocalOf<E>>>,
    initial_dcid: Option<ConnectionId>,
}

impl<E: EndpointChoices, C: ConnectingClientRole<E>> Outgoing<E, C> {
    pub(crate) fn new(
        domain: Arc<Domain<E>>,
        config: C::Config,
        link: LinkOf<E>,
        server_name: <C::Handshake as ClientHandshakeConfig>::ServerName,
    ) -> Self {
        Self {
            domain,
            config,
            link,
            server_name,
            zero_length: None,
            initial_dcid: None,
        }
    }

    /// The link the connection will start over.
    pub fn link(&self) -> &LinkOf<E> {
        &self.link
    }

    /// The configuration the connection will be made with: a clone of the
    /// client configuration, which the application may change.
    pub fn config(&self) -> &C::Config {
        &self.config
    }

    /// The configuration the connection will be made with, to change.
    pub fn config_mut(&mut self) -> &mut C::Config {
        &mut self.config
    }

    /// Makes the connection use zero-length local connection IDs on the
    /// local end of its link, which it then occupies until it ends or this
    /// outgoing connection is dropped.
    ///
    /// # Errors
    ///
    /// [`ZeroLengthLocalCidInUseError`] when another connection occupies
    /// that local end.
    pub fn use_zero_length_local_cid(&mut self) -> Result<(), ZeroLengthLocalCidInUseError> {
        if self.zero_length.is_none() {
            let local = self.link.id().local.clone();
            self.zero_length = Some(self.domain.zero_length.occupy(local)?);
        }
        Ok(())
    }

    /// Replaces the destination connection ID of the client's first Initial,
    /// which the endpoint otherwise draws at random when the connection
    /// starts. Only for tests: a deployment must not choose a predictable
    /// one (RFC 9000 §7.2).
    ///
    /// # Errors
    ///
    /// [`InitialDcidLengthError`] when `dcid` is not 8 to 20 bytes long.
    #[cfg(any(test, feature = "test-util"))]
    pub fn set_initial_dcid(&mut self, dcid: ConnectionId) -> Result<(), InitialDcidLengthError> {
        let length = dcid.as_bytes().len();
        snafu::ensure!(
            (INITIAL_DCID_LEN..=20).contains(&length),
            InitialDcidLengthSnafu { length }
        );
        self.initial_dcid = Some(dcid);
        Ok(())
    }

    /// Starts the connection: chooses the destination connection ID of its
    /// first Initial, generates and registers its first local connection
    /// ID, then makes the connection, whose future the host spawns, and its
    /// handle. The connection sends its first Initial when first polled.
    ///
    /// # Errors
    ///
    /// [`EndpointClosedError`] once the endpoint has been closed; the
    /// outgoing connection is dropped.
    ///
    /// # Panics
    ///
    /// When the endpoint's random source fails to give the destination
    /// connection ID: the client must not choose a predictable one.
    #[expect(clippy::type_complexity, reason = "the driver's inferred positions")]
    pub fn start<P, W, Bw>(
        self,
    ) -> Result<
        (
            ConnectionDriver<C::Choices, C::Parts, P, W, Bw>,
            ConnectionHandle<<C::Choices as connection::Choices>::ApplicationError>,
        ),
        EndpointClosedError,
    >
    where
        C::Parts: TreeCalls<C::Choices, P>,
        for<'v> C::Parts: LineageLists<'v, C::Choices>,
        P: CallPositions,
        ConnectionDriver<C::Choices, C::Parts, P, W, Bw>: MakeConnection<C::Choices, C::Parts>,
    {
        let Self {
            domain,
            config,
            link,
            server_name,
            zero_length,
            initial_dcid,
        } = self;
        if domain.is_closed() {
            return Err(EndpointClosedError);
        }
        let queue = DatagramDeliveryQueue::new(
            config.receive_queue_capacity.min(
                core::num::NonZeroUsize::new(DatagramDeliveryQueue::<()>::MAX_CAPACITY)
                    .unwrap_or(core::num::NonZeroUsize::MIN),
            ),
        );
        // invariant: the capacity is within the bound a queue can have.
        let queue = queue.expect("the capacity is within the bound");
        let mut receiver = ConnectionDatagramReceiver::new(queue, None);
        let client_dcid = match initial_dcid {
            Some(dcid) => dcid,
            None => random_initial_dcid(&domain),
        };
        let first_local_connection_id =
            register_first_local(&domain, &mut receiver, &link, zero_length)?;
        let handshake = config.handshake();
        let close_request = CloseRequestCell::new();
        let core = CoreFacts {
            crypto: domain.crypto.clone(),
            handshake: HandshakeStart::new(handshake.start(&server_name), handshake.limits()),
            client_dcid,
            original_destination_connection_id: None,
            first_link: LinkFacts {
                validation: AddressValidation::Validated,
            },
            crypto_receive: config.checked_crypto_receive(),
            loss_thresholds: *config.loss_thresholds(),
            first_flight: FirstFlight::Datagrams(Vec::new()),
            initial_receiver: InitialPathReceiver::new(receiver),
            reset_token_registry: domain.reset_tokens.clone(),
            first_local_connection_id,
            close_request: close_request.clone(),
        };
        let driver = make_connection::<C::Choices, C::Parts, _>(
            domain.clock.clone(),
            config.parts,
            core,
            link,
        );
        Ok((driver, ConnectionHandle::new(close_request)))
    }
}

/// A destination connection ID for a client's first Initial, from the
/// endpoint's random source.
fn random_initial_dcid<E: EndpointChoices>(domain: &Domain<E>) -> ConnectionId {
    let bytes = domain.random.random::<INITIAL_DCID_LEN>();
    #[expect(
        clippy::expect_used,
        reason = "a client must not start with a predictable connection ID"
    )]
    let bytes = bytes.expect("the endpoint's random source gives bytes");
    // invariant: eight bytes are within the length of a connection ID.
    ConnectionId::try_from(&bytes[..]).expect("eight bytes make a connection ID")
}

impl<E: EndpointChoices, C: ConnectingClientRole<E>> fmt::Debug for Outgoing<E, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Outgoing")
            .field("link", &self.link)
            .field("zero_length", &self.zero_length.is_some())
            .finish_non_exhaustive()
    }
}

/// The destination connection ID of a client's first Initial is not 8 to
/// 20 bytes long (RFC 9000 §7.2, §17.2).
#[cfg(any(test, feature = "test-util"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("an initial destination connection ID of {length} bytes is not 8 to 20 bytes"))]
pub struct InitialDcidLengthError {
    /// The length given.
    pub length: usize,
}
