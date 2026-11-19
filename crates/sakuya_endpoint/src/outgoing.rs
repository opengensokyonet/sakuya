//! The outgoing connections a client endpoint gives the application.
//!
//! A binding handle's `connect` takes a link and gives an [`Outgoing`]: the
//! link, the name of the server, and a clone of the client configuration,
//! which the application may change. [`Outgoing::start`] then registers the
//! connection's first local connection ID, takes the address validation
//! token the connection starts with from the store in the configuration,
//! and makes the connection.

use alloc::sync::Arc;
use core::fmt;

use nitori_crypto::{Random as _, RandomError};
use sakuya_clock::MonotonicClock as _;
use sakuya_connection::{
    driver::LendNode,
    error::ConnectionErrorsOf,
    shared::DrivenFromOutside,
    v1::{
        address_token::fits_initial_packet, advancing::HandshakeStart,
        amplification::AddressValidation, close_request::CloseRequestCell,
        first_flight::FirstFlight, handshake_done::ClientOnlyStart, input::InitialPathReceiver,
        link::LinkFacts,
    },
};
use sakuya_datagram_routing::claim::queue::{
    DatagramDeliveryQueue as _, DatagramDeliveryQueueState,
};
use sakuya_link::Link as _;
use sakuya_recovery::loss::GranularityBelowClockError;
use sakuya_wire::connection_id::ConnectionId;
#[cfg(any(test, feature = "test-util"))]
use snafu::Snafu;

use crate::{
    choices::{
        ConnectionDatagramReceiver, EndpointChoices, LinkOf, ReceiveQueueOf, SharedBindingOf,
        ZeroLengthOccupancyOf,
    },
    client_token::{AddressTokenStore as _, KeyedAddressTokenSink},
    config::thresholds_against_clock,
    connection::{make_connection, register_first_local},
    domain::Domain,
    endpoint::EndpointClosedError,
    handshake::ClientHandshakeConfig,
    link_connector::EndpointLinkConnector,
    part::CoreFacts,
    role::ConnectingClientRole,
    zero_length::{ZeroLengthLocalCidInUseError, ZeroLengthLocals as _},
};

/// The length of the destination connection ID a client chooses for its
/// first Initial: the shortest QUIC version 1 allows (RFC 9000 §7.2).
const INITIAL_DCID_LEN: usize = 8;

/// A connection a client is about to start, over a link it took, before
/// the application starts it or drops it.
pub struct Outgoing<E: EndpointChoices, C: ConnectingClientRole<E>> {
    domain: Arc<Domain<E>>,
    config: C::Config,
    /// The binding the link is of, on which the connection takes the links
    /// it migrates to.
    binding: SharedBindingOf<E>,
    link: LinkOf<E>,
    server_name: <C::Handshake as ClientHandshakeConfig>::ServerName,
    zero_length: Option<ZeroLengthOccupancyOf<E>>,
    initial_dcid: Option<ConnectionId>,
}

impl<E: EndpointChoices, C: ConnectingClientRole<E>> Outgoing<E, C> {
    pub(crate) fn new(
        domain: Arc<Domain<E>>,
        config: C::Config,
        binding: SharedBindingOf<E>,
        link: LinkOf<E>,
        server_name: <C::Handshake as ClientHandshakeConfig>::ServerName,
    ) -> Self {
        Self {
            domain,
            config,
            binding,
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
    /// ID, takes a token for the server name from the configuration's store
    /// of address validation tokens, then makes the connection, which the
    /// host puts in a wrapper, drives from there and takes the
    /// application's handles from
    /// ([`SharedConnection`](sakuya_connection::shared::SharedConnection)).
    /// The connection sends its first Initial when first polled.
    ///
    /// The token, which every Initial packet of the connection carries, is
    /// not put back into the store whatever becomes of the connection
    /// (RFC 9000 §8.1.3); one too long to leave room in an Initial packet is
    /// dropped. The tokens the server gives go into a clone of the store,
    /// under the same server name.
    ///
    /// # Errors
    ///
    /// [`StartOutgoingError`], which gives the outgoing connection back as
    /// it was, nothing registered: once the endpoint has been closed; when
    /// the timer granularity of its loss detection thresholds is finer than
    /// the endpoint's clock, as it may be after its configuration was
    /// replaced; when the endpoint's random source gives no destination
    /// connection ID, as the client must not choose a predictable one.
    pub fn start(
        mut self,
    ) -> Result<
        impl DrivenFromOutside + LendNode<C::Choices, C::Parts> + 'static,
        StartOutgoingError<Self>,
    >
    where
        C::Parts: ConnectionErrorsOf,
        for<'v> C::Parts: sakuya_connection::share::LineageLists<'v, C::Choices>,
    {
        if self.domain.is_closed() {
            return Err(StartOutgoingError::EndpointClosed {
                half: self,
                source: EndpointClosedError,
            });
        }
        let loss_thresholds = match thresholds_against_clock(
            self.config.loss_thresholds(),
            self.domain.clock.timer_granularity(),
        ) {
            Ok(thresholds) => thresholds,
            Err(source) => return Err(StartOutgoingError::TimerGranularity { half: self, source }),
        };
        let client_dcid = match self.initial_dcid {
            Some(dcid) => dcid,
            None => match random_initial_dcid(&self.domain) {
                Ok(dcid) => dcid,
                Err(source) => return Err(StartOutgoingError::Random { half: self, source }),
            },
        };
        let queue = ReceiveQueueOf::<E>::new(
            self.config.receive_queue_capacity.min(
                core::num::NonZeroUsize::new(DatagramDeliveryQueueState::<()>::MAX_CAPACITY)
                    .unwrap_or(core::num::NonZeroUsize::MIN),
            ),
        );
        // invariant: the capacity is within the bound a queue can have.
        let queue = queue.expect("the capacity is within the bound");
        let mut receiver = ConnectionDatagramReceiver::new(queue, None);
        let first_local = match register_first_local(
            &self.domain,
            &mut receiver,
            &self.link,
            &mut self.zero_length,
            None,
        ) {
            Ok(first_local) => first_local,
            Err(source) => return Err(StartOutgoingError::EndpointClosed { half: self, source }),
        };
        let Self {
            domain,
            config,
            binding,
            link,
            server_name,
            zero_length: _,
            initial_dcid: _,
        } = self;
        let handshake = config.handshake();
        let handshake = HandshakeStart::new(handshake.start(&server_name), handshake.limits());
        let token = config
            .address_tokens
            .take(&server_name)
            .filter(|token| {
                fits_initial_packet(token.len(), client_dcid.len(), first_local.id.id().len())
            })
            .unwrap_or_default();
        let sink = KeyedAddressTokenSink::new(config.address_tokens.clone(), server_name);
        let core = CoreFacts {
            crypto: domain.crypto.clone(),
            handshake,
            side: ClientOnlyStart::new(
                token,
                sink,
                config.retry_policy.clone(),
                EndpointLinkConnector::new(binding, domain.closed_flag()),
            ),
            client_dcid,
            original_destination_connection_id: None,
            first_link: LinkFacts {
                validation: AddressValidation::Validated,
            },
            crypto_receive: config.checked_crypto_receive(),
            loss_thresholds,
            first_flight: FirstFlight::Datagrams(Vec::new()),
            initial_receiver: InitialPathReceiver::new(receiver),
            reset_token_registry: domain.reset_tokens.clone(),
            first_local_connection_id: first_local.id,
            local_connection_id_issuer: first_local.issuer,
            close_request: CloseRequestCell::new(),
        };
        Ok(make_connection::<C::Choices, C::Parts, C::Composition>(
            domain.clock.clone(),
            config.parts,
            core,
            link,
        ))
    }
}

/// A destination connection ID for a client's first Initial, from the
/// endpoint's random source.
fn random_initial_dcid<E: EndpointChoices>(
    domain: &Domain<E>,
) -> Result<ConnectionId, RandomError> {
    let bytes = domain.random.random::<INITIAL_DCID_LEN>()?;
    // invariant: eight bytes are within the length of a connection ID.
    Ok(ConnectionId::try_from(&bytes[..]).expect("eight bytes make a connection ID"))
}

/// The outgoing connection `H` could not be started. It is given back as it
/// was, nothing registered, for the application to change, start again or
/// drop.
pub enum StartOutgoingError<H> {
    /// The endpoint has been closed.
    EndpointClosed {
        /// The outgoing connection, as it was.
        half: H,
        /// The endpoint's closing.
        source: EndpointClosedError,
    },
    /// The timer granularity of the loss detection thresholds in the
    /// configuration is finer than the endpoint's clock (RFC 9002 §6.1.2).
    TimerGranularity {
        /// The outgoing connection, as it was.
        half: H,
        /// The granularity and the clock's.
        source: GranularityBelowClockError,
    },
    /// The endpoint's random source gave no destination connection ID for
    /// the first Initial.
    Random {
        /// The outgoing connection, as it was.
        half: H,
        /// The random source's failure.
        source: RandomError,
    },
}

impl<H> fmt::Debug for StartOutgoingError<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (name, source): (_, &dyn fmt::Debug) = match self {
            Self::EndpointClosed { source, .. } => ("EndpointClosed", source),
            Self::TimerGranularity { source, .. } => ("TimerGranularity", source),
            Self::Random { source, .. } => ("Random", source),
        };
        f.debug_struct(name)
            .field("source", source)
            .finish_non_exhaustive()
    }
}

impl<H> fmt::Display for StartOutgoingError<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the outgoing connection was not started")
    }
}

impl<H> core::error::Error for StartOutgoingError<H> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::EndpointClosed { source, .. } => Some(source),
            Self::TimerGranularity { source, .. } => Some(source),
            Self::Random { source, .. } => Some(source),
        }
    }
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
