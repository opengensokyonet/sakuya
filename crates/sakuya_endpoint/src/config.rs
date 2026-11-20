//! The configuration of an endpoint and of its two roles, and the checks it
//! passes.
//!
//! A constraint on one value is checked when the value's type is made, as
//! [`AntiAmplificationFactor`](sakuya_connection::v1::amplification::AntiAmplificationFactor)
//! or [`ServerQuotas`] are; a constraint between two values is checked
//! where both are known, and fails with an [`InvalidEndpointConfigError`]:
//! the capacities of the CRYPTO data a connection receives against the
//! handshake's limits, when a role's configuration is made or either of
//! them is replaced; the versions a server offers and the loss detection
//! thresholds against the clock, when the endpoint is made.

use core::{fmt, num::NonZeroUsize};

use frunk_core::hlist::Selector;
use sakuya_connection::v1::{
    self as connection,
    crypto::{CryptoCapacityError, CryptoReceiveCapacities},
};
use sakuya_recovery::loss::{GranularityBelowClockError, LossThresholds};
use sakuya_wire::version::Version;
use snafu::{ResultExt as _, Snafu, ensure};

use crate::{
    choices::EndpointChoices,
    handshake::{ClientHandshakeConfig, ServerHandshakeConfig},
    part::{ConnectionPartsOf, EndpointMarkers, EndpointPart, PartConfigs},
    quota::ServerQuotas,
    role::{ClientRole, ServerRole},
};

/// Everything an endpoint is made with: the configuration of its two roles
/// and its capabilities.
pub struct EndpointConfig<E: EndpointChoices, S: ServerRole<E>, C: ClientRole<E>> {
    /// The configuration of the server role; `()` for [`NoServer`](crate::role::NoServer).
    pub server: S::Config,
    /// The configuration of the client role; `()` for [`NoClient`](crate::role::NoClient).
    pub client: C::Config,
    /// The clock of the endpoint and its connections.
    pub clock: E::Clock,
    /// The backend that protects packets.
    pub crypto: E::Crypto,
    /// The random source.
    pub random: E::Random,
    /// The calendar clock tokens are dated by.
    pub wall_clock: E::WallClock,
    /// The configuration the connection ID generator of each connection is
    /// made from. It matches `recognizer`, so it is the same for both roles
    /// and cannot be replaced for one connection.
    pub connection_ids: <E::ConnectionIds as sakuya_datagram_routing::route::recognizer::ConnectionIdGenerator>::Config,
    /// What tells the lengths of the destination connection IDs of short
    /// headers.
    pub recognizer: E::Recognizer,
}

impl<E: EndpointChoices, S: ServerRole<E>, C: ClientRole<E>> fmt::Debug
    for EndpointConfig<E, S, C>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EndpointConfig").finish_non_exhaustive()
    }
}

/// How much CRYPTO data a server connection accepts at each encryption
/// level past what its handshake engine has read: a server receives no
/// handshake messages in 1-RTT packets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ServerCryptoReceiveCapacities {
    /// At the Initial level, which receives the ClientHello.
    pub initial: usize,
    /// At the Handshake level, which receives the client's Finished.
    pub handshake: usize,
}

/// How much CRYPTO data a client connection accepts at each encryption
/// level past what its handshake engine has read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ClientCryptoReceiveCapacities {
    /// At the Initial level, which receives the ServerHello.
    pub initial: usize,
    /// At the Handshake level, which receives the server's flight.
    pub handshake: usize,
    /// At the 1-RTT level, which receives NewSessionTicket messages.
    pub one_rtt: usize,
}

/// The configuration of the server role, for connections of the choices
/// `T` and the endpoint's list of parts `L`, whose handshakes `H` starts, with the
/// address validation tokens `Tk` and the stateless Retry policy `Rp`.
///
/// Each incoming connection gets a clone, which the application may change
/// before it accepts.
pub struct ServerConfig<T, L, H, Tk, Rp>
where
    T: connection::Choices,
    L: EndpointMarkers + PartConfigs<T, ConnectionPartsOf<L>>,
{
    handshake: H,
    crypto_receive: ServerCryptoReceiveCapacities,
    checked_crypto_receive: CryptoReceiveCapacities,
    loss_thresholds: LossThresholds,
    /// The configuration of each part, in the order of the list of parts.
    pub parts: L::Configs,
    /// The bounds of the endpoint's own queues. They are not a
    /// connection's: replacing them in an incoming connection changes
    /// nothing.
    pub quotas: ServerQuotas,
    /// The address validation tokens. They are the endpoint's: it validates
    /// the tokens clients return with them, and an incoming connection's
    /// Retry issues its token with them, so replacing them in an incoming
    /// connection changes nothing.
    pub tokens: Tk,
    /// When the endpoint answers a new Initial with a stateless Retry.
    pub retry_policy: Rp,
    /// The versions a Version Negotiation packet lists, unless the binding
    /// it is sent on declares its own.
    pub offered_versions: Vec<Version>,
    /// How many deliveries the datagram receiver of a connection holds until
    /// the connection takes them.
    pub receive_queue_capacity: NonZeroUsize,
    /// Whether reading an incoming connection's first ClientHello
    /// ([`read_client_hello`](crate::incoming::TerminableIncoming::read_client_hello))
    /// keeps a layout of the first flight, which an endpoint that hands
    /// connections off for passthrough forwarding
    /// ([`into_passthrough_handoff`](crate::incoming::TerminableIncoming::into_passthrough_handoff))
    /// needs; off by default.
    pub keep_first_flight_layout: bool,
}

impl<T, L, H, Tk, Rp> ServerConfig<T, L, H, Tk, Rp>
where
    T: connection::Choices,
    L: EndpointMarkers + PartConfigs<T, ConnectionPartsOf<L>>,
    H: ServerHandshakeConfig,
{
    /// The configuration with the given handshake, CRYPTO capacities, loss
    /// detection thresholds, configurations of the parts, tokens and Retry
    /// policy; the default quotas, the versions the endpoint supports to
    /// offer, a receive queue of 64 deliveries, and no layout of the first
    /// flight kept.
    ///
    /// # Errors
    ///
    /// [`InvalidEndpointConfigError::CryptoReceiveCapacity`] when a capacity
    /// is below what the handshake's limits need.
    pub fn new(
        handshake: H,
        crypto_receive: ServerCryptoReceiveCapacities,
        loss_thresholds: LossThresholds,
        parts: L::Configs,
        tokens: Tk,
        retry_policy: Rp,
    ) -> Result<Self, InvalidEndpointConfigError> {
        let checked_crypto_receive = check_server_capacities(&handshake, crypto_receive)?;
        Ok(Self {
            handshake,
            crypto_receive,
            checked_crypto_receive,
            loss_thresholds,
            parts,
            quotas: ServerQuotas::default(),
            tokens,
            retry_policy,
            offered_versions: vec![Version::V1],
            receive_queue_capacity: DEFAULT_RECEIVE_QUEUE_CAPACITY,
            keep_first_flight_layout: false,
        })
    }

    /// What starts each connection's handshake.
    pub fn handshake(&self) -> &H {
        &self.handshake
    }

    /// Replaces what starts each connection's handshake.
    ///
    /// # Errors
    ///
    /// [`InvalidEndpointConfigError::CryptoReceiveCapacity`] when the CRYPTO
    /// capacities are below what the new handshake's limits need; the
    /// configuration is then unchanged.
    pub fn set_handshake(&mut self, handshake: H) -> Result<(), InvalidEndpointConfigError> {
        self.checked_crypto_receive = check_server_capacities(&handshake, self.crypto_receive)?;
        self.handshake = handshake;
        Ok(())
    }

    /// The capacities of the CRYPTO data a connection receives.
    pub fn crypto_receive(&self) -> ServerCryptoReceiveCapacities {
        self.crypto_receive
    }

    /// Replaces the capacities of the CRYPTO data a connection receives.
    ///
    /// # Errors
    ///
    /// [`InvalidEndpointConfigError::CryptoReceiveCapacity`] when a capacity
    /// is below what the handshake's limits need; the configuration is then
    /// unchanged.
    pub fn set_crypto_receive(
        &mut self,
        crypto_receive: ServerCryptoReceiveCapacities,
    ) -> Result<(), InvalidEndpointConfigError> {
        self.checked_crypto_receive = check_server_capacities(&self.handshake, crypto_receive)?;
        self.crypto_receive = crypto_receive;
        Ok(())
    }
}

impl<T, L, H, Tk, Rp> ServerConfig<T, L, H, Tk, Rp>
where
    T: connection::Choices,
    L: EndpointMarkers + PartConfigs<T, ConnectionPartsOf<L>>,
{
    /// The thresholds of loss detection.
    pub fn loss_thresholds(&self) -> &LossThresholds {
        &self.loss_thresholds
    }

    /// The configuration of the part `P`.
    pub fn part<P: EndpointPart<T, ConnectionPartsOf<L>>, I>(&self) -> &P::Config
    where
        L::Configs: Selector<P::Config, I>,
    {
        self.parts.get()
    }

    /// The configuration of the part `P`, to change.
    pub fn part_mut<P: EndpointPart<T, ConnectionPartsOf<L>>, I>(&mut self) -> &mut P::Config
    where
        L::Configs: Selector<P::Config, I>,
    {
        self.parts.get_mut()
    }

    pub(crate) fn checked_crypto_receive(&self) -> CryptoReceiveCapacities {
        self.checked_crypto_receive
    }

    pub(crate) fn set_checked_loss_thresholds(&mut self, thresholds: LossThresholds) {
        self.loss_thresholds = thresholds;
    }
}

impl<T, L, H: Clone, Tk: Clone, Rp: Clone> Clone for ServerConfig<T, L, H, Tk, Rp>
where
    T: connection::Choices,
    L: EndpointMarkers + PartConfigs<T, ConnectionPartsOf<L>>,
{
    fn clone(&self) -> Self {
        Self {
            handshake: self.handshake.clone(),
            crypto_receive: self.crypto_receive,
            checked_crypto_receive: self.checked_crypto_receive,
            loss_thresholds: self.loss_thresholds,
            parts: self.parts.clone(),
            quotas: self.quotas,
            tokens: self.tokens.clone(),
            retry_policy: self.retry_policy.clone(),
            offered_versions: self.offered_versions.clone(),
            receive_queue_capacity: self.receive_queue_capacity,
            keep_first_flight_layout: self.keep_first_flight_layout,
        }
    }
}

impl<T, L, H, Tk, Rp> fmt::Debug for ServerConfig<T, L, H, Tk, Rp>
where
    T: connection::Choices,
    L: EndpointMarkers + PartConfigs<T, ConnectionPartsOf<L>>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig")
            .field("crypto_receive", &self.crypto_receive)
            .field("loss_thresholds", &self.loss_thresholds)
            .field("quotas", &self.quotas)
            .field("offered_versions", &self.offered_versions)
            .field("receive_queue_capacity", &self.receive_queue_capacity)
            .field("keep_first_flight_layout", &self.keep_first_flight_layout)
            .finish_non_exhaustive()
    }
}

/// The configuration of the client role, for connections of the choices
/// `T` and the endpoint's list of parts `L`, whose handshakes `H` starts, with the
/// store `St` of address validation tokens and the Retry policy `Rp`.
///
/// Each outgoing connection gets a clone, which the application may change
/// before it starts.
pub struct ClientConfig<T, L, H, St, Rp>
where
    T: connection::Choices,
    L: EndpointMarkers + PartConfigs<T, ConnectionPartsOf<L>>,
{
    handshake: H,
    crypto_receive: ClientCryptoReceiveCapacities,
    checked_crypto_receive: CryptoReceiveCapacities,
    loss_thresholds: LossThresholds,
    /// The configuration of each part, in the order of the list of parts.
    pub parts: L::Configs,
    /// Where the address validation tokens servers give are kept, per
    /// server name. A connection takes the token it starts with from the
    /// store in its configuration when it starts, and puts the tokens its
    /// server gives into a clone of it; replacing it with `()` breaks
    /// continuity with servers (RFC 9000 §8.1.3).
    pub address_tokens: St,
    /// What decides whether a connection goes on after a valid Retry.
    pub retry_policy: Rp,
    /// How many deliveries the datagram receiver of a connection holds until
    /// the connection takes them.
    pub receive_queue_capacity: NonZeroUsize,
}

impl<T, L, H, St, Rp> ClientConfig<T, L, H, St, Rp>
where
    T: connection::Choices,
    L: EndpointMarkers + PartConfigs<T, ConnectionPartsOf<L>>,
    H: ClientHandshakeConfig,
{
    /// The configuration with the given handshake, CRYPTO capacities, loss
    /// detection thresholds, configurations of the parts, store of address
    /// validation tokens and Retry policy, and a receive queue of 64
    /// deliveries.
    ///
    /// # Errors
    ///
    /// [`InvalidEndpointConfigError::CryptoReceiveCapacity`] when a capacity
    /// is below what the handshake's limits need.
    pub fn new(
        handshake: H,
        crypto_receive: ClientCryptoReceiveCapacities,
        loss_thresholds: LossThresholds,
        parts: L::Configs,
        address_tokens: St,
        retry_policy: Rp,
    ) -> Result<Self, InvalidEndpointConfigError> {
        let checked_crypto_receive = check_client_capacities(&handshake, crypto_receive)?;
        Ok(Self {
            handshake,
            crypto_receive,
            checked_crypto_receive,
            loss_thresholds,
            parts,
            address_tokens,
            retry_policy,
            receive_queue_capacity: DEFAULT_RECEIVE_QUEUE_CAPACITY,
        })
    }

    /// What starts each connection's handshake.
    pub fn handshake(&self) -> &H {
        &self.handshake
    }

    /// Replaces what starts each connection's handshake.
    ///
    /// # Errors
    ///
    /// [`InvalidEndpointConfigError::CryptoReceiveCapacity`] when the CRYPTO
    /// capacities are below what the new handshake's limits need; the
    /// configuration is then unchanged.
    pub fn set_handshake(&mut self, handshake: H) -> Result<(), InvalidEndpointConfigError> {
        self.checked_crypto_receive = check_client_capacities(&handshake, self.crypto_receive)?;
        self.handshake = handshake;
        Ok(())
    }

    /// The capacities of the CRYPTO data a connection receives.
    pub fn crypto_receive(&self) -> ClientCryptoReceiveCapacities {
        self.crypto_receive
    }

    /// Replaces the capacities of the CRYPTO data a connection receives.
    ///
    /// # Errors
    ///
    /// [`InvalidEndpointConfigError::CryptoReceiveCapacity`] when a capacity
    /// is below what the handshake's limits need; the configuration is then
    /// unchanged.
    pub fn set_crypto_receive(
        &mut self,
        crypto_receive: ClientCryptoReceiveCapacities,
    ) -> Result<(), InvalidEndpointConfigError> {
        self.checked_crypto_receive = check_client_capacities(&self.handshake, crypto_receive)?;
        self.crypto_receive = crypto_receive;
        Ok(())
    }
}

impl<T, L, H, St, Rp> ClientConfig<T, L, H, St, Rp>
where
    T: connection::Choices,
    L: EndpointMarkers + PartConfigs<T, ConnectionPartsOf<L>>,
{
    /// The thresholds of loss detection.
    pub fn loss_thresholds(&self) -> &LossThresholds {
        &self.loss_thresholds
    }

    /// The configuration of the part `P`.
    pub fn part<P: EndpointPart<T, ConnectionPartsOf<L>>, I>(&self) -> &P::Config
    where
        L::Configs: Selector<P::Config, I>,
    {
        self.parts.get()
    }

    /// The configuration of the part `P`, to change.
    pub fn part_mut<P: EndpointPart<T, ConnectionPartsOf<L>>, I>(&mut self) -> &mut P::Config
    where
        L::Configs: Selector<P::Config, I>,
    {
        self.parts.get_mut()
    }

    pub(crate) fn checked_crypto_receive(&self) -> CryptoReceiveCapacities {
        self.checked_crypto_receive
    }

    pub(crate) fn set_checked_loss_thresholds(&mut self, thresholds: LossThresholds) {
        self.loss_thresholds = thresholds;
    }
}

impl<T, L, H: Clone, St: Clone, Rp: Clone> Clone for ClientConfig<T, L, H, St, Rp>
where
    T: connection::Choices,
    L: EndpointMarkers + PartConfigs<T, ConnectionPartsOf<L>>,
{
    fn clone(&self) -> Self {
        Self {
            handshake: self.handshake.clone(),
            crypto_receive: self.crypto_receive,
            checked_crypto_receive: self.checked_crypto_receive,
            loss_thresholds: self.loss_thresholds,
            parts: self.parts.clone(),
            address_tokens: self.address_tokens.clone(),
            retry_policy: self.retry_policy.clone(),
            receive_queue_capacity: self.receive_queue_capacity,
        }
    }
}

impl<T, L, H, St, Rp> fmt::Debug for ClientConfig<T, L, H, St, Rp>
where
    T: connection::Choices,
    L: EndpointMarkers + PartConfigs<T, ConnectionPartsOf<L>>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfig")
            .field("crypto_receive", &self.crypto_receive)
            .field("loss_thresholds", &self.loss_thresholds)
            .field("receive_queue_capacity", &self.receive_queue_capacity)
            .finish_non_exhaustive()
    }
}

/// The capacity of a connection's datagram receiver unless one is given.
const DEFAULT_RECEIVE_QUEUE_CAPACITY: NonZeroUsize = NonZeroUsize::new(64).unwrap();

fn check_server_capacities(
    handshake: &impl ServerHandshakeConfig,
    capacities: ServerCryptoReceiveCapacities,
) -> Result<CryptoReceiveCapacities, InvalidEndpointConfigError> {
    CryptoReceiveCapacities::server(
        handshake.limits(),
        handshake.requests_client_certificate(),
        capacities.initial,
        capacities.handshake,
    )
    .context(CryptoReceiveCapacitySnafu {
        role: EndpointRole::Server,
    })
}

fn check_client_capacities(
    handshake: &impl ClientHandshakeConfig,
    capacities: ClientCryptoReceiveCapacities,
) -> Result<CryptoReceiveCapacities, InvalidEndpointConfigError> {
    CryptoReceiveCapacities::client(
        handshake.limits(),
        capacities.initial,
        capacities.handshake,
        capacities.one_rtt,
    )
    .context(CryptoReceiveCapacitySnafu {
        role: EndpointRole::Client,
    })
}

/// The loss detection thresholds `thresholds`, checked against the
/// precision `clock_granularity` of the endpoint's clock, for `role`.
pub(crate) fn check_loss_thresholds(
    thresholds: &LossThresholds,
    clock_granularity: core::time::Duration,
    role: EndpointRole,
) -> Result<LossThresholds, InvalidEndpointConfigError> {
    thresholds_against_clock(thresholds, clock_granularity).context(TimerGranularitySnafu { role })
}

/// `thresholds` checked against the precision `clock_granularity` of the
/// endpoint's clock: they may have been made against another.
pub(crate) fn thresholds_against_clock(
    thresholds: &LossThresholds,
    clock_granularity: core::time::Duration,
) -> Result<LossThresholds, GranularityBelowClockError> {
    LossThresholds::new(
        thresholds.packet_threshold(),
        thresholds.time_threshold(),
        thresholds.granularity(),
        clock_granularity,
    )
}

/// Checks the versions a server offers in Version Negotiation packets:
/// versions routing supports, and no reserved version.
pub(crate) fn check_offered_versions(versions: &[Version]) -> Result<(), OfferedVersionsError> {
    for &version in versions {
        ensure!(!version.is_reserved(), ReservedSnafu { version });
        ensure!(version == Version::V1, UnsupportedSnafu { version });
    }
    Ok(())
}

/// Which role's configuration failed a check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EndpointRole {
    /// The server role's.
    Server,
    /// The client role's.
    Client,
}

/// A configuration of an endpoint whose values do not agree with one
/// another.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum InvalidEndpointConfigError {
    /// The versions a server offers in Version Negotiation packets.
    #[snafu(display("versions to offer"))]
    OfferedVersions {
        /// Which version does not belong.
        source: OfferedVersionsError,
    },
    /// The capacity of a level of CRYPTO data is below what the handshake's
    /// limits need.
    #[snafu(display("CRYPTO receive capacity of the {role:?} role"))]
    CryptoReceiveCapacity {
        /// The role whose configuration it is.
        role: EndpointRole,
        /// The level, its capacity, and what it needs.
        source: CryptoCapacityError,
    },
    /// The timer granularity of loss detection is below the precision of
    /// the endpoint's clock (RFC 9002 §6.1.2).
    #[snafu(display("loss detection thresholds of the {role:?} role"))]
    TimerGranularity {
        /// The role whose configuration it is.
        role: EndpointRole,
        /// The granularity and the clock's precision.
        source: GranularityBelowClockError,
    },
}

/// A list of versions to offer in Version Negotiation packets that does not
/// hold only versions the endpoint accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum OfferedVersionsError {
    /// The list holds a version routing does not support: a client using it
    /// would discard the Version Negotiation packet (RFC 9000 §6.2).
    #[snafu(display("version {:#010x} is not supported", version.get()))]
    Unsupported {
        /// The version.
        version: Version,
    },
    /// The list holds a reserved version; the endpoint adds one of its own
    /// to each packet (RFC 9000 §6.3).
    #[snafu(display("version {:#010x} is reserved", version.get()))]
    Reserved {
        /// The version.
        version: Version,
    },
}

/// What the host declares about a binding when it adds it: what holds for
/// every link of the binding.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BindingDeclarations {
    /// Whether the transport itself has validated the peer's address of
    /// every link of the binding, so that the first logical link of a new
    /// connection on it starts validated; `false` for UDP.
    pub transport_validated: bool,
    /// The versions a Version Negotiation packet sent on the binding lists;
    /// `None` takes the server configuration's.
    pub offered_versions: Option<Vec<Version>>,
}
