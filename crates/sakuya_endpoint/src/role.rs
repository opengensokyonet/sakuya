//! The two roles of an endpoint.
//!
//! An endpoint is a server, a client or both. Each role is a type parameter
//! of the [`Endpoint`](crate::endpoint::Endpoint): [`AcceptingServer`] and
//! [`ConnectingClient`] take the role, [`NoServer`] and [`NoClient`] leave
//! it, with `()` as their configuration. What a role alone can do is only
//! there when the endpoint takes it: [`incoming`](crate::endpoint::Endpoint::incoming)
//! needs an [`AcceptingServerRole`], and a binding handle's
//! [`connect`](crate::endpoint::BindingHandle::connect) a
//! [`ConnectingClientRole`].

use core::{fmt, marker::PhantomData, num::NonZeroUsize};
use std::sync::Arc;

use sakuya_connection::{
    layer::Connection,
    share::{LayerShares, LogicalPathKeys, SoleLogicalPath},
    v1,
};
use sakuya_recovery::loss::LossThresholds;
use sakuya_wire::version::Version;

use crate::{
    address_token::AddressTokens,
    choices::{ConnectionDatagramReceiver, EndpointChoices, LinkOf, ResetTokensOf},
    config::{ClientConfig, InvalidEndpointConfigError, ServerConfig},
    domain::Domain,
    dropped_input::DroppedInputCounts,
    handshake::{ClientHandshakeConfig, ServerHandshakeConfig},
    incoming::IncomingShared,
    part::PartConfigs,
    reflow::{NoServerReflow, ReflowQueues, ReflowSteps, ServerReflow},
    retry::StatelessRetryPolicy,
};

/// What keeps the role traits to the role types of this crate: their hidden
/// items are the endpoint's own workings, which another implementation
/// could not give, and new ones may be added.
mod sealed {
    pub trait Sealed {}
}

/// The server role of an endpoint of the choices `E`.
///
/// Only the role types of this crate implement it: [`NoServer`] and
/// [`AcceptingServer`].
pub trait ServerRole<E: EndpointChoices>: Sized + sealed::Sealed {
    /// The role's configuration.
    type Config;
    /// What the endpoint keeps for the role.
    #[doc(hidden)]
    type Kept: Clone;
    /// What the reflow driver does for the role.
    #[doc(hidden)]
    type Reflow: ReflowSteps<E>;

    /// What the routing domain needs of the role's configuration before the
    /// domain exists.
    #[doc(hidden)]
    fn domain_settings(config: &Self::Config) -> ServerDomainSettings;

    /// Starts the role in `domain`.
    #[doc(hidden)]
    fn start(
        config: Self::Config,
        domain: &Arc<Domain<E>>,
        queues: ReflowQueues<E>,
    ) -> Result<(Self::Kept, Self::Reflow), InvalidEndpointConfigError>;

    /// Ends the role's incoming connections, as the endpoint closes.
    #[doc(hidden)]
    fn close(kept: &Self::Kept);

    /// How many inputs the role dropped.
    #[doc(hidden)]
    fn dropped_input_counts(kept: &Self::Kept) -> DroppedInputCounts;
}

/// The client role of an endpoint of the choices `E`.
///
/// Only the role types of this crate implement it: [`NoClient`] and
/// [`ConnectingClient`].
pub trait ClientRole<E: EndpointChoices>: Sized + sealed::Sealed {
    /// The role's configuration.
    type Config;
    /// What the endpoint keeps for the role.
    #[doc(hidden)]
    type Kept: Clone;

    /// Starts the role in `domain`.
    #[doc(hidden)]
    fn start(
        config: Self::Config,
        domain: &Arc<Domain<E>>,
    ) -> Result<Self::Kept, InvalidEndpointConfigError>;
}

/// What the routing domain needs of the server role's configuration.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct ServerDomainSettings {
    /// The capacity of a new connection's receive queue.
    pub(crate) receive_queue_capacity: NonZeroUsize,
    /// How many unclaimed datagrams can wait for the reflow driver.
    pub(crate) unclaimed_queue_capacity: NonZeroUsize,
    /// How many Version Negotiation responses can wait.
    pub(crate) version_negotiation_queue_capacity: NonZeroUsize,
    /// The versions to offer on bindings that declare none.
    pub(crate) offered_versions: Vec<Version>,
}

/// The role of an endpoint that is a server: it takes new connections and
/// gives them to the application.
pub trait AcceptingServerRole<E: EndpointChoices>:
    ServerRole<
        E,
        Kept = Arc<IncomingShared<E, Self>>,
        Config = ServerConfig<
            Self::Choices,
            Self::Parts,
            Self::Handshake,
            Self::Tokens,
            Self::RetryPolicy,
        >,
    >
{
    /// The choices of the role's connections.
    type Choices: v1::Choices<
            Clock = E::Clock,
            Link = LinkOf<E>,
            Crypto = E::Crypto,
            Receiver = ConnectionDatagramReceiver<E>,
            ResetTokenRegistry = ResetTokensOf<E>,
            Side = v1::Server<<Self::Handshake as ServerHandshakeConfig>::Start>,
        >;
    /// The list of parts of the role's connections.
    type Parts: PartConfigs<Self::Choices, Self::Parts>
        + LayerShares<
            Self::Choices,
            Self::Parts,
            Connection,
            Args = <Self::Parts as PartConfigs<Self::Choices, Self::Parts>>::Args,
        > + LogicalPathKeys<Key = SoleLogicalPath>;
    /// What starts the handshake of each connection.
    type Handshake: ServerHandshakeConfig;
    /// The address validation tokens.
    type Tokens: AddressTokens + Clone;
    /// When to answer a new Initial with a stateless Retry.
    type RetryPolicy: StatelessRetryPolicy + Clone;
}

/// The role of an endpoint that is a client: it starts connections.
pub trait ConnectingClientRole<E: EndpointChoices>:
    ClientRole<E, Config = ClientConfig<Self::Choices, Self::Parts, Self::Handshake>>
{
    /// The choices of the role's connections.
    type Choices: v1::Choices<
            Clock = E::Clock,
            Link = LinkOf<E>,
            Crypto = E::Crypto,
            Receiver = ConnectionDatagramReceiver<E>,
            ResetTokenRegistry = ResetTokensOf<E>,
            Side = v1::Client<<Self::Handshake as ClientHandshakeConfig>::Start>,
        >;
    /// The list of parts of the role's connections.
    type Parts: PartConfigs<Self::Choices, Self::Parts>
        + LayerShares<
            Self::Choices,
            Self::Parts,
            Connection,
            Args = <Self::Parts as PartConfigs<Self::Choices, Self::Parts>>::Args,
        > + LogicalPathKeys<Key = SoleLogicalPath>;
    /// What starts the handshake of each connection.
    type Handshake: ClientHandshakeConfig;
}

/// No server role: the endpoint takes no new connections and answers no
/// datagram of an unsupported version.
#[derive(Debug)]
pub enum NoServer {}

impl sealed::Sealed for NoServer {}

impl<E: EndpointChoices> ServerRole<E> for NoServer {
    type Config = ();
    type Kept = ();
    type Reflow = NoServerReflow<E>;

    fn domain_settings((): &()) -> ServerDomainSettings {
        ServerDomainSettings {
            receive_queue_capacity: NonZeroUsize::MIN,
            unclaimed_queue_capacity: NonZeroUsize::MIN,
            version_negotiation_queue_capacity: NonZeroUsize::MIN,
            offered_versions: Vec::new(),
        }
    }

    fn start(
        (): (),
        _: &Arc<Domain<E>>,
        queues: ReflowQueues<E>,
    ) -> Result<((), NoServerReflow<E>), InvalidEndpointConfigError> {
        Ok(((), NoServerReflow::new(queues)))
    }

    fn close((): &()) {}

    fn dropped_input_counts((): &()) -> DroppedInputCounts {
        DroppedInputCounts::default()
    }
}

/// No client role: the endpoint starts no connections.
#[derive(Debug)]
pub enum NoClient {}

impl sealed::Sealed for NoClient {}

impl<E: EndpointChoices> ClientRole<E> for NoClient {
    type Config = ();
    type Kept = ();

    fn start((): (), _: &Arc<Domain<E>>) -> Result<(), InvalidEndpointConfigError> {
        Ok(())
    }
}

/// The server role for connections of the choices `T` and the list of parts
/// `L`, whose handshakes `H` starts, with the address validation tokens
/// `Tk` and the stateless Retry policy `Rp`.
pub struct AcceptingServer<T, L, H, Tk, Rp>(Marker<(T, L, H, Tk, Rp)>);

/// What a role type holds of its parameters: nothing.
type Marker<T> = PhantomData<fn() -> T>;

impl<T, L, H, Tk, Rp> fmt::Debug for AcceptingServer<T, L, H, Tk, Rp> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AcceptingServer")
    }
}

impl<T, L, H, Tk, Rp> sealed::Sealed for AcceptingServer<T, L, H, Tk, Rp> {}

impl<E, T, L, H, Tk, Rp> ServerRole<E> for AcceptingServer<T, L, H, Tk, Rp>
where
    E: EndpointChoices,
    T: v1::Choices<
            Clock = E::Clock,
            Link = LinkOf<E>,
            Crypto = E::Crypto,
            Receiver = ConnectionDatagramReceiver<E>,
            ResetTokenRegistry = ResetTokensOf<E>,
            Side = v1::Server<H::Start>,
        >,
    L: PartConfigs<T, L>
        + LayerShares<T, L, Connection, Args = <L as PartConfigs<T, L>>::Args>
        + LogicalPathKeys<Key = SoleLogicalPath>
        + 'static,
    H: ServerHandshakeConfig + 'static,
    Tk: AddressTokens + Clone + 'static,
    Rp: StatelessRetryPolicy + Clone + 'static,
{
    type Config = ServerConfig<T, L, H, Tk, Rp>;
    type Kept = Arc<IncomingShared<E, Self>>;
    type Reflow = ServerReflow<E, Self>;

    fn domain_settings(config: &Self::Config) -> ServerDomainSettings {
        ServerDomainSettings {
            receive_queue_capacity: config.receive_queue_capacity,
            unclaimed_queue_capacity: config.quotas.incoming_queue_capacity,
            version_negotiation_queue_capacity: config.quotas.version_negotiation_queue_capacity,
            offered_versions: config.offered_versions.clone(),
        }
    }

    fn start(
        mut config: Self::Config,
        domain: &Arc<Domain<E>>,
        queues: ReflowQueues<E>,
    ) -> Result<(Self::Kept, Self::Reflow), InvalidEndpointConfigError> {
        let thresholds = checked_thresholds(
            config.loss_thresholds(),
            domain,
            crate::config::EndpointRole::Server,
        )?;
        config.set_checked_loss_thresholds(thresholds);
        let shared = Arc::new(IncomingShared::new(config, domain));
        let reflow = ServerReflow::new(Arc::clone(&shared), domain, queues);
        Ok((shared, reflow))
    }

    fn close(kept: &Self::Kept) {
        kept.end();
    }

    fn dropped_input_counts(kept: &Self::Kept) -> DroppedInputCounts {
        kept.dropped_input_counts()
    }
}

impl<E, T, L, H, Tk, Rp> AcceptingServerRole<E> for AcceptingServer<T, L, H, Tk, Rp>
where
    E: EndpointChoices,
    T: v1::Choices<
            Clock = E::Clock,
            Link = LinkOf<E>,
            Crypto = E::Crypto,
            Receiver = ConnectionDatagramReceiver<E>,
            ResetTokenRegistry = ResetTokensOf<E>,
            Side = v1::Server<H::Start>,
        >,
    L: PartConfigs<T, L>
        + LayerShares<T, L, Connection, Args = <L as PartConfigs<T, L>>::Args>
        + LogicalPathKeys<Key = SoleLogicalPath>
        + 'static,
    H: ServerHandshakeConfig + 'static,
    Tk: AddressTokens + Clone + 'static,
    Rp: StatelessRetryPolicy + Clone + 'static,
{
    type Choices = T;
    type Parts = L;
    type Handshake = H;
    type Tokens = Tk;
    type RetryPolicy = Rp;
}

/// The client role for connections of the choices `T` and the list of parts
/// `L`, whose handshakes `H` starts.
pub struct ConnectingClient<T, L, H>(Marker<(T, L, H)>);

impl<T, L, H> fmt::Debug for ConnectingClient<T, L, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConnectingClient")
    }
}

impl<T, L, H> sealed::Sealed for ConnectingClient<T, L, H> {}

impl<E, T, L, H> ClientRole<E> for ConnectingClient<T, L, H>
where
    E: EndpointChoices,
    T: v1::Choices<
            Clock = E::Clock,
            Link = LinkOf<E>,
            Crypto = E::Crypto,
            Receiver = ConnectionDatagramReceiver<E>,
            ResetTokenRegistry = ResetTokensOf<E>,
            Side = v1::Client<H::Start>,
        >,
    L: PartConfigs<T, L>
        + LayerShares<T, L, Connection, Args = <L as PartConfigs<T, L>>::Args>
        + LogicalPathKeys<Key = SoleLogicalPath>
        + 'static,
    H: ClientHandshakeConfig + 'static,
{
    type Config = ClientConfig<T, L, H>;
    type Kept = Arc<ClientConfig<T, L, H>>;

    fn start(
        mut config: Self::Config,
        domain: &Arc<Domain<E>>,
    ) -> Result<Self::Kept, InvalidEndpointConfigError> {
        let thresholds = checked_thresholds(
            config.loss_thresholds(),
            domain,
            crate::config::EndpointRole::Client,
        )?;
        config.set_checked_loss_thresholds(thresholds);
        Ok(Arc::new(config))
    }
}

impl<E, T, L, H> ConnectingClientRole<E> for ConnectingClient<T, L, H>
where
    E: EndpointChoices,
    T: v1::Choices<
            Clock = E::Clock,
            Link = LinkOf<E>,
            Crypto = E::Crypto,
            Receiver = ConnectionDatagramReceiver<E>,
            ResetTokenRegistry = ResetTokensOf<E>,
            Side = v1::Client<H::Start>,
        >,
    L: PartConfigs<T, L>
        + LayerShares<T, L, Connection, Args = <L as PartConfigs<T, L>>::Args>
        + LogicalPathKeys<Key = SoleLogicalPath>
        + 'static,
    H: ClientHandshakeConfig + 'static,
{
    type Choices = T;
    type Parts = L;
    type Handshake = H;
}

/// `thresholds` checked against the endpoint's clock.
fn checked_thresholds<E: EndpointChoices>(
    thresholds: &LossThresholds,
    domain: &Domain<E>,
    role: crate::config::EndpointRole,
) -> Result<LossThresholds, InvalidEndpointConfigError> {
    use sakuya_clock::MonotonicClock as _;
    crate::config::check_loss_thresholds(thresholds, domain.clock.timer_granularity(), role)
}
