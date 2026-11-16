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
    clock::ConnectionChoices,
    layer::Connection,
    share::{LayerShares, LogicalPathKeys, SoleLogicalPath},
    v1,
};
use sakuya_recovery::loss::LossThresholds;
use sakuya_wire::version::Version;

use crate::{
    address_token::{AddressTokens, TokenPeerAddress},
    choices::{ConnectionDatagramReceiver, EndpointChoices, LinkOf, PeerOf, ResetTokensOf},
    client_token::{AddressTokenStore, KeyedAddressTokenSink},
    config::{ClientConfig, InvalidEndpointConfigError, ServerConfig},
    domain::Domain,
    dropped_input::DroppedInputCounts,
    handshake::{ClientHandshakeConfig, ServerHandshakeConfig},
    incoming::IncomingShared,
    issuer::EndpointConnectionIdIssuer,
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
    /// The choices of the role's connections:
    /// [`ServerConnectionChoices`] of the host's choices.
    type Choices: EndpointConnectionChoices<
            E,
            Side = v1::Server<<Self::Handshake as ServerHandshakeConfig>::Start>,
        >;
    /// The list of parts of the role's connections.
    type Parts: EndpointPartList<Self::Choices>;
    /// What starts the handshake of each connection.
    type Handshake: ServerHandshakeConfig;
    /// The address validation tokens.
    type Tokens: AddressTokens + TokenPeerAddress<PeerOf<E>> + Clone;
    /// When to answer a new Initial with a stateless Retry.
    type RetryPolicy: StatelessRetryPolicy + Clone;
}

/// The side of the connections of a client role whose handshakes `H`
/// starts, with the store `St` of address validation tokens and the Retry
/// policy `Rp`: each connection puts the tokens its server gives into the
/// store, under the server name it was made for.
pub type ConnectingClientSide<H, St, Rp> = v1::Client<
    <H as ClientHandshakeConfig>::Start,
    KeyedAddressTokenSink<St, <H as ClientHandshakeConfig>::ServerName>,
    Rp,
>;

/// The role of an endpoint that is a client: it starts connections.
pub trait ConnectingClientRole<E: EndpointChoices>:
    ClientRole<
        E,
        Config = ClientConfig<
            Self::Choices,
            Self::Parts,
            Self::Handshake,
            Self::AddressTokens,
            Self::RetryPolicy,
        >,
    >
{
    /// The choices of the role's connections:
    /// [`ClientConnectionChoices`] of the host's choices.
    type Choices: EndpointConnectionChoices<
            E,
            Side = ConnectingClientSide<Self::Handshake, Self::AddressTokens, Self::RetryPolicy>,
        >;
    /// The list of parts of the role's connections.
    type Parts: EndpointPartList<Self::Choices>;
    /// What starts the handshake of each connection.
    type Handshake: ClientHandshakeConfig;
    /// Where the address validation tokens servers give are kept.
    type AddressTokens: AddressTokenStore<<Self::Handshake as ClientHandshakeConfig>::ServerName>
        + Clone
        + 'static;
    /// What decides whether a connection goes on after a valid Retry.
    type RetryPolicy: v1::retry::ClientRetryPolicy + Clone + 'static;
}

// ---- the choices of the roles' connections ----

/// The choices of the connections of an endpoint of the choices `E`: what
/// the endpoint fixes of version 1's choices, all but the side. Both roles'
/// connection choices give it ([`ServerConnectionChoices`],
/// [`ClientConnectionChoices`]).
pub trait EndpointConnectionChoices<E: EndpointChoices>:
    v1::Choices<
        Clock = E::Clock,
        Link = LinkOf<E>,
        Crypto = E::Crypto,
        Receiver = ConnectionDatagramReceiver<E>,
        ResetTokenRegistry = ResetTokensOf<E>,
        ConnectionIdIssuer = EndpointConnectionIdIssuer<E>,
    >
{
}

impl<E: EndpointChoices, T> EndpointConnectionChoices<E> for T where
    T: v1::Choices<
            Clock = E::Clock,
            Link = LinkOf<E>,
            Crypto = E::Crypto,
            Receiver = ConnectionDatagramReceiver<E>,
            ResetTokenRegistry = ResetTokensOf<E>,
            ConnectionIdIssuer = EndpointConnectionIdIssuer<E>,
        >
{
}

/// A list of parts that an endpoint makes connections of the choices `T`
/// with: each part has its configuration and its share of the connection
/// node, and the connection has one logical path.
pub trait EndpointPartList<T: v1::Choices>:
    Sized
    + PartConfigs<T, Self>
    + LayerShares<T, Self, Connection, Args = <Self as PartConfigs<T, Self>>::Args>
    + LogicalPathKeys<Key = SoleLogicalPath>
    + 'static
{
}

impl<T: v1::Choices, L> EndpointPartList<T> for L where
    L: PartConfigs<T, L>
        + LayerShares<T, L, Connection, Args = <L as PartConfigs<T, L>>::Args>
        + LogicalPathKeys<Key = SoleLogicalPath>
        + 'static
{
}

/// The choices of the connections of a server role of an endpoint of the
/// choices `E`: the host's choices are `U`, the handshakes start from `H`'s,
/// and the endpoint fixes the rest.
pub struct ServerConnectionChoices<E, U, H>(Marker<(E, U, H)>);

impl<E, U, H> fmt::Debug for ServerConnectionChoices<E, U, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServerConnectionChoices")
    }
}

impl<E: EndpointChoices, U: 'static, H: ServerHandshakeConfig + 'static> ConnectionChoices
    for ServerConnectionChoices<E, U, H>
{
    type Clock = E::Clock;
    type Link = LinkOf<E>;
}

impl<E: EndpointChoices, U: 'static, H: ServerHandshakeConfig + 'static> v1::MakerChoices
    for ServerConnectionChoices<E, U, H>
{
    type Crypto = E::Crypto;
    type Side = v1::Server<H::Start>;
    type Receiver = ConnectionDatagramReceiver<E>;
    type ResetTokenRegistry = ResetTokensOf<E>;
    type ConnectionIdIssuer = EndpointConnectionIdIssuer<E>;
}

impl<E, U, H> v1::Choices for ServerConnectionChoices<E, U, H>
where
    E: EndpointChoices,
    U: v1::HostChoices<Self>,
    H: ServerHandshakeConfig + 'static,
{
    type Host = U;
}

/// The choices of the connections of a client role of an endpoint of the
/// choices `E`: the host's choices are `U`, the handshakes start from `H`'s,
/// with the store `St` of address validation tokens and the Retry policy
/// `Rp`, and the endpoint fixes the rest.
pub struct ClientConnectionChoices<E, U, H, St, Rp>(Marker<(E, U, H, St, Rp)>);

impl<E, U, H, St, Rp> fmt::Debug for ClientConnectionChoices<E, U, H, St, Rp> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientConnectionChoices")
    }
}

impl<E, U, H, St, Rp> ConnectionChoices for ClientConnectionChoices<E, U, H, St, Rp>
where
    E: EndpointChoices,
    U: 'static,
    H: ClientHandshakeConfig + 'static,
    St: 'static,
    Rp: 'static,
{
    type Clock = E::Clock;
    type Link = LinkOf<E>;
}

impl<E, U, H, St, Rp> v1::MakerChoices for ClientConnectionChoices<E, U, H, St, Rp>
where
    E: EndpointChoices,
    U: 'static,
    H: ClientHandshakeConfig + 'static,
    St: AddressTokenStore<H::ServerName> + Clone + 'static,
    Rp: v1::retry::ClientRetryPolicy + Clone + 'static,
{
    type Crypto = E::Crypto;
    type Side = ConnectingClientSide<H, St, Rp>;
    type Receiver = ConnectionDatagramReceiver<E>;
    type ResetTokenRegistry = ResetTokensOf<E>;
    type ConnectionIdIssuer = EndpointConnectionIdIssuer<E>;
}

impl<E, U, H, St, Rp> v1::Choices for ClientConnectionChoices<E, U, H, St, Rp>
where
    E: EndpointChoices,
    U: v1::HostChoices<Self>,
    H: ClientHandshakeConfig + 'static,
    St: AddressTokenStore<H::ServerName> + Clone + 'static,
    Rp: v1::retry::ClientRetryPolicy + Clone + 'static,
{
    type Host = U;
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

/// The server role for connections whose host's choices are `U` and list
/// of parts `L`, whose handshakes `H` starts, with the address validation
/// tokens `Tk` and the stateless Retry policy `Rp`. Its connections' choices
/// are [`ServerConnectionChoices`] of `U`.
pub struct AcceptingServer<U, L, H, Tk, Rp>(Marker<(U, L, H, Tk, Rp)>);

/// What a role type holds of its parameters: nothing.
type Marker<T> = PhantomData<fn() -> T>;

impl<U, L, H, Tk, Rp> fmt::Debug for AcceptingServer<U, L, H, Tk, Rp> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AcceptingServer")
    }
}

impl<U, L, H, Tk, Rp> sealed::Sealed for AcceptingServer<U, L, H, Tk, Rp> {}

impl<E, U, L, H, Tk, Rp> ServerRole<E> for AcceptingServer<U, L, H, Tk, Rp>
where
    E: EndpointChoices,
    U: v1::HostChoices<ServerConnectionChoices<E, U, H>>,
    L: EndpointPartList<ServerConnectionChoices<E, U, H>>,
    H: ServerHandshakeConfig + 'static,
    Tk: AddressTokens + TokenPeerAddress<PeerOf<E>> + Clone + 'static,
    Rp: StatelessRetryPolicy + Clone + 'static,
{
    type Config = ServerConfig<ServerConnectionChoices<E, U, H>, L, H, Tk, Rp>;
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

impl<E, U, L, H, Tk, Rp> AcceptingServerRole<E> for AcceptingServer<U, L, H, Tk, Rp>
where
    E: EndpointChoices,
    U: v1::HostChoices<ServerConnectionChoices<E, U, H>>,
    L: EndpointPartList<ServerConnectionChoices<E, U, H>>,
    H: ServerHandshakeConfig + 'static,
    Tk: AddressTokens + TokenPeerAddress<PeerOf<E>> + Clone + 'static,
    Rp: StatelessRetryPolicy + Clone + 'static,
{
    type Choices = ServerConnectionChoices<E, U, H>;
    type Parts = L;
    type Handshake = H;
    type Tokens = Tk;
    type RetryPolicy = Rp;
}

/// The client role for connections whose host's choices are `U` and list
/// of parts `L`, whose handshakes `H` starts, with the store `St` of address
/// validation tokens and the Retry policy `Rp`. Its connections' choices
/// are [`ClientConnectionChoices`] of `U`.
pub struct ConnectingClient<U, L, H, St, Rp>(Marker<(U, L, H, St, Rp)>);

impl<U, L, H, St, Rp> fmt::Debug for ConnectingClient<U, L, H, St, Rp> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConnectingClient")
    }
}

impl<U, L, H, St, Rp> sealed::Sealed for ConnectingClient<U, L, H, St, Rp> {}

impl<E, U, L, H, St, Rp> ClientRole<E> for ConnectingClient<U, L, H, St, Rp>
where
    E: EndpointChoices,
    U: v1::HostChoices<ClientConnectionChoices<E, U, H, St, Rp>>,
    L: EndpointPartList<ClientConnectionChoices<E, U, H, St, Rp>>,
    H: ClientHandshakeConfig + 'static,
    St: AddressTokenStore<H::ServerName> + Clone + 'static,
    Rp: v1::retry::ClientRetryPolicy + Clone + 'static,
{
    type Config = ClientConfig<ClientConnectionChoices<E, U, H, St, Rp>, L, H, St, Rp>;
    type Kept = Arc<ClientConfig<ClientConnectionChoices<E, U, H, St, Rp>, L, H, St, Rp>>;

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

impl<E, U, L, H, St, Rp> ConnectingClientRole<E> for ConnectingClient<U, L, H, St, Rp>
where
    E: EndpointChoices,
    U: v1::HostChoices<ClientConnectionChoices<E, U, H, St, Rp>>,
    L: EndpointPartList<ClientConnectionChoices<E, U, H, St, Rp>>,
    H: ClientHandshakeConfig + 'static,
    St: AddressTokenStore<H::ServerName> + Clone + 'static,
    Rp: v1::retry::ClientRetryPolicy + Clone + 'static,
{
    type Choices = ClientConnectionChoices<E, U, H, St, Rp>;
    type Parts = L;
    type Handshake = H;
    type AddressTokens = St;
    type RetryPolicy = Rp;
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
