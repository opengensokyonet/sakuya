//! The parts of an endpoint, the configuration of each, and how a
//! connection's start values are made from it.
//!
//! An endpoint takes its own list of parts, each standing for a part of
//! the connections it makes ([`EndpointMarker`]); the list of parts of the
//! connections follows from it ([`ConnectionPartsOf`]). A connection is
//! built from what each of its parts declares it needs in the connection
//! node, a list in the order of the list of parts
//! ([`ConnectionArgsOf`](sakuya_connection::share::ConnectionArgsOf)). The
//! configuration of a role holds one value for each part of the endpoint,
//! found from its list, which the application may replace in an incoming
//! or outgoing connection; when the connection is made, each part makes
//! the start values of its part of the connection from its configuration
//! and from the facts the endpoint knows about the connection. A part of a
//! connection configured with its start values as they are needs no part
//! of the endpoint of its own ([`PassThroughPart`]).

use core::{fmt, marker::PhantomData};

use sakuya_connection::v1::ApplicationErrorOf;
use sakuya_connection::{
    layer,
    share::LayerShare,
    v1::{
        self, Side,
        advancing::HandshakeStart,
        close_request::CloseRequestCell,
        connection_ids::{FirstLocalConnectionId, LocalConnectionIdIssuer},
        crypto::CryptoReceiveCapacities,
        first_flight::FirstFlight,
        input::InitialPathReceiver,
        link::LinkFacts,
    },
};
use sakuya_recovery::loss::LossThresholds;
use sakuya_wire::{
    connection_id::ConnectionId,
    parts::{HCons, HNil},
};

/// A part of an endpoint: the part of a connection it stands for
/// ([`Connection`](Self::Connection)).
///
/// An endpoint takes a list of its own parts and makes connections of the
/// list of the parts they stand for ([`ConnectionPartsOf`]). A part of a
/// connection that the endpoint configures with what it gives the
/// connection node, as it is, is one through [`PassThroughPart`]; version
/// 1, which takes the facts the endpoint knows about the connection, is
/// its own.
pub trait EndpointMarker {
    /// The part of the connection.
    type Connection;
}

/// A part of an endpoint, as it configures its part of a connection.
///
/// `T` is the connection's choices and `L` its whole list of parts. Every
/// part of a list an endpoint makes connections of implements it.
pub trait EndpointPart<T: v1::Choices, L>:
    EndpointMarker<Connection: LayerShare<T, L, layer::Connection>>
{
    /// The part's configuration, one in the configuration of each role and
    /// one in each incoming or outgoing connection.
    type Config: Clone;

    /// What the part of the connection needs given when the connection
    /// node is built, from the configuration and the facts of the
    /// connection.
    fn connection_args(config: Self::Config, facts: &mut ConnectionFacts<T>) -> ArgsOf<Self, T, L>;
}

/// What the part of the connection that the endpoint's part `P` stands
/// for needs given when the connection node is built.
pub type ArgsOf<P, T, L> =
    <<P as EndpointMarker>::Connection as LayerShare<T, L, layer::Connection>>::Args;

/// The part of the endpoint for the part of a connection `P` that is
/// configured with what it is given when the connection node is built, as
/// it is: the DATAGRAM extension, the reliable stream reset extension.
pub struct PassThroughPart<P>(PhantomData<fn() -> P>);

impl<P> fmt::Debug for PassThroughPart<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PassThroughPart")
    }
}

impl<P> EndpointMarker for PassThroughPart<P> {
    type Connection = P;
}

/// The part's configuration is what its part of the connection is given.
impl<T, L, P> EndpointPart<T, L> for PassThroughPart<P>
where
    T: v1::Choices,
    P: LayerShare<T, L, layer::Connection, Args: Clone>,
{
    type Config = P::Args;

    fn connection_args(config: Self::Config, _: &mut ConnectionFacts<T>) -> P::Args {
        config
    }
}

/// The parts of a connection that a list of parts of an endpoint stand
/// for, in the order of the list.
pub trait EndpointMarkers {
    /// The list of parts of the connection.
    type Connection;
}

impl EndpointMarkers for HNil {
    type Connection = HNil;
}

impl<P: EndpointMarker, Ps: EndpointMarkers> EndpointMarkers for HCons<P, Ps> {
    type Connection = HCons<P::Connection, Ps::Connection>;
}

/// The list of parts of the connections an endpoint with the list of parts
/// `EL` makes.
pub type ConnectionPartsOf<EL> = <EL as EndpointMarkers>::Connection;

/// The configurations of a list of parts of an endpoint, and the start
/// values of the parts of the connection made from them; `Whole` is the
/// connection's whole list of parts.
pub trait PartConfigs<T: v1::Choices, Whole> {
    /// One configuration for each part, in the order of the list.
    type Configs: Clone;
    /// The start values of each part of the connection, in the order of
    /// the list.
    type Args;

    /// Each part's start values.
    fn connection_args(configs: Self::Configs, facts: &mut ConnectionFacts<T>) -> Self::Args;
}

impl<T: v1::Choices, Whole> PartConfigs<T, Whole> for HNil {
    type Configs = HNil;
    type Args = HNil;

    fn connection_args(_: HNil, _: &mut ConnectionFacts<T>) -> HNil {
        HNil
    }
}

impl<T, Whole, P, Ps> PartConfigs<T, Whole> for HCons<P, Ps>
where
    T: v1::Choices,
    P: EndpointPart<T, Whole>,
    Ps: PartConfigs<T, Whole>,
{
    type Configs = HCons<P::Config, Ps::Configs>;
    type Args = HCons<ArgsOf<P, T, Whole>, Ps::Args>;

    fn connection_args(configs: Self::Configs, facts: &mut ConnectionFacts<T>) -> Self::Args {
        HCons {
            head: P::connection_args(configs.head, facts),
            tail: Ps::connection_args(configs.tail, facts),
        }
    }
}

/// What the endpoint knows about a connection it makes, for the parts to
/// make their start values from.
///
/// They are the facts of QUIC version 1, which [`v1::Part`] takes; other
/// parts make their start values from their configuration alone.
pub struct ConnectionFacts<T: v1::Choices> {
    pub(crate) core: Option<CoreFacts<T>>,
}

/// The facts of a connection that [`v1::Part`] takes.
pub(crate) struct CoreFacts<T: v1::Choices> {
    pub(crate) crypto: T::Crypto,
    pub(crate) handshake: HandshakeStart<<T::Side as Side>::Tls>,
    pub(crate) side: <T::Side as Side>::Start,
    pub(crate) client_dcid: ConnectionId,
    pub(crate) original_destination_connection_id: Option<ConnectionId>,
    pub(crate) first_link: LinkFacts,
    pub(crate) crypto_receive: CryptoReceiveCapacities,
    pub(crate) loss_thresholds: LossThresholds,
    pub(crate) first_flight: FirstFlight<T>,
    pub(crate) initial_receiver: InitialPathReceiver<T::Receiver>,
    pub(crate) reset_token_registry: T::ResetTokenRegistry,
    pub(crate) first_local_connection_id: FirstLocalConnectionId,
    pub(crate) local_connection_id_issuer: LocalConnectionIdIssuer<T::ConnectionIdIssuer>,
    pub(crate) close_request: CloseRequestCell<ApplicationErrorOf<T>>,
}

impl<T: v1::Choices> ConnectionFacts<T> {
    pub(crate) fn new(core: CoreFacts<T>) -> Self {
        Self { core: Some(core) }
    }
}

impl<T: v1::Choices> fmt::Debug for ConnectionFacts<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionFacts")
            .field("taken", &self.core.is_none())
            .finish_non_exhaustive()
    }
}
