//! The configuration of each part of a connection, and how a connection's
//! start values are made from it.
//!
//! A connection is built from what each of its parts declares it needs in
//! the connection node, a list in the order of the list of parts
//! ([`ConnectionArgsOf`](sakuya_connection::share::ConnectionArgsOf)). The
//! configuration of a role holds one value for each part, found from the
//! list of parts, which the application may replace in an incoming or
//! outgoing connection; when the connection is made, each part makes its
//! start values from its configuration and from the facts the endpoint
//! knows about the connection.

use core::fmt;

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

/// A part of a connection, as an endpoint configures it.
///
/// `T` is the connection's choices and `L` its whole list of parts. Every
/// part of a list an endpoint makes connections of implements it.
pub trait EndpointPart<T: v1::Choices, L>: LayerShare<T, L, layer::Connection> {
    /// The part's configuration, one in the configuration of each role and
    /// one in each incoming or outgoing connection.
    type Config: Clone;

    /// What the part needs given when the connection node is built, from
    /// its configuration and the facts of the connection.
    fn connection_args(config: Self::Config, facts: &mut ConnectionFacts<T>) -> Self::Args;
}

/// The DATAGRAM extension is configured with what it is given when the
/// connection node is built: what it announces and how its queues are
/// bounded.
#[cfg(feature = "datagram")]
impl<T, L> EndpointPart<T, L> for sakuya_connection::datagram::Part
where
    T: v1::Choices<
            Side: sakuya_connection::datagram::DatagramSide,
            Host: sakuya_connection::datagram::DatagramChoices,
        >,
{
    type Config = sakuya_connection::datagram::DatagramConnectionArgs<
        sakuya_connection::datagram::DatagramQueuesConfigOf<T>,
    >;

    fn connection_args(config: Self::Config, _: &mut ConnectionFacts<T>) -> Self::Args {
        config
    }
}

/// The reliable stream reset extension is configured with what it
/// announces.
#[cfg(feature = "reset_stream_at")]
impl<T: v1::Choices, L> EndpointPart<T, L> for sakuya_connection::reset_stream_at::Part {
    type Config =
        sakuya_connection::v1::parameters::PartSlots<sakuya_connection::reset_stream_at::Part>;

    fn connection_args(config: Self::Config, _: &mut ConnectionFacts<T>) -> Self::Args {
        config
    }
}

/// The configurations of a list of parts, and the start values made from
/// them; `Whole` is the whole list.
pub trait PartConfigs<T: v1::Choices, Whole> {
    /// One configuration for each part, in the order of the list.
    type Configs: Clone;
    /// One part's start values for each part, in the order of the list.
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
    type Args = HCons<P::Args, Ps::Args>;

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
