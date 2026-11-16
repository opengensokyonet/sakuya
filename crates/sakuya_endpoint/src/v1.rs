//! QUIC version 1 as an endpoint configures it.

use core::{fmt, num::NonZeroUsize};

use sakuya_connection::{
    layer,
    share::{LayerShare, LogicalPathKeys},
    v1::{
        self as connection, ConnectionArgs, amplification::AntiAmplificationFactor,
        connection_ids::DestinationConnectionIdConfigOf, recovery::RecoveryConfigOf,
    },
};
use sakuya_recovery::receive_journals::MaxAckRanges;
use sakuya_wire::v1::transport_parameters::TransportParameterSlots;

use crate::part::{ConnectionFacts, EndpointPart};

/// The configuration of version 1 in a connection of the choices `T` and
/// the list of parts `L`: the configuration values of [`ConnectionArgs`]
/// that are not facts of the connection.
///
/// The handshake, the capacities of the CRYPTO data the connection receives
/// and the thresholds of loss detection, which are checked against the
/// handshake's limits and the endpoint's clock, are in the configuration of
/// the role.
pub struct ConnectionConfig<T: connection::Choices, L: LogicalPathKeys> {
    /// How many times the bytes received from an address not yet validated
    /// may be sent to it; a server's limit.
    pub anti_amplification: AntiAmplificationFactor,
    /// This side's transport parameters of version 1, among them its
    /// maximum idle timeout.
    pub transport_parameters: TransportParameterSlots,
    /// The configuration the connection's recovery factory is made from.
    pub recovery: RecoveryConfigOf<T, L>,
    /// How many ranges an ACK frame this side writes reports at most.
    pub max_ack_ranges: MaxAckRanges,
    /// How many inputs the receiving call of a logical path handles at most
    /// in one poll.
    pub max_datagrams_per_poll: NonZeroUsize,
    /// How many inputs a logical path holds at most until the keys to
    /// process them come; zero holds none.
    pub max_held_inputs: usize,
    /// The configuration each logical path's destination connection ID
    /// strategy is made from.
    pub destination_connection_ids: DestinationConnectionIdConfigOf<T>,
    /// How many datagrams the sending call of a link path hands to its link
    /// at once at most.
    pub max_datagrams_per_send: NonZeroUsize,
    /// What adjusts the close the connection sends at each encryption
    /// level.
    pub immediate_close_policy: T::ImmediateClosePolicy,
}

impl<T, L> Clone for ConnectionConfig<T, L>
where
    T: connection::Choices,
    L: LogicalPathKeys,
    RecoveryConfigOf<T, L>: Clone,
    DestinationConnectionIdConfigOf<T>: Clone,
{
    fn clone(&self) -> Self {
        Self {
            anti_amplification: self.anti_amplification,
            transport_parameters: self.transport_parameters,
            recovery: self.recovery.clone(),
            max_ack_ranges: self.max_ack_ranges,
            max_datagrams_per_poll: self.max_datagrams_per_poll,
            max_held_inputs: self.max_held_inputs,
            destination_connection_ids: self.destination_connection_ids.clone(),
            max_datagrams_per_send: self.max_datagrams_per_send,
            immediate_close_policy: self.immediate_close_policy.clone(),
        }
    }
}

impl<T: connection::Choices, L: LogicalPathKeys> fmt::Debug for ConnectionConfig<T, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionConfig")
            .field("anti_amplification", &self.anti_amplification)
            .field("max_ack_ranges", &self.max_ack_ranges)
            .field("max_datagrams_per_poll", &self.max_datagrams_per_poll)
            .field("max_held_inputs", &self.max_held_inputs)
            .field("max_datagrams_per_send", &self.max_datagrams_per_send)
            .finish_non_exhaustive()
    }
}

/// Version 1 makes [`ConnectionArgs`] from its configuration and the facts
/// of the connection.
impl<T, L> EndpointPart<T, L> for connection::Part
where
    T: connection::Choices,
    L: LogicalPathKeys,
    Self: LayerShare<T, L, layer::Connection, Args = ConnectionArgs<T, L>>,
    RecoveryConfigOf<T, L>: Clone,
    DestinationConnectionIdConfigOf<T>: Clone,
{
    type Config = ConnectionConfig<T, L>;

    fn connection_args(config: Self::Config, facts: &mut ConnectionFacts<T>) -> Self::Args {
        // invariant: a list of parts holds version 1 once, and the facts
        // are made for one list.
        let core = facts.core.take().expect("version 1 takes the facts once");
        ConnectionArgs {
            crypto: core.crypto,
            handshake: core.handshake,
            client_dcid: core.client_dcid,
            original_destination_connection_id: core.original_destination_connection_id,
            anti_amplification: config.anti_amplification,
            transport_parameters: config.transport_parameters,
            first_link: core.first_link,
            recovery: config.recovery,
            loss_thresholds: core.loss_thresholds,
            max_ack_ranges: config.max_ack_ranges,
            crypto_receive: core.crypto_receive,
            first_flight: core.first_flight,
            initial_receiver: core.initial_receiver,
            max_datagrams_per_poll: config.max_datagrams_per_poll,
            max_held_inputs: config.max_held_inputs,
            destination_connection_ids: config.destination_connection_ids,
            reset_token_registry: core.reset_token_registry,
            first_local_connection_id: core.first_local_connection_id,
            max_datagrams_per_send: config.max_datagrams_per_send,
            immediate_close_policy: config.immediate_close_policy,
            close_request: core.close_request,
            stream_set: Default::default(),
            connection_handle: Default::default(),
        }
    }
}
