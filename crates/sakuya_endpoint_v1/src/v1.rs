//! QUIC version 1 as an endpoint configures it.

use core::{fmt, num::NonZeroUsize};

use sakuya_connection::v1::{
    EventsConfigOf, ImmediateClosePolicyOf, ResumedParametersPolicyOf,
    aead_usage::KeyUpdateThreshold,
};
use sakuya_connection::{
    layer,
    share::{LayerShare, LogicalPathKeys},
    v1::{
        self as connection, ConnectionArgs, amplification::AntiAmplificationFactor,
        connection_ids::DestinationConnectionIdConfigOf, recovery::RecoveryConfigOf,
    },
};
use sakuya_recovery_v1::receive_journals::MaxAckRanges;
use sakuya_wire_v1::var_int::VarInt;
use sakuya_wire_v1::{
    stream_count::StreamCount,
    transport_parameters::{
        TransportParameterSlots, TransportParameters,
        integer::{
            InitialMaxData, InitialMaxStreamDataBidiLocal, InitialMaxStreamDataBidiRemote,
            InitialMaxStreamDataUni, InitialMaxStreamsBidi, InitialMaxStreamsUni, MaxIdleTimeout,
        },
    },
};

use crate::part::{ConnectionFacts, EndpointMarker, EndpointPart};

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
    ///
    /// A server's `preferred_address` among them gives its addresses to
    /// every connection (RFC 9000 §9.6); the connection ID and the
    /// stateless reset token in it are placeholders, which each connection
    /// replaces with the connection ID it issues for it, numbered 1. A
    /// connection with a zero-length connection ID sends no preferred
    /// address. The host binds the preferred address too, with a binding of
    /// its own on the endpoint, which sakuya does not check: what arrives
    /// there reaches the connection by its connection IDs. A client's is
    /// never sent.
    pub transport_parameters: TransportParameterSlots,
    /// The configuration the connection's recovery factory is made from.
    pub recovery: RecoveryConfigOf<T, L>,
    /// How many ranges an ACK frame this side writes reports at most.
    pub max_ack_ranges: MaxAckRanges,
    /// When this side initiates a 1-RTT key update, as far as the packets
    /// sealed with one generation go.
    pub key_update: KeyUpdateThreshold,
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
    pub immediate_close_policy: ImmediateClosePolicyOf<T>,
    /// What decides how the transport parameters of version 1 go when a
    /// server resumes a connection; a client does not use it.
    pub resumed_parameters_policy: ResumedParametersPolicyOf<T>,
    /// What the receiver of the connection's events is made from; the
    /// default receiver records nothing.
    pub events: EventsConfigOf<T, L>,
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
            key_update: self.key_update,
            max_datagrams_per_poll: self.max_datagrams_per_poll,
            max_held_inputs: self.max_held_inputs,
            destination_connection_ids: self.destination_connection_ids.clone(),
            max_datagrams_per_send: self.max_datagrams_per_send,
            immediate_close_policy: self.immediate_close_policy.clone(),
            resumed_parameters_policy: self.resumed_parameters_policy.clone(),
            events: self.events.clone(),
        }
    }
}

/// The default configuration: transport parameters that let the peer open
/// streams and send data at once, and the recommended values of the rest.
///
/// - The transport parameters: a maximum idle timeout of 30 s; 16 MiB of
///   data on the connection; 4 MiB on each bidirectional stream, either
///   side's, and 1 MiB on each unidirectional stream; 100 bidirectional
///   and 100 unidirectional streams the peer may open.
/// - The anti-amplification factor 3, the most RFC 9000 §8 allows.
/// - [`MaxAckRanges::DEFAULT`] ranges in an ACK frame.
/// - A 1-RTT key update initiated near the AEAD's confidentiality limit
///   alone.
/// - 16 datagrams handled in one poll of a logical path's receiving call,
///   16 inputs held until their keys come, and 16 datagrams handed to a
///   link at once.
/// - The recovery factory's, the destination connection ID strategy's, the
///   close policy's, the policy on resumption's and the event receiver's
///   own defaults.
impl<T, L> Default for ConnectionConfig<T, L>
where
    T: connection::Choices,
    L: LogicalPathKeys,
    RecoveryConfigOf<T, L>: Default,
    DestinationConnectionIdConfigOf<T>: Default,
    ImmediateClosePolicyOf<T>: Default,
    ResumedParametersPolicyOf<T>: Default,
{
    fn default() -> Self {
        Self {
            anti_amplification: AntiAmplificationFactor::MAX,
            transport_parameters: default_transport_parameters(),
            recovery: RecoveryConfigOf::<T, L>::default(),
            max_ack_ranges: MaxAckRanges::DEFAULT,
            key_update: KeyUpdateThreshold::default(),
            max_datagrams_per_poll: SIXTEEN,
            max_held_inputs: 16,
            destination_connection_ids: DestinationConnectionIdConfigOf::<T>::default(),
            max_datagrams_per_send: SIXTEEN,
            immediate_close_policy: ImmediateClosePolicyOf::<T>::default(),
            resumed_parameters_policy: ResumedParametersPolicyOf::<T>::default(),
            events: EventsConfigOf::<T, L>::default(),
        }
    }
}

/// Sixteen, for the limits of the default configuration.
// invariant: 16 is not zero
const SIXTEEN: NonZeroUsize = NonZeroUsize::new(16).expect("16 is not zero");

/// The transport parameters of the default configuration.
fn default_transport_parameters() -> TransportParameterSlots {
    let mut parameters = TransportParameters::<Vec<u8>>::new();
    parameters.set(MaxIdleTimeout::new(VarInt::from_u32(30_000)));
    parameters.set(InitialMaxData::new(VarInt::from_u32(16 << 20)));
    parameters.set(InitialMaxStreamDataBidiLocal::new(VarInt::from_u32(
        4 << 20,
    )));
    parameters.set(InitialMaxStreamDataBidiRemote::new(VarInt::from_u32(
        4 << 20,
    )));
    parameters.set(InitialMaxStreamDataUni::new(VarInt::from_u32(1 << 20)));
    parameters.set(InitialMaxStreamsBidi::new(HUNDRED_STREAMS));
    parameters.set(InitialMaxStreamsUni::new(HUNDRED_STREAMS));
    parameters.known
}

/// A hundred streams, for the default stream limits.
// invariant: 100 is below 2^60
const HUNDRED_STREAMS: StreamCount = match StreamCount::new(100) {
    Ok(count) => count,
    Err(_) => panic!("100 is a stream count"),
};

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

/// Version 1 is its own part of the endpoint: it takes the facts the
/// endpoint knows about the connection.
impl EndpointMarker for connection::Part {
    type Connection = Self;
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

    fn connection_args(
        config: Self::Config,
        facts: &mut ConnectionFacts<T>,
    ) -> ConnectionArgs<T, L> {
        // invariant: a list of parts holds version 1 once, and the facts
        // are made for one list.
        let core = facts.core.take().expect("version 1 takes the facts once");
        ConnectionArgs {
            crypto: core.crypto,
            handshake: core.handshake,
            side: core.side,
            client_dcid: core.client_dcid,
            original_destination_connection_id: core.original_destination_connection_id,
            anti_amplification: config.anti_amplification,
            transport_parameters: config.transport_parameters,
            first_link: core.first_link,
            recovery: config.recovery,
            loss_thresholds: core.loss_thresholds,
            max_ack_ranges: config.max_ack_ranges,
            key_update: config.key_update,
            crypto_receive: core.crypto_receive,
            first_flight: core.first_flight,
            initial_receiver: core.initial_receiver,
            max_datagrams_per_poll: config.max_datagrams_per_poll,
            max_held_inputs: config.max_held_inputs,
            destination_connection_ids: config.destination_connection_ids,
            reset_token_registry: core.reset_token_registry,
            first_local_connection_id: core.first_local_connection_id,
            local_connection_id_issuer: core.local_connection_id_issuer,
            max_datagrams_per_send: config.max_datagrams_per_send,
            immediate_close_policy: config.immediate_close_policy,
            resumed_parameters_policy: config.resumed_parameters_policy,
            close_request: core.close_request,
            stream_set: Default::default(),
            events: config.events,
        }
    }
}
