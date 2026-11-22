//! What the state of a connection of version 1 makes its components from,
//! given once by whoever makes the connection ([`StateConnectionArgs`]);
//! version 1's arguments of the connection node hold them
//! ([`ConnectionArgs::state`](super::ConnectionArgs::state)), and a
//! component finds them with [`FindArgs`].

use sakuya_recovery_v1::{loss::LossThresholds, receive_journals::MaxAckRanges};

use super::{
    aead_usage::KeyUpdateThreshold,
    connection_ids::{
        DestinationConnectionIdConfigOf, FirstLocalConnectionId, LocalConnectionIdIssuer,
    },
    crypto::CryptoReceiveCapacities,
    recovery::RecoveryConfigOf,
    state_choices::StateChoices,
};
use crate::{
    component::ArgsOf,
    layer,
    share::{ConnectionArgsOf, FindArgs, LogicalPathKeys},
};

/// What the state of a connection of version 1 needs to make its
/// components in the connection node, given once by whoever makes the
/// connection.
pub struct StateConnectionArgs<T: StateChoices, L: LogicalPathKeys> {
    /// The backend the packet protection keys are derived with.
    pub crypto: T::Crypto,
    /// The configuration the connection's recovery factory is made from.
    pub recovery: RecoveryConfigOf<T, L>,
    /// The thresholds of loss detection, checked against the precision of
    /// the clock's timers.
    pub loss_thresholds: LossThresholds,
    /// How many ranges an ACK frame this side writes reports at most.
    pub max_ack_ranges: MaxAckRanges,
    /// When this side initiates a 1-RTT key update, as far as the packets
    /// sealed with one generation go.
    pub key_update: KeyUpdateThreshold,
    /// How much CRYPTO data each encryption level holds past what the
    /// handshake engine has read, for this side's role.
    pub crypto_receive: CryptoReceiveCapacities,
    /// The configuration each logical path's destination connection ID
    /// strategy is made from.
    pub destination_connection_ids: DestinationConnectionIdConfigOf<T>,
    /// What registers the reset tokens of the peer's connection IDs, as the
    /// endpoint shares it with the router that detects stateless resets.
    pub reset_token_registry: T::ResetTokenRegistry,
    /// The first of this side's connection IDs, with its stateless reset
    /// token: the Source Connection ID of the long headers this side sends.
    pub first_local_connection_id: FirstLocalConnectionId,
    /// What issues this side's connection IDs after the first, with the
    /// registration of the first with routing, which the first logical
    /// path's local connection ID strategy keeps.
    pub local_connection_id_issuer: LocalConnectionIdIssuer<T::ConnectionIdIssuer>,
}

/// The arguments the state of a connection of version 1 makes its
/// components from, among the parts' arguments `args` of the connection
/// node; `I` is where they are, which the compiler infers.
pub fn state_args<T: StateChoices, L, I>(
    args: &mut ArgsOf<T, L, layer::Connection>,
) -> &mut StateConnectionArgs<T, L>
where
    ConnectionArgsOf<T, L>: FindArgs<StateConnectionArgs<T, L>, I>,
    L: crate::share::LineagePartList<T> + LogicalPathKeys,
{
    args.find_args_mut()
}
