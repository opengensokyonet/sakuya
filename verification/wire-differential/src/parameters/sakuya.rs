//! The adapter of sakuya.
//!
//! sakuya reads with the parameter types of version 1, DATAGRAM and
//! reset_stream_at ([`Parts`]). Integer values are read in any width and
//! written in their shortest encoding; the parameters that a type claims are
//! written in the order of the list, then the unknown parameters in the
//! order they were read, with their values as read.
use super::{Params, Preferred};
use core::{convert::Infallible, marker::PhantomData};
use sakuya_wire::{
    datagram::{self, MaxDatagramFrameSize},
    parameters::ParametersOf,
    parts::HList,
    reset_stream_at,
    v1::{
        self,
        role::Role,
        transport_parameters::{
            TransportParameterSpace, TransportParameters,
            codec::{
                ReadTransportParametersError, ReadTransportParametersHostExt as _,
                WriteTransportParametersHostExt as _,
            },
            connection_id::{
                InitialSourceConnectionId, OriginalDestinationConnectionId, RetrySourceConnectionId,
            },
            integer::{AckDelayExponent, MaxAckDelay},
            preferred_address::{PreferredAddress, PreferredAddressFamilies},
            stateless_reset_token::StatelessResetToken,
        },
    },
};

/// The parts the comparisons read with.
pub type Parts = HList![v1::Part, datagram::Part, reset_stream_at::Part];

/// Version 1 alone.
pub type V1 = HList![v1::Part];

/// Parameters read from a byte slice with the parts `Ps`.
pub type Read<'a, Ps = Parts> = TransportParameters<&'a [u8], Ps>;

/// The failure of reading from a byte slice with the parts `Ps`.
pub type Error<Ps = Parts> = ReadTransportParametersError<Infallible, Ps>;

/// Reads `bytes` with the parts `Ps`, as parameters an endpoint in role
/// `sender` sent.
pub fn read_with<Ps>(bytes: &[u8], sender: Role) -> Result<Read<'_, Ps>, Error<Ps>>
where
    Ps: ParametersOf<TransportParameterSpace>,
{
    let mut source = bytes;
    source.sync_read_transport_parameters_unpin(sender, PhantomData::<Ps>)
}

/// Reads `bytes` with [`Parts`].
pub fn read(bytes: &[u8], sender: Role) -> Result<Read<'_>, Error> {
    read_with::<Parts>(bytes, sender)
}

/// The model of parameters read with a list of parts that has version 1;
/// `$datagram` is the value of `max_datagram_frame_size`.
#[macro_export]
macro_rules! sakuya_model {
    ($parameters:expr, $datagram:expr) => {{
        use sakuya_wire::v1::transport_parameters::{
            connection_id::{
                InitialSourceConnectionId, OriginalDestinationConnectionId, RetrySourceConnectionId,
            },
            disable_active_migration::DisableActiveMigration,
            integer::{
                AckDelayExponent, ActiveConnectionIdLimit, InitialMaxData,
                InitialMaxStreamDataBidiLocal, InitialMaxStreamDataBidiRemote,
                InitialMaxStreamDataUni, InitialMaxStreamsBidi, InitialMaxStreamsUni, MaxAckDelay,
                MaxIdleTimeout, MaxUdpPayloadSize,
            },
            preferred_address::PreferredAddress,
            stateless_reset_token::StatelessResetToken,
        };
        let p = &$parameters;
        $crate::parameters::Params {
            original_destination_connection_id: p
                .get::<OriginalDestinationConnectionId, _>()
                .map(|id| id.get().as_bytes().to_vec()),
            max_idle_timeout: p.get_or_default::<MaxIdleTimeout, _>().get().get(),
            stateless_reset_token: p
                .get::<StatelessResetToken, _>()
                .map(|token| *token.get().as_bytes()),
            max_udp_payload_size: p.get_or_default::<MaxUdpPayloadSize, _>().get().get(),
            initial_max_data: p.get_or_default::<InitialMaxData, _>().get().get(),
            initial_max_stream_data_bidi_local: p
                .get_or_default::<InitialMaxStreamDataBidiLocal, _>()
                .get()
                .get(),
            initial_max_stream_data_bidi_remote: p
                .get_or_default::<InitialMaxStreamDataBidiRemote, _>()
                .get()
                .get(),
            initial_max_stream_data_uni: p
                .get_or_default::<InitialMaxStreamDataUni, _>()
                .get()
                .get(),
            initial_max_streams_bidi: p.get_or_default::<InitialMaxStreamsBidi, _>().get().get(),
            initial_max_streams_uni: p.get_or_default::<InitialMaxStreamsUni, _>().get().get(),
            ack_delay_exponent: p.get_or_default::<AckDelayExponent, _>().get().get(),
            max_ack_delay: p.get_or_default::<MaxAckDelay, _>().get().get(),
            disable_active_migration: p.get::<DisableActiveMigration, _>().is_some(),
            preferred_address: p
                .get::<PreferredAddress, _>()
                .map($crate::parameters::sakuya::preferred),
            active_connection_id_limit: p
                .get_or_default::<ActiveConnectionIdLimit, _>()
                .get()
                .get(),
            initial_source_connection_id: p
                .get::<InitialSourceConnectionId, _>()
                .map(|id| id.get().as_bytes().to_vec()),
            retry_source_connection_id: p
                .get::<RetrySourceConnectionId, _>()
                .map(|id| id.get().as_bytes().to_vec()),
            max_datagram_frame_size: $datagram,
        }
    }};
}

/// The model of a preferred address.
pub fn preferred(address: &PreferredAddress) -> Preferred {
    let (v4, v6) = match address.addresses {
        PreferredAddressFamilies::Ipv4(v4) => (Some(v4), None),
        PreferredAddressFamilies::Ipv6(v6) => (None, Some(v6)),
        PreferredAddressFamilies::Both(v4, v6) => (Some(v4), Some(v6)),
    };
    Preferred {
        v4: v4.map(|a| (a.ip().octets(), a.port())),
        v6: v6.map(|a| (a.ip().octets(), a.port())),
        cid: address.connection_id.as_bytes().to_vec(),
        token: *address.stateless_reset_token.as_bytes(),
    }
}

/// The model of parameters read with [`Parts`].
pub fn model(parameters: &Read<'_>) -> Params {
    let datagram = parameters
        .get_or_default::<MaxDatagramFrameSize, _>()
        .get()
        .get();
    crate::sakuya_model!(parameters, datagram)
}

/// Reads `bytes` into the model.
pub fn read_model(bytes: &[u8], sender: Role) -> Result<Params, Error> {
    read(bytes, sender).map(|parameters| model(&parameters))
}

/// Writes `parameters` as an endpoint in role `sender`, checking that the
/// writer writes as many bytes as `encoded_len` states.
pub fn write(parameters: Read<'_>, sender: Role) -> Vec<u8> {
    let expected = parameters.encoded_len();
    let mut output = Vec::new();
    output
        .sync_write_transport_parameters_unpin(parameters, sender)
        .expect("parameters that were read can be written");
    assert_eq!(output.len(), expected, "encoded_len");
    output
}

/// What sakuya writes for what it reads from `bytes`, or `None` if it
/// rejects them.
pub fn rewrite(bytes: &[u8], sender: Role) -> Option<Vec<u8>> {
    let parameters = read(bytes, sender).ok()?;
    Some(write(parameters, sender))
}

/// Empties the slots of `parameters` that RFC 9000 §7.4.1 forbids a client
/// to remember for 0-RTT.
pub fn forget_for_zero_rtt(parameters: &mut Read<'_>) {
    *parameters.slot_mut::<AckDelayExponent, _>() = None;
    *parameters.slot_mut::<MaxAckDelay, _>() = None;
    *parameters.slot_mut::<InitialSourceConnectionId, _>() = None;
    *parameters.slot_mut::<OriginalDestinationConnectionId, _>() = None;
    *parameters.slot_mut::<PreferredAddress, _>() = None;
    *parameters.slot_mut::<RetrySourceConnectionId, _>() = None;
    *parameters.slot_mut::<StatelessResetToken, _>() = None;
}
