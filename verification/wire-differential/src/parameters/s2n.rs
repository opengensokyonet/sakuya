//! The adapter of s2n-quic-core.
//!
//! s2n-quic-core interprets the parameters of RFC 9000,
//! `max_datagram_frame_size` (0x20, RFC 9221), and two parameters of
//! s2n-quic-dc, `dc_supported_versions` (0xdc0000) and
//! `mtu_probing_complete_support` (0xdc0002), and ignores every other ID. It
//! rejects a duplicate of each parameter it interprets. Its own limits
//! differ from RFC 9000 in places, which the categories below name.
use super::{
    Entry, ErrorRepair, MAX_DATAGRAM_FRAME_SIZE, Params, Preferred, Reference, Rejected, Repair,
    first, has_long_integer, integer_value, set_first, shorten_integers,
};
use crate::generate::var_int_as;
use s2n_codec::{DecoderBuffer, EncoderValue as _};
use s2n_quic_core::transport::parameters::{
    ClientTransportParameters, MigrationSupport, ServerTransportParameters,
};
use sakuya_wire::{parameters::codec::ReadParametersError, v1::role::Role};

/// The IDs outside RFC 9000 and RFC 9221 that s2n-quic-core interprets.
pub const EXTENSIONS: [u64; 2] = [0xdc0000, 0xdc0002];

/// The parameters an endpoint in role `sender` sent, as s2n-quic-core reads
/// them.
pub enum Read {
    Client(ClientTransportParameters),
    Server(ServerTransportParameters),
}

/// Reads with s2n-quic-core.
pub fn read_raw(bytes: &[u8], sender: Role) -> Option<Read> {
    let buffer = DecoderBuffer::new(bytes);
    match sender {
        Role::Client => buffer
            .decode::<ClientTransportParameters>()
            .ok()
            .map(|(p, _)| Read::Client(p)),
        Role::Server => buffer
            .decode::<ServerTransportParameters>()
            .ok()
            .map(|(p, _)| Read::Server(p)),
    }
}

/// The model of the parameters both endpoints may send; the parameters
/// only a server sends are the remaining arguments.
macro_rules! model {
    ($p:expr, $odcid:expr, $token:expr, $preferred:expr, $retry:expr) => {{
        let p = $p;
        Params {
            original_destination_connection_id: $odcid,
            max_idle_timeout: p.max_idle_timeout.as_u64(),
            stateless_reset_token: $token,
            max_udp_payload_size: p.max_udp_payload_size.as_u64(),
            initial_max_data: p.initial_max_data.as_u64(),
            initial_max_stream_data_bidi_local: p.initial_max_stream_data_bidi_local.as_u64(),
            initial_max_stream_data_bidi_remote: p.initial_max_stream_data_bidi_remote.as_u64(),
            initial_max_stream_data_uni: p.initial_max_stream_data_uni.as_u64(),
            initial_max_streams_bidi: p.initial_max_streams_bidi.as_u64(),
            initial_max_streams_uni: p.initial_max_streams_uni.as_u64(),
            ack_delay_exponent: u64::from(*p.ack_delay_exponent),
            max_ack_delay: p.max_ack_delay.as_u64(),
            disable_active_migration: p.migration_support == MigrationSupport::Disabled,
            preferred_address: $preferred,
            active_connection_id_limit: p.active_connection_id_limit.as_u64(),
            initial_source_connection_id: p
                .initial_source_connection_id
                .as_ref()
                .map(|id| id.as_bytes().to_vec()),
            retry_source_connection_id: $retry,
            max_datagram_frame_size: p.max_datagram_frame_size.as_u64(),
        }
    }};
}

/// The model of what s2n-quic-core read.
pub fn model(read: &Read) -> Params {
    match read {
        Read::Client(p) => model!(p, None, None, None, None),
        Read::Server(p) => model!(
            p,
            p.original_destination_connection_id
                .as_ref()
                .map(|id| id.as_bytes().to_vec()),
            p.stateless_reset_token.map(|token| token.into_inner()),
            p.preferred_address.map(|a| Preferred {
                v4: a.ipv4_address.map(|s| (<[u8; 4]>::from(*s.ip()), s.port())),
                v6: a
                    .ipv6_address
                    .map(|s| (<[u8; 16]>::from(*s.ip()), s.port())),
                cid: a.connection_id.as_bytes().to_vec(),
                token: a.stateless_reset_token.into_inner(),
            }),
            p.retry_source_connection_id
                .as_ref()
                .map(|id| id.as_bytes().to_vec())
        ),
    }
}

/// Reads with s2n-quic-core into the model.
pub fn read(bytes: &[u8], sender: Role) -> Result<Params, Rejected> {
    read_raw(bytes, sender).map(|p| model(&p)).ok_or(Rejected)
}

/// What s2n-quic-core writes for what it reads from `bytes`, or `None` if
/// it rejects them.
pub fn rewrite(bytes: &[u8], sender: Role) -> Option<Vec<u8>> {
    Some(match read_raw(bytes, sender)? {
        Read::Client(p) => p.encode_to_vec(),
        Read::Server(p) => p.encode_to_vec(),
    })
}

/// An extension parameter that s2n-quic-core interprets and sakuya does not.
pub const EXTENSION: &str = "parameter of an extension s2n implements and sakuya does not (0xdc0000, 0xdc0002 of s2n-quic-dc): s2n rejects its value, sakuya ignores it as RFC 9000 7.4.2 requires";

/// ack_delay_exponent in more than one byte.
pub const ACK_DELAY_EXPONENT_WIDTH: &str = "ack_delay_exponent encoded in more than one byte: s2n reads it as a single byte, RFC 9000 18.2 makes it a variable-length integer, which RFC 9000 16 lets take any length";

/// max_udp_payload_size above 65527.
pub const LARGE_UDP_PAYLOAD: &str = "max_udp_payload_size above 65527: s2n rejects it, RFC 9000 18.2 makes only values below 1200 invalid";

/// Connection IDs shorter than s2n-quic-core requires.
pub const SHORT_CONNECTION_ID: &str = "original_destination_connection_id below 8 bytes or retry_source_connection_id below 4: s2n rejects it, RFC 9000 18.2 sets no length and 7.3 leaves matching the packets to the handshake";

/// max_ack_delay of 2^14.
pub const MAX_ACK_DELAY_LIMIT: &str =
    "max_ack_delay of 2^14: s2n accepts it, RFC 9000 18.2 makes 2^14 or greater invalid";

/// An empty connection ID in preferred_address.
pub const EMPTY_PREFERRED_CONNECTION_ID: &str = "preferred_address with an empty connection ID: s2n accepts it, RFC 9000 18.2 MUST treat it as TRANSPORT_PARAMETER_ERROR";

/// The shortest connection IDs s2n-quic-core accepts for 0x00 and 0x10.
const CONNECTION_ID_MINIMUMS: [(u64, usize); 2] = [(0x00, 8), (0x10, 4)];

/// The largest UDP payload s2n-quic-core accepts.
const UDP_PAYLOAD_LIMIT: u64 = 65527;

/// The length of a preferred_address value with an empty connection ID.
const EMPTY_PREFERRED_LEN: usize = 4 + 2 + 16 + 2 + 1 + 16;

/// The offset of the Connection ID Length field of preferred_address.
const PREFERRED_CID_LENGTH: usize = 4 + 2 + 16 + 2;

static REJECTS: [Repair; 4] = [
    Repair {
        name: EXTENSION,
        applies: |list, _| list.iter().any(|entry| EXTENSIONS.contains(&entry.id)),
        repair: |list, _| list.retain(|entry: &Entry| !EXTENSIONS.contains(&entry.id)),
    },
    Repair {
        name: ACK_DELAY_EXPONENT_WIDTH,
        applies: |list, _| has_long_integer(list, |id| id == 0x0a),
        repair: |list, _| shorten_integers(list, |id| id == 0x0a),
    },
    Repair {
        name: LARGE_UDP_PAYLOAD,
        applies: |_, values| values.max_udp_payload_size > UDP_PAYLOAD_LIMIT,
        repair: |list, _| {
            set_first(list, 0x03, var_int_as(UDP_PAYLOAD_LIMIT, 1));
        },
    },
    Repair {
        name: SHORT_CONNECTION_ID,
        applies: |list, _| {
            CONNECTION_ID_MINIMUMS
                .iter()
                .any(|&(id, minimum)| first(list, id).is_some_and(|value| value.len() < minimum))
        },
        repair: |list, _| {
            for (id, minimum) in CONNECTION_ID_MINIMUMS {
                if first(list, id).is_some_and(|value| value.len() < minimum) {
                    set_first(list, id, vec![0; minimum]);
                }
            }
        },
    },
];

/// Whether `error` is an invalid value of the parameter `id`.
fn invalid_value(error: &crate::parameters::sakuya::Error, id: u64) -> bool {
    matches!(error, ReadParametersError::InvalidValue { id: failed, .. } if failed.get() == id)
}

static ACCEPTS: [ErrorRepair; 2] = [
    ErrorRepair {
        name: MAX_ACK_DELAY_LIMIT,
        repair: |error, list| {
            let at_limit = first(list, 0x0b)
                .and_then(integer_value)
                .is_some_and(|(value, _)| value == 1 << 14);
            if !(invalid_value(error, 0x0b) && at_limit) {
                return false;
            }
            set_first(list, 0x0b, var_int_as((1 << 14) - 1, 1))
        },
    },
    ErrorRepair {
        name: EMPTY_PREFERRED_CONNECTION_ID,
        repair: |error, list| {
            let Some(value) = first(list, 0x0d) else {
                return false;
            };
            if !(invalid_value(error, 0x0d)
                && value.len() == EMPTY_PREFERRED_LEN
                && value[PREFERRED_CID_LENGTH] == 0)
            {
                return false;
            }
            let mut value = value.to_vec();
            value[PREFERRED_CID_LENGTH] = 1;
            value.insert(PREFERRED_CID_LENGTH + 1, 0);
            set_first(list, 0x0d, value)
        },
    },
];

/// s2n-quic-core as a reference.
pub static REFERENCE: Reference = Reference {
    name: "s2n",
    read,
    rejects: &REJECTS,
    checks_duplicates: |id| id <= 0x10 || id == MAX_DATAGRAM_FRAME_SIZE || EXTENSIONS.contains(&id),
    accepts: &ACCEPTS,
};
