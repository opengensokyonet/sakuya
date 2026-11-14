//! The adapter of quinn-proto.
//!
//! quinn-proto interprets the parameters of RFC 9000, `max_datagram_frame_size`
//! (0x20, RFC 9221), `grease_quic_bit` (0x2ab2, RFC 9287) and `min_ack_delay`
//! (0xff04de1b, draft-ietf-quic-ack-frequency), and ignores every other ID,
//! the reserved ones included. It rejects a duplicate of each parameter of
//! RFC 9000 and of 0x20, and requires the value of each integer parameter of
//! RFC 9000 to be its shortest encoding.
use super::{
    Entry, INTEGER_IDS, MAX_DATAGRAM_FRAME_SIZE, Params, Preferred, Reference, Rejected, Repair,
    has_long_integer, shorten_integers,
};
use quinn_proto::{Side, transport_parameters::TransportParameters};
use sakuya_wire::v1::role::Role;

/// The IDs outside RFC 9000 and RFC 9221 that quinn-proto interprets.
pub const EXTENSIONS: [u64; 2] = [0x2ab2, 0xff04de1b];

/// The side that reads parameters an endpoint in role `sender` sent.
fn side_reading(sender: Role) -> Side {
    match sender {
        Role::Client => Side::Server,
        Role::Server => Side::Client,
    }
}

/// Reads with quinn-proto.
pub fn read_raw(bytes: &[u8], sender: Role) -> Option<TransportParameters> {
    let mut source = bytes;
    TransportParameters::read(side_reading(sender), &mut source).ok()
}

/// The model of what quinn-proto read.
pub fn model(p: &TransportParameters) -> Params {
    Params {
        original_destination_connection_id: p.original_dst_cid.map(|id| id.to_vec()),
        max_idle_timeout: p.max_idle_timeout.into_inner(),
        stateless_reset_token: p
            .stateless_reset_token
            .map(|token| (*token).try_into().expect("16 bytes")),
        max_udp_payload_size: p.max_udp_payload_size.into_inner(),
        initial_max_data: p.initial_max_data.into_inner(),
        initial_max_stream_data_bidi_local: p.initial_max_stream_data_bidi_local.into_inner(),
        initial_max_stream_data_bidi_remote: p.initial_max_stream_data_bidi_remote.into_inner(),
        initial_max_stream_data_uni: p.initial_max_stream_data_uni.into_inner(),
        initial_max_streams_bidi: p.initial_max_streams_bidi.into_inner(),
        initial_max_streams_uni: p.initial_max_streams_uni.into_inner(),
        ack_delay_exponent: p.ack_delay_exponent.into_inner(),
        max_ack_delay: p.max_ack_delay.into_inner(),
        disable_active_migration: p.disable_active_migration,
        preferred_address: p.preferred_address.map(|a| Preferred {
            v4: a.address_v4.map(|s| (s.ip().octets(), s.port())),
            v6: a.address_v6.map(|s| (s.ip().octets(), s.port())),
            cid: a.connection_id.to_vec(),
            token: (*a.stateless_reset_token).try_into().expect("16 bytes"),
        }),
        active_connection_id_limit: p.active_connection_id_limit.into_inner(),
        initial_source_connection_id: p.initial_src_cid.map(|id| id.to_vec()),
        retry_source_connection_id: p.retry_src_cid.map(|id| id.to_vec()),
        max_datagram_frame_size: p
            .max_datagram_frame_size
            .map_or(0, |size| size.into_inner()),
    }
}

/// Reads with quinn-proto into the model.
pub fn read(bytes: &[u8], sender: Role) -> Result<Params, Rejected> {
    read_raw(bytes, sender).map(|p| model(&p)).ok_or(Rejected)
}

/// What quinn-proto writes for what it reads from `bytes`, or `None` if it
/// rejects them.
pub fn rewrite(bytes: &[u8], sender: Role) -> Option<Vec<u8>> {
    let parameters = read_raw(bytes, sender)?;
    let mut output = Vec::new();
    parameters.write(&mut output);
    Some(output)
}

fn is_integer(id: u64) -> bool {
    INTEGER_IDS.contains(&id)
}

/// An extension parameter that quinn-proto interprets and sakuya does not.
pub const EXTENSION: &str = "parameter of an extension quinn implements and sakuya does not (0x2ab2 grease_quic_bit, 0xff04de1b min_ack_delay): quinn rejects its value, sakuya ignores it as RFC 9000 7.4.2 requires";

/// An integer value longer than its shortest encoding.
pub const LONG_INTEGER: &str = "integer parameter value longer than its shortest encoding: quinn rejects it, RFC 9000 16 permits any length";

static REJECTS: [Repair; 2] = [
    Repair {
        name: EXTENSION,
        applies: |list, _| list.iter().any(|entry| EXTENSIONS.contains(&entry.id)),
        repair: |list, _| list.retain(|entry: &Entry| !EXTENSIONS.contains(&entry.id)),
    },
    Repair {
        name: LONG_INTEGER,
        applies: |list, _| has_long_integer(list, is_integer),
        repair: |list, _| shorten_integers(list, is_integer),
    },
];

/// quinn-proto as a reference.
pub static REFERENCE: Reference = Reference {
    name: "quinn",
    read,
    rejects: &REJECTS,
    checks_duplicates: |id| id <= 0x10 || id == MAX_DATAGRAM_FRAME_SIZE,
    accepts: &[],
};
