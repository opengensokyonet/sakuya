//! Transport parameters in the three implementations.
//!
//! [`Params`] is the neutral model: the value of every parameter of RFC 9000
//! and RFC 9221 that all three implementations interpret, with the default
//! of an absent parameter applied where RFC 9000 §18.2 gives one. Each
//! implementation has an adapter that reads into the model and writes what
//! it read ([`sakuya`], [`quinn`], [`s2n`]). [`classify`] compares sakuya
//! with one reference on one input.
//!
//! A divergence is classified by repairing the input: each known category
//! names one property of the input and a repair that removes it without
//! touching anything else, such as dropping a parameter that only the
//! reference interprets, or shortening an integer encoding. The repairs that
//! apply are made one after another, and the divergence belongs to the first
//! category only if the two implementations then read the repaired input to
//! the same values. Anything else is unclassified.
use crate::tally::{self, Comparison};
use sakuya_wire::v1::role::Role;

pub mod generate;
pub mod quinn;
pub mod s2n;
pub mod sakuya;

/// The parameters of RFC 9000 and RFC 9221 as all implementations can state
/// them; integer parameters hold the default of RFC 9000 §18.2 or RFC 9221
/// §3 when absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    pub original_destination_connection_id: Option<Vec<u8>>,
    pub max_idle_timeout: u64,
    pub stateless_reset_token: Option<[u8; 16]>,
    pub max_udp_payload_size: u64,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub ack_delay_exponent: u64,
    pub max_ack_delay: u64,
    pub disable_active_migration: bool,
    pub preferred_address: Option<Preferred>,
    pub active_connection_id_limit: u64,
    pub initial_source_connection_id: Option<Vec<u8>>,
    pub retry_source_connection_id: Option<Vec<u8>>,
    pub max_datagram_frame_size: u64,
}

/// A preferred address; a family is `None` when its address and port are
/// all zeros on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preferred {
    pub v4: Option<([u8; 4], u16)>,
    pub v6: Option<([u8; 16], u16)>,
    pub cid: Vec<u8>,
    pub token: [u8; 16],
}

/// The IDs of RFC 9000 §18.2 whose value is one variable-length integer.
pub const INTEGER_IDS: [u64; 11] = [
    0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0e,
];

/// The ID of `max_datagram_frame_size` (RFC 9221 §3).
pub const MAX_DATAGRAM_FRAME_SIZE: u64 = 0x20;

/// The ID of `reset_stream_at` (draft-ietf-quic-reliable-stream-reset-11
/// §3).
pub const RESET_STREAM_AT: u64 = 0x1d;

/// One parameter of a well-formed sequence, with the widths of its ID and
/// Length fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub id: u64,
    pub value: Vec<u8>,
    pub id_width: usize,
    pub length_width: usize,
}

impl Entry {
    /// A parameter with ID and Length in their shortest encodings.
    pub fn new(id: u64, value: Vec<u8>) -> Self {
        Self {
            id_width: shortest_width(id),
            length_width: shortest_width(value.len() as u64),
            id,
            value,
        }
    }
}

/// A variable-length integer at the start of `bytes`: the value and the
/// width, or `None` if `bytes` is too short.
pub fn var_int(bytes: &[u8]) -> Option<(u64, usize)> {
    let first = *bytes.first()?;
    let width = 1usize << (first >> 6);
    let encoding = bytes.get(..width)?;
    let value = encoding[1..]
        .iter()
        .fold(u64::from(first & 0x3f), |value, &byte| {
            (value << 8) | u64::from(byte)
        });
    Some((value, width))
}

/// The width of the shortest encoding of `value`, below 2^62.
pub fn shortest_width(value: u64) -> usize {
    match value {
        0..=63 => 1,
        64..=16383 => 2,
        16384..=0x3fff_ffff => 4,
        _ => 8,
    }
}

/// The value of an integer parameter: one variable-length integer and
/// nothing after it.
pub fn integer_value(value: &[u8]) -> Option<(u64, usize)> {
    var_int(value).filter(|&(_, width)| width == value.len())
}

/// The parameters of a well-formed sequence, read without any rule of the
/// implementations under test, or `None` if the sequence ends within a
/// parameter.
pub fn entries(bytes: &[u8]) -> Option<Vec<Entry>> {
    let mut rest = bytes;
    let mut list = Vec::new();
    while !rest.is_empty() {
        let (id, id_width) = var_int(rest)?;
        rest = &rest[id_width..];
        let (length, length_width) = var_int(rest)?;
        rest = &rest[length_width..];
        let length = usize::try_from(length).ok().filter(|&l| l <= rest.len())?;
        list.push(Entry {
            id,
            value: rest[..length].to_vec(),
            id_width,
            length_width,
        });
        rest = &rest[length..];
    }
    Some(list)
}

/// The encoding of `list`, each ID and Length in the width of its entry.
pub fn encode(list: &[Entry]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for entry in list {
        bytes.extend(crate::generate::var_int_as(entry.id, entry.id_width));
        bytes.extend(crate::generate::var_int_as(
            entry.value.len() as u64,
            entry.length_width,
        ));
        bytes.extend(&entry.value);
    }
    bytes
}

/// The position of each ID that sakuya's parameter list claims, in the
/// order sakuya writes them: version 1, then DATAGRAM, then reset_stream_at.
fn list_position(id: u64) -> Option<usize> {
    match id {
        0x00..=0x10 => Some(id as usize),
        MAX_DATAGRAM_FRAME_SIZE => Some(0x11),
        RESET_STREAM_AT => Some(0x12),
        _ => None,
    }
}

/// Whether `bytes` is the encoding sakuya writes for what it reads from it:
/// the claimed parameters in the order of the list, then the others, every
/// ID, Length and integer value in its shortest encoding.
pub fn is_canonical(bytes: &[u8]) -> bool {
    let Some(list) = entries(bytes) else {
        return false;
    };
    let shortest = list.iter().all(|entry| {
        entry.id_width == shortest_width(entry.id)
            && entry.length_width == shortest_width(entry.value.len() as u64)
            && (!(INTEGER_IDS.contains(&entry.id) || entry.id == MAX_DATAGRAM_FRAME_SIZE)
                || integer_value(&entry.value)
                    .is_some_and(|(value, width)| width == shortest_width(value)))
    });
    // The unknown parameters sort after the others.
    let positions: Vec<_> = list
        .iter()
        .map(|entry| list_position(entry.id).unwrap_or(usize::MAX))
        .collect();
    shortest && positions.is_sorted()
}

/// A reference implementation rejected the parameters; the comparisons are
/// about acceptance and values, not about the reasons.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rejected;

/// What a reference implementation offers a comparison.
pub struct Reference {
    /// The name in tallies.
    pub name: &'static str,
    /// Reads parameters an endpoint in role `sender` sent.
    pub read: fn(&[u8], Role) -> Result<Params, Rejected>,
    /// Repairs for inputs sakuya accepts and the reference rejects.
    pub rejects: &'static [Repair],
    /// The IDs whose duplicates the reference rejects.
    pub checks_duplicates: fn(u64) -> bool,
    /// Repairs for errors of sakuya on inputs the reference accepts, besides
    /// the ones every reference shares.
    pub accepts: &'static [ErrorRepair],
}

/// A known category of inputs that sakuya accepts and a reference rejects:
/// its name, whether it applies to a list of parameters that sakuya read
/// to `values`, and the repair.
pub struct Repair {
    pub name: &'static str,
    pub applies: fn(&[Entry], &Params) -> bool,
    pub repair: fn(&mut Vec<Entry>, &Params),
}

/// A known category of inputs that a reference accepts and sakuya rejects
/// with `error`: its name, and a repair of the list if the error belongs to
/// it.
pub struct ErrorRepair {
    pub name: &'static str,
    pub repair: fn(&sakuya::Error, &mut Vec<Entry>) -> bool,
}

/// Duplicates of parameters the reference does not check: sakuya rejects
/// them as RFC 9000 §7.4 recommends, and the repair keeps the first.
pub const DUPLICATE: &str = "duplicate of a parameter the reference ignores or does not check: sakuya rejects it, RFC 9000 7.4 SHOULD treat it as TRANSPORT_PARAMETER_ERROR";

/// reset_stream_at with a value: sakuya rejects it as the draft requires,
/// and neither reference implements the extension.
pub const RESET_STREAM_AT_VALUE: &str = "reset_stream_at with a non-empty value: sakuya rejects it, draft-ietf-quic-reliable-stream-reset-11 3 MUST; the reference does not implement the extension";

fn remove_duplicates(list: &mut Vec<Entry>, id: u64) {
    let mut seen = false;
    list.retain(|entry| entry.id != id || !std::mem::replace(&mut seen, true));
}

/// Sets the value of the first parameter `id` in `list`.
pub fn set_first(list: &mut [Entry], id: u64, value: Vec<u8>) -> bool {
    match list.iter_mut().find(|entry| entry.id == id) {
        Some(entry) => {
            entry.length_width = shortest_width(value.len() as u64);
            entry.value = value;
            true
        }
        None => false,
    }
}

/// The value of the first parameter `id` in `list`.
pub fn first(list: &[Entry], id: u64) -> Option<&[u8]> {
    list.iter()
        .find(|entry| entry.id == id)
        .map(|entry| entry.value.as_slice())
}

/// Repairs a failure of sakuya that every reference shares a verdict on.
fn shared_repair(
    reference: &Reference,
    error: &sakuya::Error,
    list: &mut Vec<Entry>,
) -> Option<&'static str> {
    use sakuya_wire::parameters::codec::ReadParametersError;
    match error {
        ReadParametersError::Duplicate { source }
            if !(reference.checks_duplicates)(source.id().get()) =>
        {
            remove_duplicates(list, source.id().get());
            Some(DUPLICATE)
        }
        ReadParametersError::InvalidValue { id, .. } if id.get() == RESET_STREAM_AT => {
            set_first(list, RESET_STREAM_AT, Vec::new());
            Some(RESET_STREAM_AT_VALUE)
        }
        _ => None,
    }
}

/// Compares sakuya against `reference` on `bytes`, sent by an endpoint in
/// role `sender`.
pub fn classify(reference: &Reference, bytes: &[u8], sender: Role) -> Comparison {
    let ours = sakuya::read_model(bytes, sender);
    let theirs = (reference.read)(bytes, sender);
    match (&ours, &theirs) {
        (Ok(a), Ok(b)) if a == b => return Comparison::Agree,
        (Err(_), Err(Rejected)) => return Comparison::Agree,
        (Ok(_), Ok(_)) => return Comparison::Unclassified,
        _ => {}
    }
    // One of them accepts the input, so it is a well-formed sequence.
    let Some(mut list) = entries(bytes) else {
        return Comparison::Unclassified;
    };
    let mut category = None;
    // Each repair removes a parameter, shortens or changes one value, so a
    // few more rounds than parameters always end.
    for _ in 0..list.len() + 4 {
        let bytes = encode(&list);
        let ours = sakuya::read(&bytes, sender);
        let theirs = (reference.read)(&bytes, sender);
        let name = match (ours, theirs) {
            (Ok(a), Ok(b)) if sakuya::model(&a) == b => {
                return category.map_or(Comparison::Unclassified, Comparison::Known);
            }
            (Ok(a), Err(Rejected)) => {
                let values = sakuya::model(&a);
                let applicable: Vec<_> = reference
                    .rejects
                    .iter()
                    .filter(|repair| (repair.applies)(&list, &values))
                    .collect();
                for repair in &applicable {
                    (repair.repair)(&mut list, &values);
                }
                match applicable.first() {
                    Some(repair) => repair.name,
                    None => return Comparison::Unclassified,
                }
            }
            // Once a repair has been made, a reference may reject what is
            // left for a reason of its own while sakuya still rejects it;
            // sakuya's failure is repaired first.
            (Err(error), theirs) if theirs.is_ok() || category.is_some() => {
                let shared = shared_repair(reference, &error, &mut list);
                let own = || {
                    reference
                        .accepts
                        .iter()
                        .find(|repair| (repair.repair)(&error, &mut list))
                        .map(|repair| repair.name)
                };
                match shared.or_else(own) {
                    Some(name) => name,
                    None => return Comparison::Unclassified,
                }
            }
            _ => return Comparison::Unclassified,
        };
        category.get_or_insert(name);
    }
    Comparison::Unclassified
}

/// Shortens the value of each integer parameter whose ID `selected` accepts
/// to its shortest encoding.
pub fn shorten_integers(list: &mut [Entry], selected: fn(u64) -> bool) {
    for entry in list.iter_mut().filter(|entry| selected(entry.id)) {
        if let Some((value, _)) = integer_value(&entry.value) {
            entry.value = crate::generate::var_int_as(value, 1);
            entry.length_width = shortest_width(entry.value.len() as u64);
        }
    }
}

/// Whether an integer parameter whose ID `selected` accepts has a value
/// longer than its shortest encoding.
pub fn has_long_integer(list: &[Entry], selected: fn(u64) -> bool) -> bool {
    list.iter().any(|entry| {
        selected(entry.id)
            && integer_value(&entry.value)
                .is_some_and(|(value, width)| width > shortest_width(value))
    })
}

/// The references.
pub fn references() -> [&'static Reference; 2] {
    [&quinn::REFERENCE, &s2n::REFERENCE]
}

/// Compares against both references and tallies the results under `area`.
pub fn compare_all(area: &str, bytes: &[u8], sender: Role) -> [Comparison; 2] {
    references().map(|reference| {
        let result = classify(reference, bytes, sender);
        tally::tally(area, reference.name, result, || {
            format!("{sender:?} {}", tally::hex(bytes))
        });
        result
    })
}

/// What sakuya writes for what it reads from `bytes`, compared against both
/// references, or `None` if sakuya rejects `bytes`.
pub fn sakuya_written(bytes: &[u8], sender: Role) -> Option<[Comparison; 2]> {
    let written = sakuya::rewrite(bytes, sender)?;
    Some(compare_all("parameters/sakuya-written", &written, sender))
}
