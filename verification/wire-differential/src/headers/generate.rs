//! Proptest strategies for datagrams and the headers a sender writes.
use crate::generate::{var_int_as, width};
use proptest::{collection::vec, prelude::*, sample::select};
use sakuya_wire::connection_id::ConnectionIdLength;

/// Versions a long header carries: mostly 1, sometimes Version Negotiation,
/// a reserved version or another one.
fn version() -> impl Strategy<Value = u32> + Clone {
    select(vec![
        0u32,
        1,
        1,
        1,
        1,
        1,
        0x6b33_43cf,
        0x0a0a_0a0a,
        0xff00_001d,
        0xdead_beef,
    ])
}

/// A connection ID as a long header states it: mostly what version 1
/// allows, sometimes longer, up to 255 bytes.
fn wire_cid() -> impl Strategy<Value = Vec<u8>> + Clone {
    prop_oneof![
        8 => vec(any::<u8>(), 0..=20),
        1 => vec(any::<u8>(), 21..=32),
        1 => vec(any::<u8>(), 255),
    ]
}

/// The destination connection ID length that short headers are read with.
pub fn short_dcid_len() -> impl Strategy<Value = ConnectionIdLength> + Clone {
    select(vec![0usize, 0, 4, 8, 8, 16, 20])
        .prop_map(|length| ConnectionIdLength::new(length).unwrap())
}

/// The fields of a long header packet, before they are laid out.
#[derive(Clone, Debug)]
pub struct LongFields {
    pub first: u8,
    pub version: u32,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub token: Vec<u8>,
    /// The packet number and payload, or the supported version list.
    pub body: Vec<u8>,
    /// How far the Length field is off the length of `body`.
    pub delta: i64,
    /// Bytes after the Length field's range.
    pub tail: Vec<u8>,
    pub token_width: usize,
    pub length_width: usize,
}

impl LongFields {
    /// The packet: a Version Negotiation packet for version 0, a Retry
    /// packet with a 16-byte tag for type 3 of version 1, and otherwise a
    /// version 1 layout with a Length field.
    pub fn bytes(&self) -> Vec<u8> {
        let first = self.first | 0x80;
        let mut bytes = vec![first];
        bytes.extend(self.version.to_be_bytes());
        bytes.push(self.dcid.len() as u8);
        bytes.extend(&self.dcid);
        bytes.push(self.scid.len() as u8);
        bytes.extend(&self.scid);
        if self.version == 0 {
            bytes.extend(self.body.as_chunks::<4>().0.iter().flatten());
            return bytes;
        }
        let ty = (first >> 4) & 3;
        if ty == 3 && self.version == 1 {
            bytes.extend(&self.token);
            bytes.extend([0xaa; 16]);
            return bytes;
        }
        if ty == 0 {
            bytes.extend(var_int_as(self.token.len() as u64, self.token_width));
            bytes.extend(&self.token);
        }
        let length = (self.body.len() as i64 + self.delta).max(0) as u64;
        bytes.extend(var_int_as(length, self.length_width));
        bytes.extend(&self.body);
        bytes.extend(&self.tail);
        bytes
    }
}

fn long_fields(dcid: impl Strategy<Value = Vec<u8>>) -> impl Strategy<Value = LongFields> {
    (
        any::<u8>(),
        version(),
        dcid,
        wire_cid(),
        vec(any::<u8>(), 0..32),
        vec(any::<u8>(), 0..48),
        select(vec![0i64, 0, 0, 0, 0, -1, 1, 8]),
        vec(any::<u8>(), 0..24),
        width(),
        width(),
    )
        .prop_map(
            |(first, version, dcid, scid, token, body, delta, tail, token_width, length_width)| {
                LongFields {
                    first,
                    version,
                    dcid,
                    scid,
                    token,
                    body,
                    delta,
                    tail,
                    token_width,
                    length_width,
                }
            },
        )
}

/// A long header packet, mostly well formed.
pub fn long_packet() -> impl Strategy<Value = Vec<u8>> {
    long_fields(wire_cid()).prop_map(|fields| fields.bytes())
}

/// A short header packet: a first byte with the form bit clear and anything
/// after it.
pub fn short_packet() -> impl Strategy<Value = Vec<u8>> {
    (any::<u8>(), vec(any::<u8>(), 0..48)).prop_map(|(first, rest)| {
        let mut bytes = vec![first & 0x7f];
        bytes.extend(rest);
        bytes
    })
}

/// A datagram for the header readers, with the short header connection ID
/// length to read it with: one packet, often damaged or cut short.
pub fn datagram() -> impl Strategy<Value = (Vec<u8>, ConnectionIdLength)> {
    let packet =
        prop_oneof![6 => long_packet(), 2 => short_packet(), 1 => vec(any::<u8>(), 0..64)].boxed();
    let damaged = (
        packet.clone(),
        any::<prop::sample::Index>(),
        any::<prop::sample::Index>(),
        any::<u8>(),
    )
        .prop_map(|(mut bytes, at, cut, value)| {
            if !bytes.is_empty() {
                let at = at.index(bytes.len());
                bytes[at] = value;
                bytes.truncate(cut.index(bytes.len() + 1));
            }
            bytes
        });
    (prop_oneof![3 => packet, 1 => damaged], short_dcid_len())
}

/// What follows the long header packets of a coalesced datagram.
#[derive(Clone, Debug)]
enum Tail {
    Nothing,
    /// A short header packet with this first byte and rest.
    Short(u8, Vec<u8>),
    /// Another packet of any kind, or random bytes.
    Other(Vec<u8>),
}

/// A datagram of several coalesced packets, with the short header
/// connection ID length to read it with.
///
/// Most packets share one destination connection ID of that length; some
/// have another, which RFC 9000 §12.2 has the receiver ignore. A short
/// header packet, another kind of packet or random bytes may follow the
/// long header packets; one in eight datagrams is damaged in one byte.
pub fn coalesced() -> impl Strategy<Value = (Vec<u8>, ConnectionIdLength)> {
    let part = (
        long_fields(wire_cid()),
        select(vec![true, true, true, true, true, false]),
    );
    let tail = prop_oneof![
        2 => Just(Tail::Nothing),
        3 => (any::<u8>(), vec(any::<u8>(), 0..40)).prop_map(|(first, rest)| Tail::Short(first, rest)),
        2 => prop_oneof![long_packet(), vec(any::<u8>(), 0..40)].prop_map(Tail::Other),
    ];
    (
        short_dcid_len(),
        vec(any::<u8>(), 20),
        vec(part, 1..5),
        tail,
        select(vec![false, false, false, false, false, false, false, true]),
        any::<prop::sample::Index>(),
        any::<u8>(),
    )
        .prop_map(|(len, pool, parts, tail, damage, at, value)| {
            let shared = &pool[..len.get()];
            let mut bytes = Vec::new();
            for (mut fields, use_shared) in parts {
                if use_shared {
                    fields.dcid = shared.to_vec();
                    // Packets with a Length field, exact in most of them.
                    fields.version = 1;
                    fields.first = (fields.first & !0x30) | ((fields.first % 3) << 4) | 0x40;
                    fields.delta = if fields.delta == 8 { -1 } else { 0 };
                    fields.tail.clear();
                }
                bytes.extend(fields.bytes());
            }
            match tail {
                Tail::Nothing => {}
                Tail::Short(first, rest) => {
                    bytes.push((first & 0x7f) | 0x40);
                    bytes.extend(shared);
                    bytes.extend(rest);
                }
                Tail::Other(other) => bytes.extend(other),
            }
            if damage {
                let at = at.index(bytes.len());
                bytes[at] = value;
            }
            (bytes, len)
        })
}

/// A connection ID that version 1 allows: 0 to 20 bytes.
pub fn v1_cid() -> impl Strategy<Value = Vec<u8>> + Clone {
    vec(any::<u8>(), 0..=20)
}

/// The header of an Initial, 0-RTT or Handshake packet as a sender
/// describes it, with the packet number and payload that follow.
#[derive(Clone, Debug)]
pub struct LongHeaderInput {
    /// 0 for Initial, 1 for 0-RTT, 2 for Handshake.
    pub packet_type: u8,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub token: Vec<u8>,
    /// The width of the Token Length field, which may be too narrow.
    pub token_width: usize,
    pub pn_length: usize,
    /// The length of the packet number and payload, the Length field.
    pub length: u64,
    /// The width of the Length field, which may be too narrow.
    pub length_width: usize,
}

pub fn long_header_input() -> impl Strategy<Value = LongHeaderInput> {
    (
        0u8..3,
        v1_cid(),
        v1_cid(),
        prop_oneof![3 => vec(any::<u8>(), 0..40), 1 => vec(any::<u8>(), 60..80)],
        width(),
        1usize..=4,
        prop_oneof![3 => 0u64..64, 2 => 0u64..1500, 1 => 16300u64..16400],
        width(),
    )
        .prop_map(
            |(packet_type, dcid, scid, token, token_width, pn_length, length, length_width)| {
                LongHeaderInput {
                    packet_type,
                    dcid,
                    scid,
                    token,
                    token_width,
                    pn_length,
                    length,
                    length_width,
                }
            },
        )
}

/// The header of a 1-RTT packet as a sender describes it.
#[derive(Clone, Debug)]
pub struct ShortHeaderInput {
    pub spin: bool,
    pub key_phase: bool,
    pub pn_length: usize,
    pub dcid: Vec<u8>,
    /// The packet number and payload that follow.
    pub rest: Vec<u8>,
}

pub fn short_header_input() -> impl Strategy<Value = ShortHeaderInput> {
    (
        any::<bool>(),
        any::<bool>(),
        1usize..=4,
        v1_cid(),
        vec(any::<u8>(), 0..40),
    )
        .prop_map(
            |(spin, key_phase, pn_length, dcid, rest)| ShortHeaderInput {
                spin,
                key_phase,
                pn_length,
                dcid,
                rest,
            },
        )
}

/// A Retry packet as a server describes it, before its integrity tag.
#[derive(Clone, Debug)]
pub struct RetryInput {
    pub unused: u8,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub token: Vec<u8>,
    /// The Destination Connection ID of the client's Initial.
    pub odcid: Vec<u8>,
}

pub fn retry_input() -> impl Strategy<Value = RetryInput> {
    (
        any::<u8>(),
        v1_cid(),
        v1_cid(),
        vec(any::<u8>(), 0..64),
        v1_cid(),
    )
        .prop_map(|(unused, dcid, scid, token, odcid)| RetryInput {
            unused,
            dcid,
            scid,
            token,
            odcid,
        })
}

/// A Version Negotiation packet as a server describes it.
#[derive(Clone, Debug)]
pub struct VersionNegotiationInput {
    pub unused: u8,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub versions: Vec<u32>,
}

pub fn version_negotiation_input() -> impl Strategy<Value = VersionNegotiationInput> {
    (any::<u8>(), wire_cid(), wire_cid(), vec(version(), 0..8)).prop_map(
        |(unused, dcid, scid, versions)| VersionNegotiationInput {
            unused,
            dcid,
            scid,
            versions,
        },
    )
}
