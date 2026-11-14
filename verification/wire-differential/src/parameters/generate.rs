//! Proptest strategies for sequences of transport parameters.
use super::{Entry, MAX_DATAGRAM_FRAME_SIZE, RESET_STREAM_AT, encode};
use crate::generate::{var_int, var_int_as, width};
use proptest::{
    collection::vec,
    prelude::*,
    sample::{Index, select, subsequence},
};

/// An integer value: one of `bounds` or any value, in a width from
/// `widths`.
fn integer(bounds: Vec<u64>, widths: BoxedStrategy<usize>) -> BoxedStrategy<Vec<u8>> {
    (prop_oneof![1 => select(bounds), 1 => var_int()], widths)
        .prop_map(|(value, width)| var_int_as(value, width))
        .boxed()
}

/// A few bytes, often none.
fn flag() -> BoxedStrategy<Vec<u8>> {
    prop_oneof![9 => Just(Vec::new()), 1 => vec(any::<u8>(), 1..3)].boxed()
}

/// A preferred_address value, usually well formed: addresses of one family
/// or both, sometimes of neither, a connection ID of 1 to 20 bytes,
/// sometimes empty or too long, and sometimes extra or missing bytes.
fn preferred_address() -> BoxedStrategy<Vec<u8>> {
    (
        prop_oneof![
            6 => vec(any::<u8>(), 24),
            1 => Just(vec![0; 24]),
            1 => vec(any::<u8>(), 6).prop_map(|v4| [v4, vec![0; 18]].concat()),
            1 => vec(any::<u8>(), 18).prop_map(|v6| [vec![0; 6], v6].concat()),
            // An all-zero address with a port is an address of its family.
            1 => any::<u16>().prop_map(|port| {
                let mut value = vec![0; 24];
                value[4..6].copy_from_slice(&port.to_be_bytes());
                value
            }),
        ],
        prop_oneof![9 => 1usize..=20, 1 => Just(0usize), 1 => Just(21usize)],
        any::<[u8; 21]>(),
        any::<[u8; 16]>(),
        select(vec![0usize, 0, 0, 0, 1, 3]),
        any::<bool>(),
    )
        .prop_map(|(addresses, cid_len, cid, token, extra, cut)| {
            let mut value = addresses;
            value.push(cid_len as u8);
            value.extend(&cid[..cid_len]);
            value.extend(token);
            value.extend(vec![0xab; extra]);
            if cut {
                value.truncate(value.len() / 2);
            }
            value
        })
        .boxed()
}

/// The value of parameter `id`, usually valid for it, with integers in a
/// width from `widths`.
pub fn parameter_value(id: u64, widths: BoxedStrategy<usize>) -> BoxedStrategy<Vec<u8>> {
    match id {
        0x00 | 0x0f | 0x10 => prop_oneof![
            9 => vec(any::<u8>(), 0..=20),
            1 => vec(any::<u8>(), 21..=22),
        ]
        .boxed(),
        0x02 => prop_oneof![
            9 => vec(any::<u8>(), 16),
            1 => vec(any::<u8>(), 0..=20),
        ]
        .boxed(),
        0x0c | RESET_STREAM_AT | 0x2ab2 | 0xdc0002 => flag(),
        0x0d => preferred_address(),
        0x03 => integer(vec![1199, 1200, 1201, 65527, 65528], widths),
        0x08 | 0x09 => integer(vec![(1 << 60) - 1, 1 << 60, (1 << 60) + 1], widths),
        0x0a => integer(vec![0, 3, 20, 21], widths),
        0x0b => integer(vec![0, 25, (1 << 14) - 1, 1 << 14], widths),
        0x0e => integer(vec![0, 1, 2, 3, 8], widths),
        0x01 | 0x04..=0x07 => integer(vec![0, 1, 1 << 20], widths),
        MAX_DATAGRAM_FRAME_SIZE => integer(vec![0, 1, 1200, 65535, 65536], widths),
        // min_ack_delay in microseconds, around the default max_ack_delay.
        0xff04de1b => integer(vec![0, 1000, 25_000, 25_001], widths),
        // dc_supported_versions: a few versions.
        0xdc0000 => vec((0u64..=u64::from(u32::MAX) + 1, width()), 0..5)
            .prop_map(|versions| {
                versions
                    .into_iter()
                    .flat_map(|(version, width)| var_int_as(version, width))
                    .collect()
            })
            .boxed(),
        _ => vec(any::<u8>(), 0..24).boxed(),
    }
}

/// A reserved ID: 31 × N + 27.
fn reserved_id() -> impl Strategy<Value = u64> + Clone {
    prop_oneof![
        3 => (0u64..1000).prop_map(|n| 31 * n + 27),
        1 => (0u64..((1 << 62) - 27) / 31).prop_map(|n| 31 * n + 27),
    ]
}

/// A parameter ID: mostly those of RFC 9000, then those of the extensions
/// sakuya implements, reserved ones, those that only a reference
/// implements, and any.
pub fn parameter_id() -> impl Strategy<Value = u64> + Clone {
    prop_oneof![
        7 => 0u64..=0x10,
        2 => select(vec![MAX_DATAGRAM_FRAME_SIZE, RESET_STREAM_AT]),
        2 => reserved_id(),
        1 => select(vec![0x2ab2u64, 0xff04de1b, 0xdc0000, 0xdc0002, 0x7158]),
        1 => var_int(),
    ]
}

/// The IDs sakuya's list claims, in the order it writes them.
fn claimed_ids() -> Vec<u64> {
    (0u64..=0x10)
        .chain([MAX_DATAGRAM_FRAME_SIZE, RESET_STREAM_AT])
        .collect()
}

/// Each claimed ID at most once, with values of the shortest widths, in the
/// order of the list unless `shuffle`, then a few reserved parameters.
fn distinct(shuffle: bool) -> BoxedStrategy<Vec<Entry>> {
    let ids = subsequence(claimed_ids(), 0..=claimed_ids().len());
    let ids = if shuffle {
        ids.prop_shuffle().boxed()
    } else {
        ids.boxed()
    };
    let known = ids.prop_flat_map(|ids| {
        ids.into_iter()
            .map(|id| (Just(id), parameter_value(id, Just(1).boxed())))
            .collect::<Vec<_>>()
    });
    let unknown = proptest::collection::btree_map(reserved_id(), vec(any::<u8>(), 0..8), 0..3)
        .prop_map(|map| map.into_iter().collect::<Vec<_>>())
        .prop_shuffle();
    (known, unknown)
        .prop_map(|(known, unknown)| {
            known
                .into_iter()
                .chain(unknown)
                .map(|(id, value)| Entry::new(id, value))
                .collect()
        })
        .boxed()
}

/// Any entries, IDs drawn from [`parameter_id`] and widths of every field
/// varied.
fn list() -> BoxedStrategy<Vec<Entry>> {
    let entry = parameter_id().prop_flat_map(|id| {
        (
            Just(id),
            parameter_value(id, width().boxed()),
            width(),
            width(),
        )
    });
    vec(entry, 0..12)
        .prop_map(|entries| {
            entries
                .into_iter()
                .map(|(id, value, id_width, length_width)| Entry {
                    id,
                    value,
                    id_width,
                    length_width,
                })
                .collect()
        })
        .boxed()
}

/// A sequence of transport parameters: well formed with any IDs, with
/// distinct claimed IDs in any order or in sakuya's order, one of those
/// damaged in a byte and cut, or random bytes.
pub fn parameters() -> impl Strategy<Value = Vec<u8>> {
    let damaged = (distinct(true), any::<Index>(), any::<Index>(), any::<u8>()).prop_map(
        |(list, cut, at, value)| {
            let mut bytes = encode(&list);
            if !bytes.is_empty() {
                let at = at.index(bytes.len());
                bytes[at] = value;
                bytes.truncate(cut.index(bytes.len() + 1));
            }
            bytes
        },
    );
    prop_oneof![
        3 => list().prop_map(|list| encode(&list)),
        3 => distinct(true).prop_map(|list| encode(&list)),
        2 => distinct(false).prop_map(|list| encode(&list)),
        2 => damaged,
        1 => vec(any::<u8>(), 0..48),
    ]
}
