//! Proptest strategies for the values every area uses; each area has the
//! strategies of its own inputs in its `generate` module.
use proptest::{collection::vec, prelude::*, sample::select};

/// The largest variable-length integer.
pub const VAR_MAX: u64 = (1 << 62) - 1;

/// A value below 2^62, often at a boundary of an encoding length.
pub fn var_int() -> impl Strategy<Value = u64> + Clone {
    prop_oneof![
        3 => select(vec![
            0, 1, 2, 62, 63, 64, 65, 16382, 16383, 16384, 16385,
            (1 << 30) - 1, 1 << 30, (1 << 30) + 1, (1 << 60) - 1, 1 << 60, (1 << 60) + 1,
            VAR_MAX - 1, VAR_MAX,
        ]),
        2 => 0u64..64,
        2 => 0u64..16384,
        1 => 0u64..(1 << 30),
        2 => 0u64..=VAR_MAX,
    ]
}

/// The width in bytes of a variable-length integer encoding, mostly 1.
pub fn width() -> impl Strategy<Value = usize> + Clone {
    select(vec![1usize, 1, 1, 2, 4, 8])
}

/// The encoding of `value` in `width` bytes, or in the shortest encoding
/// that holds it if `width` cannot.
pub fn var_int_as(value: u64, width: usize) -> Vec<u8> {
    let shortest = match value {
        0..=63 => 1,
        64..=16383 => 2,
        16384..=0x3fff_ffff => 4,
        _ => 8,
    };
    let width = width.max(shortest);
    let prefix = u64::from(width.trailing_zeros()) << (8 * width - 2);
    (value | prefix).to_be_bytes()[8 - width..].to_vec()
}

/// A connection ID that version 1 allows in a frame or a parameter: 1 to 20
/// bytes.
pub fn cid() -> impl Strategy<Value = Vec<u8>> + Clone {
    vec(any::<u8>(), 1..=20)
}
