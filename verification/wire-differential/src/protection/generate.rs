//! Proptest strategies for packets to protect and Packet Number fields.
use super::Initial;
use proptest::{collection::vec, prelude::*};
use rustls::Side;
use sakuya_wire::v1::packet_number::PacketNumber;

pub fn side() -> impl Strategy<Value = Side> {
    prop_oneof![Just(Side::Client), Just(Side::Server)]
}

/// An Initial packet whose payload is long enough for the header protection
/// sample.
pub fn initial() -> impl Strategy<Value = Initial> {
    (
        vec(any::<u8>(), 0..=20),
        vec(any::<u8>(), 0..=20),
        vec(any::<u8>(), 0..32),
        0u64..(1 << 40),
        0u64..(1 << 20),
        any::<bool>(),
        vec(any::<u8>(), 4..1300),
        any::<u8>(),
    )
        .prop_map(
            |(dcid, scid, token, number, gap, acked, payload, reserved_bits)| Initial {
                dcid,
                scid,
                token,
                // Without an acknowledgment the field covers the packet number
                // itself, so it stays within what four bytes can state.
                packet_number: if acked { number } else { number & 0x3fff_ffff },
                largest_acked: acked
                    .then(|| number.saturating_sub(gap + 1))
                    .filter(|_| number > 0),
                payload,
                reserved_bits,
            },
        )
}

/// A packet number, often near a window boundary of a Packet Number field
/// or near the largest packet number.
pub fn pn_value() -> impl Strategy<Value = u64> {
    let max = PacketNumber::MAX.get();
    prop_oneof![
        3 => 0u64..(1 << 34),
        1 => (0u64..0x1_0000).prop_map(move |back| max - back),
        1 => 0u64..=max,
        1 => (0u32..4).prop_flat_map(|n| {
            let win = 1u64 << (8 * (n + 1));
            (0u64..8, -4i64..4).prop_map(move |(k, d)| (k * win).saturating_add_signed(d))
        }),
    ]
}
