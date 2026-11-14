//! The Packet Number field: sakuya's truncation and recovery against the
//! pseudocode of RFC 9000 Appendix A and quinn-proto.
use crate::tally::Comparison;
use quinn_proto::packet::PacketNumber as QPacketNumber;
use sakuya_packet_protection::packet_number::{PacketNumberLength, TruncatedPacketNumber};
use sakuya_wire::v1::packet_number::PacketNumber;

/// DecodePacketNumber of RFC 9000 Appendix A.3, in arbitrary precision.
/// Without a largest packet number, packet number 0 is expected.
pub fn rfc_decode(largest: Option<u64>, truncated: u64, bits: u32) -> i128 {
    let expected = largest.map_or(0, |v| i128::from(v) + 1);
    let truncated = i128::from(truncated);
    let win = 1i128 << bits;
    let hwin = win / 2;
    let mask = win - 1;
    let candidate = (expected & !mask) | truncated;
    if candidate <= expected - hwin && candidate < (1i128 << 62) - win {
        return candidate + win;
    }
    if candidate > expected + hwin && candidate >= win {
        return candidate - win;
    }
    candidate
}

/// The field length that EncodePacketNumber of RFC 9000 Appendix A.2
/// chooses: `ceil((log2(num_unacked) + 1) / 8)` bytes, the smallest `n`
/// with `num_unacked <= 2^(8n - 1)`.
pub fn rfc_encode_len(full: u64, largest: Option<u64>) -> u64 {
    let num_unacked = largest.map_or(full + 1, |largest| full - largest);
    (1..)
        .find(|n| u128::from(num_unacked) <= 1u128 << (8 * n - 1))
        .unwrap()
}

/// A Packet Number field of `bytes` bytes holding the low bytes of `value`.
pub fn field(value: u32, bytes: usize) -> TruncatedPacketNumber {
    let len = PacketNumberLength::new(bytes).unwrap();
    let value = if bytes == 4 {
        value
    } else {
        value & ((1 << (8 * bytes)) - 1)
    };
    TruncatedPacketNumber::new(value, len).unwrap()
}

pub fn decode_sakuya(largest: Option<u64>, field: TruncatedPacketNumber) -> u64 {
    field
        .decode(largest.map(|v| PacketNumber::new(v).unwrap()))
        .get()
}

pub fn decode_quinn(largest: u64, field: TruncatedPacketNumber) -> u64 {
    let value = field.value();
    match field.encoded_len().get() {
        1 => QPacketNumber::U8(value as u8),
        2 => QPacketNumber::U16(value as u16),
        3 => QPacketNumber::U24(value),
        _ => QPacketNumber::U32(value),
    }
    .expand(largest + 1)
}

/// Compares sakuya's recovery with the pseudocode.
pub fn compare_decode_rfc(largest: Option<u64>, field: TruncatedPacketNumber) -> Comparison {
    let ours = decode_sakuya(largest, field);
    let bits = 8 * field.encoded_len().get() as u32;
    let rfc = rfc_decode(largest, u64::from(field.value()), bits);
    if i128::from(ours) == rfc {
        Comparison::Agree
    } else if rfc >= 1 << 62
        && largest == Some(PacketNumber::MAX.get())
        && i128::from(ours) == rfc - (1 << bits)
    {
        Comparison::Known(
            "largest packet number 2^62 - 1: the A.3 pseudocode leaves the range of RFC 9000 12.3, sakuya returns the closest value within it",
        )
    } else {
        Comparison::Unclassified
    }
}

/// Compares sakuya's recovery with quinn-proto's.
pub fn compare_decode_quinn(largest: u64, field: TruncatedPacketNumber) -> Comparison {
    let ours = decode_sakuya(Some(largest), field);
    let theirs = decode_quinn(largest, field);
    if ours == theirs {
        return Comparison::Agree;
    }
    if theirs >= 1 << 62 && compare_decode_rfc(Some(largest), field) != Comparison::Unclassified {
        Comparison::Known(
            "quinn leaves the 62-bit range of RFC 9000 12.3 near the largest packet number, where the A.3 pseudocode checks candidate < 2^62 - pn_win",
        )
    } else {
        Comparison::Unclassified
    }
}

/// Compares the field length sakuya chooses with the A.2 pseudocode; `None`
/// is sakuya's refusal.
pub fn compare_encode_rfc(full: u64, largest: Option<u64>) -> Comparison {
    let ours = TruncatedPacketNumber::encode(
        PacketNumber::new(full).unwrap(),
        largest.map(|v| PacketNumber::new(v).unwrap()),
    )
    .ok()
    .map(|field| field.encoded_len().get() as u64);
    let rfc = rfc_encode_len(full, largest);
    let num_unacked = largest.map_or(full + 1, |largest| full - largest);
    match ours {
        Some(ours) if ours == rfc => Comparison::Agree,
        None if rfc > 4 => Comparison::Agree,
        // At a power of two the pseudocode's field represents exactly twice
        // the range; RFC 9000 §17.1 requires more than twice.
        Some(ours) if num_unacked.is_power_of_two() && ours == rfc + 1 => Comparison::Known(
            "num_unacked a power of two: the A.2 pseudocode gives a field of exactly twice the range, RFC 9000 17.1 requires more than twice and sakuya follows it",
        ),
        None if num_unacked.is_power_of_two() && rfc == 4 => Comparison::Known(
            "num_unacked a power of two: the A.2 pseudocode gives a field of exactly twice the range, RFC 9000 17.1 requires more than twice and sakuya follows it",
        ),
        _ => Comparison::Unclassified,
    }
}
