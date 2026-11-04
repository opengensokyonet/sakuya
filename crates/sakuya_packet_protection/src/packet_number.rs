//! The Packet Number field (RFC 9000 §17.1, Appendix A.2, A.3).
//!
//! A packet header carries only the least significant bytes of a
//! [`PacketNumber`], as a [`TruncatedPacketNumber`] whose length is a
//! [`PacketNumberLength`].

use sakuya_wire::packet_number::PacketNumber;
use snafu::{OptionExt, ResultExt, Snafu, ensure};

/// The length of a Packet Number field, 1 to 4 bytes.
///
/// The two Packet Number Length bits of the unprotected first header byte
/// hold the length minus one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PacketNumberLength {
    /// A 1-byte field.
    One,
    /// A 2-byte field.
    Two,
    /// A 3-byte field.
    Three,
    /// A 4-byte field.
    Four,
}

impl PacketNumberLength {
    /// The field length of `len` bytes.
    ///
    /// # Errors
    ///
    /// Fails when `len` is not 1 to 4.
    pub const fn new(len: usize) -> Result<Self, PacketNumberLengthError> {
        match len {
            1 => Ok(Self::One),
            2 => Ok(Self::Two),
            3 => Ok(Self::Three),
            4 => Ok(Self::Four),
            _ => Err(PacketNumberLengthError { length: len }),
        }
    }

    /// The field length that the Packet Number Length bits of an unprotected
    /// first header byte encode; the other bits are ignored.
    pub const fn from_first_byte(first_byte: u8) -> Self {
        match first_byte & 0x03 {
            0 => Self::One,
            1 => Self::Two,
            2 => Self::Three,
            _ => Self::Four,
        }
    }

    /// The length in bytes, 1 to 4.
    pub const fn get(self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Three => 3,
            Self::Four => 4,
        }
    }

    /// The value of the Packet Number Length bits for this length, the
    /// length minus one, which occupies the two least significant bits of
    /// the first header byte.
    pub const fn first_byte_bits(self) -> u8 {
        match self {
            Self::One => 0,
            Self::Two => 1,
            Self::Three => 2,
            Self::Four => 3,
        }
    }
}

/// The error returned by [`PacketNumberLength::new`]: the length is not 1 to
/// 4 bytes.
///
/// Only [`PacketNumberLength::new`] constructs it, for a length it refuses.
#[derive(Debug, Snafu)]
#[snafu(display("packet number field of {length} bytes is not 1 to 4 bytes long"))]
pub struct PacketNumberLengthError {
    length: usize,
}

impl PacketNumberLengthError {
    /// The length given, which is zero or above four.
    pub const fn length(&self) -> usize {
        self.length
    }
}

/// The value of a Packet Number field: the 1 to 4 least significant bytes of
/// a full packet number.
///
/// The Packet Number Length bits of the first header byte hold
/// [`encoded_len`](Self::encoded_len) minus one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TruncatedPacketNumber {
    /// The field bytes in network byte order, left-aligned; bytes past `len`
    /// are zero.
    bytes: [u8; 4],
    len: PacketNumberLength,
}

impl TruncatedPacketNumber {
    /// A field of `len` bytes holding `value`.
    ///
    /// # Errors
    ///
    /// Fails when `value` does not fit in `len` bytes.
    pub fn new(value: u32, len: PacketNumberLength) -> Result<Self, TruncatedPacketNumberError> {
        ensure!(
            u64::from(value) < 1 << (8 * len.get()),
            TruncatedPacketNumberSnafu { value, length: len }
        );
        Ok(Self::from_low_bytes(u64::from(value), len))
    }

    /// A field from its bytes in network byte order, left-aligned, with the
    /// bytes past `len` zero.
    pub(crate) fn from_bytes(bytes: [u8; 4], len: PacketNumberLength) -> Self {
        debug_assert!(bytes[len.get()..].iter().all(|&byte| byte == 0));
        Self { bytes, len }
    }

    fn from_low_bytes(value: u64, len: PacketNumberLength) -> Self {
        let len_bytes = len.get();
        let mut bytes = [0; 4];
        bytes[..len_bytes].copy_from_slice(&value.to_be_bytes()[8 - len_bytes..]);
        Self { bytes, len }
    }

    /// Chooses the field length for sending `full_pn` and truncates it
    /// (RFC 9000 Appendix A.2).
    ///
    /// `largest_acked` is the largest packet number the peer has acknowledged
    /// in this packet number space, if any. The field is long enough to
    /// represent more than twice the number of packet numbers from
    /// `largest_acked` (exclusive, or from zero when there is none) to
    /// `full_pn` (inclusive).
    ///
    /// # Errors
    ///
    /// - [`EncodePacketNumberError::NotAfterLargestAcknowledged`] when
    ///   `full_pn` is not greater than `largest_acked`.
    /// - [`EncodePacketNumberError::RangeTooLarge`] when four bytes cannot
    ///   cover the range.
    pub fn encode(
        full_pn: PacketNumber,
        largest_acked: Option<PacketNumber>,
    ) -> Result<Self, EncodePacketNumberError> {
        let num_unacked = match largest_acked {
            // A packet number is below 2^62, so adding one does not overflow.
            None => full_pn.get() + 1,
            Some(largest_acked) => {
                ensure!(
                    full_pn > largest_acked,
                    encode_packet_number_error::NotAfterLargestAcknowledgedSnafu {
                        full_pn,
                        largest_acked
                    }
                );
                full_pn.get() - largest_acked.get()
            }
        };
        // One bit more than the bit length of `num_unacked` represents more
        // than twice that many values. `num_unacked` is at least one, so the
        // byte count is at least one and only lengths above four are refused.
        let min_bits = (u64::BITS - num_unacked.leading_zeros()) as usize + 1;
        let len = PacketNumberLength::new(min_bits.div_ceil(8))
            .ok()
            .context(PacketNumberRangeTooLargeSnafu { num_unacked })
            .context(encode_packet_number_error::RangeTooLargeSnafu)?;
        Ok(Self::from_low_bytes(full_pn.get(), len))
    }

    /// Recovers the full packet number closest to the one after
    /// `largest_processed` (RFC 9000 Appendix A.3).
    ///
    /// `largest_processed` is the largest packet number successfully
    /// processed in this packet number space, or `None` when there is none,
    /// in which case packet number zero is expected. The result is a
    /// candidate: it becomes the largest processed packet number only after
    /// the packet is authenticated.
    ///
    /// The result never exceeds [`PacketNumber::MAX`]. After
    /// [`PacketNumber::MAX`] has been processed, the closest value with the
    /// field's bits can lie above it; the closest one below is returned
    /// instead.
    pub fn decode(self, largest_processed: Option<PacketNumber>) -> PacketNumber {
        // At most 2^62, so none of the sums below overflows.
        let expected_pn = largest_processed.map_or(0, |largest| largest.get() + 1);
        let truncated = u64::from(self.value());
        let pn_win = 1u64 << (8 * self.len.get());
        let pn_hwin = pn_win / 2;
        let pn_mask = pn_win - 1;
        let candidate = (expected_pn & !pn_mask) | truncated;
        let decoded = if expected_pn >= pn_hwin
            && candidate <= expected_pn - pn_hwin
            && candidate < (1 << 62) - pn_win
        {
            candidate + pn_win
        } else if candidate > expected_pn + pn_hwin && candidate >= pn_win {
            candidate - pn_win
        } else {
            candidate
        };
        // Only an expected packet number of 2^62 places the candidate at or
        // above 2^62; one window below lies within range.
        let decoded = if decoded > PacketNumber::MAX.get() {
            decoded - pn_win
        } else {
            decoded
        };
        match PacketNumber::new(decoded) {
            Ok(decoded) => decoded,
            // invariant: the adjustment above keeps `decoded` at or below
            // `PacketNumber::MAX`.
            Err(_) => unreachable!("a decoded packet number is at most 2^62 - 1"),
        }
    }

    /// The field value.
    pub fn value(self) -> u32 {
        let mut value = [0; 4];
        let len = self.len.get();
        value[4 - len..].copy_from_slice(self.as_bytes());
        u32::from_be_bytes(value)
    }

    /// The field length.
    pub fn encoded_len(self) -> PacketNumberLength {
        self.len
    }

    /// The field bytes in network byte order, as they appear in the header.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len.get()]
    }
}

/// The error returned by [`TruncatedPacketNumber::new`]: the value does not
/// fit in the field length.
///
/// Only [`TruncatedPacketNumber::new`] constructs it, for a value that does
/// not fit, so its length is never four bytes.
#[derive(Debug, Snafu)]
#[snafu(display("value {value:#x} does not fit in {} bytes", length.get()))]
pub struct TruncatedPacketNumberError {
    value: u32,
    length: PacketNumberLength,
}

impl TruncatedPacketNumberError {
    /// The value given.
    pub const fn value(&self) -> u32 {
        self.value
    }

    /// The field length given, one to three bytes.
    pub const fn length(&self) -> PacketNumberLength {
        self.length
    }
}

/// The error returned by [`TruncatedPacketNumber::encode`].
#[derive(Debug, Snafu)]
#[snafu(module(encode_packet_number_error))]
pub enum EncodePacketNumberError {
    /// The packet number to send is not after the largest acknowledged one.
    #[snafu(display(
        "packet number {full_pn} is not greater than the largest acknowledged {largest_acked}"
    ))]
    NotAfterLargestAcknowledged {
        /// The packet number to send.
        full_pn: PacketNumber,
        /// The largest acknowledged packet number.
        largest_acked: PacketNumber,
    },
    /// Four bytes cannot represent twice the unacknowledged range.
    #[snafu(display("cannot encode the packet number"))]
    RangeTooLarge {
        /// The size of the range.
        source: PacketNumberRangeTooLargeError,
    },
}

/// Four bytes cannot represent twice the number of packet numbers after the
/// largest acknowledged one.
///
/// Only [`TruncatedPacketNumber::encode`] constructs it, for a range of at
/// least 2<sup>31</sup> packet numbers.
#[derive(Debug, Snafu)]
#[snafu(display("{num_unacked} unacknowledged packet numbers exceed the 4-byte encoding"))]
pub struct PacketNumberRangeTooLargeError {
    num_unacked: u64,
}

impl PacketNumberRangeTooLargeError {
    /// Number of packet numbers after the largest acknowledged one, up to and
    /// including the one to send: at least 2<sup>31</sup> and at most
    /// 2<sup>62</sup>.
    pub const fn num_unacked(&self) -> u64 {
        self.num_unacked
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pn(value: u64) -> PacketNumber {
        PacketNumber::new(value).unwrap()
    }

    fn len(bytes: usize) -> PacketNumberLength {
        PacketNumberLength::new(bytes).unwrap()
    }

    #[test]
    fn packet_number_length_bounds() {
        assert_eq!(PacketNumberLength::new(0).unwrap_err().length(), 0);
        assert_eq!(PacketNumberLength::new(5).unwrap_err().length(), 5);
        for (bytes, expected) in [
            (1, PacketNumberLength::One),
            (2, PacketNumberLength::Two),
            (3, PacketNumberLength::Three),
            (4, PacketNumberLength::Four),
        ] {
            let length = PacketNumberLength::new(bytes).unwrap();
            assert_eq!(length, expected);
            assert_eq!(length.get(), bytes);
            assert_eq!(usize::from(length.first_byte_bits()), bytes - 1);
            assert_eq!(
                PacketNumberLength::from_first_byte(length.first_byte_bits()),
                length
            );
        }
    }

    #[test]
    fn packet_number_length_from_first_byte_ignores_other_bits() {
        assert_eq!(
            PacketNumberLength::from_first_byte(0xfc),
            PacketNumberLength::One
        );
        assert_eq!(
            PacketNumberLength::from_first_byte(0xc1),
            PacketNumberLength::Two
        );
        assert_eq!(
            PacketNumberLength::from_first_byte(0x42),
            PacketNumberLength::Three
        );
        assert_eq!(
            PacketNumberLength::from_first_byte(0xff),
            PacketNumberLength::Four
        );
    }

    #[test]
    fn encode_rfc9000_examples() {
        // RFC 9000 Appendix A.2.
        let truncated = TruncatedPacketNumber::encode(pn(0xac5c02), Some(pn(0xabe8b3))).unwrap();
        assert_eq!(truncated.encoded_len(), PacketNumberLength::Two);
        assert_eq!(truncated.as_bytes(), [0x5c, 0x02]);
        assert_eq!(truncated.value(), 0x5c02);

        let truncated = TruncatedPacketNumber::encode(pn(0xace8fe), Some(pn(0xabe8b3))).unwrap();
        assert_eq!(truncated.encoded_len(), PacketNumberLength::Three);
        assert_eq!(truncated.as_bytes(), [0xac, 0xe8, 0xfe]);
    }

    #[test]
    fn encode_boundaries() {
        let encoded_len = |full: u64, largest_acked: Option<u64>| {
            TruncatedPacketNumber::encode(pn(full), largest_acked.map(pn))
                .unwrap()
                .encoded_len()
                .get()
        };
        assert_eq!(encoded_len(0, None), 1);
        // 127 unacknowledged need 8 bits; 128 need 9.
        assert_eq!(encoded_len(127, Some(0)), 1);
        assert_eq!(encoded_len(128, Some(0)), 2);
        assert_eq!(encoded_len(126, None), 1);
        assert_eq!(encoded_len(127, None), 2);
        assert_eq!(encoded_len((1 << 31) - 1, Some(0)), 4);
        assert_eq!(
            encoded_len(PacketNumber::MAX.get(), Some(PacketNumber::MAX.get() - 1)),
            1
        );
        assert!(matches!(
            TruncatedPacketNumber::encode(pn(1 << 31), Some(PacketNumber::ZERO)),
            Err(EncodePacketNumberError::RangeTooLarge { source }) if source.num_unacked() == 1 << 31
        ));
        assert!(matches!(
            TruncatedPacketNumber::encode(PacketNumber::MAX, None),
            Err(EncodePacketNumberError::RangeTooLarge { source }) if source.num_unacked() == 1 << 62
        ));
        assert!(matches!(
            TruncatedPacketNumber::encode(pn(5), Some(pn(5))),
            Err(EncodePacketNumberError::NotAfterLargestAcknowledged { .. })
        ));
    }

    #[test]
    fn decode_rfc9000_example() {
        // RFC 9000 Appendix A.3: largest processed 0xa82f30ea, 16-bit 0x9b32.
        let truncated = TruncatedPacketNumber::new(0x9b32, len(2)).unwrap();
        assert_eq!(truncated.decode(Some(pn(0xa82f30ea))), pn(0xa82f9b32));
    }

    #[test]
    fn decode_window_edges() {
        let one_byte = |value| TruncatedPacketNumber::new(value, len(1)).unwrap();
        // Nothing processed yet.
        assert_eq!(one_byte(2).decode(None), pn(2));
        // Wraps forward past the window.
        assert_eq!(one_byte(0x01).decode(Some(pn(0xfe))), pn(0x101));
        // Stays behind when closer.
        assert_eq!(one_byte(0xfe).decode(Some(pn(0x100))), pn(0xfe));
        // Never below zero.
        assert_eq!(one_byte(0xf0).decode(Some(pn(0x0f))), pn(0xf0));
        // Never above the largest packet number.
        let max = PacketNumber::MAX.get();
        assert_eq!(one_byte(0x00).decode(Some(pn(max - 1))), pn(max & !0xff));
        assert_eq!(one_byte(0xff).decode(Some(pn(max - 1))), PacketNumber::MAX);
        assert_eq!(
            one_byte(0x00).decode(Some(PacketNumber::MAX)),
            pn(max & !0xff)
        );
        assert_eq!(
            one_byte(0x01).decode(Some(PacketNumber::MAX)),
            pn((max & !0xff) | 0x01)
        );
        let four_bytes = TruncatedPacketNumber::new(0, len(4)).unwrap();
        assert_eq!(
            four_bytes.decode(Some(PacketNumber::MAX)),
            pn(max & !0xffff_ffff)
        );
    }

    #[test]
    fn round_trip() {
        for (full, largest_acked) in [
            (0, None),
            (2, None),
            (1000, Some(990)),
            (0x1234_5678, Some(0x1234_0000)),
            (PacketNumber::MAX.get(), Some(PacketNumber::MAX.get() - 1)),
        ] {
            let truncated = TruncatedPacketNumber::encode(pn(full), largest_acked.map(pn)).unwrap();
            assert_eq!(truncated.decode(largest_acked.map(pn)), pn(full));
        }
    }

    #[test]
    fn new_rejects_values_wider_than_the_field() {
        let error = TruncatedPacketNumber::new(0x100, len(1)).unwrap_err();
        assert_eq!(
            (error.value(), error.length()),
            (0x100, PacketNumberLength::One)
        );
        assert_eq!(
            TruncatedPacketNumber::new(0xff_ffff, len(3))
                .unwrap()
                .as_bytes(),
            [0xff; 3]
        );
        assert!(TruncatedPacketNumber::new(0x100_0000, len(3)).is_err());
        assert_eq!(
            TruncatedPacketNumber::new(u32::MAX, len(4))
                .unwrap()
                .as_bytes(),
            [0xff; 4]
        );
    }
}
