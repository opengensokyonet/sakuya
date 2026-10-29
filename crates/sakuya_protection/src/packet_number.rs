//! Packet number encoding and decoding (RFC 9000 §17.1, Appendix A.2, A.3).

use snafu::{Snafu, ensure};

/// The value of a Packet Number field: the 1 to 4 least significant bytes of
/// a full packet number.
///
/// The Packet Number Length bits of the first header byte hold
/// [`encoded_len`](Self::encoded_len) minus one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TruncatedPacketNumber {
    /// The field bytes in network byte order, left-aligned.
    bytes: [u8; 4],
    /// Number of meaningful bytes in `bytes`, 1 to 4.
    len: u8,
}

impl TruncatedPacketNumber {
    /// A field of `len` bytes holding `value`.
    ///
    /// # Errors
    ///
    /// Fails when `len` is not 1 to 4, or `value` does not fit in `len`
    /// bytes.
    pub fn new(value: u32, len: usize) -> Result<Self, TruncatedPacketNumberError> {
        ensure!(
            (1..=4).contains(&len),
            truncated_packet_number_error::InvalidLengthSnafu { len }
        );
        ensure!(
            u64::from(value) < 1 << (8 * len),
            truncated_packet_number_error::ValueTooLargeSnafu { value, len }
        );
        Ok(Self::from_low_bytes(u64::from(value), len))
    }

    /// Reads a field from its bytes, which are in network byte order.
    pub(crate) fn from_field(field: &[u8]) -> Self {
        debug_assert!((1..=4).contains(&field.len()));
        let mut bytes = [0; 4];
        bytes[..field.len()].copy_from_slice(field);
        Self {
            bytes,
            len: field.len() as u8,
        }
    }

    fn from_low_bytes(value: u64, len: usize) -> Self {
        let mut bytes = [0; 4];
        bytes[..len].copy_from_slice(&value.to_be_bytes()[8 - len..]);
        Self {
            bytes,
            len: len as u8,
        }
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
        full_pn: u64,
        largest_acked: Option<u64>,
    ) -> Result<Self, EncodePacketNumberError> {
        let num_unacked = match largest_acked {
            None => full_pn
                .checked_add(1)
                .expect("packet numbers are below 2^62"),
            Some(largest_acked) => {
                ensure!(
                    full_pn > largest_acked,
                    encode_packet_number_error::NotAfterLargestAcknowledgedSnafu {
                        full_pn,
                        largest_acked
                    }
                );
                full_pn - largest_acked
            }
        };
        // One bit more than the bit length of `num_unacked` represents more
        // than twice that many values.
        let min_bits = (u64::BITS - num_unacked.leading_zeros()) as usize + 1;
        let len = min_bits.div_ceil(8);
        ensure!(
            len <= 4,
            encode_packet_number_error::RangeTooLargeSnafu { num_unacked }
        );
        Ok(Self::from_low_bytes(full_pn, len))
    }

    /// Recovers the full packet number closest to `expected_pn`
    /// (RFC 9000 Appendix A.3).
    ///
    /// `expected_pn` is one more than the largest packet number successfully
    /// processed in this packet number space, or zero when there is none. The
    /// result is a candidate: it becomes the largest processed packet number
    /// only after the packet is authenticated.
    pub fn decode(self, expected_pn: u64) -> u64 {
        let truncated = u64::from(self.value());
        let pn_win = 1u64 << (8 * self.encoded_len());
        let pn_hwin = pn_win / 2;
        let pn_mask = pn_win - 1;
        let candidate = (expected_pn & !pn_mask) | truncated;
        if expected_pn >= pn_hwin
            && candidate <= expected_pn - pn_hwin
            && candidate < (1 << 62) - pn_win
        {
            candidate + pn_win
        } else if candidate > expected_pn.saturating_add(pn_hwin) && candidate >= pn_win {
            candidate - pn_win
        } else {
            candidate
        }
    }

    /// The field value.
    pub fn value(self) -> u32 {
        let mut value = [0; 4];
        let len = self.encoded_len();
        value[4 - len..].copy_from_slice(self.as_bytes());
        u32::from_be_bytes(value)
    }

    /// The field length in bytes, 1 to 4.
    pub fn encoded_len(self) -> usize {
        usize::from(self.len)
    }

    /// The field bytes in network byte order, as they appear in the header.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

/// The error returned by [`TruncatedPacketNumber::new`].
#[derive(Debug, Snafu)]
#[snafu(module(truncated_packet_number_error))]
pub enum TruncatedPacketNumberError {
    /// The field length is not 1 to 4 bytes.
    #[snafu(display("packet number field of {len} bytes is not 1 to 4 bytes long"))]
    InvalidLength {
        /// The length given.
        len: usize,
    },
    /// The value does not fit in the field length.
    #[snafu(display("value {value:#x} does not fit in {len} bytes"))]
    ValueTooLarge {
        /// The value given.
        value: u32,
        /// The length given.
        len: usize,
    },
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
        full_pn: u64,
        /// The largest acknowledged packet number.
        largest_acked: u64,
    },
    /// Four bytes cannot represent twice the unacknowledged range.
    #[snafu(display("{num_unacked} unacknowledged packet numbers exceed the 4-byte encoding"))]
    RangeTooLarge {
        /// Number of packet numbers after the largest acknowledged one, up to
        /// and including the one to send.
        num_unacked: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_rfc9000_examples() {
        // RFC 9000 Appendix A.2.
        let pn = TruncatedPacketNumber::encode(0xac5c02, Some(0xabe8b3)).unwrap();
        assert_eq!(pn.encoded_len(), 2);
        assert_eq!(pn.as_bytes(), [0x5c, 0x02]);
        assert_eq!(pn.value(), 0x5c02);

        let pn = TruncatedPacketNumber::encode(0xace8fe, Some(0xabe8b3)).unwrap();
        assert_eq!(pn.encoded_len(), 3);
        assert_eq!(pn.as_bytes(), [0xac, 0xe8, 0xfe]);
    }

    #[test]
    fn encode_boundaries() {
        assert_eq!(
            TruncatedPacketNumber::encode(0, None)
                .unwrap()
                .encoded_len(),
            1
        );
        // 127 unacknowledged need 8 bits; 128 need 9.
        assert_eq!(
            TruncatedPacketNumber::encode(127, Some(0))
                .unwrap()
                .encoded_len(),
            1
        );
        assert_eq!(
            TruncatedPacketNumber::encode(128, Some(0))
                .unwrap()
                .encoded_len(),
            2
        );
        assert_eq!(
            TruncatedPacketNumber::encode(126, None)
                .unwrap()
                .encoded_len(),
            1
        );
        assert_eq!(
            TruncatedPacketNumber::encode(127, None)
                .unwrap()
                .encoded_len(),
            2
        );
        assert_eq!(
            TruncatedPacketNumber::encode((1 << 31) - 1, Some(0))
                .unwrap()
                .encoded_len(),
            4
        );
        assert!(matches!(
            TruncatedPacketNumber::encode(1 << 31, Some(0)),
            Err(EncodePacketNumberError::RangeTooLarge { num_unacked }) if num_unacked == 1 << 31
        ));
        assert!(matches!(
            TruncatedPacketNumber::encode(5, Some(5)),
            Err(EncodePacketNumberError::NotAfterLargestAcknowledged { .. })
        ));
    }

    #[test]
    fn decode_rfc9000_example() {
        // RFC 9000 Appendix A.3: largest processed 0xa82f30ea, 16-bit 0x9b32.
        let pn = TruncatedPacketNumber::new(0x9b32, 2).unwrap();
        assert_eq!(pn.decode(0xa82f30ea + 1), 0xa82f9b32);
    }

    #[test]
    fn decode_window_edges() {
        let one_byte = |value| TruncatedPacketNumber::new(value, 1).unwrap();
        // Nothing processed yet.
        assert_eq!(one_byte(2).decode(0), 2);
        // Wraps forward past the window.
        assert_eq!(one_byte(0x01).decode(0xff), 0x101);
        // Stays behind when closer.
        assert_eq!(one_byte(0xfe).decode(0x101), 0xfe);
        // Never below zero.
        assert_eq!(one_byte(0xf0).decode(0x10), 0xf0);
        // Never at or above 2^62.
        let top = (1u64 << 62) - 1;
        assert_eq!(one_byte(0x00).decode(top), top & !0xff);
    }

    #[test]
    fn round_trip() {
        for (full, largest_acked) in [
            (0, None),
            (2, None),
            (1000, Some(990)),
            (0x1234_5678, Some(0x1234_0000)),
        ] {
            let pn = TruncatedPacketNumber::encode(full, largest_acked).unwrap();
            let expected = largest_acked.map_or(0, |largest| largest + 1);
            assert_eq!(pn.decode(expected), full);
        }
    }

    #[test]
    fn new_rejects_invalid_fields() {
        assert!(matches!(
            TruncatedPacketNumber::new(0, 0),
            Err(TruncatedPacketNumberError::InvalidLength { len: 0 })
        ));
        assert!(matches!(
            TruncatedPacketNumber::new(0, 5),
            Err(TruncatedPacketNumberError::InvalidLength { len: 5 })
        ));
        assert!(matches!(
            TruncatedPacketNumber::new(0x100, 1),
            Err(TruncatedPacketNumberError::ValueTooLarge { .. })
        ));
        assert_eq!(
            TruncatedPacketNumber::new(u32::MAX, 4).unwrap().as_bytes(),
            [0xff; 4]
        );
    }
}
