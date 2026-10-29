//! Header protection (RFC 9001 §5.4).

use snafu::{Snafu, ensure};

use crate::backend::{
    AeadAlgorithm, CryptoBackend, HEADER_PROTECTION_MASK_LEN, HEADER_PROTECTION_SAMPLE_LEN,
    HeaderProtectionCipher, MAX_KEY_LEN,
};
use crate::packet_number::TruncatedPacketNumber;
use crate::secret::TrafficSecret;
use crate::wipe::wipe;

/// Offset of the ciphertext sample from the start of the Packet Number
/// field, which is sampled as if it were 4 bytes long.
const SAMPLE_OFFSET_FROM_PN: usize = 4;

/// The header protection key of one traffic secret, for removing or applying
/// header protection.
///
/// It is derived once per encryption level and direction; a key update does
/// not change it.
pub struct HeaderProtectionKey<B: CryptoBackend> {
    cipher: B::HeaderProtectionCipher,
}

impl<B: CryptoBackend> HeaderProtectionKey<B> {
    /// Derives the header protection key (`"quic hp"`, `aead.key_len()`
    /// bytes) from `secret` (RFC 9001 §5.1), for the cipher that `aead`
    /// selects.
    pub fn derive(backend: &B, aead: AeadAlgorithm, secret: &TrafficSecret) -> Self {
        let mut key = [0; MAX_KEY_LEN];
        let key = &mut key[..aead.key_len()];
        secret.expand_label(backend, b"quic hp", key);
        let cipher = backend.header_protection_cipher(aead, key);
        wipe(key);
        Self { cipher }
    }

    /// Removes header protection from `packet` in place and returns the
    /// Packet Number field.
    ///
    /// `packet` holds exactly one packet, starting at its first byte;
    /// `pn_offset` is where the Packet Number field starts, as the header
    /// parser determined it. The header form bit of the first byte selects
    /// how many of its low bits are unmasked: four for a long header, five
    /// for a short header. Then the Packet Number Length bits give the field
    /// length, and that many bytes at `pn_offset` are unmasked.
    ///
    /// On success the first byte and the packet number field are
    /// unprotected; the header ends at `pn_offset` plus
    /// [`TruncatedPacketNumber::encoded_len`]. Checking the now visible
    /// Reserved Bits, and reading the Key Phase bit, is left to the caller.
    /// The sample is read from the ciphertext after the field and is not
    /// modified.
    ///
    /// # Errors
    ///
    /// Fails when `pn_offset` is zero or `packet` is too short to contain the
    /// 16-byte sample at `pn_offset + 4`; RFC 9001 §5.4.2 requires discarding
    /// such a packet. `packet` is unchanged.
    pub fn remove(
        &self,
        packet: &mut [u8],
        pn_offset: usize,
    ) -> Result<TruncatedPacketNumber, HeaderProtectionError> {
        let mask = self.mask(packet, pn_offset)?;
        packet[0] ^= mask[0] & first_byte_mask(packet[0]);
        let pn_len = pn_len(packet[0]);
        let field = &mut packet[pn_offset..pn_offset + pn_len];
        for (byte, mask) in field.iter_mut().zip(&mask[1..]) {
            *byte ^= mask;
        }
        Ok(TruncatedPacketNumber::from_field(field))
    }

    /// Applies header protection to `packet` in place.
    ///
    /// `packet` holds exactly one packet, starting at its first byte, whose
    /// payload is already sealed; `pn_offset` is where the Packet Number
    /// field starts. The field length comes from the Packet Number Length
    /// bits of the unprotected first byte. The sender pads the payload so the
    /// 16-byte sample at `pn_offset + 4` exists (RFC 9001 §5.4.2).
    ///
    /// # Errors
    ///
    /// Fails when `pn_offset` is zero or `packet` is too short to contain the
    /// sample; `packet` is unchanged.
    pub fn apply(&self, packet: &mut [u8], pn_offset: usize) -> Result<(), HeaderProtectionError> {
        let mask = self.mask(packet, pn_offset)?;
        let pn_len = pn_len(packet[0]);
        packet[0] ^= mask[0] & first_byte_mask(packet[0]);
        for (byte, mask) in packet[pn_offset..pn_offset + pn_len]
            .iter_mut()
            .zip(&mask[1..])
        {
            *byte ^= mask;
        }
        Ok(())
    }

    fn mask(
        &self,
        packet: &[u8],
        pn_offset: usize,
    ) -> Result<[u8; HEADER_PROTECTION_MASK_LEN], HeaderProtectionError> {
        ensure!(
            pn_offset > 0,
            header_protection_error::PacketNumberOffsetZeroSnafu
        );
        let sample_offset = pn_offset.saturating_add(SAMPLE_OFFSET_FROM_PN);
        let sample = packet
            .get(sample_offset..sample_offset.saturating_add(HEADER_PROTECTION_SAMPLE_LEN))
            .and_then(|sample| <&[u8; HEADER_PROTECTION_SAMPLE_LEN]>::try_from(sample).ok());
        let Some(sample) = sample else {
            return header_protection_error::SampleOutOfBoundsSnafu {
                pn_offset,
                packet_len: packet.len(),
            }
            .fail();
        };
        Ok(self.cipher.mask(sample))
    }
}

impl<B: CryptoBackend> core::fmt::Debug for HeaderProtectionKey<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HeaderProtectionKey")
            .finish_non_exhaustive()
    }
}

/// The protected low bits of the first byte: four for a long header, five
/// for a short header.
fn first_byte_mask(first_byte: u8) -> u8 {
    if first_byte & 0x80 != 0 { 0x0f } else { 0x1f }
}

/// The Packet Number field length that an unprotected first byte encodes.
fn pn_len(first_byte: u8) -> usize {
    usize::from(first_byte & 0x03) + 1
}

/// The error returned by [`HeaderProtectionKey::remove`] and
/// [`HeaderProtectionKey::apply`].
#[derive(Debug, Snafu)]
#[snafu(module(header_protection_error))]
pub enum HeaderProtectionError {
    /// The Packet Number field cannot start at the first byte.
    #[snafu(display("packet number offset is zero"))]
    PacketNumberOffsetZero,
    /// The packet ends before the end of the ciphertext sample.
    #[snafu(display(
        "packet of {packet_len} bytes has no 16-byte sample at packet number offset {pn_offset} plus 4"
    ))]
    SampleOutOfBounds {
        /// The packet number offset given.
        pn_offset: usize,
        /// Length of the packet buffer.
        packet_len: usize,
    },
}
