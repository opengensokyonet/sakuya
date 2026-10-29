//! AEAD packet protection (RFC 9001 §5.1, §5.3).

use snafu::{ResultExt, Snafu};

use crate::backend::{
    AEAD_NONCE_LEN, AEAD_TAG_LEN, AeadAlgorithm, AeadKey, AuthenticationFailed, CryptoBackend,
    MAX_KEY_LEN,
};
use crate::secret::TrafficSecret;
use crate::wipe::wipe;

/// The packet protection key and IV of one traffic secret, for opening or
/// sealing packet payloads.
///
/// A key update replaces the packet key with one derived from
/// [`TrafficSecret::next`]; the [`HeaderProtectionKey`](crate::header_protection::HeaderProtectionKey)
/// stays.
pub struct PacketKey<B: CryptoBackend> {
    key: B::AeadKey,
    iv: [u8; AEAD_NONCE_LEN],
}

impl<B: CryptoBackend> PacketKey<B> {
    /// Derives the key (`"quic key"`, `aead.key_len()` bytes) and the IV
    /// (`"quic iv"`, 12 bytes) from `secret` (RFC 9001 §5.1).
    ///
    /// `aead` is the AEAD of the cipher suite that produced `secret`, or
    /// [`INITIAL_AEAD`](crate::initial::INITIAL_AEAD) for Initial secrets.
    pub fn derive(backend: &B, aead: AeadAlgorithm, secret: &TrafficSecret) -> Self {
        let mut key = [0; MAX_KEY_LEN];
        let key = &mut key[..aead.key_len()];
        secret.expand_label(backend, b"quic key", key);
        let mut iv = [0; AEAD_NONCE_LEN];
        secret.expand_label(backend, b"quic iv", &mut iv);
        let packet_key = Self {
            key: backend.aead_key(aead, key),
            iv,
        };
        wipe(key);
        wipe(&mut iv);
        packet_key
    }

    /// Decrypts the payload of `packet` in place and returns the plaintext,
    /// which is `packet[header_len..packet.len() - 16]`.
    ///
    /// `packet` holds exactly one packet, starting at its first byte, with
    /// header protection already removed; `packet[..header_len]` is the
    /// complete header up to and including the packet number field and is
    /// authenticated as associated data. `packet_number` is the full packet
    /// number recovered from that field. The tag is the last 16 bytes.
    ///
    /// # Errors
    ///
    /// - [`OpenPacketError::PacketTooShort`] when `packet` cannot hold the
    ///   header and the tag; `packet` is unchanged.
    /// - [`OpenPacketError::Authentication`] when the tag does not match. The
    ///   payload region `packet[header_len..]` may have been overwritten: the
    ///   `ring` backend zeroes it. To try another key, the caller rebuilds the
    ///   payload — and the header bytes that header protection removal
    ///   rewrote — from the read-only received datagram; this crate keeps no
    ///   copy.
    pub fn open<'p>(
        &self,
        packet_number: u64,
        packet: &'p mut [u8],
        header_len: usize,
    ) -> Result<&'p mut [u8], OpenPacketError> {
        let payload_end = payload_end(packet.len(), header_len)?;
        let (header, rest) = packet.split_at_mut(header_len);
        let (payload, tag) = rest.split_at_mut(payload_end - header_len);
        let tag: &[u8; AEAD_TAG_LEN] = (&*tag).try_into().expect("tag is 16 bytes");
        self.key
            .open_in_place(&self.nonce(packet_number), header, payload, tag)
            .context(open_packet_error::AuthenticationSnafu)?;
        Ok(payload)
    }

    /// Encrypts the payload of `packet` in place and writes the tag into its
    /// last 16 bytes.
    ///
    /// `packet` holds exactly one packet, starting at its first byte:
    /// `packet[..header_len]` is the complete unprotected header up to and
    /// including the packet number field, followed by the plaintext payload
    /// and 16 bytes reserved for the tag, whose contents are ignored.
    /// `packet_number` is the full packet number whose truncation is in the
    /// header. Apply header protection afterwards.
    ///
    /// # Errors
    ///
    /// Fails when `packet` cannot hold the header and the tag; `packet` is
    /// unchanged.
    pub fn seal(
        &self,
        packet_number: u64,
        packet: &mut [u8],
        header_len: usize,
    ) -> Result<(), PacketTooShort> {
        let payload_end = payload_end(packet.len(), header_len)?;
        let (header, rest) = packet.split_at_mut(header_len);
        let (payload, tag) = rest.split_at_mut(payload_end - header_len);
        let tag: &mut [u8; AEAD_TAG_LEN] = tag.try_into().expect("tag is 16 bytes");
        self.key
            .seal_in_place(&self.nonce(packet_number), header, payload, tag);
        Ok(())
    }

    /// The IV exclusive-ored with the packet number, left-padded to the IV
    /// length in network byte order.
    fn nonce(&self, packet_number: u64) -> [u8; AEAD_NONCE_LEN] {
        let mut nonce = self.iv;
        let offset = AEAD_NONCE_LEN - 8;
        for (byte, pn) in nonce[offset..].iter_mut().zip(packet_number.to_be_bytes()) {
            *byte ^= pn;
        }
        nonce
    }
}

impl<B: CryptoBackend> Drop for PacketKey<B> {
    fn drop(&mut self) {
        wipe(&mut self.iv);
    }
}

impl<B: CryptoBackend> core::fmt::Debug for PacketKey<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PacketKey").finish_non_exhaustive()
    }
}

fn payload_end(packet_len: usize, header_len: usize) -> Result<usize, PacketTooShort> {
    let payload_end = packet_len.checked_sub(AEAD_TAG_LEN);
    match payload_end {
        Some(end) if end >= header_len => Ok(end),
        _ => PacketTooShortSnafu {
            packet_len,
            header_len,
        }
        .fail(),
    }
}

/// A packet buffer cannot hold its header and the 16-byte AEAD tag.
#[derive(Debug, Snafu)]
#[snafu(display(
    "packet of {packet_len} bytes cannot hold a {header_len}-byte header and a 16-byte tag"
))]
pub struct PacketTooShort {
    /// Length of the packet buffer.
    pub packet_len: usize,
    /// The header length given.
    pub header_len: usize,
}

/// The error returned by [`PacketKey::open`].
#[derive(Debug, Snafu)]
#[snafu(module(open_packet_error))]
pub enum OpenPacketError {
    /// The packet cannot hold its header and the tag.
    #[snafu(transparent)]
    PacketTooShort {
        /// The length check that failed.
        source: PacketTooShort,
    },
    /// The payload did not authenticate under this key; the payload region
    /// may have been overwritten.
    #[snafu(display("cannot open packet payload"))]
    Authentication {
        /// The backend's failure.
        source: AuthenticationFailed,
    },
}
