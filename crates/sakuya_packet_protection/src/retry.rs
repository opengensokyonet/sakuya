//! The Retry integrity tag (RFC 9001 §5.8).

use sakuya_wire::connection_id::ConnectionId;
use snafu::{OptionExt, ResultExt, Snafu};

use crate::backend::{
    AEAD_NONCE_LEN, AEAD_TAG_LEN, AeadAlgorithm, AeadKey, AuthenticationFailed, CryptoBackend,
};

/// The QUIC version 1 key of the Retry integrity tag.
const RETRY_KEY: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];

/// The QUIC version 1 nonce of the Retry integrity tag.
const RETRY_NONCE: [u8; AEAD_NONCE_LEN] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

/// Computes the Retry Integrity Tag of a QUIC version 1 Retry packet.
///
/// `odcid` is the Destination Connection ID of the client Initial the Retry
/// responds to. `retry_without_tag` is the Retry packet as sent, from its
/// first byte up to, not including, the tag. The tag is the AES-128-GCM tag
/// over the Retry pseudo-packet: the ODCID length byte, the ODCID and
/// `retry_without_tag`, with an empty plaintext.
pub fn compute_retry_integrity_tag<B: CryptoBackend>(
    backend: &B,
    odcid: &ConnectionId,
    retry_without_tag: &[u8],
) -> [u8; AEAD_TAG_LEN] {
    let mut tag = [0; AEAD_TAG_LEN];
    // invariant: the plaintext is empty, within the limit of every AEAD.
    retry_key(backend)
        .seal_in_place(
            &RETRY_NONCE,
            &pseudo_packet(odcid, retry_without_tag),
            &mut [],
            &mut tag,
        )
        .expect("an empty plaintext is within the AEAD limit");
    tag
}

/// Checks the Retry Integrity Tag at the end of a QUIC version 1 Retry
/// packet.
///
/// `odcid` is the Destination Connection ID the client sent in its Initial;
/// `retry_packet` is the whole Retry packet including its 16-byte tag. The
/// tag comparison runs inside the backend's AEAD.
///
/// # Errors
///
/// - [`VerifyRetryIntegrityError::PacketTooShort`] when `retry_packet` is
///   shorter than the tag.
/// - [`VerifyRetryIntegrityError::Authentication`] when the tag does not
///   match; the client discards such a Retry.
pub fn verify_retry_integrity_tag<B: CryptoBackend>(
    backend: &B,
    odcid: &ConnectionId,
    retry_packet: &[u8],
) -> Result<(), VerifyRetryIntegrityError> {
    let (retry_without_tag, tag) = retry_packet.split_last_chunk::<AEAD_TAG_LEN>().context(
        verify_retry_integrity_error::PacketTooShortSnafu {
            packet_len: retry_packet.len(),
        },
    )?;
    retry_key(backend)
        .open_in_place(
            &RETRY_NONCE,
            &pseudo_packet(odcid, retry_without_tag),
            &mut [],
            tag,
        )
        .context(verify_retry_integrity_error::AuthenticationSnafu)
}

fn retry_key<B: CryptoBackend>(backend: &B) -> B::AeadKey {
    // invariant: `RETRY_KEY` is the 16 bytes AES-128-GCM takes, the only
    // length a backend accepts and the only one it may refuse.
    backend
        .aead_key(AeadAlgorithm::Aes128Gcm, &RETRY_KEY)
        .expect("the 16-byte Retry key is accepted")
}

fn pseudo_packet(odcid: &ConnectionId, retry_without_tag: &[u8]) -> Vec<u8> {
    let mut pseudo_packet = Vec::with_capacity(1 + odcid.len() + retry_without_tag.len());
    pseudo_packet.push(u8::from(odcid.length()));
    pseudo_packet.extend_from_slice(odcid.as_bytes());
    pseudo_packet.extend_from_slice(retry_without_tag);
    pseudo_packet
}

/// The error returned by [`verify_retry_integrity_tag`].
#[derive(Debug, Snafu)]
#[snafu(module(verify_retry_integrity_error))]
pub enum VerifyRetryIntegrityError {
    /// The packet is shorter than the tag.
    #[snafu(display("retry packet of {packet_len} bytes is shorter than its 16-byte tag"))]
    PacketTooShort {
        /// Length of the packet given.
        packet_len: usize,
    },
    /// The tag does not match.
    #[snafu(display("retry integrity tag does not match"))]
    Authentication {
        /// The backend's failure.
        source: AuthenticationFailed,
    },
}

#[cfg(all(test, feature = "ring"))]
mod tests {
    use super::*;
    use crate::backend::KdfAlgorithm;
    use crate::backend::ring::RingBackend;

    /// RFC 9001 §5.8: the key and nonce are "quic key" and "quic iv" of this
    /// secret.
    #[test]
    fn retry_key_and_nonce_derive_from_published_secret() {
        let secret = [
            0xd9, 0xc9, 0x94, 0x3e, 0x61, 0x01, 0xfd, 0x20, 0x00, 0x21, 0x50, 0x6b, 0xcc, 0x02,
            0x81, 0x4c, 0x73, 0x03, 0x0f, 0x25, 0xc7, 0x9d, 0x71, 0xce, 0x87, 0x6e, 0xca, 0x87,
            0x6e, 0x6f, 0xca, 0x8e,
        ];
        let backend = RingBackend;
        let mut key = [0; 16];
        backend
            .hkdf_expand_label(
                KdfAlgorithm::HkdfSha256,
                &secret,
                b"quic key",
                &[],
                &mut key,
            )
            .unwrap();
        let mut nonce = [0; 12];
        backend
            .hkdf_expand_label(
                KdfAlgorithm::HkdfSha256,
                &secret,
                b"quic iv",
                &[],
                &mut nonce,
            )
            .unwrap();
        assert_eq!(key, RETRY_KEY);
        assert_eq!(nonce, RETRY_NONCE);
    }
}
