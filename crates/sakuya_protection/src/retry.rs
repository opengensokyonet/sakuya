//! The Retry integrity tag (RFC 9001 §5.8).

use snafu::{ResultExt, Snafu, ensure};

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

/// Longest connection ID in QUIC version 1, in bytes.
const MAX_CONNECTION_ID_LEN: usize = 20;

/// Computes the Retry Integrity Tag of a QUIC version 1 Retry packet.
///
/// `odcid` is the Destination Connection ID of the client Initial the Retry
/// responds to. `retry_without_tag` is the Retry packet as sent, from its
/// first byte up to, not including, the tag. The tag is the AES-128-GCM tag
/// over the Retry pseudo-packet: the ODCID length byte, the ODCID and
/// `retry_without_tag`, with an empty plaintext.
///
/// # Errors
///
/// Fails when `odcid` is longer than 20 bytes.
pub fn compute_retry_integrity_tag<B: CryptoBackend>(
    backend: &B,
    odcid: &[u8],
    retry_without_tag: &[u8],
) -> Result<[u8; AEAD_TAG_LEN], OriginalConnectionIdTooLong> {
    let pseudo_packet = pseudo_packet(odcid, retry_without_tag)?;
    let mut tag = [0; AEAD_TAG_LEN];
    backend
        .aead_key(AeadAlgorithm::Aes128Gcm, &RETRY_KEY)
        .seal_in_place(&RETRY_NONCE, &pseudo_packet, &mut [], &mut tag);
    Ok(tag)
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
/// - [`VerifyRetryIntegrityError::OriginalConnectionIdTooLong`] when `odcid`
///   is longer than 20 bytes.
/// - [`VerifyRetryIntegrityError::PacketTooShort`] when `retry_packet` is
///   shorter than the tag.
/// - [`VerifyRetryIntegrityError::Authentication`] when the tag does not
///   match; the client discards such a Retry.
pub fn verify_retry_integrity_tag<B: CryptoBackend>(
    backend: &B,
    odcid: &[u8],
    retry_packet: &[u8],
) -> Result<(), VerifyRetryIntegrityError> {
    let Some(tag_offset) = retry_packet.len().checked_sub(AEAD_TAG_LEN) else {
        return verify_retry_integrity_error::PacketTooShortSnafu {
            packet_len: retry_packet.len(),
        }
        .fail();
    };
    let (retry_without_tag, tag) = retry_packet.split_at(tag_offset);
    let tag: &[u8; AEAD_TAG_LEN] = tag.try_into().expect("tag is 16 bytes");
    let pseudo_packet = pseudo_packet(odcid, retry_without_tag)?;
    backend
        .aead_key(AeadAlgorithm::Aes128Gcm, &RETRY_KEY)
        .open_in_place(&RETRY_NONCE, &pseudo_packet, &mut [], tag)
        .context(verify_retry_integrity_error::AuthenticationSnafu)
}

fn pseudo_packet(
    odcid: &[u8],
    retry_without_tag: &[u8],
) -> Result<Vec<u8>, OriginalConnectionIdTooLong> {
    ensure!(
        odcid.len() <= MAX_CONNECTION_ID_LEN,
        OriginalConnectionIdTooLongSnafu { len: odcid.len() }
    );
    let mut pseudo_packet = Vec::with_capacity(1 + odcid.len() + retry_without_tag.len());
    // The check above bounds the length to one byte.
    pseudo_packet.push(odcid.len() as u8);
    pseudo_packet.extend_from_slice(odcid);
    pseudo_packet.extend_from_slice(retry_without_tag);
    Ok(pseudo_packet)
}

/// An original Destination Connection ID is longer than the 20 bytes QUIC
/// version 1 allows.
#[derive(Debug, Snafu)]
#[snafu(display("original destination connection ID of {len} bytes exceeds 20 bytes"))]
pub struct OriginalConnectionIdTooLong {
    /// Length of the connection ID given.
    pub len: usize,
}

/// The error returned by [`verify_retry_integrity_tag`].
#[derive(Debug, Snafu)]
#[snafu(module(verify_retry_integrity_error))]
pub enum VerifyRetryIntegrityError {
    /// The original Destination Connection ID is too long.
    #[snafu(transparent)]
    OriginalConnectionIdTooLong {
        /// The length check that failed.
        source: OriginalConnectionIdTooLong,
    },
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
