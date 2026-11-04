//! A [`CryptoBackend`] implemented with `ring`.

use ::ring::{aead, hkdf, hmac};
use snafu::{OptionExt, ResultExt, ensure};

use super::{
    AEAD_NONCE_LEN, AEAD_TAG_LEN, AeadAlgorithm, AeadInputTooLong, AeadInputTooLongSnafu, AeadKey,
    AeadOpenError, AuthenticationFailedSnafu, CryptoBackend, ExpandOutputTooLong,
    ExpandOutputTooLongSnafu, HEADER_PROTECTION_MASK_LEN, HEADER_PROTECTION_SAMPLE_LEN,
    HeaderProtectionCipher, KdfAlgorithm, KeyLengthMismatch, KeyLengthMismatchSnafu, MAX_HASH_LEN,
    aead_open_error,
};

/// The longest input `ring` 0.17 seals or opens under one nonce with
/// AES-GCM: 2<sup>32</sup> − 2 blocks of 16 bytes, the limit of NIST SP
/// 800-38D §5.2.1.1.
const AES_GCM_MAX_INPUT_LEN: u64 = ((1 << 32) - 2) * 16;

/// The longest input `ring` 0.17 seals or opens under one nonce with
/// ChaCha20-Poly1305: 2<sup>32</sup> − 1 blocks of 64 bytes, the limit of
/// RFC 8439 §2.8.
const CHACHA20_POLY1305_MAX_INPUT_LEN: u64 = ((1 << 32) - 1) * 64;

/// The backend built on `ring` 0.17.
///
/// It is stateless; every value is interchangeable.
///
/// When authentication fails, `ring` zeroes the region it was decrypting, so
/// the ciphertext is gone from the buffer. `ring` does not tell an input
/// beyond the AEAD limit apart from a failed authentication, so the backend
/// checks the length against the limit of each algorithm before calling it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RingBackend;

impl CryptoBackend for RingBackend {
    type AeadKey = RingAeadKey;
    type HeaderProtectionCipher = RingHeaderProtectionCipher;

    fn hkdf_extract(
        &self,
        kdf: KdfAlgorithm,
        salt: &[u8],
        ikm: &[u8],
        prk: &mut [u8; MAX_HASH_LEN],
    ) {
        // HKDF-Extract is HMAC keyed with the salt; computing it directly
        // exposes the PRK bytes, which `ring::hkdf::Prk` keeps opaque.
        let tag = hmac::sign(&hmac::Key::new(hmac_algorithm(kdf), salt), ikm);
        let tag = tag.as_ref();
        // invariant: the HMAC output is `kdf.hash_len()` bytes, at most
        // `MAX_HASH_LEN`.
        prk[..tag.len()].copy_from_slice(tag);
    }

    fn hkdf_expand(
        &self,
        kdf: KdfAlgorithm,
        prk: &[u8],
        info: &[&[u8]],
        output: &mut [u8],
    ) -> Result<(), ExpandOutputTooLong> {
        // `ring` refuses an output length only when it exceeds the
        // HKDF-Expand limit, before writing any output.
        let prk = hkdf::Prk::new_less_safe(hkdf_algorithm(kdf), prk);
        prk.expand(info, OutputLen(output.len()))
            .and_then(|okm| okm.fill(output))
            .ok()
            .context(ExpandOutputTooLongSnafu {
                output_len: output.len(),
                max_output_len: 255 * kdf.hash_len(),
            })
    }

    fn aead_key(&self, aead: AeadAlgorithm, key: &[u8]) -> Result<RingAeadKey, KeyLengthMismatch> {
        // `ring` refuses a key only when its length does not match.
        let key = aead::UnboundKey::new(aead_algorithm(aead), key)
            .ok()
            .context(KeyLengthMismatchSnafu {
                expected: aead.key_len(),
                actual: key.len(),
            })?;
        Ok(RingAeadKey {
            key: aead::LessSafeKey::new(key),
            max_input_len: max_input_len(aead),
        })
    }

    fn header_protection_cipher(
        &self,
        aead: AeadAlgorithm,
        key: &[u8],
    ) -> Result<RingHeaderProtectionCipher, KeyLengthMismatch> {
        let algorithm = match aead {
            AeadAlgorithm::Aes128Gcm => &aead::quic::AES_128,
            AeadAlgorithm::Aes256Gcm => &aead::quic::AES_256,
            AeadAlgorithm::ChaCha20Poly1305 => &aead::quic::CHACHA20,
        };
        // `ring` refuses a key only when its length does not match.
        let key = aead::quic::HeaderProtectionKey::new(algorithm, key)
            .ok()
            .context(KeyLengthMismatchSnafu {
                expected: aead.key_len(),
                actual: key.len(),
            })?;
        Ok(RingHeaderProtectionCipher(key))
    }
}

/// The AEAD key of [`RingBackend`].
pub struct RingAeadKey {
    key: aead::LessSafeKey,
    /// The longest input the algorithm protects under one nonce.
    max_input_len: u64,
}

impl RingAeadKey {
    /// Checks that `input_len` bytes are within the AEAD limit.
    fn check_input_len(&self, input_len: usize) -> Result<(), AeadInputTooLong> {
        // A `usize` that does not fit a `u64` exceeds every limit.
        let within = u64::try_from(input_len).is_ok_and(|len| len <= self.max_input_len);
        ensure!(within, AeadInputTooLongSnafu { input_len });
        Ok(())
    }
}

impl core::fmt::Debug for RingAeadKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RingAeadKey").finish_non_exhaustive()
    }
}

impl AeadKey for RingAeadKey {
    fn seal_in_place(
        &self,
        nonce: &[u8; AEAD_NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &mut [u8; AEAD_TAG_LEN],
    ) -> Result<(), AeadInputTooLong> {
        let input_len = in_out.len();
        self.check_input_len(input_len)?;
        // `ring` refuses to seal only an input beyond the AEAD limit, before
        // writing it.
        let computed = self
            .key
            .seal_in_place_separate_tag(
                aead::Nonce::assume_unique_for_key(*nonce),
                aead::Aad::from(aad),
                in_out,
            )
            .ok()
            .context(AeadInputTooLongSnafu { input_len })?;
        // invariant: every `ring` AEAD tag is 16 bytes.
        tag.copy_from_slice(computed.as_ref());
        Ok(())
    }

    fn open_in_place(
        &self,
        nonce: &[u8; AEAD_NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &[u8; AEAD_TAG_LEN],
    ) -> Result<(), AeadOpenError> {
        self.check_input_len(in_out.len())
            .context(aead_open_error::InputTooLongSnafu)?;
        // Within the limit, `ring` refuses to open only when authentication
        // fails.
        self.key
            .open_in_place_separate_tag(
                aead::Nonce::assume_unique_for_key(*nonce),
                aead::Aad::from(aad),
                aead::Tag::from(*tag),
                in_out,
                0..,
            )
            .map(|_| ())
            .ok()
            .context(AuthenticationFailedSnafu)
            .context(aead_open_error::AuthenticationSnafu)
    }
}

/// The header protection cipher of [`RingBackend`].
pub struct RingHeaderProtectionCipher(aead::quic::HeaderProtectionKey);

impl core::fmt::Debug for RingHeaderProtectionCipher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RingHeaderProtectionCipher")
            .finish_non_exhaustive()
    }
}

impl HeaderProtectionCipher for RingHeaderProtectionCipher {
    fn mask(
        &self,
        sample: &[u8; HEADER_PROTECTION_SAMPLE_LEN],
    ) -> [u8; HEADER_PROTECTION_MASK_LEN] {
        // invariant: `ring` refuses only a sample whose length differs from
        // the 16 bytes of every QUIC header protection cipher, which the
        // array type rules out.
        self.0
            .new_mask(sample)
            .expect("a 16-byte sample is accepted")
    }
}

fn hmac_algorithm(kdf: KdfAlgorithm) -> hmac::Algorithm {
    match kdf {
        KdfAlgorithm::HkdfSha256 => hmac::HMAC_SHA256,
        KdfAlgorithm::HkdfSha384 => hmac::HMAC_SHA384,
    }
}

fn hkdf_algorithm(kdf: KdfAlgorithm) -> hkdf::Algorithm {
    match kdf {
        KdfAlgorithm::HkdfSha256 => hkdf::HKDF_SHA256,
        KdfAlgorithm::HkdfSha384 => hkdf::HKDF_SHA384,
    }
}

fn max_input_len(aead: AeadAlgorithm) -> u64 {
    match aead {
        AeadAlgorithm::Aes128Gcm | AeadAlgorithm::Aes256Gcm => AES_GCM_MAX_INPUT_LEN,
        AeadAlgorithm::ChaCha20Poly1305 => CHACHA20_POLY1305_MAX_INPUT_LEN,
    }
}

fn aead_algorithm(aead: AeadAlgorithm) -> &'static aead::Algorithm {
    match aead {
        AeadAlgorithm::Aes128Gcm => &aead::AES_128_GCM,
        AeadAlgorithm::Aes256Gcm => &aead::AES_256_GCM,
        AeadAlgorithm::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
    }
}

/// The output length handed to `ring`'s HKDF-Expand.
struct OutputLen(usize);

impl hkdf::KeyType for OutputLen {
    fn len(&self) -> usize {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_beyond_the_aead_limit_is_refused_before_ring() {
        for (aead, limit) in [
            (AeadAlgorithm::Aes128Gcm, 68_719_476_704),
            (AeadAlgorithm::Aes256Gcm, 68_719_476_704),
            (AeadAlgorithm::ChaCha20Poly1305, 274_877_906_880),
        ] {
            let key = RingBackend
                .aead_key(aead, &[0; 32][..aead.key_len()])
                .unwrap();
            assert_eq!(key.max_input_len, limit, "{aead:?}");
            if let Ok(limit) = usize::try_from(limit) {
                assert!(key.check_input_len(limit).is_ok(), "{aead:?}");
                let error = key.check_input_len(limit + 1).unwrap_err();
                assert_eq!(error.input_len, limit + 1, "{aead:?}");
            } else {
                assert!(key.check_input_len(usize::MAX).is_ok(), "{aead:?}");
            }
        }
    }
}
