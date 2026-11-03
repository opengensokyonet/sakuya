//! A [`CryptoBackend`] implemented with `ring`.

use ::ring::{aead, hkdf, hmac};
use snafu::OptionExt;

use super::{
    AEAD_NONCE_LEN, AEAD_TAG_LEN, AeadAlgorithm, AeadInputTooLong, AeadInputTooLongSnafu, AeadKey,
    AuthenticationFailed, AuthenticationFailedSnafu, CryptoBackend, ExpandOutputTooLong,
    ExpandOutputTooLongSnafu, HEADER_PROTECTION_MASK_LEN, HEADER_PROTECTION_SAMPLE_LEN,
    HeaderProtectionCipher, KdfAlgorithm, KeyLengthMismatch, KeyLengthMismatchSnafu, MAX_HASH_LEN,
};

/// The backend built on `ring` 0.17.
///
/// It is stateless; every value is interchangeable.
///
/// When opening fails, `ring` zeroes the region it was decrypting, so the
/// ciphertext is gone from the buffer.
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
        Ok(RingAeadKey(aead::LessSafeKey::new(key)))
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
pub struct RingAeadKey(aead::LessSafeKey);

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
        // `ring` refuses to seal only an input beyond the AEAD limit, before
        // writing it.
        let computed = self
            .0
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
    ) -> Result<(), AuthenticationFailed> {
        self.0
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
