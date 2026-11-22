//! The `aws-lc-rs` implementation of the [`CryptoBackend`] of
//! `sakuya_packet_protection_v1`.

#![warn(missing_docs)]

use ::aws_lc_rs::{
    aead, hmac,
    rand::{SecureRandom, SystemRandom},
};
use nitori_crypto::{AeadAlgorithm, HashAlgorithm, Random, RandomError};

use sakuya_packet_protection_v1::backend::{
    AEAD_NONCE_LEN, AEAD_TAG_LEN, AeadInputTooLongError, AeadKey, AeadOpenError,
    AuthenticationError, CryptoBackend, ExpandOutputTooLongError, HEADER_PROTECTION_MASK_LEN,
    HEADER_PROTECTION_SAMPLE_LEN, HeaderProtectionCipher, KeyLengthMismatchError, MAX_HASH_LEN,
};

/// The backend built on `aws-lc-rs` 1.
///
/// It is stateless; every value is interchangeable.
///
/// When authentication fails, AWS-LC zeroes the region it was decrypting, so
/// the ciphertext is gone from the buffer. `aws-lc-rs` checks no AEAD input
/// limit of its own, so the backend checks the length against the limit of
/// each algorithm before calling it. With ChaCha20-Poly1305 the longest input
/// it accepts is one byte short of the limit in RFC 8439 §2.8 (2^38 − 65
/// bytes), because AWS-LC rejects 2^38 − 64 bytes and more; longer inputs
/// return [`AeadInputTooLongError`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AwsLcBackend;

/// Random bytes from the operating system's generator, as `aws-lc-rs` draws
/// them.
impl Random for AwsLcBackend {
    fn random<const N: usize>(&self) -> Result<[u8; N], RandomError> {
        let mut out = [0; N];
        // aws-lc-rs reports no detail beyond the failure itself
        SystemRandom::new()
            .fill(&mut out)
            .map_err(|_| RandomError)?;
        Ok(out)
    }
}

impl CryptoBackend for AwsLcBackend {
    type AeadKey = AwsLcAeadKey;
    type HeaderProtectionCipher = AwsLcHeaderProtectionCipher;

    fn hkdf_extract(
        &self,
        hash: HashAlgorithm,
        salt: &[u8],
        ikm: &[u8],
        prk: &mut [u8; MAX_HASH_LEN],
    ) {
        // HKDF-Extract is HMAC keyed with the salt; computing it directly
        // exposes the PRK bytes, which `aws_lc_rs::hkdf::Prk` keeps opaque.
        let tag = hmac::sign(&hmac::Key::new(hmac_algorithm(hash), salt), ikm);
        let tag = tag.as_ref();
        // invariant: the HMAC output is `hash.output_len()` bytes, at most
        // `MAX_HASH_LEN`.
        prk[..tag.len()].copy_from_slice(tag);
    }

    fn hkdf_expand(
        &self,
        hash: HashAlgorithm,
        prk: &[u8],
        info: &[&[u8]],
        output: &mut [u8],
    ) -> Result<(), ExpandOutputTooLongError> {
        let hash_len = hash.output_len();
        let max_output_len = 255 * hash_len;
        if output.len() > max_output_len {
            return Err(ExpandOutputTooLongError {
                output_len: output.len(),
                max_output_len,
            });
        }
        // HKDF-Expand is computed with HMAC directly:
        // `aws_lc_rs::hkdf::Prk::new_less_safe` panics on a PRK longer than
        // 64 bytes, and HMAC takes a key of any length.
        let key = hmac::Key::new(hmac_algorithm(hash), prk);
        let mut previous: Option<hmac::Tag> = None;
        // At most 255 blocks, by the check above.
        for (block, counter) in output.chunks_mut(hash_len).zip(1..=u8::MAX) {
            let mut context = hmac::Context::with_key(&key);
            if let Some(previous) = &previous {
                context.update(previous.as_ref());
            }
            for piece in info {
                context.update(piece);
            }
            context.update(&[counter]);
            let tag = context.sign();
            // invariant: every block is at most `hash_len` bytes, the HMAC
            // output length.
            block.copy_from_slice(&tag.as_ref()[..block.len()]);
            previous = Some(tag);
        }
        Ok(())
    }

    fn aead_key(
        &self,
        aead: AeadAlgorithm,
        key: &[u8],
    ) -> Result<AwsLcAeadKey, KeyLengthMismatchError> {
        if key.len() != aead.key_len() {
            return Err(KeyLengthMismatchError {
                expected: aead.key_len(),
                actual: key.len(),
            });
        }
        // invariant: besides a key length that does not match, `aws-lc-rs`
        // refuses a key only when allocating its AWS-LC context fails.
        let key = aead::UnboundKey::new(aead_algorithm(aead), key)
            .expect("the AEAD context is allocated");
        Ok(AwsLcAeadKey {
            key: aead::LessSafeKey::new(key),
            max_input_len: max_input_len(aead),
        })
    }

    fn header_protection_cipher(
        &self,
        aead: AeadAlgorithm,
        key: &[u8],
    ) -> Result<AwsLcHeaderProtectionCipher, KeyLengthMismatchError> {
        let algorithm = match aead {
            AeadAlgorithm::Aes128Gcm => &aead::quic::AES_128,
            AeadAlgorithm::Aes256Gcm => &aead::quic::AES_256,
            AeadAlgorithm::ChaCha20Poly1305 => &aead::quic::CHACHA20,
        };
        // `aws-lc-rs` refuses a key only when its length does not match;
        // AWS-LC's AES key schedule refuses only other key sizes.
        let key = aead::quic::HeaderProtectionKey::new(algorithm, key).map_err(|_| {
            KeyLengthMismatchError {
                expected: aead.key_len(),
                actual: key.len(),
            }
        })?;
        Ok(AwsLcHeaderProtectionCipher(key))
    }
}

/// The AEAD key of [`AwsLcBackend`].
pub struct AwsLcAeadKey {
    key: aead::LessSafeKey,
    /// The longest input the algorithm protects under one nonce.
    max_input_len: u64,
}

impl AwsLcAeadKey {
    /// Checks that `input_len` bytes are within the AEAD limit.
    fn check_input_len(&self, input_len: usize) -> Result<(), AeadInputTooLongError> {
        // A `usize` that does not fit a `u64` exceeds every limit.
        let within = u64::try_from(input_len).is_ok_and(|len| len <= self.max_input_len);
        if within {
            Ok(())
        } else {
            Err(AeadInputTooLongError { input_len })
        }
    }
}

impl core::fmt::Debug for AwsLcAeadKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AwsLcAeadKey").finish_non_exhaustive()
    }
}

impl AeadKey for AwsLcAeadKey {
    fn seal_in_place(
        &self,
        nonce: &[u8; AEAD_NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &mut [u8; AEAD_TAG_LEN],
    ) -> Result<(), AeadInputTooLongError> {
        let input_len = in_out.len();
        self.check_input_len(input_len)?;
        let computed = self
            .key
            .seal_in_place_separate_tag(
                aead::Nonce::assume_unique_for_key(*nonce),
                aead::Aad::from(aad),
                in_out,
            )
            // invariant: within the limit, AWS-LC refuses to seal only
            // associated data beyond 2^61 bytes with AES-GCM (aead.c,
            // gcm.c), more than any address space holds.
            .expect("AWS-LC seals every input within the limit");
        // invariant: AWS-LC writes a tag of the 16 bytes every key is
        // created with.
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
            .map_err(|source| AeadOpenError::InputTooLong { source })?;
        // Within the limit, AWS-LC refuses to open only when authentication
        // fails, or for associated data beyond 2^61 bytes with AES-GCM, more
        // than any address space holds.
        self.key
            .open_in_place_separate_tag(
                aead::Nonce::assume_unique_for_key(*nonce),
                aead::Aad::from(aad),
                tag,
                in_out,
            )
            .map(|_| ())
            .map_err(|_| AeadOpenError::Authentication {
                source: AuthenticationError,
            })
    }
}

/// The header protection cipher of [`AwsLcBackend`].
pub struct AwsLcHeaderProtectionCipher(aead::quic::HeaderProtectionKey);

impl core::fmt::Debug for AwsLcHeaderProtectionCipher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AwsLcHeaderProtectionCipher")
            .finish_non_exhaustive()
    }
}

impl HeaderProtectionCipher for AwsLcHeaderProtectionCipher {
    fn mask(
        &self,
        sample: &[u8; HEADER_PROTECTION_SAMPLE_LEN],
    ) -> [u8; HEADER_PROTECTION_MASK_LEN] {
        // invariant: `aws-lc-rs` refuses only a sample whose length differs
        // from the 16 bytes of every QUIC header protection cipher, which the
        // array type rules out.
        self.0
            .new_mask(sample)
            .expect("a 16-byte sample is accepted")
    }
}

fn hmac_algorithm(hash: HashAlgorithm) -> hmac::Algorithm {
    match hash {
        HashAlgorithm::Sha256 => hmac::HMAC_SHA256,
        HashAlgorithm::Sha384 => hmac::HMAC_SHA384,
    }
}

/// The longest input the backend seals or opens under one nonce with `aead`.
fn max_input_len(aead: AeadAlgorithm) -> u64 {
    let max_len = nitori_crypto::AeadInputTooLongError::max_len(aead);
    match aead {
        // AWS-LC's GCM refuses exactly the inputs beyond this limit.
        AeadAlgorithm::Aes128Gcm | AeadAlgorithm::Aes256Gcm => max_len,
        // AWS-LC refuses an input of 2^38 − 64 bytes or more, so the longest
        // it accepts is one byte short of the RFC 8439 limit.
        AeadAlgorithm::ChaCha20Poly1305 => max_len - 1,
    }
}

fn aead_algorithm(aead: AeadAlgorithm) -> &'static aead::Algorithm {
    match aead {
        AeadAlgorithm::Aes128Gcm => &aead::AES_128_GCM,
        AeadAlgorithm::Aes256Gcm => &aead::AES_256_GCM,
        AeadAlgorithm::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_beyond_the_aead_limit_is_refused_before_aws_lc() {
        for (aead, limit) in [
            (AeadAlgorithm::Aes128Gcm, 68_719_476_704),
            (AeadAlgorithm::Aes256Gcm, 68_719_476_704),
            (AeadAlgorithm::ChaCha20Poly1305, 274_877_906_879),
        ] {
            let key = AwsLcBackend
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

    /// The output of `aws-lc-rs`'s own HKDF-Expand.
    fn library_expand(hash: HashAlgorithm, prk: &[u8], info: &[&[u8]], output: &mut [u8]) {
        struct Len(usize);
        impl aws_lc_rs::hkdf::KeyType for Len {
            fn len(&self) -> usize {
                self.0
            }
        }
        let algorithm = match hash {
            HashAlgorithm::Sha256 => aws_lc_rs::hkdf::HKDF_SHA256,
            HashAlgorithm::Sha384 => aws_lc_rs::hkdf::HKDF_SHA384,
        };
        aws_lc_rs::hkdf::Prk::new_less_safe(algorithm, prk)
            .expand(info, Len(output.len()))
            .unwrap()
            .fill(output)
            .unwrap();
    }

    #[test]
    fn expand_matches_the_library_over_many_blocks() {
        let info: &[&[u8]] = &[b"tls13 ", b"quic key", &[0x00]];
        for hash in [HashAlgorithm::Sha256, HashAlgorithm::Sha384] {
            let prk = [0x5a; MAX_HASH_LEN];
            let prk = &prk[..hash.output_len()];
            for len in [
                0,
                1,
                hash.output_len(),
                3 * hash.output_len() + 7,
                255 * hash.output_len(),
            ] {
                let mut expected = vec![0; len];
                library_expand(hash, prk, info, &mut expected);
                let mut output = vec![0; len];
                AwsLcBackend
                    .hkdf_expand(hash, prk, info, &mut output)
                    .unwrap();
                assert_eq!(output, expected, "{hash:?} {len}");
            }
        }
    }

    #[test]
    fn expand_takes_a_prk_longer_than_the_library_does() {
        // HMAC hashes a key longer than its block, so a 200-byte PRK expands
        // like its SHA-256 digest.
        let prk = [0x5a; 200];
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &prk);
        let mut expected = [0; 80];
        library_expand(
            HashAlgorithm::Sha256,
            digest.as_ref(),
            &[b"info"],
            &mut expected,
        );
        let mut output = [0; 80];
        AwsLcBackend
            .hkdf_expand(HashAlgorithm::Sha256, &prk, &[b"info"], &mut output)
            .unwrap();
        assert_eq!(output, expected);
    }
}
