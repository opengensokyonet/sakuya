//! The cryptographic operations packet protection is built from.
//!
//! [`CryptoBackend`] supplies HKDF, AEAD keys and header protection ciphers.
//! Everything else in this crate — Initial secrets, key derivation, key
//! updates, header protection, payload protection and the Retry integrity
//! tag — uses cryptography only through it.

use snafu::{Snafu, ensure};

#[cfg(feature = "ring")]
pub mod ring;

/// Length in bytes of the authentication tag of every supported AEAD.
pub const AEAD_TAG_LEN: usize = 16;

/// Length in bytes of the nonce of every supported AEAD.
pub const AEAD_NONCE_LEN: usize = 12;

/// Length in bytes of the ciphertext sample header protection takes.
pub const HEADER_PROTECTION_SAMPLE_LEN: usize = 16;

/// Length in bytes of a header protection mask: one byte for the first header
/// byte and up to four for the packet number.
pub const HEADER_PROTECTION_MASK_LEN: usize = 5;

/// Largest hash output of a supported KDF, in bytes.
pub(crate) const MAX_HASH_LEN: usize = 48;

/// Largest key of a supported AEAD or header protection cipher, in bytes.
pub(crate) const MAX_KEY_LEN: usize = 32;

/// An AEAD algorithm that QUIC v1 packet protection can use.
///
/// The algorithm also selects the header protection cipher: AES-ECB with the
/// same key size for the AES-GCM algorithms, raw ChaCha20 for
/// ChaCha20-Poly1305 (RFC 9001 §5.4.3, §5.4.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AeadAlgorithm {
    /// `AEAD_AES_128_GCM`.
    Aes128Gcm,
    /// `AEAD_AES_256_GCM`.
    Aes256Gcm,
    /// `AEAD_CHACHA20_POLY1305`.
    ChaCha20Poly1305,
}

impl AeadAlgorithm {
    /// Length in bytes of the packet protection key, which is also the length
    /// of the header protection key.
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }
}

/// The HKDF hash that the TLS cipher suite selects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KdfAlgorithm {
    /// HKDF with SHA-256.
    HkdfSha256,
    /// HKDF with SHA-384.
    HkdfSha384,
}

impl KdfAlgorithm {
    /// Length in bytes of the hash output, which is also the length of every
    /// secret derived with this KDF.
    pub const fn hash_len(self) -> usize {
        match self {
            Self::HkdfSha256 => 32,
            Self::HkdfSha384 => 48,
        }
    }
}

/// A provider of the cryptographic operations packet protection needs.
///
/// Methods with byte-length preconditions are called by this crate only with
/// lengths that satisfy them; an implementation may panic when they are
/// violated.
pub trait CryptoBackend {
    /// An AEAD key ready for sealing and opening.
    type AeadKey: AeadKey;

    /// A header protection cipher ready for computing masks.
    type HeaderProtectionCipher: HeaderProtectionCipher;

    /// Writes HKDF-Extract(`salt`, `ikm`) into `prk` (RFC 5869 §2.2).
    ///
    /// Precondition: `prk.len()` equals `kdf.hash_len()`.
    fn hkdf_extract(&self, kdf: KdfAlgorithm, salt: &[u8], ikm: &[u8], prk: &mut [u8]);

    /// Fills `output` with HKDF-Expand(`prk`, info, `output.len()`) (RFC 5869
    /// §2.3), where info is the concatenation of the `info` pieces.
    ///
    /// Preconditions: `prk.len()` is at least `kdf.hash_len()`, and
    /// `output.len()` is at most 255 times `kdf.hash_len()`.
    fn hkdf_expand(&self, kdf: KdfAlgorithm, prk: &[u8], info: &[&[u8]], output: &mut [u8]);

    /// Fills `output` with HKDF-Expand-Label(`secret`, `label`, `context`,
    /// `output.len()`) from RFC 8446 §7.1, prefixing `label` with `"tls13 "`.
    ///
    /// The provided implementation checks the lengths and calls
    /// [`hkdf_expand`](Self::hkdf_expand); a backend with its own
    /// Expand-Label may override it with the same contract.
    ///
    /// Precondition: `secret.len()` is at least `kdf.hash_len()`.
    ///
    /// # Errors
    ///
    /// Fails without writing `output` when the prefixed label or the context
    /// exceeds 255 bytes, or when `output` exceeds 255 times
    /// `kdf.hash_len()`.
    fn hkdf_expand_label(
        &self,
        kdf: KdfAlgorithm,
        secret: &[u8],
        label: &[u8],
        context: &[u8],
        output: &mut [u8],
    ) -> Result<(), ExpandLabelError> {
        const PREFIX: &[u8] = b"tls13 ";
        let label_len = PREFIX.len() + label.len();
        ensure!(
            label_len <= 255,
            expand_label_error::LabelTooLongSnafu { label_len }
        );
        ensure!(
            context.len() <= 255,
            expand_label_error::ContextTooLongSnafu {
                context_len: context.len()
            }
        );
        let max_output_len = 255 * kdf.hash_len();
        ensure!(
            output.len() <= max_output_len,
            expand_label_error::OutputTooLongSnafu {
                output_len: output.len(),
                max_output_len,
            }
        );
        // The checks above bound every value to its field width.
        let (length, label_len, context_len) =
            (output.len() as u16, label_len as u8, context.len() as u8);
        let length = length.to_be_bytes();
        self.hkdf_expand(
            kdf,
            secret,
            &[
                &length,
                &[label_len],
                PREFIX,
                label,
                &[context_len],
                context,
            ],
            output,
        );
        Ok(())
    }

    /// Creates an AEAD key from `key`.
    ///
    /// Precondition: `key.len()` equals `aead.key_len()`.
    fn aead_key(&self, aead: AeadAlgorithm, key: &[u8]) -> Self::AeadKey;

    /// Creates the header protection cipher that `aead` selects, keyed with
    /// `key`.
    ///
    /// Precondition: `key.len()` equals `aead.key_len()`.
    fn header_protection_cipher(
        &self,
        aead: AeadAlgorithm,
        key: &[u8],
    ) -> Self::HeaderProtectionCipher;
}

/// An AEAD key that seals and opens in place with a detached tag.
pub trait AeadKey {
    /// Encrypts `in_out` in place, authenticating it together with `aad`, and
    /// writes the authentication tag into `tag`.
    ///
    /// Precondition: `in_out` is no longer than a QUIC packet can be.
    fn seal_in_place(
        &self,
        nonce: &[u8; AEAD_NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &mut [u8; AEAD_TAG_LEN],
    );

    /// Decrypts `in_out` in place after checking `tag` over `aad` and the
    /// ciphertext.
    ///
    /// # Errors
    ///
    /// Fails when authentication fails. The contents of `in_out` are then
    /// unspecified: an implementation may leave the ciphertext, partly
    /// decrypted data or zeros there.
    fn open_in_place(
        &self,
        nonce: &[u8; AEAD_NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &[u8; AEAD_TAG_LEN],
    ) -> Result<(), AuthenticationFailed>;
}

/// A header protection cipher (RFC 9001 §5.4.3, §5.4.4).
pub trait HeaderProtectionCipher {
    /// Computes the mask for a ciphertext `sample`.
    fn mask(&self, sample: &[u8; HEADER_PROTECTION_SAMPLE_LEN])
    -> [u8; HEADER_PROTECTION_MASK_LEN];
}

/// The error returned by [`CryptoBackend::hkdf_expand_label`].
#[derive(Debug, Snafu)]
#[snafu(module(expand_label_error))]
pub enum ExpandLabelError {
    /// The label with its `"tls13 "` prefix does not fit its one-byte length.
    #[snafu(display("label of {label_len} bytes with its prefix exceeds 255 bytes"))]
    LabelTooLong {
        /// Length of the prefixed label.
        label_len: usize,
    },
    /// The context does not fit its one-byte length.
    #[snafu(display("context of {context_len} bytes exceeds 255 bytes"))]
    ContextTooLong {
        /// Length of the context.
        context_len: usize,
    },
    /// HKDF-Expand cannot produce that much output.
    #[snafu(display("output of {output_len} bytes exceeds the {max_output_len}-byte limit"))]
    OutputTooLong {
        /// Requested output length.
        output_len: usize,
        /// Largest output the KDF can produce.
        max_output_len: usize,
    },
}

/// AEAD authentication failed: the tag does not match the ciphertext and the
/// associated data under this key and nonce.
#[derive(Debug, Snafu)]
#[snafu(display("AEAD authentication failed"))]
pub struct AuthenticationFailed;
