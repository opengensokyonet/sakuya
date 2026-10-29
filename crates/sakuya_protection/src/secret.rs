//! Traffic secrets and the key update derivation.

use snafu::{Snafu, ensure};

use crate::backend::{CryptoBackend, KdfAlgorithm, MAX_HASH_LEN};
use crate::wipe::wipe;

/// A TLS 1.3 traffic secret for one encryption level and one direction,
/// together with the KDF of the cipher suite that produced it.
///
/// The handshake engine hands traffic secrets over; Initial secrets come from
/// [`InitialSecrets`](crate::initial::InitialSecrets). Packet protection keys are
/// derived from a traffic secret with
/// [`PacketKey::derive`](crate::packet_key::PacketKey::derive) and
/// [`HeaderProtectionKey::derive`](crate::header_protection::HeaderProtectionKey::derive).
///
/// The secret bytes are overwritten when the value is dropped. `Debug` does
/// not print them.
pub struct TrafficSecret {
    kdf: KdfAlgorithm,
    bytes: [u8; MAX_HASH_LEN],
}

impl TrafficSecret {
    /// Takes a copy of `secret`, which was derived with `kdf`.
    ///
    /// # Errors
    ///
    /// Fails when `secret` is not exactly `kdf.hash_len()` bytes long.
    pub fn new(kdf: KdfAlgorithm, secret: &[u8]) -> Result<Self, SecretLengthMismatch> {
        let expected = kdf.hash_len();
        ensure!(
            secret.len() == expected,
            SecretLengthMismatchSnafu {
                expected,
                actual: secret.len()
            }
        );
        let mut bytes = [0; MAX_HASH_LEN];
        bytes[..expected].copy_from_slice(secret);
        Ok(Self { kdf, bytes })
    }

    /// The KDF this secret was derived with, which every derivation from it
    /// uses.
    pub fn kdf(&self) -> KdfAlgorithm {
        self.kdf
    }

    /// The secret bytes, `self.kdf().hash_len()` of them.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.kdf.hash_len()]
    }

    /// Derives the traffic secret of the next key phase with the
    /// `"quic ku"` label (RFC 9001 §6.1).
    ///
    /// The header protection key does not change in a key update; only the
    /// packet protection key is derived again, from the returned secret.
    pub fn next<B: CryptoBackend>(&self, backend: &B) -> Self {
        let mut next = Self::zeroed(self.kdf);
        self.expand_label(backend, b"quic ku", next.bytes_mut());
        next
    }

    /// Fills `output` with HKDF-Expand-Label(self, `label`, "",
    /// `output.len()`).
    ///
    /// Callers pass labels and lengths fixed by RFC 9001, which are within the
    /// limits of Expand-Label.
    pub(crate) fn expand_label<B: CryptoBackend>(
        &self,
        backend: &B,
        label: &[u8],
        output: &mut [u8],
    ) {
        backend
            .hkdf_expand_label(self.kdf, self.as_bytes(), label, &[], output)
            .expect("RFC 9001 labels and lengths are within the Expand-Label limits");
    }

    /// An all-zero secret for `kdf`, to be filled through
    /// [`bytes_mut`](Self::bytes_mut).
    pub(crate) fn zeroed(kdf: KdfAlgorithm) -> Self {
        Self {
            kdf,
            bytes: [0; MAX_HASH_LEN],
        }
    }

    /// The secret bytes, writable, `self.kdf().hash_len()` of them.
    pub(crate) fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.kdf.hash_len()]
    }
}

impl Drop for TrafficSecret {
    fn drop(&mut self) {
        wipe(&mut self.bytes);
    }
}

impl core::fmt::Debug for TrafficSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TrafficSecret")
            .field("kdf", &self.kdf)
            .finish_non_exhaustive()
    }
}

/// A secret's length does not match the hash length of its KDF.
#[derive(Debug, Snafu)]
#[snafu(display("expected a {expected}-byte secret, got {actual} bytes"))]
pub struct SecretLengthMismatch {
    /// The hash length of the KDF.
    pub expected: usize,
    /// The length of the given secret.
    pub actual: usize,
}
