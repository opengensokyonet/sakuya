//! The key update derivation, and the derivations from a traffic secret.
//!
//! The handshake hands over its traffic secrets as
//! [`nitori_tls::schedule::TrafficSecret`]; Initial secrets come from
//! [`InitialSecrets`](crate::initial::InitialSecrets). Packet protection keys
//! are derived from a traffic secret with
//! [`PacketKey::derive`](crate::packet_key::PacketKey::derive) and
//! [`HeaderProtectionKey::derive`](crate::header_protection::HeaderProtectionKey::derive).

use nitori_tls::schedule::TrafficSecret;

use crate::backend::CryptoBackend;

/// Derives the traffic secret of the next key phase from `secret` with the
/// `"quic ku"` label (RFC 9001 §6.1).
///
/// The header protection key does not change in a key update; only the
/// packet protection key is derived again, from the returned secret.
pub fn next_traffic_secret<B: CryptoBackend>(backend: &B, secret: &TrafficSecret) -> TrafficSecret {
    let mut next = TrafficSecret::zeroed(secret.hash());
    expand_label(backend, secret, b"quic ku", next.as_mut_bytes());
    next
}

/// Fills `output` with HKDF-Expand-Label(`secret`, `label`, "",
/// `output.len()`).
///
/// Callers pass a label fixed by RFC 9001 and an output of at most
/// `MAX_HASH_LEN` bytes.
pub(crate) fn expand_label<B: CryptoBackend>(
    backend: &B,
    secret: &TrafficSecret,
    label: &[u8],
    output: &mut [u8],
) {
    // invariant: the RFC 9001 labels are at most 7 bytes and the outputs
    // at most `MAX_HASH_LEN` bytes, within the 255-byte label limit and
    // the 255 × 32-byte output limit that Expand-Label checks.
    backend
        .hkdf_expand_label(secret.hash(), secret.as_bytes(), label, &[], output)
        .expect("RFC 9001 labels and lengths are within the Expand-Label limits");
}
