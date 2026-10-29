//! Initial secrets (RFC 9001 §5.2).

use crate::backend::{AeadAlgorithm, CryptoBackend, KdfAlgorithm, MAX_HASH_LEN};
use crate::secret::TrafficSecret;
use crate::wipe::wipe;

/// The QUIC version 1 salt from which Initial secrets are extracted.
pub const INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// The AEAD that protects Initial packets, `AEAD_AES_128_GCM`.
pub const INITIAL_AEAD: AeadAlgorithm = AeadAlgorithm::Aes128Gcm;

/// The KDF of the Initial secrets, HKDF with SHA-256.
const INITIAL_KDF: KdfAlgorithm = KdfAlgorithm::HkdfSha256;

/// The two Initial secrets of a connection, one per sending direction.
///
/// They are derived from public material: authenticating an Initial packet
/// with them proves neither the peer's identity nor that its address can
/// receive.
#[derive(Debug)]
pub struct InitialSecrets {
    /// The secret protecting packets the client sends (`"client in"`).
    pub client: TrafficSecret,
    /// The secret protecting packets the server sends (`"server in"`).
    pub server: TrafficSecret,
}

impl InitialSecrets {
    /// Derives both Initial secrets from `client_dcid`, the Destination
    /// Connection ID field of the client's first Initial packet, or of the
    /// first Initial it sends after a Retry.
    ///
    /// Any length is accepted; checking the length a connection ID may have
    /// belongs to the header parser. Both secrets use HKDF with SHA-256, and
    /// keys derived from them use [`INITIAL_AEAD`].
    pub fn derive<B: CryptoBackend>(backend: &B, client_dcid: &[u8]) -> Self {
        let len = INITIAL_KDF.hash_len();
        let mut initial_secret = [0; MAX_HASH_LEN];
        backend.hkdf_extract(
            INITIAL_KDF,
            &INITIAL_SALT,
            client_dcid,
            &mut initial_secret[..len],
        );
        let client = expand(backend, &initial_secret[..len], b"client in");
        let server = expand(backend, &initial_secret[..len], b"server in");
        wipe(&mut initial_secret);
        Self { client, server }
    }
}

fn expand<B: CryptoBackend>(backend: &B, initial_secret: &[u8], label: &[u8]) -> TrafficSecret {
    let mut secret = TrafficSecret::zeroed(INITIAL_KDF);
    backend
        .hkdf_expand_label(INITIAL_KDF, initial_secret, label, &[], secret.bytes_mut())
        .expect("Initial labels and lengths are within the Expand-Label limits");
    secret
}
