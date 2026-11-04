//! TLS 1.3 cipher suites (RFC 8446 §B.4).
//!
//! A cipher suite names the AEAD algorithm that protects records, in QUIC
//! packets, and the hash used for the transcript and HKDF.

use crate::code_point::code_point;
use nitori_crypto::HashAlgorithm;
use sakuya_packet_protection::backend::AeadAlgorithm;

code_point! {
    /// A CipherSuite code point.
    ///
    /// Any two-byte value is a code point; the readers keep suites they do
    /// not know, which a server ignores (RFC 8446 §9.3).
    CipherSuite(u16);
    /// TLS_AES_128_GCM_SHA256.
    TLS_AES_128_GCM_SHA256 = 0x1301 => "TLS_AES_128_GCM_SHA256",
    /// TLS_AES_256_GCM_SHA384.
    TLS_AES_256_GCM_SHA384 = 0x1302 => "TLS_AES_256_GCM_SHA384",
    /// TLS_CHACHA20_POLY1305_SHA256.
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
    /// TLS_AES_128_CCM_SHA256.
    TLS_AES_128_CCM_SHA256 = 0x1304 => "TLS_AES_128_CCM_SHA256",
    /// TLS_AES_128_CCM_8_SHA256, which QUIC does not use (RFC 9001 §5.3).
    TLS_AES_128_CCM_8_SHA256 = 0x1305 => "TLS_AES_128_CCM_8_SHA256",
}

impl CipherSuite {
    /// The hash of a TLS 1.3 suite, or `None` for a suite this crate does
    /// not name.
    pub const fn hash(self) -> Option<HashAlgorithm> {
        match self {
            Self::TLS_AES_128_GCM_SHA256
            | Self::TLS_CHACHA20_POLY1305_SHA256
            | Self::TLS_AES_128_CCM_SHA256
            | Self::TLS_AES_128_CCM_8_SHA256 => Some(HashAlgorithm::Sha256),
            Self::TLS_AES_256_GCM_SHA384 => Some(HashAlgorithm::Sha384),
            _ => None,
        }
    }

    /// The AEAD algorithm of the suite as packet protection provides it, or
    /// `None` for a suite whose AEAD it does not provide, the CCM suites
    /// among them.
    pub const fn aead(self) -> Option<AeadAlgorithm> {
        match self {
            Self::TLS_AES_128_GCM_SHA256 => Some(AeadAlgorithm::Aes128Gcm),
            Self::TLS_AES_256_GCM_SHA384 => Some(AeadAlgorithm::Aes256Gcm),
            Self::TLS_CHACHA20_POLY1305_SHA256 => Some(AeadAlgorithm::ChaCha20Poly1305),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CipherSuite;
    use nitori_crypto::HashAlgorithm;
    use sakuya_packet_protection::backend::AeadAlgorithm;

    #[test]
    fn suites_map_to_their_hash_and_aead() {
        let suite = CipherSuite::TLS_AES_256_GCM_SHA384;
        assert_eq!(suite.hash(), Some(HashAlgorithm::Sha384));
        assert_eq!(suite.aead(), Some(AeadAlgorithm::Aes256Gcm));
        let ccm = CipherSuite::TLS_AES_128_CCM_SHA256;
        assert_eq!(
            (ccm.hash(), ccm.aead()),
            (Some(HashAlgorithm::Sha256), None)
        );
        assert_eq!(CipherSuite::new(0x1306).hash(), None);
        assert_eq!(
            format!("{:?}", CipherSuite::TLS_AES_128_GCM_SHA256),
            "CipherSuite(TLS_AES_128_GCM_SHA256, 0x1301)"
        );
        assert_eq!(
            format!("{:?}", CipherSuite::new(0x0a0a)),
            "CipherSuite(0xa0a)"
        );
    }
}
