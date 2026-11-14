//! How much the connection has used its AEAD (RFC 9001 §6.6).

use sakuya_packet_protection::backend::AeadAlgorithm;
use snafu::Snafu;

/// The two counts the limits on AEAD usage are checked against: the packets
/// sealed with the current sending generation of the 1-RTT keys, and the
/// packets of the connection, at every level and with every key, that
/// failed authentication.
///
/// Both change with almost every packet, so they are a component of their
/// own: nothing is looked at again for them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AeadUsage {
    sealed_with_current: u64,
    failed_authentication: u64,
}

impl AeadUsage {
    /// Nothing sealed, nothing failed.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many packets were sealed with the current sending generation.
    pub fn sealed_with_current(&self) -> u64 {
        self.sealed_with_current
    }

    /// How many packets of the connection failed authentication.
    pub fn failed_authentication(&self) -> u64 {
        self.failed_authentication
    }

    /// A packet was sealed with the current sending generation.
    pub fn sealed(&mut self) {
        self.sealed_with_current = self.sealed_with_current.saturating_add(1);
    }

    /// The sending generation changed: nothing is sealed with the new one
    /// yet.
    pub(crate) fn send_keys_updated(&mut self) {
        self.sealed_with_current = 0;
    }

    /// A packet whose keys are for `aead` failed authentication.
    ///
    /// # Errors
    ///
    /// The count of failed packets exceeds the integrity limit of `aead`:
    /// the connection is to close at once and process no more packets.
    pub fn authentication_failed(
        &mut self,
        aead: AeadAlgorithm,
    ) -> Result<(), AeadLimitReachedError> {
        self.failed_authentication = self.failed_authentication.saturating_add(1);
        if self.failed_authentication > integrity_limit(aead) {
            Err(AeadLimitReachedError::IntegrityLimitExceeded { aead })
        } else {
            Ok(())
        }
    }

    /// The counts after `sealed` packets were sealed with the current
    /// sending generation, as the tests start from.
    #[cfg(test)]
    pub(crate) fn having_sealed(sealed: u64) -> Self {
        Self {
            sealed_with_current: sealed,
            failed_authentication: 0,
        }
    }

    /// Whether the packets sealed with the current sending generation have
    /// reached three quarters of the confidentiality limit of `aead`, where
    /// this side initiates a key update. Never for ChaCha20-Poly1305, whose
    /// limit is beyond the number of packets.
    pub fn update_due(&self, aead: AeadAlgorithm) -> bool {
        confidentiality_limit(aead).is_some_and(|limit| self.sealed_with_current >= limit / 4 * 3)
    }

    /// Whether the packets sealed with the current sending generation have
    /// reached the confidentiality limit of `aead`: no more may be sealed
    /// with it. Never for ChaCha20-Poly1305.
    pub fn confidentiality_limit_reached(&self, aead: AeadAlgorithm) -> bool {
        confidentiality_limit(aead).is_some_and(|limit| self.sealed_with_current >= limit)
    }
}

/// How many packets may be sealed with one key of `aead`; `None` for
/// ChaCha20-Poly1305, whose limit is greater than the number of possible
/// packets (RFC 9001 §6.6).
fn confidentiality_limit(aead: AeadAlgorithm) -> Option<u64> {
    match aead {
        AeadAlgorithm::Aes128Gcm | AeadAlgorithm::Aes256Gcm => Some(1 << 23),
        AeadAlgorithm::ChaCha20Poly1305 => None,
    }
}

/// How many packets of a connection may fail authentication with `aead`
/// (RFC 9001 §6.6).
fn integrity_limit(aead: AeadAlgorithm) -> u64 {
    match aead {
        AeadAlgorithm::Aes128Gcm | AeadAlgorithm::Aes256Gcm => 1 << 52,
        AeadAlgorithm::ChaCha20Poly1305 => 1 << 36,
    }
}

/// The connection reached a limit of RFC 9001 §6.6 on the use of its AEAD.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum AeadLimitReachedError {
    /// More packets failed authentication than the integrity limit of the
    /// AEAD allows.
    #[snafu(display("more packets failed authentication than {aead:?} allows"))]
    IntegrityLimitExceeded {
        /// The AEAD of the keys of the packet that crossed the limit.
        aead: AeadAlgorithm,
    },
    /// As many packets were sealed with the current sending generation of
    /// the 1-RTT keys as the confidentiality limit of their AEAD allows,
    /// and no key update may be initiated yet: the handshake is not
    /// confirmed, or the peer has not acknowledged a packet sealed with the
    /// current generation (RFC 9001 §6.1).
    #[snafu(display(
        "as many packets were sealed with the current keys as their AEAD allows, \
         and no key update may be initiated"
    ))]
    ConfidentialityLimitReached,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failure_past_the_integrity_limit_is_an_error() {
        let mut usage = AeadUsage::new();
        assert!(
            usage
                .authentication_failed(AeadAlgorithm::Aes128Gcm)
                .is_ok()
        );
        assert_eq!(usage.failed_authentication(), 1);
        let mut usage = AeadUsage {
            failed_authentication: 1 << 36,
            ..AeadUsage::new()
        };
        // the limit of AES-GCM is far above
        let mut copy = usage;
        assert!(copy.authentication_failed(AeadAlgorithm::Aes256Gcm).is_ok());
        assert!(matches!(
            usage.authentication_failed(AeadAlgorithm::ChaCha20Poly1305),
            Err(AeadLimitReachedError::IntegrityLimitExceeded {
                aead: AeadAlgorithm::ChaCha20Poly1305
            })
        ));
        let mut usage = AeadUsage {
            failed_authentication: (1 << 52) - 1,
            ..AeadUsage::new()
        };
        assert!(
            usage
                .authentication_failed(AeadAlgorithm::Aes128Gcm)
                .is_ok()
        );
        assert!(
            usage
                .authentication_failed(AeadAlgorithm::Aes128Gcm)
                .is_err()
        );
    }

    #[test]
    fn an_update_is_due_at_three_quarters_of_the_confidentiality_limit() {
        let mut usage = AeadUsage {
            sealed_with_current: 3 << 21,
            ..AeadUsage::new()
        };
        assert!(usage.update_due(AeadAlgorithm::Aes128Gcm));
        assert!(!usage.confidentiality_limit_reached(AeadAlgorithm::Aes128Gcm));
        assert!(!usage.update_due(AeadAlgorithm::ChaCha20Poly1305));
        usage.sealed_with_current = (3 << 21) - 1;
        assert!(!usage.update_due(AeadAlgorithm::Aes256Gcm));
        usage.sealed_with_current = (1 << 23) - 1;
        usage.sealed();
        assert!(usage.confidentiality_limit_reached(AeadAlgorithm::Aes256Gcm));
        assert!(!usage.confidentiality_limit_reached(AeadAlgorithm::ChaCha20Poly1305));
        usage.send_keys_updated();
        assert_eq!(usage.sealed_with_current(), 0);
    }
}
