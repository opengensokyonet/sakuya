//! The client's certificate verifier: it takes the server's public key
//! from the leaf certificate and checks nothing else.
//!
//! The runner's `amplificationlimit` test case gives the server a chain of
//! nine certificates, deeper than rustls-webpki builds paths (six
//! intermediates at most, fixed), and it names that test case `transfer`
//! to the client, as it names the plain transfer: the client cannot tell
//! the two apart. So the client does not verify the server's chain in any
//! test case, as the interop clients of other implementations do not.
//! The handshake still verifies CertificateVerify with the key this hands
//! back, so the server proves it holds the leaf's private key; the path to
//! a root, the validity, the purpose and the name go unchecked.
//!
//! It is only for the interop program.

use core::future::{Ready, ready};

use bytes::Bytes;
use nitori_crypto_aws_lc::AwsLcBackend;
use rustls_pki_types::CertificateDer;
use sakuya_test_support::verify::test_roots_verifier;
use sakuya_tls::{
    alert::{AlertDescription, CallsForAlert},
    client::{ServerTarget, offering::VerifierSupport},
    clock::SystemClock,
    message::certificate::CertificateEntry,
    verify::{
        AnchorStore, CertificateVerifier, SubjectPublicKey, public_key::InvalidPublicKeyError,
    },
};
use snafu::{ResultExt as _, Snafu};
use webpki::EndEntityCert;

/// A verifier that hands back the public key of the server's leaf
/// certificate without verifying the chain; see the
/// [module documentation](self).
#[derive(Clone, Debug)]
pub(crate) struct LeafKeyVerifier {
    support: VerifierSupport,
}

impl LeafKeyVerifier {
    /// The verifier, accepting the signature schemes the default verifier
    /// accepts on the aws-lc backend.
    pub(crate) fn new() -> Self {
        Self {
            support: test_roots_verifier(AwsLcBackend, AnchorStore::default(), SystemClock)
                .support(),
        }
    }

    /// The public key of the first of `certificates`.
    fn leaf_key(
        certificates: &[CertificateEntry<Bytes>],
    ) -> Result<SubjectPublicKey, LeafKeyError> {
        let leaf = certificates.first().ok_or(LeafKeyError::NoCertificate)?;
        let der = CertificateDer::from(leaf.data().as_ref());
        let leaf = EndEntityCert::try_from(&der).context(CertificateSnafu)?;
        SubjectPublicKey::from_spki(leaf.subject_public_key_info().as_ref()).context(KeySnafu)
    }
}

impl CertificateVerifier for LeafKeyVerifier {
    type Error = LeafKeyError;
    type Verifying<'a> = Ready<Result<SubjectPublicKey, LeafKeyError>>;

    fn support(&self) -> VerifierSupport {
        self.support.clone()
    }

    fn verify<'a>(
        &'a self,
        _: &'a ServerTarget,
        certificates: &'a [CertificateEntry<Bytes>],
    ) -> Self::Verifying<'a> {
        ready(Self::leaf_key(certificates))
    }
}

/// The server's leaf certificate gives no public key.
#[derive(Debug, Snafu)]
pub(crate) enum LeafKeyError {
    /// The Certificate message has no certificate.
    #[snafu(display("server sent no certificate"))]
    NoCertificate,
    /// The leaf is not a certificate rustls-webpki reads.
    #[snafu(display("the leaf certificate cannot be read"))]
    Certificate {
        /// Why.
        source: webpki::Error,
    },
    /// The leaf's public key is not one the handshake verifies with.
    #[snafu(display("the leaf certificate's key is not supported"))]
    Key {
        /// Why.
        source: InvalidPublicKeyError,
    },
}

/// The alerts the default verifier sends for the same failures.
impl CallsForAlert for LeafKeyError {
    fn alert(&self) -> AlertDescription {
        match self {
            Self::NoCertificate => AlertDescription::DECODE_ERROR,
            Self::Certificate { .. } => AlertDescription::BAD_CERTIFICATE,
            Self::Key { .. } => AlertDescription::UNSUPPORTED_CERTIFICATE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sakuya_test_support::pki;

    fn chain(leaf: Vec<u8>) -> Vec<CertificateEntry<Bytes>> {
        vec![CertificateEntry::new(Bytes::from(leaf), Vec::new()).unwrap()]
    }

    fn target(name: &str) -> ServerTarget {
        ServerTarget::from_host_name(name).unwrap()
    }

    fn verify(certificates: &[CertificateEntry<Bytes>]) -> Result<SubjectPublicKey, LeafKeyError> {
        LeafKeyVerifier::leaf_key(certificates)
    }

    #[test]
    fn the_leaf_key_is_handed_back_whatever_the_root_and_the_name() {
        let leaf = pki::leaf(2, 1, "example.com");
        let key = verify(&chain(leaf.clone())).expect("the leaf's key");
        let der = CertificateDer::from(leaf.as_slice());
        let expected = SubjectPublicKey::from_spki(
            EndEntityCert::try_from(&der)
                .unwrap()
                .subject_public_key_info()
                .as_ref(),
        )
        .unwrap();
        assert_eq!(key, expected);
        // another name and a root nobody trusts change nothing
        let verifier = LeafKeyVerifier::new();
        let verified = futures_util::FutureExt::now_or_never(verifier.verify(
            &target("example.org"),
            &chain(pki::leaf(2, 3, "example.com")),
        ))
        .expect("ready");
        assert!(verified.is_ok(), "{verified:?}");
    }

    #[test]
    fn no_certificate_is_a_decode_error() {
        let error = verify(&[]).unwrap_err();
        assert!(matches!(error, LeafKeyError::NoCertificate));
        assert_eq!(error.alert(), AlertDescription::DECODE_ERROR);
    }

    #[test]
    fn a_leaf_that_is_no_certificate_is_a_bad_certificate() {
        let error = verify(&chain(b"not a certificate".to_vec())).unwrap_err();
        assert!(matches!(error, LeafKeyError::Certificate { .. }));
        assert_eq!(error.alert(), AlertDescription::BAD_CERTIFICATE);
    }
}
