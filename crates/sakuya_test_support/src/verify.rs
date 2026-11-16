//! A certificate verifier for test roots.
//!
//! Test certificates, such as those of [`pki`](crate::pki) or the ones an
//! interop runner hands out, are issued by a root of their own and carry no
//! SCTs, so the default composition, which requires Certificate
//! Transparency, refuses them. [`TestRootsVerifier`] is
//! [`WebPkiVerifier`] with [`NoTransparencyCheck`] in the place of the CT
//! policy: the path to one of the given roots, the validity, the purpose,
//! the name and the signatures are checked as usual; revocation is not
//! checked and no key is distrusted.
//!
//! It is only for tests and test programs. A production client trusting an
//! internal CA lets that CA through the CT policy explicitly instead.

use core::convert::Infallible;

use rustls_pki_types::pem::{self, PemObject as _, SectionKind};
use sakuya_tls::verify::{
    AnchorStore, InvalidAnchorError, NoRevocationCheck, SpkiDistrustList, Transparency,
    WebPkiVerifier,
};
use snafu::{ResultExt as _, Snafu};
use time::UtcDateTime;

/// A CT check that lets every certificate through.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct NoTransparencyCheck;

impl<C> Transparency<C> for NoTransparencyCheck {
    type Error = Infallible;

    fn check(&self, _: &C, _: &[u8], _: &[u8], _: UtcDateTime) -> Result<(), Infallible> {
        Ok(())
    }
}

/// A verifier of server certificates issued under test roots, on the
/// backend `C` and the clock `K`: CT and revocation are not checked.
pub type TestRootsVerifier<C, K> =
    WebPkiVerifier<C, AnchorStore, SpkiDistrustList, NoRevocationCheck, NoTransparencyCheck, K>;

/// The verifier that trusts `roots` alone, on `backend` and `clock`.
pub fn test_roots_verifier<C, K>(
    backend: C,
    roots: AnchorStore,
    clock: K,
) -> TestRootsVerifier<C, K> {
    WebPkiVerifier::new(
        backend,
        roots,
        SpkiDistrustList::default(),
        NoRevocationCheck,
        NoTransparencyCheck,
        clock,
    )
}

/// The roots in `roots_pem`, PEM text such as the contents of a `ca.pem`
/// file: each CERTIFICATE section is one root; other sections are skipped.
///
/// # Errors
///
/// [`RootsFromPemError`].
pub fn roots_from_pem(roots_pem: &[u8]) -> Result<AnchorStore, RootsFromPemError> {
    let mut roots = Vec::new();
    for section in <(SectionKind, Vec<u8>)>::pem_slice_iter(roots_pem) {
        let (kind, der) = section.context(MalformedSnafu)?;
        if kind == SectionKind::Certificate {
            roots.push(der);
        }
    }
    if roots.is_empty() {
        return EmptySnafu.fail();
    }
    AnchorStore::from_certificates(roots.iter().map(Vec::as_slice)).context(InvalidRootSnafu)
}

/// PEM text cannot give the roots of a [`TestRootsVerifier`].
#[derive(Debug, Snafu)]
pub enum RootsFromPemError {
    /// The text is not valid PEM.
    #[snafu(display("malformed PEM"))]
    Malformed {
        /// The PEM reader's failure.
        source: pem::Error,
    },
    /// The text has no CERTIFICATE section.
    #[snafu(display("no certificate in PEM"))]
    Empty,
    /// A certificate cannot be read as a root.
    #[snafu(display("root certificate invalid"))]
    InvalidRoot {
        /// Which certificate, and why.
        source: InvalidAnchorError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki;
    use bytes::Bytes;
    use nitori_crypto_aws_lc::AwsLcBackend;
    use sakuya_tls::{
        client::ServerTarget, clock::SystemClock, message::certificate::CertificateEntry,
        verify::VerifyCertificateChainError,
    };

    fn chain(leaf: Vec<u8>) -> Vec<CertificateEntry<Bytes>> {
        vec![CertificateEntry::new(Bytes::from(leaf), Vec::new()).unwrap()]
    }

    fn target(name: &str) -> ServerTarget {
        ServerTarget::from_host_name(name).unwrap()
    }

    fn verifier(root_seed: u8) -> TestRootsVerifier<AwsLcBackend, SystemClock> {
        let roots = AnchorStore::from_certificates([pki::root(root_seed).as_slice()]).unwrap();
        test_roots_verifier(AwsLcBackend, roots, SystemClock)
    }

    #[test]
    fn a_leaf_without_scts_under_a_trusted_root_verifies() {
        let verified = verifier(1).verify_now(
            &target("example.com"),
            &chain(pki::leaf(2, 1, "example.com")),
        );
        assert!(verified.is_ok(), "{verified:?}");
    }

    #[test]
    fn a_leaf_under_another_root_is_refused() {
        let verified = verifier(1).verify_now(
            &target("example.com"),
            &chain(pki::leaf(2, 3, "example.com")),
        );
        assert!(matches!(
            verified,
            Err(VerifyCertificateChainError::Path { .. })
        ));
    }

    #[test]
    fn a_leaf_for_another_name_is_refused() {
        let verified = verifier(1).verify_now(
            &target("example.org"),
            &chain(pki::leaf(2, 1, "example.com")),
        );
        assert!(matches!(
            verified,
            Err(VerifyCertificateChainError::Name { .. })
        ));
    }

    fn base64(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for group in bytes.chunks(3) {
            let n = group
                .iter()
                .enumerate()
                .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
            for i in 0..4 {
                if i <= group.len() {
                    out.push(DIGITS[(n >> (18 - 6 * i) & 63) as usize].into());
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    fn pem(label: &str, der: &[u8]) -> String {
        let body: Vec<String> = base64(der)
            .as_bytes()
            .chunks(64)
            .map(|line| String::from_utf8(line.to_vec()).unwrap())
            .collect();
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            body.join("\n")
        )
    }

    #[test]
    fn roots_in_pem_are_the_certificate_sections() {
        let text = pem("PRIVATE KEY", b"not a root") + &pem("CERTIFICATE", &pki::root(1));
        let roots = roots_from_pem(text.as_bytes()).unwrap();
        let verified = test_roots_verifier(AwsLcBackend, roots, SystemClock).verify_now(
            &target("example.com"),
            &chain(pki::leaf(2, 1, "example.com")),
        );
        assert!(verified.is_ok(), "{verified:?}");
    }

    #[test]
    fn pem_without_a_certificate_gives_no_roots() {
        let text = pem("PRIVATE KEY", b"not a root");
        assert!(matches!(
            roots_from_pem(text.as_bytes()),
            Err(RootsFromPemError::Empty)
        ));
    }

    #[test]
    fn a_certificate_section_that_is_no_root_is_refused() {
        let text = pem("CERTIFICATE", b"not a certificate");
        assert!(matches!(
            roots_from_pem(text.as_bytes()),
            Err(RootsFromPemError::InvalidRoot { .. })
        ));
    }
}
