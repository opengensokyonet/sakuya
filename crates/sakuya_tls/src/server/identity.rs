//! What a server presents to authenticate with a certificate.
//!
//! A server sends its certificate chain in Certificate and signs the
//! transcript in CertificateVerify with the key of the leaf. The scheme of
//! that signature must be one the client offered in
//! `signature_algorithms` and fit the key; RSA signs with RSASSA-PSS, and
//! no scheme uses SHA-1 (RFC 8446 §4.4.3). [`Identity::present`] picks the
//! chain and the scheme for the selected target; the handshake computes
//! the content to sign, and the signature may wait.
//!
//! [`CertifiedKey`] presents one chain with one signing key.

use crate::{alert::AlertDescription, server::targets::Selected};
use bytes::Bytes;
use nitori_crypto::{SignatureScheme, SigningKey};
use snafu::Snafu;

/// How a server presents itself for a selected target.
///
/// `T` is the type of the selected target.
pub trait Identity<T> {
    /// The key that signs CertificateVerify.
    type Key: SigningKey;

    /// The chain and the scheme for `selected`, signing with a scheme of
    /// `offered`, the client's `signature_algorithms`.
    ///
    /// # Errors
    ///
    /// [`NoCommonSchemeError`] when the key signs with none of `offered`.
    fn present(
        &self,
        selected: &Selected<T>,
        offered: &[SignatureScheme],
    ) -> Result<Presented<'_, Self::Key>, NoCommonSchemeError>;
}

/// A certificate chain to send, with the key and scheme that sign
/// CertificateVerify.
#[derive(Debug)]
pub struct Presented<'a, K> {
    certificates: &'a [Bytes],
    key: &'a K,
    scheme: SignatureScheme,
}

impl<'a, K: SigningKey> Presented<'a, K> {
    /// The DER certificates, the leaf first.
    pub fn certificates(&self) -> &'a [Bytes] {
        self.certificates
    }

    /// The scheme CertificateVerify uses.
    pub fn scheme(&self) -> SignatureScheme {
        self.scheme
    }

    /// Signs `content`, the content of CertificateVerify, with the scheme.
    pub fn sign(&self, content: &'a [u8]) -> K::Signing<'a> {
        self.key.sign(self.scheme, content)
    }
}

/// The key signs with none of the schemes the client offered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("no offered signature scheme fits the key"))]
pub struct NoCommonSchemeError;

impl NoCommonSchemeError {
    /// The alert the failure calls for: handshake_failure.
    pub fn alert(&self) -> AlertDescription {
        AlertDescription::HANDSHAKE_FAILURE
    }
}

/// Schemes CertificateVerify does not use: RSASSA-PKCS1-v1_5 and SHA-1
/// (RFC 8446 §4.2.3, §4.4.3).
const NOT_FOR_CERTIFICATE_VERIFY: &[u16] = &[0x0201, 0x0203, 0x0401, 0x0501, 0x0601];

/// One certificate chain and the signing key of its leaf, for every
/// target.
///
/// The scheme is the first of the key's schemes, in the key's order, that
/// the client offered.
#[derive(Debug)]
pub struct CertifiedKey<K> {
    certificates: Vec<Bytes>,
    key: K,
}

impl<K> CertifiedKey<K> {
    /// The chain `certificates`, DER certificates with the leaf first, and
    /// `key`, the leaf's key.
    ///
    /// # Errors
    ///
    /// [`EmptyChainError`] when `certificates` is empty.
    pub fn new(certificates: Vec<Bytes>, key: K) -> Result<Self, EmptyChainError> {
        if certificates.is_empty() {
            return Err(EmptyChainError);
        }
        Ok(Self { certificates, key })
    }

    /// The certificates, the leaf first.
    pub fn certificates(&self) -> &[Bytes] {
        &self.certificates
    }

    /// The key.
    pub fn key(&self) -> &K {
        &self.key
    }
}

/// A [`CertifiedKey`] needs at least the leaf certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("certificate chain is empty"))]
pub struct EmptyChainError;

impl<K: SigningKey, T> Identity<T> for CertifiedKey<K> {
    type Key = K;

    fn present(
        &self,
        _selected: &Selected<T>,
        offered: &[SignatureScheme],
    ) -> Result<Presented<'_, K>, NoCommonSchemeError> {
        let scheme = self
            .key
            .schemes()
            .iter()
            .copied()
            .filter(|scheme| !NOT_FOR_CERTIFICATE_VERIFY.contains(&scheme.get()))
            .find(|scheme| offered.contains(scheme))
            .ok_or(NoCommonSchemeError)?;
        Ok(Presented {
            certificates: &self.certificates,
            key: &self.key,
            scheme,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{CertifiedKey, EmptyChainError, Identity, NoCommonSchemeError};
    use crate::{server::targets::Selected, test_support::ready_now};
    use bytes::Bytes;
    use core::{
        convert::Infallible,
        future::{Ready, ready},
    };
    use nitori_crypto::{Signature, SignatureScheme, SigningKey};

    /// A key that "signs" by echoing the scheme and the content.
    #[derive(Debug)]
    struct EchoKey(Vec<SignatureScheme>);

    impl SigningKey for EchoKey {
        type Error = Infallible;
        type Signing<'a> = Ready<Result<Signature, Infallible>>;

        fn schemes(&self) -> &[SignatureScheme] {
            &self.0
        }

        fn sign<'a>(&'a self, scheme: SignatureScheme, message: &'a [u8]) -> Self::Signing<'a> {
            let mut bytes = scheme.get().to_be_bytes().to_vec();
            bytes.extend_from_slice(message);
            ready(Ok(Signature::from_slice(&bytes)))
        }
    }

    fn selected() -> Selected<()> {
        Selected {
            target: (),
            application_protocol: None,
        }
    }

    fn identity(schemes: Vec<SignatureScheme>) -> CertifiedKey<EchoKey> {
        CertifiedKey::new(vec![Bytes::from_static(b"leaf")], EchoKey(schemes)).unwrap()
    }

    #[test]
    fn the_keys_first_offered_scheme_signs() {
        let identity = identity(vec![
            SignatureScheme::RSA_PSS_RSAE_SHA512,
            SignatureScheme::RSA_PSS_RSAE_SHA256,
        ]);
        let presented = identity
            .present(
                &selected(),
                &[
                    SignatureScheme::RSA_PSS_RSAE_SHA256,
                    SignatureScheme::RSA_PSS_RSAE_SHA512,
                ],
            )
            .unwrap();
        assert_eq!(presented.scheme(), SignatureScheme::RSA_PSS_RSAE_SHA512);
        assert_eq!(presented.certificates(), &[Bytes::from_static(b"leaf")]);
        let Ok(signature) = ready_now(presented.sign(b"content"));
        assert_eq!(signature.as_bytes(), b"\x08\x06content");
    }

    #[test]
    fn a_scheme_the_client_did_not_offer_or_pkcs1_is_not_used() {
        let identity = identity(vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_SECP256R1_SHA256,
        ]);
        let error = Identity::<()>::present(
            &identity,
            &selected(),
            &[SignatureScheme::RSA_PKCS1_SHA256, SignatureScheme::ED25519],
        )
        .unwrap_err();
        assert_eq!(error, NoCommonSchemeError);
        assert_eq!(
            error.alert(),
            crate::alert::AlertDescription::HANDSHAKE_FAILURE
        );
        assert_eq!(
            CertifiedKey::new(vec![], EchoKey(vec![])).unwrap_err(),
            EmptyChainError
        );
    }
}
