//! Whether a server asks the client for a certificate.
//!
//! A server that authenticates with a certificate may send a
//! CertificateRequest, and then reads the client's Certificate and
//! CertificateVerify before its Finished (RFC 8446 §4.3.2, §4.4.2).
//! [`PeerAuthentication::request`] decides for the selected target.
//!
//! [`NoClientCertificate`] never asks. Its request is of a type with no
//! values, so the handshake's code for client certificates is never
//! reached.

use crate::server::targets::Selected;
use core::convert::Infallible;

/// How a server decides whether to ask for a client certificate.
///
/// `T` is the type of the selected target.
pub trait PeerAuthentication<T> {
    /// What a CertificateRequest asks for.
    type Request;

    /// The request for `selected`, or `None` to ask for no certificate.
    fn request(&self, selected: &Selected<T>) -> Option<Self::Request>;
}

/// Asks no client for a certificate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct NoClientCertificate;

impl<T> PeerAuthentication<T> for NoClientCertificate {
    type Request = Infallible;

    fn request(&self, _selected: &Selected<T>) -> Option<Infallible> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{NoClientCertificate, PeerAuthentication};
    use crate::server::targets::Selected;

    #[test]
    fn no_certificate_is_asked_for() {
        let selected = Selected {
            target: (),
            application_protocol: None,
        };
        assert!(NoClientCertificate.request(&selected).is_none());
    }
}
