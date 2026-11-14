//! The Retry Integrity Tag ([RFC 9001 §5.8]): sakuya against the rustls
//! based implementation of quinn-proto, which computes the tag in its server
//! configuration and checks it in a client session.
//!
//! [RFC 9001 §5.8]: https://www.rfc-editor.org/rfc/rfc9001.html#section-5.8
use quinn_proto::{
    ConnectionId as QCid,
    crypto::{
        ClientConfig as _, ServerConfig as _, Session,
        rustls::{QuicClientConfig, QuicServerConfig},
    },
    transport_parameters::TransportParameters,
};
use rustls::{
    DigitallySignedStruct, Error, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, ring::default_provider},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
    version::TLS13,
};
use sakuya_packet_protection::{
    backend::ring::RingBackend,
    retry::{compute_retry_integrity_tag, verify_retry_integrity_tag},
};
use sakuya_wire::connection_id::ConnectionId;
use std::sync::Arc;

/// A certificate resolver without certificates: the server configuration
/// only computes Retry tags and never handshakes.
#[derive(Debug)]
struct NoCertificate;

impl ResolvesServerCert for NoCertificate {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        None
    }
}

/// A verifier that refuses every certificate: the client session only
/// checks Retry tags and never handshakes.
#[derive(Debug)]
struct RefuseCertificates;

impl ServerCertVerifier for RefuseCertificates {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Err(Error::General("no certificate is trusted".into()))
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("no certificate is trusted".into()))
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("no certificate is trusted".into()))
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(default_provider())
}

/// quinn-proto's Retry tag computation and check, for QUIC version 1.
pub struct QuinnRetry {
    server: QuicServerConfig,
    client: Box<dyn Session>,
}

impl QuinnRetry {
    pub fn new() -> Self {
        let server = rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(NoCertificate));
        let client = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(RefuseCertificates))
            .with_no_client_auth();
        let client = Arc::new(QuicClientConfig::try_from(client).unwrap())
            .start_session(1, "server.invalid", &TransportParameters::default())
            .unwrap();
        Self {
            server: QuicServerConfig::try_from(server).unwrap(),
            client,
        }
    }

    /// The tag of `retry_without_tag` for `odcid`.
    pub fn tag(&self, odcid: &[u8], retry_without_tag: &[u8]) -> [u8; 16] {
        self.server
            .retry_tag(1, &QCid::new(odcid), retry_without_tag)
    }

    /// Whether `retry` ends with the tag for `odcid`. quinn-proto takes the
    /// packet as the header and the payload after it; `header_len` says
    /// where to split.
    pub fn is_valid(&self, odcid: &[u8], retry: &[u8], header_len: usize) -> bool {
        let (header, payload) = retry.split_at(header_len.min(retry.len()));
        self.client
            .is_valid_retry(&QCid::new(odcid), header, payload)
    }
}

impl Default for QuinnRetry {
    fn default() -> Self {
        Self::new()
    }
}

pub fn tag_sakuya(odcid: &[u8], retry_without_tag: &[u8]) -> [u8; 16] {
    compute_retry_integrity_tag(
        &RingBackend,
        &ConnectionId::new(odcid).unwrap(),
        retry_without_tag,
    )
}

pub fn is_valid_sakuya(odcid: &[u8], retry: &[u8]) -> bool {
    verify_retry_integrity_tag(&RingBackend, &ConnectionId::new(odcid).unwrap(), retry).is_ok()
}
