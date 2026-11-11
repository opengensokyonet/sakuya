//! Every handshake message of RFC 8448 §3, §4 and §5, and the
//! CertificateRequest of §6, reads and writes back byte for byte, from a
//! byte slice and from `Bytes`.
#![feature(impl_trait_in_assoc_type, yield_expr)]

mod common;

use bytes::Bytes;
use common::{hex, rfc8448::*};
use nitori_crypto::{Digest, Hash as _, HashAlgorithm, NamedGroup, RunningHash as _};
use nitori_crypto_aws_lc::AwsLcBackend;
use sakuya_tls::{
    cipher_suite::CipherSuite,
    extension::{ExtensionType, psk_key_exchange_modes::PskKeyExchangeMode},
    message::{
        certificate::{
            CertificateFormat, CertificateList,
            codec::{ReadCertificateHostExt as _, WriteCertificateHostExt as _},
        },
        certificate_request::codec::{
            ReadCertificateRequestHostExt as _, WriteCertificateRequestHostExt as _,
        },
        certificate_verify::codec::{
            ReadCertificateVerifyHostExt as _, WriteCertificateVerifyHostExt as _,
        },
        client_hello::{
            ClientHelloExtension,
            codec::{ReadClientHelloHostExt as _, WriteClientHelloHostExt as _},
        },
        encrypted_extensions::{
            EncryptedExtensionsExtension,
            codec::{ReadEncryptedExtensionsHostExt as _, WriteEncryptedExtensionsHostExt as _},
        },
        finished::codec::{ReadFinishedHostExt as _, WriteFinishedHostExt as _},
        message_hash::{
            MessageHash,
            codec::{ReadMessageHashHostExt as _, WriteMessageHashHostExt as _},
        },
        new_session_ticket::codec::{
            ReadNewSessionTicketHostExt as _, WriteNewSessionTicketHostExt as _,
        },
        server_hello::{
            ServerHelloMessage,
            codec::{
                ReadServerHelloMessageHostExt as _, WriteHelloRetryRequestHostExt as _,
                WriteServerHelloHostExt as _,
            },
        },
    },
    version::ProtocolVersion,
};

/// Reads `message` with `read` from a byte slice and from `Bytes`, writes
/// both values back with `write`, checks the bytes, and returns the value
/// read from `Bytes`.
macro_rules! round_trip {
    ($message:expr, $read:ident, $write:ident $(, $argument:expr)*) => {{
        let bytes = hex($message);
        let mut input = bytes.as_slice();
        let borrowed = input.$read($($argument),*).unwrap();
        assert!(input.is_empty());
        let mut output = Vec::new();
        output.$write(&borrowed).unwrap();
        assert_eq!(output, bytes);
        let mut input = Bytes::from(bytes.clone());
        let shared = input.$read($($argument),*).unwrap();
        assert!(input.is_empty());
        let mut output = Vec::new();
        output.$write(&shared).unwrap();
        assert_eq!(output, bytes);
        assert_eq!(shared.encoded_len(), bytes.len());
        shared
    }};
}

#[test]
fn client_hellos() {
    for message in [
        s3::CLIENT_HELLO,
        s4::CLIENT_HELLO,
        s5::CLIENT_HELLO_1,
        s5::CLIENT_HELLO_2,
    ] {
        round_trip!(
            message,
            sync_read_client_hello_unpin,
            sync_write_client_hello_unpin
        );
    }
}

#[test]
fn client_hello_fields() {
    let hello = round_trip!(
        s3::CLIENT_HELLO,
        sync_read_client_hello_unpin,
        sync_write_client_hello_unpin
    );
    assert_eq!(hello.legacy_version(), ProtocolVersion::TLS_1_2);
    assert!(hello.legacy_session_id().as_bytes().is_empty());
    assert_eq!(
        hello.cipher_suites().as_slice(),
        [
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_AES_256_GCM_SHA384,
        ]
    );
    let shares = hello.key_share().unwrap().entries();
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].group(), NamedGroup::X25519);
    assert_eq!(shares[0].key_exchange().as_ref(), hex(s3::CLIENT_PUBLIC));
    let extensions = hello.extensions();
    let ClientHelloExtension::ServerName(name) = &extensions[0] else {
        panic!()
    };
    assert_eq!(name.host_name().as_ref(), b"server");
    // renegotiation_info, session_ticket and record_size_limit are kept as
    // they are.
    let unknown: Vec<_> = extensions
        .iter()
        .filter_map(|extension| match extension {
            ClientHelloExtension::Unknown(extension) => Some(extension.extension_type()),
            _ => None,
        })
        .collect();
    assert_eq!(
        unknown,
        [
            ExtensionType::new(0xff01),
            ExtensionType::new(0x23),
            ExtensionType::new(0x1c)
        ]
    );
    assert!(extensions.iter().any(|extension| matches!(
        extension,
        ClientHelloExtension::SupportedVersions(list) if list.as_slice() == [ProtocolVersion::TLS_1_3]
    )));
    assert!(extensions.iter().any(|extension| matches!(
        extension,
        ClientHelloExtension::PskKeyExchangeModes(list)
            if list.as_slice() == [PskKeyExchangeMode::PSK_DHE_KE]
    )));
    assert_eq!(hello.binders_len(), None);
}

#[test]
fn client_hello_binders() {
    let hello = round_trip!(
        s4::CLIENT_HELLO,
        sync_read_client_hello_unpin,
        sync_write_client_hello_unpin
    );
    let offered = hello.pre_shared_key().unwrap();
    assert_eq!(offered.identities().len(), 1);
    assert_eq!(offered.identities()[0].obfuscated_ticket_age(), 0xfad6aacb);
    assert_eq!(offered.binders()[0].binder().as_ref(), hex(s4::BINDER));
    assert!(
        hello
            .extensions()
            .iter()
            .any(|extension| matches!(extension, ClientHelloExtension::EarlyData))
    );
    // The binder covers the ClientHello without the binders.
    let bytes = hex(s4::CLIENT_HELLO);
    let truncated = bytes.len() - hello.binders_len().unwrap();
    assert_eq!(bytes[..truncated], hex(s4::CLIENT_HELLO_PREFIX));
}

#[test]
fn server_hellos() {
    for message in [
        s3::SERVER_HELLO,
        s4::SERVER_HELLO,
        s5::SERVER_HELLO,
        s5::HELLO_RETRY_REQUEST,
    ] {
        let bytes = hex(message);
        for value in [
            bytes
                .as_slice()
                .sync_read_server_hello_message_unpin()
                .map(|_| ()),
            Bytes::from(bytes.clone())
                .sync_read_server_hello_message_unpin()
                .map(|_| ()),
        ] {
            value.unwrap();
        }
        let hello = Bytes::from(bytes.clone())
            .sync_read_server_hello_message_unpin()
            .unwrap();
        let mut output = Vec::new();
        match &hello {
            ServerHelloMessage::ServerHello(hello) => {
                output.sync_write_server_hello_unpin(hello).unwrap();
                assert_eq!(hello.encoded_len(), bytes.len());
            }
            ServerHelloMessage::HelloRetryRequest(retry) => {
                output.sync_write_hello_retry_request_unpin(retry).unwrap();
                assert_eq!(retry.encoded_len(), bytes.len());
            }
        }
        assert_eq!(output, bytes);
    }
}

#[test]
fn server_hello_fields() {
    let hello = hex(s3::SERVER_HELLO)
        .as_slice()
        .sync_read_server_hello_message_unpin()
        .map(|hello| match hello {
            ServerHelloMessage::ServerHello(hello) => (
                hello.cipher_suite(),
                hello.supported_versions(),
                hello.pre_shared_key(),
                hello.key_share().unwrap().key_exchange().to_vec(),
            ),
            ServerHelloMessage::HelloRetryRequest(_) => panic!(),
        })
        .unwrap();
    assert_eq!(
        hello,
        (
            CipherSuite::TLS_AES_128_GCM_SHA256,
            Some(ProtocolVersion::TLS_1_3),
            None,
            hex(s3::SERVER_PUBLIC)
        )
    );
    let resumed = Bytes::from(hex(s4::SERVER_HELLO))
        .sync_read_server_hello_message_unpin()
        .unwrap();
    let ServerHelloMessage::ServerHello(resumed) = resumed else {
        panic!()
    };
    assert_eq!(resumed.pre_shared_key().map(|index| index.get()), Some(0));
    let retry = Bytes::from(hex(s5::HELLO_RETRY_REQUEST))
        .sync_read_server_hello_message_unpin()
        .unwrap();
    let ServerHelloMessage::HelloRetryRequest(retry) = retry else {
        panic!()
    };
    assert_eq!(retry.key_share(), Some(NamedGroup::SECP256R1));
    assert_eq!(retry.cookie().unwrap().cookie().len(), 0x72);
}

#[test]
fn encrypted_extensions() {
    for message in [
        s3::ENCRYPTED_EXTENSIONS,
        s4::ENCRYPTED_EXTENSIONS,
        s5::ENCRYPTED_EXTENSIONS,
    ] {
        round_trip!(
            message,
            sync_read_encrypted_extensions_unpin,
            sync_write_encrypted_extensions_unpin
        );
    }
    let message = round_trip!(
        s4::ENCRYPTED_EXTENSIONS,
        sync_read_encrypted_extensions_unpin,
        sync_write_encrypted_extensions_unpin
    );
    assert!(
        message
            .extensions()
            .iter()
            .any(|extension| matches!(extension, EncryptedExtensionsExtension::EarlyData))
    );
    assert!(
        message
            .extensions()
            .iter()
            .any(|extension| matches!(extension, EncryptedExtensionsExtension::ServerName))
    );
}

#[test]
fn certificates() {
    for message in [s3::CERTIFICATE, s5::CERTIFICATE] {
        let certificate = round_trip!(
            message,
            sync_read_certificate_unpin,
            sync_write_certificate_unpin,
            CertificateFormat::X509
        );
        let CertificateList::X509(entries) = certificate.certificates() else {
            panic!()
        };
        assert_eq!(entries.len(), 1);
        assert!(entries[0].extensions().is_empty());
        // The certificate is DER: a SEQUENCE.
        assert_eq!(entries[0].data()[0], 0x30);
    }
}

#[test]
fn certificate_verifies() {
    for message in [s3::CERTIFICATE_VERIFY, s5::CERTIFICATE_VERIFY] {
        let verify = round_trip!(
            message,
            sync_read_certificate_verify_unpin,
            sync_write_certificate_verify_unpin
        );
        assert_eq!(
            verify.algorithm(),
            nitori_crypto::SignatureScheme::RSA_PSS_RSAE_SHA256
        );
        assert_eq!(verify.signature().len(), 128);
    }
}

#[test]
fn finished_messages() {
    for message in [
        s3::SERVER_FINISHED,
        s3::CLIENT_FINISHED,
        s4::SERVER_FINISHED,
        s4::CLIENT_FINISHED,
        s5::SERVER_FINISHED,
        s5::CLIENT_FINISHED,
    ] {
        round_trip!(
            message,
            sync_read_finished_unpin,
            sync_write_finished_unpin,
            HashAlgorithm::Sha256
        );
    }
    let finished = hex(s3::SERVER_FINISHED)
        .as_slice()
        .sync_read_finished_unpin(HashAlgorithm::Sha256)
        .unwrap();
    assert_eq!(
        finished.verify_data().as_bytes(),
        hex(s3::SERVER_VERIFY_DATA)
    );
}

#[test]
fn new_session_ticket() {
    let ticket = round_trip!(
        s3::NEW_SESSION_TICKET,
        sync_read_new_session_ticket_unpin,
        sync_write_new_session_ticket_unpin
    );
    assert_eq!(ticket.ticket_lifetime().seconds(), 30);
    assert_eq!(ticket.ticket_nonce().nonce().as_ref(), [0, 0]);
    assert_eq!(ticket.ticket().len(), 0xb2);
    assert_eq!(ticket.extensions().len(), 1);
}

#[test]
fn certificate_request() {
    let request = round_trip!(
        s6::CERTIFICATE_REQUEST,
        sync_read_certificate_request_unpin,
        sync_write_certificate_request_unpin
    );
    assert!(request.certificate_request_context().is_empty());
    assert_eq!(request.extensions().len(), 1);
}

#[test]
fn message_hash() {
    let backend = AwsLcBackend;
    let sha256 = backend.hash_algorithm(HashAlgorithm::Sha256).unwrap();
    let mut hash = nitori_crypto::Hash::start(&backend, sha256);
    hash.update(&hex(s5::CLIENT_HELLO_1));
    let message = MessageHash::new(hash.finish());
    let mut output = Vec::new();
    output.sync_write_message_hash_unpin(&message).unwrap();
    assert_eq!(output[..4], [254, 0, 0, 32]);
    assert_eq!(output.len(), message.encoded_len());
    let read = output
        .as_slice()
        .sync_read_message_hash_unpin(HashAlgorithm::Sha256)
        .unwrap();
    assert_eq!(read, message);
    let _: &Digest = read.hash();
}
