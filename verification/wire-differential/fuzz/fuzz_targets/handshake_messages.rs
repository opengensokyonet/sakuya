//! Fuzzes the TLS handshake message readers of `sakuya_tls`.
//!
//! The input is the byte stream of one encryption level. The target
//! collects one message from it with `read_handshake_message`, under the
//! default limits and under a limit just below the stated length, and
//! compares the outcome with a model of the header (RFC 9846 §4): a type
//! QUIC does not carry, or Finished before the hash is known, is
//! unexpected_message; a length above the limit fails with only the header
//! consumed; a stream that ends within the message is decode_error. A
//! collected message is then read by the reader of its type, which must
//! take all of it and must not answer unexpected_message.
//!
//! Every reader also runs on the input directly, with each hash length for
//! Finished and message_hash and each form for Certificate. For each read:
//!
//! - the `&[u8]` and `Bytes` sources agree: both succeed and take the same
//!   bytes, or both fail with the same error and alert;
//! - a message read is written back byte for byte, `encoded_len` is the
//!   length written, and the written bytes read back to an equal value, from
//!   both sources; the value read from `Bytes`, written and read from a byte
//!   slice, equals the value read from the byte slice;
//! - a failure answers decode_error, illegal_parameter or
//!   unexpected_message (RFC 9846 §6), and unexpected_message exactly when
//!   the type byte is not the reader's;
//! - the header bounds the read: a message stated longer than the input is
//!   decode_error, and a success takes exactly the stated length.
#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use sakuya_tls::{
    alert::AlertDescription,
    cipher_suite::CipherSuite,
    message::{
        HandshakeType, MessageLimit, MessageLimits, ReceivedMessageType,
        certificate::{
            CertificateFormat, CertificateList,
            codec::{read_certificate, write_certificate},
        },
        certificate_request::codec::{read_certificate_request, write_certificate_request},
        certificate_verify::codec::{read_certificate_verify, write_certificate_verify},
        client_hello::codec::{read_client_hello, write_client_hello},
        codec::{ReadHandshakeMessageError, ReadHandshakeMessageHostExt as _},
        encrypted_extensions::codec::{read_encrypted_extensions, write_encrypted_extensions},
        finished::codec::{read_finished, write_finished},
        message_hash::codec::{read_message_hash, write_message_hash},
        new_session_ticket::codec::{read_new_session_ticket, write_new_session_ticket},
        server_hello::{
            ServerHelloMessage,
            codec::{read_server_hello_message, write_hello_retry_request, write_server_hello},
        },
    },
};

/// The suites whose hashes cover every hash length: SHA-256 and SHA-384.
const SUITES: [CipherSuite; 2] = [
    CipherSuite::TLS_AES_128_GCM_SHA256,
    CipherSuite::TLS_AES_256_GCM_SHA384,
];

/// The alerts a reader may answer for a message it cannot accept: the two
/// generic parse alerts and the alert for a message of the wrong type
/// (RFC 9846 §6, §6.2).
const READ_ALERTS: [AlertDescription; 3] = [
    AlertDescription::DECODE_ERROR,
    AlertDescription::ILLEGAL_PARAMETER,
    AlertDescription::UNEXPECTED_MESSAGE,
];

/// The outcome of one reader on some input: the bytes it took, or the
/// alert it answered.
type Outcome = Result<usize, AlertDescription>;

/// The length of the whole message the header of `input` states, if
/// `input` holds a header.
fn stated_len(input: &[u8]) -> Option<usize> {
    let header = input.get(..4)?;
    Some(4 + u32::from_be_bytes([0, header[1], header[2], header[3]]) as usize)
}

/// Runs a reader on `input` from a byte slice and from `Bytes`, checks that
/// the two agree, and checks every read message against its writer.
///
/// `$write` takes the output vector and a value read, writes the value and
/// returns its `encoded_len`.
macro_rules! read_both {
    (
        $input:expr,
        $read:ident($($argument:expr),*),
        |$out:ident, $value:ident| $write:expr
    ) => {{
        let input: &[u8] = $input;
        let mut borrowed_source = input;
        let borrowed = $read(&mut borrowed_source $(, $argument)*);
        let mut shared_source = Bytes::copy_from_slice(input);
        let shared = $read(&mut shared_source $(, $argument)*);
        let outcome: Outcome = match (borrowed, shared) {
            (Ok(borrowed), Ok(shared)) => {
                let taken = input.len() - borrowed_source.len();
                assert_eq!(
                    taken,
                    input.len() - shared_source.len(),
                    "sources took different lengths"
                );
                let message = &input[..taken];
                let mut borrowed_written = Vec::new();
                let borrowed_len = {
                    let $out = &mut borrowed_written;
                    let $value = &borrowed;
                    $write
                };
                assert_eq!(borrowed_written, message, "not written back byte for byte");
                assert_eq!(borrowed_len, borrowed_written.len(), "encoded_len");
                let mut shared_written = Vec::new();
                let shared_len = {
                    let $out = &mut shared_written;
                    let $value = &shared;
                    $write
                };
                assert_eq!(shared_written, message, "not written back byte for byte");
                assert_eq!(shared_len, shared_written.len(), "encoded_len");
                // The written bytes read back to the same value, from both
                // sources; the value read from `Bytes` reads back from a
                // slice as the value read from the slice.
                let mut again = borrowed_written.as_slice();
                let reread = $read(&mut again $(, $argument)*)
                    .expect("a written message reads back");
                assert!(again.is_empty(), "a written message reads back whole");
                assert_eq!(reread, borrowed);
                let mut again = shared_written.as_slice();
                let reread = $read(&mut again $(, $argument)*)
                    .expect("a written message reads back");
                assert_eq!(reread, borrowed, "sources read different values");
                let mut again = Bytes::from(shared_written);
                let reread = $read(&mut again $(, $argument)*)
                    .expect("a written message reads back");
                assert!(again.is_empty(), "a written message reads back whole");
                assert_eq!(reread, shared);
                Ok(taken)
            }
            (Err(borrowed), Err(shared)) => {
                assert_eq!(
                    format!("{borrowed:?}"),
                    format!("{shared:?}"),
                    "sources failed differently"
                );
                assert_eq!(borrowed.alert(), shared.alert());
                Err(borrowed.alert())
            }
            (borrowed, shared) => panic!(
                "sources disagree: {:?} from a slice, {:?} from Bytes",
                borrowed.map(|_| ()),
                shared.map(|_| ())
            ),
        };
        outcome
    }};
}

fn client_hello(input: &[u8]) -> Outcome {
    read_both!(input, read_client_hello(), |out, hello| {
        write_client_hello(out, hello);
        hello.encoded_len()
    })
}

fn server_hello(input: &[u8]) -> Outcome {
    read_both!(input, read_server_hello_message(), |out, hello| {
        match hello {
            ServerHelloMessage::ServerHello(hello) => {
                write_server_hello(out, hello);
                hello.encoded_len()
            }
            ServerHelloMessage::HelloRetryRequest(retry) => {
                write_hello_retry_request(out, retry);
                retry.encoded_len()
            }
        }
    })
}

fn encrypted_extensions(input: &[u8]) -> Outcome {
    read_both!(input, read_encrypted_extensions(), |out, message| {
        write_encrypted_extensions(out, message);
        message.encoded_len()
    })
}

fn certificate_request(input: &[u8]) -> Outcome {
    read_both!(input, read_certificate_request(), |out, request| {
        write_certificate_request(out, request);
        request.encoded_len()
    })
}

fn certificate(input: &[u8], format: CertificateFormat) -> Outcome {
    read_both!(input, read_certificate(format), |out, certificate| {
        assert_eq!(certificate.certificates().format(), format);
        if let CertificateList::RawPublicKey(_) = certificate.certificates() {
            assert!(certificate.certificates().entries().len() <= 1);
        }
        write_certificate(out, certificate);
        certificate.encoded_len()
    })
}

/// Reads a Certificate in both forms. The forms differ only in that a raw
/// public key list holds at most one entry (RFC 9846 §4.4.2).
fn certificates(input: &[u8]) -> [Outcome; 2] {
    let x509 = certificate(input, CertificateFormat::X509);
    let raw = certificate(input, CertificateFormat::RawPublicKey);
    match (x509, raw) {
        (Ok(x509), Ok(raw)) => assert_eq!(x509, raw),
        (Ok(_), Err(alert)) => {
            assert_eq!(alert, AlertDescription::ILLEGAL_PARAMETER);
            let mut source = input;
            let read = read_certificate(&mut source, CertificateFormat::X509).unwrap();
            assert!(read.certificates().entries().len() > 1);
        }
        (Err(_), Ok(_)) => panic!("a raw public key reads where X.509 does not"),
        (Err(x509), Err(raw)) => assert_eq!(x509, raw),
    }
    [x509, raw]
}

fn certificate_verify(input: &[u8]) -> Outcome {
    read_both!(input, read_certificate_verify(), |out, verify| {
        write_certificate_verify(out, verify);
        verify.encoded_len()
    })
}

/// Reads a Finished whose verify_data is as long as the hash of `suite`.
fn finished(input: &[u8], suite: CipherSuite) -> Outcome {
    let hash = suite.hash().unwrap();
    let outcome = read_both!(input, read_finished(hash), |out, finished| {
        assert_eq!(
            finished.verify_data().as_bytes(),
            &input[4..][..hash.output_len()]
        );
        write_finished(out, finished);
        finished.encoded_len()
    });
    check_fixed(input, HandshakeType::FINISHED, hash.output_len(), outcome);
    outcome
}

fn new_session_ticket(input: &[u8]) -> Outcome {
    read_both!(input, read_new_session_ticket(), |out, ticket| {
        write_new_session_ticket(out, ticket);
        ticket.encoded_len()
    })
}

/// Reads a message_hash whose body is a hash of the hash of `suite`.
fn message_hash(input: &[u8], suite: CipherSuite) -> Outcome {
    let hash = suite.hash().unwrap();
    let outcome = read_both!(input, read_message_hash(hash), |out, message| {
        assert_eq!(message.hash().as_bytes(), &input[4..][..hash.output_len()]);
        write_message_hash(out, message);
        message.encoded_len()
    });
    check_fixed(
        input,
        HandshakeType::MESSAGE_HASH,
        hash.output_len(),
        outcome,
    );
    outcome
}

/// Checks a reader of a message whose body is exactly `len` bytes: it reads
/// exactly the inputs of its type that start with such a message.
fn check_fixed(input: &[u8], expected: HandshakeType, len: usize, outcome: Outcome) {
    let reads = input.first() == Some(&expected.get())
        && stated_len(input) == Some(4 + len)
        && input.len() >= 4 + len;
    match reads {
        true => assert_eq!(outcome, Ok(4 + len)),
        false => assert!(outcome.is_err(), "{outcome:?}"),
    }
}

/// Checks the outcome of the reader of `expected` on `input` against the
/// header of `input`.
fn check_header(input: &[u8], expected: HandshakeType, outcome: Outcome) {
    if let Err(alert) = outcome {
        assert!(READ_ALERTS.contains(&alert), "{alert:?}");
    }
    match input.first() {
        None => assert_eq!(outcome, Err(AlertDescription::DECODE_ERROR)),
        Some(&found) if found != expected.get() => {
            assert_eq!(outcome, Err(AlertDescription::UNEXPECTED_MESSAGE));
        }
        Some(_) => match stated_len(input) {
            Some(len) if len <= input.len() => match outcome {
                Ok(taken) => assert_eq!(taken, len),
                Err(alert) => assert_ne!(alert, AlertDescription::UNEXPECTED_MESSAGE),
            },
            _ => assert_eq!(outcome, Err(AlertDescription::DECODE_ERROR)),
        },
    }
}

/// Runs the readers of a message of type `message_type` on `input`, with
/// the hash of `suite` for Finished, and returns their outcomes.
fn read_as(message_type: HandshakeType, input: &[u8], suite: Option<CipherSuite>) -> Vec<Outcome> {
    match message_type {
        HandshakeType::CLIENT_HELLO => vec![client_hello(input)],
        HandshakeType::SERVER_HELLO => vec![server_hello(input)],
        HandshakeType::ENCRYPTED_EXTENSIONS => vec![encrypted_extensions(input)],
        HandshakeType::CERTIFICATE_REQUEST => vec![certificate_request(input)],
        HandshakeType::CERTIFICATE => certificates(input).to_vec(),
        HandshakeType::CERTIFICATE_VERIFY => vec![certificate_verify(input)],
        HandshakeType::FINISHED => vec![finished(input, suite.unwrap())],
        HandshakeType::NEW_SESSION_TICKET => vec![new_session_ticket(input)],
        other => panic!("{other:?} is not collected"),
    }
}

/// Runs every reader on `input` directly.
fn read_directly(input: &[u8]) {
    for (message_type, outcome) in [
        (HandshakeType::CLIENT_HELLO, client_hello(input)),
        (HandshakeType::SERVER_HELLO, server_hello(input)),
        (
            HandshakeType::ENCRYPTED_EXTENSIONS,
            encrypted_extensions(input),
        ),
        (
            HandshakeType::CERTIFICATE_REQUEST,
            certificate_request(input),
        ),
        (HandshakeType::CERTIFICATE_VERIFY, certificate_verify(input)),
        (HandshakeType::NEW_SESSION_TICKET, new_session_ticket(input)),
    ] {
        check_header(input, message_type, outcome);
    }
    for outcome in certificates(input) {
        check_header(input, HandshakeType::CERTIFICATE, outcome);
    }
    for suite in SUITES {
        check_header(input, HandshakeType::FINISHED, finished(input, suite));
        check_header(
            input,
            HandshakeType::MESSAGE_HASH,
            message_hash(input, suite),
        );
    }
}

/// What collecting a message from `input` must produce, by RFC 9846 §4 and
/// the documented limits.
#[derive(Debug, PartialEq, Eq)]
enum Collected {
    /// The whole message, of this many bytes.
    Message(usize),
    /// A type that is not received, or Finished without a hash.
    Unexpected,
    /// A length above the limit.
    TooLong { len: u32, limit: u32 },
    /// The stream ends within the header or the body.
    Truncated,
}

/// The limit of `limits` on a message of type `message_type`, with
/// `hash_len` the length of the hash, if known: `None` for a type QUIC does
/// not carry in CRYPTO frames (RFC 9001 §6, §8.3), and for Finished without
/// a hash.
fn model_limit(limits: &MessageLimits, message_type: u8, hash_len: Option<usize>) -> Option<u32> {
    Some(match message_type {
        1 => limits.client_hello.get(),
        2 => limits.server_hello.get(),
        4 => limits.new_session_ticket.get(),
        8 => limits.encrypted_extensions.get(),
        11 => limits.certificate.get(),
        13 => limits.certificate_request.get(),
        15 => limits.certificate_verify.get(),
        20 => hash_len? as u32,
        _ => return None,
    })
}

fn model_collect(input: &[u8], limits: &MessageLimits, hash_len: Option<usize>) -> Collected {
    let Some(total) = stated_len(input) else {
        return Collected::Truncated;
    };
    let len = (total - 4) as u32;
    let Some(limit) = model_limit(limits, input[0], hash_len) else {
        return Collected::Unexpected;
    };
    if len > limit {
        return Collected::TooLong { len, limit };
    }
    if input.len() < total {
        return Collected::Truncated;
    }
    Collected::Message(total)
}

/// Collects a message from `input` under `limits` and the hash of `suite`,
/// checks the outcome against the model, and reads a collected message
/// with the readers of its type.
fn collect(input: &[u8], limits: MessageLimits, suite: Option<CipherSuite>) {
    let hash = suite.map(|suite| suite.hash().unwrap());
    let mut source = input;
    let result = source.sync_read_handshake_message_unpin(limits, hash);
    let expected = model_collect(input, &limits, hash.map(|hash| hash.output_len()));
    let actual = match &result {
        Ok(message) => Collected::Message(message.encoded().len()),
        Err(ReadHandshakeMessageError::Unexpected { source }) => {
            assert_eq!(source.message_type().get(), input[0]);
            Collected::Unexpected
        }
        Err(ReadHandshakeMessageError::TooLong { source }) => {
            assert_eq!(source.message_type().handshake_type().get(), input[0]);
            assert_eq!(
                ReceivedMessageType::new(HandshakeType::new(input[0])),
                Some(source.message_type())
            );
            Collected::TooLong {
                len: source.length(),
                limit: source.limit(),
            }
        }
        Err(ReadHandshakeMessageError::Header { .. } | ReadHandshakeMessageError::Body { .. }) => {
            Collected::Truncated
        }
    };
    assert_eq!(actual, expected, "{result:?}");
    match &result {
        Ok(message) => {
            assert_eq!(source.len(), input.len() - message.encoded().len());
            assert_eq!(
                message.encoded().as_ref(),
                &input[..message.encoded().len()]
            );
            assert_eq!(message.handshake_type().get(), input[0]);
        }
        Err(error) => {
            assert!(error.host_error().is_none());
            let alert = error.alert();
            let expected_alert = match actual {
                Collected::Unexpected => AlertDescription::UNEXPECTED_MESSAGE,
                Collected::TooLong { .. } => AlertDescription::ILLEGAL_PARAMETER,
                Collected::Truncated => AlertDescription::DECODE_ERROR,
                Collected::Message(_) => unreachable!(),
            };
            assert_eq!(alert, expected_alert);
        }
    }
    if let Collected::TooLong { .. } = actual {
        // The limit fails before the body is read: only the header is taken.
        assert_eq!(source.len(), input.len() - 4, "the body was read");
    }
    let Ok(message) = result else {
        return;
    };
    let encoded = message.encoded().as_ref();
    for outcome in read_as(message.handshake_type(), encoded, suite) {
        match outcome {
            Ok(taken) => assert_eq!(taken, encoded.len()),
            Err(alert) => {
                assert!(READ_ALERTS.contains(&alert), "{alert:?}");
                assert_ne!(alert, AlertDescription::UNEXPECTED_MESSAGE);
            }
        }
    }
}

/// The default limits with the limit of the type of `input` just below the
/// length its header states, if that type has a limit of its own and the
/// length is not zero.
fn tight_limits(input: &[u8]) -> Option<MessageLimits> {
    let len = (stated_len(input)? - 4) as u32;
    let limit = MessageLimit::new(len.checked_sub(1)?).unwrap();
    let mut limits = MessageLimits::default();
    match input[0] {
        1 => limits.client_hello = limit,
        2 => limits.server_hello = limit,
        4 => limits.new_session_ticket = limit,
        8 => limits.encrypted_extensions = limit,
        11 => limits.certificate = limit,
        13 => limits.certificate_request = limit,
        15 => limits.certificate_verify = limit,
        _ => return None,
    }
    Some(limits)
}

fuzz_target!(|input: &[u8]| {
    for suite in [None, Some(SUITES[0]), Some(SUITES[1])] {
        collect(input, MessageLimits::default(), suite);
    }
    if let Some(limits) = tight_limits(input) {
        // Above the limit, with the body there and with only the header.
        collect(input, limits, None);
        collect(&input[..4], limits, None);
    }
    read_directly(input);
});
