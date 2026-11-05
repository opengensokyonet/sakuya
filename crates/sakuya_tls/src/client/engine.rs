//! The client's handshake engine.
//!
//! [`client_handshake`] runs a TLS 1.3 handshake for a QUIC client
//! connecting to a [`ServerTarget`]. Like the server's engine, it owns the
//! backend and the client's capabilities and receives the connection's
//! receivers on every poll (see [`engine`](crate::engine)): the CRYPTO
//! streams and a [`ClientTransport`], which gives the client's transport
//! parameters and checks the server's.
//!
//! The handshake goes:
//!
//! 1. takes what to offer from the [`Offering`] and a ticket from the
//!    [`ClientTicketStore`], and writes the ClientHello at Initial, with the
//!    binder of the ticket; the hello names psk_dhe_ke with or without a
//!    ticket, for the server to send tickets; when it offers 0-RTT, it yields
//!    [`ClientHandshakeEvent::EarlyDataOffered`];
//! 2. reads the ServerHello, or a HelloRetryRequest, after which it writes
//!    the second ClientHello and reads the ServerHello; it yields
//!    [`ClientHandshakeEvent::ServerHelloRead`] and moves both streams to
//!    Handshake;
//! 3. reads EncryptedExtensions and hands the server's transport
//!    parameters to the connection;
//! 4. authenticates the server: with its certificate, verified by the
//!    [`CertificateVerifier`], and CertificateVerify, whose scheme must fit
//!    the certificate's key; or with the PSK the server accepted, keeping
//!    the identity the ticket recorded;
//! 5. reads the server's Finished, writes an empty Certificate when the
//!    server asked for one, and writes its own Finished: the handshake is
//!    complete, and it yields [`ClientHandshakeEvent::Completed`] and moves
//!    both streams to 1-RTT;
//! 6. keeps the tickets of the NewSessionTicket messages the server sends,
//!    for as long as the call runs; a ticket that allows 0-RTT with a
//!    max_early_data_size other than 0xffffffff ends the call with
//!    [`HandshakeError::ProtocolViolation`] (RFC 9001 §4.6.1).
//!
//! A failure ends the call with a [`HandshakeError`].
//!
//! `#[call]` and `#[capability]` generate the operation struct
//! [`ClientHandshake`], with a `new` constructor taking the arguments after
//! the receivers, and the extension traits `ClientHandshakeExt`,
//! `ClientTransportExt` and `ClientTransportViewExt`.

// The generated items have no documentation comments; the module
// documentation above describes them.
#![allow(missing_docs)]

use crate::{
    alert::{AlertDescription, CallsForAlert},
    cipher_suite::{CipherSuite, SupportedSuite},
    client::{
        ServerTarget,
        offering::{InvalidOfferError, Offer, OfferAttempt, Offering},
        ticket::{ClientTicketStore, StoredTicket},
    },
    clock::Clock,
    code_point::{ByteCodePointList, CodePointList},
    crypto::TlsCrypto,
    engine::{
        CryptoInput, CryptoInputExt as _, CryptoLevel, CryptoOutput, CryptoOutputExt as _,
        HandshakeError, MaxEarlyDataSizeError, encode, split_read, split_write,
    },
    extension::{
        OpaqueData,
        alpn::{ProtocolName, ProtocolNameList},
        cookie::Cookie,
        key_share::{ClientShares, KeyShareEntry},
        pre_shared_key::{
            InvalidOfferedPsksError, OfferedPsks, PskBinderEntry, PskIdentity, PskIndex,
        },
        psk_key_exchange_modes::PskKeyExchangeMode,
        server_name::ServerName,
    },
    message::{
        HandshakeMessage, HandshakeType, HelloRandom, LegacySessionId, MessageLimits,
        certificate::{
            Certificate, CertificateFormat, CertificateList,
            codec::{
                ReadCertificateError, ReadCertificateHostExt as _, WriteCertificateHostExt as _,
            },
        },
        certificate_request::codec::{
            ReadCertificateRequestError, ReadCertificateRequestHostExt as _,
        },
        certificate_verify::codec::ReadCertificateVerifyHostExt as _,
        client_hello::{
            ClientHello, ClientHelloExtension, InvalidClientHelloError,
            codec::WriteClientHelloHostExt as _,
        },
        codec::{ReadHandshakeMessageError, ReadHandshakeMessageExt as _},
        encrypted_extensions::{
            EncryptedExtensionsExtension,
            codec::{ReadEncryptedExtensionsError, ReadEncryptedExtensionsHostExt as _},
        },
        new_session_ticket::{
            NewSessionTicketExtension,
            codec::{ReadNewSessionTicketError, ReadNewSessionTicketHostExt as _},
        },
        server_hello::{
            HelloRetryRequestExtension, ServerHelloMessage,
            codec::{ReadServerHelloMessageError, ReadServerHelloMessageHostExt as _},
        },
    },
    role::Client,
    schedule::{
        Authentication, CertificateVerifyError, Exporter, FinishedError, HandshakeTrafficSecrets,
        OneRttTrafficSecrets, PskEarlySecret, ResumptionPsk, Transcript, UnofferedPskError,
        ZeroRttSendTrafficSecret,
    },
    vector::LengthOutOfRangeError,
    verify::{CertificateVerifier, SubjectPublicKey, public_key::SchemeKeyMismatchError},
    version::ProtocolVersion,
};
use bytes::Bytes;
use core::{convert::Infallible, pin::Pin};
use nitori_call::{LentAccess, ReceiverAccess, ReceiverFamily, call, capability};
use nitori_crypto::{
    CompleteError, HashAlgorithm, KeyExchange, KeyGenerationFailed, NamedGroup, Random,
    RandomError, Secret, SignatureScheme, StartedExchange, Supported,
};
use nitori_io::{Read, Write, calls::WriteAllExt as _, error::WriteZero};
use sakuya_packet_protection::backend::AeadAlgorithm;
use snafu::Snafu;

/// The connection's side of the transport parameters, as a client's
/// handshake asks for it.
#[capability]
pub trait ClientTransport: ReceiverFamily {
    /// A failure, such as TRANSPORT_PARAMETER_ERROR.
    type Error;

    /// The client's own transport parameters, for the ClientHello.
    fn local<'v>(view: Pin<&mut Self::ReceiverView<'v>>) -> OpaqueData<Bytes>
    where
        Self: 'v;

    /// Checks `peer`, the server's `quic_transport_parameters`, against
    /// what the connection sent and received, such as the connection IDs
    /// (RFC 9000 §7.3), and records them.
    ///
    /// # Errors
    ///
    /// As the implementation documents.
    fn peer<'v>(view: Pin<&mut Self::ReceiverView<'v>>, peer: &[u8]) -> Result<(), Self::Error>
    where
        Self: 'v;
}

/// The fixed choices of a client's handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientHandshakeSettings {
    /// The limits on the messages the client receives.
    pub limits: MessageLimits,
    /// Whether to offer 0-RTT when the ticket allows it.
    pub early_data: bool,
}

impl Default for ClientHandshakeSettings {
    fn default() -> Self {
        Self {
            limits: MessageLimits::default(),
            early_data: true,
        }
    }
}

/// Who the server is, as the client knows it once the handshake completes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerIdentity {
    /// The server authenticated in this handshake with the certificate of
    /// this key, verified for the target.
    Verified(SubjectPublicKey),
    /// The server authenticated with the PSK of a ticket; the identity is
    /// the one the connection of the ticket verified.
    Resumed(SubjectPublicKey),
}

/// What became of the 0-RTT a client offered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EarlyDataOutcome {
    /// The client did not offer 0-RTT.
    NotOffered,
    /// The server accepted it.
    Accepted,
    /// The server rejected it: the connection resets what it sent in 0-RTT
    /// (RFC 9001 §4.6.2).
    Rejected,
}

/// What a client's handshake hands over, in this order.
///
/// `C` is the backend.
pub enum ClientHandshakeEvent<C: TlsCrypto> {
    /// The ClientHello offering 0-RTT is written: the secret to send 0-RTT
    /// with, and what the ticket remembers of the server.
    #[doc(alias = "ZeroRttSendTrafficSecret")]
    EarlyDataOffered {
        /// The AEAD of the ticket's cipher suite.
        aead: AeadAlgorithm,
        /// The 0-RTT secret.
        secret: ZeroRttSendTrafficSecret,
        /// The server's transport parameters of the ticket's connection,
        /// which 0-RTT keeps to (RFC 9000 §7.4.1).
        transport_parameters: Bytes,
        /// The application protocol of the ticket's connection.
        application_protocol: Option<ProtocolName<Bytes>>,
    },
    /// The ServerHello is read: the Handshake traffic secrets. Both streams
    /// move to Handshake after this item.
    #[doc(alias = "HandshakeTrafficSecrets")]
    ServerHelloRead {
        /// The AEAD of the cipher suite, for every later secret.
        aead: AeadAlgorithm,
        /// The Handshake traffic secrets.
        secrets: HandshakeTrafficSecrets,
    },
    /// The server's Finished is verified and the client's written: the
    /// handshake is complete. Both streams move to 1-RTT after this item.
    Completed {
        /// The 1-RTT secrets.
        secrets: OneRttTrafficSecrets,
        /// The exporter of the connection.
        exporter: Exporter<C>,
        /// Who the server is.
        identity: ServerIdentity,
        /// The application protocol the server selected.
        application_protocol: Option<ProtocolName<Bytes>>,
        /// What became of 0-RTT.
        early_data: EarlyDataOutcome,
    },
}

/// An extension EncryptedExtensions carries that the client did not ask
/// for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UnsolicitedExtension {
    /// `application_layer_protocol_negotiation`, without protocols offered.
    ApplicationLayerProtocolNegotiation,
    /// `early_data`, without 0-RTT offered.
    EarlyData,
}

/// How a client's handshake fails with an alert.
///
/// `V` is the failure of the certificate verifier.
#[derive(Debug, Snafu)]
#[snafu(module(client_alert_error), visibility(pub(crate)))]
pub enum ClientAlertError<V> {
    /// The offering leaves nothing to offer.
    #[snafu(display("nothing to offer"))]
    Offer {
        /// The failure.
        source: InvalidOfferError,
    },
    /// A key share could not be generated.
    #[snafu(display("key share generation failed"))]
    KeyGeneration {
        /// The failure.
        source: KeyGenerationFailed,
    },
    /// The backend gave no random bytes.
    #[snafu(display("random generation failed"))]
    Random {
        /// The failure.
        source: RandomError,
    },
    /// A list of the offer does not fit the ClientHello.
    #[snafu(display("offered list too long"))]
    OfferList {
        /// The failure.
        source: LengthOutOfRangeError,
    },
    /// The ticket cannot be offered as a PSK identity.
    #[snafu(display("ticket cannot be offered"))]
    TicketIdentity {
        /// The failure.
        source: LengthOutOfRangeError,
    },
    /// The PSK of the ticket does not fit `pre_shared_key`.
    #[snafu(display("pre_shared_key too long"))]
    OfferedPsks {
        /// The failure.
        source: InvalidOfferedPsksError,
    },
    /// The ClientHello does not fit its extension block.
    #[snafu(display("ClientHello invalid"))]
    ClientHello {
        /// The failure.
        source: InvalidClientHelloError,
    },
    /// A handshake message could not be collected.
    #[snafu(display("handshake message read failed"))]
    Message {
        /// The failure.
        source: ReadHandshakeMessageError<Infallible>,
    },
    /// The ServerHello or HelloRetryRequest could not be read.
    #[snafu(display("ServerHello read failed"))]
    ServerHello {
        /// The failure.
        source: ReadServerHelloMessageError,
    },
    /// A second HelloRetryRequest arrived (RFC 9846 §4.2.4).
    #[snafu(display("second HelloRetryRequest"))]
    SecondRetry,
    /// The server did not select TLS 1.3 in `supported_versions`: it
    /// selected another version, or, without the extension, a version
    /// before TLS 1.3 (RFC 9846 §4.2.3, §4.3.1).
    #[snafu(display("server selected {version:?}, not TLS 1.3"))]
    Version {
        /// The selected version, `None` without the extension.
        version: Option<ProtocolVersion>,
    },
    /// The server echoed another legacy_session_id (RFC 9846 §4.2.3).
    #[snafu(display("legacy_session_id_echo differs from the ClientHello"))]
    SessionIdEcho,
    /// The server selected a cipher suite the client did not offer.
    #[snafu(display("server selected {suite:?}, which was not offered"))]
    UnofferedSuite {
        /// The suite.
        suite: CipherSuite,
    },
    /// The ServerHello selected another cipher suite than the
    /// HelloRetryRequest (RFC 9846 §4.2.4).
    #[snafu(display("ServerHello suite {suite:?} differs from the HelloRetryRequest's"))]
    RetrySuite {
        /// The suite of the ServerHello.
        suite: CipherSuite,
    },
    /// The HelloRetryRequest asked for a group the client did not list, or
    /// one it already shared (RFC 9846 §4.3.8).
    #[snafu(display("HelloRetryRequest asked for {group:?}"))]
    RetryGroup {
        /// The group.
        group: NamedGroup,
    },
    /// The HelloRetryRequest would not change the ClientHello
    /// (RFC 9846 §4.2.4).
    #[snafu(display("HelloRetryRequest changes nothing"))]
    RetryWithoutChange,
    /// The ServerHello has no key share.
    #[snafu(display("ServerHello has no key share"))]
    MissingServerShare,
    /// The server's key share is of a group the client did not share.
    #[snafu(display("server share of {group:?}, which was not shared"))]
    UnsharedGroup {
        /// The group.
        group: NamedGroup,
    },
    /// The key exchange could not be completed.
    #[snafu(display("key exchange failed"))]
    KeyExchange {
        /// The failure.
        source: CompleteError,
    },
    /// The server selected a PSK the client did not offer.
    #[snafu(display("server selected an unoffered PSK"))]
    Psk {
        /// The failure.
        source: UnofferedPskError,
    },
    /// The server selected the PSK with a cipher suite of another hash
    /// (RFC 9846 §4.3.11).
    #[snafu(display("PSK selected with a suite of another hash"))]
    PskHash,
    /// EncryptedExtensions could not be read.
    #[snafu(display("EncryptedExtensions read failed"))]
    EncryptedExtensions {
        /// The failure.
        source: ReadEncryptedExtensionsError,
    },
    /// EncryptedExtensions has no `quic_transport_parameters`
    /// (RFC 9001 §8.2).
    #[snafu(display("EncryptedExtensions lacks transport parameters"))]
    MissingTransportParameters,
    /// The client offered application protocols and the server selected
    /// none (RFC 9001 §8.1).
    #[snafu(display("no application protocol selected"))]
    NoApplicationProtocol,
    /// The server selected a protocol the client did not offer.
    #[snafu(display("server selected an unoffered application protocol"))]
    UnofferedProtocol,
    /// EncryptedExtensions answers an extension the client did not send
    /// (RFC 9846 §4.3).
    #[snafu(display("unsolicited {extension:?}"))]
    Unsolicited {
        /// The extension.
        extension: UnsolicitedExtension,
    },
    /// The server accepted 0-RTT without accepting the first PSK
    /// (RFC 9846 §4.3.10).
    #[snafu(display("0-RTT accepted without the PSK"))]
    EarlyDataWithoutPsk,
    /// The CertificateRequest could not be read.
    #[snafu(display("CertificateRequest read failed"))]
    CertificateRequest {
        /// The failure.
        source: ReadCertificateRequestError,
    },
    /// The Certificate could not be read.
    #[snafu(display("Certificate read failed"))]
    Certificate {
        /// The failure.
        source: ReadCertificateError,
    },
    /// The certificate chain does not authenticate the server.
    #[snafu(display("server certificate rejected"))]
    Verify {
        /// The failure.
        source: V,
    },
    /// CertificateVerify uses a scheme the client did not offer.
    #[snafu(display("CertificateVerify uses {scheme:?}, which was not offered"))]
    UnofferedScheme {
        /// The scheme.
        scheme: SignatureScheme,
    },
    /// CertificateVerify uses a scheme that does not fit the certificate's
    /// key.
    #[snafu(display("CertificateVerify scheme does not fit the key"))]
    SchemeKey {
        /// The failure.
        source: SchemeKeyMismatchError,
    },
    /// CertificateVerify does not verify.
    #[snafu(display("CertificateVerify rejected"))]
    CertificateVerify {
        /// The failure.
        source: CertificateVerifyError,
    },
    /// The server's Finished is not valid.
    #[snafu(display("server Finished rejected"))]
    Finished {
        /// The failure.
        source: FinishedError,
    },
    /// A NewSessionTicket could not be read.
    #[snafu(display("NewSessionTicket read failed"))]
    NewSessionTicket {
        /// The failure.
        source: ReadNewSessionTicketError,
    },
    /// The output stopped accepting bytes.
    #[snafu(display("CRYPTO output stopped"))]
    OutputStopped {
        /// The failure.
        source: WriteZero,
    },
}

impl<V: CallsForAlert> CallsForAlert for ClientAlertError<V> {
    /// The alert the failure calls for: unexpected_message for a second
    /// HelloRetryRequest; protocol_version when the server selected a
    /// version before TLS 1.3; missing_extension without transport
    /// parameters; no_application_protocol when none was selected;
    /// unsupported_extension for an unsolicited one; illegal_parameter for
    /// the other fields that disagree with the ClientHello; internal_error for
    /// failures of the client itself; and that of the source otherwise.
    fn alert(&self) -> AlertDescription {
        match self {
            Self::Message { source } => source.alert(),
            Self::ServerHello { source } => source.alert(),
            Self::SecondRetry => AlertDescription::UNEXPECTED_MESSAGE,
            Self::Version { version: None } => AlertDescription::PROTOCOL_VERSION,
            Self::Version { version: Some(_) }
            | Self::SessionIdEcho
            | Self::UnofferedSuite { .. }
            | Self::RetrySuite { .. }
            | Self::RetryGroup { .. }
            | Self::RetryWithoutChange
            | Self::MissingServerShare
            | Self::UnsharedGroup { .. }
            | Self::PskHash
            | Self::UnofferedProtocol
            | Self::EarlyDataWithoutPsk
            | Self::UnofferedScheme { .. } => AlertDescription::ILLEGAL_PARAMETER,
            Self::KeyExchange { source } => match source {
                CompleteError::InvalidPeerShare { .. } => AlertDescription::ILLEGAL_PARAMETER,
                CompleteError::Decapsulation { .. } => AlertDescription::INTERNAL_ERROR,
            },
            Self::Psk { source } => source.alert(),
            Self::EncryptedExtensions { source } => source.alert(),
            Self::MissingTransportParameters => AlertDescription::MISSING_EXTENSION,
            Self::NoApplicationProtocol => AlertDescription::NO_APPLICATION_PROTOCOL,
            Self::Unsolicited { .. } => AlertDescription::UNSUPPORTED_EXTENSION,
            Self::CertificateRequest { source } => source.alert(),
            Self::Certificate { source } => source.alert(),
            Self::Verify { source } => source.alert(),
            Self::SchemeKey { source } => source.alert(),
            Self::CertificateVerify { source } => source.alert(),
            Self::Finished { source } => source.alert(),
            Self::NewSessionTicket { source } => source.alert(),
            Self::Offer { .. }
            | Self::KeyGeneration { .. }
            | Self::Random { .. }
            | Self::OfferList { .. }
            | Self::TicketIdentity { .. }
            | Self::OfferedPsks { .. }
            | Self::ClientHello { .. }
            | Self::OutputStopped { .. } => AlertDescription::INTERNAL_ERROR,
        }
    }
}

fn alert<F, E>(source: F) -> HandshakeError<F, E> {
    HandshakeError::Alert { source }
}

fn connection<F, E>(source: impl Into<E>) -> HandshakeError<F, E> {
    HandshakeError::Transport {
        source: source.into(),
    }
}

/// Collects one handshake message from `input`.
async fn read_message<F, A, V, E>(
    input: &mut A,
    limits: MessageLimits,
    hash: Option<HashAlgorithm>,
) -> Result<HandshakeMessage, HandshakeError<ClientAlertError<V>, E>>
where
    F: Read,
    A: ReceiverAccess<Family = F>,
    F::Error: Into<E>,
{
    input
        .read_handshake_message(limits, hash)
        .await
        .map_err(|error| match split_read(error) {
            Ok(source) => alert(ClientAlertError::Message { source }),
            Err(error) => connection(error),
        })
}

/// Writes the bytes of one message to `output`.
async fn write_message<F, A, V, E>(
    output: &mut A,
    message: &[u8],
) -> Result<(), HandshakeError<ClientAlertError<V>, E>>
where
    F: Write,
    A: ReceiverAccess<Family = F>,
    F::Error: Into<E>,
{
    output
        .write_all(message)
        .await
        .map_err(|error| match split_write(error) {
            Ok(source) => alert(ClientAlertError::OutputStopped { source }),
            Err(error) => connection(error),
        })
}

/// A copy of a PSK, which the chain consumes.
fn copy_psk(psk: &ResumptionPsk) -> ResumptionPsk {
    // invariant: the bytes come from a `Secret`.
    ResumptionPsk::new(Secret::new(psk.secret().as_bytes()).expect("a PSK fits a secret"))
}

/// The ticket a ClientHello offers, with the hash of its suite.
struct OfferedTicket<C> {
    ticket: StoredTicket,
    hash: Supported<C, HashAlgorithm>,
}

/// What does not change between the two ClientHellos.
struct HelloParts<'a, C> {
    target: &'a ServerTarget,
    offer: &'a Offer<C>,
    transport_parameters: OpaqueData<Bytes>,
    application_protocols: Option<&'a ProtocolNameList<Bytes>>,
    random: HelloRandom,
}

impl<C> HelloParts<'_, C> {
    /// The ClientHello with the key shares of `exchanges`, the `cookie` of a
    /// HelloRetryRequest, 0-RTT when `early_data`, and the identity of
    /// `ticket` with a binder of zeros, as long as its hash, for the caller
    /// to fill in.
    fn hello<S: StartedExchange, V>(
        &self,
        exchanges: &[S],
        cookie: Option<&Cookie<Bytes>>,
        early_data: bool,
        ticket: Option<(&StoredTicket, HashAlgorithm, u32)>,
    ) -> Result<ClientHello<Bytes>, ClientAlertError<V>> {
        use ClientHelloExtension as X;
        let list = |source| ClientAlertError::OfferList { source };
        let suites = CodePointList::new(
            self.offer
                .suites()
                .iter()
                .map(SupportedSuite::suite)
                .collect(),
        )
        .map_err(list)?;
        let groups = CodePointList::new(
            self.offer
                .groups()
                .iter()
                .map(Supported::algorithm)
                .collect(),
        )
        .map_err(list)?;
        let schemes = CodePointList::new(
            self.offer
                .signature_schemes()
                .iter()
                .map(Supported::algorithm)
                .collect(),
        )
        .map_err(list)?;
        let shares = exchanges
            .iter()
            .map(|exchange| {
                // invariant: a backend's share is the size of its group's share.
                KeyShareEntry::new(
                    exchange.group(),
                    Bytes::copy_from_slice(exchange.share().as_bytes()),
                )
                .expect("a key share of the group")
            })
            .collect();
        // invariant: the offer has one share at most of each group.
        let shares = ClientShares::new(shares).expect("one share of each group");
        let mut extensions = vec![
            // invariant: a DNS name is at most 253 bytes.
            X::ServerName(
                ServerName::new(Bytes::copy_from_slice(self.target.host_name().as_bytes()))
                    .expect("a DNS name"),
            ),
            X::SupportedVersions(
                // invariant: one version fits.
                CodePointList::new(vec![ProtocolVersion::TLS_1_3]).expect("one version"),
            ),
            X::SupportedGroups(groups),
            X::SignatureAlgorithms(schemes),
        ];
        if let Some(protocols) = self.application_protocols {
            extensions.push(X::ApplicationLayerProtocolNegotiation(protocols.clone()));
        }
        if self.offer.signed_certificate_timestamps() {
            extensions.push(X::SignedCertificateTimestamp);
        }
        extensions.push(X::KeyShare(shares));
        extensions.push(X::QuicTransportParameters(
            self.transport_parameters.clone(),
        ));
        if let Some(cookie) = cookie {
            extensions.push(X::Cookie(cookie.clone()));
        }
        // Every hello names psk_dhe_ke: the mode restricts the tickets the
        // server sends too, and a server may send none without it (RFC 9846
        // §4.3.9).
        extensions.push(X::PskKeyExchangeModes(
            // invariant: one mode fits.
            ByteCodePointList::new(vec![PskKeyExchangeMode::PSK_DHE_KE]).expect("one mode"),
        ));
        if let Some((ticket, hash, age)) = ticket {
            if early_data {
                extensions.push(X::EarlyData);
            }
            let identity = PskIdentity::new(ticket.ticket.clone(), age)
                .map_err(|source| ClientAlertError::TicketIdentity { source })?;
            let binder = PskBinderEntry::new(Bytes::from(vec![0; hash.output_len()]))
                // invariant: a hash is 32 to 255 bytes.
                .expect("a binder as long as a hash");
            let offered = OfferedPsks::new(vec![identity], vec![binder])
                .map_err(|source| ClientAlertError::OfferedPsks { source })?;
            extensions.push(X::PreSharedKey(offered));
        }
        ClientHello::new(
            ProtocolVersion::TLS_1_2,
            self.random,
            LegacySessionId::EMPTY,
            suites,
            extensions,
        )
        .map_err(|source| ClientAlertError::ClientHello { source })
    }
}

/// Encodes `hello` and adds it to `transcript`. With `ticket`, it first
/// fills in the binder, over the transcript with the hello up to its
/// binders, and continues with the Early Secret of the ticket's PSK.
fn bind<C: TlsCrypto + Clone>(
    hello: &ClientHello<Bytes>,
    transcript: Transcript<Client, C>,
    ticket: Option<&OfferedTicket<C>>,
) -> (Bytes, HelloChain<C>) {
    let encoded = encode(hello.encoded_len(), |sink| {
        sink.sync_write_client_hello_unpin(hello)
    });
    let Some(ticket) = ticket else {
        let transcript = transcript.add(&encoded);
        return (encoded, HelloChain::Plain(transcript));
    };
    let mut encoded = encoded.to_vec();
    // invariant: a hello with a ticket has binders.
    let covered = encoded.len() - hello.binders_len().expect("binders");
    let early = transcript
        .add(&encoded[..covered])
        .early_secret_with_psk(copy_psk(&ticket.ticket.psk));
    let binder = early.binder();
    let end = encoded.len();
    encoded[end - binder.as_bytes().len()..].copy_from_slice(binder.as_bytes());
    let early = early.add(&encoded[covered..]);
    (Bytes::from(encoded), HelloChain::Psk(early))
}

/// The chain after a ClientHello: the Early Secret of the offered PSK, or,
/// without one, the transcript.
enum HelloChain<C: TlsCrypto> {
    /// With the PSK.
    Psk(PskEarlySecret<Client, C>),
    /// Without a PSK.
    Plain(Transcript<Client, C>),
}

/// The ClientHello sent, as the ServerHello finds it.
enum Sent<C: TlsCrypto> {
    /// The first ClientHello, whose transcript waits for the suite's hash.
    First {
        /// Its encoding.
        hello: Bytes,
        /// The Early Secret of the ticket's PSK, over the hello with the
        /// ticket's hash.
        psk: Option<PskEarlySecret<Client, C>>,
    },
    /// The second ClientHello, with the hash of the HelloRetryRequest's
    /// suite.
    Second {
        /// The suite the HelloRetryRequest selected.
        suite: CipherSuite,
        /// The transcript with the hello, or the Early Secret of the PSK.
        chain: HelloChain<C>,
    },
}

/// Runs a client's handshake to `target` with `backend`, `offering`,
/// `tickets`, `verifier`, `clock` and `settings`, offering the
/// `application_protocols`, over the connection's `input`, `output` and
/// `transport`.
///
/// It yields the [`ClientHandshakeEvent`]s, then keeps the tickets the
/// server sends until the call is dropped or fails.
///
/// # Errors
///
/// [`HandshakeError::Alert`] with a [`ClientAlertError`],
/// [`HandshakeError::ProtocolViolation`] for a ticket's
/// max_early_data_size, and [`HandshakeError::Transport`] when a receiver
/// fails.
#[call(yields = ClientHandshakeEvent<B>)]
#[allow(clippy::too_many_arguments)]
pub async fn client_handshake<I, O, T, B, F, K, V, Z>(
    input: &mut impl LentAccess<Family = I>,
    output: &mut impl LentAccess<Family = O>,
    transport: &mut impl LentAccess<Family = T>,
    backend: B,
    offering: F,
    tickets: K,
    verifier: V,
    clock: Z,
    target: ServerTarget,
    application_protocols: Option<ProtocolNameList<Bytes>>,
    settings: ClientHandshakeSettings,
) -> Result<(), HandshakeError<ClientAlertError<V::Error>, <T as ClientTransport>::Error>>
where
    I: CryptoInput,
    O: CryptoOutput,
    T: ClientTransport,
    <I as Read>::Error: Into<<T as ClientTransport>::Error>,
    <I as CryptoInput>::LevelError: Into<<T as ClientTransport>::Error>,
    <O as Write>::Error: Into<<T as ClientTransport>::Error>,
    B: TlsCrypto + Clone,
    F: Offering<B>,
    K: ClientTicketStore,
    V: CertificateVerifier,
    Z: Clock,
{
    let limits = settings.limits;

    // What to offer, and the ticket.
    let (offer, attempt) = offering
        .offer(&backend, &target, &verifier.support())
        .map_err(|source| alert(ClientAlertError::Offer { source }))?;
    let ticket = tickets.take(&target).and_then(|ticket| {
        let hash = offer
            .suites()
            .iter()
            .find(|suite| Some(suite.hash().algorithm()) == ticket.suite.hash())?
            .hash();
        Some(OfferedTicket { ticket, hash })
    });
    let zero_rtt_suite = ticket.as_ref().and_then(|offered| {
        let ticket = &offered.ticket;
        let protocol_offered = match (&ticket.application_protocol, &application_protocols) {
            (None, None) => true,
            (Some(protocol), Some(protocols)) => protocols
                .names()
                .iter()
                .any(|name| name.name().as_ref() == protocol.name().as_ref()),
            _ => false,
        };
        (settings.early_data && ticket.early_data && protocol_offered)
            .then(|| {
                offer
                    .suites()
                    .iter()
                    .find(|suite| suite.suite() == ticket.suite)
                    .copied()
            })
            .flatten()
    });
    let mut exchanges = offer
        .key_share_groups()
        .iter()
        .map(|&group| KeyExchange::start(&backend, group))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| alert(ClientAlertError::KeyGeneration { source }))?;
    let random: [u8; 32] =
        Random::random(&backend).map_err(|source| alert(ClientAlertError::Random { source }))?;
    let parts = HelloParts {
        target: &target,
        offer: &offer,
        transport_parameters: transport.local(),
        application_protocols: application_protocols.as_ref(),
        random: HelloRandom(random),
    };

    // The first ClientHello.
    let age = |offered: &OfferedTicket<B>| offered.ticket.obfuscated_ticket_age(clock.now());
    let hello = parts
        .hello(
            &exchanges,
            None,
            zero_rtt_suite.is_some(),
            ticket
                .as_ref()
                .map(|offered| (&offered.ticket, offered.hash.algorithm(), age(offered))),
        )
        .map_err(alert)?;
    let (first, psk) = match &ticket {
        Some(offered) => {
            let (encoded, chain) = bind(
                &hello,
                Transcript::<Client, B>::new(&backend, offered.hash),
                Some(offered),
            );
            (
                encoded,
                match chain {
                    HelloChain::Psk(early) => Some(early),
                    HelloChain::Plain(_) => None,
                },
            )
        }
        None => (
            encode(hello.encoded_len(), |sink| {
                sink.sync_write_client_hello_unpin(&hello)
            }),
            None,
        ),
    };
    write_message(output, &first).await?;
    let early_offered = match (zero_rtt_suite, &psk, &ticket) {
        (Some(suite), Some(early), Some(offered)) => {
            yield ClientHandshakeEvent::EarlyDataOffered {
                aead: suite.aead(),
                secret: early.early_send(),
                transport_parameters: offered.ticket.transport_parameters.clone(),
                application_protocol: offered.ticket.application_protocol.clone(),
            };
            true
        }
        _ => false,
    };
    let mut sent = Sent::First { hello: first, psk };

    // The ServerHello, after a HelloRetryRequest if there is one.
    let check_version = |version: Option<ProtocolVersion>| {
        if version == Some(ProtocolVersion::TLS_1_3) {
            Ok(())
        } else {
            Err(alert(ClientAlertError::Version { version }))
        }
    };
    let offered_suite = |suite: CipherSuite| {
        offer
            .suites()
            .iter()
            .find(|offered| offered.suite() == suite)
            .copied()
            .ok_or(alert(ClientAlertError::UnofferedSuite { suite }))
    };
    let mut attempt = Some(attempt);
    let (server_hello, encoded_server_hello) = loop {
        let message = read_message(input, limits, None).await?;
        let reply = message
            .encoded()
            .clone()
            .sync_read_server_hello_message_unpin()
            .map_err(|source| alert(ClientAlertError::ServerHello { source }))?;
        let retry = match reply {
            ServerHelloMessage::ServerHello(server_hello) => {
                break (server_hello, message.into_encoded());
            }
            ServerHelloMessage::HelloRetryRequest(retry) => retry,
        };
        let Sent::First { hello: first, .. } = &sent else {
            return Err(alert(ClientAlertError::SecondRetry));
        };
        check_version(
            retry
                .extensions()
                .iter()
                .find_map(|extension| match extension {
                    HelloRetryRequestExtension::SupportedVersions(version) => Some(*version),
                    _ => None,
                }),
        )?;
        if retry.legacy_session_id_echo() != &LegacySessionId::EMPTY {
            return Err(alert(ClientAlertError::SessionIdEcho));
        }
        let suite = offered_suite(retry.cipher_suite())?;
        let cookie = retry.cookie();
        match retry.key_share() {
            Some(group) => {
                let supported = offer
                    .groups()
                    .iter()
                    .find(|offered| offered.algorithm() == group)
                    .copied()
                    .filter(|offered| !offer.key_share_groups().contains(offered))
                    .ok_or(alert(ClientAlertError::RetryGroup { group }))?;
                if let Some(attempt) = attempt.take() {
                    attempt.retried(supported);
                }
                exchanges = vec![
                    KeyExchange::start(&backend, supported)
                        .map_err(|source| alert(ClientAlertError::KeyGeneration { source }))?,
                ];
            }
            None if cookie.is_none() => return Err(alert(ClientAlertError::RetryWithoutChange)),
            None => {}
        }
        let transcript = Transcript::<Client, B>::new(&backend, suite.hash())
            .add(first)
            .retry(message.encoded());
        let ticket = ticket
            .as_ref()
            .filter(|offered| offered.hash.algorithm() == suite.hash().algorithm());
        let hello = parts
            .hello(
                &exchanges,
                cookie,
                false,
                ticket.map(|offered| (&offered.ticket, offered.hash.algorithm(), age(offered))),
            )
            .map_err(alert)?;
        let (second, chain) = bind(&hello, transcript, ticket);
        write_message(output, &second).await?;
        sent = Sent::Second {
            suite: suite.suite(),
            chain,
        };
    };
    drop(attempt);
    check_version(server_hello.supported_versions())?;
    if server_hello.legacy_session_id_echo() != &LegacySessionId::EMPTY {
        return Err(alert(ClientAlertError::SessionIdEcho));
    }
    let suite = offered_suite(server_hello.cipher_suite())?;
    if let Sent::Second { suite: retried, .. } = &sent
        && *retried != suite.suite()
    {
        return Err(alert(ClientAlertError::RetrySuite {
            suite: suite.suite(),
        }));
    }
    let server_share = server_hello
        .key_share()
        .ok_or(alert(ClientAlertError::MissingServerShare))?;
    let position = exchanges
        .iter()
        .position(|exchange| exchange.group() == server_share.group())
        .ok_or(alert(ClientAlertError::UnsharedGroup {
            group: server_share.group(),
        }))?;
    let shared = exchanges
        .swap_remove(position)
        .complete(server_share.key_exchange().as_ref())
        .map_err(|source| alert(ClientAlertError::KeyExchange { source }))?;
    drop(exchanges);
    let selected_psk = server_hello.pre_shared_key();
    let psk_error = |source| alert(ClientAlertError::Psk { source });
    let (handshake, secrets) = match sent {
        Sent::First { hello, psk } => match psk {
            Some(early)
                if ticket.as_ref().map(|offered| offered.hash.algorithm())
                    == Some(suite.hash().algorithm()) =>
            {
                early.server_hello(shared, &encoded_server_hello, selected_psk)
            }
            Some(_) if selected_psk.is_some() => return Err(alert(ClientAlertError::PskHash)),
            _ => Transcript::<Client, B>::new(&backend, suite.hash())
                .add(&hello)
                .early_secret()
                .server_hello(shared, &encoded_server_hello, selected_psk),
        },
        Sent::Second { chain, .. } => match chain {
            HelloChain::Psk(early) => {
                early.server_hello(shared, &encoded_server_hello, selected_psk)
            }
            HelloChain::Plain(transcript) => {
                transcript
                    .early_secret()
                    .server_hello(shared, &encoded_server_hello, selected_psk)
            }
        },
    }
    .map_err(psk_error)?;
    yield ClientHandshakeEvent::ServerHelloRead {
        aead: suite.aead(),
        secrets,
    };
    output.move_to(CryptoLevel::Handshake);
    input.move_to(CryptoLevel::Handshake).map_err(connection)?;
    let hash = Some(suite.hash().algorithm());

    // EncryptedExtensions.
    let message = read_message(input, limits, hash).await?;
    let extensions = message
        .encoded()
        .clone()
        .sync_read_encrypted_extensions_unpin()
        .map_err(|source| alert(ClientAlertError::EncryptedExtensions { source }))?;
    let peer_parameters = extensions
        .quic_transport_parameters()
        .ok_or(alert(ClientAlertError::MissingTransportParameters))?
        .clone();
    let selected_protocol = extensions
        .extensions()
        .iter()
        .find_map(|extension| match extension {
            EncryptedExtensionsExtension::ApplicationLayerProtocolNegotiation(protocol) => {
                Some(protocol.clone())
            }
            _ => None,
        });
    match (&application_protocols, &selected_protocol) {
        (None, None) => {}
        (None, Some(_)) => {
            return Err(alert(ClientAlertError::Unsolicited {
                extension: UnsolicitedExtension::ApplicationLayerProtocolNegotiation,
            }));
        }
        (Some(_), None) => return Err(alert(ClientAlertError::NoApplicationProtocol)),
        (Some(protocols), Some(selected)) => {
            if !protocols
                .names()
                .iter()
                .any(|name| name.name().as_ref() == selected.name().as_ref())
            {
                return Err(alert(ClientAlertError::UnofferedProtocol));
            }
        }
    }
    let early_accepted = extensions
        .extensions()
        .iter()
        .any(|extension| matches!(extension, EncryptedExtensionsExtension::EarlyData));
    let early_data = match (early_offered, early_accepted) {
        (false, false) => EarlyDataOutcome::NotOffered,
        (false, true) => {
            return Err(alert(ClientAlertError::Unsolicited {
                extension: UnsolicitedExtension::EarlyData,
            }));
        }
        (true, true) if selected_psk != Some(PskIndex::new(0)) => {
            return Err(alert(ClientAlertError::EarlyDataWithoutPsk));
        }
        (true, true) => EarlyDataOutcome::Accepted,
        (true, false) => EarlyDataOutcome::Rejected,
    };
    transport
        .peer(&peer_parameters)
        .map_err(|error| HandshakeError::Transport { source: error })?;
    let handshake = handshake.add(message.encoded());

    // The server authenticates, by certificate or by PSK.
    let (authenticated, identity, requested) = match handshake.authentication() {
        Authentication::Certificate(mut authentication) => {
            let mut message = read_message(input, limits, hash).await?;
            let mut requested = None;
            if message.handshake_type() == HandshakeType::CERTIFICATE_REQUEST {
                let request = message
                    .encoded()
                    .clone()
                    .sync_read_certificate_request_unpin()
                    .map_err(|source| alert(ClientAlertError::CertificateRequest { source }))?;
                requested = Some(request.certificate_request_context().clone());
                authentication = authentication.add(message.encoded());
                message = read_message(input, limits, hash).await?;
            }
            let certificate = message
                .encoded()
                .clone()
                .sync_read_certificate_unpin(CertificateFormat::X509)
                .map_err(|source| alert(ClientAlertError::Certificate { source }))?;
            let leaf = verifier
                .verify(&target, certificate.certificates().entries())
                .await
                .map_err(|source| alert(ClientAlertError::Verify { source }))?;
            let authentication = authentication.add(message.encoded());
            let message = read_message(input, limits, hash).await?;
            let verify = message
                .encoded()
                .clone()
                .sync_read_certificate_verify_unpin()
                .map_err(|source| {
                    alert(ClientAlertError::CertificateVerify {
                        source: CertificateVerifyError::Read { source },
                    })
                })?;
            let scheme = verify.algorithm();
            if !offer
                .signature_schemes()
                .iter()
                .any(|offered| offered.algorithm() == scheme)
            {
                return Err(alert(ClientAlertError::UnofferedScheme { scheme }));
            }
            leaf.check_certificate_verify_scheme(scheme)
                .map_err(|source| alert(ClientAlertError::SchemeKey { source }))?;
            let authenticated = authentication
                .verify_certificate_verify(&message, leaf.key())
                .map_err(|source| alert(ClientAlertError::CertificateVerify { source }))?;
            (authenticated, ServerIdentity::Verified(leaf), requested)
        }
        Authentication::Resumed(authenticated) => {
            // invariant: the server authenticates with a PSK only when it
            // selected the offered one, which has a ticket.
            let ticket = ticket.as_ref().expect("the ticket of the selected PSK");
            (
                authenticated,
                ServerIdentity::Resumed(ticket.ticket.identity.clone()),
                None,
            )
        }
    };

    // The server's Finished, then the client's.
    let message = read_message(input, limits, hash).await?;
    let (mut master, one_rtt) = authenticated
        .server_finished(&message)
        .map_err(|source| alert(ClientAlertError::Finished { source }))?;
    if let Some(context) = requested {
        let certificate = Certificate::new(context, CertificateList::X509(Vec::new()))
            // invariant: a context read from a CertificateRequest fits.
            .expect("an empty Certificate");
        let encoded = encode(certificate.encoded_len(), |sink| {
            sink.sync_write_certificate_unpin(&certificate)
        });
        write_message(output, &encoded).await?;
        master = master.add(&encoded);
    }
    let exporter = master.exporter();
    let (resumption, finished) = master.client_finished();
    write_message(output, finished.encoded()).await?;
    let ticket_identity = match &identity {
        ServerIdentity::Verified(key) | ServerIdentity::Resumed(key) => key.clone(),
    };
    yield ClientHandshakeEvent::Completed {
        secrets: one_rtt,
        exporter,
        identity,
        application_protocol: selected_protocol.clone(),
        early_data,
    };
    output.move_to(CryptoLevel::OneRtt);
    input.move_to(CryptoLevel::OneRtt).map_err(connection)?;

    // The tickets the server sends.
    loop {
        let message = read_message(input, limits, hash).await?;
        let received = message
            .encoded()
            .clone()
            .sync_read_new_session_ticket_unpin()
            .map_err(|source| alert(ClientAlertError::NewSessionTicket { source }))?;
        let early_data = match received
            .extensions()
            .iter()
            .find_map(|extension| match extension {
                NewSessionTicketExtension::EarlyData(size) => Some(*size),
                NewSessionTicketExtension::Unknown(_) => None,
            }) {
            Some(size) => {
                MaxEarlyDataSizeError::check(size).map_err(|source| {
                    HandshakeError::ProtocolViolation {
                        source: source.into(),
                    }
                })?;
                true
            }
            None => false,
        };
        if received.ticket_lifetime().seconds() == 0 {
            continue;
        }
        tickets.store(
            &target,
            StoredTicket {
                ticket: received.ticket().clone(),
                psk: resumption.ticket_psk(received.ticket_nonce()),
                suite: suite.suite(),
                ticket_age_add: received.ticket_age_add(),
                lifetime: received.ticket_lifetime(),
                received_at: clock.now(),
                early_data,
                application_protocol: selected_protocol.clone(),
                transport_parameters: peer_parameters.clone(),
                identity: ticket_identity.clone(),
            },
        );
    }
}
