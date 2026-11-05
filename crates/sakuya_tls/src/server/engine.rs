//! The server's handshake engine.
//!
//! [`server_handshake`] runs a TLS 1.3 handshake for a QUIC server, from
//! the ClientHello to the session tickets. It owns the backend and the
//! server's capabilities, and receives the connection's receivers on every
//! poll (see [`engine`](crate::engine)): the CRYPTO streams and a
//! [`ServerTransport`], whose [`ServerTransport::negotiate`] checks the
//! client's transport parameters and gives the server's own.
//!
//! The handshake goes:
//!
//! 1. reads the ClientHello at Initial, opens its layers, selects the target
//!    and chooses the cipher suite and group; when the client sent no key
//!    share of that group, writes a HelloRetryRequest and reads the second
//!    ClientHello;
//! 2. opens an offered ticket and checks its binder;
//! 3. negotiates the transport parameters, and admits 0-RTT only when the
//!    handshake, the connection and the ticket policy all agree;
//! 4. writes the ServerHello and yields
//!    [`ServerHandshakeEvent::ServerHelloWritten`], with the 0-RTT secret when it
//!    admitted 0-RTT, then moves both streams to Handshake;
//! 5. writes EncryptedExtensions and, unless it resumed, Certificate and
//!    CertificateVerify, whose signature may wait; writes its Finished and
//!    yields [`ServerHandshakeEvent::ServerFinishedWritten`];
//! 6. reads the client's Finished: the handshake is complete, and it yields
//!    [`ServerHandshakeEvent::Completed`] with the exporter and the client's
//!    1-RTT secret, which it held back until now (RFC 9001 §5.7), then
//!    moves both streams to 1-RTT;
//! 7. issues the session tickets of its ticket policy, and ends; it issues
//!    none when the client did not name psk_dhe_ke (RFC 9846 §4.3.9).
//!
//! A failure ends the call with a [`HandshakeError`]; a ClientHello with a
//! non-empty legacy_session_id ends it with
//! [`HandshakeError::ProtocolViolation`] (RFC 9001 §8.4).
//!
//! This version neither opens encrypted layers nor asks for a client
//! certificate: it takes layers whose confirmation and retry
//! configurations, and a peer authentication whose request, are
//! [`Infallible`], so those steps have no values to act on.
//!
//! `#[call]` and `#[capability]` generate the operation struct
//! [`ServerHandshake`], with a `new` constructor taking the arguments after
//! the receivers, and the extension traits `ServerHandshakeExt`,
//! `ServerTransportExt` and `ServerTransportViewExt`.

// The generated items have no documentation comments; the module
// documentation above describes them.
#![allow(missing_docs)]

use crate::{
    alert::{AlertDescription, CallsForAlert},
    cipher_suite::SupportedSuite,
    clock::{Clock, elapsed},
    crypto::TlsCrypto,
    engine::{
        CryptoInput, CryptoInputExt as _, CryptoLevel, CryptoOutput, CryptoOutputExt as _,
        HandshakeError, LegacySessionIdError, encode, split_read, split_write,
    },
    extension::{
        InvalidExtensionsError, OpaqueData,
        early_data::MaxEarlyDataSize,
        key_share::KeyShareEntry,
        pre_shared_key::{OfferedPsks, PskIndex},
        psk_key_exchange_modes::PskKeyExchangeMode,
    },
    message::{
        HandshakeMessage, HelloRandom, MessageLimits,
        certificate::{
            Certificate, CertificateEntry, CertificateList, InvalidCertificateEntryError,
            InvalidCertificateError, codec::WriteCertificateHostExt as _,
        },
        certificate_verify::{CertificateVerify, codec::WriteCertificateVerifyHostExt as _},
        client_hello::{
            ClientHello, ClientHelloExtension,
            codec::{ReadClientHelloError, ReadClientHelloHostExt as _},
        },
        codec::{ReadHandshakeMessageError, ReadHandshakeMessageExt as _},
        encrypted_extensions::{
            EncryptedExtensions, EncryptedExtensionsExtension,
            codec::WriteEncryptedExtensionsHostExt as _,
        },
        new_session_ticket::{
            NewSessionTicket, NewSessionTicketExtension, TicketNonce,
            codec::WriteNewSessionTicketHostExt as _,
        },
        server_hello::{
            HelloRetryRequest, HelloRetryRequestExtension, ServerHello, ServerHelloExtension,
            codec::{WriteHelloRetryRequestHostExt as _, WriteServerHelloHostExt as _},
        },
    },
    role::Server,
    schedule::{
        BinderMismatchError, EarlySecret, Exporter, FinishedError, HandshakeTrafficSecrets,
        OneRttReceiveTrafficSecret, OneRttSendTrafficSecret, PskEarlySecret, ResumptionPsk,
        Transcript, ZeroRttReceiveTrafficSecret,
    },
    server::{
        choice::{ClientOffer, NoCommonParametersError, ParameterChoice},
        identity::{CertificateSelection, NoCommonSchemeError},
        layers::{AcceptedHello, HelloLayers},
        peer::PeerAuthentication,
        targets::{SelectedTarget, TargetSelection},
        ticket::{
            ClientHelloKey, Issuing, Opened, Resumable, TicketPolicy, TicketSlot, TicketState,
        },
    },
    vector::LengthOutOfRangeError,
    version::ProtocolVersion,
};
use bytes::Bytes;
use core::{convert::Infallible, pin::Pin, time::Duration};
use nitori_call::{LentAccess, ReceiverAccess, ReceiverFamily, call, capability};
use nitori_crypto::{
    Hash, HashAlgorithm, KeyExchange, Random, RandomError, RunningHash, Secret, ServerShareError,
    SigningKey,
};
use nitori_io::{Read, Write, calls::WriteAllExt as _, error::WriteZero};
use sakuya_packet_protection::backend::AeadAlgorithm;
use snafu::Snafu;
use time::UtcDateTime;

/// The connection's side of the transport parameters, as a server's
/// handshake asks for it.
///
/// `T` is the type of the server's selected target.
#[capability]
pub trait ServerTransport<T>: ReceiverFamily {
    /// A failure, such as TRANSPORT_PARAMETER_ERROR.
    type Error;

    /// Checks `peer`, the client's `quic_transport_parameters`, records
    /// what the connection learns from them, and gives the server's own,
    /// for `selected`, the target and application protocol. `resumed` is
    /// what the ticket the server resumes with recorded, against which the
    /// connection decides whether 0-RTT is compatible (RFC 9000 §7.4.1,
    /// RFC 9001 §4.6.3).
    ///
    /// # Errors
    ///
    /// As the implementation documents.
    fn negotiate<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        peer: &[u8],
        selected: &SelectedTarget<T>,
        resumed: Option<&TicketState<T>>,
    ) -> Result<Negotiated, Self::Error>
    where
        Self: 'v;
}

/// What the connection answers to [`ServerTransport::negotiate`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Negotiated {
    /// The server's own transport parameters, for EncryptedExtensions.
    pub local: OpaqueData<Bytes>,
    /// Whether the connection accepts 0-RTT with the ticket: its transport
    /// parameters and the application's configuration are compatible with
    /// what the ticket recorded, and `local` does not lower the limits
    /// 0-RTT relies on. Without a ticket it is not read.
    pub early_data: bool,
}

/// The fixed choices of a server's handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerHandshakeSettings {
    /// The limits on the messages the server receives.
    pub limits: MessageLimits,
    /// How far the age a client states for its ticket may be from the age
    /// the server measures for 0-RTT to be admitted (RFC 9846 §8.3); 10
    /// seconds by default.
    pub ticket_age_tolerance: Duration,
}

impl Default for ServerHandshakeSettings {
    fn default() -> Self {
        Self {
            limits: MessageLimits::default(),
            ticket_age_tolerance: Duration::from_secs(10),
        }
    }
}

/// What a server's handshake hands over, in this order.
///
/// `C` is the backend and `T` the type of the selected target.
pub enum ServerHandshakeEvent<C: TlsCrypto, T> {
    /// The ServerHello is written: the Handshake traffic secrets and, when
    /// the server admitted 0-RTT, the secret to receive 0-RTT with. Both
    /// streams move to Handshake after this item.
    #[doc(alias = "HandshakeTrafficSecrets")]
    ServerHelloWritten {
        /// The AEAD of the cipher suite, for every secret of the handshake.
        aead: AeadAlgorithm,
        /// The Handshake traffic secrets.
        secrets: HandshakeTrafficSecrets,
        /// The 0-RTT secret, `None` when 0-RTT is not admitted.
        zero_rtt: Option<ZeroRttReceiveTrafficSecret>,
    },
    /// The server's Finished is written: the 1-RTT secret to send with.
    #[doc(alias = "OneRttSendTrafficSecret")]
    ServerFinishedWritten(OneRttSendTrafficSecret),
    /// The client's Finished is verified, and the handshake is complete.
    /// Both streams move to 1-RTT after this item.
    Completed {
        /// The client's 1-RTT secret, the server's to receive with.
        one_rtt_receive: OneRttReceiveTrafficSecret,
        /// The exporter of the connection.
        exporter: Exporter<C>,
        /// The selected target and application protocol.
        selected: SelectedTarget<T>,
        /// Whether the server authenticated with the PSK of a ticket.
        resumed: bool,
    },
}

/// A required extension a ClientHello lacks (RFC 9846 §9.2, RFC 9001
/// §8.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RequiredExtension {
    /// `supported_groups`: the server uses (EC)DHE in every handshake.
    SupportedGroups,
    /// `key_share`, which goes with `supported_groups`.
    KeyShare,
    /// `signature_algorithms`, for a server that authenticates with a
    /// certificate.
    SignatureAlgorithms,
    /// `psk_key_exchange_modes`, which goes with `pre_shared_key`.
    PskKeyExchangeModes,
    /// `quic_transport_parameters`.
    QuicTransportParameters,
}

/// How a server's handshake fails with an alert.
///
/// `L`, `S`, `G` and `K` are the failures of opening the layers, selecting
/// the target, signing and sealing a ticket.
#[derive(Debug, Snafu)]
#[snafu(module(server_alert_error), visibility(pub(crate)))]
pub enum ServerAlertError<L, S, G, K> {
    /// A handshake message could not be collected.
    #[snafu(display("handshake message read failed"))]
    Message {
        /// The failure.
        source: ReadHandshakeMessageError<Infallible>,
    },
    /// The ClientHello could not be read.
    #[snafu(display("ClientHello read failed"))]
    ClientHello {
        /// The failure.
        source: ReadClientHelloError,
    },
    /// The ClientHello does not offer TLS 1.3 in `supported_versions`.
    #[snafu(display("ClientHello does not offer TLS 1.3"))]
    UnsupportedVersion,
    /// The ClientHello lacks a required extension.
    #[snafu(display("ClientHello lacks {extension:?}"))]
    MissingExtension {
        /// The extension.
        extension: RequiredExtension,
    },
    /// The layers of the ClientHello could not be opened.
    #[snafu(display("ClientHello layers could not be opened"))]
    Layers {
        /// The failure.
        source: L,
    },
    /// No target could be selected.
    #[snafu(display("target selection failed"))]
    Target {
        /// The failure.
        source: S,
    },
    /// The ClientHello and the server have no suite or no group in common.
    #[snafu(display("no common parameters"))]
    NoCommonParameters {
        /// Which.
        source: NoCommonParametersError,
    },
    /// The parameter choice picked a suite or group the client did not
    /// offer.
    #[snafu(display("parameter choice outside the client's offer"))]
    ChoiceNotOffered,
    /// The second ClientHello does not carry exactly one key share, of the
    /// group the HelloRetryRequest named (RFC 9846 §4.2.2).
    #[snafu(display("second ClientHello does not share the requested group"))]
    RetryKeyShare,
    /// The second ClientHello no longer offers the suite or the group the
    /// HelloRetryRequest named.
    #[snafu(display("second ClientHello withdrew the chosen suite or group"))]
    RetryOffer,
    /// The ticket policy named an identity the ClientHello does not have.
    #[snafu(display("ticket policy named PSK {}, which was not offered", index.get()))]
    TicketIndex {
        /// The index.
        index: PskIndex,
    },
    /// The binder of the PSK does not match.
    #[snafu(display("PSK binder rejected"))]
    Binder {
        /// The failure.
        source: BinderMismatchError,
    },
    /// The key exchange failed.
    #[snafu(display("key exchange failed"))]
    KeyExchange {
        /// The failure.
        source: ServerShareError,
    },
    /// The backend gave no random bytes.
    #[snafu(display("random generation failed"))]
    Random {
        /// The failure.
        source: RandomError,
    },
    /// EncryptedExtensions does not fit its block.
    #[snafu(display("EncryptedExtensions too long"))]
    EncryptedExtensions {
        /// The failure.
        source: InvalidExtensionsError,
    },
    /// The key signs with none of the client's schemes.
    #[snafu(display("no common signature scheme"))]
    NoCommonScheme {
        /// The failure.
        source: NoCommonSchemeError,
    },
    /// A certificate of the chain cannot be sent.
    #[snafu(display("certificate of the chain cannot be sent"))]
    CertificateEntry {
        /// The failure.
        source: InvalidCertificateEntryError,
    },
    /// The chain does not fit a Certificate message.
    #[snafu(display("certificate chain too long"))]
    Certificate {
        /// The failure.
        source: InvalidCertificateError,
    },
    /// The signature of CertificateVerify could not be made.
    #[snafu(display("CertificateVerify signing failed"))]
    Signing {
        /// The failure.
        source: G,
    },
    /// The signature does not fit CertificateVerify.
    #[snafu(display("signature length out of range"))]
    SignatureLength {
        /// The failure.
        source: LengthOutOfRangeError,
    },
    /// The client's Finished is not valid.
    #[snafu(display("client Finished rejected"))]
    Finished {
        /// The failure.
        source: FinishedError,
    },
    /// A ticket could not be sealed.
    #[snafu(display("ticket sealing failed"))]
    Ticket {
        /// The failure.
        source: K,
    },
    /// The output stopped accepting bytes.
    #[snafu(display("CRYPTO output stopped"))]
    OutputStopped {
        /// The failure.
        source: WriteZero,
    },
}

impl<L: CallsForAlert, S: CallsForAlert, G, K> CallsForAlert for ServerAlertError<L, S, G, K> {
    /// The alert the failure calls for: protocol_version without TLS 1.3
    /// (RFC 9846 §4.3.1), missing_extension for a required extension
    /// (§9.2), illegal_parameter for a second ClientHello that does not
    /// follow the HelloRetryRequest (§4.1.2) and an invalid key share,
    /// decrypt_error for a binder (§4.2.11), handshake_failure without
    /// common parameters or scheme, internal_error for failures of the
    /// server itself, and that of the source otherwise.
    fn alert(&self) -> AlertDescription {
        match self {
            Self::Message { source } => source.alert(),
            Self::ClientHello { source } => source.alert(),
            Self::UnsupportedVersion => AlertDescription::PROTOCOL_VERSION,
            Self::MissingExtension { .. } => AlertDescription::MISSING_EXTENSION,
            Self::Layers { source } => source.alert(),
            Self::Target { source } => source.alert(),
            Self::NoCommonParameters { source } => source.alert(),
            Self::RetryKeyShare | Self::RetryOffer => AlertDescription::ILLEGAL_PARAMETER,
            Self::Binder { source } => source.alert(),
            Self::KeyExchange { source } => match source {
                ServerShareError::InvalidPeerShare { .. } => AlertDescription::ILLEGAL_PARAMETER,
                ServerShareError::KeyGeneration { .. } => AlertDescription::INTERNAL_ERROR,
            },
            Self::NoCommonScheme { source } => source.alert(),
            Self::Finished { source } => source.alert(),
            Self::ChoiceNotOffered
            | Self::TicketIndex { .. }
            | Self::Random { .. }
            | Self::EncryptedExtensions { .. }
            | Self::CertificateEntry { .. }
            | Self::Certificate { .. }
            | Self::Signing { .. }
            | Self::SignatureLength { .. }
            | Self::Ticket { .. }
            | Self::OutputStopped { .. } => AlertDescription::INTERNAL_ERROR,
        }
    }
}

/// The failures of [`server_handshake`] with the capabilities `L`, `S`,
/// `P` and `K` and the connection's error `E`.
type Failed<E, L, S, P, K> = HandshakeError<
    ServerAlertError<
        <L as HelloLayers>::Error,
        <S as TargetSelection>::Error,
        <<P as CertificateSelection<<S as TargetSelection>::Target>>::Key as SigningKey>::Error,
        <<<K as TicketPolicy<<S as TargetSelection>::Target>>::Issuing as Issuing>::Slot as TicketSlot>::Error,
    >,
    E,
>;

fn alert<F, E>(source: F) -> HandshakeError<F, E> {
    HandshakeError::Alert { source }
}

fn connection<F, E>(source: impl Into<E>) -> HandshakeError<F, E> {
    HandshakeError::Transport {
        source: source.into(),
    }
}

/// Collects one handshake message from `input`.
async fn read_message<F, A, L, S, G, K, E>(
    input: &mut A,
    limits: MessageLimits,
    hash: Option<HashAlgorithm>,
) -> Result<HandshakeMessage, HandshakeError<ServerAlertError<L, S, G, K>, E>>
where
    F: Read,
    A: ReceiverAccess<Family = F>,
    F::Error: Into<E>,
{
    input
        .read_handshake_message(limits, hash)
        .await
        .map_err(|error| match split_read(error) {
            Ok(source) => alert(ServerAlertError::Message { source }),
            Err(error) => connection(error),
        })
}

/// Writes the bytes of one message to `output`.
async fn write_message<F, A, L, S, G, K, E>(
    output: &mut A,
    message: &[u8],
) -> Result<(), HandshakeError<ServerAlertError<L, S, G, K>, E>>
where
    F: Write,
    A: ReceiverAccess<Family = F>,
    F::Error: Into<E>,
{
    output
        .write_all(message)
        .await
        .map_err(|error| match split_write(error) {
            Ok(source) => alert(ServerAlertError::OutputStopped { source }),
            Err(error) => connection(error),
        })
}

/// Reads the ClientHello of a whole message.
fn read_hello<L, S, G, K>(
    message: &HandshakeMessage,
) -> Result<ClientHello<Bytes>, ServerAlertError<L, S, G, K>> {
    message
        .encoded()
        .clone()
        .sync_read_client_hello_unpin()
        .map_err(|source| ServerAlertError::ClientHello { source })
}

/// Checks that a ClientHello does not ask for the middlebox compatibility
/// mode (RFC 9001 §8.4).
fn check_session_id<F, E>(hello: &ClientHello<Bytes>) -> Result<(), HandshakeError<F, E>> {
    LegacySessionIdError::check(*hello.legacy_session_id()).map_err(|source| {
        HandshakeError::ProtocolViolation {
            source: source.into(),
        }
    })
}

/// The `quic_transport_parameters` of a ClientHello.
fn transport_parameters(hello: &ClientHello<Bytes>) -> Option<&Bytes> {
    hello
        .extensions()
        .iter()
        .find_map(|extension| match extension {
            ClientHelloExtension::QuicTransportParameters(data) => Some(data.data()),
            _ => None,
        })
}

/// The `psk_key_exchange_modes` of a ClientHello.
fn psk_modes(hello: &ClientHello<Bytes>) -> Option<&[PskKeyExchangeMode]> {
    hello
        .extensions()
        .iter()
        .find_map(|extension| match extension {
            ClientHelloExtension::PskKeyExchangeModes(modes) => Some(modes.as_slice()),
            _ => None,
        })
}

/// Checks what every ClientHello the server continues with must have:
/// TLS 1.3, (EC)DHE groups and shares, and transport parameters.
fn check_hello<L, S, G, K>(hello: &ClientHello<Bytes>) -> Result<(), ServerAlertError<L, S, G, K>> {
    let tls13 = hello.extensions().iter().any(|extension| {
        matches!(extension, ClientHelloExtension::SupportedVersions(versions)
            if versions.as_slice().contains(&ProtocolVersion::TLS_1_3))
    });
    if !tls13 {
        return Err(ServerAlertError::UnsupportedVersion);
    }
    let missing = |extension| ServerAlertError::MissingExtension { extension };
    if hello.supported_groups().is_none() {
        return Err(missing(RequiredExtension::SupportedGroups));
    }
    if hello.key_share().is_none() {
        return Err(missing(RequiredExtension::KeyShare));
    }
    if hello.pre_shared_key().is_some() && psk_modes(hello).is_none() {
        return Err(missing(RequiredExtension::PskKeyExchangeModes));
    }
    if transport_parameters(hello).is_none() {
        return Err(missing(RequiredExtension::QuicTransportParameters));
    }
    Ok(())
}

/// A copy of the PSK of an opened ticket, which the chain consumes.
fn copy_psk(psk: &ResumptionPsk) -> ResumptionPsk {
    // invariant: the bytes come from a `Secret`.
    ResumptionPsk::new(Secret::new(psk.secret().as_bytes()).expect("a PSK fits a secret"))
}

/// The Early Secret the server continues with.
enum Early<C: TlsCrypto> {
    /// Without a PSK.
    Plain(EarlySecret<Server, C>),
    /// With the PSK of the identity at the index.
    Psk(PskEarlySecret<Server, C>, PskIndex),
}

/// Whether the client's age of its ticket is within `tolerance` of the
/// age the server measures (RFC 9846 §4.3.11.1, §8.3).
fn ticket_age_fits<T>(
    state: &TicketState<T>,
    obfuscated_age: u32,
    now: UtcDateTime,
    tolerance: Duration,
) -> bool {
    let stated =
        Duration::from_millis(u64::from(obfuscated_age.wrapping_sub(state.ticket_age_add)));
    let Some(measured) = elapsed(state.issued_at, now) else {
        return false;
    };
    stated.abs_diff(measured) <= tolerance
}

/// Runs a server's handshake with `backend`, `choice`, `tickets`, `layers`,
/// `targets`, `identity`, `peer`, `clock` and `settings`, over the
/// connection's `input`, `output` and `transport`.
///
/// It yields the [`ServerHandshakeEvent`]s and ends once the tickets are
/// issued.
///
/// # Errors
///
/// [`HandshakeError::Alert`] with a [`ServerAlertError`],
/// [`HandshakeError::ProtocolViolation`] for a non-empty
/// legacy_session_id, and [`HandshakeError::Transport`] when a receiver
/// fails.
#[call(yields = ServerHandshakeEvent<B, <S as TargetSelection>::Target>)]
#[allow(clippy::too_many_arguments)]
pub async fn server_handshake<I, O, T, B, N, K, L, S, P, Q, Z>(
    input: &mut impl LentAccess<Family = I>,
    output: &mut impl LentAccess<Family = O>,
    transport: &mut impl LentAccess<Family = T>,
    backend: B,
    choice: N,
    tickets: K,
    layers: L,
    targets: S,
    identity: P,
    peer: Q,
    clock: Z,
    settings: ServerHandshakeSettings,
) -> Result<(), Failed<<T as ServerTransport<<S as TargetSelection>::Target>>::Error, L, S, P, K>>
where
    I: CryptoInput,
    O: CryptoOutput,
    T: ServerTransport<<S as TargetSelection>::Target>,
    <I as Read>::Error: Into<<T as ServerTransport<<S as TargetSelection>::Target>>::Error>,
    <I as CryptoInput>::LevelError:
        Into<<T as ServerTransport<<S as TargetSelection>::Target>>::Error>,
    <O as Write>::Error: Into<<T as ServerTransport<<S as TargetSelection>::Target>>::Error>,
    B: TlsCrypto + Clone,
    N: ParameterChoice<B, <S as TargetSelection>::Target>,
    K: TicketPolicy<<S as TargetSelection>::Target>,
    L: HelloLayers,
    L::Accepted: AcceptedHello<Confirmation = Infallible, RetryConfigs = Infallible>,
    S: TargetSelection,
    S::Target: Clone + PartialEq,
    P: CertificateSelection<<S as TargetSelection>::Target>,
    Q: PeerAuthentication<<S as TargetSelection>::Target, Request = Infallible>,
    Z: Clock,
{
    let limits = settings.limits;

    // The ClientHello, its layers, the target and the parameters.
    let first = read_message(input, limits, None).await?;
    let hello = read_hello(&first).map_err(alert)?;
    check_session_id(&hello)?;
    let accepted = layers
        .open(first, hello)
        .await
        .map_err(|source| alert(ServerAlertError::Layers { source }))?;
    check_hello(accepted.client_hello()).map_err(alert)?;
    let selected = targets
        .select(accepted.client_hello())
        .await
        .map_err(|source| alert(ServerAlertError::Target { source }))?;
    let (chosen, needs_retry) = {
        let offer = ClientOffer::from_client_hello(accepted.client_hello());
        let chosen = choice
            .choose(&backend, &offer, &selected)
            .map_err(|source| alert(ServerAlertError::NoCommonParameters { source }))?;
        if !offer.cipher_suites().contains(&chosen.suite().suite())
            || !offer
                .supported_groups()
                .contains(&chosen.group().algorithm())
        {
            return Err(alert(ServerAlertError::ChoiceNotOffered));
        }
        (chosen, !offer.has_key_share(chosen.group().algorithm()))
    };
    let suite: SupportedSuite<B> = chosen.suite();
    let group = chosen.group();

    // A HelloRetryRequest when the client has no share of the group.
    let (accepted, transcript, retried) = if needs_retry {
        let retry = HelloRetryRequest::new(
            ProtocolVersion::TLS_1_2,
            *accepted.client_hello().legacy_session_id(),
            suite.suite(),
            vec![
                HelloRetryRequestExtension::<Bytes>::SupportedVersions(ProtocolVersion::TLS_1_3),
                HelloRetryRequestExtension::KeyShare(group.algorithm()),
            ],
        )
        // invariant: two short extensions fit the block.
        .expect("a HelloRetryRequest of two extensions");
        let encoded = encode(retry.encoded_len(), |sink| {
            sink.sync_write_hello_retry_request_unpin(&retry)
        });
        write_message(output, &encoded).await?;
        let transcript = Transcript::<Server, B>::new(&backend, suite.hash())
            .add(accepted.encoded().encoded())
            .retry(&encoded);
        let second = read_message(input, limits, None).await?;
        let hello = read_hello(&second).map_err(alert)?;
        check_session_id(&hello)?;
        let accepted = layers
            .open(second, hello)
            .await
            .map_err(|source| alert(ServerAlertError::Layers { source }))?;
        let hello = accepted.client_hello();
        check_hello(hello).map_err(alert)?;
        let offer = ClientOffer::from_client_hello(hello);
        if !offer.cipher_suites().contains(&suite.suite())
            || !offer.supported_groups().contains(&group.algorithm())
        {
            return Err(alert(ServerAlertError::RetryOffer));
        }
        if offer.key_share_groups() != [group.algorithm()] {
            return Err(alert(ServerAlertError::RetryKeyShare));
        }
        (accepted, transcript, true)
    } else {
        let transcript = Transcript::<Server, B>::new(&backend, suite.hash());
        (accepted, transcript, false)
    };
    let hello = accepted.client_hello();
    let encoded = accepted.encoded().encoded().clone();
    let client_share = hello
        .key_share()
        .and_then(|shares| shares.get(group.algorithm()))
        // invariant: without a share of the group, the server asked for one,
        // and the second ClientHello was checked to carry it.
        .expect("a share of the chosen group");
    let peer_parameters = transport_parameters(hello)
        // invariant: `check_hello` requires the extension.
        .expect("transport parameters")
        .clone();

    // Whether the client resumes with psk_dhe_ke, the one mode the server
    // takes: it restricts both the offered tickets and the issued ones
    // (RFC 9846 §4.3.9).
    let psk_dhe =
        psk_modes(hello).is_some_and(|modes| modes.contains(&PskKeyExchangeMode::PSK_DHE_KE));

    // An offered ticket, with its binder.
    let offered: Option<&OfferedPsks<Bytes>> = hello.pre_shared_key().filter(|_| psk_dhe);
    let opened = match offered {
        Some(offered) => match tickets.open(offered).await {
            Some((index, opened)) => {
                if usize::from(index.get()) >= offered.identities().len() {
                    return Err(alert(ServerAlertError::TicketIndex { index }));
                }
                let state = opened.state();
                let fits = state.resumable.suite.hash() == Some(suite.hash().algorithm())
                    && state.resumable.target == selected.target;
                fits.then_some((index, opened))
            }
            None => None,
        },
        None => None,
    };
    let early = match &opened {
        Some((index, opened)) => {
            // invariant: a ClientHello with `pre_shared_key` has binders.
            let covered = encoded.len() - hello.binders_len().expect("binders");
            let early = transcript
                .add(&encoded[..covered])
                .early_secret_with_psk(copy_psk(opened.psk()));
            // invariant: the index was checked against the identities, and
            // there is one binder for each.
            let binder = &offered.expect("an offer").binders()[usize::from(index.get())];
            early
                .verify_binder(binder.binder().as_ref())
                .map_err(|source| alert(ServerAlertError::Binder { source }))?;
            Early::Psk(early.add(&encoded[covered..]), *index)
        }
        None => Early::Plain(transcript.add(&encoded).early_secret()),
    };

    // The transport parameters, and 0-RTT by all three.
    let negotiated = transport
        .negotiate(
            &peer_parameters,
            &selected,
            opened.as_ref().map(|(_, opened)| opened.state()),
        )
        .map_err(|error| HandshakeError::Transport { source: error })?;
    let zero_rtt = match (opened, &early) {
        (Some((index, opened)), Early::Psk(early, _)) => {
            let state = opened.state();
            let offered_age = offered.expect("an offer").identities()[usize::from(index.get())]
                .obfuscated_ticket_age();
            let handshake_allows = !retried
                && index == PskIndex::new(0)
                && hello
                    .extensions()
                    .iter()
                    .any(|extension| matches!(extension, ClientHelloExtension::EarlyData))
                && state.early_data
                && state.resumable.suite == suite.suite()
                && state.resumable.application_protocol == selected.application_protocol
                && ticket_age_fits(
                    state,
                    offered_age,
                    clock.now(),
                    settings.ticket_age_tolerance,
                );
            if handshake_allows && negotiated.early_data {
                let mut digest = Hash::start(&backend, suite.hash());
                digest.update(&encoded);
                let key = ClientHelloKey::new(digest.finish());
                opened
                    .admit_early_data(&key)
                    .await
                    .then(|| early.early_receive())
            } else {
                None
            }
        }
        _ => None,
    };
    let early_data = zero_rtt.is_some();

    // The ServerHello and the Handshake secrets.
    let (server_share, shared) =
        KeyExchange::server_share(&backend, group, client_share.key_exchange().as_ref())
            .map_err(|source| alert(ServerAlertError::KeyExchange { source }))?;
    let random: [u8; 32] =
        Random::random(&backend).map_err(|source| alert(ServerAlertError::Random { source }))?;
    if let Some(never) = accepted.confirmation() {
        match *never {}
    }
    let mut extensions = vec![
        ServerHelloExtension::SupportedVersions(ProtocolVersion::TLS_1_3),
        ServerHelloExtension::KeyShare(
            KeyShareEntry::new(
                group.algorithm(),
                Bytes::copy_from_slice(server_share.as_bytes()),
            )
            // invariant: a backend's share is the size of its group's share.
            .expect("a key share of the group"),
        ),
    ];
    let resumed = matches!(early, Early::Psk(..));
    if let Early::Psk(_, index) = &early {
        extensions.push(ServerHelloExtension::PreSharedKey(*index));
    }
    let server_hello = ServerHello::new(
        ProtocolVersion::TLS_1_2,
        HelloRandom(random),
        *hello.legacy_session_id(),
        suite.suite(),
        extensions,
    )
    // invariant: three short extensions fit the block, and a random equal to
    // that of a HelloRetryRequest is a broken backend.
    .expect("a ServerHello of three extensions");
    let encoded_hello = encode(server_hello.encoded_len(), |sink| {
        sink.sync_write_server_hello_unpin(&server_hello)
    });
    write_message(output, &encoded_hello).await?;
    let (handshake, secrets) = match early {
        Early::Plain(early) => early.server_hello(shared, &encoded_hello),
        Early::Psk(early, _) => early.server_hello(shared, &encoded_hello),
    };
    yield ServerHandshakeEvent::ServerHelloWritten {
        aead: suite.aead(),
        secrets,
        zero_rtt,
    };
    output.move_to(CryptoLevel::Handshake);
    input.move_to(CryptoLevel::Handshake).map_err(connection)?;

    // EncryptedExtensions.
    if let Some(never) = accepted.retry_configs() {
        match *never {}
    }
    let mut extensions = Vec::new();
    if let Some(protocol) = &selected.application_protocol {
        extensions.push(
            EncryptedExtensionsExtension::ApplicationLayerProtocolNegotiation(protocol.clone()),
        );
    }
    if early_data {
        extensions.push(EncryptedExtensionsExtension::EarlyData);
    }
    extensions.push(EncryptedExtensionsExtension::QuicTransportParameters(
        negotiated.local.clone(),
    ));
    let encrypted = EncryptedExtensions::new(extensions)
        .map_err(|source| alert(ServerAlertError::EncryptedExtensions { source }))?;
    let encoded = encode(encrypted.encoded_len(), |sink| {
        sink.sync_write_encrypted_extensions_unpin(&encrypted)
    });
    write_message(output, &encoded).await?;
    let mut handshake = handshake.add(&encoded);

    // Certificate and CertificateVerify, unless the PSK authenticates.
    if !resumed {
        if let Some(never) = peer.request(&selected) {
            match never {}
        }
        let offered =
            hello
                .signature_algorithms()
                .ok_or(alert(ServerAlertError::MissingExtension {
                    extension: RequiredExtension::SignatureAlgorithms,
                }))?;
        let presented = identity
            .present(&selected, offered.as_slice())
            .map_err(|source| alert(ServerAlertError::NoCommonScheme { source }))?;
        let entries = presented
            .certificates()
            .iter()
            .map(|certificate| CertificateEntry::new(certificate.clone(), Vec::new()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| alert(ServerAlertError::CertificateEntry { source }))?;
        let certificate = Certificate::new(Bytes::new(), CertificateList::X509(entries))
            .map_err(|source| alert(ServerAlertError::Certificate { source }))?;
        let encoded = encode(certificate.encoded_len(), |sink| {
            sink.sync_write_certificate_unpin(&certificate)
        });
        write_message(output, &encoded).await?;
        handshake = handshake.add(&encoded);
        let content = handshake.certificate_verify_content();
        let signature = presented
            .sign(content.as_bytes())
            .await
            .map_err(|source| alert(ServerAlertError::Signing { source }))?;
        let verify = CertificateVerify::new(
            presented.scheme(),
            Bytes::copy_from_slice(signature.as_bytes()),
        )
        .map_err(|source| alert(ServerAlertError::SignatureLength { source }))?;
        let encoded = encode(verify.encoded_len(), |sink| {
            sink.sync_write_certificate_verify_unpin(&verify)
        });
        write_message(output, &encoded).await?;
        handshake = handshake.add(&encoded);
    }

    // The server's Finished, then the client's.
    let (master, finished, one_rtt_send) = handshake.server_finished();
    write_message(output, finished.encoded()).await?;
    yield ServerHandshakeEvent::ServerFinishedWritten(one_rtt_send);
    let received = read_message(input, limits, Some(suite.hash().algorithm())).await?;
    let (resumption, completed) = master
        .client_finished(&received)
        .map_err(|source| alert(ServerAlertError::Finished { source }))?;
    yield ServerHandshakeEvent::Completed {
        one_rtt_receive: completed.one_rtt_receive,
        exporter: completed.exporter,
        selected: selected.clone(),
        resumed,
    };
    output.move_to(CryptoLevel::OneRtt);
    input.move_to(CryptoLevel::OneRtt).map_err(connection)?;

    // The tickets, none when the client cannot resume with them.
    if !psk_dhe {
        return Ok(());
    }
    let session = Resumable {
        suite: suite.suite(),
        application_protocol: selected.application_protocol.clone(),
        target: selected.target.clone(),
        transport_parameters: negotiated.local.data().clone(),
    };
    let mut issuing = tickets.issuing(&session);
    let mut count: u64 = 0;
    while let Some(slot) = issuing.next().await {
        // invariant: eight bytes are within the 255 of a nonce.
        let nonce = TicketNonce::new(Bytes::copy_from_slice(&count.to_be_bytes()))
            .expect("an eight-byte nonce");
        count += 1;
        let ticket_age_add = u32::from_be_bytes(
            Random::random(&backend)
                .map_err(|source| alert(ServerAlertError::Random { source }))?,
        );
        let ticket = slot
            .seal(resumption.ticket_psk(&nonce), &nonce, ticket_age_add)
            .await
            .map_err(|source| alert(ServerAlertError::Ticket { source }))?;
        let mut extensions = Vec::new();
        if ticket.early_data() {
            extensions.push(NewSessionTicketExtension::EarlyData(MaxEarlyDataSize::QUIC));
        }
        let message = NewSessionTicket::new(
            ticket.lifetime(),
            ticket_age_add,
            nonce,
            ticket.ticket().clone(),
            extensions,
        )
        // invariant: `Ticket` holds 1 to 65535 bytes, and one extension fits
        // the block.
        .expect("a NewSessionTicket of a ticket");
        let encoded = encode(message.encoded_len(), |sink| {
            sink.sync_write_new_session_ticket_unpin(&message)
        });
        write_message(output, &encoded).await?;
    }
    Ok(())
}
