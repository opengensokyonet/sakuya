//! The server's and the client's handshake engines run against each other,
//! over CRYPTO streams in memory.
//!
//! Each side has a byte buffer per level for what it receives and for what
//! it sends; between polls, what one side sent moves to the other side's
//! buffers of the same level, where a test may change it on the way. The
//! server presents an Ed25519 certificate for example.com, issued by an
//! Ed25519 root that the client's verifier alone trusts; both are built
//! here and signed with nitori_crypto_aws_lc.

use bytes::{Buf, BufMut, Bytes};
use core::{
    future::Future,
    ops::ControlFlow,
    pin::{Pin, pin},
    task::{Context, Poll, Waker},
};
use nitori_call::{BorrowedReceiver, LentCall, Receiver, family_receiver};
use nitori_crypto::{ExpandLength, NamedGroup, SignatureScheme, SigningKey};
use nitori_crypto_aws_lc::{AwsLcBackend, Ed25519SigningKey};
use nitori_io::{Read, Write};
use sakuya_tls::{
    alert::AlertDescription,
    cipher_suite::CipherSuite,
    client::{
        ServerTarget,
        engine::{
            ClientAlertError, ClientHandshake, ClientHandshakeEvent, ClientHandshakeSettings,
            ClientTransport, EarlyDataOutcome, ServerIdentity,
        },
        offering::{Offering, PreferenceOffering},
        ticket::TakeOnceTicketMap,
    },
    clock::ManualClock,
    engine::{CryptoInput, CryptoLevel, CryptoOutput, HandshakeError},
    extension::{
        OpaqueData,
        alpn::{ProtocolName, ProtocolNameList},
    },
    message::{HandshakeType, new_session_ticket::TicketLifetime},
    schedule::{CertificateVerifyError, ExporterLabel, FinishedError},
    server::{
        choice::{GroupPreference, PreferenceTable},
        engine::{
            Negotiated, ServerAlertError, ServerHandshake, ServerHandshakeEvent,
            ServerHandshakeSettings, ServerTransport,
        },
        identity::CertifiedKey,
        layers::PassThroughLayers,
        peer::NoClientCertificate,
        targets::{Selected, SniTargets},
        ticket::{SingleUseTicketTable, TicketState},
    },
    verify::{
        AnchorStore, NoRevocationCheck, SpkiDistrustList, SubjectPublicKey, WebPkiVerifier,
        transparency::{EmbeddedSctPolicy, LogList, StaleLogList},
    },
};
use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, SystemTime},
};

/// 2026-11-04T00:00:00Z.
fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_793_750_400)
}

mod pki {
    //! An Ed25519 root and a certificate it issues, in DER.

    use super::*;

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match content.len() {
            len @ 0..=127 => out.push(len as u8),
            len @ 128..=255 => out.extend([0x81, len as u8]),
            len => out.extend([0x82, (len >> 8) as u8, len as u8]),
        }
        out.extend_from_slice(content);
        out
    }

    fn seq(parts: &[&[u8]]) -> Vec<u8> {
        tlv(0x30, &parts.concat())
    }

    fn name(common_name: &str) -> Vec<u8> {
        let attribute = seq(&[
            &tlv(0x06, &[0x55, 0x04, 0x03]),
            &tlv(0x0c, common_name.as_bytes()),
        ]);
        seq(&[&tlv(0x31, &attribute)])
    }

    /// id-Ed25519 as an AlgorithmIdentifier.
    fn ed25519() -> Vec<u8> {
        seq(&[&tlv(0x06, &[0x2b, 0x65, 0x70])])
    }

    fn bits(bytes: &[u8]) -> Vec<u8> {
        tlv(0x03, &[&[0], bytes].concat())
    }

    pub fn spki(public_key: &[u8]) -> Vec<u8> {
        seq(&[&ed25519(), &bits(public_key)])
    }

    fn extension(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
        let critical = if critical {
            tlv(0x01, &[0xff])
        } else {
            Vec::new()
        };
        seq(&[&tlv(0x06, oid), &critical, &tlv(0x04, value)])
    }

    /// The key of a 32-byte Ed25519 seed, from a PKCS#8 v1 document.
    pub fn key(seed: u8) -> Ed25519SigningKey {
        let mut pkcs8 = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        pkcs8.extend([seed; 32]);
        Ed25519SigningKey::from_pkcs8(&pkcs8).unwrap()
    }

    fn certificate(
        serial: u8,
        issuer: &str,
        subject: &str,
        public_key: &[u8],
        extensions: &[Vec<u8>],
        signer: &Ed25519SigningKey,
    ) -> Vec<u8> {
        let extensions: Vec<&[u8]> = extensions.iter().map(Vec::as_slice).collect();
        let validity = seq(&[&tlv(0x17, b"250101000000Z"), &tlv(0x17, b"491231235959Z")]);
        let tbs = seq(&[
            &tlv(0xa0, &tlv(0x02, &[2])),
            &tlv(0x02, &[serial]),
            &ed25519(),
            &name(issuer),
            &validity,
            &name(subject),
            &spki(public_key),
            &tlv(0xa3, &seq(&extensions)),
        ]);
        let signature = super::ready(signer.sign(SignatureScheme::ED25519, &tbs)).unwrap();
        seq(&[&tbs, &ed25519(), &bits(signature.as_bytes())])
    }

    /// The root, self-signed by `key(1)`.
    pub fn root() -> Vec<u8> {
        let root = key(1);
        let basic_constraints = extension(&[0x55, 0x1d, 0x13], true, &seq(&[&tlv(0x01, &[0xff])]));
        certificate(
            1,
            "Test Root",
            "Test Root",
            root.public_key(),
            &[basic_constraints],
            &root,
        )
    }

    /// The certificate of `key(2)` for example.com, issued by the root.
    pub fn leaf() -> Vec<u8> {
        let alternative_names = extension(
            &[0x55, 0x1d, 0x11],
            false,
            &seq(&[&tlv(0x82, b"example.com")]),
        );
        let server_auth = extension(
            &[0x55, 0x1d, 0x25],
            false,
            &seq(&[&tlv(
                0x06,
                &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01],
            )]),
        );
        certificate(
            2,
            "Test Root",
            "example.com",
            key(2).public_key(),
            &[alternative_names, server_auth],
            &key(1),
        )
    }
}

/// The output of a future that is ready at once.
fn ready<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("future not ready"),
    }
}

/// A failure of the receivers in memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    /// Bytes of the level left were not read.
    Unread(CryptoLevel),
    /// The transport parameters were refused.
    Parameters,
}

fn index(level: CryptoLevel) -> usize {
    match level {
        CryptoLevel::Initial => 0,
        CryptoLevel::Handshake => 1,
        CryptoLevel::OneRtt => 2,
    }
}

const LEVELS: [CryptoLevel; 3] = [
    CryptoLevel::Initial,
    CryptoLevel::Handshake,
    CryptoLevel::OneRtt,
];

/// What one side receives: a buffer per level and the current level.
struct Incoming {
    levels: [VecDeque<u8>; 3],
    current: CryptoLevel,
}

impl Default for Incoming {
    fn default() -> Self {
        Self {
            levels: Default::default(),
            current: CryptoLevel::Initial,
        }
    }
}

family_receiver!(impl [] for Incoming);

impl Read for Incoming {
    type Error = Fault;

    fn poll_read<'v, Output: BufMut + ?Sized>(
        host: Pin<&mut BorrowedReceiver<'v, Incoming>>,
        _: &mut Context<'_>,
        destination: &mut Output,
    ) -> Poll<Result<usize, Fault>>
    where
        Self: 'v,
    {
        let incoming = host.get_pin_mut().get_mut();
        let buffer = &mut incoming.levels[index(incoming.current)];
        if buffer.is_empty() {
            return Poll::Pending;
        }
        let len = buffer.len().min(destination.remaining_mut());
        for byte in buffer.drain(..len) {
            destination.put_u8(byte);
        }
        Poll::Ready(Ok(len))
    }
}

impl CryptoInput for Incoming {
    type LevelError = Fault;

    fn move_to<'v>(
        view: Pin<&mut BorrowedReceiver<'v, Incoming>>,
        level: CryptoLevel,
    ) -> Result<(), Fault>
    where
        Self: 'v,
    {
        let incoming = view.get_pin_mut().get_mut();
        if !incoming.levels[index(incoming.current)].is_empty() {
            return Err(Fault::Unread(incoming.current));
        }
        incoming.current = level;
        Ok(())
    }
}

/// What one side sends: a buffer per level and the current level.
struct Outgoing {
    levels: [Vec<u8>; 3],
    current: CryptoLevel,
}

impl Default for Outgoing {
    fn default() -> Self {
        Self {
            levels: Default::default(),
            current: CryptoLevel::Initial,
        }
    }
}

family_receiver!(impl [] for Outgoing);

impl Write for Outgoing {
    type Error = Fault;

    fn poll_write<'v, Input: Buf + ?Sized>(
        host: Pin<&mut BorrowedReceiver<'v, Outgoing>>,
        _: &mut Context<'_>,
        input: &mut Input,
    ) -> Poll<Result<usize, Fault>>
    where
        Self: 'v,
    {
        let outgoing = host.get_pin_mut().get_mut();
        let buffer = &mut outgoing.levels[index(outgoing.current)];
        let len = input.remaining();
        while input.has_remaining() {
            let chunk = input.chunk();
            let chunk_len = chunk.len();
            buffer.extend_from_slice(chunk);
            input.advance(chunk_len);
        }
        Poll::Ready(Ok(len))
    }
}

impl CryptoOutput for Outgoing {
    fn move_to<'v>(view: Pin<&mut BorrowedReceiver<'v, Outgoing>>, level: CryptoLevel)
    where
        Self: 'v,
    {
        view.get_pin_mut().get_mut().current = level;
    }
}

/// The server's connection side of the transport parameters.
struct ServerParameters {
    local: Bytes,
    peer: Option<Bytes>,
    early_data: bool,
    refuse: bool,
}

family_receiver!(impl [] for ServerParameters);

impl ServerTransport<&'static str> for ServerParameters {
    type Error = Fault;

    fn negotiate<'v>(
        view: Pin<&mut BorrowedReceiver<'v, ServerParameters>>,
        peer: &[u8],
        _selected: &Selected<&'static str>,
        resumed: Option<&TicketState<&'static str>>,
    ) -> Result<Negotiated, Fault>
    where
        Self: 'v,
    {
        let parameters = view.get_pin_mut().get_mut();
        if parameters.refuse {
            return Err(Fault::Parameters);
        }
        parameters.peer = Some(Bytes::copy_from_slice(peer));
        let compatible =
            resumed.is_some_and(|state| state.resumable.transport_parameters == parameters.local);
        Ok(Negotiated {
            local: OpaqueData::new(parameters.local.clone()).unwrap(),
            early_data: parameters.early_data && compatible,
        })
    }
}

/// The client's connection side of the transport parameters.
struct ClientParameters {
    local: Bytes,
    peer: Option<Bytes>,
}

family_receiver!(impl [] for ClientParameters);

impl ClientTransport for ClientParameters {
    type Error = Fault;

    fn local<'v>(view: Pin<&mut BorrowedReceiver<'v, ClientParameters>>) -> OpaqueData<Bytes>
    where
        Self: 'v,
    {
        OpaqueData::new(view.get_pin_mut().get_mut().local.clone()).unwrap()
    }

    fn peer<'v>(
        view: Pin<&mut BorrowedReceiver<'v, ClientParameters>>,
        peer: &[u8],
    ) -> Result<(), Fault>
    where
        Self: 'v,
    {
        view.get_pin_mut().get_mut().peer = Some(Bytes::copy_from_slice(peer));
        Ok(())
    }
}

/// Who sent bytes on their way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sender {
    Server,
    Client,
}

/// The receivers of both sides.
struct Wire {
    server_in: Incoming,
    server_out: Outgoing,
    server_parameters: ServerParameters,
    client_in: Incoming,
    client_out: Outgoing,
    client_parameters: ClientParameters,
    /// The messages that went past, by sender and level.
    seen: Vec<(Sender, CryptoLevel, HandshakeType)>,
}

impl Wire {
    fn new() -> Self {
        Self {
            server_in: Incoming::default(),
            server_out: Outgoing::default(),
            server_parameters: ServerParameters {
                local: Bytes::from_static(b"server parameters"),
                peer: None,
                early_data: true,
                refuse: false,
            },
            client_in: Incoming::default(),
            client_out: Outgoing::default(),
            client_parameters: ClientParameters {
                local: Bytes::from_static(b"client parameters"),
                peer: None,
            },
            seen: Vec::new(),
        }
    }

    /// Moves what each side sent to the other, through `change`; whether
    /// anything moved.
    fn deliver(&mut self, change: &mut impl FnMut(Sender, CryptoLevel, &mut Vec<u8>)) -> bool {
        let mut moved = false;
        for (from, out, into) in [
            (Sender::Server, &mut self.server_out, &mut self.client_in),
            (Sender::Client, &mut self.client_out, &mut self.server_in),
        ] {
            for level in LEVELS {
                let mut bytes = core::mem::take(&mut out.levels[index(level)]);
                if bytes.is_empty() {
                    continue;
                }
                for (message_type, _) in messages(&bytes) {
                    self.seen.push((from, level, message_type));
                }
                change(from, level, &mut bytes);
                into.levels[index(level)].extend(bytes);
                moved = true;
            }
        }
        moved
    }

    fn seen(&self, from: Sender, message_type: HandshakeType) -> usize {
        self.seen
            .iter()
            .filter(|&&(sender, _, seen)| sender == from && seen == message_type)
            .count()
    }
}

/// The whole messages in `bytes`, with their ranges.
fn messages(bytes: &[u8]) -> Vec<(HandshakeType, core::ops::Range<usize>)> {
    let mut found = Vec::new();
    let mut at = 0;
    while at + 4 <= bytes.len() {
        let len = u32::from_be_bytes([0, bytes[at + 1], bytes[at + 2], bytes[at + 3]]) as usize;
        let end = (at + 4 + len).min(bytes.len());
        found.push((HandshakeType::new(bytes[at]), at..end));
        at = end;
    }
    found
}

/// Flips the last byte of each message of `message_type` in `bytes`.
fn flip_last(bytes: &mut [u8], message_type: HandshakeType) {
    for (found, range) in messages(bytes) {
        if found == message_type {
            bytes[range.end - 1] ^= 1;
        }
    }
}

/// What a run of both sides left.
struct Run<SE, SF, CE, CF> {
    server_events: Vec<SE>,
    server_end: Option<SF>,
    client_events: Vec<CE>,
    client_end: Option<CF>,
}

/// Polls `server` and `client` in turns, delivering what they send through
/// `change`, until neither moves.
fn run<SE, SF, CE, CF>(
    wire: &mut Wire,
    mut server: impl FnMut(&mut Wire) -> Poll<ControlFlow<SF, SE>>,
    mut client: impl FnMut(&mut Wire) -> Poll<ControlFlow<CF, CE>>,
    mut change: impl FnMut(Sender, CryptoLevel, &mut Vec<u8>),
) -> Run<SE, SF, CE, CF> {
    let mut result = Run {
        server_events: Vec::new(),
        server_end: None,
        client_events: Vec::new(),
        client_end: None,
    };
    for _ in 0..64 {
        let mut progress = false;
        while result.client_end.is_none() {
            match client(wire) {
                Poll::Ready(ControlFlow::Continue(event)) => result.client_events.push(event),
                Poll::Ready(ControlFlow::Break(end)) => result.client_end = Some(end),
                Poll::Pending => break,
            }
            progress = true;
        }
        progress |= wire.deliver(&mut change);
        while result.server_end.is_none() {
            match server(wire) {
                Poll::Ready(ControlFlow::Continue(event)) => result.server_events.push(event),
                Poll::Ready(ControlFlow::Break(end)) => result.server_end = Some(end),
                Poll::Pending => break,
            }
            progress = true;
        }
        progress |= wire.deliver(&mut change);
        if !progress {
            return result;
        }
    }
    panic!("the handshake does not settle");
}

/// What both sides keep across connections.
struct Endpoints {
    clock: Arc<ManualClock>,
    server_tickets: SingleUseTicketTable<&'static str, AwsLcBackend, Arc<ManualClock>>,
    client_tickets: Arc<TakeOnceTicketMap<Arc<ManualClock>>>,
    offering: PreferenceOffering,
    server_protocols: Vec<ProtocolName<Bytes>>,
    group_preference: GroupPreference,
    server_groups: Vec<NamedGroup>,
    /// Whether the server serves its one target to every name.
    fallback: bool,
}

impl Endpoints {
    fn new() -> Self {
        let clock = Arc::new(ManualClock::new(now()));
        Self {
            server_tickets: SingleUseTicketTable::new(
                AwsLcBackend,
                Arc::clone(&clock),
                2,
                TicketLifetime::new(3600).unwrap(),
                true,
                16,
            ),
            client_tickets: Arc::new(TakeOnceTicketMap::new(
                Arc::clone(&clock),
                Duration::from_secs(86_400),
                4,
            )),
            offering: offering(&[NamedGroup::X25519]),
            server_protocols: vec![h3()],
            group_preference: GroupPreference::KeyShareFirst,
            server_groups: vec![NamedGroup::X25519, NamedGroup::SECP256R1],
            fallback: false,
            clock,
        }
    }
}

fn h3() -> ProtocolName<Bytes> {
    ProtocolName::new(Bytes::from_static(b"h3")).unwrap()
}

fn offering(key_shares: &[NamedGroup]) -> PreferenceOffering {
    PreferenceOffering::new(
        vec![
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_AES_256_GCM_SHA384,
        ],
        vec![NamedGroup::X25519, NamedGroup::SECP256R1],
        key_shares.to_vec(),
    )
    .unwrap()
}

type Verifier = WebPkiVerifier<
    AwsLcBackend,
    AnchorStore,
    SpkiDistrustList,
    NoRevocationCheck,
    EmbeddedSctPolicy,
    Arc<ManualClock>,
>;

fn verifier(clock: &Arc<ManualClock>) -> Verifier {
    // The certificates carry no SCTs: a log list past its age skips the CT
    // check.
    let transparency = EmbeddedSctPolicy::with_list_age(
        LogList::new(Vec::new(), SystemTime::UNIX_EPOCH),
        Duration::ZERO,
        StaleLogList::SkipCheck,
    );
    WebPkiVerifier::new(
        AwsLcBackend,
        AnchorStore::from_certificates([pki::root().as_slice()]).unwrap(),
        SpkiDistrustList::default(),
        NoRevocationCheck,
        transparency,
        Arc::clone(clock),
    )
}

fn leaf_key() -> SubjectPublicKey {
    SubjectPublicKey::from_spki(&pki::spki(pki::key(2).public_key())).unwrap()
}

type ServerEvent = ServerHandshakeEvent<AwsLcBackend, &'static str>;
type ClientEvent = ClientHandshakeEvent<AwsLcBackend>;

/// The events and final values of one connection between the endpoints.
struct Connection<SF, CF> {
    wire: Wire,
    server_events: Vec<ServerEvent>,
    server_end: Option<SF>,
    client_events: Vec<ClientEvent>,
    client_end: Option<CF>,
}

/// Runs one connection to `host` with the server's parameters as `wire`
/// has them, through `change`.
macro_rules! connect {
    ($endpoints:expr, $wire:expr, $host:expr, $change:expr) => {{
        let endpoints: &Endpoints = $endpoints;
        let mut wire: Wire = $wire;
        let mut targets = SniTargets::new();
        targets.insert("example.com", "web", endpoints.server_protocols.clone());
        if endpoints.fallback {
            targets.set_fallback("web", endpoints.server_protocols.clone());
        }
        let identity = CertifiedKey::new(vec![Bytes::from(pki::leaf())], pki::key(2)).unwrap();
        let server = ServerHandshake::new(
            AwsLcBackend,
            PreferenceTable::new(
                vec![
                    CipherSuite::TLS_AES_128_GCM_SHA256,
                    CipherSuite::TLS_AES_256_GCM_SHA384,
                ],
                endpoints.server_groups.clone(),
                endpoints.group_preference,
            ),
            endpoints.server_tickets.clone(),
            PassThroughLayers,
            targets,
            identity,
            NoClientCertificate,
            Arc::clone(&endpoints.clock),
            ServerHandshakeSettings::default(),
        );
        let client = ClientHandshake::new(
            AwsLcBackend,
            endpoints.offering.clone(),
            Arc::clone(&endpoints.client_tickets),
            verifier(&endpoints.clock),
            Arc::clone(&endpoints.clock),
            ServerTarget::from_host_name($host).unwrap(),
            Some(ProtocolNameList::new(vec![h3()]).unwrap()),
            ClientHandshakeSettings::default(),
        );
        let mut server = pin!(LentCall::<(Incoming, Outgoing, ServerParameters,), _>::new(
            server
        ));
        let mut client = pin!(LentCall::<(Incoming, Outgoing, ClientParameters,), _>::new(
            client
        ));
        let run = run(
            &mut wire,
            |wire| {
                let mut input = pin!(Pin::new(&mut wire.server_in).view());
                let mut output = pin!(Pin::new(&mut wire.server_out).view());
                let mut parameters = pin!(Pin::new(&mut wire.server_parameters).view());
                server.as_mut().poll_with_views(
                    (input.as_mut(), output.as_mut(), parameters.as_mut()),
                    &mut Context::from_waker(Waker::noop()),
                )
            },
            |wire| {
                let mut input = pin!(Pin::new(&mut wire.client_in).view());
                let mut output = pin!(Pin::new(&mut wire.client_out).view());
                let mut parameters = pin!(Pin::new(&mut wire.client_parameters).view());
                client.as_mut().poll_with_views(
                    (input.as_mut(), output.as_mut(), parameters.as_mut()),
                    &mut Context::from_waker(Waker::noop()),
                )
            },
            $change,
        );
        Connection {
            wire,
            server_events: run.server_events,
            server_end: run.server_end,
            client_events: run.client_events,
            client_end: run.client_end,
        }
    }};
}

fn unchanged(_: Sender, _: CryptoLevel, _: &mut Vec<u8>) {}

/// The secrets and facts of a completed connection, checked to agree on
/// both sides.
struct Agreed {
    resumed: bool,
    zero_rtt: bool,
    identity: ServerIdentity,
    early_data: EarlyDataOutcome,
}

fn agreed(server_events: &[ServerEvent], client_events: &[ClientEvent]) -> Agreed {
    let mut server = server_events.iter();
    let mut client = client_events.iter();
    let label = ExporterLabel::new(b"EXPORTER-test").unwrap();
    let len = ExpandLength::new(32).unwrap();

    let Some(ServerHandshakeEvent::HandshakeKeys {
        aead: server_aead,
        keys: server_keys,
        zero_rtt,
    }) = server.next()
    else {
        panic!("no Handshake secrets from the server")
    };
    let mut client_event = client.next();
    let zero_rtt_sent = match client_event {
        Some(ClientHandshakeEvent::ZeroRttKeys { aead, keys, .. }) => {
            if let Some(received) = zero_rtt {
                assert_eq!(received.0.as_bytes(), keys.0.as_bytes());
                assert_eq!(aead, server_aead);
            }
            client_event = client.next();
            true
        }
        _ => false,
    };
    let Some(ClientHandshakeEvent::HandshakeKeys {
        aead: client_aead,
        keys: client_keys,
    }) = client_event
    else {
        panic!("no Handshake secrets for the client")
    };
    assert_eq!(server_aead, client_aead);
    assert_eq!(server_keys.send.as_bytes(), client_keys.receive.as_bytes());
    assert_eq!(server_keys.receive.as_bytes(), client_keys.send.as_bytes());
    assert_ne!(server_keys.send.as_bytes(), server_keys.receive.as_bytes());

    let Some(ServerHandshakeEvent::OneRttSend(server_send)) = server.next() else {
        panic!("no 1-RTT secret from the server")
    };
    let Some(ServerHandshakeEvent::Completed {
        one_rtt_receive,
        exporter: server_exporter,
        selected,
        resumed,
    }) = server.next()
    else {
        panic!("the server did not complete")
    };
    let Some(ClientHandshakeEvent::Completed {
        keys,
        exporter: client_exporter,
        identity,
        application_protocol,
        early_data,
    }) = client.next()
    else {
        panic!("the client did not complete")
    };
    assert!(server.next().is_none() && client.next().is_none());
    assert_eq!(server_send.0.as_bytes(), keys.receive.as_bytes());
    assert_eq!(one_rtt_receive.as_bytes(), keys.send.as_bytes());
    assert_ne!(keys.send.as_bytes(), client_keys.send.as_bytes());
    assert_eq!(
        server_exporter.export(&label, b"context", len).as_bytes(),
        client_exporter.export(&label, b"context", len).as_bytes()
    );
    assert_ne!(
        server_exporter.export(&label, b"context", len).as_bytes(),
        client_exporter.export(&label, b"other", len).as_bytes()
    );
    assert_eq!(selected.target, "web");
    assert_eq!(selected.application_protocol, Some(h3()));
    assert_eq!(application_protocol, &Some(h3()));
    assert_eq!(
        zero_rtt.is_some(),
        *early_data == EarlyDataOutcome::Accepted
    );
    if !zero_rtt_sent {
        assert_eq!(*early_data, EarlyDataOutcome::NotOffered);
    }
    Agreed {
        resumed: *resumed,
        zero_rtt: zero_rtt.is_some(),
        identity: identity.clone(),
        early_data: *early_data,
    }
}

/// The alert a side ended with.
fn alert_of<F: sakuya_tls::alert::CallsForAlert, E: core::fmt::Debug>(
    end: Option<Result<(), HandshakeError<F, E>>>,
) -> AlertDescription {
    match end {
        Some(Err(error)) => error.alert().expect("an alert"),
        Some(Ok(())) => panic!("the side succeeded"),
        None => panic!("the side did not end"),
    }
}

#[test]
fn a_full_handshake_agrees_on_every_secret() {
    let endpoints = Endpoints::new();
    let connection = connect!(&endpoints, Wire::new(), "example.com", unchanged);
    assert!(matches!(connection.server_end, Some(Ok(()))));
    // The client keeps reading tickets.
    assert!(connection.client_end.is_none());
    let agreed = agreed(&connection.server_events, &connection.client_events);
    assert!(!agreed.resumed && !agreed.zero_rtt);
    assert_eq!(agreed.identity, ServerIdentity::Verified(leaf_key()));
    assert_eq!(agreed.early_data, EarlyDataOutcome::NotOffered);
    let wire = &connection.wire;
    assert_eq!(
        wire.server_parameters.peer.as_deref(),
        Some(&b"client parameters"[..])
    );
    assert_eq!(
        wire.client_parameters.peer.as_deref(),
        Some(&b"server parameters"[..])
    );
    assert_eq!(wire.seen(Sender::Server, HandshakeType::SERVER_HELLO), 1);
    assert_eq!(wire.seen(Sender::Server, HandshakeType::CERTIFICATE), 1);
    assert_eq!(
        wire.seen(Sender::Server, HandshakeType::CERTIFICATE_VERIFY),
        1
    );
    assert_eq!(
        wire.seen(Sender::Server, HandshakeType::NEW_SESSION_TICKET),
        2
    );
    assert!(wire.seen.contains(&(
        Sender::Client,
        CryptoLevel::Handshake,
        HandshakeType::FINISHED
    )));
    assert!(wire.seen.contains(&(
        Sender::Server,
        CryptoLevel::OneRtt,
        HandshakeType::NEW_SESSION_TICKET
    )));
    // Every byte was read at its level.
    for side in [&wire.server_in, &wire.client_in] {
        assert!(side.levels.iter().all(VecDeque::is_empty));
        assert_eq!(side.current, CryptoLevel::OneRtt);
    }
}

#[test]
fn a_hello_retry_request_moves_the_key_share() {
    let mut endpoints = Endpoints::new();
    endpoints.offering = offering(&[NamedGroup::SECP256R1]);
    endpoints.group_preference = GroupPreference::TableOrder;
    let connection = connect!(&endpoints, Wire::new(), "example.com", unchanged);
    assert!(matches!(connection.server_end, Some(Ok(()))));
    let agreed = agreed(&connection.server_events, &connection.client_events);
    assert!(!agreed.resumed);
    let wire = &connection.wire;
    // The HelloRetryRequest and the ServerHello, after two ClientHellos.
    assert_eq!(wire.seen(Sender::Server, HandshakeType::SERVER_HELLO), 2);
    assert_eq!(wire.seen(Sender::Client, HandshakeType::CLIENT_HELLO), 2);
    // The offering remembers the group the server asked for.
    let target = ServerTarget::from_host_name("example.com").unwrap();
    let support = verifier(&endpoints.clock).support();
    let (offer, _) =
        Offering::<AwsLcBackend>::offer(&endpoints.offering, &AwsLcBackend, &target, &support)
            .unwrap();
    let shared: Vec<_> = offer
        .key_share_groups()
        .iter()
        .map(|group| group.algorithm())
        .collect();
    assert_eq!(shared, [NamedGroup::X25519]);
    let again = connect!(&endpoints, Wire::new(), "example.com", unchanged);
    assert_eq!(
        again.wire.seen(Sender::Server, HandshakeType::SERVER_HELLO),
        1
    );
}

use sakuya_tls::verify::CertificateVerifier as _;

#[test]
fn a_ticket_resumes_with_0_rtt_accepted() {
    let endpoints = Endpoints::new();
    let first = connect!(&endpoints, Wire::new(), "example.com", unchanged);
    agreed(&first.server_events, &first.client_events);
    let second = connect!(&endpoints, Wire::new(), "example.com", unchanged);
    assert!(matches!(second.server_end, Some(Ok(()))));
    assert!(matches!(
        second.client_events.first(),
        Some(ClientHandshakeEvent::ZeroRttKeys { transport_parameters, application_protocol, .. })
            if transport_parameters.as_ref() == b"server parameters"
                && application_protocol == &Some(h3())
    ));
    let resumed = agreed(&second.server_events, &second.client_events);
    assert!(resumed.resumed && resumed.zero_rtt);
    assert_eq!(resumed.early_data, EarlyDataOutcome::Accepted);
    assert_eq!(resumed.identity, ServerIdentity::Resumed(leaf_key()));
    let wire = &second.wire;
    assert_eq!(wire.seen(Sender::Server, HandshakeType::CERTIFICATE), 0);
    assert_eq!(
        wire.seen(Sender::Server, HandshakeType::CERTIFICATE_VERIFY),
        0
    );
    // The resumed connection issues tickets of its own, which resume again.
    assert_eq!(
        wire.seen(Sender::Server, HandshakeType::NEW_SESSION_TICKET),
        2
    );
    let third = connect!(&endpoints, Wire::new(), "example.com", unchanged);
    let agreed = agreed(&third.server_events, &third.client_events);
    assert!(agreed.resumed);
    assert_eq!(agreed.identity, ServerIdentity::Resumed(leaf_key()));
}

#[test]
fn the_connection_can_reject_0_rtt() {
    let endpoints = Endpoints::new();
    connect!(&endpoints, Wire::new(), "example.com", unchanged);
    let mut wire = Wire::new();
    wire.server_parameters.early_data = false;
    let second = connect!(&endpoints, wire, "example.com", unchanged);
    assert!(matches!(second.server_end, Some(Ok(()))));
    let agreed = agreed(&second.server_events, &second.client_events);
    assert!(agreed.resumed && !agreed.zero_rtt);
    assert_eq!(agreed.early_data, EarlyDataOutcome::Rejected);
}

#[test]
fn a_retry_rejects_0_rtt_but_resumes() {
    let mut endpoints = Endpoints::new();
    connect!(&endpoints, Wire::new(), "example.com", unchanged);
    // The server now wants a group the client does not share.
    endpoints.server_groups = vec![NamedGroup::SECP256R1, NamedGroup::X25519];
    endpoints.group_preference = GroupPreference::TableOrder;
    let second = connect!(&endpoints, Wire::new(), "example.com", unchanged);
    assert!(matches!(second.server_end, Some(Ok(()))));
    assert_eq!(
        second
            .wire
            .seen(Sender::Server, HandshakeType::SERVER_HELLO),
        2
    );
    let agreed = agreed(&second.server_events, &second.client_events);
    assert!(agreed.resumed && !agreed.zero_rtt);
    assert_eq!(agreed.early_data, EarlyDataOutcome::Rejected);
}

#[test]
fn a_ticket_without_0_rtt_resumes_without_offering_it() {
    let mut endpoints = Endpoints::new();
    endpoints.server_tickets = SingleUseTicketTable::new(
        AwsLcBackend,
        Arc::clone(&endpoints.clock),
        1,
        TicketLifetime::new(3600).unwrap(),
        false,
        16,
    );
    connect!(&endpoints, Wire::new(), "example.com", unchanged);
    let second = connect!(&endpoints, Wire::new(), "example.com", unchanged);
    let agreed = agreed(&second.server_events, &second.client_events);
    assert!(agreed.resumed && !agreed.zero_rtt);
    assert_eq!(agreed.early_data, EarlyDataOutcome::NotOffered);
}

#[test]
fn a_changed_server_finished_fails_with_decrypt_error() {
    let endpoints = Endpoints::new();
    let connection = connect!(&endpoints, Wire::new(), "example.com", |from,
                                                                       level,
                                                                       bytes: &mut Vec<
        u8,
    >| {
        if from == Sender::Server && level == CryptoLevel::Handshake {
            flip_last(bytes, HandshakeType::FINISHED);
        }
    });
    let end = connection.client_end;
    assert!(matches!(
        end.as_ref().and_then(|end| end.as_ref().err()?.failure()),
        Some(ClientAlertError::Finished {
            source: FinishedError::Mismatch
        })
    ));
    assert_eq!(alert_of(end), AlertDescription::DECRYPT_ERROR);
    assert!(connection.server_end.is_none());
}

#[test]
fn a_changed_client_finished_fails_with_decrypt_error() {
    let endpoints = Endpoints::new();
    let connection = connect!(&endpoints, Wire::new(), "example.com", |from,
                                                                       level,
                                                                       bytes: &mut Vec<
        u8,
    >| {
        if from == Sender::Client && level == CryptoLevel::Handshake {
            flip_last(bytes, HandshakeType::FINISHED);
        }
    });
    let end = connection.server_end;
    assert!(matches!(
        end.as_ref().and_then(|end| end.as_ref().err()?.failure()),
        Some(ServerAlertError::Finished {
            source: FinishedError::Mismatch
        })
    ));
    assert_eq!(alert_of(end), AlertDescription::DECRYPT_ERROR);
    // The server completes nothing.
    assert!(
        !connection
            .server_events
            .iter()
            .any(|event| matches!(event, ServerHandshakeEvent::Completed { .. }))
    );
}

#[test]
fn a_changed_signature_fails_with_decrypt_error() {
    let endpoints = Endpoints::new();
    let connection = connect!(&endpoints, Wire::new(), "example.com", |from,
                                                                       _,
                                                                       bytes: &mut Vec<
        u8,
    >| {
        if from == Sender::Server {
            flip_last(bytes, HandshakeType::CERTIFICATE_VERIFY);
        }
    });
    let end = connection.client_end;
    assert!(matches!(
        end.as_ref().and_then(|end| end.as_ref().err()?.failure()),
        Some(ClientAlertError::CertificateVerify {
            source: CertificateVerifyError::Signature { .. }
        })
    ));
    assert_eq!(alert_of(end), AlertDescription::DECRYPT_ERROR);
}

#[test]
fn a_scheme_that_does_not_fit_the_key_fails_with_illegal_parameter() {
    let endpoints = Endpoints::new();
    let connection = connect!(&endpoints, Wire::new(), "example.com", |from,
                                                                       _,
                                                                       bytes: &mut Vec<
        u8,
    >| {
        if from == Sender::Server {
            for (found, range) in messages(bytes) {
                if found == HandshakeType::CERTIFICATE_VERIFY {
                    // ecdsa_secp256r1_sha256, which the client offers, for
                    // the Ed25519 key of the certificate.
                    bytes[range.start + 4..range.start + 6].copy_from_slice(&[0x04, 0x03]);
                }
            }
        }
    });
    let end = connection.client_end;
    assert!(matches!(
        end.as_ref().and_then(|end| end.as_ref().err()?.failure()),
        Some(ClientAlertError::SchemeKey { .. })
    ));
    assert_eq!(alert_of(end), AlertDescription::ILLEGAL_PARAMETER);
}

#[test]
fn without_a_common_application_protocol_the_server_fails() {
    let mut endpoints = Endpoints::new();
    endpoints.server_protocols = vec![ProtocolName::new(Bytes::from_static(b"h2")).unwrap()];
    let connection = connect!(&endpoints, Wire::new(), "example.com", unchanged);
    assert_eq!(
        alert_of(connection.server_end),
        AlertDescription::NO_APPLICATION_PROTOCOL
    );
    assert!(connection.server_events.is_empty());
}

#[test]
fn a_certificate_for_another_name_fails_with_bad_certificate() {
    let mut endpoints = Endpoints::new();
    // The server serves its certificate for example.com to every name.
    endpoints.fallback = true;
    let connection = connect!(&endpoints, Wire::new(), "example.net", unchanged);
    assert_eq!(
        alert_of(connection.client_end),
        AlertDescription::BAD_CERTIFICATE
    );
}

#[test]
fn a_changed_binder_fails_with_decrypt_error() {
    let endpoints = Endpoints::new();
    connect!(&endpoints, Wire::new(), "example.com", unchanged);
    let second = connect!(&endpoints, Wire::new(), "example.com", |from,
                                                                   _,
                                                                   bytes: &mut Vec<
        u8,
    >| {
        if from == Sender::Client {
            // The binder ends the ClientHello.
            flip_last(bytes, HandshakeType::CLIENT_HELLO);
        }
    });
    let end = second.server_end;
    assert!(matches!(
        end.as_ref().and_then(|end| end.as_ref().err()?.failure()),
        Some(ServerAlertError::Binder { .. })
    ));
    assert_eq!(alert_of(end), AlertDescription::DECRYPT_ERROR);
}

#[test]
fn refused_transport_parameters_fail_through_the_connection() {
    let endpoints = Endpoints::new();
    let mut wire = Wire::new();
    wire.server_parameters.refuse = true;
    let connection = connect!(&endpoints, wire, "example.com", unchanged);
    match connection.server_end {
        Some(Err(error)) => {
            assert_eq!(error.transport(), Some(&Fault::Parameters));
            assert!(error.alert().is_none());
        }
        _ => panic!("the server did not fail"),
    }
}

#[test]
fn bytes_left_unread_at_a_level_fail_through_the_connection() {
    let endpoints = Endpoints::new();
    let connection = connect!(&endpoints, Wire::new(), "example.com", |from,
                                                                       level,
                                                                       bytes: &mut Vec<
        u8,
    >| {
        if from == Sender::Client && level == CryptoLevel::Initial {
            // The start of a message after the ClientHello.
            bytes.push(HandshakeType::CLIENT_HELLO.get());
        }
    });
    match connection.server_end {
        Some(Err(error)) => {
            assert_eq!(
                error.transport(),
                Some(&Fault::Unread(CryptoLevel::Initial))
            );
        }
        _ => panic!("the server did not fail"),
    }
}

#[test]
fn a_key_update_after_the_handshake_fails_with_unexpected_message() {
    let endpoints = Endpoints::new();
    let connection = connect!(&endpoints, Wire::new(), "example.com", |from,
                                                                       level,
                                                                       bytes: &mut Vec<
        u8,
    >| {
        if from == Sender::Server && level == CryptoLevel::OneRtt {
            // KeyUpdate, which QUIC does not carry (RFC 9001 §6).
            bytes.extend([HandshakeType::KEY_UPDATE.get(), 0, 0, 1, 0]);
        }
    });
    assert!(matches!(connection.server_end, Some(Ok(()))));
    assert_eq!(
        alert_of(connection.client_end),
        AlertDescription::UNEXPECTED_MESSAGE
    );
}
