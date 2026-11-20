//! A client and a server connection run their handshake against each
//! other, with nitori_tls's engines, over links in memory and the tests'
//! clock.
//!
//! The server presents an Ed25519 certificate for example.com, issued by an
//! Ed25519 root that the client's verifier trusts; both are built by the
//! fixtures the tests share (`common/handshake.rs`). A stand-in part in
//! each connection notes what the tests look at as it changes: the
//! confirmation, the keys of the Initial and Handshake levels, the record
//! of why the connection closed, what only the side has, and the packet
//! number spaces of the logical path.
#![allow(
    clippy::arc_with_non_send_sync,
    reason = "the tests' routing domains are on one thread; deliverers are given as `Arc`s"
)]
#![feature(impl_trait_in_assoc_type, type_alias_impl_trait, yield_expr)]

mod common;
// The fixtures are a module of their own, apart from `common`, so that the
// other tests of the package do not build them.
#[macro_use]
#[path = "common/handshake.rs"]
mod fixtures;

/// Allocations are counted, for the measurements of the exchanges.
#[global_allocator]
static ALLOCATOR: sakuya_test_support::measure::CountingAllocator =
    sakuya_test_support::measure::CountingAllocator;

use std::{
    cell::{Cell, RefCell},
    num::NonZeroUsize,
    rc::Rc,
    sync::Arc,
    task::Poll,
    time::Duration,
};

use bytes::Bytes;
use common::events::Recorded;
use common::{Outer, TestClock, TestLink, TestReceiver, advance_to, ms, now};
use fixtures::*;
use nitori_io::{ReadChunkHostExt as _, calls::WriteAllHostExt as _};
use nitori_tls::{clock::ManualClock, message::MessageLimits};
use sakuya_connection::prelude::*;
use sakuya_connection::v1::events::{CloseTrigger, ConnectionState, EventInitiator, KeyChange};
use sakuya_connection::v1::{HostChoices, HostOf};
use sakuya_connection::{
    clock::ConnectionChoices,
    driver::LendNode,
    layer::{LinkPathArgs, LogicalPathArgs},
    role::LinkPathRole,
    shared::{DrivenFromOutside, SharedConnectionDriver},
    v1::{
        self, CloseCauseOf, Side,
        advancing::HandshakeStart,
        amplification::{AddressValidation, AntiAmplificationFactor},
        application_handles::{
            connection::ConnectionHandle, credential::HandleCredential,
            established_layer::TryOpenStreamError,
        },
        close::LocalCloseCause,
        close_request::CloseRequestCell,
        connection_ids::FirstLocalConnectionId,
        crypto::CryptoReceiveCapacities,
        first_flight::FirstFlight,
        handshake_done::ClientOnlyStart,
        input::InitialPathReceiver,
        keys::DirectionKeys,
        link::LinkFacts,
        retry::ContinueOnRetry,
    },
};
use sakuya_link::{LinkId, MIN_DATAGRAM_SIZE};
use sakuya_packet_protection::{
    backend::ring::RingBackend,
    initial::{INITIAL_AEAD, InitialSecrets},
};
use sakuya_recovery::{
    loss::LossThresholds, packet_number_space::PacketNumberSpaceKind,
    receive_journals::MaxAckRanges,
};
use sakuya_stream::{
    connection::{AbortCause, CloseReason, ImmediateClose, LayerEnd},
    receive::read::ReadError,
    send::{finish::CloseError, write::WriteError},
};
use sakuya_wire::v1::encryption_level::EncryptionLevel;
use sakuya_wire::{
    parts::{HList, HNil},
    v1::{
        role::Role,
        stream_count::StreamCount,
        transport_error::TransportErrorCode,
        transport_parameters::{
            TransportParameters,
            integer::{
                ActiveConnectionIdLimit, InitialMaxData, InitialMaxStreamDataBidiLocal,
                InitialMaxStreamDataBidiRemote, InitialMaxStreamsBidi, MaxIdleTimeout,
            },
        },
    },
    var_int::VarInt,
    version::Version,
};

choices!(
    ServerChoices,
    v1::Server<ServerEngine, common::TestNewTokenIssuer>,
    common::events::RecordingEvents
);
// the client's strategy plans as the ranked one does, and ends the intents
// a test marks when its link path's role next changes
choices!(
    ClientChoices,
    v1::Client<ClientEngine, common::TestTokenSink, ContinueOnRetry, ()>,
    common::events::RecordingEvents,
    common::ending::IntentEndingSendStrategy<I>
);

/// The parts of the tests' connections: version 1, and the part that notes
/// what the tests look at.
type Parts = HList![v1::Part, watch::Part];
sakuya_connection::composition!(impl for ServerChoices: ServerChoices, Parts);
sakuya_connection::composition!(impl for ClientChoices: ClientChoices, Parts);

harness!(server: [HNil], client: [HNil]);

// ---- the tests ----

#[test]
fn a_client_and_a_server_complete_and_confirm_the_handshake() {
    let clock = tls_clock();
    let complete = |noted: &Noted| {
        noted.confirmed
            && noted.initial_keys == "Discarded"
            && noted.handshake_keys == "Discarded"
            && noted.spaces == [PacketNumberSpaceKind::ApplicationData]
    };
    let run = handshake(client_engine(&clock, 1), &clock, |_| {
        complete(&noted(Role::Server))
            && complete(&noted(Role::Client))
            && noted(Role::Server).own == "Delivered"
    });
    let (server, client) = (noted(Role::Server), noted(Role::Client));
    // each side's events: the connection starts first, packets of every
    // level arrive whole, the recovery state is reported, nothing is lost,
    // and only packets of a level whose keys are gone are dropped
    for role in [Role::Server, Role::Client] {
        let events = common::events::recorded(role);
        assert_eq!(events.first(), Some(&Recorded::Started), "{role:?}");
        for level in [
            EncryptionLevel::Initial,
            EncryptionLevel::Handshake,
            EncryptionLevel::OneRtt,
        ] {
            assert!(
                events.iter().any(|event| matches!(
                    event,
                    Recorded::Received { level: received, whole: true, .. } if *received == level
                )),
                "{role:?} received a packet of {level:?}: {events:#?}"
            );
        }
        assert!(
            events
                .iter()
                .any(|event| matches!(event, Recorded::Metrics { .. })),
            "{role:?}"
        );
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Recorded::Lost { .. })
                    || matches!(event, Recorded::Dropped { reason, .. } if reason != "NoReceiveKeys")),
            "{role:?}: {events:#?}"
        );
        let count = |wanted: &Recorded| events.iter().filter(|event| *event == wanted).count();
        // this side's parameters and the peer's, once each
        assert_eq!(
            count(&Recorded::Parameters(EventInitiator::Local)),
            1,
            "{role:?}"
        );
        assert_eq!(
            count(&Recorded::Parameters(EventInitiator::Remote)),
            1,
            "{role:?}"
        );
        assert_eq!(count(&Recorded::Version(Version::V1)), 1, "{role:?}");
        assert_eq!(
            count(&Recorded::State(ConnectionState::HandshakeComplete)),
            1,
            "{role:?}"
        );
        assert_eq!(
            count(&Recorded::State(ConnectionState::HandshakeConfirmed)),
            1,
            "{role:?}"
        );
        for level in [EncryptionLevel::Initial, EncryptionLevel::Handshake] {
            for sender in [Role::Client, Role::Server] {
                let key = KeyChange {
                    level,
                    sender,
                    key_phase: None,
                    trigger: None,
                };
                assert_eq!(count(&Recorded::KeyUpdated(key)), 1, "{role:?} {key:?}");
                assert_eq!(count(&Recorded::KeyDiscarded(key)), 1, "{role:?} {key:?}");
            }
        }
        for sender in [Role::Client, Role::Server] {
            let key = KeyChange {
                level: EncryptionLevel::OneRtt,
                sender,
                key_phase: None,
                trigger: None,
            };
            assert_eq!(count(&Recorded::KeyUpdated(key)), 1, "{role:?} {key:?}");
        }
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, Recorded::Alpn(_)))
                .count(),
            1,
            "{role:?}"
        );
    }
    // every packet a side sealed is the one the other side opened: the
    // same level and packet number, both whole
    let sent_and_received = |sender: Role, receiver: Role| {
        let sent: Vec<_> = common::events::recorded(sender)
            .into_iter()
            .filter_map(|event| match event {
                Recorded::Sent {
                    level,
                    number,
                    whole,
                } => Some((level, number, whole)),
                _ => None,
            })
            .collect();
        let received: Vec<_> = common::events::recorded(receiver)
            .into_iter()
            .filter_map(|event| match event {
                Recorded::Received {
                    level,
                    number,
                    whole,
                } => Some((level, number, whole)),
                _ => None,
            })
            .collect();
        (sent, received)
    };
    for (sender, receiver) in [(Role::Client, Role::Server), (Role::Server, Role::Client)] {
        let (sent, received) = sent_and_received(sender, receiver);
        assert!(!sent.is_empty() && sent.iter().all(|(_, _, whole)| *whole));
        for packet in &received {
            assert!(
                sent.contains(packet),
                "{receiver:?} opened {packet:?}, which {sender:?} sealed"
            );
        }
    }
    // both connections were open when the run dropped them: each records
    // its close last, an abort of this side
    for role in [Role::Server, Role::Client] {
        let events = common::events::recorded(role);
        assert_eq!(
            events[events.len() - 2..],
            [
                Recorded::Closed {
                    initiator: EventInitiator::Local,
                    trigger: CloseTrigger::Aborted,
                },
                Recorded::State(ConnectionState::Closed),
            ],
            "{role:?}"
        );
    }
    for (side, noted) in [("server", &server), ("client", &client)] {
        assert!(noted.confirmed, "the {side}'s handshake is confirmed");
        assert_eq!(noted.initial_keys, "Discarded", "the {side}'s Initial keys");
        assert_eq!(
            noted.handshake_keys, "Discarded",
            "the {side}'s Handshake keys"
        );
        assert_eq!(
            noted.spaces,
            [PacketNumberSpaceKind::ApplicationData],
            "the {side} retired its Initial and Handshake spaces"
        );
        assert_eq!(noted.record, None, "the {side}'s connection is not closing");
        assert_eq!(noted.exporter, "Held(..)", "the {side} keeps its exporter");
        assert!(
            noted.streams,
            "the {side}'s established layer holds the stream set"
        );
    }
    // the connection handles give the handshake's results and the layers
    let client_facts =
        ready(run.client_handle.handshake_completed()).expect("the client's handshake completed");
    let server_facts =
        ready(run.server_handle.handshake_completed()).expect("the server's handshake completed");
    assert_eq!(
        client_facts.application_protocol, server_facts.selected.application_protocol,
        "both sides name the protocol selected"
    );
    assert!(!server_facts.resumed);
    assert!(
        ready(run.client_handle.early()).expect("settled").is_none(),
        "a client without 0-RTT has no early layer"
    );
    let server_early = ready(run.server_handle.early())
        .expect("settled")
        .expect("a server's layer comes before its handshake completes");
    let server_layer = ready(run.server_handle.established()).expect("established");
    assert_eq!(server_layer.selected(), &server_facts.selected);
    assert_eq!(
        server_early.application_protocol(),
        server_layer.application_protocol()
    );
    let client_layer = ready(run.client_handle.established()).expect("established");
    assert_eq!(
        client_layer.application_protocol(),
        client_facts.application_protocol.as_ref()
    );
    // the drivers were dropped when the run returned: the connections
    // ended without a close, the exporter is let go, and the layers ended
    // with the same reason; the handshakes still completed
    assert!(matches!(
        ready(run.client_handle.closed()),
        CloseReason::Aborted(AbortCause::DriverDropped)
    ));
    assert!(matches!(
        ready(run.server_handle.closed()),
        CloseReason::Aborted(AbortCause::DriverDropped)
    ));
    assert!(
        ready(run.client_handle.exporter())
            .expect("completed")
            .is_none(),
        "the exporter is let go once the connection closed"
    );
    assert!(matches!(
        ready(server_layer.ended()),
        LayerEnd::ConnectionClosed(CloseReason::Aborted(AbortCause::DriverDropped))
    ));
    assert!(matches!(
        client_layer.try_open_bi(),
        Err(TryOpenStreamError::LayerEnded { .. })
    ));
    assert!(matches!(
        ready(server_early.accept_uni()),
        Err(error) if matches!(error.end(), LayerEnd::ConnectionClosed(_))
    ));
    // the server sent HANDSHAKE_DONE, and the client acknowledged it
    assert_eq!(server.own, "Delivered");
    assert!(!run.server_ended && !run.client_ended);
    let initials: Vec<_> = run
        .client_sent
        .iter()
        .filter(|datagram| starts_with_initial(datagram))
        .collect();
    assert!(!initials.is_empty(), "the client sent Initial packets");
    for datagram in initials {
        assert!(
            datagram.len() >= MIN_DATAGRAM_SIZE,
            "a client's Initial datagram of {} bytes",
            datagram.len()
        );
    }
}

#[test]
fn a_client_whose_first_initial_datagram_is_lost_sends_its_hello_again_and_the_handshake_completes()
{
    let clock = tls_clock();
    // the link loses the client's first datagram; the server's connection
    // is made when the first one that arrives does, after the client's
    // probe timeout expired and handed the ClientHello, still in flight,
    // back to be sent again
    CLIENT_DATAGRAMS_LOST.with(|lost| lost.set(1));
    let run = handshake(client_engine(&clock, 1), &clock, |_| {
        noted(Role::Server).confirmed && noted(Role::Client).confirmed
    });
    CLIENT_DATAGRAMS_LOST.with(|lost| lost.set(0));
    // the client's events: the first Initial packet, never acknowledged
    // while later ones are, was declared lost on an acknowledgment
    let events = common::events::recorded(Role::Client);
    assert!(
        events.iter().any(|event| matches!(
            event,
            Recorded::Lost {
                space: PacketNumberSpaceKind::Initial,
                number: 0,
                ..
            }
        )),
        "{events:#?}"
    );
    // nothing could happen before the probe timeout, which expires at
    // 999 ms with the initial round trip time
    assert!(now() >= ms(999), "confirmed at {:?}", now());
    let (server, client) = (noted(Role::Server), noted(Role::Client));
    assert!(client.confirmed, "the client's handshake is confirmed");
    assert!(server.confirmed, "the server's handshake is confirmed");
    ready(run.client_handle.handshake_completed()).expect("the client's handshake completed");
    ready(run.server_handle.handshake_completed()).expect("the server's handshake completed");
    // the first datagram was lost, and the ClientHello went again in the
    // probe datagrams after it
    let initials: Vec<_> = run
        .client_sent
        .iter()
        .filter(|datagram| starts_with_initial(datagram))
        .collect();
    assert!(initials.len() >= 2, "{} Initial datagrams", initials.len());
    for datagram in initials {
        assert!(datagram.len() >= MIN_DATAGRAM_SIZE);
    }
    assert!(!run.server_ended && !run.client_ended);
}

#[test]
fn both_probe_datagrams_of_a_client_carry_its_hello_and_the_second_completes_the_handshake() {
    let clock = tls_clock();
    // the link loses the first flight and the first probe datagram: only
    // the second probe datagram of the first probe timeout arrives
    CLIENT_DATAGRAMS_LOST.with(|lost| lost.set(2));
    let run = handshake(client_engine(&clock, 1), &clock, |_| {
        noted(Role::Server).confirmed && noted(Role::Client).confirmed
    });
    CLIENT_DATAGRAMS_LOST.with(|lost| lost.set(0));
    assert!(noted(Role::Client).confirmed && noted(Role::Server).confirmed);
    // the first probe timeout expires at 999 ms; the second would be
    // 1998 ms later: the ClientHello arrived with the first one's probes
    assert!(
        now() >= ms(999) && now() < ms(2997),
        "confirmed at {:?}",
        now()
    );
    // the first flight, then the two probe datagrams: each leads its
    // Initial packet with the ClientHello's CRYPTO frame, from offset 0
    let payloads: Vec<_> = run.client_sent[..3]
        .iter()
        .map(|datagram| client_initial_payload(datagram))
        .collect();
    for (at, payload) in payloads.iter().enumerate() {
        assert_eq!(payload[..2], [0x06, 0x00], "datagram {at}: {payload:?}");
    }
    assert_eq!(
        payloads[1], payloads[2],
        "both probes carry the same CRYPTO frame and PING"
    );
    assert!(!run.server_ended && !run.client_ended);
}

#[test]
fn a_client_that_fails_to_verify_the_server_closes_with_the_alert() {
    let clock = tls_clock();
    // the client trusts another root than the server's certificate's
    let run = handshake(client_engine(&clock, 3), &clock, |_| {
        noted(Role::Server).peer_close.is_some()
    });
    let client = noted(Role::Client);
    let alert = client
        .alert
        .expect("the client's handshake failed with an alert");
    assert!(
        client
            .record
            .as_deref()
            .is_some_and(|record| record.starts_with("Local(Handshake(Alert")),
        "{:?}",
        client.record
    );
    let Some(ImmediateClose::Transport(close)) = noted(Role::Server).peer_close else {
        panic!(
            "the server received a transport close: {:?}",
            noted(Role::Server)
        );
    };
    assert_eq!(close.code, TransportErrorCode::crypto_error(alert));
    assert_eq!(
        close.code.get().get(),
        0x0100 + u64::from(alert),
        "CRYPTO_ERROR with the alert"
    );
    // a Frame Type of 0
    assert_eq!(close.frame_type, None);
    assert_eq!(
        client.exporter, "Released",
        "a closed connection keeps no exporter"
    );
    assert!(!run.server_ended, "the server closes in its own time");
    // the client, closing, keeps only the receiving halves of its keys,
    // and still records the packets that come; the server drains and
    // discards every half it had, the 1-RTT keys only sending
    let client_events = common::events::recorded(Role::Client);
    let discarded = |events: &[Recorded]| {
        events
            .iter()
            .filter_map(|event| match event {
                Recorded::KeyDiscarded(key) => Some((key.level, key.sender)),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        discarded(&client_events),
        [
            (EncryptionLevel::Initial, Role::Client),
            (EncryptionLevel::Handshake, Role::Client),
        ]
    );
    let closed_at = client_events
        .iter()
        .position(|event| matches!(event, Recorded::Closed { .. }))
        .expect("the client closed");
    assert!(
        client_events[closed_at..]
            .iter()
            .any(|event| matches!(event, Recorded::Received { whole: true, .. })),
        "{client_events:#?}"
    );
    assert_eq!(
        discarded(&common::events::recorded(Role::Server)),
        [
            (EncryptionLevel::Initial, Role::Server),
            (EncryptionLevel::Initial, Role::Client),
            (EncryptionLevel::Handshake, Role::Server),
            (EncryptionLevel::Handshake, Role::Client),
            (EncryptionLevel::OneRtt, Role::Server),
        ]
    );
    // each side's events say who closed and why, once
    let closed = |role| {
        common::events::recorded(role)
            .into_iter()
            .filter(|event| matches!(event, Recorded::Closed { .. }))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        closed(Role::Client),
        [Recorded::Closed {
            initiator: EventInitiator::Local,
            trigger: CloseTrigger::Error,
        }]
    );
    assert_eq!(
        closed(Role::Server),
        [Recorded::Closed {
            initiator: EventInitiator::Remote,
            trigger: CloseTrigger::PeerClose,
        }]
    );
}

#[test]
fn a_client_that_only_closes_discards_its_receiving_halves_when_its_closing_period_ends() {
    let clock = tls_clock();
    // the client trusts another root than the server's certificate's: it
    // closes, and the server drains without answering
    let run = handshake(client_engine(&clock, 3), &clock, |run| run.client_ended);
    assert!(run.client_ended, "the client's closing period ended");
    let discarded: Vec<_> = common::events::recorded(Role::Client)
        .iter()
        .filter_map(|event| match event {
            Recorded::KeyDiscarded(key) => Some((key.level, key.sender)),
            _ => None,
        })
        .collect();
    // the sending halves as it closed, the receiving halves as it ended
    assert_eq!(
        discarded,
        [
            (EncryptionLevel::Initial, Role::Client),
            (EncryptionLevel::Handshake, Role::Client),
            (EncryptionLevel::Initial, Role::Server),
            (EncryptionLevel::Handshake, Role::Server),
        ]
    );
}

#[test]
fn a_connection_dropped_before_its_first_poll_records_nothing() {
    let clock = tls_clock();
    common::events::reset();
    common::reset_links();
    advance_to(ms(0));
    let (routing, receiver) = Routing::new(&[cid(&CLIENT_CID)]);
    let args = args::<ClientChoices>(
        HandshakeStart::new(client_engine(&clock, 1), MessageLimits::default()),
        ClientOnlyStart::new(Bytes::new(), common::TestTokenSink, ContinueOnRetry, ()),
        AddressValidation::Validated,
        client_capacities(),
        FirstFlight::Datagrams(Vec::new()),
        receiver,
        &routing,
        first_local(&CLIENT_CID, 0xc1),
    );
    let connection = connection!(ClientChoices, args, link(), [][HNil]);
    drop(connection);
    // the connection never started: no close without a start
    assert_eq!(common::events::recorded(Role::Client), []);
}

#[test]
fn a_server_that_read_its_first_flight_first_records_the_packets_it_read() {
    let clock = tls_clock();
    SERVER_READS_FIRST.with(|reads| reads.set(true));
    let _run = handshake(client_engine(&clock, 1), &clock, |_| {
        noted(Role::Server).confirmed && noted(Role::Client).confirmed
    });
    let events = common::events::recorded(Role::Server);
    assert_eq!(events.first(), Some(&Recorded::Started));
    // the client's first Initial packet, read before the connection was
    // made, once, and every packet opened is one the client sealed
    let received: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            Recorded::Received {
                level,
                number,
                whole,
            } => Some((*level, *number, *whole)),
            _ => None,
        })
        .collect();
    assert_eq!(
        received
            .iter()
            .filter(|packet| **packet == (EncryptionLevel::Initial, 0, true))
            .count(),
        1,
        "{events:#?}"
    );
    let sent: Vec<_> = common::events::recorded(Role::Client)
        .into_iter()
        .filter_map(|event| match event {
            Recorded::Sent {
                level,
                number,
                whole,
            } => Some((level, number, whole)),
            _ => None,
        })
        .collect();
    for packet in &received {
        assert!(sent.contains(packet), "the server opened {packet:?}");
    }
}

#[test]
fn an_application_close_is_an_event_on_both_sides() {
    let clock = tls_clock();
    let mut asked = false;
    let _run = handshake(client_engine(&clock, 1), &clock, |run| {
        if !asked && noted(Role::Client).confirmed {
            asked = true;
            run.client_handle.close(common::AppClose(7));
        }
        noted(Role::Server).peer_close.is_some()
    });
    // the client, closing, drops the sending half of its 1-RTT keys; the
    // server, draining, both
    let one_rtt_discarded = |role| {
        common::events::recorded(role)
            .into_iter()
            .filter_map(|event| match event {
                Recorded::KeyDiscarded(key) if key.level == EncryptionLevel::OneRtt => {
                    Some(key.sender)
                }
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(one_rtt_discarded(Role::Client), [Role::Client]);
    assert_eq!(
        one_rtt_discarded(Role::Server),
        [Role::Server, Role::Client]
    );
    let closed = |role| {
        common::events::recorded(role)
            .into_iter()
            .filter(|event| matches!(event, Recorded::Closed { .. }))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        closed(Role::Client),
        [Recorded::Closed {
            initiator: EventInitiator::Local,
            trigger: CloseTrigger::Application,
        }]
    );
    assert_eq!(
        closed(Role::Server),
        [Recorded::Closed {
            initiator: EventInitiator::Remote,
            trigger: CloseTrigger::PeerClose,
        }]
    );
}

/// Read what the stream reader `$reader` has now into the `Vec<u8>`
/// `$into`; whether it read the stream's end.
macro_rules! read_now {
    ($reader:expr, $into:expr) => {{
        let maximum = NonZeroUsize::new(64).expect("not zero");
        loop {
            match poll_now($reader.read_chunk_unpin(maximum)) {
                Poll::Ready(Ok(Some(chunk))) => $into.extend_from_slice(&chunk),
                Poll::Ready(Ok(None)) => break true,
                Poll::Ready(Err(error)) => panic!("the stream is read: {error:?}"),
                Poll::Pending => break false,
            }
        }
    }};
}

/// A measurement, not a check, of the harness `handshake` of where it
/// expands: once both sides are established, the client and the server
/// exchange `MEASURE_EXCHANGES` requests and answers (by default none), one
/// bidirectional stream each, one after the other, through the shared
/// connection. It prints how many times the drivers were woken and how
/// many heap operations the test's thread made during the exchanges; a
/// profiler run with the count and without it gives what else the
/// exchanges cost.
macro_rules! exchange_measurement {
    ($name:ident) => {
        #[test]
        #[ignore = "a measurement, run by hand"]
        fn $name() {
            let exchanges: usize = std::env::var("MEASURE_EXCHANGES")
                .ok()
                .and_then(|count| count.parse().ok())
                .unwrap_or(0);
            let clock = tls_clock();
            let mut client_layer = None;
            let mut server_layer = None;
            let mut client_stream = None;
            let mut server_stream = None;
            let (mut request, mut answer) = (Vec::new(), Vec::new());
            let mut answered = false;
            let mut finished = 0;
            let mut before = None;
            let mut wakes = 0;
            let mut allocations = sakuya_test_support::measure::AllocationCounts::default();
            handshake(client_engine(&clock, 1), &clock, |run| {
                if client_layer.is_none()
                    && let Poll::Ready(Ok(layer)) = poll_now(run.client_handle.established())
                {
                    client_layer = Some(layer);
                }
                if server_layer.is_none()
                    && let Poll::Ready(layer) = poll_now(run.server_handle.established())
                {
                    server_layer = Some(layer.expect("the server's handshake completed"));
                }
                let (Some(client), Some(server)) = (&client_layer, &server_layer) else {
                    return false;
                };
                let (wakes_before, allocations_before) = *before.get_or_insert((
                    run.driver_wakes,
                    sakuya_test_support::measure::allocation_counts(),
                ));
                wakes = run.driver_wakes - wakes_before;
                allocations =
                    sakuya_test_support::measure::allocation_counts().since(allocations_before);
                if finished == exchanges {
                    return true;
                }
                if client_stream.is_none() {
                    let (mut writer, reader) =
                        client.try_open_bi().expect("the server grants streams");
                    ready(writer.write_all_unpin(Bytes::from_static(b"ping"))).expect("written");
                    writer.close().expect("the request ends");
                    client_stream = Some((writer, reader));
                }
                if server_stream.is_none()
                    && let Poll::Ready(stream) = poll_now(server.accept_bi())
                {
                    server_stream = Some(stream.expect("the client's stream is accepted"));
                }
                if let Some((writer, reader)) = &mut server_stream
                    && !answered
                    && read_now!(reader, request)
                {
                    ready(writer.write_all_unpin(Bytes::from_static(b"pong"))).expect("written");
                    writer.close().expect("the answer ends");
                    answered = true;
                }
                if let Some((_, reader)) = &mut client_stream
                    && answered
                    && read_now!(reader, answer)
                {
                    assert_eq!((&request[..], &answer[..]), (&b"ping"[..], &b"pong"[..]));
                    request.clear();
                    answer.clear();
                    answered = false;
                    client_stream = None;
                    server_stream = None;
                    finished += 1;
                }
                false
            });
            assert_eq!(finished, exchanges, "the exchanges finished within 3 s");
            println!(
                "exchanges={exchanges} driver_wakes={wakes} allocations={} reallocations={} \
                 deallocations={} bytes={}",
                allocations.allocations,
                allocations.reallocations,
                allocations.deallocations,
                allocations.bytes,
            );
        }
    };
}

/// Node 1: over the tests' in-memory link, a client and a server complete
/// the handshake, the client opens a bidirectional stream and sends a
/// request with its end, and the server reads it and answers on the same
/// stream.
/// The Token field of the Initial packet `datagram` starts with.
fn initial_token(datagram: &[u8]) -> &[u8] {
    let mut at = 5;
    at += 1 + usize::from(datagram[at]);
    at += 1 + usize::from(datagram[at]);
    let (len, width) = match datagram[at] >> 6 {
        0 => (usize::from(datagram[at]), 1),
        1 => (
            usize::from(u16::from_be_bytes([datagram[at] & 0x3f, datagram[at + 1]])),
            2,
        ),
        _ => unreachable!("the tests' tokens are shorter than 16384 bytes"),
    };
    &datagram[at + width..at + width + len]
}

/// The payload of the first packet of `datagram`, an Initial packet of
/// the client, opened with the keys of its Initial secret (RFC 9001 §5.2).
fn client_initial_payload(datagram: &[u8]) -> Vec<u8> {
    assert!(starts_with_initial(datagram), "an Initial packet");
    let token = initial_token(datagram);
    // the token's length takes one byte for the tests' tokens here
    let at = 5 + 1 + 8 + 1 + 8 + 1 + token.len();
    assert!(token.len() < 64);
    let length = usize::from(u16::from_be_bytes([datagram[at] & 0x3f, datagram[at + 1]]));
    assert_eq!(datagram[at] >> 6, 1, "a two-byte Length field");
    let pn_offset = at + 2;
    let mut packet = datagram[..pn_offset + length].to_vec();
    let secrets = InitialSecrets::derive(&RingBackend, &cid(&CLIENT_DCID));
    let keys = DirectionKeys::derive(&RingBackend, INITIAL_AEAD, &secrets.client);
    let truncated = keys.header.remove(&mut packet, pn_offset).expect("sampled");
    let header_len = pn_offset + truncated.encoded_len().get();
    let number = truncated.decode(None);
    keys.packet
        .open(number, &mut packet, header_len)
        .expect("opened")
        .to_vec()
}

#[test]
fn every_initial_packet_of_a_client_carries_the_token_it_started_with() {
    let clock = tls_clock();
    let token = Bytes::from(vec![0x70; 100]);
    CLIENT_TOKEN.with(|cell| *cell.borrow_mut() = token.clone());
    let run = handshake(client_engine(&clock, 1), &clock, |_| {
        noted(Role::Client).confirmed
    });
    ready(run.client_handle.handshake_completed()).expect("the client's handshake completed");
    let initials: Vec<_> = run
        .client_sent
        .iter()
        .filter(|datagram| starts_with_initial(datagram))
        .collect();
    assert!(
        initials.len() >= 2,
        "the client sent its ClientHello and an acknowledgment"
    );
    for datagram in initials {
        assert_eq!(initial_token(datagram), &token[..]);
        assert!(datagram.len() >= MIN_DATAGRAM_SIZE);
    }
}

#[test]
fn once_confirmed_each_side_issues_connection_ids_up_to_the_peer_s_limit_and_the_peer_takes_them() {
    let clock = tls_clock();
    let issued = |noted: &Noted| {
        noted.confirmed && noted.local_connection_ids == 4 && noted.offered_connection_ids == 4
    };
    handshake(client_engine(&clock, 1), &clock, |_| {
        issued(&noted(Role::Server)) && issued(&noted(Role::Client))
    });
    for (side, role) in [("server", Role::Server), ("client", Role::Client)] {
        let noted = noted(role);
        assert!(noted.confirmed, "the {side}'s handshake is confirmed");
        assert_eq!(
            noted.local_connection_ids, 4,
            "the {side} keeps its handshake connection ID and three more issued"
        );
        assert_eq!(
            noted.offered_connection_ids, 4,
            "the {side} took the peer's NEW_CONNECTION_ID frames"
        );
    }
}

#[test]
fn once_confirmed_a_server_gives_one_token_and_its_client_keeps_it() {
    let clock = tls_clock();
    handshake(client_engine(&clock, 1), &clock, |_| {
        noted(Role::Server).confirmed && !common::tokens_kept().is_empty()
    });
    let issued = common::new_tokens_issued();
    assert_eq!(
        issued,
        [Bytes::from_static(b"token-1")],
        "one token, once confirmed"
    );
    assert_eq!(
        common::tokens_kept(),
        issued,
        "the client keeps what the server gave"
    );
}

#[test]
fn a_server_whose_issuer_gives_no_token_sends_none() {
    let clock = tls_clock();
    common::set_new_token_issuing(false);
    handshake(client_engine(&clock, 1), &clock, |_| {
        noted(Role::Server).confirmed && noted(Role::Client).confirmed
    });
    common::set_new_token_issuing(true);
    assert_eq!(common::new_tokens_issued(), Vec::<Bytes>::new());
    assert_eq!(common::tokens_kept(), Vec::<Bytes>::new());
}

exchange_measurement!(measure_exchanges_on_the_default_stream_set);

#[test]
fn a_client_and_a_server_exchange_a_request_and_its_answer_on_a_stream() {
    let clock = tls_clock();
    let mut client_stream = None;
    let mut server_layer = None;
    let mut server_stream = None;
    let (mut request, mut answer) = (Vec::new(), Vec::new());
    let mut answered = false;
    let mut done = false;
    handshake(client_engine(&clock, 1), &clock, |run| {
        if client_stream.is_none()
            && let Poll::Ready(layer) = poll_now(run.client_handle.established())
        {
            let layer = layer.expect("the client's handshake completed");
            let (mut writer, reader) = layer.try_open_bi().expect("the server grants streams");
            ready(writer.write_all_unpin(Bytes::from_static(b"ping")))
                .expect("the request is written");
            writer.close().expect("the request ends");
            client_stream = Some((writer, reader));
        }
        if server_layer.is_none()
            && let Poll::Ready(layer) = poll_now(run.server_handle.established())
        {
            server_layer = Some(layer.expect("the server's handshake completed"));
        }
        if server_stream.is_none()
            && let Some(layer) = &server_layer
            && let Poll::Ready(stream) = poll_now(layer.accept_bi())
        {
            server_stream = Some(stream.expect("the client's stream is accepted"));
        }
        if let Some((writer, reader)) = &mut server_stream
            && !answered
            && read_now!(reader, request)
        {
            assert_eq!(request, b"ping");
            ready(writer.write_all_unpin(Bytes::from_static(b"pong")))
                .expect("the answer is written");
            writer.close().expect("the answer ends");
            answered = true;
        }
        if let Some((_, reader)) = &mut client_stream
            && !done
        {
            done = read_now!(reader, answer);
        }
        done
    });
    assert!(done, "the client read the answer's end within 3 s");
    assert_eq!(request, b"ping");
    assert_eq!(answer, b"pong");
}

/// What reading `reader` gives now, its data going into `into`: `Ok(true)`
/// at the end, `Ok(false)` once it waits, or the error.
macro_rules! read_what_comes {
    ($reader:expr, $into:expr) => {{
        let maximum = NonZeroUsize::new(64).expect("not zero");
        loop {
            match poll_now($reader.read_chunk_unpin(maximum)) {
                Poll::Ready(Ok(Some(chunk))) => $into.extend_from_slice(&chunk),
                Poll::Ready(Ok(None)) => break Ok(true),
                Poll::Ready(Err(error)) => break Err(error),
                Poll::Pending => break Ok(false),
            }
        }
    }};
}

/// The client's writer turns into one with a shared credential and is
/// cloned: dropping one of the two writers does not give the stream up,
/// and the server goes on waiting for more; dropping the last one does, and
/// the stream's termination policy resets it, which the server reads.
#[test]
fn a_stream_is_given_up_once_the_last_of_its_shared_writers_is_dropped() {
    let clock = tls_clock();
    let mut writers: Option<(Option<_>, Option<_>)> = None;
    let mut client_reader = None;
    let mut server_layer = None;
    let mut server_stream = None;
    let mut read = Vec::new();
    let mut step = 0;
    let mut waited = 0;
    let mut reset = false;
    handshake(client_engine(&clock, 1), &clock, |run| {
        if writers.is_none()
            && let Poll::Ready(Ok(layer)) = poll_now(run.client_handle.established())
        {
            let (mut writer, reader) = layer.try_open_bi().expect("a stream");
            client_reader = Some(reader);
            ready(writer.write_all_unpin(Bytes::from_static(b"ab"))).expect("written");
            let writer = writer.into_shared::<Arc<HandleCredential>>();
            let second = writer.clone();
            writers = Some((Some(writer), Some(second)));
        }
        if server_layer.is_none()
            && let Poll::Ready(layer) = poll_now(run.server_handle.established())
        {
            server_layer = Some(layer.expect("the server's handshake completed"));
        }
        if server_stream.is_none()
            && let Some(layer) = &server_layer
            && let Poll::Ready(stream) = poll_now(layer.accept_bi())
        {
            server_stream = Some(stream.expect("the client's stream is accepted"));
        }
        let Some((_, reader)) = &mut server_stream else {
            return false;
        };
        let read_now = read_what_comes!(reader, read);
        let (first, second) = writers.as_mut().expect("opened before accepted");
        match step {
            0 if read == b"ab" => {
                drop(first.take());
                step = 1;
            }
            1 => {
                assert!(
                    matches!(read_now, Ok(false)),
                    "one writer is left: {read_now:?}"
                );
                waited += 1;
                if waited == 100 {
                    drop(second.take());
                    step = 2;
                }
            }
            2 => {
                if let Err(error) = read_now {
                    assert!(matches!(error, ReadError::Reset { .. }), "{error:?}");
                    reset = true;
                }
            }
            _ => {}
        }
        reset
    });
    assert!(reset, "the server read the reset within 3 s");
    assert_eq!(read, b"ab");
    drop(client_reader);
}

/// The server's reader turns into one with a shared credential, behind an
/// `Rc`, and is cloned: the client goes on writing while one of the two
/// readers is left, and both read the same stream; once the last one is
/// dropped, the server asks the client to stop, and the client's writes
/// fail.
#[test]
fn reading_is_given_up_once_the_last_of_the_shared_readers_is_dropped() {
    let clock = tls_clock();
    let mut client_writer = None;
    let mut client_reader = None;
    let mut server_layer = None;
    let mut server_writer = None;
    let mut readers: Option<(Option<_>, Option<_>)> = None;
    let mut read = Vec::new();
    let mut step = 0;
    let mut stopped = false;
    handshake(client_engine(&clock, 1), &clock, |run| {
        if client_writer.is_none()
            && let Poll::Ready(Ok(layer)) = poll_now(run.client_handle.established())
        {
            let (mut writer, reader) = layer.try_open_bi().expect("a stream");
            ready(writer.write_all_unpin(Bytes::from_static(b"a"))).expect("written");
            client_writer = Some(writer);
            client_reader = Some(reader);
        }
        if server_layer.is_none()
            && let Poll::Ready(layer) = poll_now(run.server_handle.established())
        {
            server_layer = Some(layer.expect("the server's handshake completed"));
        }
        if readers.is_none()
            && let Some(layer) = &server_layer
            && let Poll::Ready(stream) = poll_now(layer.accept_bi())
        {
            let (writer, reader) = stream.expect("the client's stream is accepted");
            server_writer = Some(writer);
            let reader = reader.into_shared::<Rc<HandleCredential>>();
            let second = reader.clone();
            readers = Some((Some(reader), Some(second)));
        }
        let (Some(writer), Some((first, second))) = (&mut client_writer, &mut readers) else {
            return false;
        };
        match step {
            0 => {
                let reader = first.as_mut().expect("kept");
                read_what_comes!(reader, read).expect("the stream goes on");
                if read == b"a" {
                    drop(first.take());
                    ready(writer.write_all_unpin(Bytes::from_static(b"b")))
                        .expect("one reader is left");
                    step = 1;
                }
            }
            1 => {
                let reader = second.as_mut().expect("kept");
                read_what_comes!(reader, read).expect("the stream goes on");
                if read == b"ab" {
                    drop(second.take());
                    step = 2;
                }
            }
            2 => {
                if let Poll::Ready(Err(error)) =
                    poll_now(writer.write_all_unpin(Bytes::from_static(b"c")))
                {
                    assert!(
                        !matches!(
                            error,
                            nitori_io::calls::WriteAllError::Receiver {
                                source: WriteError::LayerEnded { .. },
                                ..
                            }
                        ),
                        "the stream is stopped, not the layer: {error:?}"
                    );
                    stopped = true;
                }
            }
            _ => {}
        }
        stopped
    });
    assert!(stopped, "the client's writes failed within 3 s");
    assert_eq!(read, b"ab");
    drop((client_reader, server_writer));
}

/// Both parts of a stream are done — the client's request was
/// acknowledged and the client read the answer's end — while the client
/// still holds its writer and reader: the stream set keeps them for it, and
/// every operation gives the last result again, not the layer's end.
#[test]
fn a_done_stream_whose_handles_are_held_gives_its_last_results() {
    let clock = tls_clock();
    let mut client_stream = None;
    let mut server_layer = None;
    let mut server_stream = None;
    let (mut request, mut answer) = (Vec::new(), Vec::new());
    let mut answered = false;
    let mut done = false;
    let mut looked = false;
    handshake(client_engine(&clock, 1), &clock, |run| {
        if client_stream.is_none()
            && let Poll::Ready(Ok(layer)) = poll_now(run.client_handle.established())
        {
            let (mut writer, reader) = layer.try_open_bi().expect("the server grants streams");
            ready(writer.write_all_unpin(Bytes::from_static(b"ping"))).expect("written");
            writer.close().expect("the request ends");
            client_stream = Some((writer, reader));
        }
        if server_layer.is_none()
            && let Poll::Ready(layer) = poll_now(run.server_handle.established())
        {
            server_layer = Some(layer.expect("the server's handshake completed"));
        }
        if server_stream.is_none()
            && let Some(layer) = &server_layer
            && let Poll::Ready(stream) = poll_now(layer.accept_bi())
        {
            server_stream = Some(stream.expect("the client's stream is accepted"));
        }
        if !answered
            && let Some((writer, reader)) = &mut server_stream
            && read_now!(reader, request)
        {
            ready(writer.write_all_unpin(Bytes::from_static(b"pong"))).expect("written");
            writer.close().expect("the answer ends");
            answered = true;
        }
        let Some((writer, reader)) = &mut client_stream else {
            return false;
        };
        if done {
            // the next millisecond: both parts are done and held
            let mut again = Vec::new();
            assert!(
                matches!(read_what_comes!(reader, again), Ok(true)),
                "the reader reads the end again"
            );
            assert!(again.is_empty());
            assert!(matches!(
                poll_now(writer.all_acknowledged()),
                Poll::Ready(Ok(()))
            ));
            let Poll::Ready(Err(error)) =
                poll_now(writer.write_all_unpin(Bytes::from_static(b"late")))
            else {
                panic!("a write after the end fails");
            };
            assert!(
                !matches!(
                    error,
                    nitori_io::calls::WriteAllError::Receiver {
                        source: WriteError::LayerEnded { .. },
                        ..
                    }
                ),
                "the stream ended, not the layer: {error:?}"
            );
            looked = true;
            return true;
        }
        done = read_now!(reader, answer)
            && matches!(poll_now(writer.all_acknowledged()), Poll::Ready(Ok(())));
        false
    });
    assert!(
        looked,
        "the request was acknowledged and the answer read within 3 s"
    );
    assert_eq!(request, b"ping");
    assert_eq!(answer, b"pong");
}

/// The events of a stream on both sides: the client opens a bidirectional
/// stream, writes a request and ends it; the server reads it to its end.
/// Each side's parts leave idle, as this side's on the client and as the
/// peer's on the server; the client's sending part ends in "Data Recvd" once
/// the server acknowledged everything, the server's receiving part in "Data
/// Read"; the bytes the client's writer moved to its transport are those the
/// server's reader took from its own.
#[test]
fn both_sides_give_the_states_of_a_streams_parts_and_the_data_moved() {
    use common::events::{SharedRecorded, shared_recorded};
    use sakuya_connection::v1::events::{DataLocation, StreamStateChange};
    use sakuya_stream::{receive::ReceiveStreamState, send::SendStreamState};

    let clock = tls_clock();
    let mut server_layer = None;
    let mut client_stream = None;
    let mut server_stream = None;
    let mut request = Vec::new();
    let mut read_end = false;
    let delivered = |recorded: &[SharedRecorded]| {
        recorded.iter().any(|event| {
            matches!(
                event,
                SharedRecorded::StreamState {
                    change: StreamStateChange::Sending {
                        new: Some(SendStreamState::DataRecvd),
                        ..
                    },
                    ..
                }
            )
        })
    };
    handshake(client_engine(&clock, 1), &clock, |run| {
        if client_stream.is_none()
            && let Poll::Ready(layer) = poll_now(run.client_handle.established())
        {
            let layer = layer.expect("the client's handshake completed");
            let (mut writer, reader) = layer.try_open_bi().expect("the server grants streams");
            ready(writer.write_all_unpin(Bytes::from_static(b"request")))
                .expect("the request is written");
            writer.close().expect("the request ends");
            client_stream = Some((writer, reader));
        }
        if server_layer.is_none()
            && let Poll::Ready(layer) = poll_now(run.server_handle.established())
        {
            server_layer = Some(layer.expect("the server's handshake completed"));
        }
        if server_stream.is_none()
            && let Some(layer) = &server_layer
            && let Poll::Ready(stream) = poll_now(layer.accept_bi())
        {
            server_stream = Some(stream.expect("the client's stream is accepted"));
        }
        if let Some((_, reader)) = &mut server_stream
            && !read_end
        {
            read_end = read_now!(reader, request);
        }
        read_end && delivered(&shared_recorded(Role::Client))
    });
    assert_eq!(request, b"request");

    let client = shared_recorded(Role::Client);
    let server = shared_recorded(Role::Server);
    let has = |recorded: &[SharedRecorded], change: StreamStateChange, trigger: EventInitiator| {
        recorded.iter().any(|event| {
            matches!(
                event,
                SharedRecorded::StreamState { change: c, trigger: t, .. }
                    if *c == change && *t == trigger
            )
        })
    };
    let made_sending = StreamStateChange::Sending {
        old: None,
        new: Some(SendStreamState::Ready),
    };
    let made_receiving = StreamStateChange::Receiving {
        old: None,
        new: Some(ReceiveStreamState::Recv),
    };
    assert!(
        has(&client, made_sending, EventInitiator::Local),
        "{client:?}"
    );
    assert!(
        has(&client, made_receiving, EventInitiator::Local),
        "{client:?}"
    );
    assert!(
        has(&server, made_sending, EventInitiator::Remote),
        "{server:?}"
    );
    assert!(
        has(&server, made_receiving, EventInitiator::Remote),
        "{server:?}"
    );
    assert!(delivered(&client), "{client:?}");
    assert!(
        server.iter().any(|event| matches!(
            event,
            SharedRecorded::StreamState {
                change: StreamStateChange::Receiving {
                    new: Some(ReceiveStreamState::DataRead),
                    ..
                },
                trigger: EventInitiator::Local,
                ..
            }
        )),
        "{server:?}"
    );
    let moved = |recorded: &[SharedRecorded], from: DataLocation, to: DataLocation| -> u64 {
        recorded
            .iter()
            .filter_map(|event| match event {
                SharedRecorded::StreamDataMoved(moved) if moved.from == from && moved.to == to => {
                    Some(moved.length)
                }
                _ => None,
            })
            .sum()
    };
    let length = b"request".len() as u64;
    assert_eq!(
        moved(&client, DataLocation::Application, DataLocation::Transport),
        length
    );
    assert_eq!(
        moved(&server, DataLocation::Transport, DataLocation::Application),
        length
    );
}

/// Over the tests' in-memory link, the server grants the client four
/// bidirectional streams, and the client opens ten, one after the other,
/// each with a request and its end, each answered with its end; the server
/// holds every writer and reader to the end. A stream the server read to
/// its end and whose answer the client acknowledged is reclaimed all the
/// same, and the server's MAX_STREAMS lets the client open the next
/// (RFC 9000 §4.6): without it, the fifth would wait for good.
#[test]
fn a_client_opens_more_streams_than_first_granted_as_the_server_reclaims_finished_ones() {
    const STREAMS: usize = 10;
    let clock = tls_clock();
    let mut server_layer = None;
    let mut client_stream = None;
    let mut server_streams = Vec::new();
    let mut finished = 0;
    handshake(client_engine(&clock, 1), &clock, |run| {
        let Poll::Ready(Ok(client)) = poll_now(run.client_handle.established()) else {
            return false;
        };
        if server_layer.is_none()
            && let Poll::Ready(layer) = poll_now(run.server_handle.established())
        {
            server_layer = Some(layer.expect("the server's handshake completed"));
        }
        if client_stream.is_none() && finished < STREAMS {
            match client.try_open_bi() {
                Ok((mut writer, reader)) => {
                    ready(writer.write_all_unpin(Bytes::from_static(b"ping")))
                        .expect("the request is written");
                    writer.close().expect("the request ends");
                    client_stream = Some((writer, reader, Vec::new()));
                }
                // the server has not granted more yet
                Err(TryOpenStreamError::AtLimit) => {}
                Err(error) => panic!("the client opens a stream: {error:?}"),
            }
        }
        if let Some(layer) = &server_layer {
            while let Poll::Ready(stream) = poll_now(layer.accept_bi()) {
                let (writer, reader) = stream.expect("the client's stream is accepted");
                server_streams.push((writer, reader, Vec::new(), false));
            }
        }
        for (writer, reader, request, answered) in &mut server_streams {
            if !*answered && read_now!(reader, *request) {
                assert_eq!(request, b"ping");
                ready(writer.write_all_unpin(Bytes::from_static(b"pong")))
                    .expect("the answer is written");
                writer.close().expect("the answer ends");
                *answered = true;
            }
        }
        let answered = match &mut client_stream {
            Some((_, reader, answer)) => read_now!(reader, *answer),
            None => false,
        };
        if answered {
            let (_, _, answer) = client_stream.take().expect("a stream");
            assert_eq!(answer, b"pong");
            finished += 1;
        }
        finished == STREAMS
    });
    assert_eq!(
        finished, STREAMS,
        "the client finished every stream within 3 s"
    );
    assert_eq!(server_streams.len(), STREAMS);
}

/// Over the tests' in-memory link, the server answers with as much as the
/// client lets it send on the stream at once. Once the server has processed
/// a Handshake packet the client's address is validated (RFC 9000 §8.1), so
/// the anti-amplification limit no longer holds the answer to three times
/// what the client sends: it arrives well within the harness's 3 s.
#[test]
fn a_server_sends_past_the_anti_amplification_limit_once_the_handshake_validates_the_client() {
    const ANSWER: usize = 16_384;
    let clock = tls_clock();
    let mut client_stream = None;
    let mut server_layer = None;
    let mut server_stream = None;
    let (mut request, mut answer) = (Vec::new(), Vec::new());
    let mut answered = false;
    let mut done = false;
    handshake(client_engine(&clock, 1), &clock, |run| {
        if client_stream.is_none()
            && let Poll::Ready(layer) = poll_now(run.client_handle.established())
        {
            let layer = layer.expect("the client's handshake completed");
            let (mut writer, reader) = layer.try_open_bi().expect("the server grants streams");
            ready(writer.write_all_unpin(Bytes::from_static(b"get")))
                .expect("the request is written");
            writer.close().expect("the request ends");
            client_stream = Some((writer, reader));
        }
        if server_layer.is_none()
            && let Poll::Ready(layer) = poll_now(run.server_handle.established())
        {
            server_layer = Some(layer.expect("the server's handshake completed"));
        }
        if server_stream.is_none()
            && let Some(layer) = &server_layer
            && let Poll::Ready(stream) = poll_now(layer.accept_bi())
        {
            server_stream = Some(stream.expect("the client's stream is accepted"));
        }
        if let Some((writer, reader)) = &mut server_stream
            && !answered
            && read_now!(reader, request)
        {
            ready(writer.write_all_unpin(Bytes::from(vec![7; ANSWER])))
                .expect("the answer is written");
            writer.close().expect("the answer ends");
            answered = true;
        }
        if let Some((_, reader)) = &mut client_stream
            && !done
        {
            done = read_now!(reader, answer);
        }
        done
    });
    assert!(done, "the client read the answer's end within 3 s");
    assert_eq!(request, b"get");
    assert_eq!(answer.len(), ANSWER);
}

/// Over the tests' in-memory link, a client completes the handshake and
/// opens a stream; then its link ends. The connection ends at once, with
/// the link's end as its reason, which the layer and the stream report
/// too, and the client sends nothing more.
#[test]
fn a_client_whose_link_ends_reports_the_end_everywhere_and_sends_nothing_more() {
    let clock = tls_clock();
    let mut stream = None;
    let mut layer = None;
    let mut sent_before_end = None;
    let run = handshake(client_engine(&clock, 1), &clock, |run| {
        if stream.is_none()
            && let Poll::Ready(established) = poll_now(run.client_handle.established())
        {
            let established = established.expect("the client's handshake completed");
            stream = Some(
                established
                    .try_open_bi()
                    .expect("the server grants streams"),
            );
            layer = Some(established);
            sent_before_end = Some(run.client_sent.len());
            common::end_link(&run.client_link);
        }
        run.client_ended
    });
    assert!(run.client_ended, "the client's connection ended");
    assert_eq!(
        Some(run.client_sent.len()),
        sent_before_end,
        "nothing is sent once the link ended"
    );
    let link_ended = |reason: &CloseReason<CloseCauseOf<ClientChoices, Parts>>| {
        matches!(
            reason,
            CloseReason::Local(cause) if matches!(**cause, LocalCloseCause::LinkEnded(()))
        )
    };
    let closed = ready(run.client_handle.closed());
    assert!(link_ended(&closed), "{closed:?}");
    let layer = layer.expect("the client's layer");
    assert!(matches!(
        ready(layer.ended()),
        LayerEnd::ConnectionClosed(reason) if link_ended(&reason)
    ));
    let (mut writer, _) = stream.expect("the client's stream");
    let Poll::Ready(Err(error)) = poll_now(writer.write_all_unpin(Bytes::from_static(b"late")))
    else {
        panic!("the write fails at once");
    };
    assert!(
        matches!(
            error.host_error(),
            Some(WriteError::LayerEnded { source })
                if matches!(source.end(), LayerEnd::ConnectionClosed(reason) if link_ended(reason))
        ),
        "{error:?}"
    );
}

/// Over the tests' in-memory link, a client completes the handshake and
/// waits on its layer: to read a stream, to write past the stream's limit,
/// to open a stream past the server's limit, and to accept one. Then a
/// poll of the client's connection panics, the host catches the panic and
/// drops the driver, which runs no end action: every wait that was pending
/// is woken and ends with the layer's end, the driver's panic.
#[test]
fn a_panic_in_the_clients_poll_ends_every_wait_on_its_streams() {
    let clock = tls_clock();
    let maximum = NonZeroUsize::new(64).expect("not zero");
    let mut layer = None;
    let mut read = None;
    let mut write = None;
    let mut open = None;
    let mut accept = None;
    let mut others = Vec::new();
    let run = handshake(client_engine(&clock, 1), &clock, |run| {
        if run.client_panicked {
            return true;
        }
        if layer.is_some() {
            return false;
        }
        let Poll::Ready(Ok(client)) = poll_now(run.client_handle.established()) else {
            return false;
        };
        let (mut writer, mut reader) = client.try_open_bi().expect("the server grants streams");
        // the server grants four bidirectional streams
        for _ in 0..3 {
            others.push(client.try_open_bi().expect("the server grants streams"));
        }
        let mut reading = Waiting::new(async move { reader.read_chunk_unpin(maximum).await });
        // past the 16 KiB the server grants the stream
        let mut writing =
            Waiting::new(async move { writer.write_all_unpin(Bytes::from(vec![7; 20_000])).await });
        let mut opening = Waiting::new(client.open_bi_owned());
        let mut accepting = Waiting::new(client.accept_bi_owned());
        assert!(reading.poll().is_pending(), "the server sent nothing");
        assert!(writing.poll().is_pending(), "the stream's limit holds it");
        assert!(opening.poll().is_pending(), "the server's limit holds it");
        assert!(accepting.poll().is_pending(), "the server opened nothing");
        watch::panic_client();
        (read, write, open, accept) =
            (Some(reading), Some(writing), Some(opening), Some(accepting));
        layer = Some(client);
        false
    });
    assert!(run.client_panicked, "the client's poll panicked");
    let (mut read, mut write, mut open, mut accept) = (
        read.expect("waits"),
        write.expect("waits"),
        open.expect("waits"),
        accept.expect("waits"),
    );
    assert!(matches!(
        ready(run.client_handle.closed()),
        CloseReason::Aborted(AbortCause::Panicked)
    ));
    let layer = layer.expect("the client's layer");
    assert!(panicked(&ready(layer.ended())));
    for (wait, wakes) in [
        ("read", read.wakes()),
        ("write", write.wakes()),
        ("open", open.wakes()),
        ("accept", accept.wakes()),
    ] {
        assert!(wakes > 0, "the {wait} is woken");
    }
    let Poll::Ready(Err(error)) = read.poll() else {
        panic!("the read ends");
    };
    assert!(
        matches!(&error, ReadError::LayerEnded { source } if panicked(source.end())),
        "{error:?}"
    );
    let Poll::Ready(Err(error)) = write.poll() else {
        panic!("the write ends");
    };
    assert!(
        matches!(error.host_error(), Some(WriteError::LayerEnded { source }) if panicked(source.end())),
        "{error:?}"
    );
    assert!(matches!(open.poll(), Poll::Ready(Err(error)) if panicked(error.end())));
    assert!(matches!(accept.poll(), Poll::Ready(Err(error)) if panicked(error.end())));
    // every later operation reports the end at once
    let (mut writer, _) = others.pop().expect("a stream");
    assert!(matches!(
        writer.close(),
        Err(CloseError::LayerEnded { source }) if panicked(source.end())
    ));
    assert!(matches!(
        layer.try_open_uni(),
        Err(TryOpenStreamError::LayerEnded { source }) if panicked(source.end())
    ));
}

/// The compositions of the locked stream set, whose capabilities can be
/// held apart from the connection as well as through it: the other tests
/// run on the default set, held by the connection.
mod locked_set {
    use sakuya_connection::v1::streams::locked::LockedStreamSetFamily;

    use super::*;

    choices!(
        ServerChoices,
        v1::Server<ServerEngine, common::TestNewTokenIssuer>,
        common::events::RecordingEvents,
        sakuya_connection::send_strategy::ranked::RankedSendStrategy<I>,
        LockedStreamSetFamily
    );
    choices!(
        ClientChoices,
        v1::Client<ClientEngine, common::TestTokenSink, ContinueOnRetry, ()>,
        common::events::RecordingEvents,
        common::ending::IntentEndingSendStrategy<I>,
        LockedStreamSetFamily
    );
    /// The parts of these connections, as of the others.
    type Parts = HList![v1::Part, watch::Part];
    sakuya_connection::composition!(impl for ServerChoices: ServerChoices, Parts);
    sakuya_connection::composition!(impl for ClientChoices: ClientChoices, Parts);

    harness!(server: [HNil], client: [HNil]);

    exchange_measurement!(measure_exchanges_on_the_locked_stream_set);

    /// A request and its answer on a stream through the shared connection
    /// of the locked set: the layer's handle opens and accepts it.
    #[test]
    fn a_client_and_a_server_exchange_a_request_and_its_answer_through_the_connection() {
        let clock = tls_clock();
        let mut client_stream = None;
        let mut server_layer = None;
        let mut server_stream = None;
        let (mut request, mut answer) = (Vec::new(), Vec::new());
        let mut answered = false;
        let mut done = false;
        handshake(client_engine(&clock, 1), &clock, |run| {
            if client_stream.is_none()
                && let Poll::Ready(Ok(layer)) = poll_now(run.client_handle.established())
            {
                let (mut writer, reader) = layer.try_open_bi().expect("the server grants streams");
                ready(writer.write_all_unpin(Bytes::from_static(b"ping"))).expect("written");
                writer.close().expect("the request ends");
                client_stream = Some((writer, reader));
            }
            if server_layer.is_none()
                && let Poll::Ready(layer) = poll_now(run.server_handle.established())
            {
                server_layer = Some(layer.expect("the server's handshake completed"));
            }
            if server_stream.is_none()
                && let Some(layer) = &server_layer
                && let Poll::Ready(stream) = poll_now(layer.accept_bi())
            {
                server_stream = Some(stream.expect("the client's stream is accepted"));
            }
            if let Some((writer, reader)) = &mut server_stream
                && !answered
                && read_now!(reader, request)
            {
                ready(writer.write_all_unpin(Bytes::from_static(b"pong"))).expect("written");
                writer.close().expect("the answer ends");
                answered = true;
            }
            if let Some((_, reader)) = &mut client_stream
                && !done
            {
                done = read_now!(reader, answer);
            }
            done
        });
        assert!(done, "the client read the answer's end within 3 s");
        assert_eq!(request, b"ping");
        assert_eq!(answer, b"pong");
    }

    /// The client's strategy ends the intent of a stream's data when the
    /// client's link path changes role: the intent goes back to the stream,
    /// whose destination falls back and publishes it again at once, and the
    /// data reaches the server. While the link path is settling the data waits
    /// with the strategy; it is the return to the active role that ends it.
    /// The client's strategy keeps only what is published through its intake,
    /// as the locked set publishes.
    #[test]
    fn a_stream_intent_the_strategy_ends_is_published_again_and_its_data_arrives() {
        let clock = tls_clock();
        let mut step = 0;
        let mut client_stream = None;
        let mut published = (0, 0);
        let mut server_layer = None;
        let mut server_stream = None;
        let mut read = Vec::new();
        let mut done = false;
        handshake(client_engine(&clock, 1), &clock, |run| {
            let Poll::Ready(Ok(client)) = poll_now(run.client_handle.established()) else {
                return false;
            };
            match step {
                0 => watch::set_client_role(|now| LinkPathRole::Settling(now + ms(60_000))),
                1 => {
                    common::ending::end_at_next_role_change("Stream {");
                    let (mut writer, reader) =
                        client.try_open_bi().expect("the server grants streams");
                    ready(writer.write_all_unpin(Bytes::from_static(b"hello")))
                        .expect("the data is written");
                    writer.close().expect("the stream ends");
                    client_stream = Some((writer, reader));
                    published.0 = common::ending::published("Stream {");
                    watch::set_client_role(|_| LinkPathRole::Active);
                }
                2 => published.1 = common::ending::published("Stream {"),
                _ => {}
            }
            step += 1;
            if server_layer.is_none()
                && let Poll::Ready(layer) = poll_now(run.server_handle.established())
            {
                server_layer = Some(layer.expect("the server's handshake completed"));
            }
            if server_stream.is_none()
                && let Some(layer) = &server_layer
                && let Poll::Ready(stream) = poll_now(layer.accept_bi())
            {
                server_stream = Some(stream.expect("the client's stream is accepted"));
            }
            if let Some((_, reader)) = &mut server_stream
                && !done
            {
                done = read_now!(reader, read);
            }
            done
        });
        assert!(
            published.0 > 0,
            "the data's intent is published while settling"
        );
        assert_eq!(
            published.1,
            2 * published.0,
            "each intent ended is published again at once"
        );
        assert!(done, "the server read the stream's end within 3 s");
        assert_eq!(read, b"hello");
    }

    /// The same exchange as on a stream through the shared connection, on one
    /// with independent shares: the layer's handle opens and accepts it with
    /// the detached methods.
    #[test]
    fn a_client_and_a_server_exchange_a_request_and_its_answer_on_a_detached_stream() {
        let clock = tls_clock();
        let mut client_stream = None;
        let mut server_layer = None;
        let mut server_stream = None;
        let (mut request, mut answer) = (Vec::new(), Vec::new());
        let mut answered = false;
        let mut done = false;
        handshake(client_engine(&clock, 1), &clock, |run| {
            if client_stream.is_none()
                && let Poll::Ready(Ok(layer)) = poll_now(run.client_handle.established())
            {
                let (mut writer, reader) = layer
                    .try_open_bi_detached()
                    .expect("the server grants streams");
                ready(writer.write_all_unpin(Bytes::from_static(b"ping"))).expect("written");
                writer.close().expect("the request ends");
                client_stream = Some((writer, reader.into_shared::<Arc<HandleCredential>>()));
            }
            if server_layer.is_none()
                && let Poll::Ready(layer) = poll_now(run.server_handle.established())
            {
                server_layer = Some(layer.expect("the server's handshake completed"));
            }
            if server_stream.is_none()
                && let Some(layer) = &server_layer
                && let Poll::Ready(stream) = poll_now(layer.accept_bi_detached())
            {
                server_stream = Some(stream.expect("the client's stream is accepted"));
            }
            if let Some((writer, reader)) = &mut server_stream
                && !answered
                && read_now!(reader, request)
            {
                ready(writer.write_all_unpin(Bytes::from_static(b"pong"))).expect("written");
                writer.close().expect("the answer ends");
                answered = true;
            }
            if let Some((_, reader)) = &mut client_stream
                && !done
            {
                let mut clone = reader.clone();
                done = read_now!(clone, answer);
            }
            done
        });
        assert!(done, "the client read the answer's end within 3 s");
        assert_eq!(request, b"ping");
        assert_eq!(answer, b"pong");
    }
}

/// A client and a server whose compositions have the reliable stream reset
/// extension, each announcing `reset_stream_at` or not.
#[cfg(feature = "reset_stream_at")]
mod reliable {
    use std::cell::Cell;

    use sakuya_connection::{
        reset_stream_at::{self, ResetAtError, ResetStreamAtChoices, ResetStreamAtConnectionArgs},
        v1::parameters::UseConfiguredParameters,
    };
    use sakuya_stream::receive::read::ReadError;
    use sakuya_wire::{
        reset_stream_at::ResetStreamAt, v1::application_error::ApplicationErrorCode,
    };

    use super::*;

    /// The parts of these connections: version 1, the watch, and the
    /// extension.
    type Parts = HList![v1::Part, watch::Part, reset_stream_at::Part];
    // the DATAGRAM extension's tests compose this extension too
    impl ResetStreamAtChoices for ServerChoices {}
    impl ResetStreamAtChoices for ClientChoices {}
    sakuya_connection::composition!(impl for crate::ServerChoices: crate::ServerChoices, Parts);
    sakuya_connection::composition!(impl for crate::ClientChoices: crate::ClientChoices, Parts);

    thread_local! {
        /// Whether each side announces `reset_stream_at`: the server's
        /// first.
        static ANNOUNCES: Cell<[bool; 2]> = const { Cell::new([true, true]) };
    }

    /// The extension's facts of the side of `role`, as the test set them.
    fn slots(role: Role) -> ResetStreamAtConnectionArgs {
        let announces = ANNOUNCES.with(|announces| announces.get()[index(role)]);
        ResetStreamAtConnectionArgs {
            transport_parameters: frunk_core::hlist![announces.then_some(ResetStreamAt)],
            resumed_parameters_policy: UseConfiguredParameters,
        }
    }

    harness!(server: [HNil, slots(Role::Server)], client: [HNil, slots(Role::Client)]);

    /// Run a handshake with the server announcing `reset_stream_at` if
    /// `server` and the client if `client`, as [`handshake`] does.
    fn run_announcing(
        server: bool,
        client: bool,
        clock: &Arc<ManualClock>,
        done: impl FnMut(&Run) -> bool,
    ) -> Run {
        ANNOUNCES.with(|announces| announces.set([server, client]));
        handshake(client_engine(clock, 1), clock, done)
    }

    fn code(value: u32) -> ApplicationErrorCode {
        ApplicationErrorCode::new(VarInt::from_u32(value))
    }

    /// The client writes 10 bytes on a stream and resets it at a reliable
    /// size of 4: the server, which announced `reset_stream_at`, reads the
    /// first 4 bytes and then the reset, with its code and reliable size
    /// (draft-ietf-quic-reliable-stream-reset §4, §5). The client could
    /// reset so only because the server's parameter reached it.
    #[test]
    fn a_reset_at_a_reliable_size_delivers_the_prefix_and_then_the_reset() {
        let clock = tls_clock();
        let mut client_stream = None;
        let mut server_layer = None;
        let mut server_stream = None;
        let mut read = Vec::new();
        let mut reset = None;
        run_announcing(true, true, &clock, |run| {
            if client_stream.is_none()
                && let Poll::Ready(layer) = poll_now(run.client_handle.established())
            {
                let layer = layer.expect("the client's handshake completed");
                let (mut writer, reader) = layer.try_open_bi().expect("the server grants streams");
                ready(writer.write_all_unpin(Bytes::from_static(b"0123456789")))
                    .expect("the data is written");
                writer
                    .reset_at(code(7), VarInt::from_u32(4))
                    .expect("the server announced reset_stream_at");
                client_stream = Some((writer, reader));
            }
            if server_layer.is_none()
                && let Poll::Ready(layer) = poll_now(run.server_handle.established())
            {
                server_layer = Some(layer.expect("the server's handshake completed"));
            }
            if server_stream.is_none()
                && let Some(layer) = &server_layer
                && let Poll::Ready(stream) = poll_now(layer.accept_bi())
            {
                server_stream = Some(stream.expect("the client's stream is accepted"));
            }
            if let Some((_, reader)) = &mut server_stream
                && reset.is_none()
            {
                let maximum = NonZeroUsize::new(64).expect("not zero");
                loop {
                    match poll_now(reader.read_chunk_unpin(maximum)) {
                        Poll::Ready(Ok(Some(chunk))) => read.extend_from_slice(&chunk),
                        Poll::Ready(Ok(None)) => panic!("the stream was reset, not ended"),
                        Poll::Ready(Err(ReadError::Reset { reset: facts, .. })) => {
                            reset = Some(facts);
                            break;
                        }
                        Poll::Ready(Err(error)) => panic!("the stream is reset: {error:?}"),
                        Poll::Pending => break,
                    }
                }
            }
            reset.is_some()
        });
        let reset = reset.expect("the server read the reset within 3 s");
        assert_eq!(read, b"0123");
        assert_eq!(reset.code(), code(7));
        assert_eq!(reset.reliable_size(), VarInt::from_u32(4));
        let (server, client) = (noted(Role::Server), noted(Role::Client));
        assert_eq!(
            server.record, None,
            "the server's connection is not closing"
        );
        assert_eq!(
            client.record, None,
            "the client's connection is not closing"
        );
    }

    /// A server that does not announce `reset_stream_at` takes no
    /// RESET_STREAM_AT: the client's writer refuses to reset at a reliable
    /// size, and the stream stays as it was (draft §3).
    #[test]
    fn a_reset_at_a_reliable_size_needs_the_peers_parameter() {
        let clock = tls_clock();
        let mut refused = None;
        run_announcing(false, true, &clock, |run| {
            if let Poll::Ready(layer) = poll_now(run.client_handle.established()) {
                let layer = layer.expect("the client's handshake completed");
                let (mut writer, _) = layer.try_open_bi().expect("the server grants streams");
                ready(writer.write_all_unpin(Bytes::from_static(b"0123456789")))
                    .expect("the data is written");
                refused = Some(writer.reset_at(code(7), VarInt::from_u32(4)));
                writer.reset(code(8)).expect("a plain reset is taken");
                return true;
            }
            false
        });
        assert!(
            matches!(refused, Some(Err(ResetAtError::NotSupportedByPeer))),
            "{refused:?}"
        );
    }
}

/// A client and a server whose compositions have the DATAGRAM extension,
/// each announcing a `max_datagram_frame_size` or not; the tests send and
/// receive through the handles of the established layers the connection
/// handles give.
#[cfg(feature = "datagram")]
mod datagram {
    use std::cell::Cell;

    use sakuya_connection::datagram::{
        self, DatagramChoices, DatagramConnectionArgs, DatagramOverflow, DatagramQueueBounds,
        ServerReceivedDatagram,
        application::SendDatagramError,
        owned::OwnedDatagramQueuesConfig,
        send::{DatagramSettlement, DatagramState},
    };
    use sakuya_wire::datagram::MaxDatagramFrameSize;

    use super::*;

    impl DatagramChoices for ServerChoices {}

    impl DatagramChoices for ClientChoices {}

    /// The parts of these connections: version 1, the extension, and the
    /// watch; with the reliable stream reset extension too, version 1 is
    /// not first: the watch and that extension come before it, and the
    /// DATAGRAM extension last. Both orders run the same tests; one binary
    /// with both harnesses would not link with its debug information.
    #[cfg(not(feature = "reset_stream_at"))]
    type Parts = HList![v1::Part, datagram::Part, watch::Part];
    #[cfg(feature = "reset_stream_at")]
    type Parts = HList![
        watch::Part,
        sakuya_connection::reset_stream_at::Part,
        v1::Part,
        datagram::Part
    ];
    sakuya_connection::composition!(impl for crate::ServerChoices: crate::ServerChoices, Parts);
    sakuya_connection::composition!(impl for crate::ClientChoices: crate::ClientChoices, Parts);

    thread_local! {
        /// The `max_datagram_frame_size` each side announces: the
        /// server's first; 0 leaves it out.
        static ANNOUNCES: Cell<[u32; 2]> = const { Cell::new([65535, 65535]) };
        /// The server's bounds of the datagrams received; the default
        /// unless a test sets them.
        static SERVER_RECEIVES: Cell<Option<DatagramQueueBounds>> = const { Cell::new(None) };
    }

    /// The extension's facts of the side of `role`, as the test set them.
    fn datagram_args(role: Role) -> DatagramConnectionArgs<OwnedDatagramQueuesConfig> {
        let size = ANNOUNCES.with(|announces| announces.get()[index(role)]);
        DatagramConnectionArgs {
            transport_parameters: frunk_core::hlist![
                (size > 0).then(|| MaxDatagramFrameSize::new(VarInt::from_u32(size)))
            ],
            queues: OwnedDatagramQueuesConfig {
                receive: match role {
                    Role::Server => SERVER_RECEIVES.with(Cell::get).unwrap_or_default(),
                    Role::Client => DatagramQueueBounds::default(),
                },
                ..OwnedDatagramQueuesConfig::default()
            },
            resumed_parameters_policy: Default::default(),
        }
    }

    #[cfg(not(feature = "reset_stream_at"))]
    harness!(server: [datagram_args(Role::Server), HNil], client: [datagram_args(Role::Client), HNil]);
    #[cfg(feature = "reset_stream_at")]
    harness!(
        server: [
            HNil,
            sakuya_connection::reset_stream_at::ResetStreamAtConnectionArgs {
                transport_parameters: frunk_core::hlist![Some(
                    sakuya_wire::reset_stream_at::ResetStreamAt
                )],
                resumed_parameters_policy: Default::default(),
            }
        ] [datagram_args(Role::Server)],
        client: [
            HNil,
            sakuya_connection::reset_stream_at::ResetStreamAtConnectionArgs {
                transport_parameters: frunk_core::hlist![Some(
                    sakuya_wire::reset_stream_at::ResetStreamAt
                )],
                resumed_parameters_policy: Default::default(),
            }
        ] [datagram_args(Role::Client)]
    );

    /// Run a handshake with the server announcing `server` and the client
    /// `client` as their `max_datagram_frame_size`, as [`handshake`] does.
    fn run_announcing(
        server: u32,
        client: u32,
        clock: &Arc<ManualClock>,
        done: impl FnMut(&Run) -> bool,
    ) -> Run {
        ANNOUNCES.with(|announces| announces.set([server, client]));
        handshake(client_engine(clock, 1), clock, done)
    }

    /// The client opens a stream and sends a datagram through the same
    /// handle of its established layer, and the server accepts the stream
    /// and receives the datagram through the same handle of its own: the
    /// capabilities find their shares wherever the parts are.
    #[test]
    fn one_layer_handle_opens_streams_and_exchanges_datagrams() {
        let clock = tls_clock();
        let mut client_stream = None;
        let mut server_stream = None;
        let mut read = Vec::new();
        let mut received = None;
        run_announcing(65535, 65535, &clock, |run| {
            let Poll::Ready(Ok(client)) = poll_now(run.client_handle.established()) else {
                return false;
            };
            if client_stream.is_none() {
                let (mut writer, reader) = client.try_open_bi().expect("the server grants streams");
                ready(writer.write_all_unpin(Bytes::from_static(b"hello")))
                    .expect("the data is written");
                writer.close().expect("the stream ends");
                client
                    .datagram_writer()
                    .send(Bytes::from_static(b"ping"))
                    .expect("the server announced support")
                    .release();
                client_stream = Some((writer, reader));
            }
            let Poll::Ready(Ok(server)) = poll_now(run.server_handle.established()) else {
                return false;
            };
            if server_stream.is_none()
                && let Poll::Ready(stream) = poll_now(server.accept_bi())
            {
                server_stream = Some(stream.expect("the client's stream is accepted"));
            }
            if let Some((_, reader)) = &mut server_stream {
                let maximum = NonZeroUsize::new(64).expect("not zero");
                while let Poll::Ready(Ok(Some(chunk))) = poll_now(reader.read_chunk_unpin(maximum))
                {
                    read.extend_from_slice(&chunk);
                }
            }
            if received.is_none()
                && let Poll::Ready(datagram) = poll_now(server.recv_datagram())
            {
                let datagram: ServerReceivedDatagram = datagram.expect("the layer goes on");
                received = Some(datagram.into_bytes());
            }
            read == b"hello" && received.is_some()
        });
        assert_eq!(read, b"hello");
        assert_eq!(received, Some(Bytes::from_static(b"ping")));
        let (server, client) = (noted(Role::Server), noted(Role::Client));
        assert_eq!(
            server.record, None,
            "the server's connection is not closing"
        );
        assert_eq!(
            client.record, None,
            "the client's connection is not closing"
        );
    }

    /// Over the tests' in-memory link, a client completes the handshake,
    /// waits to receive a datagram, and sends one whose ticket waits to be
    /// settled; before the datagram is written, a poll of the client's
    /// connection panics, the host catches the panic and drops the driver.
    /// Both waits are woken: the receive ends with the layer's end, the
    /// driver's panic, and the ticket settles as withdrawn as the layer
    /// ended.
    #[test]
    fn a_panic_in_the_clients_poll_ends_the_waits_on_its_datagrams() {
        let clock = tls_clock();
        let mut layer = None;
        let mut receive = None;
        let mut settle = None;
        let run = run_announcing(65535, 65535, &clock, |run| {
            if run.client_panicked {
                return true;
            }
            if layer.is_some() {
                return false;
            }
            let Poll::Ready(Ok(client)) = poll_now(run.client_handle.established()) else {
                return false;
            };
            let mut receiving = Waiting::new(client.recv_datagram_owned());
            let mut ticket = client
                .datagram_writer()
                .send(Bytes::from_static(b"ping"))
                .expect("the server announced support");
            assert_eq!(ticket.state(), DatagramState::Waiting);
            let mut settling = Waiting::new(async move {
                let settlement = ticket.settled().await;
                (settlement, ticket)
            });
            assert!(receiving.poll().is_pending(), "the server sent nothing");
            assert!(settling.poll().is_pending(), "the datagram waits");
            watch::panic_client();
            (receive, settle) = (Some(receiving), Some(settling));
            layer = Some(client);
            false
        });
        assert!(run.client_panicked, "the client's poll panicked");
        let (mut receive, mut settle) = (receive.expect("waits"), settle.expect("waits"));
        assert!(receive.wakes() > 0, "the receive is woken");
        assert!(settle.wakes() > 0, "the ticket's wait is woken");
        assert!(matches!(receive.poll(), Poll::Ready(Err(error)) if panicked(error.end())));
        let Poll::Ready((settlement, ticket)) = settle.poll() else {
            panic!("the ticket settles");
        };
        assert_eq!(
            settlement,
            DatagramSettlement::Withdrawn(datagram::send::DatagramWithdrawCause::LayerEnded)
        );
        assert_eq!(
            ticket.state(),
            DatagramState::Withdrawn(datagram::send::DatagramWithdrawCause::LayerEnded)
        );
        ticket.release();
        let layer = layer.expect("the client's layer");
        assert!(matches!(
            layer.datagram_writer().send(Bytes::from_static(b"late")),
            Err(SendDatagramError::LayerEnded { source }) if panicked(source.end())
        ));
    }

    /// A datagram written into a packet whose acknowledgment has not come
    /// when the client's poll panics settles as lost: its packet's fate is
    /// never known. One more datagram sent after it moves it out of the
    /// send queue first, so that it is woken from among those in flight.
    #[test]
    fn a_panic_in_the_clients_poll_settles_a_datagram_in_flight_as_lost() {
        let clock = tls_clock();
        let mut ticket = None;
        let mut settle = None;
        let mut later = None;
        let run = run_announcing(65535, 65535, &clock, |run| {
            if run.client_panicked {
                return true;
            }
            if settle.is_some() {
                return false;
            }
            let Poll::Ready(Ok(client)) = poll_now(run.client_handle.established()) else {
                return false;
            };
            let ticket = ticket.get_or_insert_with(|| {
                client
                    .datagram_writer()
                    .send(Bytes::from_static(b"ping"))
                    .expect("the server announced support")
            });
            if ticket.state() != DatagramState::Sent {
                return false;
            }
            let mut ticket = core::mem::replace(
                ticket,
                client
                    .datagram_writer()
                    .send(Bytes::from_static(b"pong"))
                    .expect("the server announced support"),
            );
            let mut settling = Waiting::new(async move {
                let settlement = ticket.settled().await;
                (settlement, ticket)
            });
            assert!(settling.poll().is_pending(), "the datagram is in flight");
            watch::panic_client();
            settle = Some(settling);
            later = Some(client);
            false
        });
        assert!(run.client_panicked, "the client's poll panicked");
        let mut settle = settle.expect("a datagram was in flight before an acknowledgment");
        assert!(settle.wakes() > 0, "the ticket's wait is woken");
        let Poll::Ready((settlement, sent)) = settle.poll() else {
            panic!("the ticket settles");
        };
        assert_eq!(settlement, DatagramSettlement::Lost);
        assert_eq!(sent.state(), DatagramState::Lost);
        sent.release();
        ticket.expect("sent").release();
        drop(later);
    }

    /// The server keeps two datagrams received at most and takes no new
    /// one beyond them; the client sends three, which the server does not
    /// read. Its layer counts the one it dropped. Once the server closes
    /// the connection, its layer is gone, and what its queues received
    /// stays: it reads the first datagram while the connection closes and
    /// the second once the connection ended, and only then the layer's end;
    /// the count of what was dropped stays all along.
    #[test]
    fn what_a_layer_received_is_read_after_it_ended_and_its_drops_still_count() {
        let clock = tls_clock();
        SERVER_RECEIVES.with(|bounds| {
            bounds.set(Some(DatagramQueueBounds {
                datagrams: NonZeroUsize::new(2).expect("not zero"),
                bytes: 1024,
                overflow: DatagramOverflow::RejectNew,
            }))
        });
        let mut sent = false;
        let mut server_layer = None;
        let mut closed = false;
        let mut during_close = None;
        run_announcing(65535, 65535, &clock, |run| {
            let Poll::Ready(Ok(client)) = poll_now(run.client_handle.established()) else {
                return false;
            };
            if !sent {
                let writer = client.datagram_writer();
                for payload in [&b"one"[..], b"two", b"three"] {
                    writer
                        .send(Bytes::from_static(payload))
                        .expect("the server announced support")
                        .release();
                }
                sent = true;
            }
            if server_layer.is_none()
                && let Poll::Ready(layer) = poll_now(run.server_handle.established())
            {
                server_layer = Some(layer.expect("the server's handshake completed"));
            }
            let Some(server) = &server_layer else {
                return false;
            };
            if !closed {
                if server.dropped_datagrams() == 1 {
                    run.server_handle.close(common::AppClose(7));
                    closed = true;
                }
                return false;
            }
            if during_close.is_none() {
                assert!(
                    matches!(poll_now(server.ended()), Poll::Ready(_)),
                    "the layer ended with the close"
                );
                assert!(!run.server_ended, "the connection closes");
                let Poll::Ready(first) = poll_now(Datagrams::recv_datagram(server)) else {
                    panic!("what was received is there at once");
                };
                let first: ServerReceivedDatagram = first.expect("received before the end");
                during_close = Some((first.into_bytes(), server.dropped_datagrams()));
            }
            true
        });
        SERVER_RECEIVES.with(|bounds| bounds.set(None));
        assert_eq!(
            during_close,
            Some((Bytes::from_static(b"one"), 1)),
            "read while the connection closes"
        );
        let server = server_layer.expect("the server's layer");
        let Poll::Ready(Ok(second)) = poll_now(Datagrams::recv_datagram(&server)) else {
            panic!("the second is read once the connection ended");
        };
        assert_eq!(second.into_bytes(), Bytes::from_static(b"two"));
        assert!(matches!(
            poll_now(Datagrams::recv_datagram(&server)),
            Poll::Ready(Err(_))
        ));
        assert_eq!(server.dropped_datagrams(), 1);
    }

    /// A ticket turned into one with a shared credential is cloned: the
    /// clones read the same datagram, and dropping one of them does not
    /// withdraw it; dropping the last withdraws a datagram not written yet.
    #[test]
    fn a_shared_ticket_settles_its_datagram_and_its_last_drop_withdraws() {
        let clock = tls_clock();
        let mut tickets = None;
        let mut received = Vec::new();
        let mut settled = None;
        run_announcing(65535, 65535, &clock, |run| {
            let (Poll::Ready(Ok(client)), Poll::Ready(Ok(server))) = (
                poll_now(run.client_handle.established()),
                poll_now(run.server_handle.established()),
            ) else {
                return false;
            };
            if tickets.is_none() {
                let ticket = client
                    .datagram_writer()
                    .send(Bytes::from_static(b"shared"))
                    .expect("the server announced support")
                    .into_shared::<Rc<HandleCredential>>();
                let other = ticket.clone();
                drop(ticket);
                tickets = Some(other);
                let dropped = client
                    .datagram_writer()
                    .send(Bytes::from_static(b"dropped"))
                    .expect("the server announced support");
                assert_eq!(dropped.state(), DatagramState::Waiting);
                drop(dropped);
            }
            while let Poll::Ready(datagram) = poll_now(Datagrams::recv_datagram(&server)) {
                let datagram: ServerReceivedDatagram = datagram.expect("the layer goes on");
                received.push(datagram.into_bytes());
            }
            if let Some(ticket) = &mut tickets
                && settled.is_none()
                && let Poll::Ready(settlement) = poll_now(ticket.settled())
            {
                settled = Some(settlement);
            }
            settled.is_some()
        });
        assert_eq!(
            received,
            [Bytes::from_static(b"shared")],
            "the drop of one clone withdrew nothing, the drop of the last its datagram"
        );
        assert_eq!(settled, Some(DatagramSettlement::Acknowledged));
        tickets.expect("sent").release();
    }

    #[test]
    fn a_client_and_a_server_exchange_datagrams() {
        let clock = tls_clock();
        let mut ticket = None;
        let mut answered = false;
        let mut answer = None;
        let mut settled = None;
        run_announcing(65535, 65535, &clock, |run| {
            let (Poll::Ready(Ok(client)), Poll::Ready(Ok(server))) = (
                poll_now(run.client_handle.established()),
                poll_now(run.server_handle.established()),
            ) else {
                return false;
            };
            if ticket.is_none() {
                let writer = Datagrams::datagram_writer(&client);
                ticket = Some(
                    writer
                        .send(Bytes::from_static(b"ping"))
                        .expect("the server announced support"),
                );
            }
            if !answered && let Poll::Ready(received) = poll_now(Datagrams::recv_datagram(&server))
            {
                let received: ServerReceivedDatagram = received.expect("the layer goes on");
                assert!(!received.received_zero_rtt());
                assert_eq!(received.into_bytes(), Bytes::from_static(b"ping"));
                Datagrams::datagram_writer(&server)
                    .send(Bytes::from_static(b"pong"))
                    .expect("the client announced support")
                    .release();
                answered = true;
            }
            if answer.is_none()
                && let Poll::Ready(received) = poll_now(Datagrams::recv_datagram(&client))
            {
                answer = Some(received.expect("the layer goes on"));
            }
            if let Some(ticket) = &mut ticket
                && settled.is_none()
                && let Poll::Ready(settlement) = poll_now(ticket.settled())
            {
                settled = Some(settlement);
            }
            answer.is_some() && settled.is_some()
        });
        assert_eq!(answer, Some(Bytes::from_static(b"pong")));
        assert_eq!(settled, Some(DatagramSettlement::Acknowledged));
        let ticket = ticket.expect("sent");
        assert_eq!(ticket.state(), DatagramState::Acknowledged);
        ticket.release();
        let (server, client) = (noted(Role::Server), noted(Role::Client));
        assert_eq!(
            server.record, None,
            "the server's connection is not closing"
        );
        assert_eq!(
            client.record, None,
            "the client's connection is not closing"
        );
    }

    /// A server that announces no `max_datagram_frame_size` takes no
    /// DATAGRAM frame: the client's writer refuses to send (RFC 9221 §3).
    #[test]
    fn nothing_is_sent_to_a_server_that_did_not_announce_support() {
        let clock = tls_clock();
        let mut refused = None;
        run_announcing(0, 65535, &clock, |run| {
            let Poll::Ready(Ok(client)) = poll_now(run.client_handle.established()) else {
                return false;
            };
            let writer = Datagrams::datagram_writer(&client);
            refused = Some(
                writer
                    .send(Bytes::from_static(b"ping"))
                    .map(|ticket| ticket.release()),
            );
            true
        });
        assert!(
            matches!(refused, Some(Err(SendDatagramError::NotSupportedByPeer))),
            "{refused:?}"
        );
    }

    /// A datagram over the server's limit, counted with a Length field, is
    /// refused with the limit (RFC 9221 §3); one at the limit is taken.
    #[test]
    fn a_datagram_over_the_servers_limit_is_too_large() {
        let clock = tls_clock();
        let mut results = None;
        run_announcing(100, 65535, &clock, |run| {
            let Poll::Ready(Ok(client)) = poll_now(run.client_handle.established()) else {
                return false;
            };
            let writer = Datagrams::datagram_writer(&client);
            let limits = writer.datagram_limits();
            let at_limit = writer
                .send(Bytes::from(vec![0; 97]))
                .map(|ticket| ticket.release());
            let over = writer
                .send(Bytes::from(vec![0; 98]))
                .map(|ticket| ticket.release());
            results = Some((limits.peer, at_limit, over));
            true
        });
        let (limit, at_limit, over) = results.expect("the client's layer was built");
        assert_eq!(limit, 97);
        assert!(at_limit.is_ok(), "{at_limit:?}");
        assert!(
            matches!(over, Err(SendDatagramError::TooLarge { limit: 97 })),
            "{over:?}"
        );
    }
}

/// A client and a server whose DATAGRAM queues are the locked ones, which
/// also give a share of the send queue apart from the connection, and
/// publish through the strategy's intake.
#[cfg(feature = "datagram")]
mod locked_datagram {
    use sakuya_connection::datagram::{
        self, DatagramChoices, DatagramConnectionArgs, ServerReceivedDatagram,
        application::DetachedDatagrams,
        locked::{LockedDatagramQueuesConfig, LockedDatagramQueuesFamily},
        send::{DatagramSettlement, DatagramState},
    };

    use super::*;

    /// The receiver of these connections' events, which keeps the events
    /// of the datagrams too.
    type DatagramEvents =
        common::events::RecordingEvents<frunk_core::Coprod![datagram::DatagramEvent]>;

    choices!(
        ServerChoices,
        v1::Server<ServerEngine, common::TestNewTokenIssuer>,
        DatagramEvents
    );
    choices!(
        ClientChoices,
        v1::Client<ClientEngine, common::TestTokenSink, ContinueOnRetry, ()>,
        DatagramEvents,
        common::ending::IntentEndingSendStrategy<I>
    );

    impl DatagramChoices for ServerChoices {
        type DatagramQueues = LockedDatagramQueuesFamily;
    }

    impl DatagramChoices for ClientChoices {
        type DatagramQueues = LockedDatagramQueuesFamily;
    }

    /// The parts of these connections: version 1, the extension, and the
    /// watch.
    type Parts = HList![v1::Part, datagram::Part, watch::Part];
    sakuya_connection::composition!(impl for ServerChoices: ServerChoices, Parts);
    sakuya_connection::composition!(impl for ClientChoices: ClientChoices, Parts);

    /// The extension's facts: the recommended `max_datagram_frame_size`
    /// and the default bounds.
    fn datagram_args() -> DatagramConnectionArgs<LockedDatagramQueuesConfig> {
        DatagramConnectionArgs::default()
    }

    harness!(server: [datagram_args(), HNil], client: [datagram_args(), HNil]);

    /// The client's strategy ends a datagram's intent when the client's
    /// link path changes role: the queues let its destination decide at
    /// once, which publishes it again with the same ticket, before any
    /// other send; the datagram then reaches the server and is
    /// acknowledged.
    #[test]
    fn a_datagram_intent_the_strategy_ends_is_published_again_at_once() {
        let clock = tls_clock();
        let mut step = 0;
        let mut ticket = None;
        let mut published = (0, 0);
        let mut state = None;
        let mut received = None;
        let mut settled = None;
        handshake(client_engine(&clock, 1), &clock, |run| {
            let (Poll::Ready(Ok(client)), Poll::Ready(Ok(server))) = (
                poll_now(run.client_handle.established()),
                poll_now(run.server_handle.established()),
            ) else {
                return false;
            };
            match step {
                0 => watch::set_client_role(|now| LinkPathRole::Settling(now + ms(60_000))),
                1 => {
                    common::ending::end_at_next_role_change("DatagramIntent");
                    ticket = Some(
                        Datagrams::datagram_writer(&client)
                            .send(Bytes::from_static(b"ping"))
                            .expect("the server announced support"),
                    );
                    published.0 = common::ending::published("DatagramIntent");
                    watch::set_client_role(|_| LinkPathRole::Active);
                }
                2 => {
                    published.1 = common::ending::published("DatagramIntent");
                    state = ticket.as_ref().map(|ticket| ticket.state());
                }
                _ => {}
            }
            step += 1;
            if received.is_none()
                && let Poll::Ready(datagram) = poll_now(Datagrams::recv_datagram(&server))
            {
                let datagram: ServerReceivedDatagram = datagram.expect("the layer goes on");
                received = Some(datagram.into_bytes());
            }
            if let Some(ticket) = &mut ticket
                && settled.is_none()
                && let Poll::Ready(settlement) = poll_now(ticket.settled())
            {
                settled = Some(settlement);
            }
            received.is_some() && settled.is_some()
        });
        assert_eq!(
            published,
            (1, 2),
            "published again once, with no other send"
        );
        assert!(
            matches!(state, Some(DatagramState::Waiting | DatagramState::Sent)),
            "the ticket goes on: {state:?}"
        );
        assert_eq!(received, Some(Bytes::from_static(b"ping")));
        assert_eq!(settled, Some(DatagramSettlement::Acknowledged));
        ticket.expect("sent").release();
    }

    /// A ticket turned into one with a shared credential is cloned: the
    /// clones read the same datagram, and dropping one of them does not
    /// withdraw it. The writer with an independent share sends as well,
    /// and its ticket settles alike.
    #[test]
    fn a_shared_ticket_and_a_detached_writer_settle_their_datagrams() {
        let clock = tls_clock();
        let mut tickets = None;
        let mut detached = None;
        let mut received = Vec::new();
        let mut settled = (None, None);
        handshake(client_engine(&clock, 1), &clock, |run| {
            let (Poll::Ready(Ok(client)), Poll::Ready(Ok(server))) = (
                poll_now(run.client_handle.established()),
                poll_now(run.server_handle.established()),
            ) else {
                return false;
            };
            if tickets.is_none() {
                let ticket = client
                    .datagram_writer()
                    .send(Bytes::from_static(b"shared"))
                    .expect("the server announced support")
                    .into_shared::<Rc<HandleCredential>>();
                let other = ticket.clone();
                drop(ticket);
                tickets = Some(other);
                detached = Some(
                    client
                        .datagram_writer_detached()
                        .send(Bytes::from_static(b"detached"))
                        .expect("the server announced support"),
                );
            }
            while let Poll::Ready(datagram) = poll_now(Datagrams::recv_datagram(&server)) {
                let datagram: ServerReceivedDatagram = datagram.expect("the layer goes on");
                received.push(datagram.into_bytes());
            }
            if let Some(ticket) = &mut tickets
                && settled.0.is_none()
                && let Poll::Ready(settlement) = poll_now(ticket.settled())
            {
                settled.0 = Some(settlement);
            }
            if let Some(ticket) = &mut detached
                && settled.1.is_none()
                && let Poll::Ready(settlement) = poll_now(ticket.settled())
            {
                settled.1 = Some(settlement);
            }
            settled.0.is_some() && settled.1.is_some()
        });
        received.sort();
        assert_eq!(
            received,
            [
                Bytes::from_static(b"detached"),
                Bytes::from_static(b"shared")
            ],
            "the drop of one clone withdrew nothing"
        );
        assert_eq!(
            settled,
            (
                Some(DatagramSettlement::Acknowledged),
                Some(DatagramSettlement::Acknowledged)
            )
        );
        tickets.expect("sent").release();
        detached.expect("sent").release();
    }
}

#[test]
fn a_server_that_receives_its_clients_hello_again_sends_its_own_again_at_once() {
    let clock = tls_clock();
    // the client's first flight arrives 100 ms late, and the link loses
    // the server's first two datagrams, its ServerHello with them: the
    // client's probe timeout expires first, and its probes carry the
    // ClientHello the server read already
    FIRST_FLIGHT_DELAY_MS.with(|delay| delay.set(100));
    SERVER_DATAGRAMS_LOST.with(|lost| lost.set(2));
    let run = handshake(client_engine(&clock, 1), &clock, |_| {
        noted(Role::Server).confirmed && noted(Role::Client).confirmed
    });
    FIRST_FLIGHT_DELAY_MS.with(|delay| delay.set(0));
    SERVER_DATAGRAMS_LOST.with(|lost| lost.set(0));
    let sent: Vec<_> = run
        .server_sent
        .iter()
        .map(|(at, datagram, lost)| (at.as_millis(), datagram.len(), *lost))
        .collect();
    assert!(
        noted(Role::Client).confirmed && noted(Role::Server).confirmed,
        "{sent:?}"
    );
    // the first two went at 100 ms, the server's probe timeout expires
    // about 1 s after; the duplicate ClientHello had it send its Initial
    // CRYPTO data at once, in a datagram expanded to 1200 bytes, where an
    // acknowledgment alone is not (RFC 9002 §6.2.3)
    let (at, datagram, lost) = &run.server_sent[2];
    assert!(
        !lost && *at < ms(1050) && datagram.len() >= 1200,
        "{sent:?}"
    );
    assert!(!run.server_ended && !run.client_ended);
}

#[test]
fn a_servers_second_probe_carries_its_initial_and_handshake_crypto_data_again() {
    let clock = tls_clock();
    // the server's address checks are passed, so that it sends both
    // probes at once; the link loses its first flight and its first
    // probe, and the client's own probes, which would have the server
    // answer at once (RFC 9002 §6.2.3)
    SERVER_ADDRESS_VALIDATED.with(|validated| validated.set(true));
    SERVER_DATAGRAMS_LOST.with(|lost| lost.set(3));
    CLIENT_DATAGRAMS_LOST_AT.with(|at| *at.borrow_mut() = vec![1, 2]);
    let run = handshake(client_engine(&clock, 1), &clock, |_| {
        noted(Role::Server).confirmed && noted(Role::Client).confirmed
    });
    SERVER_ADDRESS_VALIDATED.with(|validated| validated.set(false));
    SERVER_DATAGRAMS_LOST.with(|lost| lost.set(0));
    CLIENT_DATAGRAMS_LOST_AT.with(|at| at.borrow_mut().clear());
    let sent: Vec<_> = run
        .server_sent
        .iter()
        .map(|(at, datagram, lost)| (at.as_millis(), datagram.len(), *lost))
        .collect();
    assert!(
        noted(Role::Client).confirmed && noted(Role::Server).confirmed,
        "{sent:?}"
    );
    // the first flight went at once, the two probes about 1 s later
    let (probe_at, _, lost) = run.server_sent[2];
    assert!(lost && probe_at >= ms(900), "{sent:?}");
    let (second_at, _, lost) = run.server_sent[3];
    assert!(!lost && second_at == probe_at, "{sent:?}");
    // the second probe alone, its Initial packet and its Handshake
    // packet, had the client send its Finished: both carried the server's
    // CRYPTO data, which the first probe carried as well
    let received: Vec<_> = common::events::recorded(Role::Client)
        .into_iter()
        .take_while(|event| {
            !matches!(
                event,
                common::events::Recorded::Sent {
                    level: EncryptionLevel::Handshake,
                    ..
                }
            )
        })
        .filter_map(|event| match event {
            common::events::Recorded::Received { level, .. } => Some(level),
            _ => None,
        })
        .collect();
    assert_eq!(
        received,
        [EncryptionLevel::Initial, EncryptionLevel::Handshake],
        "the client's Finished went after the second probe's two packets: {sent:?}"
    );
    assert!(!run.server_ended && !run.client_ended);
}
