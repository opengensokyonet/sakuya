//! A client and a server connection whose compositions have the DATAGRAM
//! extension run their handshake against each other, with the fixtures of
//! `sakuya_connection`'s handshake tests.
#![allow(
    clippy::arc_with_non_send_sync,
    reason = "the tests' routing domains are on one thread; deliverers are given as `Arc`s"
)]
#![feature(impl_trait_in_assoc_type, type_alias_impl_trait, yield_expr)]

#[path = "../../sakuya_connection/tests/common/mod.rs"]
mod common;
#[macro_use]
#[path = "../../sakuya_connection/tests/common/handshake.rs"]
mod fixtures;

use std::{
    cell::{Cell, RefCell},
    num::NonZeroUsize,
    rc::Rc,
    sync::Arc,
    task::Poll,
    time::Duration,
};

use bytes::Bytes;
use common::{Outer, TestClock, TestLink, TestReceiver, advance_to, ms, now};
use fixtures::*;
use kasen_handshake::{clock::ManualClock, message::MessageLimits};
use nitori_io::{ReadChunkHostExt as _, calls::WriteAllHostExt as _};
use sakuya_connection::prelude::*;
use sakuya_connection::v1::HostOf;
use sakuya_connection::{
    clock::ConnectionChoices,
    driver::LendNode,
    layer::{LinkPathArgs, LogicalPathArgs},
    role::LinkPathRole,
    shared::{DrivenFromOutside, SharedConnectionDriver},
    v1::{
        self, Side,
        advancing::HandshakeStart,
        amplification::{AddressValidation, AntiAmplificationFactor},
        application_handles::connection::ConnectionHandle,
        close_request::CloseRequestCell,
        connection_ids::FirstLocalConnectionId,
        crypto::CryptoReceiveCapacities,
        first_flight::FirstFlight,
        handshake_done::ClientOnlyStart,
        input::InitialPathReceiver,
        link::LinkFacts,
        retry::ContinueOnRetry,
    },
};
use sakuya_connection_datagram::{
    DatagramChoices,
    application::{Datagrams, DatagramsOwned, DroppedDatagrams},
};
use sakuya_link::LinkId;
use sakuya_packet_protection_ring::RingBackend;
use sakuya_recovery_v1::{loss::LossThresholds, receive_journals::MaxAckRanges};
use sakuya_wire::parts::{HList, HNil};
use sakuya_wire_v1::var_int::VarInt;
use sakuya_wire_v1::{
    role::Role,
    stream_count::StreamCount,
    transport_parameters::{
        TransportParameters,
        integer::{
            ActiveConnectionIdLimit, InitialMaxData, InitialMaxStreamDataBidiLocal,
            InitialMaxStreamDataBidiRemote, InitialMaxStreamsBidi, MaxIdleTimeout,
        },
    },
};

choices!(
    ServerChoices,
    v1::Server<ServerEngine, common::TestNewTokenIssuer>,
    DatagramEventSink
);
// the client's strategy plans as the ranked one does, and ends the intents
// a test marks when its link path's role next changes
choices!(
    ClientChoices,
    v1::Client<ClientEngine, common::TestTokenSink, ContinueOnRetry, ()>,
    DatagramEventSink,
    common::ending::IntentEndingSendStrategy<I>
);

/// The receiver of these connections' events, which keeps the events of
/// the datagrams too.
type DatagramEventSink =
    common::events::RecordingEvents<frunk_core::Coprod![sakuya_connection_datagram::DatagramEvent]>;

impl DatagramChoices for ServerChoices {}

impl DatagramChoices for ClientChoices {}

/// A client and a server whose compositions have the DATAGRAM extension
/// (the tests in `handshake/datagram.rs`): the parts of these connections
/// are the watch, version 1 and the extension, so version 1 is not first.
/// The same tests with version 1 first are a test target of their own,
/// `handshake_v1_first`: one binary with both compositions would carry
/// the debug information of both.
#[path = "handshake"]
mod datagram {
    use super::*;

    type Parts = HList![watch::Part, v1::Part, sakuya_connection_datagram::Part];
    sakuya_connection::composition!(impl for crate::ServerChoices: crate::ServerChoices, Parts);
    sakuya_connection::composition!(impl for crate::ClientChoices: crate::ClientChoices, Parts);

    /// The facts of the parts of each side, around version 1's.
    macro_rules! datagram_harness {
        () => {
            harness!(
                server: [HNil] [datagram_args(Role::Server)],
                client: [HNil] [datagram_args(Role::Client)]
            );
        };
    }

    #[path = "datagram.rs"]
    mod cases;
}

/// A client and a server whose DATAGRAM queues are the locked ones, which
/// also give a share of the send queue apart from the connection, and
/// publish through the strategy's intake.
mod locked_datagram {
    use sakuya_connection_datagram::{
        self as datagram, DatagramChoices, DatagramConnectionArgs, ServerReceivedDatagram,
        application::DetachedDatagrams,
        locked::{LockedDatagramQueuesConfig, LockedDatagramQueuesFamily},
        send::{DatagramSettlement, DatagramState, DatagramTicketCredential},
    };

    use super::*;

    /// The receiver of these connections' events, which keeps the events
    /// of the datagrams too.
    type DatagramEventSink =
        common::events::RecordingEvents<frunk_core::Coprod![datagram::DatagramEvent]>;

    choices!(
        ServerChoices,
        v1::Server<ServerEngine, common::TestNewTokenIssuer>,
        DatagramEventSink
    );
    choices!(
        ClientChoices,
        v1::Client<ClientEngine, common::TestTokenSink, ContinueOnRetry, ()>,
        DatagramEventSink,
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
                    .into_shared::<Rc<DatagramTicketCredential>>();
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
