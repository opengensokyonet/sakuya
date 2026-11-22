//! The tests of `handshake.rs` whose compositions have the DATAGRAM
//! extension, with version 1 first among the parts: a test target of its
//! own, so that each binary carries the debug information of one
//! composition.
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

use std::{cell::RefCell, num::NonZeroUsize, rc::Rc, sync::Arc, task::Poll, time::Duration};

use bytes::Bytes;
use common::{Outer, TestClock, TestLink, TestReceiver, advance_to, ms, now};
use fixtures::*;
use kasen_handshake::{clock::ManualClock, message::MessageLimits};
use nitori_io::{ReadChunkHostExt as _, calls::WriteAllHostExt as _};
use sakuya_connection::prelude::*;
use sakuya_connection::v1::{HostChoices, HostOf};
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
/// are version 1, the extension and the watch.
#[path = "handshake"]
mod datagram {
    use super::*;

    type Parts = HList![v1::Part, sakuya_connection_datagram::Part, watch::Part];
    sakuya_connection::composition!(impl for crate::ServerChoices: crate::ServerChoices, Parts);
    sakuya_connection::composition!(impl for crate::ClientChoices: crate::ClientChoices, Parts);

    /// The facts of the parts of each side, around version 1's.
    macro_rules! datagram_harness {
        () => {
            harness!(
                server: [datagram_args(Role::Server), HNil],
                client: [datagram_args(Role::Client), HNil]
            );
        };
    }

    #[path = "datagram.rs"]
    mod cases;
}
