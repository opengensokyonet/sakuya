//! A client and a server connection whose compositions have the reliable
//! stream reset extension run their handshake against each other, with the
//! fixtures of `sakuya_connection`'s handshake tests.
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
use sakuya_connection_reset_stream_at::StreamResetAt;
use sakuya_link::LinkId;
use sakuya_packet_protection_ring::RingBackend;
use sakuya_recovery_v1::{loss::LossThresholds, receive_journals::MaxAckRanges};
use sakuya_var_int::VarInt;
use sakuya_wire::parts::{HList, HNil};
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

/// A client and a server whose compositions have the reliable stream reset
/// extension, each announcing `reset_stream_at` or not.
mod reliable {
    use std::cell::Cell;

    use sakuya_connection::v1::parameters::UseConfiguredParameters;
    use sakuya_connection_reset_stream_at::{
        self as reset_stream_at, ResetAtError, ResetStreamAtChoices, ResetStreamAtConnectionArgs,
    };
    use sakuya_stream_v1::receive::read::ReadError;
    use sakuya_wire_reset_stream_at::ResetStreamAt;
    use sakuya_wire_v1::application_error::ApplicationErrorCode;

    use super::*;

    /// The parts of these connections: version 1, the watch, and the
    /// extension.
    type Parts = HList![v1::Part, watch::Part, reset_stream_at::Part];
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
        clock: &Arc<ManualClock<TlsSynchronization>>,
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
                ready(writer.write_all_unpin(Bytes::from_static(b"0123456789"), ()))
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
                        Poll::Ready(Ok(Some(nitori_io::ChunkSegment {
                            chunk,
                            metadata: (),
                        }))) => read.extend_from_slice(&chunk),
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
                ready(writer.write_all_unpin(Bytes::from_static(b"0123456789"), ()))
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
