//! How much memory a forwarding application's zero-copy writes keep alive
//! on the sending side of another connection, when that connection's peer
//! acknowledges all but the last byte of each write.
//!
//! The application reads STREAM data from connection A and writes each chunk
//! it reads to a stream of connection B as it is, a \`Bytes\` that the
//! stream sender keeps without copying (\`TakePrefix for Bytes\`,
//! \`sakuya_stream_v1/src/send_buffer/covered_bytes.rs\`). A's data arrives in
//! order, one small piece per datagram, each datagram a slice of its own
//! receive block of the UDP binding (see [\`retention\`]); A delivers each at
//! once, so A holds nothing and its window is released. B's stream sender
//! has the default composition (\`sakuya_connection\`, \`streams/set_state.rs\`,
//! \`send_composition\`); its data is selected for sending, and the peer of B
//! acknowledges every byte of each write but the last.
//!
//! What the connections do around the stream parts (packets, frames, loss
//! detection) is not run here.
//!
//! This only measures and prints; it asserts no bound on the ratio.

#![cfg(target_os = "linux")]

mod retention;

use core::num::NonZeroUsize;
use std::sync::Arc;

use bytes::Bytes;
use retention::{BLOCK, CONNECTION_WINDOW, CloseCause, LiveBytes, STREAM_WINDOW, Wire, live, run};
use sakuya_stream_receive_buffer_fragmented::FragmentedStreamReceiveBuffer;
use sakuya_stream_sets::{
    receive::StreamReceiver,
    send::{StreamSender, termination::ResetOnAbandonTermination},
};
use sakuya_stream_v1::{
    connection_receive_flow::ConnectionReceiveFlowController,
    connection_send_credit::{
        AtomicConnectionCreditReservation, AtomicConnectionSendFlowController,
    },
    receive::{
        composition::ReceiveComposition, flow_control::SlidingWindowAdvertisement,
        read::ReadOutcome, termination::FollowingTermination,
    },
    send::{composition::SendComposition, flow_control::FullCeilingAdmission, write::WriteOutcome},
    send_buffer::offset_map::OffsetMapStreamSendBuffer,
    send_options::{SendOptions, destination::AnyActiveLinkPath, urgency::Urgency},
};
use sakuya_var_int::{VarInt, VarIntField};
use sakuya_wire_v1::{
    application_error::ApplicationErrorCode, frame::stream::StreamFrame, stream_id::StreamId,
};

#[global_allocator]
static ALLOCATOR: LiveBytes = LiveBytes;

/// The chunks forwarded, one per block.
const CHUNKS: u32 = 64;

/// How many times every unacknowledged byte is declared lost.
const LOSSES: usize = 1000;

/// The STREAM data of each of A's datagrams.
const CHUNK_LEN: usize = 32;

type Receiver = StreamReceiver<
    ReceiveComposition<
        FragmentedStreamReceiveBuffer,
        SlidingWindowAdvertisement,
        FollowingTermination,
    >,
    CloseCause,
>;

type Options = SendOptions<Urgency, AnyActiveLinkPath>;

type Sender = StreamSender<
    SendComposition<
        OffsetMapStreamSendBuffer<Bytes, AtomicConnectionCreditReservation, Options>,
        FullCeilingAdmission,
        ResetOnAbandonTermination,
    >,
    AtomicConnectionSendFlowController,
    CloseCause,
>;

fn code() -> ApplicationErrorCode {
    ApplicationErrorCode::new(VarInt::from_u32(0))
}

fn receiver() -> Receiver {
    let window = VarInt::from_u32(STREAM_WINDOW);
    StreamReceiver::new(
        ReceiveComposition::new(
            FragmentedStreamReceiveBuffer::new(),
            SlidingWindowAdvertisement::new(window),
            FollowingTermination::new(code()),
        ),
        window,
    )
}

/// The sender of B, under the limits B's peer grants: the default windows.
fn sender(connection: &Arc<AtomicConnectionSendFlowController>) -> Sender {
    StreamSender::new(
        StreamId::from_var_int(VarInt::from_u32(0)),
        VarInt::from_u32(STREAM_WINDOW),
        SendComposition::new(
            OffsetMapStreamSendBuffer::new(),
            FullCeilingAdmission::new(),
            ResetOnAbandonTermination::new(code(), code()),
        ),
        Arc::clone(connection),
    )
}

fn chunk_frame(offset: u32, data: Bytes) -> StreamFrame<Bytes, impl Sized> {
    StreamFrame::new(
        VarIntField::shortest(StreamId::from_var_int(VarInt::from_u32(0))),
        Some(VarIntField::shortest(VarInt::from_u32(offset))),
        data,
        false,
    )
    .expect("a valid STREAM frame")
}

#[test]
fn partly_acknowledged_forwarded_chunks_pin_whole_receive_blocks() {
    run(async {
        let wire = Wire::new().await;
        let mut a_flow = ConnectionReceiveFlowController::new(VarInt::from_u32(CONNECTION_WINDOW));
        let mut a = receiver();
        let b_flow = Arc::new(AtomicConnectionSendFlowController::new(VarInt::from_u32(
            CONNECTION_WINDOW,
        )));
        let mut b = sender(&b_flow);
        let options = Options::new(Urgency::default(), AnyActiveLinkPath);
        let before = live();

        let mut offset = 0;
        for _ in 0..CHUNKS {
            let carrier = wire.carrier().await;
            a.on_stream_frame(chunk_frame(offset, carrier.slice(..CHUNK_LEN)), &mut a_flow)
                .expect("within both windows");
            drop(carrier);
            // the application forwards what A delivers
            let ReadOutcome::Data(mut chunk) =
                a.read_chunk(NonZeroUsize::MAX).expect("the stream is open")
            else {
                panic!("the chunk is delivered at once");
            };
            assert!(matches!(
                b.write(&mut chunk, &options),
                Ok(WriteOutcome::Written(_))
            ));
            // B sends it, and B's peer acknowledges all of it but the last byte
            let selected = b
                .select(&AnyActiveLinkPath, CHUNK_LEN)
                .expect("the write waits to be sent");
            let start = selected.offset;
            let last = start.saturating_add(VarInt::from_u32(CHUNK_LEN as u32 - 1));
            drop(selected);
            b.on_data_acknowledged(start..last);
            offset += CHUNK_LEN as u32;
            wire.fill().await;
        }
        a.report_release(&mut a_flow).expect("the same controller");

        // B's peer never acknowledges the last bytes: each loss puts them
        // back to wait, and they are selected again, as often as it happens
        let mut reselected = 0;
        for _ in 0..LOSSES {
            for index in 0..CHUNKS {
                let tail = VarInt::from_u32((index + 1) * CHUNK_LEN as u32 - 1);
                b.on_data_lost(tail..tail.saturating_add(VarInt::from_u32(1)));
            }
            while let Some(selected) = b.select(&AnyActiveLinkPath, CHUNK_LEN) {
                reselected += selected.bytes.len();
            }
        }

        let holding = live();
        drop(a);
        let a_freed = holding - live();
        let unacknowledged: usize = b
            .composition()
            .buffer
            .retained()
            .map(|(_, bytes)| bytes.len())
            .sum();
        let b_state = b.send_state();
        let before_b = live();
        drop(b);
        let pinned = before_b - live();

        println!("chunks: {CHUNKS} of {CHUNK_LEN} bytes, one per block of {BLOCK} bytes");
        println!(
            "A: used {} bytes, released {} bytes; dropping A frees {a_freed} bytes",
            a_flow.used().get(),
            a_flow.released().get(),
        );
        println!(
            "B: written {} bytes, unacknowledged {unacknowledged} bytes",
            CHUNKS as usize * CHUNK_LEN
        );
        println!(
            "live heap while B holds them, over the start: {} bytes",
            holding - before
        );
        println!("freed by dropping B's stream sender: {pinned} bytes");
        println!(
            "pinned / unacknowledged: {:.0}",
            pinned as f64 / unacknowledged as f64
        );
        println!(
            "after {LOSSES} losses of each: {reselected} bytes selected again, the stream {:?}",
            b_state
        );

        assert_eq!(
            unacknowledged, CHUNKS as usize,
            "one byte of each write stays"
        );
    });
}
