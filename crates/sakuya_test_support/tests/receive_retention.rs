//! How much memory out-of-order STREAM data keeps alive on the receive path,
//! against how much the receive windows let the peer use.
//!
//! Each piece is one byte of STREAM data, a slice of a datagram the UDP
//! binding handed out (see [\`retention\`]), given to a stream receiver of the
//! default composition (the fragmented receive buffer, the sliding window and
//! the following termination, as \`sakuya_connection\` makes it in
//! \`streams/set_state.rs\`, \`new_receiving_end\`) under the default windows.
//! What the connection does in between is not run here: it opens the packet
//! in place and reads the frame's data as a slice of the packet, copying
//! nothing either.
//!
//! The pieces sit above a gap at offset 0, so none is delivered.
//!
//! This only measures and prints; it asserts no bound on the ratio.

#![cfg(target_os = "linux")]

mod retention;

use bytes::Bytes;
use retention::{
    BLOCK, CARRIER_LEN, CONNECTION_WINDOW, CloseCause, LiveBytes, STREAM_WINDOW, Wire, live, run,
};
use sakuya_stream_receive_buffer_fragmented::FragmentedStreamReceiveBuffer;
use sakuya_stream_sets::receive::StreamReceiver;
use sakuya_stream_v1::{
    connection_receive_flow::ConnectionReceiveFlowController,
    receive::{
        composition::ReceiveComposition, flow_control::SlidingWindowAdvertisement,
        termination::FollowingTermination,
    },
};
use sakuya_var_int::{VarInt, VarIntField};
use sakuya_wire_v1::{
    application_error::ApplicationErrorCode, frame::stream::StreamFrame, stream_id::StreamId,
};

#[global_allocator]
static ALLOCATOR: LiveBytes = LiveBytes;

/// The pieces the attacker leaves, one per block.
const PIECES: u32 = 64;

type Receiver = StreamReceiver<
    ReceiveComposition<
        FragmentedStreamReceiveBuffer,
        SlidingWindowAdvertisement,
        FollowingTermination,
    >,
    CloseCause,
>;

fn receiver() -> Receiver {
    let window = VarInt::from_u32(STREAM_WINDOW);
    StreamReceiver::new(
        ReceiveComposition::new(
            FragmentedStreamReceiveBuffer::new(),
            SlidingWindowAdvertisement::new(window),
            FollowingTermination::new(ApplicationErrorCode::new(VarInt::from_u32(0))),
        ),
        window,
    )
}

/// STREAM data of stream 0 at \`offset\`.
fn piece(offset: u32, data: Bytes) -> StreamFrame<Bytes, impl Sized> {
    StreamFrame::new(
        VarIntField::shortest(StreamId::from_var_int(VarInt::from_u32(0))),
        Some(VarIntField::shortest(VarInt::from_u32(offset))),
        data,
        false,
    )
    .expect("a valid STREAM frame")
}

#[test]
fn out_of_order_pieces_pin_whole_receive_blocks() {
    run(async {
        let wire = Wire::new().await;
        let mut connection =
            ConnectionReceiveFlowController::new(VarInt::from_u32(CONNECTION_WINDOW));
        let mut stream = receiver();
        let before = live();

        for index in 0..PIECES {
            let carrier = wire.carrier().await;
            // above the gap at offset 0, one byte apart
            stream
                .on_stream_frame(piece(1 + index, carrier.slice(..1)), &mut connection)
                .expect("within both windows");
            drop(carrier);
            wire.fill().await;
        }

        let holding = live();
        let accounted = connection.used().get();
        let held = stream.parts().buffer.held_len();
        drop(stream);
        let pinned = holding - live();

        let sent = u64::from(PIECES) * CARRIER_LEN as u64;
        println!("pieces: {PIECES}, one per block of {BLOCK} bytes");
        println!("accounted by flow control (connection used): {accounted} bytes");
        println!("held payload (held_len): {held} bytes");
        println!(
            "live heap while holding, over the start: {} bytes",
            holding - before
        );
        println!("freed by dropping the stream receiver: {pinned} bytes");
        println!(
            "pinned / accounted: {:.0}",
            pinned as f64 / accounted as f64
        );
        println!(
            "pinned / attacker's datagram bytes: {:.0}",
            pinned as f64 / sent as f64
        );
        println!(
            "one-byte pieces the default windows admit: {STREAM_WINDOW} on a bidirectional stream, {CONNECTION_WINDOW} on the connection"
        );

        assert_eq!(held, PIECES as usize, "every piece is held");
        assert_eq!(
            accounted,
            u64::from(PIECES) + 1,
            "flow control counts up to the last offset"
        );
    });
}
