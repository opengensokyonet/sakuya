use crate::receive::StreamReceiver;
use core::num::NonZeroUsize;
use sakuya_stream_receive_buffer_fragmented::FragmentedStreamReceiveBuffer;
use sakuya_stream_v1::connection_receive_flow::ConnectionReceiveFlowController;
use sakuya_stream_v1::receive::composition::ReceiveComposition;
use sakuya_stream_v1::receive::flow_control::SlidingWindowAdvertisement;
use sakuya_stream_v1::receive::read::ReadOutcome;
use sakuya_stream_v1::receive::termination::FollowingTermination;
use sakuya_stream_v1::receive::test_support::{c, data, stream, v};
use sakuya_stream_v1::send::test_support::TestCloseCause;

const KIB: u32 = 1024;

fn nz(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).unwrap()
}

/// The default composition end to end: the window slides with reads, a
/// dropped reader requests STOP with the abandon code.
#[test]
fn default_composition_advertises_after_half_a_window_and_stops_on_drop() {
    let window = v(64 * KIB);
    let mut receiver: StreamReceiver<
        ReceiveComposition<
            FragmentedStreamReceiveBuffer,
            SlidingWindowAdvertisement,
            FollowingTermination,
        >,
        TestCloseCause,
    > = StreamReceiver::new(
        ReceiveComposition::new(
            FragmentedStreamReceiveBuffer::new(),
            SlidingWindowAdvertisement::new(window),
            FollowingTermination::new(c(7)),
        ),
        window,
    );
    let mut connection = ConnectionReceiveFlowController::new(v(1 << 20));
    receiver
        .on_stream_frame(stream(0, 64 * KIB, false), &mut connection)
        .unwrap();
    assert_eq!(receiver.advertisement(), None);

    assert_eq!(
        receiver.read_chunk(nz(20 * 1024)),
        Ok(ReadOutcome::Data(data(0, 20 * KIB)))
    );
    assert_eq!(receiver.advertisement(), None);
    assert_eq!(
        receiver.read_chunk(nz(12 * 1024)),
        Ok(ReadOutcome::Data(data(20 * KIB, 12 * KIB)))
    );
    assert_eq!(receiver.advertisement(), Some(v(96 * KIB)));

    receiver.open_limit(v(96 * KIB));
    assert_eq!(receiver.opened_limit(), v(96 * KIB));
    assert_eq!(receiver.advertisement(), None);

    receiver.reader_dropped();
    assert_eq!(receiver.pending_stop(), Some(c(7)));
}
