use super::ReceiveComposition;
use crate::connection_receive_flow::ConnectionReceiveFlowController;
use crate::receive::StreamReceiver;
use crate::receive::flow_control::SlidingWindowAdvertisement;
use crate::receive::read::ReadOutcome;
use crate::receive::termination::FollowingTermination;
use crate::receive::test_support::{c, data, stream, v};
use crate::receive_buffer::fragmented::FragmentedStreamReceiveBuffer;
use crate::send::test_support::TestCloseCause;
use core::num::NonZeroUsize;

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
        ReceiveComposition::with_window_and_abandon_code(window, c(7)),
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
