use super::DataBlockedSignal;
use crate::connection_send_credit::{
    AtomicConnectionSendFlowController, ConnectionSendFlowController,
};
use sakuya_wire::v1::stream_id::{Directionality, Initiator, StreamId};
use sakuya_wire::var_int::VarInt;

fn v(value: u32) -> VarInt {
    VarInt::from_u32(value)
}

/// With the controller: blocked at 100 wants one frame at 100; once sent,
/// blocking again at 100 wants nothing; `MAX_DATA` to 200 clears it, and
/// blocking at 200 wants a frame at 200.
#[test]
fn once_for_each_connection_limit() {
    let stream = StreamId::new(Initiator::Client, Directionality::Bidirectional, 0).unwrap();
    let controller = AtomicConnectionSendFlowController::new(v(100));
    let mut signal = DataBlockedSignal::new();
    assert_eq!(signal.wanted(), None);

    let reservation = controller.reserve_up_to(stream, v(100)).unwrap();
    assert!(controller.reserve_up_to(stream, v(1)).is_none());
    signal.on_write_blocked(controller.limit());
    assert_eq!(signal.wanted(), Some(v(100)));
    signal.on_sent(v(100));
    assert_eq!(signal.wanted(), None);
    signal.on_write_blocked(controller.limit());
    assert_eq!(signal.wanted(), None);

    controller.on_max_data(v(200));
    signal.on_limit_raised(controller.limit());
    assert_eq!(signal.wanted(), None);
    let more = controller.reserve_up_to(stream, v(100)).unwrap();
    assert!(controller.reserve_up_to(stream, v(1)).is_none());
    signal.on_write_blocked(controller.limit());
    assert_eq!(signal.wanted(), Some(v(200)));
    drop((reservation, more));
}

/// A higher limit clears an intent that was not sent yet.
#[test]
fn a_higher_limit_clears_an_unsent_intent() {
    let mut signal = DataBlockedSignal::new();
    signal.on_write_blocked(v(100));
    signal.on_limit_raised(v(150));
    assert_eq!(signal.wanted(), None);
    // A frame for the old limit sent late changes nothing.
    signal.on_sent(v(100));
    signal.on_write_blocked(v(150));
    assert_eq!(signal.wanted(), Some(v(150)));
}

/// A lost frame at 100 is wanted again while 100 is the limit, and not
/// once `MAX_DATA` raised it.
#[test]
fn a_lost_frame_is_wanted_again_while_its_limit_holds() {
    let mut signal = DataBlockedSignal::new();
    signal.on_write_blocked(v(100));
    signal.on_sent(v(100));
    signal.on_lost(v(100));
    assert_eq!(signal.wanted(), Some(v(100)));
    signal.on_sent(v(100));
    signal.on_limit_raised(v(200));
    signal.on_lost(v(100));
    assert_eq!(signal.wanted(), None);
}
