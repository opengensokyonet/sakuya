use super::{
    LocalResetAt, LocalResetAtFrame, PeerResetStreamAtSupport, ReliableSizeIncreaseError,
    ResetTarget,
};
use bytes::BytesMut;
use sakuya_stream_v1::send::SendTerminalState;
use sakuya_stream_v1::send::local_reset::{LocalReset, LocalResetTarget};
use sakuya_stream_v1::send::test_support::{CODE, v};
use sakuya_wire_reset_stream_at::{ReliableSizeError, ResetStreamAt, ResetStreamAtFrame};
use sakuya_wire_v1::application_error::ApplicationErrorCode;
use sakuya_wire_v1::frame::reset_stream::ResetStreamFrame;
use sakuya_wire_v1::frame::write::DelimitedFrame;
use sakuya_wire_v1::stream_id::StreamId;
use sakuya_wire_v1::var_int::{VarInt, VarIntField};

/// The peer of these tests advertised `reset_stream_at`.
const SUPPORT: PeerResetStreamAtSupport =
    PeerResetStreamAtSupport::from_peer_parameter(ResetStreamAt);

fn reset_target(
    error_code: ApplicationErrorCode,
    reliable_size: u32,
    final_size: u32,
) -> ResetTarget {
    ResetTarget::new(SUPPORT, error_code, v(reliable_size), v(final_size)).unwrap()
}

/// A reset target keeps its reliable size within its final size, and lowers
/// it but never raises it.
#[test]
fn a_reset_target_keeps_its_reliable_size_within_its_final_size() {
    assert_eq!(
        ResetTarget::new(SUPPORT, CODE, v(60), v(50)),
        Err(ReliableSizeError::check(v(50), v(60)).unwrap_err())
    );
    let target = reset_target(CODE, 50, 50);
    assert_eq!(
        (
            target.error_code(),
            target.reliable_size(),
            target.final_size()
        ),
        (CODE, v(50), v(50))
    );
    assert_eq!(target.lowered_to(v(20)), Ok(reset_target(CODE, 20, 50)));
    assert_eq!(
        target.lowered_to(v(51)),
        Err(ReliableSizeIncreaseError::check(v(50), v(51)).unwrap_err())
    );
    assert_eq!(target.without_reliable_prefix(), reset_target(CODE, 0, 50));

    let reset_at = LocalResetAt::ResetAt(target);
    assert_eq!(reset_at.reliable_size(), v(50));
    assert_eq!(reset_at.acknowledged_state(), SendTerminalState::DataRecvd);
    let reset = LocalResetAt::Reset(LocalReset {
        error_code: CODE,
        final_size: v(50),
    });
    assert_eq!(reset.reliable_size(), VarInt::ZERO);
    assert_eq!(reset.acknowledged_state(), SendTerminalState::ResetRecvd);
}

/// The reset frame of a [`LocalResetAt`] writes as its frame, in the length
/// it states.
#[test]
fn a_reset_frame_of_either_kind_writes_its_encoded_length() {
    let at = ResetStreamAtFrame::new(
        VarIntField::shortest(StreamId::from(VarInt::from_u32(4))),
        VarIntField::shortest(ApplicationErrorCode::new(VarInt::from_u32(1))),
        VarIntField::shortest(VarInt::from_u32(9)),
        VarIntField::shortest(VarInt::from_u32(5)),
    )
    .expect("the reliable size is within the final size");
    let frame = LocalResetAtFrame::ResetStreamAt(at);
    let mut buffer = BytesMut::new();
    let len = DelimitedFrame::encoded_len(&frame);
    DelimitedFrame::write_to(frame, &mut buffer);
    assert_eq!(&buffer[..], [0x24, 0x04, 0x01, 0x09, 0x05]);
    assert_eq!(len, buffer.len());

    let plain = LocalResetAtFrame::ResetStream(ResetStreamFrame::new(
        VarIntField::shortest(StreamId::from(VarInt::from_u32(4))),
        VarIntField::shortest(ApplicationErrorCode::new(VarInt::from_u32(1))),
        VarIntField::shortest(VarInt::from_u32(9)),
    ));
    let mut buffer = BytesMut::new();
    let len = DelimitedFrame::encoded_len(&plain);
    DelimitedFrame::write_to(plain, &mut buffer);
    assert_eq!(&buffer[..], [0x04, 0x04, 0x01, 0x09]);
    assert_eq!(len, buffer.len());
}
