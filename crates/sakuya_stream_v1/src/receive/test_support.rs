//! What the tests of stream receivers share, whatever the type of their reset
//! facts: frames, data and the decisions of scripted termination policies.
use super::termination::{BoundaryAction, BoundaryUpdate, TerminationDecision};
use crate::connection::{CloseReason, ImmediateClose, TransportImmediateClose};
use crate::send::test_support::TestCloseCause;
use bytes::Bytes;
use sakuya_var_int::{VarInt, VarIntField};
use sakuya_wire_v1::application_error::ApplicationErrorCode;
use sakuya_wire_v1::frame::UndecidedLength;
use sakuya_wire_v1::frame::{reset_stream::ResetStreamFrame, stream::StreamFrame};
use sakuya_wire_v1::stream_id::StreamId;
use sakuya_wire_v1::transport_error::TransportErrorCode;

/// The reason the tests close connections for.
pub fn close_reason() -> CloseReason<TestCloseCause> {
    CloseReason::Peer(ImmediateClose::Transport(TransportImmediateClose {
        code: TransportErrorCode::PROTOCOL_VIOLATION,
        frame_type: Some(VarInt::from(0x08u8)),
        reason_phrase: Bytes::from_static(b"bad stream"),
    }))
}

pub fn v(value: u32) -> VarInt {
    VarInt::from_u32(value)
}

pub fn c(value: u32) -> ApplicationErrorCode {
    ApplicationErrorCode::new(v(value))
}

/// `len` bytes whose values are their stream offsets modulo 251.
pub fn data(offset: u32, len: u32) -> Bytes {
    (offset..offset + len)
        .map(|at| u8::try_from(at % 251).unwrap())
        .collect()
}

/// The Stream ID the frames state; a receiver does not look at it.
pub fn stream_id() -> VarIntField<StreamId> {
    VarIntField::shortest(StreamId::from_var_int(v(0)))
}

/// A STREAM frame with `data` at `offset`.
pub fn stream_frame(offset: VarInt, data: Bytes, fin: bool) -> StreamFrame<Bytes, UndecidedLength> {
    StreamFrame::new(stream_id(), Some(VarIntField::shortest(offset)), data, fin)
        .expect("test data ends within 2^62 - 1")
}

/// A STREAM frame with `len` bytes of [`data`] at `offset`.
pub fn stream(offset: u32, len: u32, fin: bool) -> StreamFrame<Bytes, UndecidedLength> {
    stream_frame(v(offset), data(offset, len), fin)
}

pub fn reset(code: u32, final_size: u32) -> ResetStreamFrame {
    ResetStreamFrame::new(
        stream_id(),
        VarIntField::shortest(c(code)),
        VarIntField::shortest(v(final_size)),
    )
}

pub fn restrict(
    acceptance: BoundaryUpdate,
    delivery: BoundaryUpdate,
    reason: &'static str,
) -> TerminationDecision<&'static str> {
    TerminationDecision::new(BoundaryAction::Restrict {
        acceptance,
        delivery,
        reason,
    })
}

pub fn fix_both(limit: u32, reason: &'static str) -> TerminationDecision<&'static str> {
    restrict(
        BoundaryUpdate::Fix(v(limit)),
        BoundaryUpdate::Fix(v(limit)),
        reason,
    )
}

pub fn destroy(reason: &'static str) -> TerminationDecision<&'static str> {
    TerminationDecision::new(BoundaryAction::Destroy { reason })
}
