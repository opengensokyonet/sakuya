//! What the tests of stream receivers share, whatever the type of their reset
//! facts: frames, data and the decisions of scripted termination policies.
use super::termination::{BoundaryAction, BoundaryUpdate, TerminationDecision};
use super::{ResetStreamFrame, StreamFrame};
use crate::connection::{CloseReason, ImmediateClose, TransportImmediateClose};
use crate::send::test_support::TestCloseCause;
use bytes::Bytes;
use sakuya_wire::v1::application_error::ApplicationErrorCode;
use sakuya_wire::v1::transport_error::TransportErrorCode;
use sakuya_wire::var_int::VarInt;

/// The reason the tests close connections for.
pub(crate) fn close_reason() -> CloseReason<TestCloseCause> {
    CloseReason::Peer(ImmediateClose::Transport(TransportImmediateClose {
        code: TransportErrorCode::PROTOCOL_VIOLATION,
        frame_type: Some(VarInt::from(0x08u8)),
        reason_phrase: Bytes::from_static(b"bad stream"),
    }))
}

pub(crate) fn v(value: u32) -> VarInt {
    VarInt::from_u32(value)
}

pub(crate) fn c(value: u32) -> ApplicationErrorCode {
    ApplicationErrorCode::new(v(value))
}

/// `len` bytes whose values are their stream offsets modulo 251.
pub(crate) fn data(offset: u32, len: u32) -> Bytes {
    (offset..offset + len)
        .map(|at| u8::try_from(at % 251).unwrap())
        .collect()
}

pub(crate) fn stream(offset: u32, len: u32, fin: bool) -> StreamFrame {
    StreamFrame {
        offset: v(offset),
        data: data(offset, len),
        fin,
    }
}

pub(crate) fn reset(code: u32, final_size: u32) -> ResetStreamFrame {
    ResetStreamFrame {
        code: c(code),
        final_size: v(final_size),
    }
}

pub(crate) fn restrict(
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

pub(crate) fn fix_both(limit: u32, reason: &'static str) -> TerminationDecision<&'static str> {
    restrict(
        BoundaryUpdate::Fix(v(limit)),
        BoundaryUpdate::Fix(v(limit)),
        reason,
    )
}

pub(crate) fn destroy(reason: &'static str) -> TerminationDecision<&'static str> {
    TerminationDecision::new(BoundaryAction::Destroy { reason })
}
