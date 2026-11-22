//! Model-based tests of the stream receiver that also takes
//! `RESET_STREAM_AT`, driven by generated operation sequences on two
//! streams that share one connection receive flow controller.
//!
//! The model is the one of the stream receiver's tests in `sakuya_stream_sets`,
//! which follows draft-ietf-quic-reliable-stream-reset-11 for this
//! receiver; the `dialect` module holds what differs from the receiver of
//! RFC 9000 resets.

#[path = "receive_model/reset_at.rs"]
mod reset_at;
