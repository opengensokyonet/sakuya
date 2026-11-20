//! Model-based tests of the stream sender that also ends a stream with
//! `RESET_STREAM_AT`, driven by generated operation sequences on two
//! streams that share one connection send flow controller.
//!
//! The model is the one of the stream sender's tests in `sakuya_stream`,
//! which follows draft-ietf-quic-reliable-stream-reset-11 for this sender;
//! the `dialect` module holds what differs from the sender of RFC 9000
//! resets.

#[path = "send_model/reset_at.rs"]
mod reset_at;
