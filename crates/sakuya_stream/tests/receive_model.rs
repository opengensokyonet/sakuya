//! Model-based tests of the stream receiver, driven by generated operation
//! sequences on two streams that share one connection receive flow
//! controller.
//!
//! The model restates the contract of RFC 9000 §3.2, §3.5 and §4 and of the
//! stream receiver independently of the code: final size and flow control
//! checks, the read priorities, the local limits, the STOP request table and
//! the released progress. A scripted termination policy takes only legal
//! decisions, so that any panic is a defect of the receiver.
//!
//! The receiver under test is the one of RFC 9000 resets. With the
//! `reset_stream_at` feature it is the one that also takes `RESET_STREAM_AT`,
//! and the model follows draft-ietf-quic-reliable-stream-reset-11 for it;
//! the `dialect` module of each holds what differs between the two.
//!
//! The model runs once for each: as module `v1` always, and as `reset_at` when the
//! feature is on.

#[path = "receive_model/v1.rs"]
mod v1;

#[cfg(feature = "reset_stream_at")]
#[path = "receive_model/reset_at.rs"]
mod reset_at;
