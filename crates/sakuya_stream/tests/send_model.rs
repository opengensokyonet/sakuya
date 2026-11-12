//! Model-based tests of the stream sender, driven by generated operation
//! sequences on two streams that share one connection send flow controller.
//!
//! The model restates the contract independently of the code: the
//! outcome of every operation, the ledgers (`L`, `R`, `C`, per-stream `W`, `E`
//! and coverage), and the end state. After every operation the implementation
//! must agree with it, and the monotonic and conservation invariants of
//! RFC 9000 §3–§4 must hold.
//!
//! The sender under test is the one of RFC 9000 resets. With the
//! `reset_stream_at` feature it is the one that also ends a stream with
//! `RESET_STREAM_AT`, and the model follows
//! draft-ietf-quic-reliable-stream-reset-11 for it; the `dialect` module of each holds what
//! differs between the two.
//!
//! The model runs once for each: as module `v1` always, and as `reset_at` when the
//! feature is on.

#[path = "send_model/v1.rs"]
mod v1;

#[cfg(feature = "reset_stream_at")]
#[path = "send_model/reset_at.rs"]
mod reset_at;
