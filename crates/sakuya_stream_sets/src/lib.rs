//! The stream sender and the stream receiver of sakuya, and the stream resets
//! of RFC 9000.
//!
//! [`send::StreamSender`] and [`receive::StreamReceiver`] keep one stream's
//! send and receive direction at the connection layer. They are built on the
//! contracts and the simple components of `sakuya_stream_v1`: the send buffer,
//! the flow-control and termination policies, and the reset targets
//! and facts. This package adds the operations on the two, the policy
//! [`send::termination::ResetOnAbandonTermination`], and the
//! [`resets`] that choose which resets a connection takes.
//!
//! The feature `reset_stream_at` adds the reliable stream reset extension
//! of `sakuya_stream_reset_stream_at` to the sender and the receiver
//! (module `reset_stream_at`).
#![warn(missing_docs)]

pub mod receive;
#[cfg(feature = "reset_stream_at")]
pub mod reset_stream_at;
pub mod resets;
pub mod send;
