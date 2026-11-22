//! The reliable stream reset extension (`RESET_STREAM_AT`) for the stream
//! sender and the stream receiver.
//!
//! The package `sakuya_stream_reset_stream_at` defines the extension's reset
//! target, facts, requests and frames; this module adds them to
//! [`StreamSender`](crate::send::StreamSender) and
//! [`StreamReceiver`](crate::receive::StreamReceiver). [`send`] has the
//! resets of a sender whose reset target is
//! [`LocalResetAt`](sakuya_stream_reset_stream_at::send::LocalResetAt) and the
//! termination policy that answers for such a sender, [`receive`] has the
//! frames of a receiver whose reset facts are
//! [`RemoteResetAt`](sakuya_stream_reset_stream_at::receive::RemoteResetAt).

pub mod receive;
pub mod send;
