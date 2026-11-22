//! The outcomes and failures of writing to a stream sender and flushing it.
//!
//! A write attempt, `StreamSender::write` of the package `sakuya_stream_sets`,
//! reports [`WriteOutcome::Written`] or [`WriteOutcome::Wait`], or fails with
//! a [`WriteError`]; `StreamSender::flush` fails with a [`FlushError`].
use super::StreamResetError;
use crate::connection::LayerEndedError;
use core::fmt;
use core::ops::Deref;
use sakuya_wire_v1::var_int::VarInt;
use snafu::Snafu;
use std::sync::Arc;

/// The outcome of a write attempt that did not fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteOutcome {
    /// A prefix of the input entered the send buffer; for empty input, the
    /// report counts zero bytes.
    Written(WriteReport),
    /// Nothing was consumed; the attempt has to be repeated once the cause
    /// may have changed.
    Wait(WriteWait),
}

/// What a successful write attempt accomplished.
///
/// The report only describes facts and carries no obligation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct WriteReport {
    /// The bytes handed to the send buffer: zero for empty input, otherwise
    /// at least one.
    pub new_bytes: VarInt,
}

impl WriteReport {
    /// A report of `new_bytes` handed to the send buffer.
    pub fn new(new_bytes: VarInt) -> Self {
        Self { new_bytes }
    }
}

/// Why a write attempt has to wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriteWait {
    /// The peer's stream limit leaves no room: wait for `MAX_STREAM_DATA`.
    StreamCredit,
    /// The flow-control policy admitted nothing although the hard
    /// constraints leave room.
    Admission,
    /// No connection credit is available: wait for `MAX_DATA` or for
    /// reservations of other streams to be released.
    ConnectionCredit,
}

/// Failures of `StreamSender::write`; none of them consumes input.
///
/// `R` is the termination policy's write limit reason; `Lc` is the type of
/// the connection's local close cause.
#[derive(Debug, Snafu)]
#[snafu(module(write_error), visibility(pub))]
pub enum WriteError<R, Lc> {
    /// The connection has closed.
    #[snafu(transparent)]
    LayerEnded {
        /// The closed connection.
        source: LayerEndedError<Lc>,
    },
    /// The stream was reset.
    #[snafu(transparent)]
    Reset {
        /// The reset in effect.
        source: StreamResetError,
    },
    /// The stream was closed.
    #[snafu(display("the stream was closed"))]
    Closed,
    /// The write limit end was reached; growth of the peer's limits does not
    /// lift it.
    #[snafu(display("the write limit end {write_limit_end} is reached"))]
    WriteLimitReached {
        /// The write limit end.
        write_limit_end: VarInt,
        /// The reason the termination policy gave.
        reason: SharedWriteLimitReason<R>,
    },
    /// The written end has reached [`VarInt::MAX`]; no stream can carry more
    /// data, and growth of the peer's limits does not change that.
    #[snafu(display("the stream has reached the largest stream offset"))]
    StreamSizeExhausted,
}

/// A shared handle to a write limit reason.
///
/// Every write beyond the limit receives a clone of the same handle, so the
/// reason itself needs neither `Clone` nor `Send` and `Sync`.
pub struct SharedWriteLimitReason<R>(Arc<R>);

impl<R> SharedWriteLimitReason<R> {
    /// The handle of `reason`, which its clones share.
    pub fn new(reason: R) -> Self {
        Self(Arc::new(reason))
    }
}

impl<R> Clone for SharedWriteLimitReason<R> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<R> Deref for SharedWriteLimitReason<R> {
    type Target = R;

    fn deref(&self) -> &R {
        &self.0
    }
}

impl<R: fmt::Debug> fmt::Debug for SharedWriteLimitReason<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&*self.0, f)
    }
}

/// Failures of `StreamSender::flush`.
///
/// `Lc` is the type of the connection's local close cause.
#[derive(Clone, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(flush_error), visibility(pub(crate)))]
pub enum FlushError<Lc> {
    /// The connection has closed.
    #[snafu(transparent)]
    LayerEnded {
        /// The closed connection.
        source: LayerEndedError<Lc>,
    },
    /// The stream was reset.
    #[snafu(transparent)]
    Reset {
        /// The reset in effect.
        source: StreamResetError,
    },
}
