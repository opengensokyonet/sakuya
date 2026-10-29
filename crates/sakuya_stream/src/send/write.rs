//! Writing to a stream sender and flushing it.
//!
//! [`StreamSender::write`] is the synchronous core of a write attempt. It
//! takes the prefix of the caller's [`Buf`] that it can accept and leaves the
//! rest with the caller. In order, an attempt
//!
//! 1. checks the connection, the end state, empty input and the write limit;
//! 2. asks the flow-control policy for an admission guard at the current
//!    written end;
//! 3. reserves at most the granted amount of connection credit;
//! 4. without any credit, abandons the guard, consumes nothing and reports
//!    that it has to wait;
//! 5. otherwise consumes exactly the reserved amount from the input, appends
//!    it with its reservation to the send buffer and settles the guard with
//!    that amount;
//! 6. reports the appended amount.
//!
//! Once input is consumed, nothing turns the attempt into an error. A
//! successful write hands the data and its reliable delivery to the
//! transport; it does not mean the data was sent or acknowledged.
//!
//! Status: the attempt's steps, the report and the errors are confirmed
//! (`send-side.md`, "一次写入的流程（已确认）", "写入报告与错误（已确认）"). The
//! asynchronous interface (`AsyncBufWrite`) is tentative and not provided
//! here; [`WriteOutcome::Wait`] is where it will register for wake-ups.
use super::{SendEndState, StreamSender, WriteLimit};
use crate::connection_send_credit::ConnectionSendFlowController;
use crate::send::flow_control::{SendFlowControlPolicy, WriteAttempt};
use crate::send::termination::{SendTerminationEvent, SendTerminationPolicy};
use crate::send_buffer::SendBuffer;
use bytes::Buf;
use core::fmt;
use core::ops::Deref;
use sakuya_wire::var_int::VarInt;
use snafu::{Snafu, ensure};
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

/// Failures of [`StreamSender::write`]; none of them consumes input.
///
/// `R` is the termination policy's write limit reason.
#[derive(Debug, Snafu)]
#[snafu(module(write_error), visibility(pub(crate)))]
pub enum WriteError<R> {
    /// The connection has closed.
    #[snafu(display("the connection is closed"))]
    ConnectionClosed,
    /// The stream was reset.
    #[snafu(display("the stream was reset"))]
    Reset,
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
}

/// A shared handle to a write limit reason.
///
/// Every write beyond the limit receives a clone of the same handle, so the
/// reason itself needs neither `Clone` nor `Send` and `Sync`.
pub struct SharedWriteLimitReason<R>(Arc<R>);

impl<R> SharedWriteLimitReason<R> {
    pub(crate) fn new(reason: R) -> Self {
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

/// Failures of [`StreamSender::flush`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(flush_error), visibility(pub(crate)))]
pub enum FlushError {
    /// The connection has closed.
    #[snafu(display("the connection is closed"))]
    ConnectionClosed,
    /// The stream was reset.
    #[snafu(display("the stream was reset"))]
    Reset,
}

impl<C> StreamSender<C>
where
    C: SendBuffer + SendFlowControlPolicy + SendTerminationPolicy,
{
    /// Makes one write attempt with `source`: hands the prefix that admission
    /// and connection credit allow to the send buffer and advances `source`
    /// past it.
    ///
    /// Empty input succeeds with zero bytes while the stream accepts writes;
    /// it asks for no admission and produces no event. An attempt that would
    /// cross the write limit end takes the part below it and succeeds; the
    /// next attempt fails.
    ///
    /// # Errors
    ///
    /// Checked in this order: [`WriteError::ConnectionClosed`],
    /// [`WriteError::Reset`], [`WriteError::Closed`], and for non-empty input
    /// [`WriteError::WriteLimitReached`].
    ///
    /// # Panics
    ///
    /// If the flow-control policy grants beyond the attempt's ceiling or for
    /// another offset.
    pub fn write<S: Buf + ?Sized>(
        &mut self,
        source: &mut S,
        connection: &mut ConnectionSendFlowController,
    ) -> Result<WriteOutcome, WriteError<C::WriteLimitReason>> {
        ensure!(!self.connection_closed, write_error::ConnectionClosedSnafu);
        match self.end_state {
            SendEndState::Reset { .. } => return write_error::ResetSnafu.fail(),
            SendEndState::Closed { .. } => return write_error::ClosedSnafu.fail(),
            SendEndState::Open => {}
        }
        if !source.has_remaining() {
            return Ok(WriteOutcome::Written(WriteReport {
                new_bytes: VarInt::ZERO,
            }));
        }

        let offset = self.written_end();
        let write_limit_remaining = match &self.write_limit {
            Some(WriteLimit { end, reason }) => {
                let remaining = end.saturating_sub(offset);
                ensure!(
                    remaining > VarInt::ZERO,
                    write_error::WriteLimitReachedSnafu {
                        write_limit_end: *end,
                        reason: reason.clone(),
                    }
                );
                Some(remaining)
            }
            None => None,
        };
        let requested = VarInt::try_from(source.remaining()).unwrap_or(VarInt::MAX);
        let stream_available = self.peer_stream_limit.saturating_sub(offset);
        let ceiling = write_limit_remaining
            .map_or(requested, |remaining| remaining.min(requested))
            .min(stream_available);
        let attempt = WriteAttempt {
            offset,
            requested,
            stream_available,
            write_limit_remaining,
            connection_available: connection.available(),
            ceiling,
        };

        let context = self.flow_context();
        let Some(guard) = self.composition.admit_write(&attempt, &context) else {
            return Ok(WriteOutcome::Wait(if ceiling == VarInt::ZERO {
                WriteWait::StreamCredit
            } else {
                WriteWait::Admission
            }));
        };
        assert_eq!(
            guard.offset(),
            offset,
            "flow-control policy granted admission for another offset"
        );
        assert!(
            guard.granted() > VarInt::ZERO && guard.granted() <= ceiling,
            "flow-control policy granted {} bytes outside 1..={ceiling}",
            guard.granted()
        );

        let Some(reservation) = connection.reserve_up_to(self.stream_id, guard.granted()) else {
            self.composition.on_admission_abandoned(guard, &context);
            return Ok(WriteOutcome::Wait(WriteWait::ConnectionCredit));
        };
        let used = reservation.amount();
        let length =
            usize::try_from(used.get()).expect("the reserved amount fits the input length");
        let bytes = source.copy_to_bytes(length);
        self.composition.append(bytes, reservation);
        let end = self.written_end();
        let context = self.flow_context();
        self.composition.on_admission_used(guard, used, &context);
        self.dispatch_termination(SendTerminationEvent::DataAppended {
            appended_range: offset..end,
        });
        Ok(WriteOutcome::Written(WriteReport { new_bytes: used }))
    }

    /// Flushes the stream sender.
    ///
    /// Data is handed over by each successful write, so nothing is pending:
    /// flushing does not wait for credit, packetisation, sending or
    /// acknowledgement. It succeeds after a close.
    ///
    /// # Errors
    ///
    /// [`FlushError::ConnectionClosed`], then [`FlushError::Reset`] once a
    /// reset is in effect, even if nothing remains to deliver.
    pub fn flush(&self) -> Result<(), FlushError> {
        ensure!(!self.connection_closed, flush_error::ConnectionClosedSnafu);
        ensure!(
            !matches!(self.end_state, SendEndState::Reset { .. }),
            flush_error::ResetSnafu
        );
        Ok(())
    }
}
