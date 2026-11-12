//! Writing to a stream sender and flushing it.
//!
//! [`StreamSender::write`] is the synchronous core of a write attempt. It
//! takes the prefix of the caller's [`Buf`] that it can accept and leaves the
//! rest with the caller. In order, an attempt
//!
//! 1. checks the connection, the end state, empty input, the write limit and
//!    the room left below the largest stream offset, and caps the attempt by
//!    them and by the peer's stream limit;
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
//! No asynchronous interface is provided here; [`WriteOutcome::Wait`] tells
//! the caller to retry once the cause may have changed.
use super::local_reset::LocalResetTarget;
use super::{SendEndState, StreamResetError, StreamSender, WriteLimit};
use crate::connection::ConnectionClosedError;
use crate::connection_send_credit::{ConnectionCreditReservation, ConnectionSendFlowController};
use crate::send::flow_control::{
    AdmissionGuard, GrantAboveCeilingError, SendFlowControlPolicy, WriteAttempt,
};
use crate::send::termination::{SendTerminationEvent, SendTerminationPolicy};
use crate::send_buffer::StreamSendBuffer;
use crate::send_buffer::covered_bytes::CoveredBytes;
use bytes::Buf;
use core::fmt;
use core::ops::Deref;
use sakuya_wire::var_int::VarInt;
use snafu::{Report, ResultExt, Snafu, ensure};
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
/// `R` is the termination policy's write limit reason; `Lc` is the type of
/// the connection's local close cause.
#[derive(Debug, Snafu)]
#[snafu(module(write_error), visibility(pub(crate)))]
pub enum WriteError<R, Lc> {
    /// The connection has closed.
    #[snafu(transparent)]
    ConnectionClosed {
        /// The closed connection.
        source: ConnectionClosedError<Lc>,
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
///
/// `Lc` is the type of the connection's local close cause.
#[derive(Clone, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(flush_error), visibility(pub(crate)))]
pub enum FlushError<Lc> {
    /// The connection has closed.
    #[snafu(transparent)]
    ConnectionClosed {
        /// The closed connection.
        source: ConnectionClosedError<Lc>,
    },
    /// The stream was reset.
    #[snafu(transparent)]
    Reset {
        /// The reset in effect.
        source: StreamResetError,
    },
}

impl<C, K, Lc, T> StreamSender<C, K, Lc, T>
where
    T: LocalResetTarget,
    K: ConnectionSendFlowController,
    C: StreamSendBuffer<Reservation = K::Reservation>
        + SendFlowControlPolicy<T>
        + SendTerminationPolicy<T>,
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
    /// [`WriteError::WriteLimitReached`] and
    /// [`WriteError::StreamSizeExhausted`].
    ///
    /// # Panics
    ///
    /// If the flow-control policy returns a guard that it did not build from
    /// this attempt, which violates the
    /// [policy contract](SendFlowControlPolicy#contract).
    pub fn write<S: Buf + ?Sized>(
        &mut self,
        source: &mut S,
    ) -> Result<WriteOutcome, WriteError<C::WriteLimitReason, Lc>> {
        self.check_connection_open()?;
        match self.end_state() {
            SendEndState::Reset { .. } => return Err(StreamResetError.into()),
            SendEndState::Closed { .. } => return write_error::ClosedSnafu.fail(),
            SendEndState::Open => {}
        }
        if !source.has_remaining() {
            return Ok(WriteOutcome::Written(WriteReport {
                new_bytes: VarInt::ZERO,
            }));
        }

        let offset = self.written_end();
        let write_limit_remaining = match self.write_limit() {
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
        let size_remaining = VarInt::MAX.saturating_sub(offset);
        ensure!(
            size_remaining > VarInt::ZERO,
            write_error::StreamSizeExhaustedSnafu
        );
        let requested = VarInt::try_from(source.remaining()).unwrap_or(VarInt::MAX);
        let stream_available = self.peer_stream_limit.saturating_sub(offset);
        let ceiling = write_limit_remaining
            .map_or(requested, |remaining| remaining.min(requested))
            .min(stream_available)
            .min(size_remaining);
        let attempt = WriteAttempt {
            offset,
            requested,
            stream_available,
            write_limit_remaining,
            connection_available: self.connection.available(),
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
        if let Err(violation) = check_grant(&guard, &attempt) {
            panic!("{}", Report::from_error(violation));
        }

        let Some(reservation) = self
            .connection
            .reserve_up_to(self.stream_id, guard.granted())
        else {
            self.composition.on_admission_abandoned(guard, &context);
            return Ok(WriteOutcome::Wait(WriteWait::ConnectionCredit));
        };
        let used = reservation.amount();
        // invariant: `used <= granted <= ceiling <= requested`, and `requested`
        // is the input length unless that exceeds `VarInt::MAX`, so `used`
        // bytes of input exist and their count is a `usize`.
        let length = usize::try_from(used.get())
            .map_or(source.remaining(), |length| length.min(source.remaining()));
        let bytes = source.copy_to_bytes(length);
        let data = match CoveredBytes::new(bytes, reservation) {
            Ok(data) => data,
            // invariant: `length` equals the reservation's amount `used`, a
            // `VarInt`, by the bound above.
            Err(error) => unreachable!("consumed input does not match its reservation: {error}"),
        };
        match self.composition.append(data) {
            Ok(()) => {}
            // invariant: input is open, so no reset was applied and no final
            // size was exposed; the ceiling keeps the written end within
            // `VarInt::MAX`. A send buffer that still refuses the data breaks
            // the `StreamSendBuffer` contract.
            Err(error) => unreachable!("an open send buffer refused admitted data: {error}"),
        }
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
    pub fn flush(&self) -> Result<(), FlushError<Lc>> {
        self.check_connection_open()?;
        if let SendEndState::Reset { .. } = self.end_state() {
            return Err(StreamResetError.into());
        }
        Ok(())
    }
}

/// A guard that the flow-control policy did not build from the attempt it
/// was asked about.
#[derive(Debug, Snafu)]
#[snafu(module(grant_violation))]
enum GrantViolationError {
    /// The guard names another offset.
    #[snafu(display(
        "flow-control policy granted admission for offset {granted_offset}, not {offset}"
    ))]
    Offset {
        offset: VarInt,
        granted_offset: VarInt,
    },
    /// The guard exceeds the attempt's ceiling.
    #[snafu(display("flow-control policy granted admission above the ceiling"))]
    Ceiling { source: GrantAboveCeilingError },
}

/// Checks the [policy contract](SendFlowControlPolicy#contract) for a guard
/// returned for `attempt`.
fn check_grant(guard: &AdmissionGuard, attempt: &WriteAttempt) -> Result<(), GrantViolationError> {
    ensure!(
        guard.offset() == attempt.offset,
        grant_violation::OffsetSnafu {
            offset: attempt.offset,
            granted_offset: guard.offset(),
        }
    );
    // A guard never grants zero bytes: `AdmissionGuard::new` rejects that.
    GrantAboveCeilingError::check(guard.granted(), attempt.ceiling)
        .context(grant_violation::CeilingSnafu)?;
    Ok(())
}
