//! The synchronous core of the stream reader: read results and their
//! priorities.
//!
//! Both ways of reading — copying into a [`BufMut`] with
//! [`StreamReceiver::read_into`] and taking whole blocks with
//! [`StreamReceiver::read_chunk`] — share one read position and one terminal
//! result. A read returns, in this order of priority:
//!
//! 1. [`ReadError::ReaderDropped`] once the reader was dropped;
//! 2. the connection failure, if the connection closed or input of the
//!    stream violated the protocol;
//! 3. the committed terminal result (end of stream or a terminal error), or
//!    the result of a buffer destruction that already took effect;
//! 4. no progress, for an empty target ([`read_into`] only);
//! 5. the contiguous data that can be delivered now, without waiting to fill
//!    the target;
//! 6. end of stream or a terminal error, judged from the final size, the
//!    local limits and the reset facts;
//! 7. otherwise, [`ReadOutcome::Wait`].
//!
//! A call that delivers data never also reports the end; the next call does.
//! The call that delivers a terminal error destroys the receive buffer, and
//! repeated reads return the same result, unless a connection failure appears
//! later. An empty target never commits a result, so a read that cannot take
//! a byte does not end a stream that late data could still complete.
//!
//! [`read_into`]: StreamReceiver::read_into
use super::{
    Applied, Boundary, BufferPhase, Committed, ConnectionFailureError, Destruction, Reading,
    StreamReceiver, flow_control::ReceiveFlowControlPolicy, flow_control::ReceiveFlowEvent,
    termination::ReceiveTerminationPolicy, termination::ResetPresentation,
    termination::TerminationEvent,
};
use crate::receive_buffer::ReceiveBuffer;
use bytes::BufMut;
use core::num::NonZeroUsize;
use sakuya_wire::application_error::ApplicationErrorCode;
use sakuya_wire::var_int::VarInt;
use snafu::Snafu;

/// The successful outcome of one read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadOutcome<T> {
    /// Non-empty data was delivered.
    Data(T),
    /// The target had no room; nothing was consumed and nothing committed.
    NoProgress,
    /// All data of the stream was delivered: the normal end of stream.
    End,
    /// Nothing can be delivered yet; data that is still expected may arrive.
    Wait,
}

/// The reset facts of a stream: what the peer's `RESET_STREAM` or
/// `RESET_STREAM_AT` frames stated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RemoteReset {
    /// The application protocol error code.
    pub code: ApplicationErrorCode,
    /// The final size of the stream.
    pub final_size: VarInt,
    /// The effective reliable size: the smallest one received, zero for
    /// `RESET_STREAM`.
    pub reliable_size: VarInt,
}

/// A terminal read error.
///
/// `R` is the receive termination policy's reason type. Every variant can be
/// reported repeatedly: the reason is a shared handle cloned for each report.
#[derive(Clone, Debug, PartialEq, Eq, Snafu)]
pub enum ReadError<R> {
    /// The stream reader was dropped; the receive direction takes no more
    /// reads.
    #[snafu(display("the stream reader was dropped"))]
    ReaderDropped,
    /// The connection closed, or input of the stream violated the protocol.
    #[snafu(display("connection failed"))]
    Connection {
        /// The failure.
        source: ConnectionFailureError,
    },
    /// The peer reset the stream.
    ///
    /// `complete` is true when every byte of `[0, final_size)` was delivered
    /// to the application: the receive termination policy chose to report the
    /// reset although nothing is missing. Complete means the stream's bytes,
    /// not that the application's object or business succeeded.
    #[snafu(display("stream reset by the peer with error code {}", reset.code))]
    Reset {
        /// The reset facts.
        reset: RemoteReset,
        /// Whether all of `[0, final_size)` was delivered.
        complete: bool,
    },
    /// Delivery ended locally: a local limit was reached, or the receive
    /// buffer was destroyed, before the whole stream was delivered.
    #[snafu(display("delivery of the stream ended locally"))]
    LocalTermination {
        /// The receive termination policy's reason.
        reason: R,
        /// The event during which the limit or destruction took effect.
        trigger: TerminationEvent,
        /// The reset facts, if the peer reset the stream too.
        remote: Option<RemoteReset>,
    },
}

impl<R> ReadError<R> {
    fn local(applied: Applied<R>, remote: Option<RemoteReset>) -> Self {
        Self::LocalTermination {
            reason: applied.reason,
            trigger: applied.trigger,
            remote,
        }
    }
}

impl<C> StreamReceiver<C>
where
    C: ReceiveBuffer + ReceiveFlowControlPolicy + ReceiveTerminationPolicy,
{
    /// Reads the next block of contiguous data.
    ///
    /// # Errors
    ///
    /// Returns the terminal error of the stream, or
    /// [`ReadError::ReaderDropped`] after
    /// [`reader_dropped`](Self::reader_dropped); see the [module
    /// documentation](self) for priorities.
    pub fn read_chunk(&mut self) -> Result<ReadOutcome<C::Chunk>, ReadError<C::Reason>> {
        if let Some(settled) = self.settled_read() {
            return settled.map(|()| ReadOutcome::End);
        }
        match self.parts.read_chunk(self.delivery.limit()) {
            Some(chunk) => {
                self.notify_flow(ReceiveFlowEvent::Delivered);
                Ok(ReadOutcome::Data(chunk))
            }
            None => self.end_or_wait(),
        }
    }

    /// Copies contiguous data into `target`, as much as fits and is
    /// available, and returns the number of bytes copied.
    ///
    /// # Errors
    ///
    /// As [`read_chunk`](Self::read_chunk).
    pub fn read_into<T: BufMut + ?Sized>(
        &mut self,
        target: &mut T,
    ) -> Result<ReadOutcome<NonZeroUsize>, ReadError<C::Reason>> {
        if let Some(settled) = self.settled_read() {
            return settled.map(|()| ReadOutcome::End);
        }
        if target.remaining_mut() == 0 {
            return Ok(ReadOutcome::NoProgress);
        }
        let limit = self.delivery.limit();
        match NonZeroUsize::new(self.parts.read_into(limit, target)) {
            Some(copied) => {
                self.notify_flow(ReceiveFlowEvent::Delivered);
                Ok(ReadOutcome::Data(copied))
            }
            None => self.end_or_wait(),
        }
    }

    /// The result of the first three priorities: `Some(Ok(()))` for a
    /// committed end of stream.
    fn settled_read(&mut self) -> Option<Result<(), ReadError<C::Reason>>> {
        if self.is_reader_dropped() {
            return Some(Err(ReadError::ReaderDropped));
        }
        if let Some(failure) = self.failure() {
            return Some(Err(ReadError::Connection { source: failure }));
        }
        match &self.reading {
            Reading::Committed(Committed::End) => return Some(Ok(())),
            Reading::Committed(Committed::Error(error)) => return Some(Err(error.clone())),
            Reading::Open | Reading::ReaderDropped { .. } => {}
        }
        match &self.buffer {
            BufferPhase::Destroyed(Destruction::Policy(applied)) => {
                let error = ReadError::local(applied.clone(), self.remote_reset());
                Some(Err(self.commit_error(error)))
            }
            // invariant: the mechanism destroys the buffer only together with
            // dropping the reader or committing a result, both handled above,
            // so an open reader never meets a forced destruction.
            BufferPhase::Destroyed(Destruction::Forced)
            | BufferPhase::Live
            | BufferPhase::Failed(_) => None,
        }
    }

    /// Judges end of stream and gaps once no data can be delivered.
    fn end_or_wait<T>(&mut self) -> Result<ReadOutcome<T>, ReadError<C::Reason>> {
        let delivered = self.parts.delivered_end();
        let remote = self.remote_reset();
        if self.parts.final_size() == Some(delivered) {
            return match remote {
                Some(reset) if self.reset_presentation == ResetPresentation::Report => {
                    let error = ReadError::Reset {
                        reset,
                        complete: true,
                    };
                    Err(self.commit_error(error))
                }
                _ => {
                    self.reading = Reading::Committed(Committed::End);
                    self.notify_termination(TerminationEvent::ReadResultCommitted);
                    Ok(ReadOutcome::End)
                }
            };
        }
        if let Boundary::Fixed { limit, applied } = &self.delivery
            && delivered >= *limit
        {
            let error = ReadError::local(applied.clone(), remote);
            return Err(self.commit_error(error));
        }
        if let Some(reset) = remote
            && delivered >= reset.reliable_size
        {
            let error = ReadError::Reset {
                reset,
                complete: false,
            };
            return Err(self.commit_error(error));
        }
        // The gap at the read position can no longer be filled.
        if let Boundary::Fixed { limit, applied } = &self.acceptance
            && delivered >= *limit
        {
            let error = ReadError::local(applied.clone(), remote);
            return Err(self.commit_error(error));
        }
        Ok(ReadOutcome::Wait)
    }

    /// Commits a terminal error and destroys the receive buffer in the same
    /// operation.
    fn commit_error(&mut self, error: ReadError<C::Reason>) -> ReadError<C::Reason> {
        self.reading = Reading::Committed(Committed::Error(error.clone()));
        self.destroy_buffer(Destruction::Forced);
        self.notify_termination(TerminationEvent::ReadResultCommitted);
        error
    }
}
