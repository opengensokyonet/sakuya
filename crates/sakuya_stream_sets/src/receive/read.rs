//! The synchronous core of the stream reader: read results and their
//! priorities.
//!
//! Both ways of reading — copying into a [`BufMut`] with
//! [`StreamReceiver::read_into`] and taking whole blocks with
//! [`StreamReceiver::read_chunk`], at most a given number of bytes each — share one read position and one terminal
//! result. A read returns, in this order of priority:
//!
//! 1. [`ReadError::ReaderDropped`] once the reader was dropped;
//! 2. [`ReadError::LayerEnded`], once the connection closed;
//! 3. the committed terminal result (end of stream or a terminal error);
//! 4. [`ReadOutcome::Wait`], while the stream waits for the connection to
//!    close after a frame violated the protocol: the read does not complete,
//!    exactly as if no new data had arrived, and nothing wakes the reader;
//! 5. the result of a buffer destruction that already took effect;
//! 6. no progress, for an empty target ([`read_into`] only);
//! 7. the contiguous data that can be delivered now, without waiting to fill
//!    the target;
//! 8. end of stream or a terminal error, judged from the final size, the
//!    local limits and the reset facts: a reset is returned once delivery has
//!    reached the end of the prefix the peer still owes;
//! 9. otherwise, [`ReadOutcome::Wait`].
//!
//! A call that delivers data never also reports the end; the next call does.
//! The call that delivers a terminal error destroys the receive buffer, and
//! repeated reads return the same result, unless the connection closes later.
//! An empty target never commits a result, so a read that cannot take a byte
//! does not end a stream that late data could still complete.
//!
//! [`read_into`]: StreamReceiver::read_into
use super::{Boundary, BufferPhase, Committed, Destruction, Reading, StreamReceiver};
use bytes::BufMut;
use core::num::NonZeroUsize;
use sakuya_stream_v1::receive::flow_control::ReceiveFlowControlPolicy;
use sakuya_stream_v1::receive::flow_control::ReceiveFlowEvent;
use sakuya_stream_v1::receive::read::{ReadError, ReadOutcome};
use sakuya_stream_v1::receive::remote_reset::RemoteResetFacts;
use sakuya_stream_v1::receive::termination::ReceiveTerminationPolicy;
use sakuya_stream_v1::receive::termination::ResetPresentation;
use sakuya_stream_v1::receive::termination::TerminationEvent;
use sakuya_stream_v1::receive_buffer::{StreamReceiveBuffer, offset_add};
use sakuya_var_int::VarInt;

/// A read result known without looking at the data.
#[derive(Clone, Copy)]
enum Settled {
    /// The end of stream, committed by an earlier read.
    End,
    /// The read does not complete: the stream waits for the connection to
    /// close.
    Wait,
}

impl Settled {
    fn outcome<T>(self) -> ReadOutcome<T> {
        match self {
            Self::End => ReadOutcome::End,
            Self::Wait => ReadOutcome::Wait,
        }
    }
}

/// The result a read settles on without consulting the buffer, if any.
type SettledRead<R, Lc, F> = Option<Result<Settled, ReadError<R, Lc, F>>>;

impl<C, Lc, F> StreamReceiver<C, Lc, F>
where
    C: StreamReceiveBuffer + ReceiveFlowControlPolicy + ReceiveTerminationPolicy<F>,
    F: RemoteResetFacts,
{
    /// Reads the next block of contiguous data, at most `maximum` bytes.
    ///
    /// A block longer than `maximum` is cut: the first `maximum` bytes are
    /// delivered and the rest stays in the receive buffer, still undelivered.
    ///
    /// # Errors
    ///
    /// Returns the terminal error of the stream, or
    /// [`ReadError::ReaderDropped`] after
    /// [`reader_dropped`](Self::reader_dropped); see the [module
    /// documentation](self) for priorities.
    pub fn read_chunk(
        &mut self,
        maximum: NonZeroUsize,
    ) -> Result<ReadOutcome<C::Chunk>, ReadError<C::Reason, Lc, F>> {
        if let Some(settled) = self.settled_read() {
            return settled.map(Settled::outcome);
        }
        // An end past the largest offset bounds nothing the delivery limit
        // does not already bound.
        let maximum_end =
            offset_add(self.parts.delivered_end(), maximum.get()).unwrap_or(VarInt::MAX);
        match self
            .parts
            .read_chunk(self.delivery.limit().min(maximum_end))
        {
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
    ) -> Result<ReadOutcome<NonZeroUsize>, ReadError<C::Reason, Lc, F>> {
        if let Some(settled) = self.settled_read() {
            return settled.map(Settled::outcome);
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

    /// The result of the first five priorities.
    fn settled_read(&mut self) -> SettledRead<C::Reason, Lc, F> {
        if self.is_reader_dropped() {
            return Some(Err(ReadError::ReaderDropped));
        }
        if let Some(closed) = self.closed() {
            return Some(Err(ReadError::LayerEnded {
                source: closed.clone(),
            }));
        }
        match &self.reading {
            Reading::Committed(Committed::End) => return Some(Ok(Settled::End)),
            Reading::Committed(Committed::Error(error)) => return Some(Err(error.clone())),
            Reading::Open | Reading::ReaderDropped { .. } => {}
        }
        // A result judged now would be a new one, and the connection is
        // about to close for the violation.
        if self.is_violated() {
            return Some(Ok(Settled::Wait));
        }
        match &self.buffer {
            BufferPhase::Destroyed(Destruction::Policy(applied)) => {
                let error = ReadError::BufferDestroyed {
                    reason: applied.reason.clone(),
                    trigger: applied.trigger,
                    remote: self.remote_reset(),
                };
                Some(Err(self.commit_error(error)))
            }
            // invariant: the mechanism destroys the buffer only together with
            // dropping the reader or committing a result, both handled above,
            // so an open reader never meets a forced destruction.
            BufferPhase::Destroyed(Destruction::Forced) | BufferPhase::Live => None,
        }
    }

    /// Judges end of stream and gaps once no data can be delivered.
    fn end_or_wait<T>(&mut self) -> Result<ReadOutcome<T>, ReadError<C::Reason, Lc, F>> {
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
            let error = ReadError::DeliveryLimitReached {
                reason: applied.reason.clone(),
                trigger: applied.trigger,
                remote,
            };
            return Err(self.commit_error(error));
        }
        if let Some(reset) = remote
            && delivered >= reset.owed_end()
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
            let error = ReadError::AcceptanceLimitReached {
                reason: applied.reason.clone(),
                trigger: applied.trigger,
                remote,
            };
            return Err(self.commit_error(error));
        }
        Ok(ReadOutcome::Wait)
    }

    /// Commits a terminal error and destroys the receive buffer in the same
    /// operation.
    fn commit_error(&mut self, error: ReadError<C::Reason, Lc, F>) -> ReadError<C::Reason, Lc, F> {
        self.reading = Reading::Committed(Committed::Error(error.clone()));
        self.destroy_buffer(Destruction::Forced);
        self.notify_termination(TerminationEvent::ReadResultCommitted);
        error
    }
}
