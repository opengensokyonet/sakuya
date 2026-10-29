//! Ending a stream sender: close, reset and reset with a reliable prefix.
//!
//! Each end operation is a local commitment. It fixes the final size, keeps
//! the data and credit the end still needs, closes input and installs the end
//! state before it returns; it never waits for the network, for congestion
//! control or for acknowledgements, and it needs no new credit.
//!
//! - [`StreamSender::close`] ends at the written end.
//! - [`StreamSender::reset`] and [`StreamSender::reset_at`] reset with
//!   reliable size zero or the requested reliable size. While no final size
//!   is fixed, the termination policy chooses it within
//!   `max(exposure_end, reliable_size) ..= written_end`.
//! - [`StreamSender::reset_with_final_size`] and
//!   [`StreamSender::reset_at_with_final_size`] name the final size
//!   themselves, within the same range.
//!
//! Repeating the effective target succeeds without effect. A reset may
//! replace a close and may lower an effective reliable size; it cannot raise
//! the reliable size or change the error code or final size, and a close
//! cannot follow a reset. Whether a call conflicts is judged against the
//! target in effect, regardless of who committed it.
//!
//! Status: confirmed (`send-side.md`, "结束操作是本地提交（已确认）" through
//! "close 后 reset 与完整确认的边界（已确认）"); the signatures of the explicit
//! final size operations are not settled.
use super::{EndSource, ResetTarget, SendEndState, SendTerminalState, StreamSender, WriteLimit};
use crate::send::flow_control::{SendFlowControlPolicy, StreamCreditEvent};
use crate::send::termination::{
    FinalSizeRequest, SendTerminationEvent, SendTerminationPolicy, TerminationAction,
};
use crate::send::write::SharedWriteLimitReason;
use crate::send_buffer::{ResetRetention, SendBuffer};
use core::fmt;
use sakuya_wire::var_int::VarInt;
use snafu::{Snafu, ensure};

/// Failures of [`StreamSender::close`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(close_error), visibility(pub(crate)))]
pub enum CloseError {
    /// The connection has closed.
    #[snafu(display("the connection is closed"))]
    ConnectionClosed,
    /// A reset is in effect; a close cannot replace it.
    #[snafu(display("the stream was already reset"))]
    AlreadyReset,
}

/// Failures of the reset operations; none of them changes any state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(reset_error), visibility(pub(crate)))]
pub enum ResetError {
    /// The connection has closed.
    #[snafu(display("the connection is closed"))]
    ConnectionClosed,
    /// The request conflicts with the effective end.
    #[snafu(display("reset conflicts with the effective end: {conflict}"))]
    ResetConflict {
        /// The conflicting field.
        conflict: ResetConflictKind,
    },
    /// The send direction is in a terminal state and takes no new reset.
    #[snafu(display("the send direction is in the terminal state {state:?}"))]
    ProtocolTerminal {
        /// The terminal state.
        state: SendTerminalState,
    },
    /// A reliable size above zero needs `RESET_STREAM_AT`, which the
    /// handshake did not negotiate.
    #[snafu(display("reliable size {reliable_size} needs the RESET_STREAM_AT extension"))]
    UnsupportedExtension {
        /// The requested reliable size.
        reliable_size: VarInt,
    },
    /// The requested reliable size lies beyond the written end: the prefix it
    /// names has not been handed over.
    #[snafu(display("reliable size {reliable_size} lies beyond the written end {written_end}"))]
    ReliablePrefixNotPrepared {
        /// The requested reliable size.
        reliable_size: VarInt,
        /// The written end.
        written_end: VarInt,
    },
    /// The requested final size lies outside the legal range.
    #[snafu(display("final size {final_size} lies outside {minimum}..={maximum}"))]
    InvalidFinalSize {
        /// The requested final size.
        final_size: VarInt,
        /// `max(exposure_end, reliable_size)`.
        minimum: VarInt,
        /// The written end.
        maximum: VarInt,
    },
}

/// The field of a reset request that conflicts with the effective end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResetConflictKind {
    /// The error code differs from the effective reset's.
    ErrorCode {
        /// The effective error code.
        current: VarInt,
        /// The requested error code.
        requested: VarInt,
    },
    /// The final size differs from the fixed one.
    FinalSize {
        /// The fixed final size.
        current: VarInt,
        /// The requested final size.
        requested: VarInt,
    },
    /// The reliable size exceeds the effective reset's: data it allowed to
    /// abandon cannot be promised again.
    ReliableSizeIncrease {
        /// The effective reliable size.
        current: VarInt,
        /// The requested reliable size.
        requested: VarInt,
    },
}

impl fmt::Display for ResetConflictKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ErrorCode { current, requested } => {
                write!(f, "error code {requested} differs from {current}")
            }
            Self::FinalSize { current, requested } => {
                write!(f, "final size {requested} differs from {current}")
            }
            Self::ReliableSizeIncrease { current, requested } => {
                write!(f, "reliable size {requested} exceeds {current}")
            }
        }
    }
}

/// What a validated reset request leads to.
enum ResetPlan {
    /// The request equals the effective target.
    Unchanged,
    /// A new target to install.
    Install(ResetTarget),
    /// A new target whose final size the termination policy chooses.
    CompleteFinalSize(FinalSizeRequest),
}

impl<C> StreamSender<C>
where
    C: SendBuffer + SendFlowControlPolicy + SendTerminationPolicy,
{
    /// Closes the stream normally at the written end.
    ///
    /// Succeeds without effect if a close is already in effect, also in a
    /// terminal state.
    ///
    /// # Errors
    ///
    /// [`CloseError::ConnectionClosed`], then [`CloseError::AlreadyReset`].
    pub fn close(&mut self) -> Result<(), CloseError> {
        ensure!(!self.connection_closed, close_error::ConnectionClosedSnafu);
        match self.end_state {
            SendEndState::Reset { .. } => close_error::AlreadyResetSnafu.fail(),
            SendEndState::Closed { .. } => Ok(()),
            SendEndState::Open => {
                self.commit_close(EndSource::Application);
                self.dispatch_termination(SendTerminationEvent::EndCommitted {
                    source: EndSource::Application,
                });
                Ok(())
            }
        }
    }

    /// Resets the stream with `error_code` and reliable size zero
    /// (`RESET_STREAM`).
    ///
    /// # Errors
    ///
    /// See [`reset_at_with_final_size`](Self::reset_at_with_final_size).
    pub fn reset(&mut self, error_code: VarInt) -> Result<(), ResetError> {
        self.request_reset(error_code, VarInt::ZERO, None)
    }

    /// Resets the stream with `error_code`, keeping the reliable delivery of
    /// the first `reliable_size` bytes (`RESET_STREAM_AT`).
    ///
    /// The prefix must already be written; the operation takes no input.
    ///
    /// # Errors
    ///
    /// See [`reset_at_with_final_size`](Self::reset_at_with_final_size).
    pub fn reset_at(
        &mut self,
        error_code: VarInt,
        reliable_size: VarInt,
    ) -> Result<(), ResetError> {
        self.request_reset(error_code, reliable_size, None)
    }

    /// Resets the stream with `error_code` and the explicit `final_size`.
    ///
    /// Status: extension operation; its signature is not settled.
    ///
    /// # Errors
    ///
    /// See [`reset_at_with_final_size`](Self::reset_at_with_final_size).
    pub fn reset_with_final_size(
        &mut self,
        error_code: VarInt,
        final_size: VarInt,
    ) -> Result<(), ResetError> {
        self.request_reset(error_code, VarInt::ZERO, Some(final_size))
    }

    /// Resets the stream with `error_code`, `reliable_size` and the explicit
    /// `final_size`.
    ///
    /// Status: extension operation; its signature is not settled.
    ///
    /// # Errors
    ///
    /// Checked in this order, after which the request succeeds without effect
    /// if it equals the effective reset:
    ///
    /// 1. [`ResetError::ConnectionClosed`];
    /// 2. [`ResetError::ResetConflict`] against the effective end;
    /// 3. [`ResetError::ProtocolTerminal`];
    /// 4. [`ResetError::UnsupportedExtension`] for a reliable size above zero
    ///    without `RESET_STREAM_AT`;
    /// 5. [`ResetError::ReliablePrefixNotPrepared`] for a reliable size beyond
    ///    the written end;
    /// 6. [`ResetError::InvalidFinalSize`] for a final size outside
    ///    `max(exposure_end, reliable_size) ..= written_end`.
    pub fn reset_at_with_final_size(
        &mut self,
        error_code: VarInt,
        reliable_size: VarInt,
        final_size: VarInt,
    ) -> Result<(), ResetError> {
        self.request_reset(error_code, reliable_size, Some(final_size))
    }

    fn request_reset(
        &mut self,
        error_code: VarInt,
        reliable_size: VarInt,
        final_size: Option<VarInt>,
    ) -> Result<(), ResetError> {
        let target = match self.plan_reset(error_code, reliable_size, final_size)? {
            ResetPlan::Unchanged => return Ok(()),
            ResetPlan::Install(target) => target,
            ResetPlan::CompleteFinalSize(request) => {
                let context = self.termination_context();
                let final_size = self.composition.complete_final_size(request, &context);
                assert!(
                    (request.minimum..=request.maximum).contains(&final_size),
                    "termination policy chose final size {final_size} outside {}..={}",
                    request.minimum,
                    request.maximum
                );
                ResetTarget {
                    error_code,
                    reliable_size,
                    final_size,
                }
            }
        };
        self.commit_reset(target, EndSource::Application);
        self.dispatch_termination(SendTerminationEvent::EndCommitted {
            source: EndSource::Application,
        });
        Ok(())
    }

    /// Validates a reset request against the effective state.
    fn plan_reset(
        &self,
        error_code: VarInt,
        reliable_size: VarInt,
        final_size: Option<VarInt>,
    ) -> Result<ResetPlan, ResetError> {
        ensure!(!self.connection_closed, reset_error::ConnectionClosedSnafu);
        let conflict = |conflict| reset_error::ResetConflictSnafu { conflict }.fail();
        match self.end_state {
            SendEndState::Reset { target, .. } => {
                if target.error_code == error_code
                    && target.reliable_size == reliable_size
                    && final_size.is_none_or(|size| size == target.final_size)
                {
                    return Ok(ResetPlan::Unchanged);
                }
                if target.error_code != error_code {
                    return conflict(ResetConflictKind::ErrorCode {
                        current: target.error_code,
                        requested: error_code,
                    });
                }
                if let Some(requested) = final_size
                    && requested != target.final_size
                {
                    return conflict(ResetConflictKind::FinalSize {
                        current: target.final_size,
                        requested,
                    });
                }
                if reliable_size > target.reliable_size {
                    return conflict(ResetConflictKind::ReliableSizeIncrease {
                        current: target.reliable_size,
                        requested: reliable_size,
                    });
                }
            }
            SendEndState::Closed {
                final_size: current,
                ..
            } => {
                if let Some(requested) = final_size
                    && requested != current
                {
                    return conflict(ResetConflictKind::FinalSize { current, requested });
                }
            }
            SendEndState::Open => {}
        }
        if let Some(state) = self.terminal_state {
            return reset_error::ProtocolTerminalSnafu { state }.fail();
        }
        ensure!(
            reliable_size == VarInt::ZERO || self.reset_stream_at_supported,
            reset_error::UnsupportedExtensionSnafu { reliable_size }
        );
        let written_end = self.written_end();
        ensure!(
            reliable_size <= written_end,
            reset_error::ReliablePrefixNotPreparedSnafu {
                reliable_size,
                written_end,
            }
        );
        if let Some(fixed) = self.end_state.final_size() {
            return Ok(ResetPlan::Install(ResetTarget {
                error_code,
                reliable_size,
                final_size: fixed,
            }));
        }
        let minimum = self.exposure_end().max(reliable_size);
        match final_size {
            Some(final_size) => {
                ensure!(
                    minimum <= final_size && final_size <= written_end,
                    reset_error::InvalidFinalSizeSnafu {
                        final_size,
                        minimum,
                        maximum: written_end,
                    }
                );
                Ok(ResetPlan::Install(ResetTarget {
                    error_code,
                    reliable_size,
                    final_size,
                }))
            }
            None => Ok(ResetPlan::CompleteFinalSize(FinalSizeRequest {
                error_code,
                reliable_size,
                minimum,
                maximum: written_end,
            })),
        }
    }

    fn commit_close(&mut self, source: EndSource) {
        self.end_state = SendEndState::Closed {
            final_size: self.written_end(),
            source,
        };
        self.notify_flow_control(StreamCreditEvent::EndCommitted { source });
    }

    fn commit_reset(&mut self, target: ResetTarget, source: EndSource) {
        self.end_state = SendEndState::Reset { target, source };
        self.composition.apply_reset(ResetRetention {
            final_size: target.final_size,
            reliable_size: target.reliable_size,
        });
        self.notify_flow_control(StreamCreditEvent::EndCommitted { source });
    }

    /// Validates and commits an automatic action, returning the event that
    /// reports it, or `None` if it changes nothing.
    ///
    /// # Panics
    ///
    /// If the action is illegal in the current state.
    pub(super) fn apply_termination_action(
        &mut self,
        action: TerminationAction<C::WriteLimitReason>,
    ) -> Option<SendTerminationEvent> {
        match action {
            TerminationAction::Keep => None,
            TerminationAction::NarrowWriteLimit {
                write_limit_end,
                reason,
            } => self.narrow_write_limit(write_limit_end, reason),
            TerminationAction::Close => match self.end_state {
                SendEndState::Closed { .. } => None,
                SendEndState::Reset { .. } => {
                    panic!("termination policy closed a stream that was reset")
                }
                SendEndState::Open => {
                    assert!(
                        !self.connection_closed,
                        "termination policy closed a stream after the connection closed"
                    );
                    self.commit_close(EndSource::Policy);
                    Some(SendTerminationEvent::EndCommitted {
                        source: EndSource::Policy,
                    })
                }
            },
            TerminationAction::Reset(target) => {
                let plan = self
                    .plan_reset(
                        target.error_code,
                        target.reliable_size,
                        Some(target.final_size),
                    )
                    .unwrap_or_else(|error| {
                        panic!("termination policy decided an illegal reset {target:?}: {error}")
                    });
                match plan {
                    ResetPlan::Unchanged => None,
                    ResetPlan::Install(target) => {
                        self.commit_reset(target, EndSource::Policy);
                        Some(SendTerminationEvent::EndCommitted {
                            source: EndSource::Policy,
                        })
                    }
                    ResetPlan::CompleteFinalSize(_) => {
                        unreachable!("an automatic reset names its final size")
                    }
                }
            }
        }
    }

    fn narrow_write_limit(
        &mut self,
        write_limit_end: VarInt,
        reason: C::WriteLimitReason,
    ) -> Option<SendTerminationEvent> {
        assert!(
            !self.connection_closed && self.terminal_state.is_none(),
            "termination policy narrowed the write limit of a finished stream"
        );
        assert!(
            self.end_state == SendEndState::Open,
            "termination policy narrowed the write limit after input was closed"
        );
        assert!(
            self.stop_sending.is_some(),
            "termination policy narrowed the write limit without a STOP_SENDING request"
        );
        if let Some(current) = &self.write_limit {
            assert!(
                write_limit_end <= current.end,
                "termination policy widened the write limit end from {} to {write_limit_end}",
                current.end
            );
            if write_limit_end == current.end {
                return None;
            }
        }
        self.write_limit = Some(WriteLimit {
            end: write_limit_end,
            reason: SharedWriteLimitReason::new(reason),
        });
        self.notify_flow_control(StreamCreditEvent::WriteLimitNarrowed { write_limit_end });
        Some(SendTerminationEvent::WriteLimitNarrowed { write_limit_end })
    }
}
