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
//! The signatures of the operations that name the final size are
//! provisional.
use super::{
    CommittedEnd, EndPhase, EndSource, ResetTarget, SendEndState, SendTerminalState, StopSending,
    StreamSender, WriteLimit,
};
use crate::application_error_code::ApplicationErrorCode;
use crate::send::flow_control::{SendFlowControlPolicy, StreamCreditEvent};
use crate::send::termination::{
    FinalSizeRequest, SendTerminationEvent, SendTerminationPolicy, TerminationAction,
};
use crate::send::write::SharedWriteLimitReason;
use crate::send_buffer::{ResetRetention, SendBuffer};
use core::fmt;
use sakuya_wire::var_int::VarInt;
use snafu::{Report, ResultExt, Snafu, ensure};

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
        current: ApplicationErrorCode,
        /// The requested error code.
        requested: ApplicationErrorCode,
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

/// What a reset request leads to once checked against the effective state.
enum ResetCheck {
    /// The request equals the effective target.
    Unchanged,
    /// The final size is already fixed at this value.
    FinalSizeFixed(VarInt),
    /// No final size is fixed; a new one must lie in `minimum..=maximum`.
    FinalSizeOpen { minimum: VarInt, maximum: VarInt },
}

/// What a valid application reset request leads to.
enum ResetPlan {
    /// The request equals the effective target.
    Unchanged,
    /// A new target to install.
    Install(ResetTarget),
    /// A new target whose final size the termination policy chooses.
    CompleteFinalSize(FinalSizeRequest),
}

/// A checked termination policy result, ready to commit.
enum PolicyPlan<R> {
    /// Nothing changes.
    Keep,
    /// Close at the written end.
    Close,
    /// Narrow the write limit end strictly.
    NarrowWriteLimit { write_limit_end: VarInt, reason: R },
    /// Install a reset target.
    Reset(ResetTarget),
}

/// A termination policy result that violates the
/// [policy contract](crate::send::termination#contract).
#[derive(Debug, Snafu)]
#[snafu(module(policy_violation))]
enum PolicyViolation {
    #[snafu(display("termination policy closed a stream that was reset"))]
    CloseAfterReset,
    #[snafu(display("termination policy closed a stream after the connection closed"))]
    CloseAfterConnectionClosed,
    #[snafu(display("termination policy narrowed the write limit of a finished stream"))]
    NarrowFinished,
    #[snafu(display("termination policy narrowed the write limit after input was closed"))]
    NarrowAfterInputClosed,
    #[snafu(display("termination policy narrowed the write limit without a STOP_SENDING request"))]
    NarrowWithoutStopSending,
    #[snafu(display(
        "termination policy widened the write limit end from {current} to {requested}"
    ))]
    WidenWriteLimit { current: VarInt, requested: VarInt },
    #[snafu(display("termination policy decided an illegal reset {target:?}"))]
    IllegalReset {
        target: ResetTarget,
        source: ResetError,
    },
    #[snafu(display(
        "termination policy chose final size {final_size} outside {minimum}..={maximum}"
    ))]
    FinalSizeOutOfRange {
        final_size: VarInt,
        minimum: VarInt,
        maximum: VarInt,
    },
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
        match self.end_state() {
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
    pub fn reset(&mut self, error_code: ApplicationErrorCode) -> Result<(), ResetError> {
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
        error_code: ApplicationErrorCode,
        reliable_size: VarInt,
    ) -> Result<(), ResetError> {
        self.request_reset(error_code, reliable_size, None)
    }

    /// Resets the stream with `error_code` and the explicit `final_size`.
    ///
    /// This signature is provisional.
    ///
    /// # Errors
    ///
    /// See [`reset_at_with_final_size`](Self::reset_at_with_final_size).
    pub fn reset_with_final_size(
        &mut self,
        error_code: ApplicationErrorCode,
        final_size: VarInt,
    ) -> Result<(), ResetError> {
        self.request_reset(error_code, VarInt::ZERO, Some(final_size))
    }

    /// Resets the stream with `error_code`, `reliable_size` and the explicit
    /// `final_size`.
    ///
    /// This signature is provisional.
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
        error_code: ApplicationErrorCode,
        reliable_size: VarInt,
        final_size: VarInt,
    ) -> Result<(), ResetError> {
        self.request_reset(error_code, reliable_size, Some(final_size))
    }

    fn request_reset(
        &mut self,
        error_code: ApplicationErrorCode,
        reliable_size: VarInt,
        final_size: Option<VarInt>,
    ) -> Result<(), ResetError> {
        let target = match self.plan_reset(error_code, reliable_size, final_size)? {
            ResetPlan::Unchanged => return Ok(()),
            ResetPlan::Install(target) => target,
            ResetPlan::CompleteFinalSize(request) => {
                let context = self.termination_context();
                let chosen = self.composition.complete_final_size(request, &context);
                enforce_policy(check_completed_final_size(request, chosen))
            }
        };
        self.commit_reset(target, EndSource::Application);
        self.dispatch_termination(SendTerminationEvent::EndCommitted {
            source: EndSource::Application,
        });
        Ok(())
    }

    /// Validates an application reset request against the effective state.
    fn plan_reset(
        &self,
        error_code: ApplicationErrorCode,
        reliable_size: VarInt,
        final_size: Option<VarInt>,
    ) -> Result<ResetPlan, ResetError> {
        let target = |final_size| ResetTarget {
            error_code,
            reliable_size,
            final_size,
        };
        match self.check_reset(error_code, reliable_size, final_size)? {
            ResetCheck::Unchanged => Ok(ResetPlan::Unchanged),
            ResetCheck::FinalSizeFixed(fixed) => Ok(ResetPlan::Install(target(fixed))),
            ResetCheck::FinalSizeOpen { minimum, maximum } => match final_size {
                Some(final_size) => {
                    check_final_size_range(final_size, minimum, maximum)?;
                    Ok(ResetPlan::Install(target(final_size)))
                }
                None => Ok(ResetPlan::CompleteFinalSize(FinalSizeRequest {
                    error_code,
                    reliable_size,
                    minimum,
                    maximum,
                })),
            },
        }
    }

    /// Validates a complete reset target against the effective state;
    /// `None` means it equals the effective target.
    fn plan_complete_reset(&self, target: ResetTarget) -> Result<Option<ResetTarget>, ResetError> {
        match self.check_reset(
            target.error_code,
            target.reliable_size,
            Some(target.final_size),
        )? {
            ResetCheck::Unchanged => Ok(None),
            ResetCheck::FinalSizeFixed(_) => Ok(Some(target)),
            ResetCheck::FinalSizeOpen { minimum, maximum } => {
                check_final_size_range(target.final_size, minimum, maximum)?;
                Ok(Some(target))
            }
        }
    }

    /// Checks a reset request against the effective state, up to the choice
    /// of the final size. An explicit final size must equal a fixed one.
    fn check_reset(
        &self,
        error_code: ApplicationErrorCode,
        reliable_size: VarInt,
        final_size: Option<VarInt>,
    ) -> Result<ResetCheck, ResetError> {
        ensure!(!self.connection_closed, reset_error::ConnectionClosedSnafu);
        let conflict = |conflict| reset_error::ResetConflictSnafu { conflict }.fail();
        let end_state = self.end_state();
        match end_state {
            SendEndState::Reset { target, .. } => {
                if target.error_code == error_code
                    && target.reliable_size == reliable_size
                    && final_size.is_none_or(|size| size == target.final_size)
                {
                    return Ok(ResetCheck::Unchanged);
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
        if let Some(state) = self.terminal_state() {
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
        Ok(match end_state.final_size() {
            Some(fixed) => ResetCheck::FinalSizeFixed(fixed),
            None => ResetCheck::FinalSizeOpen {
                minimum: self.exposure_end().max(reliable_size),
                maximum: written_end,
            },
        })
    }

    fn commit_close(&mut self, source: EndSource) {
        self.set_end(CommittedEnd::Closed {
            final_size: self.written_end(),
            source,
        });
        self.notify_flow_control(StreamCreditEvent::EndCommitted { source });
    }

    /// Installs `target`, which [`check_reset`](Self::check_reset) accepted.
    fn commit_reset(&mut self, target: ResetTarget, source: EndSource) {
        let retention = ResetRetention {
            final_size: target.final_size,
            reliable_size: target.reliable_size,
        };
        if let Err(error) = self.composition.apply_reset(retention) {
            // invariant: the target was checked against the send buffer's own
            // written and exposure ends and against the final size the end
            // state fixed, which is the only one the buffer can have been
            // shown. A send buffer that still refuses it breaks the
            // `SendBuffer` contract.
            unreachable!("send buffer refused a checked reset target {target:?}: {error}");
        }
        self.set_end(CommittedEnd::Reset { target, source });
        self.notify_flow_control(StreamCreditEvent::EndCommitted { source });
    }

    /// Replaces the committed end; a terminal state is never replaced, since
    /// a send direction in one takes no new end.
    fn set_end(&mut self, end: CommittedEnd) {
        let terminal = self.terminal_state();
        debug_assert!(terminal.is_none());
        self.end = EndPhase::Ended { end, terminal };
    }

    /// Validates and commits an automatic action, returning the event that
    /// reports it, or `None` if it changes nothing.
    pub(super) fn apply_termination_action(
        &mut self,
        action: TerminationAction<C::WriteLimitReason>,
    ) -> Option<SendTerminationEvent> {
        match enforce_policy(self.check_termination_action(action)) {
            PolicyPlan::Keep => None,
            PolicyPlan::Close => {
                self.commit_close(EndSource::Policy);
                Some(SendTerminationEvent::EndCommitted {
                    source: EndSource::Policy,
                })
            }
            PolicyPlan::NarrowWriteLimit {
                write_limit_end,
                reason,
            } => {
                if let StopSending::Received { write_limit, .. } = &mut self.stop_sending {
                    *write_limit = Some(WriteLimit {
                        end: write_limit_end,
                        reason: SharedWriteLimitReason::new(reason),
                    });
                }
                self.notify_flow_control(StreamCreditEvent::WriteLimitNarrowed { write_limit_end });
                Some(SendTerminationEvent::WriteLimitNarrowed { write_limit_end })
            }
            PolicyPlan::Reset(target) => {
                self.commit_reset(target, EndSource::Policy);
                Some(SendTerminationEvent::EndCommitted {
                    source: EndSource::Policy,
                })
            }
        }
    }

    /// Checks an automatic action against the
    /// [policy contract](crate::send::termination#contract) and the current
    /// state.
    fn check_termination_action(
        &self,
        action: TerminationAction<C::WriteLimitReason>,
    ) -> Result<PolicyPlan<C::WriteLimitReason>, PolicyViolation> {
        match action {
            TerminationAction::Keep => Ok(PolicyPlan::Keep),
            TerminationAction::Close => match self.end_state() {
                SendEndState::Closed { .. } => Ok(PolicyPlan::Keep),
                SendEndState::Reset { .. } => policy_violation::CloseAfterResetSnafu.fail(),
                SendEndState::Open => {
                    ensure!(
                        !self.connection_closed,
                        policy_violation::CloseAfterConnectionClosedSnafu
                    );
                    Ok(PolicyPlan::Close)
                }
            },
            TerminationAction::NarrowWriteLimit {
                write_limit_end,
                reason,
            } => {
                ensure!(
                    !self.connection_closed && self.terminal_state().is_none(),
                    policy_violation::NarrowFinishedSnafu
                );
                ensure!(
                    self.end_state() == SendEndState::Open,
                    policy_violation::NarrowAfterInputClosedSnafu
                );
                ensure!(
                    self.stop_sending_code().is_some(),
                    policy_violation::NarrowWithoutStopSendingSnafu
                );
                if let Some(current) = self.write_limit_end() {
                    ensure!(
                        write_limit_end <= current,
                        policy_violation::WidenWriteLimitSnafu {
                            current,
                            requested: write_limit_end,
                        }
                    );
                    if write_limit_end == current {
                        return Ok(PolicyPlan::Keep);
                    }
                }
                Ok(PolicyPlan::NarrowWriteLimit {
                    write_limit_end,
                    reason,
                })
            }
            TerminationAction::Reset(target) => Ok(self
                .plan_complete_reset(target)
                .context(policy_violation::IllegalResetSnafu { target })?
                .map_or(PolicyPlan::Keep, PolicyPlan::Reset)),
        }
    }
}

/// Checks the completion entry's `chosen` final size for `request` against
/// the [policy contract](crate::send::termination#contract).
fn check_completed_final_size(
    request: FinalSizeRequest,
    chosen: VarInt,
) -> Result<ResetTarget, PolicyViolation> {
    ensure!(
        (request.minimum..=request.maximum).contains(&chosen),
        policy_violation::FinalSizeOutOfRangeSnafu {
            final_size: chosen,
            minimum: request.minimum,
            maximum: request.maximum,
        }
    );
    Ok(ResetTarget {
        error_code: request.error_code,
        reliable_size: request.reliable_size,
        final_size: chosen,
    })
}

/// The single place where a termination policy's contract violation ends
/// the operation: every policy result passes through here after its check
/// and before anything changes.
fn enforce_policy<T>(checked: Result<T, PolicyViolation>) -> T {
    match checked {
        Ok(plan) => plan,
        Err(violation) => panic!("{}", Report::from_error(violation)),
    }
}

fn check_final_size_range(
    final_size: VarInt,
    minimum: VarInt,
    maximum: VarInt,
) -> Result<(), ResetError> {
    ensure!(
        minimum <= final_size && final_size <= maximum,
        reset_error::InvalidFinalSizeSnafu {
            final_size,
            minimum,
            maximum,
        }
    );
    Ok(())
}
