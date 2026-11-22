//! Ending a stream sender: close and reset.
//!
//! Each end operation is a local commitment. It fixes the final size, keeps
//! the data and credit the end still needs, closes input and installs the end
//! state before it returns; it never waits for the network, for congestion
//! control or for acknowledgements, and it needs no new credit.
//!
//! - [`StreamSender::close`] ends at the written end.
//! - [`StreamSender::request_reset`] resets as a request of the stream's
//!   reset target type asks. While no final size is fixed, the request names
//!   it or the termination policy chooses it, within
//!   `max(exposure_end, minimum) ..= written_end`, where `minimum` is what
//!   the request needs ([`LocalResetTarget::minimum_final_size`]).
//! - [`StreamSender::reset`] and [`StreamSender::reset_with_final_size`] are
//!   the requests of [`LocalReset`]: they reset with `RESET_STREAM`.
//!
//! Repeating the effective target succeeds without effect. A reset may
//! replace a close; it cannot change the error code or the final size, and a
//! close cannot follow a reset. Whether a later request replaces the target
//! in effect is up to the target type; a [`LocalReset`] is never replaced.
//! Whether a call conflicts is judged against the target in effect,
//! regardless of who committed it.
//!
//! The signatures of the operations that name the final size are
//! provisional.
use super::{CommittedEnd, EndPhase, SentEndFrames, StopSending, StreamSender, WriteLimit};
use core::convert::Infallible;
use sakuya_stream_v1::connection_send_credit::ConnectionSendFlowController;
use sakuya_stream_v1::send::finish::{
    CloseError, ProtocolTerminalError, RequestResetErrorOf, ResetError, ResetWithFinalSizeError,
    request_reset_error,
};
use sakuya_stream_v1::send::flow_control::{SendFlowControlPolicy, StreamCreditEvent};
use sakuya_stream_v1::send::local_reset::{LocalReset, LocalResetTarget};
use sakuya_stream_v1::send::termination::{
    FinalSizeRequest, SendTerminationEvent, SendTerminationPolicy, TerminationAction,
};
use sakuya_stream_v1::send::write::SharedWriteLimitReason;
use sakuya_stream_v1::send::{EndSource, SendEndState, StreamResetError};
use sakuya_stream_v1::send_buffer::visibility::FinalSizeBelowExposureError;
use sakuya_stream_v1::send_buffer::{
    FinalSizeBeyondWrittenEndError, ResetRetention, SendMarker, StreamSendBuffer,
};
use sakuya_stream_v1::stream_end::{FinalSizeChangeError, ResetCodeChangeError};
use sakuya_wire_v1::application_error::ApplicationErrorCode;
use sakuya_wire_v1::var_int::VarInt;
use snafu::{Report, ResultExt, Snafu, ensure};

/// What a valid reset request leads to.
enum ResetPlan<T: LocalResetTarget> {
    /// The request equals the effective target.
    Unchanged,
    /// A new target to install.
    Install(T),
    /// No final size is fixed and the request names none: the termination
    /// policy chooses it within these bounds.
    CompleteFinalSize(FinalSizeBounds),
}

/// The values that bound a new final size: it is at least what the request
/// needs and the exposure end, and at most the written end.
#[derive(Clone, Copy)]
struct FinalSizeBounds {
    /// The smallest final size the request can end the stream at.
    minimum: VarInt,
    exposure_end: VarInt,
    written_end: VarInt,
}

impl FinalSizeBounds {
    /// The question for the termination policy's completion entry.
    fn request<T: LocalResetTarget>(self, request: T::Request) -> FinalSizeRequest<T> {
        FinalSizeRequest {
            request,
            minimum: self.exposure_end.max(self.minimum),
            maximum: self.written_end,
        }
    }
}

/// A checked termination policy result, ready to commit.
enum PolicyPlan<R, T> {
    /// Nothing changes.
    Keep,
    /// Close at the written end.
    Close,
    /// Narrow the write limit end strictly.
    NarrowWriteLimit { write_limit_end: VarInt, reason: R },
    /// Install a reset target.
    Reset(T),
}

/// The connection is closed; stands for [`LayerEndedError`] in the
/// failure of a policy's decision, whose cause the failure does not keep.
#[derive(Debug, Snafu)]
#[snafu(display("the connection is closed"))]
struct ConnectionIsClosed;

/// A termination policy result that violates the
/// [policy contract](crate::send::termination#contract).
#[derive(Debug, Snafu)]
#[snafu(module(policy_violation))]
enum PolicyViolationError<T: LocalResetTarget> {
    #[snafu(display("termination policy closed a stream that was reset"))]
    CloseAfterReset { source: StreamResetError },
    #[snafu(display("termination policy closed a stream after the connection closed"))]
    CloseAfterConnectionClosed { source: ConnectionIsClosed },
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
        target: T,
        source: RequestResetErrorOf<T, Infallible>,
    },
    #[snafu(display("termination policy decided an illegal reset {target:?}"))]
    ResetAfterConnectionClosed {
        target: T,
        source: ConnectionIsClosed,
    },
    #[snafu(display("termination policy chose a final size the reset cannot end at"))]
    ChosenFinalSizeUnfit { source: T::Unfit },
    #[snafu(display("termination policy chose a final size below the exposure end"))]
    ChosenFinalSizeBelowExposure { source: FinalSizeBelowExposureError },
    #[snafu(display("termination policy chose a final size beyond the written end"))]
    ChosenFinalSizeBeyondWrittenEnd {
        source: FinalSizeBeyondWrittenEndError,
    },
}

impl<C, K, Lc, B, M> StreamSender<C, K, Lc, LocalReset, B, M>
where
    K: ConnectionSendFlowController,
    M: SendMarker,
    C: StreamSendBuffer<B, K::Reservation, M> + SendFlowControlPolicy + SendTerminationPolicy,
{
    /// Resets the stream with `error_code` and ends it with `RESET_STREAM`.
    ///
    /// While no final size is fixed, the termination policy chooses it.
    ///
    /// # Errors
    ///
    /// Checked in this order, after which the request succeeds without effect
    /// if it equals the effective reset:
    ///
    /// 1. [`ResetError::LayerEnded`];
    /// 2. [`ResetError::ErrorCodeConflict`] against an effective reset;
    /// 3. [`ResetError::ProtocolTerminal`].
    pub fn reset(&mut self, error_code: ApplicationErrorCode) -> Result<(), ResetError<Lc>> {
        self.request_reset(error_code, None)
            .map_err(ResetError::from_request_without_final_size)
    }

    /// Resets the stream with `error_code` and the explicit `final_size`, as
    /// [`reset`](Self::reset) does.
    ///
    /// This signature is provisional.
    ///
    /// # Errors
    ///
    /// Checked in this order, after which the request succeeds without effect
    /// if it equals the effective reset:
    ///
    /// 1. [`ResetWithFinalSizeError::LayerEnded`];
    /// 2. against an effective reset,
    ///    [`ResetWithFinalSizeError::ErrorCodeConflict`], then
    ///    [`ResetWithFinalSizeError::FinalSizeConflictsWithReset`]; against an
    ///    effective close,
    ///    [`ResetWithFinalSizeError::FinalSizeConflictsWithClose`];
    /// 3. [`ResetWithFinalSizeError::ProtocolTerminal`];
    /// 4. while no final size is fixed,
    ///    [`ResetWithFinalSizeError::FinalSizeBelowExposure`], then
    ///    [`ResetWithFinalSizeError::FinalSizeBeyondWrittenEnd`].
    pub fn reset_with_final_size(
        &mut self,
        error_code: ApplicationErrorCode,
        final_size: VarInt,
    ) -> Result<(), ResetWithFinalSizeError<Lc>> {
        Ok(self.request_reset(error_code, Some(final_size))?)
    }
}

impl<C, K, Lc, T, B, M> StreamSender<C, K, Lc, T, B, M>
where
    T: LocalResetTarget,
    K: ConnectionSendFlowController,
    M: SendMarker,
    C: StreamSendBuffer<B, K::Reservation, M> + SendFlowControlPolicy<T> + SendTerminationPolicy<T>,
{
    /// Closes the stream normally at the written end.
    ///
    /// Succeeds without effect if a close is already in effect, also in a
    /// terminal state.
    ///
    /// # Errors
    ///
    /// [`CloseError::LayerEnded`], then [`CloseError::AlreadyReset`].
    pub fn close(&mut self) -> Result<(), CloseError<Lc>> {
        self.check_connection_open()?;
        match self.end_state() {
            SendEndState::Reset { .. } => Err(StreamResetError.into()),
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

    /// Resets the stream as `request` asks, ending it at `final_size` if one
    /// is given.
    ///
    /// The operations that reset a stream are written for each reset target
    /// type and call this one; [`reset`](StreamSender::reset) is that of
    /// [`LocalReset`]. While no final size is fixed and `final_size` is
    /// `None`, the termination policy chooses it. A request that
    /// [restates](LocalResetTarget::restates) the reset target in effect,
    /// with the same final size if it names one, succeeds without effect.
    ///
    /// # Errors
    ///
    /// Checked in this order; a request that restates the target in effect
    /// succeeds before the second check:
    ///
    /// 1. [`RequestResetError::LayerEnded`](sakuya_stream_v1::send::finish::RequestResetError::LayerEnded);
    /// 2. against an effective reset,
    ///    [`RequestResetError::ErrorCodeConflict`](sakuya_stream_v1::send::finish::RequestResetError::ErrorCodeConflict), then
    ///    [`RequestResetError::FinalSizeConflictsWithReset`](sakuya_stream_v1::send::finish::RequestResetError::FinalSizeConflictsWithReset); against an
    ///    effective close, [`RequestResetError::FinalSizeConflictsWithClose`](sakuya_stream_v1::send::finish::RequestResetError::FinalSizeConflictsWithClose);
    /// 3. [`RequestResetError::ProtocolTerminal`](sakuya_stream_v1::send::finish::RequestResetError::ProtocolTerminal);
    /// 4. against an effective reset, [`RequestResetError::Conflict`](sakuya_stream_v1::send::finish::RequestResetError::Conflict) if the
    ///    target type refuses the replacement;
    /// 5. without an effective reset, [`RequestResetError::Unfit`](sakuya_stream_v1::send::finish::RequestResetError::Unfit) if the
    ///    data written so far does not allow the request, or if it cannot end
    ///    the stream at the final size;
    /// 6. while no final size is fixed,
    ///    [`RequestResetError::FinalSizeBelowExposure`](sakuya_stream_v1::send::finish::RequestResetError::FinalSizeBelowExposure), then
    ///    [`RequestResetError::FinalSizeBeyondWrittenEnd`](sakuya_stream_v1::send::finish::RequestResetError::FinalSizeBeyondWrittenEnd).
    pub fn request_reset(
        &mut self,
        request: T::Request,
        final_size: Option<VarInt>,
    ) -> Result<(), RequestResetErrorOf<T, Lc>> {
        let target = match self.plan_reset(request, final_size)? {
            ResetPlan::Unchanged => return Ok(()),
            ResetPlan::Install(target) => target,
            ResetPlan::CompleteFinalSize(bounds) => {
                let context = self.termination_context();
                let chosen = self
                    .composition
                    .complete_final_size(bounds.request(request), &context);
                enforce_policy(check_completed_final_size::<T>(request, bounds, chosen))
            }
        };
        self.commit_reset(target, EndSource::Application);
        self.dispatch_termination(SendTerminationEvent::EndCommitted {
            source: EndSource::Application,
        });
        Ok(())
    }

    /// Validates a reset request against the effective state. An explicit
    /// final size must equal a fixed one.
    fn plan_reset(
        &self,
        request: T::Request,
        final_size: Option<VarInt>,
    ) -> Result<ResetPlan<T>, RequestResetErrorOf<T, Lc>> {
        use request_reset_error as e;
        self.check_connection_open()?;
        match self.end_state() {
            SendEndState::Reset {
                target: effective, ..
            } => {
                if effective.restates(&request)
                    && final_size.is_none_or(|size| size == effective.final_size())
                {
                    return Ok(ResetPlan::Unchanged);
                }
                ResetCodeChangeError::check(
                    effective.error_code(),
                    T::requested_error_code(&request),
                )
                .context(e::ErrorCodeConflictSnafu)?;
                if let Some(requested) = final_size {
                    FinalSizeChangeError::check(effective.final_size(), requested)
                        .context(e::FinalSizeConflictsWithResetSnafu)?;
                }
                ProtocolTerminalError::check(self.terminal_state())
                    .context(e::ProtocolTerminalSnafu)?;
                let target = effective.replace(request).context(e::ConflictSnafu)?;
                debug_assert_eq!(target.error_code(), effective.error_code());
                debug_assert_eq!(target.final_size(), effective.final_size());
                Ok(ResetPlan::Install(target))
            }
            SendEndState::Closed {
                final_size: fixed, ..
            } => {
                if let Some(requested) = final_size {
                    FinalSizeChangeError::check(fixed, requested)
                        .context(e::FinalSizeConflictsWithCloseSnafu)?;
                }
                ProtocolTerminalError::check(self.terminal_state())
                    .context(e::ProtocolTerminalSnafu)?;
                T::minimum_final_size(&request, self.written_end()).context(e::UnfitSnafu)?;
                let target = T::establish(request, fixed).context(e::UnfitSnafu)?;
                Ok(ResetPlan::Install(target))
            }
            SendEndState::Open => {
                let written_end = self.written_end();
                let bounds = FinalSizeBounds {
                    minimum: T::minimum_final_size(&request, written_end).context(e::UnfitSnafu)?,
                    exposure_end: self.exposure_end(),
                    written_end,
                };
                let Some(final_size) = final_size else {
                    return Ok(ResetPlan::CompleteFinalSize(bounds));
                };
                let target = T::establish(request, final_size).context(e::UnfitSnafu)?;
                FinalSizeBelowExposureError::check(final_size, bounds.exposure_end)
                    .context(e::FinalSizeBelowExposureSnafu)?;
                FinalSizeBeyondWrittenEndError::check(final_size, bounds.written_end)
                    .context(e::FinalSizeBeyondWrittenEndSnafu)?;
                Ok(ResetPlan::Install(target))
            }
        }
    }

    fn commit_close(&mut self, source: EndSource) {
        self.set_end(CommittedEnd::Closed {
            final_size: self.written_end(),
            source,
        });
        self.notify_flow_control(StreamCreditEvent::EndCommitted { source });
    }

    /// Installs `target`, which [`plan_reset`](Self::plan_reset) accepted.
    fn commit_reset(&mut self, target: T, source: EndSource) {
        let retention = ResetRetention {
            final_size: target.final_size(),
            reliable_size: target.reliable_size(),
        };
        if let Err(error) = self.composition.apply_reset(retention) {
            // invariant: the target was checked against the send buffer's own
            // written and exposure ends and against the final size the end
            // state fixed, which is the only one the buffer can have been
            // shown, and its reliable size is at most its final size by the
            // `LocalResetTarget` contract. A send buffer that still refuses
            // it breaks the `StreamSendBuffer` contract.
            unreachable!("send buffer refused a checked reset target {target:?}: {error}");
        }
        self.set_end(CommittedEnd::Reset { target, source });
        self.notify_flow_control(StreamCreditEvent::EndCommitted { source });
    }

    /// Replaces the committed end; a terminal state is never replaced, since
    /// a send direction in one takes no new end.
    fn set_end(&mut self, end: CommittedEnd<T>) {
        let terminal = self.terminal_state();
        debug_assert!(terminal.is_none());
        let sent = match &self.end {
            EndPhase::Open => SentEndFrames::none(),
            EndPhase::Ended { sent, .. } => *sent,
        };
        self.end = EndPhase::Ended {
            end,
            sent,
            terminal,
        };
    }

    /// Validates and commits an automatic action, returning the event that
    /// reports it, or `None` if it changes nothing.
    pub(super) fn apply_termination_action(
        &mut self,
        action: TerminationAction<C::WriteLimitReason, T>,
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
        action: TerminationAction<C::WriteLimitReason, T>,
    ) -> Result<PolicyPlan<C::WriteLimitReason, T>, PolicyViolationError<T>> {
        match action {
            TerminationAction::Keep => Ok(PolicyPlan::Keep),
            TerminationAction::Close => match self.end_state() {
                SendEndState::Closed { .. } => Ok(PolicyPlan::Keep),
                SendEndState::Reset { .. } => {
                    Err(StreamResetError).context(policy_violation::CloseAfterResetSnafu)
                }
                SendEndState::Open => {
                    if self.is_connection_closed() {
                        return Err(ConnectionIsClosed)
                            .context(policy_violation::CloseAfterConnectionClosedSnafu);
                    }
                    Ok(PolicyPlan::Close)
                }
            },
            TerminationAction::NarrowWriteLimit {
                write_limit_end,
                reason,
            } => {
                ensure!(
                    !self.is_connection_closed() && self.terminal_state().is_none(),
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
            // A complete target is its request with its final size.
            TerminationAction::Reset(target) => {
                let plan = match self.plan_reset(target.request(), Some(target.final_size())) {
                    Ok(plan) => plan,
                    Err(error) => {
                        return Err(match error.without_closed_connection() {
                            Ok(error) => PolicyViolationError::IllegalReset {
                                target,
                                source: error,
                            },
                            Err(_closed) => PolicyViolationError::ResetAfterConnectionClosed {
                                target,
                                source: ConnectionIsClosed,
                            },
                        });
                    }
                };
                match plan {
                    ResetPlan::Unchanged => Ok(PolicyPlan::Keep),
                    ResetPlan::Install(target) => Ok(PolicyPlan::Reset(target)),
                    ResetPlan::CompleteFinalSize(_) => {
                        // invariant: `plan_reset` leaves the final size open
                        // only for a request that names none.
                        unreachable!("a complete reset target names its final size")
                    }
                }
            }
        }
    }
}

/// Checks the completion entry's `chosen` final size for `request` and
/// `bounds` against the [policy contract](crate::send::termination#contract).
fn check_completed_final_size<T: LocalResetTarget>(
    request: T::Request,
    bounds: FinalSizeBounds,
    chosen: VarInt,
) -> Result<T, PolicyViolationError<T>> {
    let target =
        T::establish(request, chosen).context(policy_violation::ChosenFinalSizeUnfitSnafu)?;
    FinalSizeBelowExposureError::check(chosen, bounds.exposure_end)
        .context(policy_violation::ChosenFinalSizeBelowExposureSnafu)?;
    FinalSizeBeyondWrittenEndError::check(chosen, bounds.written_end)
        .context(policy_violation::ChosenFinalSizeBeyondWrittenEndSnafu)?;
    Ok(target)
}

/// The single place where a termination policy's contract violation ends
/// the operation: every policy result passes through here after its check
/// and before anything changes.
fn enforce_policy<P, T: LocalResetTarget>(checked: Result<P, PolicyViolationError<T>>) -> P {
    match checked {
        Ok(plan) => plan,
        Err(violation) => panic!("{}", Report::from_error(violation)),
    }
}
