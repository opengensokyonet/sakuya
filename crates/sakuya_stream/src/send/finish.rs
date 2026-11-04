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
    StreamResetError, StreamSender, WriteLimit,
};
use crate::connection::ConnectionClosedError;
use crate::send::flow_control::{SendFlowControlPolicy, StreamCreditEvent};
use crate::send::termination::{
    FinalSizeRequest, SendTerminationEvent, SendTerminationPolicy, TerminationAction,
};
use crate::send::write::SharedWriteLimitReason;
use crate::send_buffer::visibility::FinalSizeBelowExposureError;
use crate::send_buffer::{FinalSizeBeyondWrittenEndError, ResetRetention, SendBuffer};
use crate::stream_end::{FinalSizeChangeError, ResetCodeChangeError};
use sakuya_wire::application_error::ApplicationErrorCode;
use sakuya_wire::frame::reset_stream_at::ReliableSizeError;
use sakuya_wire::var_int::VarInt;
use snafu::{Report, ResultExt, Snafu, ensure};

/// Failures of [`StreamSender::close`].
#[derive(Clone, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(close_error), visibility(pub(crate)))]
pub enum CloseError {
    /// The connection has closed.
    #[snafu(transparent)]
    ConnectionClosed {
        /// The closed connection.
        source: ConnectionClosedError,
    },
    /// A reset is in effect; a close cannot replace it.
    #[snafu(transparent)]
    AlreadyReset {
        /// The reset in effect.
        source: StreamResetError,
    },
}

/// Failures of [`StreamSender::reset`]; none of them changes any state.
#[derive(Clone, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(reset_error), visibility(pub(crate)))]
pub enum ResetError {
    /// The connection has closed.
    #[snafu(transparent)]
    ConnectionClosed {
        /// The closed connection.
        source: ConnectionClosedError,
    },
    /// The error code differs from the effective reset's.
    #[snafu(display("the reset conflicts with the effective reset"))]
    ErrorCodeConflict {
        /// The effective and the requested error code.
        source: ResetCodeChangeError,
    },
    /// The send direction is in a terminal state and takes no new reset.
    #[snafu(display("the send direction takes no new reset"))]
    ProtocolTerminal {
        /// The terminal state.
        source: ProtocolTerminalError,
    },
}

/// Failures of [`StreamSender::reset_at`]; none of them changes any state.
#[derive(Clone, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(reset_at_error), visibility(pub(crate)))]
pub enum ResetAtError {
    /// The connection has closed.
    #[snafu(transparent)]
    ConnectionClosed {
        /// The closed connection.
        source: ConnectionClosedError,
    },
    /// The error code differs from the effective reset's.
    #[snafu(display("the reset conflicts with the effective reset"))]
    ErrorCodeConflict {
        /// The effective and the requested error code.
        source: ResetCodeChangeError,
    },
    /// The reliable size exceeds the effective reset's.
    #[snafu(display("the reset conflicts with the effective reset"))]
    ReliableSizeIncrease {
        /// The effective and the requested reliable size.
        source: ReliableSizeIncreaseError,
    },
    /// The send direction is in a terminal state and takes no new reset.
    #[snafu(display("the send direction takes no new reset"))]
    ProtocolTerminal {
        /// The terminal state.
        source: ProtocolTerminalError,
    },
    /// A reliable size above zero needs `RESET_STREAM_AT`, which the
    /// handshake did not negotiate.
    #[snafu(display("the reset cannot keep a reliable prefix"))]
    UnsupportedExtension {
        /// The requested reliable size.
        source: ResetStreamAtNotNegotiatedError,
    },
    /// The requested reliable size lies beyond the written end.
    #[snafu(display("the reset cannot keep a reliable prefix"))]
    ReliablePrefixNotPrepared {
        /// The requested reliable size and the written end.
        source: ReliablePrefixNotPreparedError,
    },
}

/// Failures of [`StreamSender::reset_with_final_size`]; none of them
/// changes any state.
#[derive(Clone, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(reset_with_final_size_error), visibility(pub(crate)))]
pub enum ResetWithFinalSizeError {
    /// The connection has closed.
    #[snafu(transparent)]
    ConnectionClosed {
        /// The closed connection.
        source: ConnectionClosedError,
    },
    /// The error code differs from the effective reset's.
    #[snafu(display("the reset conflicts with the effective reset"))]
    ErrorCodeConflict {
        /// The effective and the requested error code.
        source: ResetCodeChangeError,
    },
    /// The final size differs from the one the effective reset fixed.
    #[snafu(display("the reset conflicts with the effective reset"))]
    FinalSizeConflictsWithReset {
        /// The fixed and the requested final size.
        source: FinalSizeChangeError,
    },
    /// The final size differs from the one the effective close fixed.
    #[snafu(display("the reset conflicts with the effective close"))]
    FinalSizeConflictsWithClose {
        /// The fixed and the requested final size.
        source: FinalSizeChangeError,
    },
    /// The send direction is in a terminal state and takes no new reset.
    #[snafu(display("the send direction takes no new reset"))]
    ProtocolTerminal {
        /// The terminal state.
        source: ProtocolTerminalError,
    },
    /// The requested final size lies below the exposure end.
    #[snafu(display("the reset cannot end at this final size"))]
    FinalSizeBelowExposure {
        /// The requested final size and the exposure end.
        source: FinalSizeBelowExposureError,
    },
    /// The requested final size lies beyond the written end.
    #[snafu(display("the reset cannot end at this final size"))]
    FinalSizeBeyondWrittenEnd {
        /// The requested final size and the written end.
        source: FinalSizeBeyondWrittenEndError,
    },
}

/// Failures of [`StreamSender::reset_at_with_final_size`]; none of them
/// changes any state.
///
/// Every failure of a reset request is one of these; the other reset
/// operations fail with the variants their requests can reach.
#[derive(Clone, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(reset_at_with_final_size_error), visibility(pub(crate)))]
pub enum ResetAtWithFinalSizeError {
    /// The connection has closed.
    #[snafu(transparent)]
    ConnectionClosed {
        /// The closed connection.
        source: ConnectionClosedError,
    },
    /// The error code differs from the effective reset's.
    #[snafu(display("the reset conflicts with the effective reset"))]
    ErrorCodeConflict {
        /// The effective and the requested error code.
        source: ResetCodeChangeError,
    },
    /// The final size differs from the one the effective reset fixed.
    #[snafu(display("the reset conflicts with the effective reset"))]
    FinalSizeConflictsWithReset {
        /// The fixed and the requested final size.
        source: FinalSizeChangeError,
    },
    /// The reliable size exceeds the effective reset's.
    #[snafu(display("the reset conflicts with the effective reset"))]
    ReliableSizeIncrease {
        /// The effective and the requested reliable size.
        source: ReliableSizeIncreaseError,
    },
    /// The final size differs from the one the effective close fixed.
    #[snafu(display("the reset conflicts with the effective close"))]
    FinalSizeConflictsWithClose {
        /// The fixed and the requested final size.
        source: FinalSizeChangeError,
    },
    /// The send direction is in a terminal state and takes no new reset.
    #[snafu(display("the send direction takes no new reset"))]
    ProtocolTerminal {
        /// The terminal state.
        source: ProtocolTerminalError,
    },
    /// A reliable size above zero needs `RESET_STREAM_AT`, which the
    /// handshake did not negotiate.
    #[snafu(display("the reset cannot keep a reliable prefix"))]
    UnsupportedExtension {
        /// The requested reliable size.
        source: ResetStreamAtNotNegotiatedError,
    },
    /// The requested reliable size lies beyond the written end.
    #[snafu(display("the reset cannot keep a reliable prefix"))]
    ReliablePrefixNotPrepared {
        /// The requested reliable size and the written end.
        source: ReliablePrefixNotPreparedError,
    },
    /// The requested final size lies below the requested reliable size.
    #[snafu(display("the reset cannot end at this final size"))]
    FinalSizeBelowReliableSize {
        /// The requested final size and reliable size.
        source: ReliableSizeError,
    },
    /// The requested final size lies below the exposure end.
    #[snafu(display("the reset cannot end at this final size"))]
    FinalSizeBelowExposure {
        /// The requested final size and the exposure end.
        source: FinalSizeBelowExposureError,
    },
    /// The requested final size lies beyond the written end.
    #[snafu(display("the reset cannot end at this final size"))]
    FinalSizeBeyondWrittenEnd {
        /// The requested final size and the written end.
        source: FinalSizeBeyondWrittenEndError,
    },
}

impl ResetError {
    /// The failure of a request with reliable size zero and no final size.
    fn narrow(error: ResetAtWithFinalSizeError) -> Self {
        use ResetAtWithFinalSizeError as General;
        match error {
            General::ConnectionClosed { source } => Self::ConnectionClosed { source },
            General::ErrorCodeConflict { source } => Self::ErrorCodeConflict { source },
            General::ProtocolTerminal { source } => Self::ProtocolTerminal { source },
            // invariant: a reliable size of zero never exceeds an effective
            // one, needs no extension, is always written and never exceeds a
            // final size; a request without a final size is not compared with
            // a fixed one and leaves the choice to the termination policy.
            General::FinalSizeConflictsWithReset { .. }
            | General::ReliableSizeIncrease { .. }
            | General::FinalSizeConflictsWithClose { .. }
            | General::UnsupportedExtension { .. }
            | General::ReliablePrefixNotPrepared { .. }
            | General::FinalSizeBelowReliableSize { .. }
            | General::FinalSizeBelowExposure { .. }
            | General::FinalSizeBeyondWrittenEnd { .. } => {
                unreachable!("a plain reset cannot fail with {error:?}")
            }
        }
    }
}

impl ResetAtError {
    /// The failure of a request without a final size.
    fn narrow(error: ResetAtWithFinalSizeError) -> Self {
        use ResetAtWithFinalSizeError as General;
        match error {
            General::ConnectionClosed { source } => Self::ConnectionClosed { source },
            General::ErrorCodeConflict { source } => Self::ErrorCodeConflict { source },
            General::ReliableSizeIncrease { source } => Self::ReliableSizeIncrease { source },
            General::ProtocolTerminal { source } => Self::ProtocolTerminal { source },
            General::UnsupportedExtension { source } => Self::UnsupportedExtension { source },
            General::ReliablePrefixNotPrepared { source } => {
                Self::ReliablePrefixNotPrepared { source }
            }
            // invariant: a request without a final size is not compared with
            // a fixed one and leaves the choice to the termination policy.
            General::FinalSizeConflictsWithReset { .. }
            | General::FinalSizeConflictsWithClose { .. }
            | General::FinalSizeBelowReliableSize { .. }
            | General::FinalSizeBelowExposure { .. }
            | General::FinalSizeBeyondWrittenEnd { .. } => {
                unreachable!("a reset without a final size cannot fail with {error:?}")
            }
        }
    }
}

impl ResetWithFinalSizeError {
    /// The failure of a request with reliable size zero.
    fn narrow(error: ResetAtWithFinalSizeError) -> Self {
        use ResetAtWithFinalSizeError as General;
        match error {
            General::ConnectionClosed { source } => Self::ConnectionClosed { source },
            General::ErrorCodeConflict { source } => Self::ErrorCodeConflict { source },
            General::FinalSizeConflictsWithReset { source } => {
                Self::FinalSizeConflictsWithReset { source }
            }
            General::FinalSizeConflictsWithClose { source } => {
                Self::FinalSizeConflictsWithClose { source }
            }
            General::ProtocolTerminal { source } => Self::ProtocolTerminal { source },
            General::FinalSizeBelowExposure { source } => Self::FinalSizeBelowExposure { source },
            General::FinalSizeBeyondWrittenEnd { source } => {
                Self::FinalSizeBeyondWrittenEnd { source }
            }
            // invariant: a reliable size of zero never exceeds an effective
            // one, needs no extension, is always written and never exceeds a
            // final size.
            General::ReliableSizeIncrease { .. }
            | General::UnsupportedExtension { .. }
            | General::ReliablePrefixNotPrepared { .. }
            | General::FinalSizeBelowReliableSize { .. } => {
                unreachable!("a reset without a reliable prefix cannot fail with {error:?}")
            }
        }
    }
}

/// A reset raises the reliable size of the effective reset: data it allowed
/// to abandon cannot be promised again.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("reliable size {requested} exceeds the effective reliable size {effective}"))]
pub struct ReliableSizeIncreaseError {
    effective: VarInt,
    requested: VarInt,
}

impl ReliableSizeIncreaseError {
    /// Checks that `requested` does not exceed the `effective` reliable
    /// size.
    ///
    /// # Errors
    ///
    /// [`ReliableSizeIncreaseError`] if `requested` exceeds `effective`.
    pub fn check(effective: VarInt, requested: VarInt) -> Result<(), Self> {
        ensure!(
            requested <= effective,
            ReliableSizeIncreaseSnafu {
                effective,
                requested,
            }
        );
        Ok(())
    }

    /// The reliable size of the effective reset.
    pub const fn effective(self) -> VarInt {
        self.effective
    }

    /// The requested reliable size, which exceeds
    /// [`effective`](Self::effective).
    pub const fn requested(self) -> VarInt {
        self.requested
    }
}

/// The send direction is in a terminal state, which no reset changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("the send direction is in the terminal state {state:?}"))]
pub struct ProtocolTerminalError {
    state: SendTerminalState,
}

impl ProtocolTerminalError {
    /// Checks that the send direction has not reached a terminal state;
    /// `terminal_state` is the one it reached, if any.
    ///
    /// # Errors
    ///
    /// [`ProtocolTerminalError`] if `terminal_state` is a state.
    pub fn check(terminal_state: Option<SendTerminalState>) -> Result<(), Self> {
        match terminal_state {
            Some(state) => ProtocolTerminalSnafu { state }.fail(),
            None => Ok(()),
        }
    }

    /// The terminal state.
    pub const fn state(self) -> SendTerminalState {
        self.state
    }
}

/// A reset keeps a reliable size above zero, which needs the
/// `RESET_STREAM_AT` extension, and the handshake did not negotiate it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("reliable size {reliable_size} needs the RESET_STREAM_AT extension"))]
pub struct ResetStreamAtNotNegotiatedError {
    reliable_size: VarInt,
}

impl ResetStreamAtNotNegotiatedError {
    /// Checks that a reset with `reliable_size` can be sent;
    /// `reset_stream_at_supported` tells whether the handshake negotiated
    /// `RESET_STREAM_AT`.
    ///
    /// # Errors
    ///
    /// [`ResetStreamAtNotNegotiatedError`] if `reliable_size` is above zero
    /// and the extension was not negotiated.
    pub fn check(reliable_size: VarInt, reset_stream_at_supported: bool) -> Result<(), Self> {
        ensure!(
            reliable_size == VarInt::ZERO || reset_stream_at_supported,
            ResetStreamAtNotNegotiatedSnafu { reliable_size }
        );
        Ok(())
    }

    /// The requested reliable size, above zero.
    pub const fn reliable_size(self) -> VarInt {
        self.reliable_size
    }
}

/// A reset keeps a reliable size beyond the written end: the prefix it names
/// has not been handed over.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("reliable size {reliable_size} lies beyond the written end {written_end}"))]
pub struct ReliablePrefixNotPreparedError {
    reliable_size: VarInt,
    written_end: VarInt,
}

impl ReliablePrefixNotPreparedError {
    /// Checks that `reliable_size` is at most `written_end`.
    ///
    /// # Errors
    ///
    /// [`ReliablePrefixNotPreparedError`] if `reliable_size` lies beyond
    /// `written_end`.
    pub fn check(reliable_size: VarInt, written_end: VarInt) -> Result<(), Self> {
        ensure!(
            reliable_size <= written_end,
            ReliablePrefixNotPreparedSnafu {
                reliable_size,
                written_end,
            }
        );
        Ok(())
    }

    /// The requested reliable size, beyond
    /// [`written_end`](Self::written_end).
    pub const fn reliable_size(self) -> VarInt {
        self.reliable_size
    }

    /// The written end.
    pub const fn written_end(self) -> VarInt {
        self.written_end
    }
}

/// What a reset request leads to once checked against the effective state.
enum ResetCheck {
    /// The request equals the effective target.
    Unchanged,
    /// The final size is already fixed at this value.
    FinalSizeFixed(VarInt),
    /// No final size is fixed; a new one must satisfy these bounds.
    FinalSizeOpen(FinalSizeBounds),
}

/// The values that bound a new final size: it is at least the reliable size
/// and the exposure end and at most the written end.
#[derive(Clone, Copy)]
struct FinalSizeBounds {
    reliable_size: VarInt,
    exposure_end: VarInt,
    written_end: VarInt,
}

impl FinalSizeBounds {
    /// The question for the termination policy's completion entry.
    fn request(self, error_code: ApplicationErrorCode) -> FinalSizeRequest {
        FinalSizeRequest {
            error_code,
            reliable_size: self.reliable_size,
            minimum: self.exposure_end.max(self.reliable_size),
            maximum: self.written_end,
        }
    }

    /// Checks an explicit final size, reporting a failure below the reliable
    /// size, then below the exposure end, then beyond the written end.
    fn check(self, final_size: VarInt) -> Result<(), ResetAtWithFinalSizeError> {
        use reset_at_with_final_size_error as e;
        ReliableSizeError::check(final_size, self.reliable_size)
            .context(e::FinalSizeBelowReliableSizeSnafu)?;
        FinalSizeBelowExposureError::check(final_size, self.exposure_end)
            .context(e::FinalSizeBelowExposureSnafu)?;
        FinalSizeBeyondWrittenEndError::check(final_size, self.written_end)
            .context(e::FinalSizeBeyondWrittenEndSnafu)
    }
}

/// What a valid application reset request leads to.
enum ResetPlan {
    /// The request equals the effective target.
    Unchanged,
    /// A new target to install.
    Install(ResetTarget),
    /// A new target whose final size the termination policy chooses.
    CompleteFinalSize {
        error_code: ApplicationErrorCode,
        bounds: FinalSizeBounds,
    },
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
enum PolicyViolationError {
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
        source: ResetAtWithFinalSizeError,
    },
    #[snafu(display("termination policy chose a final size below the reliable size"))]
    ChosenFinalSizeBelowReliableSize { source: ReliableSizeError },
    #[snafu(display("termination policy chose a final size below the exposure end"))]
    ChosenFinalSizeBelowExposure { source: FinalSizeBelowExposureError },
    #[snafu(display("termination policy chose a final size beyond the written end"))]
    ChosenFinalSizeBeyondWrittenEnd {
        source: FinalSizeBeyondWrittenEndError,
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

    /// Resets the stream with `error_code` and reliable size zero
    /// (`RESET_STREAM`).
    ///
    /// While no final size is fixed, the termination policy chooses it.
    ///
    /// # Errors
    ///
    /// Checked in this order, after which the request succeeds without effect
    /// if it equals the effective reset:
    ///
    /// 1. [`ResetError::ConnectionClosed`];
    /// 2. [`ResetError::ErrorCodeConflict`] against an effective reset;
    /// 3. [`ResetError::ProtocolTerminal`].
    pub fn reset(&mut self, error_code: ApplicationErrorCode) -> Result<(), ResetError> {
        self.request_reset(error_code, VarInt::ZERO, None)
            .map_err(ResetError::narrow)
    }

    /// Resets the stream with `error_code`, keeping the reliable delivery of
    /// the first `reliable_size` bytes (`RESET_STREAM_AT`).
    ///
    /// The prefix must already be written; the operation takes no input.
    /// While no final size is fixed, the termination policy chooses it.
    ///
    /// # Errors
    ///
    /// Checked in this order, after which the request succeeds without effect
    /// if it equals the effective reset:
    ///
    /// 1. [`ResetAtError::ConnectionClosed`];
    /// 2. against an effective reset, [`ResetAtError::ErrorCodeConflict`],
    ///    then [`ResetAtError::ReliableSizeIncrease`];
    /// 3. [`ResetAtError::ProtocolTerminal`];
    /// 4. [`ResetAtError::UnsupportedExtension`] for a reliable size above
    ///    zero without `RESET_STREAM_AT`;
    /// 5. [`ResetAtError::ReliablePrefixNotPrepared`] for a reliable size
    ///    beyond the written end.
    pub fn reset_at(
        &mut self,
        error_code: ApplicationErrorCode,
        reliable_size: VarInt,
    ) -> Result<(), ResetAtError> {
        self.request_reset(error_code, reliable_size, None)
            .map_err(ResetAtError::narrow)
    }

    /// Resets the stream with `error_code` and the explicit `final_size`.
    ///
    /// This signature is provisional.
    ///
    /// # Errors
    ///
    /// Checked in this order, after which the request succeeds without effect
    /// if it equals the effective reset:
    ///
    /// 1. [`ResetWithFinalSizeError::ConnectionClosed`];
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
    ) -> Result<(), ResetWithFinalSizeError> {
        self.request_reset(error_code, VarInt::ZERO, Some(final_size))
            .map_err(ResetWithFinalSizeError::narrow)
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
    /// 1. [`ResetAtWithFinalSizeError::ConnectionClosed`];
    /// 2. against an effective reset,
    ///    [`ResetAtWithFinalSizeError::ErrorCodeConflict`],
    ///    [`ResetAtWithFinalSizeError::FinalSizeConflictsWithReset`], then
    ///    [`ResetAtWithFinalSizeError::ReliableSizeIncrease`]; against an
    ///    effective close,
    ///    [`ResetAtWithFinalSizeError::FinalSizeConflictsWithClose`];
    /// 3. [`ResetAtWithFinalSizeError::ProtocolTerminal`];
    /// 4. [`ResetAtWithFinalSizeError::UnsupportedExtension`] for a reliable
    ///    size above zero without `RESET_STREAM_AT`;
    /// 5. [`ResetAtWithFinalSizeError::ReliablePrefixNotPrepared`] for a
    ///    reliable size beyond the written end;
    /// 6. while no final size is fixed,
    ///    [`ResetAtWithFinalSizeError::FinalSizeBelowReliableSize`],
    ///    [`ResetAtWithFinalSizeError::FinalSizeBelowExposure`], then
    ///    [`ResetAtWithFinalSizeError::FinalSizeBeyondWrittenEnd`].
    pub fn reset_at_with_final_size(
        &mut self,
        error_code: ApplicationErrorCode,
        reliable_size: VarInt,
        final_size: VarInt,
    ) -> Result<(), ResetAtWithFinalSizeError> {
        self.request_reset(error_code, reliable_size, Some(final_size))
    }

    fn request_reset(
        &mut self,
        error_code: ApplicationErrorCode,
        reliable_size: VarInt,
        final_size: Option<VarInt>,
    ) -> Result<(), ResetAtWithFinalSizeError> {
        let target = match self.plan_reset(error_code, reliable_size, final_size)? {
            ResetPlan::Unchanged => return Ok(()),
            ResetPlan::Install(target) => target,
            ResetPlan::CompleteFinalSize { error_code, bounds } => {
                let context = self.termination_context();
                let chosen = self
                    .composition
                    .complete_final_size(bounds.request(error_code), &context);
                enforce_policy(check_completed_final_size(error_code, bounds, chosen))
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
    ) -> Result<ResetPlan, ResetAtWithFinalSizeError> {
        let target = |final_size| ResetTarget {
            error_code,
            reliable_size,
            final_size,
        };
        match self.check_reset(error_code, reliable_size, final_size)? {
            ResetCheck::Unchanged => Ok(ResetPlan::Unchanged),
            ResetCheck::FinalSizeFixed(fixed) => Ok(ResetPlan::Install(target(fixed))),
            ResetCheck::FinalSizeOpen(bounds) => match final_size {
                Some(final_size) => {
                    bounds.check(final_size)?;
                    Ok(ResetPlan::Install(target(final_size)))
                }
                None => Ok(ResetPlan::CompleteFinalSize { error_code, bounds }),
            },
        }
    }

    /// Validates a complete reset target against the effective state;
    /// `None` means it equals the effective target.
    fn plan_complete_reset(
        &self,
        target: ResetTarget,
    ) -> Result<Option<ResetTarget>, ResetAtWithFinalSizeError> {
        match self.check_reset(
            target.error_code,
            target.reliable_size,
            Some(target.final_size),
        )? {
            ResetCheck::Unchanged => Ok(None),
            ResetCheck::FinalSizeFixed(_) => Ok(Some(target)),
            ResetCheck::FinalSizeOpen(bounds) => {
                bounds.check(target.final_size)?;
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
    ) -> Result<ResetCheck, ResetAtWithFinalSizeError> {
        use reset_at_with_final_size_error as e;
        self.check_connection_open()?;
        let end_state = self.end_state();
        match end_state {
            SendEndState::Reset { target, .. } => {
                if target.error_code == error_code
                    && target.reliable_size == reliable_size
                    && final_size.is_none_or(|size| size == target.final_size)
                {
                    return Ok(ResetCheck::Unchanged);
                }
                ResetCodeChangeError::check(target.error_code, error_code)
                    .context(e::ErrorCodeConflictSnafu)?;
                if let Some(requested) = final_size {
                    FinalSizeChangeError::check(target.final_size, requested)
                        .context(e::FinalSizeConflictsWithResetSnafu)?;
                }
                ReliableSizeIncreaseError::check(target.reliable_size, reliable_size)
                    .context(e::ReliableSizeIncreaseSnafu)?;
            }
            SendEndState::Closed {
                final_size: fixed, ..
            } => {
                if let Some(requested) = final_size {
                    FinalSizeChangeError::check(fixed, requested)
                        .context(e::FinalSizeConflictsWithCloseSnafu)?;
                }
            }
            SendEndState::Open => {}
        }
        ProtocolTerminalError::check(self.terminal_state()).context(e::ProtocolTerminalSnafu)?;
        ResetStreamAtNotNegotiatedError::check(reliable_size, self.reset_stream_at_supported)
            .context(e::UnsupportedExtensionSnafu)?;
        let written_end = self.written_end();
        ReliablePrefixNotPreparedError::check(reliable_size, written_end)
            .context(e::ReliablePrefixNotPreparedSnafu)?;
        Ok(match end_state.final_size() {
            Some(fixed) => ResetCheck::FinalSizeFixed(fixed),
            None => ResetCheck::FinalSizeOpen(FinalSizeBounds {
                reliable_size,
                exposure_end: self.exposure_end(),
                written_end,
            }),
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
    ) -> Result<PolicyPlan<C::WriteLimitReason>, PolicyViolationError> {
        match action {
            TerminationAction::Keep => Ok(PolicyPlan::Keep),
            TerminationAction::Close => match self.end_state() {
                SendEndState::Closed { .. } => Ok(PolicyPlan::Keep),
                SendEndState::Reset { .. } => policy_violation::CloseAfterResetSnafu.fail(),
                SendEndState::Open => {
                    ensure!(
                        !self.is_connection_closed(),
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
            TerminationAction::Reset(target) => Ok(self
                .plan_complete_reset(target)
                .context(policy_violation::IllegalResetSnafu { target })?
                .map_or(PolicyPlan::Keep, PolicyPlan::Reset)),
        }
    }
}

/// Checks the completion entry's `chosen` final size for a reset with
/// `error_code` and `bounds` against the
/// [policy contract](crate::send::termination#contract).
fn check_completed_final_size(
    error_code: ApplicationErrorCode,
    bounds: FinalSizeBounds,
    chosen: VarInt,
) -> Result<ResetTarget, PolicyViolationError> {
    ReliableSizeError::check(chosen, bounds.reliable_size)
        .context(policy_violation::ChosenFinalSizeBelowReliableSizeSnafu)?;
    FinalSizeBelowExposureError::check(chosen, bounds.exposure_end)
        .context(policy_violation::ChosenFinalSizeBelowExposureSnafu)?;
    FinalSizeBeyondWrittenEndError::check(chosen, bounds.written_end)
        .context(policy_violation::ChosenFinalSizeBeyondWrittenEndSnafu)?;
    Ok(ResetTarget {
        error_code,
        reliable_size: bounds.reliable_size,
        final_size: chosen,
    })
}

/// The single place where a termination policy's contract violation ends
/// the operation: every policy result passes through here after its check
/// and before anything changes.
fn enforce_policy<T>(checked: Result<T, PolicyViolationError>) -> T {
    match checked {
        Ok(plan) => plan,
        Err(violation) => panic!("{}", Report::from_error(violation)),
    }
}
