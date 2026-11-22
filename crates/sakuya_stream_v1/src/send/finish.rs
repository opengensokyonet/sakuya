//! Failures of ending a stream sender: close and reset.
//!
//! The operations are those of `sakuya_stream_sets::send::StreamSender`:
//! `close`, `request_reset`, and `reset` and `reset_with_final_size`, the
//! requests of [`LocalReset`](super::local_reset::LocalReset). Each failure type here belongs to one of them.
use super::local_reset::LocalResetTarget;
use super::{SendTerminalState, StreamResetError};
use crate::connection::LayerEndedError;
use crate::send_buffer::FinalSizeBeyondWrittenEndError;
use crate::send_buffer::visibility::FinalSizeBelowExposureError;
use crate::stream_end::{FinalSizeChangeError, ResetCodeChangeError};
use core::convert::Infallible;
use core::error::Error;
use snafu::Snafu;

/// Failures of `StreamSender::close`.
///
/// `Lc` is the type of the connection's local close cause.
#[derive(Clone, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(close_error), visibility(pub(crate)))]
pub enum CloseError<Lc> {
    /// The connection has closed.
    #[snafu(transparent)]
    LayerEnded {
        /// The closed connection.
        source: LayerEndedError<Lc>,
    },
    /// A reset is in effect; a close cannot replace it.
    #[snafu(transparent)]
    AlreadyReset {
        /// The reset in effect.
        source: StreamResetError,
    },
}

/// Failures of `StreamSender::request_reset`; none of them changes any
/// state.
///
/// `X` and `U` are the [`Conflict`](LocalResetTarget::Conflict) and the
/// [`Unfit`](LocalResetTarget::Unfit) of the stream's reset target type; `Lc`
/// is the type of the connection's local close cause.
#[derive(Clone, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(request_reset_error), visibility(pub))]
pub enum RequestResetError<X: Error + 'static, U: Error + 'static, Lc> {
    /// The connection has closed.
    #[snafu(transparent)]
    LayerEnded {
        /// The closed connection.
        source: LayerEndedError<Lc>,
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
    /// The request cannot replace the reset target in effect.
    #[snafu(display("the reset cannot replace the effective reset"))]
    Conflict {
        /// Why the target type refuses the replacement.
        source: X,
    },
    /// The request cannot be the first reset of the stream with the data
    /// written so far, or at the requested final size.
    #[snafu(display("the reset cannot end the stream as requested"))]
    Unfit {
        /// Why the target type refuses the request.
        source: U,
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

impl<X: Error + 'static, U: Error + 'static, Lc> RequestResetError<X, U, Lc> {
    /// The same failure without the connection closure, which the failure
    /// of a policy's decision never reports; the closure itself otherwise.
    pub fn without_closed_connection(
        self,
    ) -> Result<RequestResetError<X, U, Infallible>, LayerEndedError<Lc>> {
        use RequestResetError as E;
        Ok(match self {
            E::LayerEnded { source } => return Err(source),
            E::ErrorCodeConflict { source } => E::ErrorCodeConflict { source },
            E::FinalSizeConflictsWithReset { source } => E::FinalSizeConflictsWithReset { source },
            E::FinalSizeConflictsWithClose { source } => E::FinalSizeConflictsWithClose { source },
            E::ProtocolTerminal { source } => E::ProtocolTerminal { source },
            E::Conflict { source } => E::Conflict { source },
            E::Unfit { source } => E::Unfit { source },
            E::FinalSizeBelowExposure { source } => E::FinalSizeBelowExposure { source },
            E::FinalSizeBeyondWrittenEnd { source } => E::FinalSizeBeyondWrittenEnd { source },
        })
    }
}

/// The failure of a request for a target of type `T`.
pub type RequestResetErrorOf<T, Lc> =
    RequestResetError<<T as LocalResetTarget>::Conflict, <T as LocalResetTarget>::Unfit, Lc>;

/// Failures of `StreamSender::reset`; none of them changes any state.
///
/// `Lc` is the type of the connection's local close cause.
#[derive(Clone, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(reset_error), visibility(pub(crate)))]
pub enum ResetError<Lc> {
    /// The connection has closed.
    #[snafu(transparent)]
    LayerEnded {
        /// The closed connection.
        source: LayerEndedError<Lc>,
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

/// Failures of `StreamSender::reset_with_final_size`; none of them
/// changes any state.
///
/// `Lc` is the type of the connection's local close cause.
#[derive(Clone, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(reset_with_final_size_error), visibility(pub(crate)))]
pub enum ResetWithFinalSizeError<Lc> {
    /// The connection has closed.
    #[snafu(transparent)]
    LayerEnded {
        /// The closed connection.
        source: LayerEndedError<Lc>,
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

impl<Lc> ResetError<Lc> {
    /// The failure of a request that names no final size and that the target
    /// type never refuses.
    ///
    /// # Panics
    ///
    /// If `error` is a failure only a request with a final size can meet.
    pub fn from_request_without_final_size(
        error: RequestResetError<Infallible, Infallible, Lc>,
    ) -> Self {
        use RequestResetError as General;
        match error {
            General::LayerEnded { source } => Self::LayerEnded { source },
            General::ErrorCodeConflict { source } => Self::ErrorCodeConflict { source },
            General::ProtocolTerminal { source } => Self::ProtocolTerminal { source },
            General::Conflict { source } | General::Unfit { source } => match source {},
            // invariant: a request without a final size is not compared with
            // a fixed one and leaves the choice to the termination policy.
            General::FinalSizeConflictsWithReset { .. }
            | General::FinalSizeConflictsWithClose { .. }
            | General::FinalSizeBelowExposure { .. }
            | General::FinalSizeBeyondWrittenEnd { .. } => {
                unreachable!("a reset without a final size cannot fail with a final size error")
            }
        }
    }
}

impl<Lc> From<RequestResetError<Infallible, Infallible, Lc>> for ResetWithFinalSizeError<Lc> {
    fn from(error: RequestResetError<Infallible, Infallible, Lc>) -> Self {
        use RequestResetError as General;
        match error {
            General::LayerEnded { source } => Self::LayerEnded { source },
            General::ErrorCodeConflict { source } => Self::ErrorCodeConflict { source },
            General::FinalSizeConflictsWithReset { source } => {
                Self::FinalSizeConflictsWithReset { source }
            }
            General::FinalSizeConflictsWithClose { source } => {
                Self::FinalSizeConflictsWithClose { source }
            }
            General::ProtocolTerminal { source } => Self::ProtocolTerminal { source },
            General::Conflict { source } | General::Unfit { source } => match source {},
            General::FinalSizeBelowExposure { source } => Self::FinalSizeBelowExposure { source },
            General::FinalSizeBeyondWrittenEnd { source } => {
                Self::FinalSizeBeyondWrittenEnd { source }
            }
        }
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
