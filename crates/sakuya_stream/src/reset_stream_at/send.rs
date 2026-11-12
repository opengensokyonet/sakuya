//! The reliable stream reset extension for the send direction of a stream.
//!
//! With the extension this endpoint can reset a stream and still deliver a
//! prefix of it reliably. This module adds that to the stream sender without
//! changing the sender of RFC 9000:
//!
//! - [`LocalResetAt`] is the type of reset target that is either a reset
//!   with `RESET_STREAM` or one with `RESET_STREAM_AT` and a reliable size
//!   ([`ResetTarget`]). A [`StreamSender`] of these targets,
//!   `StreamSender<C, K, Lc, LocalResetAt>`, resets with
//!   [`reset`](StreamSender::reset) and
//!   [`reset_at`](StreamSender::reset_at).
//! - A `reset_at` in effect may lower its reliable size, and `reset` may
//!   replace it, sending `RESET_STREAM` from then on; the reliable size
//!   never grows, and `reset_at` cannot follow a `reset` (§5.2).
//! - A stream ended by `RESET_STREAM_AT` reaches "Data Recvd" once the frame
//!   with the smallest reliable size and all data up to that size are
//!   acknowledged (§5.3), so that state does not imply that all data
//!   arrived. Once a `RESET_STREAM` replaced it, the stream reaches "Reset
//!   Recvd" instead.
//!
//! An endpoint must not send `RESET_STREAM_AT` unless the peer advertised
//! the `reset_stream_at` transport parameter (§3). A reset with a reliable
//! size is therefore requested and decided only with a
//! [`PeerResetStreamAtSupport`], which exists only for a peer that did; the
//! sender has no setting for it.
use crate::connection::ConnectionClosedError;
use crate::connection_send_credit::ConnectionSendFlowController;
use crate::send::finish::{
    ProtocolTerminalError, RequestResetError, ResetError, ResetWithFinalSizeError,
};
use crate::send::flow_control::SendFlowControlPolicy;
use crate::send::local_reset::{LocalReset, LocalResetTarget};
use crate::send::termination::{
    FinalSizeRequest, ResetOnAbandonTermination, SendTerminationContext, SendTerminationEvent,
    SendTerminationPolicy, TerminationAction,
};
use crate::send::{SendEndState, SendTerminalState, StreamSender};
use crate::send_buffer::visibility::FinalSizeBelowExposureError;
use crate::send_buffer::{FinalSizeBeyondWrittenEndError, StreamSendBuffer};
use crate::stream_end::{FinalSizeChangeError, ResetCodeChangeError};
use core::convert::Infallible;
use sakuya_wire::reset_stream_at::{ReliableSizeError, ResetStreamAt, ResetStreamAtFrame};
use sakuya_wire::v1::application_error::ApplicationErrorCode;
use sakuya_wire::v1::frame::reset_stream::ResetStreamFrame;
use sakuya_wire::v1::stream_id::StreamId;
use sakuya_wire::var_int::{VarInt, VarIntField};
use snafu::{ResultExt, Snafu, ensure};

/// The peer advertised that it supports receiving `RESET_STREAM_AT` frames.
///
/// A value is made only from the `reset_stream_at` transport parameter of
/// the peer, and every reset with a reliable size takes one: without it no
/// [`ResetTarget`] and no request for one can be built, so a stream sender
/// never has a `RESET_STREAM_AT` to send to a peer that did not advertise
/// the extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PeerResetStreamAtSupport(());

impl PeerResetStreamAtSupport {
    /// The support the peer stated with its `reset_stream_at` transport
    /// parameter; with 0-RTT, the one remembered from the connection the
    /// ticket came from.
    pub const fn from_peer_parameter(_parameter: ResetStreamAt) -> Self {
        Self(())
    }
}

/// A complete target of a reset at a reliable size (`reset_at`): error code,
/// reliable size and final size. The reliable size is at most the final
/// size.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ResetTarget {
    error_code: ApplicationErrorCode,
    reliable_size: VarInt,
    final_size: VarInt,
}

impl ResetTarget {
    /// The target with these fields, for a peer of the given `support`.
    ///
    /// # Errors
    ///
    /// [`ReliableSizeError`] if `reliable_size` exceeds `final_size`.
    pub fn new(
        _support: PeerResetStreamAtSupport,
        error_code: ApplicationErrorCode,
        reliable_size: VarInt,
        final_size: VarInt,
    ) -> Result<Self, ReliableSizeError> {
        ReliableSizeError::check(final_size, reliable_size)?;
        Ok(Self {
            error_code,
            reliable_size,
            final_size,
        })
    }

    /// The application error code.
    pub const fn error_code(&self) -> ApplicationErrorCode {
        self.error_code
    }

    /// The reliable size (`reliable_size`): the prefix that must still be
    /// delivered.
    pub const fn reliable_size(&self) -> VarInt {
        self.reliable_size
    }

    /// The final size.
    pub const fn final_size(&self) -> VarInt {
        self.final_size
    }

    /// This target with its reliable size lowered to `reliable_size`.
    ///
    /// # Errors
    ///
    /// [`ReliableSizeIncreaseError`] if `reliable_size` exceeds the reliable
    /// size of this target.
    pub fn lowered_to(self, reliable_size: VarInt) -> Result<Self, ReliableSizeIncreaseError> {
        ReliableSizeIncreaseError::check(self.reliable_size, reliable_size)?;
        Ok(Self {
            reliable_size,
            ..self
        })
    }

    /// This target with a reliable size of zero: the stream still ends with
    /// `RESET_STREAM_AT`, and delivers no more data.
    pub const fn without_reliable_prefix(self) -> Self {
        Self {
            reliable_size: VarInt::ZERO,
            ..self
        }
    }
}

/// The reset target of a stream that can end with `RESET_STREAM_AT` as well
/// as with `RESET_STREAM`.
///
/// Which of the two it is follows the call that committed it: the kind is
/// part of the target, also for a reliable size of zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LocalResetAt {
    /// A reset committed with `reset`: `RESET_STREAM` announces it, it
    /// abandons all data, and its acknowledgement leads to "Reset Recvd". It
    /// may have replaced a [`ResetAt`](Self::ResetAt).
    Reset(LocalReset),
    /// A reset committed with `reset_at`: `RESET_STREAM_AT` announces it, and
    /// its acknowledgement, with that of the data below the reliable size,
    /// leads to "Data Recvd".
    ResetAt(ResetTarget),
}

/// A reset request of a stream whose reset target is a [`LocalResetAt`]:
/// what `reset` or `reset_at` asks for, without the final size.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LocalResetAtRequest {
    kind: ResetKind,
    error_code: ApplicationErrorCode,
    /// Zero for `ResetKind::ResetStream`.
    reliable_size: VarInt,
}

/// Which reset frame a request asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ResetKind {
    ResetStream,
    ResetStreamAt,
}

impl LocalResetAtRequest {
    /// The request of `reset`: end with `RESET_STREAM`.
    pub const fn reset(error_code: ApplicationErrorCode) -> Self {
        Self {
            kind: ResetKind::ResetStream,
            error_code,
            reliable_size: VarInt::ZERO,
        }
    }

    /// The request of `reset_at`: end with `RESET_STREAM_AT` and keep the
    /// reliable delivery of the first `reliable_size` bytes, for a peer of
    /// the given `support`.
    pub const fn reset_at(
        _support: PeerResetStreamAtSupport,
        error_code: ApplicationErrorCode,
        reliable_size: VarInt,
    ) -> Self {
        Self {
            kind: ResetKind::ResetStreamAt,
            error_code,
            reliable_size,
        }
    }

    /// The requested application error code.
    pub const fn error_code(&self) -> ApplicationErrorCode {
        self.error_code
    }

    /// The requested reliable size; zero for the request of `reset`.
    pub const fn reliable_size(&self) -> VarInt {
        self.reliable_size
    }

    /// Whether this is the request of `reset_at`.
    pub const fn is_reset_at(&self) -> bool {
        matches!(self.kind, ResetKind::ResetStreamAt)
    }
}

/// The reset frame that announces a [`LocalResetAt`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LocalResetAtFrame {
    /// A `RESET_STREAM` frame.
    ResetStream(ResetStreamFrame),
    /// A `RESET_STREAM_AT` frame.
    ResetStreamAt(ResetStreamAtFrame),
}

/// Why a request cannot replace the [`LocalResetAt`] in effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(conflict_error))]
pub enum LocalResetAtConflictError {
    /// The reliable size exceeds the effective reset's.
    #[snafu(display("the reset conflicts with the effective reset"))]
    ReliableSizeIncrease {
        /// The effective and the requested reliable size.
        source: ReliableSizeIncreaseError,
    },
    /// The effective end is a `reset`, which `reset_at` cannot follow.
    #[snafu(display("the reset cannot follow a plain reset"))]
    PlainResetEffective {
        /// The plain reset in effect.
        source: PlainResetEffectiveError,
    },
}

/// Why a request cannot become the first [`LocalResetAt`] of a stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(unfit_error))]
pub enum LocalResetAtUnfitError {
    /// The requested reliable size lies beyond the written end.
    #[snafu(display("the reset cannot keep a reliable prefix"))]
    ReliablePrefixNotPrepared {
        /// The requested reliable size and the written end.
        source: ReliablePrefixNotPreparedError,
    },
    /// The final size lies below the requested reliable size.
    #[snafu(display("the reset cannot end at this final size"))]
    FinalSizeBelowReliableSize {
        /// The final size and the requested reliable size.
        source: ReliableSizeError,
    },
}

impl LocalResetTarget for LocalResetAt {
    type Request = LocalResetAtRequest;
    type Frame = LocalResetAtFrame;
    type Conflict = LocalResetAtConflictError;
    type Unfit = LocalResetAtUnfitError;

    fn error_code(&self) -> ApplicationErrorCode {
        match self {
            Self::Reset(reset) => reset.error_code,
            Self::ResetAt(target) => target.error_code,
        }
    }

    fn final_size(&self) -> VarInt {
        match self {
            Self::Reset(reset) => reset.final_size,
            Self::ResetAt(target) => target.final_size,
        }
    }

    fn reliable_size(&self) -> VarInt {
        match self {
            Self::Reset(_) => VarInt::ZERO,
            Self::ResetAt(target) => target.reliable_size,
        }
    }

    fn frame(&self, stream_id: StreamId) -> LocalResetAtFrame {
        match self {
            Self::Reset(reset) => LocalResetAtFrame::ResetStream(reset.frame(stream_id)),
            Self::ResetAt(target) => {
                match ResetStreamAtFrame::new(
                    VarIntField::shortest(stream_id),
                    VarIntField::shortest(target.error_code),
                    VarIntField::shortest(target.final_size),
                    VarIntField::shortest(target.reliable_size),
                ) {
                    Ok(frame) => LocalResetAtFrame::ResetStreamAt(frame),
                    // invariant: a `ResetTarget` keeps its reliable size
                    // within its final size.
                    Err(error) => unreachable!("reset target {target:?}: {error}"),
                }
            }
        }
    }

    fn acknowledged_state(&self) -> SendTerminalState {
        match self {
            Self::Reset(_) => SendTerminalState::ResetRecvd,
            Self::ResetAt(_) => SendTerminalState::DataRecvd,
        }
    }

    fn request(&self) -> LocalResetAtRequest {
        LocalResetAtRequest {
            kind: match self {
                Self::Reset(_) => ResetKind::ResetStream,
                Self::ResetAt(_) => ResetKind::ResetStreamAt,
            },
            error_code: self.error_code(),
            reliable_size: self.reliable_size(),
        }
    }

    fn requested_error_code(request: &LocalResetAtRequest) -> ApplicationErrorCode {
        request.error_code
    }

    fn restates(&self, request: &LocalResetAtRequest) -> bool {
        self.request() == *request
    }

    /// A request may lower the reliable size, and the request of `reset`
    /// replaces a `reset_at` in effect.
    ///
    /// # Errors
    ///
    /// [`LocalResetAtConflictError::ReliableSizeIncrease`], then
    /// [`LocalResetAtConflictError::PlainResetEffective`] for the request of
    /// `reset_at` after a `reset` in effect.
    fn replace(self, request: LocalResetAtRequest) -> Result<Self, LocalResetAtConflictError> {
        ReliableSizeIncreaseError::check(self.reliable_size(), request.reliable_size)
            .context(conflict_error::ReliableSizeIncreaseSnafu)?;
        match request.kind {
            ResetKind::ResetStream => Ok(Self::Reset(LocalReset {
                error_code: self.error_code(),
                final_size: self.final_size(),
            })),
            ResetKind::ResetStreamAt => match self {
                Self::Reset(_) => {
                    Err(PlainResetEffectiveError).context(conflict_error::PlainResetEffectiveSnafu)
                }
                Self::ResetAt(target) => Ok(Self::ResetAt(ResetTarget {
                    reliable_size: request.reliable_size,
                    ..target
                })),
            },
        }
    }

    /// The requested reliable size.
    ///
    /// # Errors
    ///
    /// [`LocalResetAtUnfitError::ReliablePrefixNotPrepared`] if it lies
    /// beyond the written end.
    fn minimum_final_size(
        request: &LocalResetAtRequest,
        written_end: VarInt,
    ) -> Result<VarInt, LocalResetAtUnfitError> {
        ReliablePrefixNotPreparedError::check(request.reliable_size, written_end)
            .context(unfit_error::ReliablePrefixNotPreparedSnafu)?;
        Ok(request.reliable_size)
    }

    /// # Errors
    ///
    /// [`LocalResetAtUnfitError::FinalSizeBelowReliableSize`] if
    /// `final_size` lies below the requested reliable size.
    fn establish(
        request: LocalResetAtRequest,
        final_size: VarInt,
    ) -> Result<Self, LocalResetAtUnfitError> {
        ReliableSizeError::check(final_size, request.reliable_size)
            .context(unfit_error::FinalSizeBelowReliableSizeSnafu)?;
        Ok(match request.kind {
            ResetKind::ResetStream => Self::Reset(LocalReset {
                error_code: request.error_code,
                final_size,
            }),
            ResetKind::ResetStreamAt => Self::ResetAt(ResetTarget {
                error_code: request.error_code,
                reliable_size: request.reliable_size,
                final_size,
            }),
        })
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

/// A `reset_at` follows a plain `reset` in effect: `RESET_STREAM` leaves the
/// stream in Reset Sent, which `reset_at` could not turn into the Data Sent
/// path of `RESET_STREAM_AT`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("a reset_at cannot follow a plain reset"))]
pub struct PlainResetEffectiveError;

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

/// Failures of [`StreamSender::reset_at`]; none of them changes any state.
///
/// `Lc` is the type of the connection's local close cause.
#[derive(Clone, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(reset_at_error))]
pub enum ResetAtError<Lc> {
    /// The connection has closed.
    #[snafu(transparent)]
    ConnectionClosed {
        /// The closed connection.
        source: ConnectionClosedError<Lc>,
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
    /// The reliable size exceeds the effective reset's.
    #[snafu(display("the reset conflicts with the effective reset"))]
    ReliableSizeIncrease {
        /// The effective and the requested reliable size.
        source: ReliableSizeIncreaseError,
    },
    /// The effective end is a plain reset, which `reset_at` cannot follow.
    #[snafu(display("the reset cannot follow a plain reset"))]
    PlainResetEffective {
        /// The plain reset in effect.
        source: PlainResetEffectiveError,
    },
    /// The requested reliable size lies beyond the written end.
    #[snafu(display("the reset cannot keep a reliable prefix"))]
    ReliablePrefixNotPrepared {
        /// The requested reliable size and the written end.
        source: ReliablePrefixNotPreparedError,
    },
}

/// Failures of [`StreamSender::reset_at_with_final_size`]; none of them
/// changes any state.
///
/// `Lc` is the type of the connection's local close cause.
#[derive(Clone, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(reset_at_with_final_size_error))]
pub enum ResetAtWithFinalSizeError<Lc> {
    /// The connection has closed.
    #[snafu(transparent)]
    ConnectionClosed {
        /// The closed connection.
        source: ConnectionClosedError<Lc>,
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
    /// The reliable size exceeds the effective reset's.
    #[snafu(display("the reset conflicts with the effective reset"))]
    ReliableSizeIncrease {
        /// The effective and the requested reliable size.
        source: ReliableSizeIncreaseError,
    },
    /// The effective end is a plain reset, which `reset_at` cannot follow.
    #[snafu(display("the reset cannot follow a plain reset"))]
    PlainResetEffective {
        /// The plain reset in effect.
        source: PlainResetEffectiveError,
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

/// The failure of a request for a [`LocalResetAt`].
type RequestError<Lc> = RequestResetError<LocalResetAtConflictError, LocalResetAtUnfitError, Lc>;

impl<Lc> From<RequestError<Lc>> for ResetAtWithFinalSizeError<Lc> {
    fn from(error: RequestError<Lc>) -> Self {
        use LocalResetAtConflictError as Conflict;
        use LocalResetAtUnfitError as Unfit;
        use RequestResetError as General;
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
            General::Conflict {
                source: Conflict::ReliableSizeIncrease { source },
            } => Self::ReliableSizeIncrease { source },
            General::Conflict {
                source: Conflict::PlainResetEffective { source },
            } => Self::PlainResetEffective { source },
            General::Unfit {
                source: Unfit::ReliablePrefixNotPrepared { source },
            } => Self::ReliablePrefixNotPrepared { source },
            General::Unfit {
                source: Unfit::FinalSizeBelowReliableSize { source },
            } => Self::FinalSizeBelowReliableSize { source },
            General::FinalSizeBelowExposure { source } => Self::FinalSizeBelowExposure { source },
            General::FinalSizeBeyondWrittenEnd { source } => {
                Self::FinalSizeBeyondWrittenEnd { source }
            }
        }
    }
}

impl<Lc> ResetAtError<Lc> {
    /// The failure of a `reset_at` request without a final size.
    fn narrow(error: RequestError<Lc>) -> Self {
        use ResetAtWithFinalSizeError as General;
        match General::from(error) {
            General::ConnectionClosed { source } => Self::ConnectionClosed { source },
            General::ErrorCodeConflict { source } => Self::ErrorCodeConflict { source },
            General::ProtocolTerminal { source } => Self::ProtocolTerminal { source },
            General::ReliableSizeIncrease { source } => Self::ReliableSizeIncrease { source },
            General::PlainResetEffective { source } => Self::PlainResetEffective { source },
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
                unreachable!("a reset without a final size cannot fail with a final size error")
            }
        }
    }
}

/// The failure of a `reset` request, whose reliable size is zero, as the
/// failure of the same request for a [`LocalReset`].
fn plain_reset_error<Lc>(error: RequestError<Lc>) -> RequestResetError<Infallible, Infallible, Lc> {
    use RequestResetError as General;
    match error {
        General::ConnectionClosed { source } => General::ConnectionClosed { source },
        General::ErrorCodeConflict { source } => General::ErrorCodeConflict { source },
        General::FinalSizeConflictsWithReset { source } => {
            General::FinalSizeConflictsWithReset { source }
        }
        General::FinalSizeConflictsWithClose { source } => {
            General::FinalSizeConflictsWithClose { source }
        }
        General::ProtocolTerminal { source } => General::ProtocolTerminal { source },
        General::FinalSizeBelowExposure { source } => General::FinalSizeBelowExposure { source },
        General::FinalSizeBeyondWrittenEnd { source } => {
            General::FinalSizeBeyondWrittenEnd { source }
        }
        // invariant: a reliable size of zero exceeds no effective reliable
        // size, no written end and no final size, and the request of `reset`
        // may follow either kind of reset.
        General::Conflict { .. } | General::Unfit { .. } => {
            unreachable!(
                "a reset without a reliable prefix cannot fail with a reliable prefix error"
            )
        }
    }
}

impl<C, K, Lc> StreamSender<C, K, Lc, LocalResetAt>
where
    K: ConnectionSendFlowController,
    C: StreamSendBuffer<Reservation = K::Reservation>
        + SendFlowControlPolicy<LocalResetAt>
        + SendTerminationPolicy<LocalResetAt>,
{
    /// Resets the stream with `error_code` and ends it with `RESET_STREAM`.
    ///
    /// While no final size is fixed, the termination policy chooses it. A
    /// `reset_at` in effect is replaced: `RESET_STREAM` is sent from then on,
    /// and the stream reaches `DataRecvd` only if its FIN was sent and
    /// everything was acknowledged, otherwise `ResetRecvd`.
    ///
    /// # Errors
    ///
    /// Checked in this order, after which the request succeeds without effect
    /// if it equals the effective reset:
    ///
    /// 1. [`ResetError::ConnectionClosed`];
    /// 2. [`ResetError::ErrorCodeConflict`] against an effective reset;
    /// 3. [`ResetError::ProtocolTerminal`].
    pub fn reset(&mut self, error_code: ApplicationErrorCode) -> Result<(), ResetError<Lc>> {
        self.request_reset(LocalResetAtRequest::reset(error_code), None)
            .map_err(|error| ResetError::from_request_without_final_size(plain_reset_error(error)))
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
    ) -> Result<(), ResetWithFinalSizeError<Lc>> {
        self.request_reset(LocalResetAtRequest::reset(error_code), Some(final_size))
            .map_err(|error| plain_reset_error(error).into())
    }

    /// Resets the stream with `error_code`, keeping the reliable delivery of
    /// the first `reliable_size` bytes, and ends it with `RESET_STREAM_AT`,
    /// also for a reliable size of zero. `support` is the peer's
    /// advertisement of the extension.
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
    /// 2. [`ResetAtError::ErrorCodeConflict`] against an effective reset;
    /// 3. [`ResetAtError::ProtocolTerminal`];
    /// 4. against an effective reset, [`ResetAtError::ReliableSizeIncrease`],
    ///    then [`ResetAtError::PlainResetEffective`] after a `reset`;
    /// 5. [`ResetAtError::ReliablePrefixNotPrepared`] for a reliable size
    ///    beyond the written end.
    pub fn reset_at(
        &mut self,
        support: PeerResetStreamAtSupport,
        error_code: ApplicationErrorCode,
        reliable_size: VarInt,
    ) -> Result<(), ResetAtError<Lc>> {
        let request = LocalResetAtRequest::reset_at(support, error_code, reliable_size);
        self.request_reset(request, None)
            .map_err(ResetAtError::narrow)
    }

    /// Resets the stream with `error_code`, `reliable_size` and the explicit
    /// `final_size`, as [`reset_at`](Self::reset_at) does.
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
    ///    [`ResetAtWithFinalSizeError::ErrorCodeConflict`], then
    ///    [`ResetAtWithFinalSizeError::FinalSizeConflictsWithReset`]; against
    ///    an effective close,
    ///    [`ResetAtWithFinalSizeError::FinalSizeConflictsWithClose`];
    /// 3. [`ResetAtWithFinalSizeError::ProtocolTerminal`];
    /// 4. against an effective reset,
    ///    [`ResetAtWithFinalSizeError::ReliableSizeIncrease`], then
    ///    [`ResetAtWithFinalSizeError::PlainResetEffective`] after a `reset`;
    /// 5. [`ResetAtWithFinalSizeError::ReliablePrefixNotPrepared`] for a
    ///    reliable size beyond the written end;
    /// 6. while no final size is fixed,
    ///    [`ResetAtWithFinalSizeError::FinalSizeBelowReliableSize`],
    ///    [`ResetAtWithFinalSizeError::FinalSizeBelowExposure`], then
    ///    [`ResetAtWithFinalSizeError::FinalSizeBeyondWrittenEnd`].
    pub fn reset_at_with_final_size(
        &mut self,
        support: PeerResetStreamAtSupport,
        error_code: ApplicationErrorCode,
        reliable_size: VarInt,
        final_size: VarInt,
    ) -> Result<(), ResetAtWithFinalSizeError<Lc>> {
        let request = LocalResetAtRequest::reset_at(support, error_code, reliable_size);
        Ok(self.request_reset(request, Some(final_size))?)
    }
}

/// For a stream that can end with `RESET_STREAM_AT` the policy behaves as for
/// one of RFC 9000, except that a `reset_at` in effect stays a
/// `RESET_STREAM_AT` when `STOP_SENDING` arrives and has its reliable size
/// lowered to zero (§5.4), so the stream still reaches `DataRecvd`. The
/// policy never starts a `RESET_STREAM_AT` itself.
impl SendTerminationPolicy<LocalResetAt> for ResetOnAbandonTermination {
    type WriteLimitReason = Infallible;

    fn on_termination_event(
        &mut self,
        event: SendTerminationEvent,
        context: &SendTerminationContext<LocalResetAt>,
    ) -> TerminationAction<Infallible, LocalResetAt> {
        if context.connection_closed || context.terminal_state.is_some() {
            return TerminationAction::Keep;
        }
        let reset = |error_code| {
            TerminationAction::Reset(LocalResetAt::Reset(LocalReset {
                error_code,
                final_size: context.minimum_final_size(VarInt::ZERO),
            }))
        };
        match (event, context.end_state) {
            (
                SendTerminationEvent::StopSendingReceived { .. },
                SendEndState::Reset {
                    target: LocalResetAt::Reset(_),
                    ..
                },
            ) => TerminationAction::Keep,
            (
                SendTerminationEvent::StopSendingReceived { .. },
                SendEndState::Reset {
                    target: LocalResetAt::ResetAt(target),
                    ..
                },
            ) => {
                if target.reliable_size() > VarInt::ZERO {
                    TerminationAction::Reset(LocalResetAt::ResetAt(
                        target.without_reliable_prefix(),
                    ))
                } else {
                    TerminationAction::Keep
                }
            }
            (SendTerminationEvent::StopSendingReceived { error_code }, _) => reset(error_code),
            (SendTerminationEvent::WriterAbandoned, SendEndState::Open) => {
                reset(self.abandon_code())
            }
            _ => TerminationAction::Keep,
        }
    }

    fn complete_final_size(
        &mut self,
        request: FinalSizeRequest<LocalResetAt>,
        _: &SendTerminationContext<LocalResetAt>,
    ) -> VarInt {
        request.minimum
    }
}

#[cfg(test)]
mod tests;
