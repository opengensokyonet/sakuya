//! The stream send termination policy ([`SendTerminationPolicy`]): automatic
//! end decisions, the write limit, and the final size of resets the
//! application leaves open.
//!
//! The policy has two entries with separate powers:
//!
//! - the automatic entry
//!   ([`on_termination_event`](SendTerminationPolicy::on_termination_event))
//!   observes facts such as a received `STOP_SENDING`, appended data, a grown
//!   exposure end, a committed end, an abandoned stream writer or the closed
//!   connection, and may answer with a complete, legal action;
//! - the completion entry
//!   ([`complete_final_size`](SendTerminationPolicy::complete_final_size)) is
//!   asked only for the final size of an application reset that names none
//!   while no final size is fixed. It cannot refuse the reset or change its
//!   error code or reliable size.
//!
//! The stream sender commits an automatic action synchronously, in the same
//! operation that delivered the event.
//!
//! # Contract
//!
//! An action, or a completed final size, that is illegal for the context the
//! policy was given violates this contract. The stream sender checks every
//! result before it changes the end state, discards data or releases credit,
//! and panics on a violation: it is a defect of the policy, never clamped and
//! never reported to the application as an error.
//!
//! Which actions are legal depends on the end state:
//!
//! | End state | Legal actions |
//! | --- | --- |
//! | Open | keep; narrow the write limit once `STOP_SENDING` arrived; close; reset |
//! | Closed | keep; reset with the fixed final size |
//! | Reset | keep; lower the reliable size with the same error code and final size |
//! | Terminal, or connection closed | keep |
//!
//! An action equal to the current state counts as keeping it.
use super::{EndSource, ResetTarget, SendEndState, SendTerminalState};
use crate::application_error_code::ApplicationErrorCode;
use core::convert::Infallible;
use core::ops::Range;
use sakuya_wire::stream_id::StreamId;
use sakuya_wire::var_int::VarInt;

/// The stream send termination policy (`SendTerminationPolicy`).
pub trait SendTerminationPolicy {
    /// The reason that accompanies a narrowed write limit
    /// (`WriteLimitReason`); writes beyond the limit fail with a shared
    /// handle to it.
    type WriteLimitReason;

    /// The automatic entry: observes `event` and decides an action.
    fn on_termination_event(
        &mut self,
        event: SendTerminationEvent,
        context: &SendTerminationContext,
    ) -> TerminationAction<Self::WriteLimitReason>;

    /// The completion entry: chooses the final size of an application reset
    /// within `request.minimum..=request.maximum`.
    ///
    /// A size outside the range violates the [contract](self#contract).
    fn complete_final_size(
        &mut self,
        request: FinalSizeRequest,
        context: &SendTerminationContext,
    ) -> VarInt;
}

/// An action decided by the automatic entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminationAction<R> {
    /// Change nothing.
    Keep,
    /// Narrow the write limit end to `write_limit_end` because of `reason`.
    ///
    /// Legal while input is open and after a `STOP_SENDING` arrived. The new
    /// end must not exceed the current one; an equal end keeps the original
    /// reason.
    NarrowWriteLimit {
        /// The new write limit end; it may lie below the written end.
        write_limit_end: VarInt,
        /// Why the limit narrowed.
        reason: R,
    },
    /// Close normally at the written end.
    Close,
    /// Reset with a complete target.
    Reset(ResetTarget),
}

/// Facts the automatic entry observes (`SendTerminationEvent`).
///
/// Each event follows the change it describes; the context passed along
/// shows the state after it. The set of events is provisional and may grow.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SendTerminationEvent {
    /// A `STOP_SENDING` frame arrived.
    StopSendingReceived {
        /// The error code it carried.
        error_code: ApplicationErrorCode,
    },
    /// Data entered the send buffer.
    DataAppended {
        /// The stream range of the appended data.
        appended_range: Range<VarInt>,
    },
    /// The exposure end grew.
    FirstExposed {
        /// The new exposure end.
        exposure_end: VarInt,
    },
    /// A close or reset was committed.
    EndCommitted {
        /// Who committed it.
        source: EndSource,
    },
    /// The write limit end narrowed.
    WriteLimitNarrowed {
        /// The new write limit end.
        write_limit_end: VarInt,
    },
    /// The application gave up its stream writer.
    WriterAbandoned,
    /// The send direction reached a terminal state.
    TerminalStateEntered {
        /// The terminal state.
        state: SendTerminalState,
    },
    /// The connection closed.
    ConnectionClosed,
}

/// The facts a termination policy reads when deciding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SendTerminationContext {
    /// The stream's ID.
    pub stream_id: StreamId,
    /// The written end.
    pub written_end: VarInt,
    /// The exposure end.
    pub exposure_end: VarInt,
    /// The current reliable size.
    pub reliable_size: VarInt,
    /// The end state, with the current target and its source.
    pub end_state: SendEndState,
    /// The error code of the first `STOP_SENDING` received, if any.
    pub stop_sending: Option<ApplicationErrorCode>,
    /// The write limit end, if set.
    pub write_limit_end: Option<VarInt>,
    /// Whether `RESET_STREAM_AT` was negotiated.
    pub reset_stream_at_supported: bool,
    /// The terminal state, once reached.
    pub terminal_state: Option<SendTerminalState>,
    /// Whether the connection has closed.
    pub connection_closed: bool,
}

impl SendTerminationContext {
    /// The final size a committed close or reset fixed.
    pub fn fixed_final_size(&self) -> Option<VarInt> {
        self.end_state.final_size()
    }

    /// The smallest legal final size of a reset that keeps `reliable_size`:
    /// the fixed final size if there is one, otherwise
    /// `max(exposure_end, reliable_size)`.
    pub fn minimum_final_size(&self, reliable_size: VarInt) -> VarInt {
        self.fixed_final_size()
            .unwrap_or_else(|| self.exposure_end.max(reliable_size))
    }
}

/// The question put to [`SendTerminationPolicy::complete_final_size`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalSizeRequest {
    /// The requested error code.
    pub error_code: ApplicationErrorCode,
    /// The requested reliable size; zero for a plain reset.
    pub reliable_size: VarInt,
    /// The smallest legal final size: `max(exposure_end, reliable_size)`.
    pub minimum: VarInt,
    /// The largest legal final size: the written end.
    pub maximum: VarInt,
}

/// A termination policy that answers `STOP_SENDING` and an abandoned stream
/// writer with a reset.
///
/// - Chooses the smallest legal final size.
/// - Answers `STOP_SENDING` at once with a reset carrying its error code and
///   reliable size zero; when a reset is already in effect it keeps the
///   error code and final size and lowers the reliable size to zero.
/// - Resets with the configured `abandon_code` when the stream writer is
///   abandoned while input is open; an abandoned writer of a closed or reset
///   stream changes nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResetOnAbandonTermination {
    abandon_code: ApplicationErrorCode,
}

/// The termination policy of the default composition.
pub type DefaultSendTerminationPolicy = ResetOnAbandonTermination;

impl ResetOnAbandonTermination {
    /// Creates the policy; `abandon_code` is the application error code of
    /// the reset that follows an abandoned stream writer.
    pub fn new(abandon_code: ApplicationErrorCode) -> Self {
        Self { abandon_code }
    }

    /// The error code used when the stream writer is abandoned.
    pub fn abandon_code(&self) -> ApplicationErrorCode {
        self.abandon_code
    }

    fn reset_without_prefix(
        error_code: ApplicationErrorCode,
        context: &SendTerminationContext,
    ) -> ResetTarget {
        ResetTarget {
            error_code,
            reliable_size: VarInt::ZERO,
            final_size: context.minimum_final_size(VarInt::ZERO),
        }
    }
}

impl SendTerminationPolicy for ResetOnAbandonTermination {
    type WriteLimitReason = Infallible;

    fn on_termination_event(
        &mut self,
        event: SendTerminationEvent,
        context: &SendTerminationContext,
    ) -> TerminationAction<Infallible> {
        if context.connection_closed || context.terminal_state.is_some() {
            return TerminationAction::Keep;
        }
        match (event, context.end_state) {
            (
                SendTerminationEvent::StopSendingReceived { .. },
                SendEndState::Reset { target, .. },
            ) => {
                if target.reliable_size > VarInt::ZERO {
                    TerminationAction::Reset(ResetTarget {
                        reliable_size: VarInt::ZERO,
                        ..target
                    })
                } else {
                    TerminationAction::Keep
                }
            }
            (SendTerminationEvent::StopSendingReceived { error_code }, _) => {
                TerminationAction::Reset(Self::reset_without_prefix(error_code, context))
            }
            (SendTerminationEvent::WriterAbandoned, SendEndState::Open) => {
                TerminationAction::Reset(Self::reset_without_prefix(self.abandon_code, context))
            }
            _ => TerminationAction::Keep,
        }
    }

    fn complete_final_size(
        &mut self,
        request: FinalSizeRequest,
        _: &SendTerminationContext,
    ) -> VarInt {
        request.minimum
    }
}
