//! A stream send termination policy that answers `STOP_SENDING`, an abandoned
//! stream writer and data without a destination with a reset
//! ([`ResetOnAbandonTermination`]).
use core::convert::Infallible;
use sakuya_stream_v1::send::SendEndState;
use sakuya_stream_v1::send::local_reset::LocalReset;
use sakuya_stream_v1::send::termination::{
    FinalSizeRequest, SendTerminationContext, SendTerminationEvent, SendTerminationPolicy,
    TerminationAction,
};
use sakuya_var_int::VarInt;
use sakuya_wire_v1::application_error::ApplicationErrorCode;

/// A termination policy that answers `STOP_SENDING`, an abandoned stream
/// writer and data without a destination with a reset.
///
/// - Chooses the smallest legal final size.
/// - Answers `STOP_SENDING` at once with a [`TerminationAction::Reset`]
///   carrying its error code; a reset already in effect stays as it is.
/// - Resets with the configured `abandon_code` when the stream writer is
///   abandoned while input is open; an abandoned writer of a closed or reset
///   stream changes nothing.
/// - Resets with the configured `destination_exhausted_code` when data has
///   no destination left
///   ([`SendTerminationEvent::DestinationExhausted`]) while input is open or
///   after a close; a reset already in effect stays as it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResetOnAbandonTermination {
    abandon_code: ApplicationErrorCode,
    destination_exhausted_code: ApplicationErrorCode,
}

impl ResetOnAbandonTermination {
    /// Creates the policy; `abandon_code` is the application error code of
    /// the reset that follows an abandoned stream writer, and
    /// `destination_exhausted_code` that of the reset that follows data
    /// whose destination has nothing left to fall back to.
    pub fn new(
        abandon_code: ApplicationErrorCode,
        destination_exhausted_code: ApplicationErrorCode,
    ) -> Self {
        Self {
            abandon_code,
            destination_exhausted_code,
        }
    }

    /// The error code used when the stream writer is abandoned.
    pub fn abandon_code(&self) -> ApplicationErrorCode {
        self.abandon_code
    }

    /// The error code used when data has no destination left.
    pub fn destination_exhausted_code(&self) -> ApplicationErrorCode {
        self.destination_exhausted_code
    }

    fn reset(
        error_code: ApplicationErrorCode,
        context: &SendTerminationContext,
    ) -> TerminationAction<Infallible> {
        TerminationAction::Reset(LocalReset {
            error_code,
            final_size: context.minimum_final_size(VarInt::ZERO),
        })
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
            (SendTerminationEvent::StopSendingReceived { .. }, SendEndState::Reset { .. }) => {
                TerminationAction::Keep
            }
            (SendTerminationEvent::StopSendingReceived { error_code }, _) => {
                Self::reset(error_code, context)
            }
            (SendTerminationEvent::WriterAbandoned, SendEndState::Open) => {
                Self::reset(self.abandon_code, context)
            }
            (SendTerminationEvent::DestinationExhausted { .. }, SendEndState::Reset { .. }) => {
                TerminationAction::Keep
            }
            (SendTerminationEvent::DestinationExhausted { .. }, _) => {
                Self::reset(self.destination_exhausted_code, context)
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
