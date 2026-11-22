//! The reliable stream reset extension for the stream sender: the resets of a
//! sender whose reset target is [`LocalResetAt`], and the termination policy
//! that answers for such a sender.
use crate::send::StreamSender;
use crate::send::termination::ResetOnAbandonTermination;
use core::convert::Infallible;
use sakuya_stream_reset_stream_at::send::{
    LocalResetAt, LocalResetAtRequest, PeerResetStreamAtSupport, ResetAtError,
    ResetAtWithFinalSizeError, plain_reset_error,
};
use sakuya_stream_v1::connection_send_credit::ConnectionSendFlowController;
use sakuya_stream_v1::send::SendEndState;
use sakuya_stream_v1::send::finish::{ResetError, ResetWithFinalSizeError};
use sakuya_stream_v1::send::flow_control::SendFlowControlPolicy;
use sakuya_stream_v1::send::local_reset::LocalReset;
use sakuya_stream_v1::send::termination::{
    FinalSizeRequest, SendTerminationContext, SendTerminationEvent, SendTerminationPolicy,
    TerminationAction,
};
use sakuya_stream_v1::send_buffer::{SendMarker, StreamSendBuffer};
use sakuya_wire_v1::application_error::ApplicationErrorCode;
use sakuya_wire_v1::var_int::VarInt;

#[cfg(test)]
mod tests;

/// The resets of a stream sender whose reset target is [`LocalResetAt`]:
/// `RESET_STREAM`, and `RESET_STREAM_AT` with a reliable prefix.
pub trait ResetStreamAtSender<Lc> {
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
    /// 1. [`ResetError::LayerEnded`];
    /// 2. [`ResetError::ErrorCodeConflict`] against an effective reset;
    /// 3. [`ResetError::ProtocolTerminal`].
    fn reset(&mut self, error_code: ApplicationErrorCode) -> Result<(), ResetError<Lc>>;

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
    fn reset_with_final_size(
        &mut self,
        error_code: ApplicationErrorCode,
        final_size: VarInt,
    ) -> Result<(), ResetWithFinalSizeError<Lc>>;

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
    /// 1. [`ResetAtError::LayerEnded`];
    /// 2. [`ResetAtError::ErrorCodeConflict`] against an effective reset;
    /// 3. [`ResetAtError::ProtocolTerminal`];
    /// 4. against an effective reset, [`ResetAtError::ReliableSizeIncrease`],
    ///    then [`ResetAtError::PlainResetEffective`] after a `reset`;
    /// 5. [`ResetAtError::ReliablePrefixNotPrepared`] for a reliable size
    ///    beyond the written end.
    fn reset_at(
        &mut self,
        support: PeerResetStreamAtSupport,
        error_code: ApplicationErrorCode,
        reliable_size: VarInt,
    ) -> Result<(), ResetAtError<Lc>>;

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
    /// 1. [`ResetAtWithFinalSizeError::LayerEnded`];
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
    fn reset_at_with_final_size(
        &mut self,
        support: PeerResetStreamAtSupport,
        error_code: ApplicationErrorCode,
        reliable_size: VarInt,
        final_size: VarInt,
    ) -> Result<(), ResetAtWithFinalSizeError<Lc>>;
}

impl<C, K, Lc, B, M> ResetStreamAtSender<Lc> for StreamSender<C, K, Lc, LocalResetAt, B, M>
where
    K: ConnectionSendFlowController,
    M: SendMarker,
    C: StreamSendBuffer<B, K::Reservation, M>
        + SendFlowControlPolicy<LocalResetAt>
        + SendTerminationPolicy<LocalResetAt>,
{
    fn reset(&mut self, error_code: ApplicationErrorCode) -> Result<(), ResetError<Lc>> {
        self.request_reset(LocalResetAtRequest::reset(error_code), None)
            .map_err(|error| ResetError::from_request_without_final_size(plain_reset_error(error)))
    }

    fn reset_with_final_size(
        &mut self,
        error_code: ApplicationErrorCode,
        final_size: VarInt,
    ) -> Result<(), ResetWithFinalSizeError<Lc>> {
        self.request_reset(LocalResetAtRequest::reset(error_code), Some(final_size))
            .map_err(|error| plain_reset_error(error).into())
    }

    fn reset_at(
        &mut self,
        support: PeerResetStreamAtSupport,
        error_code: ApplicationErrorCode,
        reliable_size: VarInt,
    ) -> Result<(), ResetAtError<Lc>> {
        let request = LocalResetAtRequest::reset_at(support, error_code, reliable_size);
        self.request_reset(request, None)
            .map_err(ResetAtError::narrow)
    }

    fn reset_at_with_final_size(
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
/// lowered to zero (§5.4), so the stream still reaches `DataRecvd`; data
/// without a destination lowers it to zero the same way. The policy never
/// starts a `RESET_STREAM_AT` itself.
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
            (
                SendTerminationEvent::DestinationExhausted { .. },
                SendEndState::Reset {
                    target: LocalResetAt::Reset(_),
                    ..
                },
            ) => TerminationAction::Keep,
            // Data below the reliable size cannot be delivered any more: the
            // reliable prefix is given up, the reset stays a
            // `RESET_STREAM_AT`.
            (
                SendTerminationEvent::DestinationExhausted { .. },
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
            (SendTerminationEvent::DestinationExhausted { .. }, _) => {
                reset(self.destination_exhausted_code())
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
