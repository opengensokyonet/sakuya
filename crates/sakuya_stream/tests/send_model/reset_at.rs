/// The sender that also ends a stream with `RESET_STREAM_AT`.
mod dialect {
    use super::model::{EffectiveReset, ResetFailure, SenderOf, TestCloseCause};
    use sakuya_stream::connection_send_credit::AtomicConnectionCreditReservation;
    use sakuya_stream::reset_stream_at::send::{
        LocalResetAt, LocalResetAtFrame, PeerResetStreamAtSupport, ResetAtError,
        ResetAtWithFinalSizeError,
    };
    use sakuya_stream::send::flow_control::SendFlowControlPolicy;
    use sakuya_stream::send::termination::SendTerminationPolicy;
    use sakuya_stream::send_buffer::StreamSendBuffer;
    use sakuya_wire::reset_stream_at::{ResetStreamAt, ResetStreamAtFrame};
    use sakuya_wire::v1::application_error::ApplicationErrorCode;
    use sakuya_wire::v1::frame::reset_stream::ResetStreamFrame;
    use sakuya_wire::v1::stream_id::StreamId;
    use sakuya_wire::var_int::{VarInt, VarIntField};

    pub type Target = LocalResetAt;

    /// Whether the application also resets with a reliable size.
    pub const RESETS_AT: bool = true;

    const SUPPORT: PeerResetStreamAtSupport =
        PeerResetStreamAtSupport::from_peer_parameter(ResetStreamAt);

    impl From<ResetAtWithFinalSizeError<TestCloseCause>> for ResetFailure {
        fn from(error: ResetAtWithFinalSizeError<TestCloseCause>) -> Self {
            use ResetAtWithFinalSizeError as E;
            match error {
                E::ConnectionClosed { source } => Self::ConnectionClosed(source),
                E::ErrorCodeConflict { source } => Self::ErrorCodeConflict(source),
                E::FinalSizeConflictsWithReset { source } => {
                    Self::FinalSizeConflictsWithReset(source)
                }
                E::FinalSizeConflictsWithClose { source } => {
                    Self::FinalSizeConflictsWithClose(source)
                }
                E::ProtocolTerminal { source } => Self::ProtocolTerminal(source),
                E::ReliableSizeIncrease { source } => Self::ReliableSizeIncrease {
                    effective: source.effective().get(),
                    requested: source.requested().get(),
                },
                E::PlainResetEffective { .. } => Self::PlainResetEffective,
                E::ReliablePrefixNotPrepared { source } => Self::ReliablePrefixNotPrepared {
                    reliable: source.reliable_size().get(),
                    written: source.written_end().get(),
                },
                E::FinalSizeBelowReliableSize { source } => Self::FinalSizeBelowReliableSize {
                    final_size: source.final_size().get(),
                    reliable: source.reliable_size().get(),
                },
                E::FinalSizeBelowExposure { source } => Self::FinalSizeBelowExposure(source),
                E::FinalSizeBeyondWrittenEnd { source } => Self::FinalSizeBeyondWrittenEnd(source),
            }
        }
    }

    impl From<ResetAtError<TestCloseCause>> for ResetFailure {
        fn from(error: ResetAtError<TestCloseCause>) -> Self {
            use ResetAtError as E;
            match error {
                E::ConnectionClosed { source } => Self::ConnectionClosed(source),
                E::ErrorCodeConflict { source } => Self::ErrorCodeConflict(source),
                E::ProtocolTerminal { source } => Self::ProtocolTerminal(source),
                E::ReliableSizeIncrease { source } => Self::ReliableSizeIncrease {
                    effective: source.effective().get(),
                    requested: source.requested().get(),
                },
                E::PlainResetEffective { .. } => Self::PlainResetEffective,
                E::ReliablePrefixNotPrepared { source } => Self::ReliablePrefixNotPrepared {
                    reliable: source.reliable_size().get(),
                    written: source.written_end().get(),
                },
            }
        }
    }

    pub fn request<C>(
        sender: &mut SenderOf<C>,
        reliable: Option<VarInt>,
        code: ApplicationErrorCode,
        final_size: Option<VarInt>,
    ) -> Result<(), ResetFailure>
    where
        C: StreamSendBuffer<Reservation = AtomicConnectionCreditReservation>
            + SendFlowControlPolicy<Target>
            + SendTerminationPolicy<Target>,
    {
        match (reliable, final_size) {
            (None, None) => Ok(sender.reset(code)?),
            (None, Some(size)) => Ok(sender.reset_with_final_size(code, size)?),
            (Some(reliable), None) => Ok(sender.reset_at(SUPPORT, code, reliable)?),
            (Some(reliable), Some(size)) => {
                Ok(sender.reset_at_with_final_size(SUPPORT, code, reliable, size)?)
            }
        }
    }

    pub fn effective(target: Target) -> EffectiveReset {
        match target {
            LocalResetAt::Reset(reset) => EffectiveReset {
                code: reset.error_code,
                reliable: None,
                final_size: reset.final_size,
            },
            LocalResetAt::ResetAt(target) => EffectiveReset {
                code: target.error_code(),
                reliable: Some(target.reliable_size()),
                final_size: target.final_size(),
            },
        }
    }

    pub fn frame(
        stream: StreamId,
        plain: ResetStreamFrame,
        reliable: Option<VarInt>,
    ) -> LocalResetAtFrame {
        match reliable {
            None => LocalResetAtFrame::ResetStream(plain),
            Some(reliable) => LocalResetAtFrame::ResetStreamAt(
                ResetStreamAtFrame::new(
                    VarIntField::shortest(stream),
                    plain.application_error_code(),
                    plain.final_size(),
                    VarIntField::shortest(reliable),
                )
                .unwrap(),
            ),
        }
    }
}

// The same model runs against each dialect.
#[allow(clippy::duplicate_mod)]
#[path = "model.rs"]
mod model;
