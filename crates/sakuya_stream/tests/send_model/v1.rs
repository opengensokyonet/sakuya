/// The sender of RFC 9000 resets: every reset ends with `RESET_STREAM`.
mod dialect {
    use super::model::{EffectiveReset, ResetFailure, SenderOf};
    use sakuya_stream::connection_send_credit::AtomicConnectionCreditReservation;
    use sakuya_stream::send::flow_control::SendFlowControlPolicy;
    use sakuya_stream::send::local_reset::LocalReset;
    use sakuya_stream::send::termination::SendTerminationPolicy;
    use sakuya_stream::send_buffer::StreamSendBuffer;
    use sakuya_wire::v1::application_error::ApplicationErrorCode;
    use sakuya_wire::v1::frame::reset_stream::ResetStreamFrame;
    use sakuya_wire::v1::stream_id::StreamId;
    use sakuya_wire::var_int::VarInt;

    pub type Target = LocalReset;

    /// Whether the application also resets with a reliable size.
    pub const RESETS_AT: bool = false;

    pub fn request<C>(
        sender: &mut SenderOf<C>,
        reliable: Option<VarInt>,
        code: ApplicationErrorCode,
        final_size: Option<VarInt>,
    ) -> Result<(), ResetFailure>
    where
        C: StreamSendBuffer<Reservation = AtomicConnectionCreditReservation>
            + SendFlowControlPolicy
            + SendTerminationPolicy,
    {
        assert_eq!(reliable, None, "this sender has no reset_at");
        match final_size {
            None => Ok(sender.reset(code)?),
            Some(size) => Ok(sender.reset_with_final_size(code, size)?),
        }
    }

    pub fn effective(target: Target) -> EffectiveReset {
        EffectiveReset {
            code: target.error_code,
            reliable: None,
            final_size: target.final_size,
        }
    }

    pub fn frame(
        _stream: StreamId,
        plain: ResetStreamFrame,
        reliable: Option<VarInt>,
    ) -> ResetStreamFrame {
        assert_eq!(reliable, None, "this sender has no RESET_STREAM_AT");
        plain
    }
}

// The same model runs against each dialect.
#[allow(clippy::duplicate_mod)]
#[path = "model.rs"]
mod model;
