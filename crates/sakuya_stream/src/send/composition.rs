//! Joining a send buffer and the two policies into one composition
//! ([`SendComposition`]), and the default choice of the three
//! ([`DefaultSendComposition`]).
use super::flow_control::{
    AdmissionGuard, DefaultSendFlowControlPolicy, SendFlowContext, SendFlowControlPolicy,
    StreamCreditEvent, WriteAttempt,
};
use super::termination::{
    DefaultSendTerminationPolicy, FinalSizeRequest, SendTerminationContext, SendTerminationEvent,
    SendTerminationPolicy, TerminationAction,
};
use crate::application_error_code::ApplicationErrorCode;
use crate::connection_send_credit::ConnectionSendFlowController;
use crate::send_buffer::covered_bytes::CoveredBytes;
use crate::send_buffer::offset_map::OffsetMapSendBuffer;
use crate::send_buffer::{
    AppendError, ApplyResetError, ExposeUsageError, ExposedEnd, ResetRetention, Selection,
    SelectionConstraints, SendBuffer, TransmissionReceipt,
};
use sakuya_wire::var_int::VarInt;

/// A transparent composition of an independent send buffer, flow-control
/// policy and termination policy, fulfilling all three contracts by
/// forwarding.
///
/// The components must belong to the same stream: the policies then see the
/// real buffer, and grants and resets act on the data they describe.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SendComposition<B, F, T> {
    /// The send buffer.
    pub buffer: B,
    /// The flow-control policy.
    pub flow_control: F,
    /// The termination policy.
    pub termination: T,
}

/// The default composition: [`OffsetMapSendBuffer`],
/// [`DefaultSendFlowControlPolicy`] and [`DefaultSendTerminationPolicy`].
///
/// It is a replaceable base, not behaviour every policy must share.
pub type DefaultSendComposition = SendComposition<
    OffsetMapSendBuffer,
    DefaultSendFlowControlPolicy,
    DefaultSendTerminationPolicy,
>;

impl<B, F, T> SendComposition<B, F, T> {
    /// Joins the three components.
    pub fn new(buffer: B, flow_control: F, termination: T) -> Self {
        Self {
            buffer,
            flow_control,
            termination,
        }
    }
}

impl DefaultSendComposition {
    /// The default composition with an empty buffer; an abandoned stream
    /// writer leads to a reset with `abandon_code`.
    pub fn with_abandon_code(abandon_code: ApplicationErrorCode) -> Self {
        Self::new(
            OffsetMapSendBuffer::new(),
            DefaultSendFlowControlPolicy::new(),
            DefaultSendTerminationPolicy::new(abandon_code),
        )
    }
}

impl<B: SendBuffer, F, T> SendBuffer for SendComposition<B, F, T> {
    fn written_end(&self) -> VarInt {
        self.buffer.written_end()
    }

    fn exposure_end(&self) -> VarInt {
        self.buffer.exposure_end()
    }

    fn append(&mut self, data: CoveredBytes) -> Result<(), AppendError> {
        self.buffer.append(data)
    }

    fn apply_reset(&mut self, retention: ResetRetention) -> Result<(), ApplyResetError> {
        self.buffer.apply_reset(retention)
    }

    fn expose_usage_through(
        &mut self,
        usage_end: VarInt,
        end: ExposedEnd,
        connection: &mut ConnectionSendFlowController,
    ) -> Result<VarInt, ExposeUsageError> {
        self.buffer.expose_usage_through(usage_end, end, connection)
    }

    fn select(&mut self, constraints: SelectionConstraints) -> Selection {
        self.buffer.select(constraints)
    }

    fn on_acknowledged(&mut self, receipt: TransmissionReceipt) {
        self.buffer.on_acknowledged(receipt);
    }

    fn on_lost(&mut self, receipt: TransmissionReceipt) {
        self.buffer.on_lost(receipt);
    }
}

impl<B, F: SendFlowControlPolicy, T> SendFlowControlPolicy for SendComposition<B, F, T> {
    fn admit_write(
        &mut self,
        attempt: &WriteAttempt,
        context: &SendFlowContext,
    ) -> Option<AdmissionGuard> {
        self.flow_control.admit_write(attempt, context)
    }

    fn on_admission_used(
        &mut self,
        guard: AdmissionGuard,
        used: VarInt,
        context: &SendFlowContext,
    ) {
        self.flow_control.on_admission_used(guard, used, context);
    }

    fn on_admission_abandoned(&mut self, guard: AdmissionGuard, context: &SendFlowContext) {
        self.flow_control.on_admission_abandoned(guard, context);
    }

    fn on_flow_event(&mut self, event: StreamCreditEvent, context: &SendFlowContext) {
        self.flow_control.on_flow_event(event, context);
    }

    fn wants_stream_data_blocked(&self, context: &SendFlowContext) -> bool {
        self.flow_control.wants_stream_data_blocked(context)
    }
}

impl<B, F, T: SendTerminationPolicy> SendTerminationPolicy for SendComposition<B, F, T> {
    type WriteLimitReason = T::WriteLimitReason;

    fn on_termination_event(
        &mut self,
        event: SendTerminationEvent,
        context: &SendTerminationContext,
    ) -> TerminationAction<Self::WriteLimitReason> {
        self.termination.on_termination_event(event, context)
    }

    fn complete_final_size(
        &mut self,
        request: FinalSizeRequest,
        context: &SendTerminationContext,
    ) -> VarInt {
        self.termination.complete_final_size(request, context)
    }
}
