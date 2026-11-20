//! Joining a send buffer and the two policies into one composition
//! ([`SendComposition`]), and the default choice of the three
//! ([`DefaultSendComposition`]).
use super::flow_control::{
    AdmissionGuard, DefaultSendFlowControlPolicy, SendFlowContext, SendFlowControlPolicy,
    StreamCreditEvent, WriteAttempt,
};
use super::local_reset::LocalResetTarget;
use super::termination::{
    DefaultSendTerminationPolicy, FinalSizeRequest, SendTerminationContext, SendTerminationEvent,
    SendTerminationPolicy, TerminationAction,
};
use crate::connection_send_credit::{
    AtomicConnectionCreditReservation, ConnectionCreditReservation,
};
use crate::send_buffer::covered_bytes::CoveredBytes;
use crate::send_buffer::offset_map::OffsetMapStreamSendBuffer;
use crate::send_buffer::{
    AppendError, ApplyResetError, CurrentDestinationOf, DestinationChanges, ExposeUsageError,
    ExposedContent, NextSegment, ResetRetention, SelectedData, SendMarker, StreamSendBuffer,
};
use crate::send_options::SendOptions;
use crate::send_options::destination::{AnyActiveLinkPath, Unfulfilled};
use crate::send_options::urgency::Urgency;
use bytes::Bytes;
use core::ops::Range;
use sakuya_wire::var_int::VarInt;
use sakuya_wire_v1::application_error::ApplicationErrorCode;

/// A transparent composition of an independent send buffer, flow-control
/// policy and termination policy, fulfilling all three contracts by
/// forwarding.
///
/// The components must belong to the same stream: the policies then see the
/// real buffer, and grants and resets act on the data they describe.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SendComposition<B, F, P> {
    /// The send buffer.
    pub buffer: B,
    /// The flow-control policy.
    pub flow_control: F,
    /// The termination policy.
    pub termination: P,
}

/// The default composition: [`OffsetMapStreamSendBuffer`],
/// [`DefaultSendFlowControlPolicy`] and [`DefaultSendTerminationPolicy`],
/// over the data `B` ([`Bytes`] by default), the connection credit
/// reservation `R` ([`AtomicConnectionCreditReservation`] by default) and
/// the marker `M` (by default the send options of an [`Urgency`] to
/// [`AnyActiveLinkPath`]).
///
/// It is a replaceable base, not behaviour every policy must share.
pub type DefaultSendComposition<
    B = Bytes,
    R = AtomicConnectionCreditReservation,
    M = SendOptions<Urgency, AnyActiveLinkPath>,
> = SendComposition<
    OffsetMapStreamSendBuffer<B, R, M>,
    DefaultSendFlowControlPolicy,
    DefaultSendTerminationPolicy,
>;

impl<B, F, P> SendComposition<B, F, P> {
    /// Joins the three components.
    pub fn new(buffer: B, flow_control: F, termination: P) -> Self {
        Self {
            buffer,
            flow_control,
            termination,
        }
    }
}

impl<B, R: ConnectionCreditReservation, M: SendMarker> DefaultSendComposition<B, R, M> {
    /// The default composition with an empty buffer; an abandoned stream
    /// writer leads to a reset with `abandon_code`, and data whose
    /// destination has nothing left to fall back to to a reset with
    /// `destination_exhausted_code`.
    pub fn with_reset_codes(
        abandon_code: ApplicationErrorCode,
        destination_exhausted_code: ApplicationErrorCode,
    ) -> Self {
        Self::new(
            OffsetMapStreamSendBuffer::new(),
            DefaultSendFlowControlPolicy::new(),
            DefaultSendTerminationPolicy::new(abandon_code, destination_exhausted_code),
        )
    }
}

impl<S, F, P, B, R, M> StreamSendBuffer<B, R, M> for SendComposition<S, F, P>
where
    S: StreamSendBuffer<B, R, M>,
    M: SendMarker,
{
    fn written_end(&self) -> VarInt {
        self.buffer.written_end()
    }

    fn exposure_end(&self) -> VarInt {
        self.buffer.exposure_end()
    }

    fn append(&mut self, data: CoveredBytes<B, R, M>) -> Result<(), AppendError<B, R, M>> {
        self.buffer.append(data)
    }

    fn apply_reset(&mut self, retention: ResetRetention) -> Result<(), ApplyResetError> {
        self.buffer.apply_reset(retention)
    }

    fn expose_usage_through(
        &mut self,
        usage_end: VarInt,
        content: ExposedContent,
    ) -> Result<VarInt, ExposeUsageError> {
        self.buffer.expose_usage_through(usage_end, content)
    }

    fn destinations(&self) -> Vec<CurrentDestinationOf<M>> {
        self.buffer.destinations()
    }

    fn next(&self, destination: &CurrentDestinationOf<M>) -> Option<NextSegment<'_, M>> {
        self.buffer.next(destination)
    }

    fn select(
        &mut self,
        destination: &CurrentDestinationOf<M>,
        max_len: usize,
    ) -> Option<SelectedData<B>> {
        self.buffer.select(destination, max_len)
    }

    fn on_acknowledged(&mut self, range: Range<VarInt>) -> Vec<CurrentDestinationOf<M>> {
        self.buffer.on_acknowledged(range)
    }

    fn on_lost(&mut self, range: Range<VarInt>) -> DestinationChanges<CurrentDestinationOf<M>> {
        self.buffer.on_lost(range)
    }

    fn on_unfulfilled(
        &mut self,
        destination: &CurrentDestinationOf<M>,
        cause: Unfulfilled,
    ) -> DestinationChanges<CurrentDestinationOf<M>> {
        self.buffer.on_unfulfilled(destination, cause)
    }
}

impl<B, F, P, T> SendFlowControlPolicy<T> for SendComposition<B, F, P>
where
    T: LocalResetTarget,
    F: SendFlowControlPolicy<T>,
{
    fn admit_write(
        &mut self,
        attempt: &WriteAttempt,
        context: &SendFlowContext<T>,
    ) -> Option<AdmissionGuard> {
        self.flow_control.admit_write(attempt, context)
    }

    fn on_admission_used(
        &mut self,
        guard: AdmissionGuard,
        used: VarInt,
        context: &SendFlowContext<T>,
    ) {
        self.flow_control.on_admission_used(guard, used, context);
    }

    fn on_admission_abandoned(&mut self, guard: AdmissionGuard, context: &SendFlowContext<T>) {
        self.flow_control.on_admission_abandoned(guard, context);
    }

    fn on_flow_event(&mut self, event: StreamCreditEvent, context: &SendFlowContext<T>) {
        self.flow_control.on_flow_event(event, context);
    }

    fn wants_stream_data_blocked(&self, context: &SendFlowContext<T>) -> bool {
        self.flow_control.wants_stream_data_blocked(context)
    }
}

impl<B, F, P, T> SendTerminationPolicy<T> for SendComposition<B, F, P>
where
    T: LocalResetTarget,
    P: SendTerminationPolicy<T>,
{
    type WriteLimitReason = P::WriteLimitReason;

    fn on_termination_event(
        &mut self,
        event: SendTerminationEvent,
        context: &SendTerminationContext<T>,
    ) -> TerminationAction<Self::WriteLimitReason, T> {
        self.termination.on_termination_event(event, context)
    }

    fn complete_final_size(
        &mut self,
        request: FinalSizeRequest<T>,
        context: &SendTerminationContext<T>,
    ) -> VarInt {
        self.termination.complete_final_size(request, context)
    }
}
