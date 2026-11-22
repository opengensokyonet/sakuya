//! Joining a receive buffer and the two policies into one composition
//! ([`ReceiveComposition`]).
use super::flow_control::{
    AdvertisementIntent, ReceiveFlowControlPolicy, ReceiveFlowEvent, ReceiveFlowView,
    SlidingWindowAdvertisement,
};
use super::remote_reset::RemoteResetFacts;
use super::termination::{
    FollowingTermination, ReceiveTerminationPolicy, TerminationDecision, TerminationEvent,
    TerminationView,
};
use crate::receive_buffer::fragmented::FragmentedStreamReceiveBuffer;
use crate::receive_buffer::{StreamDataInput, StreamReceiveBuffer};
use bytes::BufMut;
use sakuya_wire_v1::application_error::ApplicationErrorCode;
use sakuya_wire_v1::var_int::VarInt;

/// A transparent composition of an independent receive buffer, flow control
/// policy and termination policy, fulfilling all three contracts by
/// forwarding.
///
/// The components must belong to the same stream: the policies then see the
/// real buffer through the stream receiver's views.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReceiveComposition<B, F, P> {
    /// The receive buffer.
    pub buffer: B,
    /// The flow control policy.
    pub flow_control: F,
    /// The termination policy.
    pub termination: P,
}

impl<B, F, P> ReceiveComposition<B, F, P> {
    /// Joins the three components.
    pub fn new(buffer: B, flow_control: F, termination: P) -> Self {
        Self {
            buffer,
            flow_control,
            termination,
        }
    }
}

impl
    ReceiveComposition<
        FragmentedStreamReceiveBuffer,
        SlidingWindowAdvertisement,
        FollowingTermination,
    >
{
    /// The composition of a [`FragmentedStreamReceiveBuffer`] with
    /// [`SlidingWindowAdvertisement`] and [`FollowingTermination`], with an empty buffer; the flow control window
    /// is `window`, and a dropped stream reader leads to a STOP request with
    /// `abandon_code`.
    pub fn with_window_and_abandon_code(
        window: VarInt,
        abandon_code: ApplicationErrorCode,
    ) -> Self {
        Self::new(
            FragmentedStreamReceiveBuffer::new(),
            SlidingWindowAdvertisement::new(window),
            FollowingTermination::new(abandon_code),
        )
    }
}

impl<B: StreamReceiveBuffer, F, P> StreamReceiveBuffer for ReceiveComposition<B, F, P> {
    type Chunk = B::Chunk;

    fn receive_data(&mut self, input: StreamDataInput) {
        self.buffer.receive_data(input);
    }

    fn receive_final_size(&mut self, final_size: VarInt) {
        self.buffer.receive_final_size(final_size);
    }

    fn accounted_end(&self) -> VarInt {
        self.buffer.accounted_end()
    }

    fn final_size(&self) -> Option<VarInt> {
        self.buffer.final_size()
    }

    fn delivered_end(&self) -> VarInt {
        self.buffer.delivered_end()
    }

    fn read_chunk(&mut self, limit: VarInt) -> Option<Self::Chunk> {
        self.buffer.read_chunk(limit)
    }

    fn read_into<T: BufMut + ?Sized>(&mut self, limit: VarInt, target: &mut T) -> usize {
        self.buffer.read_into(limit, target)
    }

    fn release_from(&mut self, end: VarInt) {
        self.buffer.release_from(end);
    }

    fn destroy(&mut self) {
        self.buffer.destroy();
    }
}

impl<B, F: ReceiveFlowControlPolicy, P> ReceiveFlowControlPolicy for ReceiveComposition<B, F, P> {
    fn on_receive_flow_event(&mut self, event: ReceiveFlowEvent, view: &ReceiveFlowView) {
        self.flow_control.on_receive_flow_event(event, view);
    }

    fn advertisement_intent(&self) -> AdvertisementIntent {
        self.flow_control.advertisement_intent()
    }
}

impl<B, F, P, X> ReceiveTerminationPolicy<X> for ReceiveComposition<B, F, P>
where
    X: RemoteResetFacts,
    P: ReceiveTerminationPolicy<X>,
{
    type Reason = P::Reason;

    fn on_termination_event(
        &mut self,
        event: TerminationEvent<X::Change>,
        view: &TerminationView<X>,
    ) -> TerminationDecision<Self::Reason> {
        self.termination.on_termination_event(event, view)
    }
}

#[cfg(test)]
mod tests;
