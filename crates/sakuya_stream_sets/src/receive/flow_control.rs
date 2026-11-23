//! The stream limit a stream receiver advertises, and the limit it opens.
//!
//! The stream receiver asks its receive flow control policy for an intent and
//! turns it into the limit to advertise now, once the stream still needs
//! limit increases.
use super::StreamReceiver;
use sakuya_stream_v1::receive::flow_control::{
    AdvertisementIntent, ReceiveFlowControlPolicy, ReceiveFlowEvent,
};
use sakuya_stream_v1::receive::remote_reset::RemoteResetFacts;
use sakuya_stream_v1::receive::termination::ReceiveTerminationPolicy;
use sakuya_stream_v1::receive_buffer::StreamReceiveBuffer;
use sakuya_var_int::VarInt;

impl<C, Lc, F> StreamReceiver<C, Lc, F>
where
    C: StreamReceiveBuffer + ReceiveFlowControlPolicy + ReceiveTerminationPolicy<F>,
    F: RemoteResetFacts,
{
    /// The stream limit to advertise now, if any.
    ///
    /// It is the policy's target when that is above the opened stream limit
    /// and the stream still needs limit increases: no final size is known and
    /// the connection has not closed.
    pub fn advertisement(&self) -> Option<VarInt> {
        if self.closed().is_some() || self.parts.final_size().is_some() {
            return None;
        }
        match self.parts.advertisement_intent() {
            AdvertisementIntent::Withhold => None,
            AdvertisementIntent::Advertise { target_limit } => {
                (target_limit > self.opened_limit).then_some(target_limit)
            }
        }
    }

    /// Records that a stream limit of `limit` may have become visible to the
    /// peer, for example because a `MAX_STREAM_DATA` frame carrying it can no
    /// longer be withdrawn.
    ///
    /// The opened stream limit takes the larger of the old value and
    /// `limit`; from now on input up to it is accepted. The policy observes
    /// [`ReceiveFlowEvent::LimitOpened`] when the limit grew.
    pub fn open_limit(&mut self, limit: VarInt) {
        if limit > self.opened_limit {
            self.opened_limit = limit;
            self.notify_flow(ReceiveFlowEvent::LimitOpened);
        }
    }
}
