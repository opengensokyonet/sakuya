//! The receive flow control policy: when to advertise a higher stream limit.
//!
//! This crate provides no implementation of the policy. The events and the
//! view it observes are provisional.
//!
//! The policy keeps an intent: advertise nothing, or advertise up to an
//! absolute target limit. Events update it; a query returns the current
//! intent and creates no request that must be honoured separately, so a new
//! intent simply replaces the old one while the old one is still revocable.
//!
//! The stream receive component keeps a separate fact, the stream limit
//! opened to the peer: the highest limit that may be visible to the peer,
//! starting from the transport parameters. It only grows
//! ([RFC 9000 §4.1]); input beyond it is a protocol violation. Replacing or
//! withdrawing an intent never lowers it.
//!
//! [RFC 9000 §4.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-4.1
use super::{BoundaryMode, StreamReceiver, termination::ReceiveTerminationPolicy};
use crate::receive_buffer::StreamReceiveBuffer;
use sakuya_wire::var_int::VarInt;

/// The events a receive flow control policy observes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReceiveFlowEvent {
    /// A STREAM or reset frame was accepted; the accounted end may or may not
    /// have grown.
    Received,
    /// Data was delivered to the application.
    Delivered,
    /// A local delivery limit was fixed or tightened.
    BoundaryChanged,
    /// The receive buffer was destroyed.
    BufferDestroyed,
    /// The stream limit opened to the peer grew.
    LimitOpened,
    /// The peer sent `STREAM_DATA_BLOCKED` at `limit`.
    PeerBlocked {
        /// The limit the peer reports being blocked at.
        limit: VarInt,
    },
    /// The stream reader was dropped.
    ReaderDropped,
}

/// The state a receive flow control policy decides on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReceiveFlowView {
    /// The stream limit opened to the peer.
    pub opened_limit: VarInt,
    /// The accounted end.
    pub accounted_end: VarInt,
    /// How far data has been delivered to the application.
    pub delivered_end: VarInt,
    /// The final size, if known.
    pub final_size: Option<VarInt>,
    /// The data acceptance limit.
    pub acceptance: BoundaryMode,
    /// The delivery limit.
    pub delivery: BoundaryMode,
    /// Whether the receive buffer is destroyed.
    pub destroyed: bool,
    /// Whether the reader was dropped.
    pub reader_dropped: bool,
}

/// The current advertisement intent of a receive flow control policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum AdvertisementIntent {
    /// Advertise nothing.
    #[default]
    Withhold,
    /// Advertise a stream limit of `target_limit`.
    Advertise {
        /// The absolute stream limit to advertise, not an increment.
        target_limit: VarInt,
    },
}

/// Stream-level receive flow control decisions.
pub trait ReceiveFlowControlPolicy {
    /// Observes `event`, given the state after it, and updates the intent.
    fn on_receive_flow_event(&mut self, event: ReceiveFlowEvent, view: &ReceiveFlowView);

    /// The current intent. Querying it changes nothing.
    fn advertisement_intent(&self) -> AdvertisementIntent;
}

impl<C> StreamReceiver<C>
where
    C: StreamReceiveBuffer + ReceiveFlowControlPolicy + ReceiveTerminationPolicy,
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
