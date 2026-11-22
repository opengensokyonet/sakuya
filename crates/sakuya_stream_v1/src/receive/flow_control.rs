//! The receive flow control policy: when to advertise a higher stream limit.
//!
//! [`SlidingWindowAdvertisement`] implements it with a fixed window that
//! slides with delivery; it is the policy of the default receive composition
//! ([`SlidingWindowAdvertisement`]). The events and the view a policy
//! observes are provisional.
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
use super::BoundaryMode;
use sakuya_wire_v1::var_int::VarInt;

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

impl ReceiveFlowView {
    /// A view with the given facts, as the stream receiver presents it.
    #[expect(
        clippy::too_many_arguments,
        reason = "one argument per field of the view"
    )]
    pub fn new(
        opened_limit: VarInt,
        accounted_end: VarInt,
        delivered_end: VarInt,
        final_size: Option<VarInt>,
        acceptance: BoundaryMode,
        delivery: BoundaryMode,
        destroyed: bool,
        reader_dropped: bool,
    ) -> Self {
        Self {
            opened_limit,
            accounted_end,
            delivered_end,
            final_size,
            acceptance,
            delivery,
            destroyed,
            reader_dropped,
        }
    }
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

/// A receive flow control policy with a fixed window `W` that slides with
/// delivery.
///
/// The target is the delivered end plus `W`, an absolute stream limit. The
/// policy advertises it once it lies at least `W / 2` (rounded down) above
/// the stream limit opened to the peer, and withholds otherwise: with
/// `W` = 64 KiB and 64 KiB opened, delivering 20 KiB makes a target of
/// 84 KiB, which is withheld, and delivering 32 KiB makes one of 96 KiB,
/// which is advertised.
///
/// The intent is worked out afresh from the view at every event, so it never
/// grows from repeated events and an opened limit that reached the target
/// withdraws it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlidingWindowAdvertisement {
    window: VarInt,
    intent: AdvertisementIntent,
}

impl SlidingWindowAdvertisement {
    /// Creates the policy with the window `window`, for example the initial
    /// stream limit this endpoint advertised for streams of this type.
    pub fn new(window: VarInt) -> Self {
        Self {
            window,
            intent: AdvertisementIntent::Withhold,
        }
    }

    /// The window `W`.
    pub fn window(&self) -> VarInt {
        self.window
    }
}

impl ReceiveFlowControlPolicy for SlidingWindowAdvertisement {
    fn on_receive_flow_event(&mut self, _: ReceiveFlowEvent, view: &ReceiveFlowView) {
        self.intent =
            match sliding_window_target(view.delivered_end, view.opened_limit, self.window) {
                Some(target_limit) => AdvertisementIntent::Advertise { target_limit },
                None => AdvertisementIntent::Withhold,
            };
    }

    fn advertisement_intent(&self) -> AdvertisementIntent {
        self.intent
    }
}

/// The limit a fixed window `window` sliding with `progress` advertises over
/// the limit `advertised`: `progress + window`, saturating at the largest
/// offset, once it lies above `advertised` by at least `window / 2`.
pub(crate) fn sliding_window_target(
    progress: VarInt,
    advertised: VarInt,
    window: VarInt,
) -> Option<VarInt> {
    let target = progress.saturating_add(window);
    let threshold = window.get() / 2;
    (target > advertised && target.get() - advertised.get() >= threshold).then_some(target)
}

#[cfg(test)]
mod tests;
