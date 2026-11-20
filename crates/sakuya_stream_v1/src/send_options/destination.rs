//! Where data is sent and where it falls back to: the send destination
//! ([`SendDestination`], [`StreamSendDestination`]) and the destination of
//! content any active link path may send ([`AnyActiveLinkPath`]).
//!
//! A destination remembers where its data goes first and where it goes once
//! sending there failed, and may move on at each failure; at any one time
//! it has a single current destination ([`SendDestination::current`]). The
//! fallback is the destination's own decision: the send buffer only tells
//! it what happened, then groups the data by the new current destination.

/// A send destination (`SendDestination`): where data goes now, and where it
/// goes once an intent to send it there was not fulfilled.
///
/// Datagrams use this trait as it is; the data of a stream also falls back
/// on loss ([`StreamSendDestination`]).
pub trait SendDestination {
    /// The destination at this time, which a send intent is published to.
    type Current;

    /// The destination at this time.
    fn current(&self) -> Self::Current;

    /// The intent to send to [`current`](Self::current) was not fulfilled
    /// for `cause`. Returns whether the destination fell back to another
    /// one, which `current` gives from now on, or has none left.
    fn on_unfulfilled(&mut self, cause: Unfulfilled) -> DestinationFallback;
}

/// The send destination of stream data (`StreamSendDestination`): it also
/// falls back when data sent to it was lost.
pub trait StreamSendDestination: SendDestination {
    /// Data sent to [`current`](SendDestination::current) was declared
    /// lost. Returns whether the destination fell back to another one, which
    /// `current` gives from now on, or has none left.
    fn on_lost(&mut self) -> DestinationFallback;
}

/// Why a send intent was not fulfilled (`Unfulfilled`).
///
/// The end of the layer is not among them: a stream learns it from the end
/// of its layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Unfulfilled {
    /// The send strategy rejected the intent when it was published.
    Rejected,
    /// The send strategy ended the intent after it had taken it.
    Ended,
}

/// What a destination did after a failure (`DestinationFallback`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DestinationFallback {
    /// It moved to the next destination, or stays where it was if that is
    /// where it falls back to; the data is sent to the current destination
    /// again.
    Degraded,
    /// No destination is left to fall back to.
    Exhausted,
}

/// The destination of content any active link path may send, including one
/// that becomes active later. A component whose intents go there asks for
/// `S::Destination: From<AnyActiveLinkPath>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct AnyActiveLinkPath;

/// Any active link path never falls back to anything narrower: there is no
/// destination behind it to fall back to, and it is still where the data
/// goes. A failure therefore reports [`DestinationFallback::Degraded`] and
/// [`current`](SendDestination::current) stays [`AnyActiveLinkPath`], so the
/// data is sent to any active link path again.
impl SendDestination for AnyActiveLinkPath {
    type Current = Self;

    fn current(&self) -> Self {
        Self
    }

    fn on_unfulfilled(&mut self, _: Unfulfilled) -> DestinationFallback {
        DestinationFallback::Degraded
    }
}

/// Loss does not narrow it either, as for
/// [`on_unfulfilled`](SendDestination::on_unfulfilled).
impl StreamSendDestination for AnyActiveLinkPath {
    fn on_lost(&mut self) -> DestinationFallback {
        DestinationFallback::Degraded
    }
}
