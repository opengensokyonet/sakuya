//! Receiving a stateless reset ([RFC 9000 §10.3]).
//!
//! Routing recognizes a stateless reset before it classifies a datagram,
//! by the tokens of the peer's connection IDs this side used; the target a
//! token was registered for is the [`StatelessResetSignal`] of the logical
//! path the connection ID belongs to. Routing only marks the signal and
//! wakes whoever waits on it; it does not touch the connection's state.
//! The logical path's receiving call waits on it, and once it is marked
//! drains the connection ([`input`](super::input)).
//!
//! [RFC 9000 §10.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-10.3

use core::{
    sync::atomic::{AtomicBool, Ordering},
    task::Waker,
};

use futures_util::task::AtomicWaker;
use sakuya_datagram_routing::route::reset::StatelessResetTarget;

/// The mark that a stateless reset was received for a logical path, shared
/// between the logical path's node and routing.
#[derive(Debug, Default)]
pub struct StatelessResetSignal {
    received: AtomicBool,
    waker: AtomicWaker,
}

impl StatelessResetSignal {
    /// No reset received yet, and nothing waiting.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a stateless reset was received.
    pub fn received(&self) -> bool {
        self.received.load(Ordering::Acquire)
    }

    /// Wake `waker` when a stateless reset is received; it replaces the
    /// waker registered before.
    pub fn register(&self, waker: &Waker) {
        self.waker.register(waker);
    }
}

/// Routing marks the signal and wakes what waits on it.
impl StatelessResetTarget for StatelessResetSignal {
    fn stateless_reset_received(&self) {
        self.received.store(true, Ordering::Release);
        self.waker.wake();
    }
}
