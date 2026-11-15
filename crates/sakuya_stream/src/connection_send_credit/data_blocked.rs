//! When to send the connection-level `DATA_BLOCKED` frame
//! ([RFC 9000 §19.12]): once for each connection limit.
//!
//! [RFC 9000 §19.12]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.12
use crate::blocked_signal::BlockedSignal;
use sakuya_wire::var_int::VarInt;

/// The intent to send `DATA_BLOCKED`, once for each connection limit.
///
/// - The intent arises only when a write was actually held back by
///   connection credit ([`on_write_blocked`](Self::on_write_blocked)), not
///   when a stream limit or the flow control policy held it back.
/// - Once a frame carrying a limit was sent, no other is wanted for that
///   limit.
/// - A higher limit (`MAX_DATA`) clears the intent left from a lower one.
///
/// Sending the frame again when it is lost or after some time is not part of
/// this type. It keeps no counters of its own: the limit comes from the
/// connection send flow controller at each call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DataBlockedSignal {
    signal: BlockedSignal<VarInt>,
}

impl DataBlockedSignal {
    /// Creates the signal with no intent.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that a write was held back by connection credit while the
    /// connection limit was `limit`
    /// ([`WriteWait::ConnectionCredit`](crate::send::write::WriteWait::ConnectionCredit)).
    pub fn on_write_blocked(&mut self, limit: VarInt) {
        self.signal.on_blocked(limit);
    }

    /// Records that a `DATA_BLOCKED` frame carrying `limit` was sent.
    pub fn on_sent(&mut self, limit: VarInt) {
        self.signal.on_sent(limit);
    }

    /// Records that the connection limit grew to `limit`, for example by a
    /// `MAX_DATA` frame.
    pub fn on_limit_raised(&mut self, limit: VarInt) {
        self.signal.on_limit_raised(limit);
    }

    /// The limit to send in `DATA_BLOCKED` now, if any.
    pub fn wanted(&self) -> Option<VarInt> {
        self.signal.wanted()
    }
}

#[cfg(test)]
mod tests;
