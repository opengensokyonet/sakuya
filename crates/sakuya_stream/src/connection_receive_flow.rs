//! The connection receive flow controller: connection-wide accounting of the
//! stream data the peer has sent.
//!
//! [RFC 9000 §4.1] limits the sum of all streams' flow-control usage to the
//! connection limit this endpoint has advertised (`initial_max_data`, then
//! `MAX_DATA`). Each stream's usage is its accounted end, the highest end
//! offset or final size it has received; the stream receive component reports
//! how much its accounted end grew, and this controller adds that to the
//! connection's usage. Receiving beyond the advertised limit is a protocol
//! error of the peer, not back-pressure to wait out.
//!
//! [RFC 9000 §4.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-4.1
use sakuya_wire::var_int::VarInt;
use snafu::{Snafu, ensure};

/// Connection-wide receive accounting: the advertised limit, the cumulative
/// usage of all streams and the cumulative released progress.
///
/// Status: the state is the minimal candidate of the design (`limit`, `used`,
/// `released`); the name is proposed and the connection-level window growth
/// (when and how far to raise the limit, sending `MAX_DATA`) is not part of
/// this type.
///
/// - `limit` is the highest connection limit that may have become visible to
///   the peer. It only grows.
/// - `used` is the sum of the accounted ends of all streams of the
///   connection. Reading or discarding data does not lower it, and closed
///   streams keep their contribution.
/// - `released` is cumulative progress of data that no longer needs to be
///   held for the application, input to a window-growth policy. It is not
///   memory that was freed and is never subtracted from `used`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionReceiveFlowController {
    limit: VarInt,
    used: VarInt,
    released: VarInt,
}

impl ConnectionReceiveFlowController {
    /// Creates the controller with the connection limit this endpoint sent as
    /// `initial_max_data`.
    pub fn new(initial_limit: VarInt) -> Self {
        Self {
            limit: initial_limit,
            used: VarInt::ZERO,
            released: VarInt::ZERO,
        }
    }

    /// The highest connection limit that may be visible to the peer.
    pub fn limit(&self) -> VarInt {
        self.limit
    }

    /// The cumulative usage of all streams.
    pub fn used(&self) -> VarInt {
        self.used
    }

    /// The cumulative released progress.
    pub fn released(&self) -> VarInt {
        self.released
    }

    /// Records that `limit` may have become visible to the peer.
    ///
    /// The limit takes the larger of the old value and `limit`; returns
    /// whether it grew.
    pub fn raise_limit(&mut self, limit: VarInt) -> bool {
        let grew = limit > self.limit;
        self.limit = self.limit.max(limit);
        grew
    }

    /// Adds `increase` to the usage.
    ///
    /// # Errors
    ///
    /// Fails, without changing the usage, if the new usage would exceed the
    /// limit; the peer has then violated connection-level flow control
    /// (`FLOW_CONTROL_ERROR`).
    pub fn record_usage(&mut self, increase: VarInt) -> Result<(), RecordUsageError> {
        let used = self.used.checked_add(increase);
        let error = RecordUsageSnafu {
            used: self.used,
            increase,
            limit: self.limit,
        };
        let used = used.ok_or_else(|| error.build())?;
        ensure!(used <= self.limit, error);
        self.used = used;
        Ok(())
    }

    /// Adds `increase` to the released progress.
    ///
    /// # Panics
    ///
    /// Panics if the released progress would exceed the usage: a stream can
    /// release only what it has accounted.
    pub fn record_release(&mut self, increase: VarInt) {
        let released = self
            .released
            .checked_add(increase)
            .filter(|released| *released <= self.used)
            .expect("released progress exceeds connection usage");
        self.released = released;
    }
}

/// [`ConnectionReceiveFlowController::record_usage`] would exceed the
/// advertised connection limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "stream data of the connection would reach {used} + {increase}, beyond the advertised limit {limit}"
))]
pub struct RecordUsageError {
    /// The usage before the rejected increase.
    pub used: VarInt,
    /// The rejected increase.
    pub increase: VarInt,
    /// The advertised connection limit.
    pub limit: VarInt,
}

#[cfg(test)]
mod tests;
