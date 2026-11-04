//! Facts about the connection that both directions of a stream report.
use snafu::Snafu;

/// The connection is closed: no operation on its streams proceeds.
///
/// The send direction and the receive direction report it through their
/// own errors, which hold this one as their source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("the connection is closed"))]
pub struct ConnectionClosedError {
    // Leaves room for details of the close.
    _private: (),
}

impl ConnectionClosedError {
    /// The error for a closed connection.
    ///
    /// This constructor is provisional.
    pub const fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for ConnectionClosedError {
    fn default() -> Self {
        Self::new()
    }
}
