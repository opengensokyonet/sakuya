//! The two endpoint roles of a QUIC connection ([RFC 9000 §1.2]).
//!
//! [RFC 9000 §1.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-1.2
use core::fmt;

/// Whether an endpoint initiated the connection or accepted it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    /// The endpoint that initiates the connection.
    Client,
    /// The endpoint that accepts the connection.
    Server,
}

impl Role {
    /// The role of the peer.
    pub const fn peer(self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }
}

/// Formats `client` or `server`.
impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Client => "client",
            Self::Server => "server",
        })
    }
}
