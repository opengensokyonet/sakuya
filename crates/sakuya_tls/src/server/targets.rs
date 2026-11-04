//! The target a ClientHello asks for.

use crate::extension::alpn::ProtocolName;
use bytes::Bytes;

/// A selected target: what the server serves on this connection, with the
/// application protocol negotiated for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selected<T> {
    /// The target.
    pub target: T,
    /// The application protocol, `None` when the connection negotiates
    /// none.
    pub application_protocol: Option<ProtocolName<Bytes>>,
}
