//! Whether the handshake is confirmed.

/// Whether the handshake is confirmed (RFC 9001 §4.1.2), as this side
/// knows it.
///
/// A connection starts not confirmed. A server's handshake is confirmed
/// when it completes; a client's when it receives HANDSHAKE_DONE, or an
/// acknowledgment of a 1-RTT packet it sent. Until then a client arms the
/// probe timeout even with nothing in flight (RFC 9002 §6.2.2.1), and the
/// probe timeout does not cover the Application Data space (§6.2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeConfirmation {
    /// Not confirmed yet.
    NotConfirmed,
    /// Confirmed.
    Confirmed,
}
