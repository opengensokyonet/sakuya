//! Whether the handshake is confirmed.

use super::component_events::HandshakeConfirmed;
use crate::component_event::Happened;

/// Whether the handshake is confirmed (RFC 9001 §4.1.2), as this side
/// knows it.
///
/// A connection starts not confirmed. A server's handshake is confirmed
/// when it completes; a client's when it receives HANDSHAKE_DONE. A client
/// does not take an acknowledgment of a 1-RTT packet it sent as
/// confirming it, which RFC 9001 §4.1.2 allows. Until then a client arms the
/// probe timeout even with nothing in flight (RFC 9002 §6.2.2.1), and the
/// probe timeout does not cover the Application Data space (§6.2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeConfirmation {
    /// Not confirmed yet.
    NotConfirmed,
    /// Confirmed.
    Confirmed,
}

impl HandshakeConfirmation {
    /// Confirm the handshake. What happened, when it was not confirmed
    /// before.
    #[must_use = "what happened is to be published in the lend"]
    pub fn confirm(&mut self) -> Option<Happened<HandshakeConfirmed>> {
        if *self == Self::Confirmed {
            return None;
        }
        *self = Self::Confirmed;
        Some(Happened::new())
    }
}
