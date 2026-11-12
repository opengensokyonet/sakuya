//! The error QUIC version 1 finds in a connection.
use bytes::Bytes;
use sakuya_wire::{
    v1::{encryption_level::EncryptionLevel, transport_error::TransportErrorCode},
    var_int::VarInt,
};
use snafu::Snafu;

use super::close::TransportClose;

/// An error of version 1 in a connection: one variant for each type of
/// error it comes from, which gives the transport error code; a failure
/// without a type of its own has its fields here.
#[derive(Debug, PartialEq, Eq, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum ConnectionError {
    /// A packet carries no frames (RFC 9000 §12.4).
    #[snafu(display("a packet at the {level:?} level has no frames"))]
    EmptyPacket {
        /// The level of the packet.
        level: EncryptionLevel,
    },
    /// No link path of the connection can send after one stopped sending
    /// (RFC 9000 §14.2).
    #[snafu(display("no link path can send"))]
    NoViablePath,
    /// The handshake completed without the 1-RTT keys for sending.
    #[snafu(display("the handshake completed without 1-RTT send keys"))]
    OneRttSendKeysMissing,
}

/// None of these failures is in a frame: the Frame Type field is 0. The
/// reason phrase is what this layer shows, without its sources: a
/// description of the violation, for the peer, with nothing internal to
/// this endpoint.
impl TransportClose for ConnectionError {
    fn code(&self) -> TransportErrorCode {
        match self {
            Self::EmptyPacket { .. } => TransportErrorCode::PROTOCOL_VIOLATION,
            Self::NoViablePath => TransportErrorCode::NO_VIABLE_PATH,
            Self::OneRttSendKeysMissing => TransportErrorCode::INTERNAL_ERROR,
        }
    }

    fn frame_type(&self) -> Option<VarInt> {
        None
    }

    fn reason_phrase(&self) -> Bytes {
        Bytes::from(self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reason_phrase_describes_the_violation() {
        let error = ConnectionError::EmptyPacket {
            level: EncryptionLevel::Handshake,
        };
        assert_eq!(
            error.immediate_close().reason_phrase,
            Bytes::from_static(b"a packet at the Handshake level has no frames")
        );
    }
}
