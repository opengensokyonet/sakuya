//! The error QUIC version 1 finds in a connection.
use core::convert::Infallible;

use bytes::Bytes;
use sakuya_wire::{
    parts::CNil,
    v1::{
        encryption_level::EncryptionLevel,
        frame::{
            FrameType,
            codec::ReadFieldsError,
            set::{FrameFieldsError, codec::ReadFrameError},
        },
        transport_error::TransportErrorCode,
    },
    var_int::VarInt,
};
use snafu::Snafu;

use super::{close::TransportClose, crypto::CryptoFrameError, dispatch::FrameNotPermittedError};

/// An error of version 1 in a connection: one variant for each type of
/// error it comes from, which gives the transport error code; a failure
/// without a type of its own has its fields here.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum ConnectionError {
    /// A packet carries no frames (RFC 9000 §12.4).
    #[snafu(display("a packet at the {level:?} level has no frames"))]
    EmptyPacket {
        /// The level of the packet.
        level: EncryptionLevel,
    },
    /// A packet has a reserved bit of its first byte set once both layers
    /// of protection are removed (RFC 9000 §17.2, §17.3.1).
    #[snafu(display("a packet at the {level:?} level has reserved bits set"))]
    ReservedBitsSet {
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
    /// The Frame Type of a frame could not be read, is not the shortest
    /// encoding of its value, or is a value no part of the connection
    /// claims (RFC 9000 §12.4).
    #[snafu(display("frame read failed"))]
    ReadFrame {
        /// The failure.
        source: ReadFrameError<Infallible, CNil>,
    },
    /// The fields of a frame of version 1 could not be read.
    #[snafu(display("frame fields read failed"))]
    ReadFrameFields {
        /// The failure.
        source: ReadFieldsError<Infallible>,
    },
    /// A frame is in a packet type it cannot appear in, or reached an
    /// endpoint whose role does not receive it.
    #[snafu(display("frame not permitted"))]
    FrameNotPermitted {
        /// The broken rule.
        source: FrameNotPermittedError,
    },
    /// A CRYPTO frame broke a rule of receiving CRYPTO data.
    #[snafu(display("CRYPTO frame rejected"))]
    Crypto {
        /// The broken rule.
        source: CryptoFrameError,
    },
    /// A frame of a kind this version does not handle yet; the connection
    /// closes with INTERNAL_ERROR. It goes away as the components that
    /// handle each kind are added.
    #[snafu(display("{kind:?} frames are not handled"))]
    UnhandledFrame {
        /// The kind of the frame.
        kind: FrameType,
    },
}

/// The Frame Type field holds the type of the frame that failed when it is
/// known, and is 0 otherwise. The reason phrase is what this layer shows, without its sources: a
/// description of the violation, for the peer, with nothing internal to
/// this endpoint.
impl TransportClose for ConnectionError {
    fn code(&self) -> TransportErrorCode {
        match self {
            Self::EmptyPacket { .. } | Self::ReservedBitsSet { .. } => {
                TransportErrorCode::PROTOCOL_VIOLATION
            }
            Self::NoViablePath => TransportErrorCode::NO_VIABLE_PATH,
            Self::OneRttSendKeysMissing | Self::UnhandledFrame { .. } => {
                TransportErrorCode::INTERNAL_ERROR
            }
            Self::ReadFrame { source } => source.transport_error_code(),
            Self::ReadFrameFields { source } => source.transport_error_code(),
            Self::FrameNotPermitted { .. } => TransportErrorCode::PROTOCOL_VIOLATION,
            Self::Crypto { source } => match source {
                CryptoFrameError::BufferExceeded { .. } => {
                    TransportErrorCode::CRYPTO_BUFFER_EXCEEDED
                }
                CryptoFrameError::BeyondReceivedEnd { .. } => {
                    TransportErrorCode::PROTOCOL_VIOLATION
                }
                CryptoFrameError::Refused => TransportErrorCode::crypto_error(UNEXPECTED_MESSAGE),
            },
        }
    }

    fn frame_type(&self) -> Option<VarInt> {
        match self {
            Self::ReadFrame { source } => source.frame_type(),
            Self::ReadFrameFields { source } => Some(source.frame_type()),
            Self::Crypto { .. } => Some(VarInt::from_u32(CRYPTO_FRAME_TYPE)),
            Self::EmptyPacket { .. }
            | Self::ReservedBitsSet { .. }
            | Self::NoViablePath
            | Self::OneRttSendKeysMissing
            | Self::FrameNotPermitted { .. }
            | Self::UnhandledFrame { .. } => None,
        }
    }

    fn reason_phrase(&self) -> Bytes {
        Bytes::from(self.to_string())
    }
}

/// The Frame Type of CRYPTO (RFC 9000 §19.6).
const CRYPTO_FRAME_TYPE: u32 = 0x06;

/// The TLS alert unexpected_message (RFC 9846 §6.2): a server receives no
/// handshake messages at 1-RTT (RFC 9001 §6).
const UNEXPECTED_MESSAGE: u8 = 10;

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
