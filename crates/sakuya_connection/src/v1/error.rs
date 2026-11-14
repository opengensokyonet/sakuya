//! The error QUIC version 1 finds in a connection.
use core::convert::Infallible;

use bytes::Bytes;
use sakuya_recovery::packet_number_space::PacketNumberSpaceKind;
use sakuya_wire::{
    parts::CNil,
    v1::{
        encryption_level::EncryptionLevel,
        frame::{
            FrameType,
            codec::ReadFieldsError,
            set::{FrameFieldsError, codec::ReadFrameError},
        },
        packet_number::PacketNumber,
        transport_error::TransportErrorCode,
    },
    var_int::VarInt,
};
use snafu::Snafu;

use crate::connection_id::violation::NewConnectionIdViolationError;

use super::{
    aead_usage::AeadLimitReachedError,
    close::TransportClose,
    crypto::{CryptoFrameError, CryptoLevelMoveError, send::CryptoDataEndError},
    dispatch::FrameNotPermittedError,
    key_update::KeyUpdateError,
    parameters::PeerTransportParametersError,
};

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
    /// The handshake engine could not move the CRYPTO data it reads to
    /// another level.
    #[snafu(display("CRYPTO input level not moved"))]
    CryptoLevelMove {
        /// The broken rule.
        source: CryptoLevelMoveError,
    },
    /// The handshake engine wrote CRYPTO data past the largest offset.
    #[snafu(display("CRYPTO output beyond the largest offset"))]
    CryptoDataEnd {
        /// The failure.
        source: CryptoDataEndError,
    },
    /// The peer's transport parameters failed the checks of version 1 (RFC
    /// 9000 §7.3, §7.4).
    #[snafu(display("peer transport parameters rejected"))]
    PeerTransportParameters {
        /// The failed check.
        source: PeerTransportParametersError,
    },
    /// The connection reached a limit on the use of its AEAD (RFC 9001
    /// §6.6): it closes at once and processes no more packets.
    #[snafu(display("AEAD limit reached"))]
    AeadLimitReached {
        /// The limit reached.
        source: AeadLimitReachedError,
    },
    /// The peer broke a rule of 1-RTT key updates (RFC 9001 §6.2).
    #[snafu(display("key update rule broken"))]
    KeyUpdate {
        /// The broken rule.
        source: KeyUpdateError,
    },
    /// An ACK frame acknowledges a packet number its packet number space
    /// has not sent yet (RFC 9000 §13.1).
    #[snafu(display(
        "an ACK frame of the {space:?} space acknowledges packet {largest}, \
         and the next packet sent there is {next}"
    ))]
    UnsentPacketAcknowledged {
        /// The packet number space of the frame.
        space: PacketNumberSpaceKind,
        /// The frame's Largest Acknowledged.
        largest: PacketNumber,
        /// The packet number the next packet sent in the space gets.
        next: PacketNumber,
        /// Whether the frame carries ECN counts: its type is `0x03` rather
        /// than `0x02`.
        ecn_counts: bool,
    },
    /// A NEW_CONNECTION_ID frame broke a rule the destination connection ID
    /// strategy checks.
    #[snafu(display("NEW_CONNECTION_ID frame rejected"))]
    NewConnectionId {
        /// The broken rule.
        source: NewConnectionIdViolationError,
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
            Self::EmptyPacket { .. }
            | Self::ReservedBitsSet { .. }
            | Self::UnsentPacketAcknowledged { .. } => TransportErrorCode::PROTOCOL_VIOLATION,
            Self::NoViablePath => TransportErrorCode::NO_VIABLE_PATH,
            Self::OneRttSendKeysMissing | Self::UnhandledFrame { .. } => {
                TransportErrorCode::INTERNAL_ERROR
            }
            Self::ReadFrame { source } => source.transport_error_code(),
            Self::ReadFrameFields { source } => source.transport_error_code(),
            Self::FrameNotPermitted { .. } => TransportErrorCode::PROTOCOL_VIOLATION,
            Self::AeadLimitReached { .. } => TransportErrorCode::AEAD_LIMIT_REACHED,
            Self::KeyUpdate { .. } => TransportErrorCode::KEY_UPDATE_ERROR,
            Self::NewConnectionId { source } => source.transport_error_code(),
            Self::CryptoLevelMove { source } => match source {
                CryptoLevelMoveError::UnreadBytes { .. } => TransportErrorCode::PROTOCOL_VIOLATION,
                CryptoLevelMoveError::NotForward { .. } => TransportErrorCode::INTERNAL_ERROR,
            },
            Self::CryptoDataEnd { .. } => TransportErrorCode::INTERNAL_ERROR,
            Self::PeerTransportParameters { .. } => TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
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
            Self::NewConnectionId { .. } => Some(VarInt::from_u32(NEW_CONNECTION_ID_FRAME_TYPE)),
            Self::UnsentPacketAcknowledged { ecn_counts, .. } => {
                Some(VarInt::from_u32(if *ecn_counts {
                    ACK_ECN_FRAME_TYPE
                } else {
                    ACK_FRAME_TYPE
                }))
            }
            Self::EmptyPacket { .. }
            | Self::ReservedBitsSet { .. }
            | Self::NoViablePath
            | Self::OneRttSendKeysMissing
            | Self::FrameNotPermitted { .. }
            | Self::AeadLimitReached { .. }
            | Self::KeyUpdate { .. }
            | Self::CryptoLevelMove { .. }
            | Self::CryptoDataEnd { .. }
            | Self::PeerTransportParameters { .. }
            | Self::UnhandledFrame { .. } => None,
        }
    }

    fn reason_phrase(&self) -> Bytes {
        Bytes::from(self.to_string())
    }
}

/// The Frame Type of CRYPTO (RFC 9000 §19.6).
const CRYPTO_FRAME_TYPE: u32 = 0x06;

/// The Frame Type of NEW_CONNECTION_ID (RFC 9000 §19.15).
const NEW_CONNECTION_ID_FRAME_TYPE: u32 = 0x18;

/// The Frame Type of ACK without ECN counts (RFC 9000 §19.3).
const ACK_FRAME_TYPE: u32 = 0x02;

/// The Frame Type of ACK with ECN counts (RFC 9000 §19.3).
const ACK_ECN_FRAME_TYPE: u32 = 0x03;

/// The TLS alert unexpected_message (RFC 9846 §6.2): a server receives no
/// handshake messages at 1-RTT (RFC 9001 §6).
const UNEXPECTED_MESSAGE: u8 = 10;

#[cfg(test)]
mod tests {
    use sakuya_packet_protection::backend::AeadAlgorithm;

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

    #[test]
    fn an_ack_of_a_packet_not_sent_is_a_protocol_violation_of_its_frame_type() {
        let error = |ecn_counts| ConnectionError::UnsentPacketAcknowledged {
            space: PacketNumberSpaceKind::Handshake,
            largest: PacketNumber::new(7).unwrap(),
            next: PacketNumber::new(5).unwrap(),
            ecn_counts,
        };
        assert_eq!(error(false).code(), TransportErrorCode::PROTOCOL_VIOLATION);
        assert_eq!(error(false).frame_type(), Some(VarInt::from_u32(0x02)));
        assert_eq!(error(true).frame_type(), Some(VarInt::from_u32(0x03)));
    }

    #[test]
    fn the_aead_limit_closes_with_aead_limit_reached() {
        let error = ConnectionError::AeadLimitReached {
            source: AeadLimitReachedError::IntegrityLimitExceeded {
                aead: AeadAlgorithm::Aes128Gcm,
            },
        };
        assert_eq!(error.code(), TransportErrorCode::AEAD_LIMIT_REACHED);
        assert_eq!(error.frame_type(), None);
        let error = ConnectionError::AeadLimitReached {
            source: AeadLimitReachedError::ConfidentialityLimitReached,
        };
        assert_eq!(error.code(), TransportErrorCode::AEAD_LIMIT_REACHED);
    }

    #[test]
    fn a_broken_key_update_rule_closes_with_key_update_error() {
        let error = ConnectionError::KeyUpdate {
            source: KeyUpdateError::ConsecutiveUpdates {
                trigger: PacketNumber::new(4).unwrap(),
                number: PacketNumber::new(9).unwrap(),
            },
        };
        assert_eq!(error.code(), TransportErrorCode::KEY_UPDATE_ERROR);
        assert_eq!(error.frame_type(), None);
        assert_eq!(
            error.immediate_close().reason_phrase,
            Bytes::from_static(b"key update rule broken")
        );
    }
}
