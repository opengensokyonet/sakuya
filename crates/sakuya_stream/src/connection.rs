//! Facts about the connection that both directions of a stream report.
use bytes::Bytes;
use core::fmt;
use sakuya_wire::application_error::ApplicationErrorCode;
use sakuya_wire::transport_error::TransportErrorCode;
use sakuya_wire::var_int::VarInt;
use snafu::Snafu;

/// The connection is closed: no operation on its streams proceeds.
///
/// The send direction and the receive direction report it through their
/// own errors, which hold this one as their source. It carries why the
/// connection closed.
#[derive(Clone, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("the connection is closed: {reason}"))]
pub struct ConnectionClosedError {
    reason: CloseReason,
}

impl ConnectionClosedError {
    /// The error for a connection that closed for `reason`.
    ///
    /// This constructor is provisional.
    pub const fn new(reason: CloseReason) -> Self {
        Self { reason }
    }

    /// Why the connection closed.
    pub const fn reason(&self) -> &CloseReason {
        &self.reason
    }
}

/// Why a connection closed.
///
/// A close of this endpoint and a close of the peer are told apart; the
/// other reasons end the connection without a CONNECTION_CLOSE frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// This endpoint closed the connection.
    ///
    /// The close records this endpoint's intent, not the frames sent for it:
    /// in Initial and Handshake packets an application close goes out as a
    /// transport close without its reason phrase
    /// ([RFC 9000 §10.2.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2.3)),
    /// so the frames of one close can differ.
    Local(ImmediateClose),
    /// The peer closed the connection with a CONNECTION_CLOSE frame.
    Peer(ImmediateClose),
    /// This endpoint's idle timer expired. An idle timeout of the peer is
    /// not observable here.
    IdleTimeout,
    /// A valid stateless reset was received.
    StatelessReset,
    /// The client has no version in common with the server's Version
    /// Negotiation packet. Only a client closes for this reason.
    VersionNegotiation,
    /// This endpoint ended the connection without sending a close.
    Aborted,
}

/// The contents of an immediate close: the error fields and the reason
/// phrase of a CONNECTION_CLOSE frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImmediateClose {
    /// An error of the QUIC layer (type `0x1c`).
    Transport {
        /// The transport error code.
        code: TransportErrorCode,
        /// The value of the Frame Type field: the type of the frame that
        /// triggered the error, `None` if it is unknown (the field is 0).
        frame_type: Option<VarInt>,
        /// The reason phrase.
        reason_phrase: Bytes,
    },
    /// A close of the application (type `0x1d`).
    Application {
        /// The application protocol error code.
        code: ApplicationErrorCode,
        /// The reason phrase.
        reason_phrase: Bytes,
    },
}

impl fmt::Display for CloseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local(close) => write!(f, "closed locally with {close}"),
            Self::Peer(close) => write!(f, "closed by the peer with {close}"),
            Self::IdleTimeout => f.write_str("idle timeout"),
            Self::StatelessReset => f.write_str("stateless reset received"),
            Self::VersionNegotiation => f.write_str("no version in common with the server"),
            Self::Aborted => f.write_str("ended without a close"),
        }
    }
}

impl fmt::Display for ImmediateClose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport {
                code,
                frame_type: Some(frame_type),
                ..
            } => write!(
                f,
                "transport error {code} in frame type {:#x}",
                frame_type.get()
            ),
            Self::Transport {
                code,
                frame_type: None,
                ..
            } => write!(f, "transport error {code}"),
            Self::Application { code, .. } => write!(f, "application error {code}"),
        }
    }
}
