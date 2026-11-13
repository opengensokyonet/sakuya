//! Facts about the connection that both directions of a stream report.
use bytes::Bytes;
use core::fmt;
use sakuya_wire::v1::application_error::ApplicationErrorCode;
use sakuya_wire::v1::transport_error::TransportErrorCode;
use sakuya_wire::var_int::VarInt;
use sakuya_wire::version::Version;
use snafu::Snafu;
use std::sync::Arc;

/// The connection is closed: no operation on its streams proceeds.
///
/// The send direction and the receive direction report it through their
/// own errors, which hold this one as their source. It carries why the
/// connection closed; `C` is the type of this endpoint's reason for
/// closing, as in [`CloseReason`].
#[derive(Debug, PartialEq, Eq, Snafu)]
#[snafu(display("the connection is closed: {reason}"))]
pub struct ConnectionClosedError<C> {
    reason: CloseReason<C>,
}

impl<C> ConnectionClosedError<C> {
    /// The error for a connection that closed for `reason`.
    ///
    /// This constructor is provisional.
    pub const fn new(reason: CloseReason<C>) -> Self {
        Self { reason }
    }

    /// Why the connection closed.
    pub const fn reason(&self) -> &CloseReason<C> {
        &self.reason
    }
}

/// Every error reports the same reason, shared: cloning does not need `C`
/// to be [`Clone`].
impl<C> Clone for ConnectionClosedError<C> {
    fn clone(&self) -> Self {
        Self {
            reason: self.reason.clone(),
        }
    }
}

/// Why a connection closed.
///
/// A close of this endpoint and a close of the peer are told apart; the
/// other reasons end the connection without a CONNECTION_CLOSE frame. `C`
/// is the type of this endpoint's reason for closing: complete, with the
/// whole chain of its sources. A connection has one reason; everything that
/// reports it holds the same one.
#[derive(Debug, PartialEq, Eq)]
pub enum CloseReason<C> {
    /// This endpoint closed the connection, for the reason it holds, shared.
    ///
    /// The reason is what this endpoint found, not the frames sent for it:
    /// the frames are worked out from it, can be adjusted and truncated, and
    /// in Initial and Handshake packets an application close goes out as a
    /// transport close without its reason phrase
    /// ([RFC 9000 §10.2.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2.3)),
    /// so the frames of one close can differ from one another.
    Local(Arc<C>),
    /// The peer closed the connection with a CONNECTION_CLOSE frame, which
    /// is kept as it was received.
    Peer(ImmediateClose),
    /// This endpoint's idle timer expired. An idle timeout of the peer is
    /// not observable here.
    IdleTimeout,
    /// A valid stateless reset was received.
    StatelessReset,
    /// The client has no version in common with the server's Version
    /// Negotiation packet. Only a client closes for this reason.
    VersionNegotiation {
        /// The versions the server listed. Nothing authenticates a Version
        /// Negotiation packet: anyone on the path can have written the list.
        versions: Arc<[Version]>,
    },
    /// The client received a valid Retry packet and its policy gave up the
    /// connection attempt; nothing was sent. Only a client closes for this
    /// reason.
    #[doc(alias = "Retry")]
    RetryAbandoned,
    /// This endpoint ended the connection without sending a close, for the
    /// cause it holds.
    Aborted(AbortCause),
}

/// Why this endpoint ended a connection without sending a close.
///
/// None of the causes has an error to carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AbortCause {
    /// A panic unwound through the connection's driver.
    Panicked,
    /// The connection's driver was dropped before the connection ended and
    /// before any reason was recorded. A close the application asked for
    /// that the driver had not recorded yet is not the reason: the peer
    /// received nothing.
    DriverDropped,
    /// The connection did not form: at the deadline, no valid Initial
    /// packet was in the first datagrams. Only a server ends a connection
    /// for this cause.
    NoValidInitial,
}

impl fmt::Display for AbortCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Panicked => "a panic unwound through the connection's driver",
            Self::DriverDropped => "the connection's driver was dropped",
            Self::NoValidInitial => "no valid Initial packet arrived",
        })
    }
}

/// Every reporter gets the same reason: this endpoint's is shared, so
/// cloning does not need `C` to be [`Clone`].
impl<C> Clone for CloseReason<C> {
    fn clone(&self) -> Self {
        match self {
            Self::Local(cause) => Self::Local(Arc::clone(cause)),
            Self::Peer(close) => Self::Peer(close.clone()),
            Self::IdleTimeout => Self::IdleTimeout,
            Self::StatelessReset => Self::StatelessReset,
            Self::VersionNegotiation { versions } => Self::VersionNegotiation {
                versions: Arc::clone(versions),
            },
            Self::RetryAbandoned => Self::RetryAbandoned,
            Self::Aborted(cause) => Self::Aborted(*cause),
        }
    }
}

/// The contents of an immediate close: the error fields and the reason
/// phrase of a CONNECTION_CLOSE frame, of one of its two types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImmediateClose {
    /// An error of the QUIC layer (type `0x1c`).
    Transport(TransportImmediateClose),
    /// A close of the application (type `0x1d`).
    Application(ApplicationImmediateClose),
}

/// The contents of a CONNECTION_CLOSE frame of type `0x1c`: an error of the
/// QUIC layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportImmediateClose {
    /// The transport error code.
    pub code: TransportErrorCode,
    /// The value of the Frame Type field: the type of the frame that
    /// triggered the error, `None` if it is unknown (the field is 0).
    pub frame_type: Option<VarInt>,
    /// The reason phrase.
    pub reason_phrase: Bytes,
}

/// The contents of a CONNECTION_CLOSE frame of type `0x1d`: a close of the
/// application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationImmediateClose {
    /// The application protocol error code.
    pub code: ApplicationErrorCode,
    /// The reason phrase.
    pub reason_phrase: Bytes,
}

impl From<TransportImmediateClose> for ImmediateClose {
    fn from(close: TransportImmediateClose) -> Self {
        Self::Transport(close)
    }
}

impl From<ApplicationImmediateClose> for ImmediateClose {
    fn from(close: ApplicationImmediateClose) -> Self {
        Self::Application(close)
    }
}

impl<C: fmt::Display> fmt::Display for CloseReason<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local(cause) => write!(f, "closed locally: {cause}"),
            Self::Peer(close) => write!(f, "closed by the peer with {close}"),
            Self::IdleTimeout => f.write_str("idle timeout"),
            Self::StatelessReset => f.write_str("stateless reset received"),
            Self::VersionNegotiation { .. } => f.write_str("no version in common with the server"),
            Self::RetryAbandoned => {
                f.write_str("the connection attempt was given up after a Retry")
            }
            Self::Aborted(cause) => write!(f, "ended without a close: {cause}"),
        }
    }
}

impl fmt::Display for ImmediateClose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(close) => close.fmt(f),
            Self::Application(close) => close.fmt(f),
        }
    }
}

impl fmt::Display for TransportImmediateClose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.frame_type {
            Some(frame_type) => write!(
                f,
                "transport error {} in frame type {:#x}",
                self.code,
                frame_type.get()
            ),
            None => write!(f, "transport error {}", self.code),
        }
    }
}

impl fmt::Display for ApplicationImmediateClose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "application error {}", self.code)
    }
}
