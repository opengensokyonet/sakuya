//! The failures of the local STOP request: asking the peer to stop sending.
//!
//! `StreamReceiver::stop` of the package `sakuya_stream_sets` installs the
//! duty to send `STOP_SENDING` ([RFC 9000 §3.5]) and reports a [`StopError`]
//! when the request cannot be installed.
//!
//! [RFC 9000 §3.5]: https://www.rfc-editor.org/rfc/rfc9000.html#section-3.5
use crate::connection::LayerEndedError;
use core::convert::Infallible;
use core::fmt;
use sakuya_wire_v1::application_error::ApplicationErrorCode;
use snafu::Snafu;

/// Failures of `StreamReceiver::stop`.
///
/// A failed request does not end reading and does not change the local
/// limits.
///
/// `Lc` is the type of the connection's local close cause.
#[derive(Clone, Debug, PartialEq, Eq, Snafu)]
#[snafu(visibility(pub))]
pub enum StopError<Lc> {
    /// The connection has closed.
    #[snafu(transparent)]
    LayerEnded {
        /// The closed connection.
        source: LayerEndedError<Lc>,
    },
    /// A STOP request with another error code is already installed; it is
    /// kept.
    #[snafu(display("a STOP request with error code {installed} is installed, not {requested}"))]
    StopConflict {
        /// The code of the installed request.
        installed: ApplicationErrorCode,
        /// The code of the rejected request.
        requested: ApplicationErrorCode,
    },
    /// The protocol no longer needs a STOP request.
    #[snafu(display("no STOP request is needed: {reason}"))]
    StopNotNeeded {
        /// Why no request is needed.
        reason: StopNotNeededReason,
    },
}

impl<Lc> StopError<Lc> {
    /// The same failure without the connection closure, which the failure
    /// of a policy's decision never reports; the closure itself otherwise.
    pub fn without_closed_connection(self) -> Result<StopError<Infallible>, LayerEndedError<Lc>> {
        match self {
            Self::LayerEnded { source } => Err(source),
            Self::StopConflict {
                installed,
                requested,
            } => Ok(StopError::StopConflict {
                installed,
                requested,
            }),
            Self::StopNotNeeded { reason } => Ok(StopError::StopNotNeeded { reason }),
        }
    }
}

/// Why [`StopError::StopNotNeeded`] was returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StopNotNeededReason {
    /// Every byte of the stream has been received.
    DataComplete,
    /// The peer reset the stream, and the prefix it still owes, if any, has
    /// been received.
    PeerReset,
}

impl fmt::Display for StopNotNeededReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DataComplete => "all stream data has been received",
            Self::PeerReset => "the peer reset the stream",
        })
    }
}

/// `StreamReceiver::on_stop_sent` was called without an installed STOP
/// request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(
    visibility(pub),
    display("STOP_SENDING reported sent without an installed request")
)]
pub struct NoStopRequestError;
