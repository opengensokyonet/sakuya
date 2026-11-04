//! The local STOP request: asking the peer to stop sending.
//!
//! [`StreamReceiver::stop`] only installs the duty to send `STOP_SENDING`
//! ([RFC 9000 §3.5]); it returns as soon as the request is checked and
//! installed, without waiting for a packet, an acknowledgement, a reset or
//! delivery, and it does not end reading. Protocol processing lets the duty
//! lapse when it is no longer useful, so success does not promise that a
//! frame will be sent.
//!
//! The checks, in order:
//!
//! | State | Result |
//! | --- | --- |
//! | connection closed or persistent protocol failure | [`StopError::Connection`] |
//! | a request with the same code is installed | success, nothing new happens |
//! | a request with another code is installed | [`StopError::StopConflict`], the request stays |
//! | no request, and all data was received or the peer reset the stream | [`StopError::StopNotNeeded`] |
//! | no request, and the protocol still allows one | the request is installed |
//!
//! A `RESET_STREAM_AT` whose reliable prefix has not been received yet still
//! allows a request; once the prefix is received, none is needed.
//!
//! [RFC 9000 §3.5]: https://www.rfc-editor.org/rfc/rfc9000.html#section-3.5
use super::{
    ConnectionFailureError, StopRequest, StreamReceiver, flow_control::ReceiveFlowControlPolicy,
    termination::ReceiveTerminationPolicy, termination::TerminationEvent,
};
use crate::receive_buffer::ReceiveBuffer;
use core::fmt;
use sakuya_wire::application_error::ApplicationErrorCode;
use sakuya_wire::var_int::VarInt;
use snafu::{Snafu, ensure};

/// Failures of [`StreamReceiver::stop`].
///
/// A failed request does not end reading and does not change the local
/// limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
pub enum StopError {
    /// The connection closed, or input of the stream violated the protocol.
    #[snafu(display("connection failed"))]
    Connection {
        /// The failure.
        source: ConnectionFailureError,
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

/// Why [`StopError::StopNotNeeded`] was returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StopNotNeededReason {
    /// Every byte of the stream has been received.
    DataComplete,
    /// The peer reset the stream, and the reliable prefix it still owes, if
    /// any, has been received.
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

/// [`StreamReceiver::on_stop_sent`] was called without an installed STOP
/// request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("STOP_SENDING reported sent without an installed request"))]
pub struct NoStopRequestError;

impl<C> StreamReceiver<C>
where
    C: ReceiveBuffer + ReceiveFlowControlPolicy + ReceiveTerminationPolicy,
{
    /// Installs a request that the peer stop sending, with application error
    /// code `code`.
    ///
    /// On first installation the receive termination policy observes
    /// [`TerminationEvent::StopRequested`]; it cannot veto the request or
    /// change its code. See the [module documentation](self) for the checks.
    ///
    /// # Errors
    ///
    /// See [`StopError`].
    pub fn stop(&mut self, code: ApplicationErrorCode) -> Result<(), StopError> {
        if self.check_stop(code)? {
            self.install_stop(code);
            self.notify_termination(TerminationEvent::StopRequested);
        }
        Ok(())
    }

    /// The error code of a STOP request still waiting to be sent, if it is
    /// still needed.
    pub fn pending_stop(&self) -> Option<ApplicationErrorCode> {
        match self.stop {
            StopRequest::Pending(code)
                if self.failure().is_none() && self.stop_not_needed().is_none() =>
            {
                Some(code)
            }
            StopRequest::NotRequested | StopRequest::Pending(_) | StopRequest::Sent(_) => None,
        }
    }

    /// Records that the installed STOP request was actually sent.
    ///
    /// The receive termination policy observes
    /// [`TerminationEvent::StopSent`], which gives it a local reason to
    /// restrict or destroy the receive buffer. Repeated calls do nothing.
    ///
    /// # Errors
    ///
    /// [`NoStopRequestError`] if no STOP request is installed; nothing
    /// changes then.
    pub fn on_stop_sent(&mut self) -> Result<(), NoStopRequestError> {
        match self.stop {
            StopRequest::NotRequested => NoStopRequestSnafu.fail(),
            StopRequest::Sent(_) => Ok(()),
            StopRequest::Pending(code) => {
                self.stop = StopRequest::Sent(code);
                self.notify_termination(TerminationEvent::StopSent);
                Ok(())
            }
        }
    }

    /// Checks a STOP request; `Ok(true)` means it is to be installed,
    /// `Ok(false)` that the same request is already installed.
    pub(super) fn check_stop(&self, code: ApplicationErrorCode) -> Result<bool, StopError> {
        if let Some(failure) = self.failure() {
            return Err(StopError::Connection { source: failure });
        }
        if let Some(installed) = self.stop.code() {
            ensure!(
                installed == code,
                StopConflictSnafu {
                    installed,
                    requested: code,
                }
            );
            return Ok(false);
        }
        if let Some(reason) = self.stop_not_needed() {
            return StopNotNeededSnafu { reason }.fail();
        }
        Ok(true)
    }

    pub(super) fn install_stop(&mut self, code: ApplicationErrorCode) {
        self.stop = StopRequest::Pending(code);
    }

    /// Why the protocol needs no STOP request, if it does not.
    pub(super) fn stop_not_needed(&self) -> Option<StopNotNeededReason> {
        if self.fully_received() {
            return Some(StopNotNeededReason::DataComplete);
        }
        let reset = self.reset?;
        self.parts
            .is_received(VarInt::ZERO..reset.reliable_size)
            .then_some(StopNotNeededReason::PeerReset)
    }
}
