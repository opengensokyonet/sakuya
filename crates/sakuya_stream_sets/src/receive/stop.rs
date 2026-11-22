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
//! | connection closed | [`StopError::LayerEnded`] |
//! | a request with the same code is installed | success, nothing new happens |
//! | a request with another code is installed | [`StopError::StopConflict`], the request stays |
//! | no request, and all data was received or the peer reset the stream | [`StopError::StopNotNeeded`] |
//! | no request, and the protocol still allows one | the request is installed |
//!
//! A reset after which the peer still owes a prefix that has not been
//! received yet still allows a request; once the prefix is received, none is
//! needed.
//!
//! While the stream waits for the connection to close after a frame
//! violated the protocol, a request is checked and installed as usual: it
//! is not a result about the connection.
//!
//! [RFC 9000 §3.5]: https://www.rfc-editor.org/rfc/rfc9000.html#section-3.5
use super::{StopRequest, StreamReceiver};
use sakuya_stream_v1::receive::flow_control::ReceiveFlowControlPolicy;
use sakuya_stream_v1::receive::remote_reset::RemoteResetFacts;
use sakuya_stream_v1::receive::stop::{
    NoStopRequestError, NoStopRequestSnafu, StopConflictSnafu, StopError, StopNotNeededReason,
    StopNotNeededSnafu,
};
use sakuya_stream_v1::receive::termination::{ReceiveTerminationPolicy, TerminationEvent};
use sakuya_stream_v1::receive_buffer::StreamReceiveBuffer;
use sakuya_wire_v1::application_error::ApplicationErrorCode;
use sakuya_wire_v1::var_int::VarInt;
use snafu::ensure;

impl<C, Lc, F> StreamReceiver<C, Lc, F>
where
    C: StreamReceiveBuffer + ReceiveFlowControlPolicy + ReceiveTerminationPolicy<F>,
    F: RemoteResetFacts,
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
    pub fn stop(&mut self, code: ApplicationErrorCode) -> Result<(), StopError<Lc>> {
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
                if self.closed().is_none() && self.stop_not_needed().is_none() =>
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

    /// Records that the frame carrying the STOP request was declared lost:
    /// the request waits to be sent again while the protocol still needs it
    /// and the connection has not closed ([RFC 9000 §13.3]); otherwise
    /// nothing changes.
    ///
    /// [RFC 9000 §13.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-13.3
    pub fn on_stop_lost(&mut self) {
        if let StopRequest::Sent(code) = self.stop
            && self.closed().is_none()
            && self.stop_not_needed().is_none()
        {
            self.stop = StopRequest::Pending(code);
        }
    }

    /// Checks a STOP request; `Ok(true)` means it is to be installed,
    /// `Ok(false)` that the same request is already installed.
    pub(super) fn check_stop(&self, code: ApplicationErrorCode) -> Result<bool, StopError<Lc>> {
        if let Some(closed) = self.closed() {
            return Err(StopError::LayerEnded {
                source: closed.clone(),
            });
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
        self.received
            .covers(VarInt::ZERO..reset.owed_end())
            .then_some(StopNotNeededReason::PeerReset)
    }
}
