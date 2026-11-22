//! The reliable stream reset extension for the stream receiver: the frames of
//! a receiver whose reset facts are [`RemoteResetAt`].
use crate::receive::StreamReceiver;
use sakuya_stream_reset_stream_at::receive::{OnResetStreamError, RemoteResetAt};
use sakuya_stream_v1::connection_receive_flow::ConnectionReceiveFlowController;
use sakuya_stream_v1::receive::flow_control::ReceiveFlowControlPolicy;
use sakuya_stream_v1::receive::termination::ReceiveTerminationPolicy;
use sakuya_stream_v1::receive::violation::OnRemoteResetError;
use sakuya_stream_v1::receive_buffer::StreamReceiveBuffer;
use sakuya_wire_reset_stream_at::ResetStreamAtFrame;
use sakuya_wire_v1::frame::reset_stream::ResetStreamFrame;

#[cfg(test)]
mod tests;

/// The resets of a stream receiver whose reset facts are
/// [`RemoteResetAt`]: `RESET_STREAM` and `RESET_STREAM_AT` frames.
pub trait ResetStreamAtReceiver {
    /// Processes a `RESET_STREAM` frame of the stream.
    ///
    /// It establishes the reset facts with a reliable size of zero, or lowers
    /// an earlier `RESET_STREAM_AT`'s reliable size to zero. What remains
    /// deliverable is up to the receive termination policy; reading stops at
    /// the first gap. As for
    /// [`on_stream_frame`](StreamReceiver::on_stream_frame), a violating
    /// frame leaves no trace, and a frame after a violation or after the
    /// connection closed is ignored.
    ///
    /// # Errors
    ///
    /// [`OnResetStreamError`] if this frame violates the protocol; the
    /// caller must close the connection with its
    /// [`transport_error_code`](OnResetStreamError::transport_error_code).
    fn on_reset_stream(
        &mut self,
        frame: ResetStreamFrame,
        connection: &mut ConnectionReceiveFlowController,
    ) -> Result<(), OnResetStreamError>;

    /// Processes a `RESET_STREAM_AT` frame of the stream.
    ///
    /// The first reset establishes the reset facts. The effective reliable
    /// size becomes the smallest one received; a larger one arriving later
    /// does not raise it. Reading waits for gaps below it. As for
    /// [`on_stream_frame`](StreamReceiver::on_stream_frame), a violating
    /// frame leaves no trace, and a frame after a violation or after the
    /// connection closed is ignored.
    ///
    /// # Errors
    ///
    /// [`OnResetStreamError`] if this frame violates the protocol; the
    /// caller must close the connection with its
    /// [`transport_error_code`](OnResetStreamError::transport_error_code).
    fn on_reset_stream_at(
        &mut self,
        frame: ResetStreamAtFrame,
        connection: &mut ConnectionReceiveFlowController,
    ) -> Result<(), OnResetStreamError>;
}

impl<C, Lc> ResetStreamAtReceiver for StreamReceiver<C, Lc, RemoteResetAt>
where
    C: StreamReceiveBuffer + ReceiveFlowControlPolicy + ReceiveTerminationPolicy<RemoteResetAt>,
{
    fn on_reset_stream(
        &mut self,
        frame: ResetStreamFrame,
        connection: &mut ConnectionReceiveFlowController,
    ) -> Result<(), OnResetStreamError> {
        self.on_remote_reset(frame, connection)
            .map_err(|error| match error {
                OnRemoteResetError::Violation { source } => source.into(),
                OnRemoteResetError::Conflict { source } => source.into(),
            })
    }

    fn on_reset_stream_at(
        &mut self,
        frame: ResetStreamAtFrame,
        connection: &mut ConnectionReceiveFlowController,
    ) -> Result<(), OnResetStreamError> {
        self.on_remote_reset(frame, connection)
            .map_err(|error| match error {
                OnRemoteResetError::Violation { source } => source.into(),
                OnRemoteResetError::Conflict { source } => source.into(),
            })
    }
}
