//! The reliable stream reset extension for the receive direction of a
//! stream.
//!
//! This module adds the extension to the stream receiver without changing
//! the receiver of RFC 9000:
//!
//! - [`RemoteResetAt`] is the type of reset facts that keeps a reliable
//!   size. A [`StreamReceiver`] of these facts,
//!   `StreamReceiver<C, Lc, RemoteResetAt>`, takes `RESET_STREAM_AT` with
//!   [`on_reset_stream_at`](StreamReceiver::on_reset_stream_at) and
//!   `RESET_STREAM` with [`on_reset_stream`](StreamReceiver::on_reset_stream),
//!   in any order.
//! - The reliable size is the end of the prefix the peer still owes
//!   ([`RemoteResetFacts::owed_end`]): reading waits for gaps below it, a
//!   STOP request stays useful until everything below it has been received,
//!   and the receive termination policy may give up data below it only after
//!   a local cancellation.
//! - Resets of one stream must agree on the error code (§5.2): a reset that
//!   states another one is a connection error of type `STREAM_STATE_ERROR`.
//!   A receiver of RFC 9000 resets ignores the later code instead.
//!
//! Whether this endpoint advertised the `reset_stream_at` transport
//! parameter, and so whether the peer may send the frame at all, is for the
//! connection to check where it dispatches frames; the receiver has no
//! setting for it.
//!
//! [draft-ietf-quic-reliable-stream-reset-11]: https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-11.html
use crate::connection_receive_flow::ConnectionReceiveFlowController;
use crate::receive::StreamReceiver;
use crate::receive::flow_control::ReceiveFlowControlPolicy;
use crate::receive::remote_reset::RemoteResetFacts;
use crate::receive::termination::ReceiveTerminationPolicy;
use crate::receive::violation::{self, OnRemoteResetError};
use crate::receive_buffer::StreamReceiveBuffer;
use crate::stream_end::ResetCodeChangeError;
use sakuya_wire::reset_stream_at::{ReliableSizeError, ResetStreamAtFrame};
use sakuya_wire::v1::application_error::ApplicationErrorCode;
use sakuya_wire::v1::frame::reset_stream::ResetStreamFrame;
use sakuya_wire::v1::transport_error::TransportErrorCode;
use sakuya_wire::var_int::VarInt;
use snafu::Snafu;

/// The reset facts of a stream that takes `RESET_STREAM_AT` as well as
/// `RESET_STREAM`: what the peer's reset frames stated.
///
/// The error code and the final size are those of the first reset. The
/// reliable size is the effective one: the smallest any reset stated, where
/// a `RESET_STREAM` counts as zero. It is at most the final size.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RemoteResetAt {
    code: ApplicationErrorCode,
    final_size: VarInt,
    reliable_size: VarInt,
}

impl RemoteResetAt {
    /// The facts a reset with these fields states.
    ///
    /// # Errors
    ///
    /// [`ReliableSizeError`] if `reliable_size` exceeds `final_size`.
    pub fn new(
        code: ApplicationErrorCode,
        final_size: VarInt,
        reliable_size: VarInt,
    ) -> Result<Self, ReliableSizeError> {
        ReliableSizeError::check(final_size, reliable_size)?;
        Ok(Self {
            code,
            final_size,
            reliable_size,
        })
    }

    /// The application protocol error code.
    pub const fn code(&self) -> ApplicationErrorCode {
        self.code
    }

    /// The final size of the stream.
    pub const fn final_size(&self) -> VarInt {
        self.final_size
    }

    /// The effective reliable size: the smallest one received, zero once a
    /// `RESET_STREAM` was received.
    pub const fn reliable_size(&self) -> VarInt {
        self.reliable_size
    }
}

/// What a later reset changes in the [`RemoteResetAt`] facts of a stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RemoteResetAtChange {
    /// The later reset lowered the effective reliable size.
    ReliablePrefixLowered,
}

impl RemoteResetFacts for RemoteResetAt {
    type Change = RemoteResetAtChange;
    type Conflict = ResetCodeChangeError;

    fn code(&self) -> ApplicationErrorCode {
        self.code
    }

    fn final_size(&self) -> VarInt {
        self.final_size
    }

    fn owed_end(&self) -> VarInt {
        self.reliable_size
    }

    /// The effective reliable size becomes the smaller of the two; a larger
    /// one arriving later does not raise it.
    ///
    /// # Errors
    ///
    /// [`ResetCodeChangeError`] if `later` states another error code.
    fn merge(
        self,
        later: Self,
    ) -> Result<Option<(Self, RemoteResetAtChange)>, ResetCodeChangeError> {
        ResetCodeChangeError::check(self.code, later.code)?;
        Ok((later.reliable_size < self.reliable_size).then_some((
            Self {
                reliable_size: later.reliable_size,
                ..self
            },
            RemoteResetAtChange::ReliablePrefixLowered,
        )))
    }
}

/// A `RESET_STREAM` states a reliable size of zero.
impl From<ResetStreamFrame> for RemoteResetAt {
    fn from(frame: ResetStreamFrame) -> Self {
        Self {
            code: frame.application_error_code().get(),
            final_size: frame.final_size().get(),
            reliable_size: VarInt::ZERO,
        }
    }
}

/// A `RESET_STREAM_AT` frame states its reliable size, which is at most its
/// final size: the frame checks that when it is constructed or read.
impl From<ResetStreamAtFrame> for RemoteResetAt {
    fn from(frame: ResetStreamAtFrame) -> Self {
        Self {
            code: frame.application_error_code().get(),
            final_size: frame.final_size().get(),
            reliable_size: frame.reliable_size().get(),
        }
    }
}

/// Violations of a reset frame on a stream that also takes
/// `RESET_STREAM_AT`: failures of
/// [`on_reset_stream`](StreamReceiver::on_reset_stream) and
/// [`on_reset_stream_at`](StreamReceiver::on_reset_stream_at) of a
/// `StreamReceiver<C, Lc, RemoteResetAt>`. The two frames share the rules
/// for the final size, the error code and flow control.
///
/// The error code to close the connection with is
/// [`transport_error_code`](Self::transport_error_code).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
pub enum OnResetStreamError {
    /// The frame violates a rule of RFC 9000 for `RESET_STREAM`.
    #[snafu(transparent)]
    ResetStream {
        /// The violation.
        source: violation::OnResetStreamError,
    },
    /// The frame states an error code different from an earlier reset's
    /// (`STREAM_STATE_ERROR`, [draft-ietf-quic-reliable-stream-reset-11
    /// §5.2]).
    ///
    /// [draft-ietf-quic-reliable-stream-reset-11 §5.2]: https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-11.html#section-5.2
    #[snafu(context(false), display("a reset frame changes the error code"))]
    ResetCodeChanged {
        /// The error code of the earlier reset and the one the frame states.
        source: ResetCodeChangeError,
    },
}

impl OnResetStreamError {
    /// The QUIC transport error code to close the connection with.
    pub fn transport_error_code(&self) -> TransportErrorCode {
        match self {
            Self::ResetStream { source } => source.transport_error_code(),
            Self::ResetCodeChanged { .. } => TransportErrorCode::STREAM_STATE_ERROR,
        }
    }
}

impl<C, Lc> StreamReceiver<C, Lc, RemoteResetAt>
where
    C: StreamReceiveBuffer + ReceiveFlowControlPolicy + ReceiveTerminationPolicy<RemoteResetAt>,
{
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
    pub fn on_reset_stream(
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
    pub fn on_reset_stream_at(
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

#[cfg(test)]
mod tests;
