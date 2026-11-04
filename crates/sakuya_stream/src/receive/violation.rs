//! The protocol violations that the peer's frames can commit on the receive
//! direction of a stream.
//!
//! Each frame method of [`StreamReceiver`](super::StreamReceiver) returns the
//! violations its own frame can commit and no others:
//! [`OnStreamFrameError`] for STREAM, [`OnResetStreamError`] for
//! `RESET_STREAM` and [`OnResetStreamAtError`] for `RESET_STREAM_AT`. Every
//! violation is a connection error ([RFC 9000 §11]): the caller closes the
//! connection with the transport error code of the error's
//! `transport_error_code`.
//!
//! A failure that more than one of the three can report is defined once and
//! wrapped by each of them as a source: [`FinalSizeChangeError`],
//! [`ResetCodeChangeError`], [`FinalSizeBelowReceivedError`],
//! [`StreamLimitExceededError`] and [`RecordUsageError`]. The variants keep
//! apart what was violated, so that the stream-level limit and the
//! connection-level limit stay distinguishable although both are
//! `FLOW_CONTROL_ERROR`.
//!
//! Each error struct defined here has private fields and is constructed only
//! by its `check` when the check fails, so it holds only values for which the
//! rule fails.
//!
//! [RFC 9000 §11]: https://www.rfc-editor.org/rfc/rfc9000.html#section-11
use crate::connection_receive_flow::RecordUsageError;
use crate::stream_end::{BeyondFinalSizeError, FinalSizeChangeError, ResetCodeChangeError};
use sakuya_wire::frame::reset_stream_at::ReliableSizeError;
use sakuya_wire::transport_error::TransportErrorCode;
use sakuya_wire::var_int::VarInt;
use snafu::{Snafu, ensure};

/// A FIN or reset states a final size below data already received
/// (`FINAL_SIZE_ERROR`, [RFC 9000 §4.5]).
///
/// [RFC 9000 §4.5]: https://www.rfc-editor.org/rfc/rfc9000.html#section-4.5
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("final size {final_size} is below the received end {accounted_end}"))]
pub struct FinalSizeBelowReceivedError {
    final_size: VarInt,
    accounted_end: VarInt,
}

impl FinalSizeBelowReceivedError {
    /// Checks that `final_size` is not below the highest end received,
    /// `accounted_end`.
    ///
    /// # Errors
    ///
    /// [`FinalSizeBelowReceivedError`] if it is.
    pub fn check(final_size: VarInt, accounted_end: VarInt) -> Result<(), Self> {
        ensure!(
            final_size >= accounted_end,
            FinalSizeBelowReceivedSnafu {
                final_size,
                accounted_end,
            }
        );
        Ok(())
    }

    /// The final size the frame states.
    pub const fn final_size(self) -> VarInt {
        self.final_size
    }

    /// The highest end received before, which exceeds
    /// [`final_size`](Self::final_size).
    pub const fn accounted_end(self) -> VarInt {
        self.accounted_end
    }
}

/// The stream's accounted end exceeds the stream limit opened to the peer
/// (`FLOW_CONTROL_ERROR`, [RFC 9000 §4.1]).
///
/// [RFC 9000 §4.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-4.1
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("stream data reaches {accounted_end}, beyond the stream limit {limit}"))]
pub struct StreamLimitExceededError {
    accounted_end: VarInt,
    limit: VarInt,
}

impl StreamLimitExceededError {
    /// Checks that the accounted end after a frame, `accounted_end`, is within
    /// the stream `limit` opened to the peer.
    ///
    /// # Errors
    ///
    /// [`StreamLimitExceededError`] if it is beyond the limit.
    pub fn check(accounted_end: VarInt, limit: VarInt) -> Result<(), Self> {
        ensure!(
            accounted_end <= limit,
            StreamLimitExceededSnafu {
                accounted_end,
                limit,
            }
        );
        Ok(())
    }

    /// The accounted end after the frame.
    pub const fn accounted_end(self) -> VarInt {
        self.accounted_end
    }

    /// The stream limit opened to the peer, which
    /// [`accounted_end`](Self::accounted_end) exceeds.
    pub const fn limit(self) -> VarInt {
        self.limit
    }
}

/// Violations of a STREAM frame.
///
/// The error code to close the connection with is
/// [`transport_error_code`](Self::transport_error_code).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(visibility(pub(super)))]
pub enum OnStreamFrameError {
    /// A FIN states a final size different from the known one
    /// (`FINAL_SIZE_ERROR`, [RFC 9000 §4.5]).
    ///
    /// [RFC 9000 §4.5]: https://www.rfc-editor.org/rfc/rfc9000.html#section-4.5
    #[snafu(context(false), display("a STREAM frame changes the final size"))]
    FinalSizeChanged {
        /// The known final size and the one the frame states.
        source: FinalSizeChangeError,
    },
    /// The frame's data ends beyond the known final size
    /// (`FINAL_SIZE_ERROR`).
    #[snafu(context(false), display("a STREAM frame passes the final size"))]
    BeyondFinalSize {
        /// The known final size and the end of the frame's data.
        source: BeyondFinalSizeError,
    },
    /// A FIN states a final size below data already received
    /// (`FINAL_SIZE_ERROR`).
    #[snafu(
        context(false),
        display("a STREAM frame ends the stream below received data")
    )]
    FinalSizeBelowReceived {
        /// The final size the frame states and the highest end received
        /// before.
        source: FinalSizeBelowReceivedError,
    },
    /// The stream's accounted end exceeds the stream limit opened to the peer
    /// (`FLOW_CONTROL_ERROR`).
    #[snafu(context(false), display("a STREAM frame exceeds the stream limit"))]
    StreamLimitExceeded {
        /// The accounted end after the frame and the stream limit.
        source: StreamLimitExceededError,
    },
    /// The connection's usage exceeds the connection limit
    /// (`FLOW_CONTROL_ERROR`).
    #[snafu(context(false), display("connection flow control violated"))]
    ConnectionLimitExceeded {
        /// The rejected usage increase.
        source: RecordUsageError,
    },
    /// The frame's offset plus length exceeds 2<sup>62</sup> − 1
    /// (`FRAME_ENCODING_ERROR`, [RFC 9000 §19.8]).
    ///
    /// [RFC 9000 §19.8]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.8
    #[snafu(display("stream data at offset {offset} with length {len} ends beyond 2^62 - 1"))]
    OffsetOverflow {
        /// The frame's offset.
        offset: VarInt,
        /// The frame's data length.
        len: usize,
    },
}

impl OnStreamFrameError {
    /// The QUIC transport error code to close the connection with.
    pub fn transport_error_code(&self) -> TransportErrorCode {
        match self {
            Self::StreamLimitExceeded { .. } | Self::ConnectionLimitExceeded { .. } => {
                TransportErrorCode::FLOW_CONTROL_ERROR
            }
            Self::FinalSizeChanged { .. }
            | Self::BeyondFinalSize { .. }
            | Self::FinalSizeBelowReceived { .. } => TransportErrorCode::FINAL_SIZE_ERROR,
            Self::OffsetOverflow { .. } => TransportErrorCode::FRAME_ENCODING_ERROR,
        }
    }
}

/// Violations of a `RESET_STREAM` frame.
///
/// The error code to close the connection with is
/// [`transport_error_code`](Self::transport_error_code).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
pub enum OnResetStreamError {
    /// The reset states a final size different from the known one
    /// (`FINAL_SIZE_ERROR`, [RFC 9000 §4.5]).
    ///
    /// [RFC 9000 §4.5]: https://www.rfc-editor.org/rfc/rfc9000.html#section-4.5
    #[snafu(context(false), display("a reset frame changes the final size"))]
    FinalSizeChanged {
        /// The known final size and the one the frame states.
        source: FinalSizeChangeError,
    },
    /// The reset states a final size below data already received
    /// (`FINAL_SIZE_ERROR`).
    #[snafu(
        context(false),
        display("a reset frame ends the stream below received data")
    )]
    FinalSizeBelowReceived {
        /// The final size the frame states and the highest end received
        /// before.
        source: FinalSizeBelowReceivedError,
    },
    /// The reset states an error code different from an earlier reset's
    /// (`STREAM_STATE_ERROR`, draft-ietf-quic-reliable-stream-reset-11 §5).
    #[snafu(context(false), display("a reset frame changes the error code"))]
    ResetCodeChanged {
        /// The error code of the earlier reset and the one the frame states.
        source: ResetCodeChangeError,
    },
    /// The stream's accounted end exceeds the stream limit opened to the peer
    /// (`FLOW_CONTROL_ERROR`, [RFC 9000 §4.1]).
    ///
    /// [RFC 9000 §4.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-4.1
    #[snafu(context(false), display("a reset frame exceeds the stream limit"))]
    StreamLimitExceeded {
        /// The accounted end after the frame and the stream limit.
        source: StreamLimitExceededError,
    },
    /// The connection's usage exceeds the connection limit
    /// (`FLOW_CONTROL_ERROR`).
    #[snafu(context(false), display("connection flow control violated"))]
    ConnectionLimitExceeded {
        /// The rejected usage increase.
        source: RecordUsageError,
    },
}

impl OnResetStreamError {
    /// The QUIC transport error code to close the connection with.
    pub fn transport_error_code(&self) -> TransportErrorCode {
        match self {
            Self::StreamLimitExceeded { .. } | Self::ConnectionLimitExceeded { .. } => {
                TransportErrorCode::FLOW_CONTROL_ERROR
            }
            Self::ResetCodeChanged { .. } => TransportErrorCode::STREAM_STATE_ERROR,
            Self::FinalSizeChanged { .. } | Self::FinalSizeBelowReceived { .. } => {
                TransportErrorCode::FINAL_SIZE_ERROR
            }
        }
    }
}

/// Violations of a `RESET_STREAM_AT` frame: those of `RESET_STREAM`, and a
/// reliable size beyond the final size.
///
/// The error code to close the connection with is
/// [`transport_error_code`](Self::transport_error_code).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
pub enum OnResetStreamAtError {
    /// The frame states a reliable size above its final size
    /// (`FRAME_ENCODING_ERROR`, draft-ietf-quic-reliable-stream-reset-11 §4).
    #[snafu(
        context(false),
        display("a RESET_STREAM_AT frame states a reliable size beyond its final size")
    )]
    ReliableSizeExceedsFinalSize {
        /// The reliable size and the final size the frame states.
        source: ReliableSizeError,
    },
    /// The frame states a final size different from the known one
    /// (`FINAL_SIZE_ERROR`, [RFC 9000 §4.5]).
    ///
    /// [RFC 9000 §4.5]: https://www.rfc-editor.org/rfc/rfc9000.html#section-4.5
    #[snafu(context(false), display("a reset frame changes the final size"))]
    FinalSizeChanged {
        /// The known final size and the one the frame states.
        source: FinalSizeChangeError,
    },
    /// The frame states a final size below data already received
    /// (`FINAL_SIZE_ERROR`).
    #[snafu(
        context(false),
        display("a reset frame ends the stream below received data")
    )]
    FinalSizeBelowReceived {
        /// The final size the frame states and the highest end received
        /// before.
        source: FinalSizeBelowReceivedError,
    },
    /// The frame states an error code different from an earlier reset's
    /// (`STREAM_STATE_ERROR`, draft-ietf-quic-reliable-stream-reset-11 §5).
    #[snafu(context(false), display("a reset frame changes the error code"))]
    ResetCodeChanged {
        /// The error code of the earlier reset and the one the frame states.
        source: ResetCodeChangeError,
    },
    /// The stream's accounted end exceeds the stream limit opened to the peer
    /// (`FLOW_CONTROL_ERROR`, [RFC 9000 §4.1]).
    ///
    /// [RFC 9000 §4.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-4.1
    #[snafu(context(false), display("a reset frame exceeds the stream limit"))]
    StreamLimitExceeded {
        /// The accounted end after the frame and the stream limit.
        source: StreamLimitExceededError,
    },
    /// The connection's usage exceeds the connection limit
    /// (`FLOW_CONTROL_ERROR`).
    #[snafu(context(false), display("connection flow control violated"))]
    ConnectionLimitExceeded {
        /// The rejected usage increase.
        source: RecordUsageError,
    },
}

impl OnResetStreamAtError {
    /// The QUIC transport error code to close the connection with.
    pub fn transport_error_code(&self) -> TransportErrorCode {
        match self {
            Self::StreamLimitExceeded { .. } | Self::ConnectionLimitExceeded { .. } => {
                TransportErrorCode::FLOW_CONTROL_ERROR
            }
            Self::ResetCodeChanged { .. } => TransportErrorCode::STREAM_STATE_ERROR,
            Self::FinalSizeChanged { .. } | Self::FinalSizeBelowReceived { .. } => {
                TransportErrorCode::FINAL_SIZE_ERROR
            }
            Self::ReliableSizeExceedsFinalSize { .. } => TransportErrorCode::FRAME_ENCODING_ERROR,
        }
    }
}

/// Every violation of `RESET_STREAM` is a violation of `RESET_STREAM_AT`
/// too, since the two frames share the rules for the final size, the error
/// code and flow control.
impl From<OnResetStreamError> for OnResetStreamAtError {
    fn from(error: OnResetStreamError) -> Self {
        match error {
            OnResetStreamError::FinalSizeChanged { source } => Self::FinalSizeChanged { source },
            OnResetStreamError::FinalSizeBelowReceived { source } => {
                Self::FinalSizeBelowReceived { source }
            }
            OnResetStreamError::ResetCodeChanged { source } => Self::ResetCodeChanged { source },
            OnResetStreamError::StreamLimitExceeded { source } => {
                Self::StreamLimitExceeded { source }
            }
            OnResetStreamError::ConnectionLimitExceeded { source } => {
                Self::ConnectionLimitExceeded { source }
            }
        }
    }
}
