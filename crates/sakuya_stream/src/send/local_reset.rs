//! The reset target of a stream: the reset this endpoint committed for its
//! send direction.
//!
//! A [`StreamSender`](super::StreamSender) is generic over the type of its
//! reset target, a [`LocalResetTarget`]. The type decides what a reset
//! request can ask for beyond the error code, how a later request replaces
//! the target in effect, how far the stream still delivers data reliably
//! after the reset ([`reliable_size`](LocalResetTarget::reliable_size)),
//! which frame announces the target and which terminal state the
//! acknowledgement of that frame leads to. The stream sender applies the
//! rules that every reset follows and keeps one state machine for all of
//! them.
//!
//! [`LocalReset`] is the reset of [RFC 9000 §3.1]: `RESET_STREAM` abandons
//! all data, and a later request changes nothing.
//!
//! [RFC 9000 §3.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-3.1
use super::SendTerminalState;
use core::convert::Infallible;
use core::error::Error;
use core::fmt;
use sakuya_wire::v1::application_error::ApplicationErrorCode;
use sakuya_wire::v1::frame::reset_stream::ResetStreamFrame;
use sakuya_wire::v1::stream_id::StreamId;
use sakuya_wire::var_int::{VarInt, VarIntField};

/// The reset target of one stream, as a stream sender keeps it once a reset
/// is committed.
///
/// A [`Request`](Self::Request) is a target that does not name its final
/// size yet: what the application asks for, or what a target states apart
/// from its final size. The first request of a stream becomes a target with
/// [`establish`](Self::establish), and each later one replaces the target in
/// effect with [`replace`](Self::replace).
///
/// # Contract
///
/// [`reliable_size`](Self::reliable_size) is at most
/// [`final_size`](Self::final_size). A target that
/// [`replace`](Self::replace) returns keeps the error code and the final
/// size, and a target that [`establish`](Self::establish) returns has the
/// final size it was given and the error code of the request.
pub trait LocalResetTarget: Copy + fmt::Debug + Eq {
    /// A reset request: a target without its final size.
    type Request: Copy + fmt::Debug + Eq;

    /// The reset frame that announces a target to the peer.
    type Frame: Copy + fmt::Debug + Eq;

    /// Why a request cannot replace the target in effect. It is uninhabited
    /// when every request with the same error code can.
    type Conflict: Error + 'static;

    /// Why a request cannot become the first reset of a stream with the
    /// data written so far, or at a certain final size. It is uninhabited
    /// when every request can, at any final size.
    type Unfit: Error + 'static;

    /// The application protocol error code of the reset.
    fn error_code(&self) -> ApplicationErrorCode;

    /// The final size of the stream.
    fn final_size(&self) -> VarInt;

    /// The end of the prefix the stream still delivers reliably after the
    /// reset: data in `[0, reliable_size)` is sent and retransmitted, the
    /// rest is abandoned.
    fn reliable_size(&self) -> VarInt;

    /// The frame that announces this target for the stream `stream_id`, with
    /// its fields in the shortest encodings.
    fn frame(&self, stream_id: StreamId) -> Self::Frame;

    /// The terminal state the send direction reaches once the frame of this
    /// target, and the data the target still delivers, are acknowledged.
    fn acknowledged_state(&self) -> SendTerminalState;

    /// What this target states apart from its final size.
    fn request(&self) -> Self::Request;

    /// The application protocol error code `request` asks for.
    fn requested_error_code(request: &Self::Request) -> ApplicationErrorCode;

    /// Whether `request` asks for what this target already is, whatever the
    /// final size.
    fn restates(&self, request: &Self::Request) -> bool;

    /// Replaces this target, which is in effect, by what `request` asks for.
    ///
    /// The stream sender has already checked that `request` states the same
    /// error code and does not [restate](Self::restates) this target.
    ///
    /// # Errors
    ///
    /// [`Conflict`](Self::Conflict) if `request` cannot replace this target.
    fn replace(self, request: Self::Request) -> Result<Self, Self::Conflict>;

    /// The smallest final size at which `request` can become the first reset
    /// of a stream whose written end is `written_end`.
    ///
    /// # Errors
    ///
    /// [`Unfit`](Self::Unfit) if the data written so far does not allow the
    /// request at any final size.
    fn minimum_final_size(
        request: &Self::Request,
        written_end: VarInt,
    ) -> Result<VarInt, Self::Unfit>;

    /// The target that makes `request` the first reset of a stream, ending
    /// it at `final_size`.
    ///
    /// # Errors
    ///
    /// [`Unfit`](Self::Unfit) if `request` cannot end the stream at
    /// `final_size`.
    fn establish(request: Self::Request, final_size: VarInt) -> Result<Self, Self::Unfit>;
}

/// The reset target of a stream under [RFC 9000 §3.1]: the reset a
/// `RESET_STREAM` frame announces.
///
/// The reset abandons all stream data
/// ([`reliable_size`](LocalResetTarget::reliable_size) is zero), and its
/// acknowledgement leads to "Reset Recvd". A request is the error code alone;
/// once a reset is in effect no request replaces it, since the content of a
/// `RESET_STREAM` frame does not change when it is sent again
/// ([RFC 9000 §13.3]).
///
/// [RFC 9000 §3.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-3.1
/// [RFC 9000 §13.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-13.3
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LocalReset {
    /// The application protocol error code.
    pub error_code: ApplicationErrorCode,
    /// The final size of the stream.
    pub final_size: VarInt,
}

impl LocalResetTarget for LocalReset {
    type Request = ApplicationErrorCode;
    type Frame = ResetStreamFrame;
    type Conflict = Infallible;
    type Unfit = Infallible;

    fn error_code(&self) -> ApplicationErrorCode {
        self.error_code
    }

    fn final_size(&self) -> VarInt {
        self.final_size
    }

    fn reliable_size(&self) -> VarInt {
        VarInt::ZERO
    }

    fn frame(&self, stream_id: StreamId) -> ResetStreamFrame {
        ResetStreamFrame::new(
            VarIntField::shortest(stream_id),
            VarIntField::shortest(self.error_code),
            VarIntField::shortest(self.final_size),
        )
    }

    fn acknowledged_state(&self) -> SendTerminalState {
        SendTerminalState::ResetRecvd
    }

    fn request(&self) -> ApplicationErrorCode {
        self.error_code
    }

    fn requested_error_code(request: &ApplicationErrorCode) -> ApplicationErrorCode {
        *request
    }

    fn restates(&self, request: &ApplicationErrorCode) -> bool {
        self.error_code == *request
    }

    fn replace(self, _request: ApplicationErrorCode) -> Result<Self, Infallible> {
        Ok(self)
    }

    fn minimum_final_size(
        _request: &ApplicationErrorCode,
        _written_end: VarInt,
    ) -> Result<VarInt, Infallible> {
        Ok(VarInt::ZERO)
    }

    fn establish(error_code: ApplicationErrorCode, final_size: VarInt) -> Result<Self, Infallible> {
        Ok(Self {
            error_code,
            final_size,
        })
    }
}
