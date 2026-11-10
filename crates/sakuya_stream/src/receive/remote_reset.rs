//! The reset facts of a stream: what the peer's resets stated.
//!
//! A [`StreamReceiver`](super::StreamReceiver) is generic over the type of
//! its reset facts, a [`RemoteResetFacts`]. The type decides what a reset can
//! state beyond the error code and the final size, how a later reset of the
//! same stream changes the facts, and how far the peer still owes stream data
//! after the reset ([`owed_end`](RemoteResetFacts::owed_end)); the receiver
//! applies the rules that every reset follows and keeps one state machine for
//! all of them.
//!
//! [`RemoteReset`] is the reset of [RFC 9000 §3.2]: the peer abandons all
//! data, and a later reset changes nothing.
//!
//! [RFC 9000 §3.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-3.2
use super::ResetStreamFrame;
use core::convert::Infallible;
use core::error::Error;
use core::fmt;
use sakuya_wire::v1::application_error::ApplicationErrorCode;
use sakuya_wire::var_int::VarInt;

/// The reset facts of one stream, as a stream receiver keeps them.
///
/// A value is what one reset states, and also what the receiver keeps after
/// several: the first reset establishes the facts, and each later one is
/// merged into them with [`merge`](Self::merge).
///
/// # Contract
///
/// [`owed_end`](Self::owed_end) is at most [`final_size`](Self::final_size),
/// and a value [`merge`](Self::merge) returns keeps the final size.
pub trait RemoteResetFacts: Copy + fmt::Debug + Eq {
    /// What a later reset can change in the facts, as the receive termination
    /// policy observes it in
    /// [`TerminationEvent::ResetChanged`](super::termination::TerminationEvent::ResetChanged).
    /// It is uninhabited when no later reset changes anything.
    type Change: Copy + fmt::Debug + Eq;

    /// Why a later reset contradicts the facts, which is a protocol
    /// violation of the peer. It is uninhabited when no later reset does.
    type Conflict: Error + 'static;

    /// The application protocol error code of the reset.
    fn code(&self) -> ApplicationErrorCode;

    /// The final size of the stream.
    fn final_size(&self) -> VarInt;

    /// The end of the prefix the peer still owes after the reset: it goes on
    /// delivering `[0, owed_end)` and has abandoned the rest.
    ///
    /// Reading waits for gaps below this offset and returns the reset once
    /// it has delivered up to it; a STOP request is no longer needed once
    /// everything below it has been received; and the receive termination
    /// policy may give up data below it only after a local cancellation.
    fn owed_end(&self) -> VarInt;

    /// Merges a later reset of the same stream into these facts.
    ///
    /// The stream receiver has already checked that `later` states the same
    /// final size. `Ok(None)` leaves the facts as they are; `Ok(Some(..))`
    /// gives the new facts and the change the receive termination policy
    /// observes.
    ///
    /// # Errors
    ///
    /// [`Conflict`](Self::Conflict) if `later` contradicts these facts.
    fn merge(self, later: Self) -> Result<Option<(Self, Self::Change)>, Self::Conflict>;
}

/// The reset facts of a stream under [RFC 9000 §3.2]: what the peer's first
/// `RESET_STREAM` frame stated.
///
/// The peer abandons all stream data with the reset, so it owes nothing
/// ([`owed_end`](RemoteResetFacts::owed_end) is zero). A later `RESET_STREAM`
/// changes nothing: the first error code is kept.
///
/// [RFC 9000 §3.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-3.2
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RemoteReset {
    /// The application protocol error code.
    pub code: ApplicationErrorCode,
    /// The final size of the stream.
    pub final_size: VarInt,
}

impl RemoteResetFacts for RemoteReset {
    type Change = Infallible;
    type Conflict = Infallible;

    fn code(&self) -> ApplicationErrorCode {
        self.code
    }

    fn final_size(&self) -> VarInt {
        self.final_size
    }

    fn owed_end(&self) -> VarInt {
        VarInt::ZERO
    }

    fn merge(self, _later: Self) -> Result<Option<(Self, Infallible)>, Infallible> {
        Ok(None)
    }
}

impl From<ResetStreamFrame> for RemoteReset {
    fn from(frame: ResetStreamFrame) -> Self {
        Self {
            code: frame.code,
            final_size: frame.final_size,
        }
    }
}
