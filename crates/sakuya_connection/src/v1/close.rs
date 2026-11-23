//! Why a connection closes, as this endpoint records it, and what its
//! CONNECTION_CLOSE frames carry.
//!
//! A connection has one reason for closing ([`CloseReason`]): the first one
//! written into its record ([`CloseReasonRecord`]) stays, and every API of
//! the connection reports that one. This endpoint's own reason is a
//! [`LocalCloseCause`], complete with the chain of its sources and never
//! truncated. The frames are worked out from it only when the close packets
//! are sealed: its error says which close it can become ([`TransportClose`]
//! or [`ApplicationClose`]), and a policy ([`ImmediateClosePolicy`]) can
//! adjust what goes out at each encryption level. The record keeps the
//! reason, not the frames. The end of a link that leaves the connection no
//! link path is this endpoint's reason too, and becomes no close: the
//! connection ends at once, with nothing sent.
use bytes::Bytes;
use core::{error::Error, fmt};
use kasen_handshake::{alert::CallsForAlert, engine::HandshakeError};
use sakuya_stream_v1::connection::{
    ApplicationImmediateClose, CloseReason, ImmediateClose, TransportImmediateClose,
};
use sakuya_var_int::VarInt;
use sakuya_wire::parts::{CNil, Coproduct, PartsError};
use sakuya_wire_v1::{
    application_error::ApplicationErrorCode, encryption_level::EncryptionLevel,
    transport_error::TransportErrorCode,
};

use super::component_events::CloseReasonWritten;
use crate::component_event::Happened;

/// This endpoint's reason for closing a connection: the first one, with
/// the whole chain of its sources.
///
/// `E` is the connection's error, `H` the error of the handshake, `A` the
/// application's own error type for closing, `R` why a link ended (a
/// link's `RecvError`). The close it becomes follows from the branch: a
/// connection error and a handshake error become a transport close, an
/// application close an application close; the end of a link becomes
/// none.
#[derive(Debug, PartialEq, Eq)]
pub enum LocalCloseCause<E, H, A, R> {
    /// An error of the connection: of processing a packet, of a frame, of
    /// CRYPTO data.
    Connection(E),
    /// The handshake failed.
    Handshake(H),
    /// The application closed the connection.
    Application(A),
    /// A link ended, for the reason it holds, and no link path of the
    /// connection was left: the connection ended at once, with no close
    /// sent.
    LinkEnded(R),
}

impl<E: TransportClose, H: TransportClose, A: ApplicationClose, R> LocalCloseCause<E, H, A, R> {
    /// The close this reason becomes, as its error gives it, before any
    /// adjustment; `None` for the end of a link, which sends no close.
    pub fn immediate_close(&self) -> Option<ImmediateClose> {
        match self {
            Self::Connection(error) => Some(error.immediate_close().into()),
            Self::Handshake(error) => Some(error.immediate_close().into()),
            Self::Application(error) => Some(error.immediate_close().into()),
            Self::LinkEnded(_) => None,
        }
    }
}

/// It shows as the error it holds.
impl<E: fmt::Display, H: fmt::Display, A: fmt::Display, R: fmt::Display> fmt::Display
    for LocalCloseCause<E, H, A, R>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection(error) => error.fmt(f),
            Self::Handshake(error) => error.fmt(f),
            Self::Application(error) => error.fmt(f),
            Self::LinkEnded(error) => error.fmt(f),
        }
    }
}

/// Its source is the source of the error it holds.
impl<E: Error, H: Error, A: Error, R: Error> Error for LocalCloseCause<E, H, A, R> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Connection(error) => error.source(),
            Self::Handshake(error) => error.source(),
            Self::Application(error) => error.source(),
            Self::LinkEnded(error) => error.source(),
        }
    }
}

/// An error that closes the connection with a CONNECTION_CLOSE frame of
/// type `0x1c`, an error of the QUIC layer.
///
/// Such an error cannot give an application error code.
pub trait TransportClose {
    /// The transport error code.
    fn code(&self) -> TransportErrorCode;
    /// The type of the frame that triggered the error, `None` if it is
    /// unknown.
    fn frame_type(&self) -> Option<VarInt>;
    /// The reason phrase; by default empty.
    fn reason_phrase(&self) -> Bytes {
        Bytes::new()
    }
    /// The close, from the three above.
    fn immediate_close(&self) -> TransportImmediateClose {
        TransportImmediateClose {
            code: self.code(),
            frame_type: self.frame_type(),
            reason_phrase: self.reason_phrase(),
        }
    }
}

/// The error of a composition closes as the part's error it holds.
impl<C: TransportClose> TransportClose for PartsError<C> {
    fn code(&self) -> TransportErrorCode {
        self.0.code()
    }
    fn frame_type(&self) -> Option<VarInt> {
        self.0.frame_type()
    }
    fn reason_phrase(&self) -> Bytes {
        self.0.reason_phrase()
    }
    fn immediate_close(&self) -> TransportImmediateClose {
        self.0.immediate_close()
    }
}

/// A sum of errors closes as the error it holds.
impl<H: TransportClose, T: TransportClose> TransportClose for Coproduct<H, T> {
    fn code(&self) -> TransportErrorCode {
        match self {
            Self::Inl(error) => error.code(),
            Self::Inr(rest) => rest.code(),
        }
    }
    fn frame_type(&self) -> Option<VarInt> {
        match self {
            Self::Inl(error) => error.frame_type(),
            Self::Inr(rest) => rest.frame_type(),
        }
    }
    fn reason_phrase(&self) -> Bytes {
        match self {
            Self::Inl(error) => error.reason_phrase(),
            Self::Inr(rest) => rest.reason_phrase(),
        }
    }
    fn immediate_close(&self) -> TransportImmediateClose {
        match self {
            Self::Inl(error) => error.immediate_close(),
            Self::Inr(rest) => rest.immediate_close(),
        }
    }
}

/// The end of a sum holds no error.
impl TransportClose for CNil {
    fn code(&self) -> TransportErrorCode {
        match *self {}
    }
    fn frame_type(&self) -> Option<VarInt> {
        match *self {}
    }
}

/// The error of a part that has none never closes anything.
impl TransportClose for core::convert::Infallible {
    fn code(&self) -> TransportErrorCode {
        match *self {}
    }
    fn frame_type(&self) -> Option<VarInt> {
        match *self {}
    }
}

/// A failed handshake closes with `0x0100` plus the alert it calls for
/// (RFC 9001 §4.8), with PROTOCOL_VIOLATION when the peer broke a rule of
/// TLS in QUIC, and with the code and frame type of the connection's error
/// when a receiver failed. Its reason phrase is empty, whichever the
/// failure: the responses to the failures after the protection is removed
/// do not tell them apart.
impl<F: CallsForAlert, E: TransportClose> TransportClose for HandshakeError<F, E> {
    fn code(&self) -> TransportErrorCode {
        match self {
            Self::Alert { source } => TransportErrorCode::crypto_error(source.alert().get()),
            Self::ProtocolViolation { .. } => TransportErrorCode::PROTOCOL_VIOLATION,
            Self::Transport { source } => source.code(),
        }
    }
    fn frame_type(&self) -> Option<VarInt> {
        match self {
            Self::Alert { .. } | Self::ProtocolViolation { .. } => None,
            Self::Transport { source } => source.frame_type(),
        }
    }
}

/// An error that closes the connection with a CONNECTION_CLOSE frame of
/// type `0x1d`, a close of the application.
///
/// Such an error cannot give a transport error code.
pub trait ApplicationClose {
    /// The application protocol error code.
    fn code(&self) -> ApplicationErrorCode;
    /// The reason phrase; by default empty.
    fn reason_phrase(&self) -> Bytes {
        Bytes::new()
    }
    /// The close, from the two above.
    fn immediate_close(&self) -> ApplicationImmediateClose {
        ApplicationImmediateClose {
            code: self.code(),
            reason_phrase: self.reason_phrase(),
        }
    }
}

/// What adjusts the close this endpoint is about to send, chosen with the
/// composition; `C` is this endpoint's reason for closing.
///
/// When the close packets are sealed it is called once for each encryption
/// level, with the reason, the level of the packet the frame goes in and the
/// close the reason gives, and returns the close to send, error code
/// included. It is never called for the end of a link
/// ([`LocalCloseCause::LinkEnded`]), which gives no close. What follows does not depend on it: in Initial and Handshake
/// packets an application close becomes a transport close with
/// APPLICATION_ERROR and no reason phrase (RFC 9000 §10.2.3), and a reason
/// phrase that does not fit is truncated. The record keeps the reason as it
/// was. Different levels are read by different parties: anyone on the path
/// can remove the protection of Initial packets.
pub trait ImmediateClosePolicy<C> {
    /// The close to send at `level` for `cause`, from the one it gives.
    fn adjust(
        &mut self,
        cause: &C,
        level: EncryptionLevel,
        close: ImmediateClose,
    ) -> ImmediateClose;
}

/// The policy that sends the close the reason gives, unchanged: the reason
/// phrase an error gives goes out.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PassThroughImmediateClosePolicy;

impl<C> ImmediateClosePolicy<C> for PassThroughImmediateClosePolicy {
    fn adjust(&mut self, _: &C, _: EncryptionLevel, close: ImmediateClose) -> ImmediateClose {
        close
    }
}

/// The record of why a connection closed: empty until the first reason is
/// written, which stays.
///
/// `C` is this endpoint's reason for closing, a [`LocalCloseCause`] in a
/// composition. A component that subscribes to the reason written
/// ([`CloseReasonWritten`]) learns that the connection is closing.
#[derive(Debug)]
pub struct CloseReasonRecord<C> {
    reason: Option<CloseReason<C>>,
}

impl<C> CloseReasonRecord<C> {
    /// An empty record.
    pub const fn new() -> Self {
        Self { reason: None }
    }

    /// Write `reason`, if no reason was written before; the first one
    /// stays. What happened, when this was the first.
    #[must_use = "what happened is to be published in the lend"]
    pub fn record(&mut self, reason: CloseReason<C>) -> Option<Happened<CloseReasonWritten>> {
        if self.reason.is_some() {
            return None;
        }
        self.reason = Some(reason);
        Some(Happened::new())
    }

    /// The reason, once one is written.
    pub fn reason(&self) -> Option<&CloseReason<C>> {
        self.reason.as_ref()
    }

    /// Whether a reason is written.
    pub fn is_written(&self) -> bool {
        self.reason.is_some()
    }
}

impl<C> Default for CloseReasonRecord<C> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[derive(Debug, PartialEq, Eq)]
    struct Violation;
    impl fmt::Display for Violation {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("frame of a wrong type")
        }
    }
    impl Error for Violation {}
    impl TransportClose for Violation {
        fn code(&self) -> TransportErrorCode {
            TransportErrorCode::PROTOCOL_VIOLATION
        }
        fn frame_type(&self) -> Option<VarInt> {
            Some(VarInt::from_u32(0x1e))
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Done;
    impl fmt::Display for Done {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("done")
        }
    }
    impl Error for Done {}
    impl ApplicationClose for Done {
        fn code(&self) -> ApplicationErrorCode {
            ApplicationErrorCode::new(VarInt::from_u32(7))
        }
        fn reason_phrase(&self) -> Bytes {
            Bytes::from_static(b"bye")
        }
    }

    /// Why a link of the tests ended.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Terminated;
    impl fmt::Display for Terminated {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("the relay terminated the link")
        }
    }
    impl Error for Terminated {}

    type Cause = LocalCloseCause<Violation, Violation, Done, Terminated>;

    #[test]
    fn each_branch_becomes_its_kind_of_close() {
        assert_eq!(
            Cause::Connection(Violation).immediate_close(),
            Some(ImmediateClose::Transport(TransportImmediateClose {
                code: TransportErrorCode::PROTOCOL_VIOLATION,
                frame_type: Some(VarInt::from_u32(0x1e)),
                reason_phrase: Bytes::new(),
            }))
        );
        assert_eq!(
            Cause::Handshake(Violation).immediate_close(),
            Cause::Connection(Violation).immediate_close(),
        );
        assert_eq!(
            Cause::Application(Done).immediate_close(),
            Some(ImmediateClose::Application(ApplicationImmediateClose {
                code: ApplicationErrorCode::new(VarInt::from_u32(7)),
                reason_phrase: Bytes::from_static(b"bye"),
            }))
        );
    }

    #[test]
    fn the_end_of_a_link_becomes_no_close() {
        assert_eq!(Cause::LinkEnded(Terminated).immediate_close(), None);
    }

    #[test]
    fn the_cause_shows_as_its_error() {
        assert_eq!(
            Cause::Handshake(Violation).to_string(),
            "frame of a wrong type"
        );
        assert_eq!(
            Cause::LinkEnded(Terminated).to_string(),
            "the relay terminated the link"
        );
    }

    #[test]
    fn the_first_reason_stays() {
        let mut record = CloseReasonRecord::<Cause>::new();
        assert!(!record.is_written());
        let first = CloseReason::Local(Arc::new(Cause::Connection(Violation)));
        assert!(record.record(first.clone()).is_some());
        assert!(record.record(CloseReason::IdleTimeout).is_none());
        assert_eq!(record.reason(), Some(&first));
    }

    #[test]
    fn passing_through_keeps_the_close() {
        let close = Cause::Application(Done)
            .immediate_close()
            .expect("an application close");
        let mut policy = PassThroughImmediateClosePolicy;
        let adjusted = ImmediateClosePolicy::<Cause>::adjust(
            &mut policy,
            &Cause::Application(Done),
            EncryptionLevel::Initial,
            close.clone(),
        );
        assert_eq!(adjusted, close);
    }
}
