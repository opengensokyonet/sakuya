//! The receive direction of one stream: the contracts and policies a stream
//! receiver consults, and the types it reports.
//!
//! The stream receiver itself, `sakuya_stream_sets::receive::StreamReceiver`,
//! is in the package `sakuya_stream_sets`. It composes three contracts that
//! one type implements: the receive buffer
//! ([`StreamReceiveBuffer`](crate::receive_buffer::StreamReceiveBuffer)), the
//! receive flow control policy
//! ([`ReceiveFlowControlPolicy`](flow_control::ReceiveFlowControlPolicy)) and
//! the receive termination policy
//! ([`ReceiveTerminationPolicy`](termination::ReceiveTerminationPolicy)).
//! [`composition::ReceiveComposition`] joins three independent components.
//!
//! The receiver is also generic over the type of its reset facts, a
//! [`RemoteResetFacts`](remote_reset::RemoteResetFacts): what a reset of the
//! peer states and how far the peer still owes data after it.
//! [`RemoteReset`](remote_reset::RemoteReset), the default, is the reset of
//! RFC 9000.
use sakuya_var_int::VarInt;

pub mod composition;
pub mod flow_control;
pub mod read;
pub mod remote_reset;
pub mod stop;
pub mod termination;
pub mod violation;

/// The mode of a local delivery limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BoundaryMode {
    /// The limit follows reception and bounds nothing locally.
    Following,
    /// The limit is fixed at this offset; it can only stay or tighten.
    ///
    /// Fixing a following limit is a real change even when the value equals
    /// the current accounted end.
    Fixed(VarInt),
}

impl BoundaryMode {
    /// The offset the limit bounds at: the fixed value, or [`VarInt::MAX`]
    /// while following.
    pub fn effective_limit(self) -> VarInt {
        match self {
            Self::Following => VarInt::MAX,
            Self::Fixed(limit) => limit,
        }
    }
}

/// The state of a stream's receive direction ([RFC 9000 §3.2]), as far as
/// the stream receiver knows it.
///
/// It follows from the final size, the ranges received, the reset facts and
/// the read result the application has; it is read, never kept, and no
/// operation acts on it. A reset that still owes a prefix, a
/// `RESET_STREAM_AT` of the reliable stream reset extension, acts as a FIN
/// does: it leads to Size Known, and Data Recvd once the prefix it owes was
/// received ([draft-ietf-quic-reliable-stream-reset-11 §5.3]). A reset that
/// owes nothing leads to Reset Recvd: the reset facts keep no kind of frame,
/// so a `RESET_STREAM_AT` with a reliable size of zero reads as the
/// `RESET_STREAM` it is equivalent to for data delivery (§5 of the draft).
///
/// What only this side decides, a STOP request, a reader dropped, a buffer
/// the receive termination policy destroyed or the end of the layer, is no
/// state of its own: the state stays where the peer's frames put it.
///
/// [RFC 9000 §3.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-3.2
/// [draft-ietf-quic-reliable-stream-reset-11 §5.3]: https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-11.html#section-5.3
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReceiveStreamState {
    /// The final size is not known.
    Recv,
    /// The final size is known and data below it, or below the prefix a reset
    /// owes, is missing.
    SizeKnown,
    /// Every byte below the final size, or below the prefix a reset owes, was
    /// received.
    ///
    /// A stream that received all its data and then a reset that owes
    /// nothing stays here when it presents the reset as a normal end
    /// ([`ResetPresentation::Suppress`](termination::ResetPresentation::Suppress)).
    DataRecvd,
    /// A reset that owes nothing was received.
    ResetRecvd,
    /// A read gave the application the end of the stream, or the reset after
    /// the whole prefix it owed.
    DataRead,
    /// A read gave the application a reset that owed nothing.
    ResetRead,
}

#[cfg(any(test, feature = "test-util"))]
#[allow(
    missing_docs,
    reason = "only for tests, compiled with the feature `test-util`"
)]
pub mod test_support;
