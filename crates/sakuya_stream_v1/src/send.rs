//! The send direction of one stream: the policies a stream sender consults
//! and the types it reports, with the composition that joins the policies
//! with a send buffer.
//!
//! The stream sender itself, `sakuya_stream_sets::send::StreamSender`, is in
//! the package `sakuya_stream_sets`; it is generic over the reset target it
//! commits, by default [`LocalReset`], the reset of RFC 9000, which a
//! `RESET_STREAM` frame announces.
//!
//! [`composition::SendComposition`] joins three independent components
//! transparently; a single type may also fulfil several contracts.
use local_reset::{LocalReset, LocalResetTarget};
use sakuya_wire_v1::frame::UndecidedLength;
use sakuya_wire_v1::frame::{reset_stream::ResetStreamFrame, stream::StreamFrame};
use sakuya_wire_v1::stream_id::StreamId;
use sakuya_wire_v1::var_int::{VarInt, VarIntField};
use snafu::Snafu;

pub mod composition;
#[allow(
    missing_docs,
    reason = "the derive of `Snafu` makes the public module of the context selectors without documentation"
)]
pub mod finish;
pub mod flow_control;
pub mod local_reset;
pub mod termination;
#[allow(
    missing_docs,
    reason = "the derive of `Snafu` makes the public module of the context selectors without documentation"
)]
pub mod write;

/// The end state of a stream's send direction as the stream sender keeps it.
///
/// A committed end fixes the final size at once; committing does not wait for
/// any frame to be sent or acknowledged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendEndState<T = LocalReset> {
    /// Input is open.
    Open,
    /// A normal close is committed at the written end of that time.
    Closed {
        /// The final size, equal to the written end when closing.
        final_size: VarInt,
        /// Who committed the close.
        source: EndSource,
    },
    /// A reset is committed; it may have replaced a close or an earlier
    /// reset target.
    Reset {
        /// The reset target in effect.
        target: T,
        /// Who committed the current target.
        source: EndSource,
    },
}

impl<T: LocalResetTarget> SendEndState<T> {
    /// The fixed final size, if an end is committed.
    pub fn final_size(&self) -> Option<VarInt> {
        match self {
            Self::Open => None,
            Self::Closed { final_size, .. } => Some(*final_size),
            Self::Reset { target, .. } => Some(target.final_size()),
        }
    }
}

/// The state of a stream's send direction ([RFC 9000 §3.1]), as far as the
/// stream sender knows it.
///
/// It follows from the committed end, the end frames exposed so far, the
/// exposure end and the terminal state; it is read, never kept, and no
/// operation acts on it. A `RESET_STREAM_AT` of the reliable stream reset
/// extension leads to Data Sent, as a FIN does
/// ([draft-ietf-quic-reliable-stream-reset-11 §5.3]).
///
/// [RFC 9000 §3.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-3.1
/// [draft-ietf-quic-reliable-stream-reset-11 §5.3]: https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-11.html#section-5.3
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SendStreamState {
    /// Nothing of the stream was exposed yet.
    ///
    /// A sender that sent only `STREAM_DATA_BLOCKED` frames is still read as
    /// Ready: it does not keep whether one was sent.
    Ready,
    /// Data was exposed, and no end frame yet.
    Send,
    /// The FIN, or a reset frame whose acknowledgement leads to Data Recvd
    /// (a `RESET_STREAM_AT`), was exposed last among the end frames.
    DataSent,
    /// A `RESET_STREAM` was exposed last among the reset frames.
    ResetSent,
    /// All data and the final size were acknowledged.
    DataRecvd,
    /// The reset was acknowledged.
    ResetRecvd,
}

/// Who committed an end state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndSource {
    /// An active close or reset of the application.
    Application,
    /// An automatic decision of the termination policy.
    Policy,
}

/// The terminal states of a send direction ([RFC 9000 §3.1]).
///
/// [RFC 9000 §3.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-3.1
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendTerminalState {
    /// All data and the final size have been acknowledged.
    DataRecvd,
    /// The reset has been acknowledged. Only a send direction that was reset
    /// reaches it.
    ResetRecvd,
}

/// A reset is in effect: the stream takes no more data and no close.
///
/// Writing, flushing and closing report it through their own errors, which
/// hold this one as their source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("the stream was reset"))]
pub struct StreamResetError;

/// The end frame a stream has to send (`StreamEndFrame`): the wire frame that
/// carries the committed end, as `StreamSender::prepare_end_frame` of the package
/// `sakuya_stream_sets` gives it.
///
/// `F` is the reset frame of the stream's reset target
/// ([`LocalResetTarget::Frame`]). The frames hold their fields in the
/// shortest encodings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamEndFrame<F = ResetStreamFrame> {
    /// A STREAM frame with the FIN bit, no data and an offset equal to the
    /// final size. Its Length field is not decided: the packet writer decides
    /// it by the position of the frame in the packet.
    Fin(StreamFrame<&'static [u8], UndecidedLength>),
    /// The frame that announces the reset target in effect.
    Reset(F),
}

impl<F> StreamEndFrame<F> {
    /// The FIN of the stream `stream_id` that ends at `final_size`.
    pub fn fin(stream_id: VarIntField<StreamId>, final_size: VarInt) -> Self {
        // An absent Offset field states offset zero in one byte less.
        let offset = (final_size > VarInt::ZERO).then(|| VarIntField::shortest(final_size));
        match StreamFrame::new(stream_id, offset, &[][..], true) {
            Ok(frame) => Self::Fin(frame),
            // invariant: the frame carries no data, so it ends at its offset,
            // a `VarInt`.
            Err(error) => unreachable!("FIN at {final_size}: {error}"),
        }
    }
}

#[cfg(any(test, feature = "test-util"))]
#[allow(
    missing_docs,
    reason = "only for tests, compiled with the feature `test-util`"
)]
pub mod test_support;
#[cfg(test)]
mod tests;
