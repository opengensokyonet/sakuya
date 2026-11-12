//! The send direction of one stream: the stream sender ([`StreamSender`]),
//! the two policies it consults and the composition that joins them with a
//! send buffer.
//!
//! A stream sender keeps the local state of one stream's send direction: the
//! end state, the peer's stream limit, the write limit end
//! (`write_limit_end`) and the protocol facts that constrain resets. It
//! requires one composition type to fulfil three contracts at once:
//!
//! - [`StreamSendBuffer`], for storage, the written end and the coverage of
//!   connection credit;
//! - [`SendFlowControlPolicy`], for write admission and the
//!   `STREAM_DATA_BLOCKED` signal intent;
//! - [`SendTerminationPolicy`], for automatic end decisions, the write limit,
//!   and the final size of resets the application leaves open.
//!
//! It is generic over the type of its reset target, a [`LocalResetTarget`]:
//! by default [`LocalReset`], the reset of RFC 9000, which a `RESET_STREAM`
//! frame announces.
//!
//! [`composition::SendComposition`] joins three independent components
//! transparently; a single type may also fulfil several contracts.
//!
//! Each operation takes `&mut self` and runs to completion: an operation has
//! exclusive access to the whole stream sender. The connection send flow
//! controller ([`ConnectionSendFlowController`]) is shared by all streams of
//! the connection; the stream sender holds a shared handle to it, given when
//! it is created, for the operations that reserve connection credit. Nothing
//! here waits: an operation that
//! would have to wait for credit or admission reports that instead
//! ([`write::WriteOutcome::Wait`]). Polling, wake-ups, the stream writer
//! handle, send selection and feedback dispatch are not part of this module.
use crate::connection::{CloseReason, ConnectionClosedError};
use crate::connection_send_credit::ConnectionSendFlowController;
use crate::send_buffer::visibility::UsageBeyondCoverageError;
use crate::send_buffer::{
    ExposeUsageError, ExposedContent, StreamSendBuffer, UsageBeyondWrittenEndError,
};
use crate::stream_end::BeyondFinalSizeError;
use core::ops::Deref;
use flow_control::{SendFlowContext, SendFlowControlPolicy, StreamCreditEvent};
use local_reset::{LocalReset, LocalResetTarget};
use sakuya_wire::frame::UndecidedLength;
use sakuya_wire::v1::application_error::ApplicationErrorCode;
use sakuya_wire::v1::frame::{reset_stream::ResetStreamFrame, stream::StreamFrame};
use sakuya_wire::v1::stream_id::StreamId;
use sakuya_wire::var_int::{VarInt, VarIntField};
use snafu::{IntoError, ResultExt, Snafu};
use std::sync::Arc;
use termination::{SendTerminationContext, SendTerminationEvent, SendTerminationPolicy};
use write::SharedWriteLimitReason;

pub mod composition;
pub mod finish;
pub mod flow_control;
pub mod local_reset;
pub mod termination;
pub mod write;

/// The stream sender (`StreamSender`): the per-stream send direction state
/// kept at the connection layer.
///
/// `C` is the composition of a [`StreamSendBuffer`], a
/// [`SendFlowControlPolicy`] and a [`SendTerminationPolicy`] that act on this
/// stream and on the same data; `K` is the connection send flow controller
/// that grants the reservations the buffer takes; `Lc` is the type of the
/// connection's local close cause; `T` is the type of the reset target.
///
/// Operations are grouped by subject: writing and flushing in [`write`](mod@write),
/// close and reset in [`finish`]; peer and feedback facts are applied by the
/// `on_*` methods here.
pub struct StreamSender<C, K, Lc, T = LocalReset>
where
    C: SendTerminationPolicy<T>,
    K: ConnectionSendFlowController,
    T: LocalResetTarget,
{
    stream_id: StreamId,
    peer_stream_limit: VarInt,
    composition: C,
    connection: Arc<K>,
    end: EndPhase<T>,
    stop_sending: StopSending<C::WriteLimitReason>,
    close_reason: Option<CloseReason<Lc>>,
}

/// The end of the send direction:
///
/// ```text
/// Open ──close──▶ Closed
/// Open, Closed ──reset──▶ Reset ──reset (as the target type allows)──▶ Reset
/// ```
///
/// A terminal state can be entered once an end is committed; afterwards the
/// end no longer changes.
enum EndPhase<T> {
    /// Input is open.
    Open,
    /// An end is committed.
    Ended {
        /// The committed end.
        end: CommittedEnd<T>,
        /// The end frames sent so far, kept across a reset that replaces a
        /// close.
        sent: SentEndFrames<T>,
        /// The terminal state, once reached.
        terminal: Option<SendTerminalState>,
    },
}

/// The end frames exposed so far through [`PreparedEndFrame::expose`]. A FIN
/// may be followed by a reset, and a reset frame is exposed again when the
/// reset target changes.
#[derive(Clone, Copy)]
struct SentEndFrames<T> {
    fin: bool,
    /// The reset target whose frame was exposed last.
    last_reset: Option<T>,
}

impl<T: LocalResetTarget> SentEndFrames<T> {
    fn none() -> Self {
        Self {
            fin: false,
            last_reset: None,
        }
    }

    /// Whether an end was exposed whose acknowledgement leads to `state`: for
    /// "Data Recvd" also the FIN, with all data.
    fn reaches(&self, state: SendTerminalState) -> bool {
        (self.fin && state == SendTerminalState::DataRecvd)
            || self
                .last_reset
                .is_some_and(|target| target.acknowledged_state() == state)
    }
}

/// A committed close or reset.
#[derive(Clone, Copy)]
enum CommittedEnd<T> {
    Closed {
        final_size: VarInt,
        source: EndSource,
    },
    Reset {
        target: T,
        source: EndSource,
    },
}

impl<T: LocalResetTarget> EndPhase<T> {
    fn end_state(&self) -> SendEndState<T> {
        match *self {
            Self::Open => SendEndState::Open,
            Self::Ended {
                end: CommittedEnd::Closed { final_size, source },
                ..
            } => SendEndState::Closed { final_size, source },
            Self::Ended {
                end: CommittedEnd::Reset { target, source },
                ..
            } => SendEndState::Reset { target, source },
        }
    }

    fn terminal_state(&self) -> Option<SendTerminalState> {
        match self {
            Self::Open => None,
            Self::Ended { terminal, .. } => *terminal,
        }
    }
}

/// What the peer's `STOP_SENDING` requested, and the write limit that may
/// follow from it:
///
/// ```text
///                STOP_SENDING                  narrow (only lower)
///   NotReceived ──────────────▶ Received ─────────────────────────▶ Received
///                               (no limit)                         (limit)
/// ```
enum StopSending<R> {
    /// No `STOP_SENDING` arrived.
    NotReceived,
    /// The first `STOP_SENDING` arrived with `error_code`.
    Received {
        /// The error code of the first `STOP_SENDING`.
        error_code: ApplicationErrorCode,
        /// The write limit the termination policy set in response, if any.
        write_limit: Option<WriteLimit<R>>,
    },
}

/// The write limit end and the reason that came with it.
struct WriteLimit<R> {
    end: VarInt,
    reason: SharedWriteLimitReason<R>,
}

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

impl<C, K, Lc, T> StreamSender<C, K, Lc, T>
where
    C: SendTerminationPolicy<T>,
    K: ConnectionSendFlowController,
    T: LocalResetTarget,
{
    /// Creates the send direction of `stream_id`.
    ///
    /// `peer_stream_limit` is the initial stream data limit that the peer's
    /// transport parameters grant this stream, or a later `MAX_STREAM_DATA`
    /// value already in effect. `connection` is the connection send flow
    /// controller shared by the streams of the connection.
    pub fn new(
        stream_id: StreamId,
        peer_stream_limit: VarInt,
        composition: C,
        connection: Arc<K>,
    ) -> Self {
        Self {
            stream_id,
            peer_stream_limit,
            composition,
            connection,
            end: EndPhase::Open,
            stop_sending: StopSending::NotReceived,
            close_reason: None,
        }
    }

    /// The stream's ID.
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// The peer's stream data limit currently in effect.
    pub fn peer_stream_limit(&self) -> VarInt {
        self.peer_stream_limit
    }

    /// The end state.
    pub fn end_state(&self) -> SendEndState<T> {
        self.end.end_state()
    }

    /// The write limit end, if a termination policy has set one.
    pub fn write_limit_end(&self) -> Option<VarInt> {
        self.write_limit().map(|limit| limit.end)
    }

    /// The reason of the write limit, if one is set.
    pub fn write_limit_reason(&self) -> Option<&SharedWriteLimitReason<C::WriteLimitReason>> {
        self.write_limit().map(|limit| &limit.reason)
    }

    /// The error code of the first `STOP_SENDING` received, if any.
    pub fn stop_sending_code(&self) -> Option<ApplicationErrorCode> {
        match self.stop_sending {
            StopSending::NotReceived => None,
            StopSending::Received { error_code, .. } => Some(error_code),
        }
    }

    /// The terminal state, once reached.
    pub fn terminal_state(&self) -> Option<SendTerminalState> {
        self.end.terminal_state()
    }

    fn write_limit(&self) -> Option<&WriteLimit<C::WriteLimitReason>> {
        match &self.stop_sending {
            StopSending::NotReceived => None,
            StopSending::Received { write_limit, .. } => write_limit.as_ref(),
        }
    }

    /// Whether the connection has closed.
    pub fn is_connection_closed(&self) -> bool {
        self.close_reason.is_some()
    }

    /// The composition of buffer and policies, for inspection.
    pub fn composition(&self) -> &C {
        &self.composition
    }
}

impl<C, K, Lc, T> StreamSender<C, K, Lc, T>
where
    T: LocalResetTarget,
    K: ConnectionSendFlowController,
    C: StreamSendBuffer<Reservation = K::Reservation>
        + SendFlowControlPolicy<T>
        + SendTerminationPolicy<T>,
{
    /// The written end (`written_end`), as the send buffer keeps it.
    pub fn written_end(&self) -> VarInt {
        self.composition.written_end()
    }

    /// The exposure end (`exposure_end`), as the send buffer keeps it.
    pub fn exposure_end(&self) -> VarInt {
        self.composition.exposure_end()
    }

    /// The reliable size (`reliable_size`): the end up to which data must
    /// still be delivered reliably.
    ///
    /// It follows the written end while input is open, equals the final size
    /// after a close, and is the reliable size of the reset target after a
    /// reset.
    pub fn reliable_size(&self) -> VarInt {
        match self.end_state() {
            SendEndState::Open => self.written_end(),
            SendEndState::Closed { final_size, .. } => final_size,
            SendEndState::Reset { target, .. } => target.reliable_size(),
        }
    }

    /// Applies a `MAX_STREAM_DATA` value: the peer's stream limit becomes the
    /// larger of the current limit and `limit`.
    ///
    /// A growth is reported to the flow-control policy.
    pub fn on_max_stream_data(&mut self, limit: VarInt) {
        if limit <= self.peer_stream_limit {
            return;
        }
        let previous_limit = core::mem::replace(&mut self.peer_stream_limit, limit);
        self.notify_flow_control(StreamCreditEvent::PeerStreamLimitIncreased {
            previous_limit,
            current_limit: limit,
        });
    }

    /// Applies a `STOP_SENDING` frame with `error_code` that protocol
    /// validation has accepted for this stream.
    ///
    /// The request is recorded and given to the termination policy, which
    /// decides whether and how to end the stream; receiving it changes
    /// nothing else. Ignored once the connection has closed.
    pub fn on_stop_sending(&mut self, error_code: ApplicationErrorCode) {
        if self.is_connection_closed() {
            return;
        }
        if let StopSending::NotReceived = self.stop_sending {
            self.stop_sending = StopSending::Received {
                error_code,
                write_limit: None,
            };
        }
        self.dispatch_termination(SendTerminationEvent::StopSendingReceived { error_code });
    }

    /// Records that the application gave up its stream writer.
    ///
    /// The termination policy decides what follows. Data already accepted and
    /// its reliable delivery stay with the stream sender either way.
    pub fn on_writer_abandoned(&mut self) {
        self.dispatch_termination(SendTerminationEvent::WriterAbandoned);
    }

    /// Records that the connection has closed for `reason`.
    ///
    /// The connection side calls this on every stream in the poll in which
    /// the connection records its first close reason, whichever its source;
    /// the stream never reads the reason from anywhere else.
    ///
    /// Every later operation fails with a [`ConnectionClosedError`] that
    /// carries `reason`; results returned before are not changed. Only the
    /// first reason is kept; a later call has no effect.
    pub fn on_connection_closed(&mut self, reason: CloseReason<Lc>) {
        if self.is_connection_closed() {
            return;
        }
        self.close_reason = Some(reason);
        self.dispatch_termination(SendTerminationEvent::ConnectionClosed);
    }

    /// Records that the send direction reached a terminal state: all data
    /// and the final size, or the reset, were acknowledged.
    ///
    /// `state` must be one the committed end can reach: "Reset Recvd" follows
    /// "Reset Sent" only ([RFC 9000 §3.1]), so a send direction that was
    /// closed and never reset cannot enter [`SendTerminalState::ResetRecvd`].
    /// An end whose acknowledgement leads to `state` must also have been
    /// sent, as recorded by [`PreparedEndFrame::expose`]:
    ///
    /// - the reset frame exposed last, if its target reaches `state` when
    ///   acknowledged ([`LocalResetTarget::acknowledged_state`]): a
    ///   `RESET_STREAM` leads to [`SendTerminalState::ResetRecvd`];
    /// - for [`SendTerminalState::DataRecvd`] also a FIN. After a reset the
    ///   caller enters it only when the FIN was sent before and all data
    ///   with the FIN was acknowledged; otherwise the stream waits for its
    ///   reset to be acknowledged ([RFC 9000 §13.3]).
    ///
    /// Only the first terminal state is kept; a later call with a state the
    /// committed end can reach succeeds without effect. This entry is
    /// provisional.
    ///
    /// # Errors
    ///
    /// [`EnterTerminalStateError`] if no end is committed, if the committed
    /// end cannot reach `state`, or if no end that leads to `state` was sent,
    /// checked in this order. Nothing changes then.
    ///
    /// [RFC 9000 §3.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-3.1
    /// [RFC 9000 §13.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-13.3
    pub fn enter_terminal_state(
        &mut self,
        state: SendTerminalState,
    ) -> Result<(), EnterTerminalStateError> {
        use enter_terminal_state_error as e;
        let EndPhase::Ended {
            end,
            sent,
            terminal,
        } = &mut self.end
        else {
            return e::EndNotCommittedSnafu.fail();
        };
        if let (SendTerminalState::ResetRecvd, CommittedEnd::Closed { .. }) = (state, &*end) {
            return e::ResetNotCommittedSnafu.fail();
        }
        if !sent.reaches(state) {
            return match state {
                SendTerminalState::DataRecvd => e::DataRecvdEndNotSentSnafu.fail(),
                SendTerminalState::ResetRecvd => e::ResetStreamNotSentSnafu.fail(),
            };
        }
        if terminal.is_some() {
            return Ok(());
        }
        *terminal = Some(state);
        self.dispatch_termination(SendTerminationEvent::TerminalStateEntered { state });
        Ok(())
    }

    /// Settles the first exposure of the data up to `usage_end` through the
    /// send buffer, and reports a grown exposure end to both policies
    /// afterwards.
    ///
    /// Data must not pass the final size the committed end fixed. The end
    /// frames are not exposed here but through
    /// [`prepare_end_frame`](Self::prepare_end_frame). Returns the newly
    /// committed connection credit. This entry is provisional.
    ///
    /// # Errors
    ///
    /// [`SenderExposeUsageError`] if the exposure is inconsistent with the
    /// end state, then if the send buffer refuses it; nothing changes then.
    pub fn expose_usage_through(
        &mut self,
        usage_end: VarInt,
    ) -> Result<VarInt, SenderExposeUsageError> {
        use sender_expose_usage_error as e;
        if let Some(final_size) = self.end_state().final_size() {
            BeyondFinalSizeError::check(final_size, usage_end).context(e::BeyondFinalSizeSnafu)?;
        }
        match self.settle_exposure(usage_end, ExposedContent::Data) {
            Ok(committed) => Ok(committed),
            Err(ExposeUsageError::BeyondWrittenEnd { source }) => {
                Err(e::BeyondWrittenEndSnafu.into_error(source))
            }
            Err(ExposeUsageError::BeyondCoverage { source }) => {
                Err(e::BeyondCoverageSnafu.into_error(source))
            }
            Err(
                error @ (ExposeUsageError::BeyondFinalSize { .. }
                | ExposeUsageError::FinalSizeMismatch { .. }
                | ExposeUsageError::FinalSizeBelowExposure { .. }),
            ) => {
                // invariant: the only final size the send buffer can know is
                // the one the committed end fixed, which the check above
                // compared, and data exposure never passes it, so the
                // exposure end stays at or below it. A send buffer that still
                // refuses the final size breaks the `StreamSendBuffer` contract.
                unreachable!("send buffer refused a checked exposure through {usage_end}: {error}")
            }
        }
    }

    /// Exposes through the send buffer and reports a grown exposure end to
    /// both policies.
    fn settle_exposure(
        &mut self,
        usage_end: VarInt,
        content: ExposedContent,
    ) -> Result<VarInt, ExposeUsageError> {
        let previous = self.exposure_end();
        let committed = self.composition.expose_usage_through(usage_end, content)?;
        let exposure_end = self.exposure_end();
        if exposure_end > previous {
            self.notify_flow_control(StreamCreditEvent::FirstExposed { exposure_end });
            self.dispatch_termination(SendTerminationEvent::FirstExposed { exposure_end });
        }
        Ok(committed)
    }

    /// Prepares the end frame the stream has to send now, if any.
    ///
    /// The frame follows from the committed end and from the end frames
    /// exposed before:
    ///
    /// - a reset is in effect and the frame of its target was not the reset
    ///   frame exposed last: the frame of the target
    ///   ([`LocalResetTarget::frame`]), also if a close was replaced and its
    ///   FIN was exposed;
    /// - a close is in effect and the FIN was not exposed yet: the FIN.
    ///
    /// No frame is due once the connection has closed or a terminal state was
    /// entered. The returned guard holds the stream sender: it gives the
    /// frame to write, and [`PreparedEndFrame::expose`] settles its
    /// exposure after the frame was written to a packet. Dropping the guard
    /// changes nothing. This entry is provisional.
    pub fn prepare_end_frame(&mut self) -> Option<PreparedEndFrame<'_, C, K, Lc, T>> {
        if self.is_connection_closed() || self.terminal_state().is_some() {
            return None;
        }
        let EndPhase::Ended { end, sent, .. } = &self.end else {
            return None;
        };
        let (frame, exposed) = match *end {
            CommittedEnd::Closed { final_size, .. } => {
                if sent.fin {
                    return None;
                }
                (
                    StreamEndFrame::fin(VarIntField::shortest(self.stream_id), final_size),
                    ExposedEndFrame::Fin,
                )
            }
            CommittedEnd::Reset { target, .. } => {
                if sent.last_reset == Some(target) {
                    return None;
                }
                (
                    StreamEndFrame::Reset(target.frame(self.stream_id)),
                    ExposedEndFrame::Reset(target),
                )
            }
        };
        Some(PreparedEndFrame {
            sender: self,
            frame,
            exposed,
        })
    }

    /// The limit to carry in a `STREAM_DATA_BLOCKED` frame, if the
    /// flow-control policy currently wants one sent.
    ///
    /// The limit is the current peer stream limit, never a value of the
    /// policy's choosing. No signal is offered after a reset, in a terminal
    /// state or after the connection closed ([RFC 9000 §3.3]). Querying
    /// neither consumes the intent nor counts as sending.
    ///
    /// [RFC 9000 §3.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-3.3
    pub fn stream_data_blocked_limit(&self) -> Option<VarInt> {
        let allowed = !self.is_connection_closed()
            && self.terminal_state().is_none()
            && !matches!(self.end_state(), SendEndState::Reset { .. });
        (allowed
            && self
                .composition
                .wants_stream_data_blocked(&self.flow_context()))
        .then_some(self.peer_stream_limit)
    }

    /// Records that a `STREAM_DATA_BLOCKED` frame carrying
    /// `stream_data_limit` was sent.
    ///
    /// Every sending is reported, also of a value sent before.
    pub fn on_stream_data_blocked_sent(&mut self, stream_data_limit: VarInt) {
        self.notify_flow_control(StreamCreditEvent::StreamBlockedSignalSent { stream_data_limit });
    }

    /// Records that a `STREAM_DATA_BLOCKED` frame carrying
    /// `stream_data_limit` was acknowledged.
    ///
    /// The value is the one the acknowledged frame carried, not the current
    /// limit; it does not promise that the peer raises its limit.
    pub fn on_stream_data_blocked_acknowledged(&mut self, stream_data_limit: VarInt) {
        self.notify_flow_control(StreamCreditEvent::StreamBlockedSignalAcknowledged {
            stream_data_limit,
        });
    }

    /// Fails once the connection has closed.
    fn check_connection_open(&self) -> Result<(), ConnectionClosedError<Lc>> {
        match &self.close_reason {
            Some(reason) => Err(ConnectionClosedError::new(reason.clone())),
            None => Ok(()),
        }
    }

    fn flow_context(&self) -> SendFlowContext<T> {
        SendFlowContext {
            stream_id: self.stream_id,
            written_end: self.written_end(),
            exposure_end: self.exposure_end(),
            peer_stream_limit: self.peer_stream_limit,
            write_limit_end: self.write_limit_end(),
            end_state: self.end_state(),
            terminal_state: self.terminal_state(),
        }
    }

    fn termination_context(&self) -> SendTerminationContext<T> {
        SendTerminationContext {
            stream_id: self.stream_id,
            written_end: self.written_end(),
            exposure_end: self.exposure_end(),
            reliable_size: self.reliable_size(),
            end_state: self.end_state(),
            stop_sending: self.stop_sending_code(),
            write_limit_end: self.write_limit_end(),
            terminal_state: self.terminal_state(),
            connection_closed: self.is_connection_closed(),
        }
    }

    fn notify_flow_control(&mut self, event: StreamCreditEvent) {
        let context = self.flow_context();
        self.composition.on_flow_event(event, &context);
    }

    /// Gives `event` to the termination policy and commits its decision.
    ///
    /// A committed decision is reported back to the policy as a further event,
    /// which may lead to another decision. Every decision that changes
    /// anything moves the end state, the reliable size or the write limit
    /// strictly in its only permitted direction, so the chain ends; a decision
    /// that changes nothing ends it.
    fn dispatch_termination(&mut self, mut event: SendTerminationEvent) {
        loop {
            let context = self.termination_context();
            let action = self.composition.on_termination_event(event, &context);
            match self.apply_termination_action(action) {
                Some(receipt) => event = receipt,
                None => return,
            }
        }
    }
}

/// A reset is in effect: the stream takes no more data and no close.
///
/// Writing, flushing and closing report it through their own errors, which
/// hold this one as their source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("the stream was reset"))]
pub struct StreamResetError;

/// Failures of [`StreamSender::expose_usage_through`]; none of them changes
/// any state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(sender_expose_usage_error), visibility(pub(crate)))]
pub enum SenderExposeUsageError {
    /// Data passes the final size the committed end fixed.
    #[snafu(display("data exposure passes the final size"))]
    BeyondFinalSize {
        /// The fixed final size and the rejected usage end.
        source: BeyondFinalSizeError,
    },
    /// The usage end lies beyond the written end.
    #[snafu(display("cannot expose usage that was not written"))]
    BeyondWrittenEnd {
        /// The rejected usage end and the written end.
        source: UsageBeyondWrittenEndError,
    },
    /// The send buffer's stored coverage does not reach the usage end.
    #[snafu(display("cannot expose usage without stored coverage"))]
    BeyondCoverage {
        /// The rejected usage end and the end of the stored coverage.
        source: UsageBeyondCoverageError,
    },
}

/// The end frame a stream has to send (`StreamEndFrame`): the wire frame that
/// carries the committed end, as [`StreamSender::prepare_end_frame`] gives it.
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
    fn fin(stream_id: VarIntField<StreamId>, final_size: VarInt) -> Self {
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

/// The end frame a [`PreparedEndFrame`] stands for, as the stream sender
/// records it once exposed.
#[derive(Clone, Copy)]
enum ExposedEndFrame<T> {
    Fin,
    Reset(T),
}

/// An end frame prepared by [`StreamSender::prepare_end_frame`]
/// (`PreparedEndFrame`): the guard holds the stream sender until the frame is
/// exposed or the guard is dropped.
///
/// It dereferences to the [`StreamEndFrame`] to write. After the frame was written
/// to a packet, [`expose`](Self::expose) settles its first exposure; it does
/// not fail. Dropping the guard changes nothing.
///
/// `Lc` is the type of the connection's local close cause, as for the
/// [`StreamSender`] it holds.
pub struct PreparedEndFrame<'a, C, K, Lc, T = LocalReset>
where
    C: SendTerminationPolicy<T>,
    K: ConnectionSendFlowController,
    T: LocalResetTarget,
{
    sender: &'a mut StreamSender<C, K, Lc, T>,
    frame: StreamEndFrame<T::Frame>,
    exposed: ExposedEndFrame<T>,
}

impl<C, K, Lc, T> Deref for PreparedEndFrame<'_, C, K, Lc, T>
where
    C: SendTerminationPolicy<T>,
    K: ConnectionSendFlowController,
    T: LocalResetTarget,
{
    type Target = StreamEndFrame<T::Frame>;

    fn deref(&self) -> &StreamEndFrame<T::Frame> {
        &self.frame
    }
}

impl<C, K, Lc, T> PreparedEndFrame<'_, C, K, Lc, T>
where
    T: LocalResetTarget,
    K: ConnectionSendFlowController,
    C: StreamSendBuffer<Reservation = K::Reservation>
        + SendFlowControlPolicy<T>
        + SendTerminationPolicy<T>,
{
    /// Settles the first exposure of the frame, which was written to a
    /// packet: the credit that covers the usage up to the final size is
    /// committed, the frame is recorded as exposed for
    /// [`enter_terminal_state`](StreamSender::enter_terminal_state), and a
    /// grown exposure end is reported to both policies.
    ///
    /// Returns the newly committed connection credit.
    pub fn expose(self) -> VarInt {
        let Self {
            sender,
            frame: _,
            exposed,
        } = self;
        // invariant: the frame is due only while an end is committed, and the
        // end fixes the final size.
        let Some(final_size) = sender.end_state().final_size() else {
            unreachable!("an end frame is prepared only after an end is committed")
        };
        let committed = match sender.settle_exposure(final_size, ExposedContent::FinalSize) {
            Ok(committed) => committed,
            // invariant: a committed end keeps its final size within the
            // written end, at or above the exposure end and covered by the
            // buffer's stored coverage, and the buffer knows no other final
            // size. A send buffer that still refuses it breaks the
            // `StreamSendBuffer` contract.
            Err(error) => unreachable!("send buffer refused the final size {final_size}: {error}"),
        };
        if let EndPhase::Ended { sent, .. } = &mut sender.end {
            match exposed {
                ExposedEndFrame::Fin => sent.fin = true,
                ExposedEndFrame::Reset(target) => sent.last_reset = Some(target),
            }
        }
        committed
    }
}

/// Failures of [`StreamSender::enter_terminal_state`]; none of them changes
/// any state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(enter_terminal_state_error), visibility(pub(crate)))]
pub enum EnterTerminalStateError {
    /// No end is committed: a terminal state needs a fixed final size.
    #[snafu(display("a send direction reaches a terminal state only after its end is committed"))]
    EndNotCommitted,
    /// [`SendTerminalState::ResetRecvd`] was requested, but the committed end
    /// is a close: no reset was committed that could have been acknowledged.
    #[snafu(display("a send direction that was not reset cannot reach Reset Recvd"))]
    ResetNotCommitted,
    /// [`SendTerminalState::DataRecvd`] was requested, but no FIN was sent,
    /// and the reset frame sent last, if any, does not lead to it: the peer
    /// cannot have acknowledged the final size in a way that reaches Data
    /// Recvd.
    #[snafu(display(
        "a send direction reaches Data Recvd only after a FIN, or a reset frame that leads to it, was sent"
    ))]
    DataRecvdEndNotSent,
    /// [`SendTerminalState::ResetRecvd`] was requested, but no `RESET_STREAM`
    /// was sent that could have been acknowledged.
    #[snafu(display("a send direction reaches Reset Recvd only after a RESET_STREAM was sent"))]
    ResetStreamNotSent,
}

#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;
