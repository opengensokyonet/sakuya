//! The send direction of one stream: the stream sender ([`StreamSender`]),
//! the two policies it consults and the composition that joins them with a
//! send buffer.
//!
//! A stream sender keeps the local state of one stream's send direction: the
//! end state, the peer's stream limit, the write limit end
//! (`write_limit_end`) and the protocol facts that constrain resets. It
//! requires one composition type to fulfil three contracts at once:
//!
//! - [`SendBuffer`], for storage, the written end and the coverage of
//!   connection credit;
//! - [`SendFlowControlPolicy`], for write admission and the
//!   `STREAM_DATA_BLOCKED` signal intent;
//! - [`SendTerminationPolicy`], for automatic end decisions, the write limit,
//!   and the final size of resets the application leaves open.
//!
//! [`composition::SendComposition`] joins three independent components
//! transparently; a single type may also fulfil several contracts.
//!
//! Each operation takes `&mut self` and runs to completion: an operation has
//! exclusive access to the whole stream sender. The connection send flow
//! controller is passed in by the composing code for the operations that
//! reserve or commit connection credit. Nothing here waits: an operation that
//! would have to wait for credit or admission reports that instead
//! ([`write::WriteOutcome::Wait`]). Polling, wake-ups, the stream writer
//! handle, send selection and feedback dispatch are not part of this module.
use crate::connection_send_credit::ConnectionSendFlowController;
use crate::send_buffer::{ExposeUsageError, ExposedEnd, SendBuffer, expose_usage_error};
use flow_control::{SendFlowContext, SendFlowControlPolicy, StreamCreditEvent};
use sakuya_wire::application_error::ApplicationErrorCode;
use sakuya_wire::stream_id::StreamId;
use sakuya_wire::var_int::VarInt;
use snafu::{Snafu, ensure};
use termination::{SendTerminationContext, SendTerminationEvent, SendTerminationPolicy};
use write::SharedWriteLimitReason;

pub mod composition;
pub mod finish;
pub mod flow_control;
pub mod termination;
pub mod write;

/// The stream sender (`StreamSender`): the per-stream send direction state
/// kept at the connection layer.
///
/// `C` is the composition of a [`SendBuffer`], a
/// [`SendFlowControlPolicy`] and a [`SendTerminationPolicy`] that act on this
/// stream and on the same data.
///
/// Operations are grouped by subject: writing and flushing in [`write`](mod@write),
/// close and reset in [`finish`]; peer and feedback facts are applied by the
/// `on_*` methods here.
pub struct StreamSender<C: SendTerminationPolicy> {
    stream_id: StreamId,
    peer_stream_limit: VarInt,
    reset_stream_at_supported: bool,
    composition: C,
    end: EndPhase,
    stop_sending: StopSending<C::WriteLimitReason>,
    connection_closed: bool,
}

/// The end of the send direction:
///
/// ```text
///          close           reset           reset (lower reliable size)
///   Open ───────▶ Closed ───────▶ Reset ◀──┐
///     │                             ▲ └────┘
///     └──────────── reset ──────────┘
/// ```
///
/// A terminal state can be entered once an end is committed; afterwards the
/// end no longer changes.
enum EndPhase {
    /// Input is open.
    Open,
    /// An end is committed.
    Ended {
        /// The committed end.
        end: CommittedEnd,
        /// The terminal state, once reached.
        terminal: Option<SendTerminalState>,
    },
}

/// A committed close or reset.
#[derive(Clone, Copy)]
enum CommittedEnd {
    Closed {
        final_size: VarInt,
        source: EndSource,
    },
    Reset {
        target: ResetTarget,
        source: EndSource,
    },
}

impl EndPhase {
    fn end_state(&self) -> SendEndState {
        match self {
            Self::Open => SendEndState::Open,
            Self::Ended {
                end: CommittedEnd::Closed { final_size, source },
                ..
            } => SendEndState::Closed {
                final_size: *final_size,
                source: *source,
            },
            Self::Ended {
                end: CommittedEnd::Reset { target, source },
                ..
            } => SendEndState::Reset {
                target: *target,
                source: *source,
            },
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
pub enum SendEndState {
    /// Input is open.
    Open,
    /// A normal close is committed at the written end of that time.
    Closed {
        /// The final size, equal to the written end when closing.
        final_size: VarInt,
        /// Who committed the close.
        source: EndSource,
    },
    /// A reset is committed; it may have replaced a close.
    Reset {
        /// The effective reset target.
        target: ResetTarget,
        /// Who committed the current target.
        source: EndSource,
    },
}

impl SendEndState {
    /// The fixed final size, if an end is committed.
    pub fn final_size(&self) -> Option<VarInt> {
        match self {
            Self::Open => None,
            Self::Closed { final_size, .. } => Some(*final_size),
            Self::Reset { target, .. } => Some(target.final_size),
        }
    }
}

/// A complete reset target: error code, reliable size and final size.
///
/// A plain reset has reliable size zero; a reliable size above zero needs the
/// `RESET_STREAM_AT` extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResetTarget {
    /// The application error code.
    pub error_code: ApplicationErrorCode,
    /// The reliable size (`reliable_size`): the prefix that must still be
    /// delivered.
    pub reliable_size: VarInt,
    /// The final size.
    pub final_size: VarInt,
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
    /// The reset has been acknowledged.
    ResetRecvd,
}

impl<C: SendTerminationPolicy> StreamSender<C> {
    /// Creates the send direction of `stream_id`.
    ///
    /// `peer_stream_limit` is the initial stream data limit that the peer's
    /// transport parameters grant this stream, or a later `MAX_STREAM_DATA`
    /// value already in effect. `reset_stream_at_supported` tells whether the
    /// handshake negotiated the `RESET_STREAM_AT` extension.
    pub fn new(
        stream_id: StreamId,
        peer_stream_limit: VarInt,
        reset_stream_at_supported: bool,
        composition: C,
    ) -> Self {
        Self {
            stream_id,
            peer_stream_limit,
            reset_stream_at_supported,
            composition,
            end: EndPhase::Open,
            stop_sending: StopSending::NotReceived,
            connection_closed: false,
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
    pub fn end_state(&self) -> SendEndState {
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
        self.connection_closed
    }

    /// Whether the handshake negotiated `RESET_STREAM_AT`.
    pub fn reset_stream_at_supported(&self) -> bool {
        self.reset_stream_at_supported
    }

    /// The composition of buffer and policies, for inspection.
    pub fn composition(&self) -> &C {
        &self.composition
    }
}

impl<C> StreamSender<C>
where
    C: SendBuffer + SendFlowControlPolicy + SendTerminationPolicy,
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
    /// after a close, and is the reset's reliable size after a reset.
    pub fn reliable_size(&self) -> VarInt {
        match self.end_state() {
            SendEndState::Open => self.written_end(),
            SendEndState::Closed { final_size, .. } => final_size,
            SendEndState::Reset { target, .. } => target.reliable_size,
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
        if self.connection_closed {
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

    /// Records that the connection has closed.
    ///
    /// Every later operation fails with a connection-closed error; results
    /// returned before are not changed.
    pub fn on_connection_closed(&mut self) {
        if self.connection_closed {
            return;
        }
        self.connection_closed = true;
        self.dispatch_termination(SendTerminationEvent::ConnectionClosed);
    }

    /// Records that the send direction reached a terminal state: all data
    /// and the final size, or the reset, were acknowledged.
    ///
    /// Only the first terminal state is kept; later calls succeed without
    /// effect. This entry is provisional.
    ///
    /// # Errors
    ///
    /// [`EndNotCommittedError`] if no end is committed: a terminal state
    /// needs a fixed final size. Nothing changes then.
    pub fn enter_terminal_state(
        &mut self,
        state: SendTerminalState,
    ) -> Result<(), EndNotCommittedError> {
        let EndPhase::Ended { terminal, .. } = &mut self.end else {
            return EndNotCommittedSnafu.fail();
        };
        if terminal.is_some() {
            return Ok(());
        }
        *terminal = Some(state);
        self.dispatch_termination(SendTerminationEvent::TerminalStateEntered { state });
        Ok(())
    }

    /// Settles the first exposure of usage up to `usage_end` through the send
    /// buffer, and reports a grown exposure end to both policies afterwards.
    ///
    /// A final size must equal the one the committed end fixed; data must not
    /// pass it. Returns the newly committed connection credit. This entry is
    /// provisional.
    ///
    /// # Errors
    ///
    /// [`ExposeUsageError`] if the exposure is inconsistent with the end
    /// state or the send buffer; nothing changes then.
    pub fn expose_usage_through(
        &mut self,
        usage_end: VarInt,
        end: ExposedEnd,
        connection: &mut ConnectionSendFlowController,
    ) -> Result<VarInt, ExposeUsageError> {
        let fixed_final_size = self.end_state().final_size();
        match (end, fixed_final_size) {
            (ExposedEnd::FinalSize, None) => {
                return expose_usage_error::FinalSizeNotFixedSnafu {
                    final_size: usage_end,
                }
                .fail();
            }
            (ExposedEnd::FinalSize, Some(final_size)) => ensure!(
                usage_end == final_size,
                expose_usage_error::FinalSizeMismatchSnafu {
                    final_size: usage_end,
                    established: final_size,
                }
            ),
            (ExposedEnd::Data, Some(final_size)) => ensure!(
                usage_end <= final_size,
                expose_usage_error::BeyondFinalSizeSnafu {
                    usage_end,
                    final_size,
                }
            ),
            (ExposedEnd::Data, None) => {}
        }
        let previous = self.exposure_end();
        let committed = self
            .composition
            .expose_usage_through(usage_end, end, connection)?;
        let exposure_end = self.exposure_end();
        if exposure_end > previous {
            self.notify_flow_control(StreamCreditEvent::FirstExposed { exposure_end });
            self.dispatch_termination(SendTerminationEvent::FirstExposed { exposure_end });
        }
        Ok(committed)
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
        let allowed = !self.connection_closed
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

    fn flow_context(&self) -> SendFlowContext {
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

    fn termination_context(&self) -> SendTerminationContext {
        SendTerminationContext {
            stream_id: self.stream_id,
            written_end: self.written_end(),
            exposure_end: self.exposure_end(),
            reliable_size: self.reliable_size(),
            end_state: self.end_state(),
            stop_sending: self.stop_sending_code(),
            write_limit_end: self.write_limit_end(),
            reset_stream_at_supported: self.reset_stream_at_supported,
            terminal_state: self.terminal_state(),
            connection_closed: self.connection_closed,
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

/// [`StreamSender::enter_terminal_state`] was called before an end was
/// committed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("a send direction reaches a terminal state only after its end is committed"))]
pub struct EndNotCommittedError;

#[cfg(test)]
mod tests;
