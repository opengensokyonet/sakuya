//! Model-based tests of the stream sender, driven by generated operation
//! sequences on two streams that share one connection send flow controller.
//!
//! The model restates the contract independently of the code: the
//! outcome of every operation, the ledgers (`L`, `R`, `C`, per-stream `W`, `E`
//! and coverage), and the end state. After every operation the implementation
//! must agree with it, and the monotonic and conservation invariants of
//! RFC 9000 §3–§4 must hold.

use bytes::{Buf, Bytes};
use proptest::prelude::*;
use sakuya_stream::connection::{CloseReason, ConnectionClosedError, ImmediateClose};
use sakuya_stream::connection_send_credit::{
    AtomicConnectionCreditReservation, AtomicConnectionSendFlowController,
    ConnectionSendFlowController,
};
use sakuya_stream::send::composition::{DefaultSendComposition, SendComposition};
use sakuya_stream::send::finish::{
    CloseError, PlainResetEffectiveError, ProtocolTerminalError, ReliablePrefixNotPreparedError,
    ReliableSizeIncreaseError, ResetAtError, ResetAtWithFinalSizeError, ResetError,
    ResetStreamAtNotNegotiatedError, ResetWithFinalSizeError,
};
use sakuya_stream::send::flow_control::{
    AdmissionGuard, SendFlowContext, SendFlowControlPolicy, StreamCreditEvent, WriteAttempt,
};
use sakuya_stream::send::termination::{
    FinalSizeRequest, SendTerminationContext, SendTerminationEvent, SendTerminationPolicy,
    TerminationAction,
};
use sakuya_stream::send::write::{FlushError, WriteError, WriteOutcome, WriteWait};
use sakuya_stream::send::{
    EndFrame, EndSource, EnterTerminalStateError, ResetTarget, SendEndState, SendTerminalState,
    SenderExposeUsageError, StreamResetError, StreamSender,
};
use sakuya_stream::send_buffer::offset_map::OffsetMapStreamSendBuffer;
use sakuya_stream::send_buffer::visibility::FinalSizeBelowExposureError;
use sakuya_stream::send_buffer::{FinalSizeBeyondWrittenEndError, UsageBeyondWrittenEndError};
use sakuya_stream::stream_end::{BeyondFinalSizeError, FinalSizeChangeError, ResetCodeChangeError};
use sakuya_wire::application_error::ApplicationErrorCode;
use sakuya_wire::frame::UndecidedLength;
use sakuya_wire::frame::reset_stream::ResetStreamFrame;
use sakuya_wire::frame::reset_stream_at::{ReliableSizeError, ResetStreamAtFrame};
use sakuya_wire::frame::stream::StreamFrame;
use sakuya_wire::stream_id::StreamId;
use sakuya_wire::var_int::{VarInt, VarIntField};
use std::sync::Arc;

const STREAMS: usize = 2;
const ABANDON_CODE: u32 = 77;

fn v(value: u64) -> VarInt {
    VarInt::new(value).unwrap()
}

fn code(value: u32) -> ApplicationErrorCode {
    ApplicationErrorCode::new(VarInt::from_u32(value))
}

/// The byte a stream carries at `offset`.
fn byte_at(stream: usize, offset: u64) -> u8 {
    u8::try_from((offset * 7 + stream as u64 * 13 + 1) % 251).unwrap()
}

fn source(stream: usize, offset: u64, len: u64) -> Bytes {
    (offset..offset + len)
        .map(|at| byte_at(stream, at))
        .collect()
}

#[derive(Clone, Debug)]
enum Op {
    Write {
        stream: usize,
        len: u64,
    },
    Flush {
        stream: usize,
    },
    MaxStreamData {
        stream: usize,
        limit: u64,
    },
    MaxData {
        limit: u64,
    },
    ExposeData {
        stream: usize,
        usage_end: u64,
    },
    /// Prepares the end frame that is due and, if `expose`, exposes it;
    /// otherwise drops the guard.
    SendEndFrame {
        stream: usize,
        expose: bool,
    },
    Close {
        stream: usize,
    },
    Reset {
        stream: usize,
        /// `reset_at` (with a reliable size) instead of `reset`.
        at: bool,
        code: u32,
        reliable: u64,
        final_size: Option<u64>,
    },
    StopSending {
        stream: usize,
        code: u32,
    },
    WriterAbandoned {
        stream: usize,
    },
    BlockedSent {
        stream: usize,
    },
    Terminal {
        stream: usize,
        reset: bool,
    },
    ConnectionClosed {
        stream: usize,
    },
}

fn op() -> impl Strategy<Value = Op> {
    let stream = 0..STREAMS;
    prop_oneof![
        8 => (stream.clone(), 0u64..120).prop_map(|(stream, len)| Op::Write { stream, len }),
        1 => stream.clone().prop_map(|stream| Op::Flush { stream }),
        2 => (stream.clone(), 0u64..600)
            .prop_map(|(stream, limit)| Op::MaxStreamData { stream, limit }),
        2 => (0u64..900).prop_map(|limit| Op::MaxData { limit }),
        5 => (stream.clone(), 0u64..500)
            .prop_map(|(stream, usage_end)| Op::ExposeData { stream, usage_end }),
        3 => (stream.clone(), any::<bool>())
            .prop_map(|(stream, expose)| Op::SendEndFrame { stream, expose }),
        2 => stream.clone().prop_map(|stream| Op::Close { stream }),
        4 => (stream.clone(), any::<bool>(), 1u32..4, 0u64..300, prop::option::of(0u64..400))
            .prop_map(|(stream, at, code, reliable, final_size)| Op::Reset {
                stream,
                at,
                code,
                reliable,
                final_size,
            }),
        2 => (stream.clone(), 1u32..4).prop_map(|(stream, code)| Op::StopSending { stream, code }),
        1 => stream.clone().prop_map(|stream| Op::WriterAbandoned { stream }),
        2 => stream.clone().prop_map(|stream| Op::BlockedSent { stream }),
        1 => (stream.clone(), any::<bool>())
            .prop_map(|(stream, reset)| Op::Terminal { stream, reset }),
        1 => stream.prop_map(|stream| Op::ConnectionClosed { stream }),
    ]
}

/// How the composition under test decides, as far as the model must know.
trait PolicyModel {
    /// The grant for a `ceiling` above zero.
    fn grant(&self, ceiling: u64) -> u64;
    /// The final size a reset that names none gets.
    fn complete(&self, minimum: u64, maximum: u64) -> u64;
    /// What happens on `STOP_SENDING`.
    fn on_stop(&self, stream: &mut ModelStream, code: u32);
    /// What happens to an abandoned writer.
    fn on_abandon(&self, stream: &mut ModelStream);
    /// Whether the composition's signal logic is the default one.
    fn signals(&self) -> bool;
}

/// The default composition: full ceiling, smallest final size, reset on
/// `STOP_SENDING` and on an abandoned writer.
struct DefaultPolicy;

impl PolicyModel for DefaultPolicy {
    fn grant(&self, ceiling: u64) -> u64 {
        ceiling
    }

    fn complete(&self, minimum: u64, _maximum: u64) -> u64 {
        minimum
    }

    fn on_stop(&self, stream: &mut ModelStream, code: u32) {
        match stream.end {
            ModelEnd::ResetAt {
                code: fixed,
                final_size,
                reliable,
            } if reliable > 0 => {
                stream.commit_reset_at(fixed, 0, final_size, EndSource::Policy);
            }
            ModelEnd::Reset { .. } | ModelEnd::ResetAt { .. } => {}
            ModelEnd::Closed { final_size, .. } => {
                stream.commit_reset(code, final_size, EndSource::Policy);
            }
            ModelEnd::Open => {
                stream.commit_reset(code, stream.exposure, EndSource::Policy);
            }
        }
    }

    fn on_abandon(&self, stream: &mut ModelStream) {
        if matches!(stream.end, ModelEnd::Open) {
            stream.commit_reset(ABANDON_CODE, stream.exposure, EndSource::Policy);
        }
    }

    fn signals(&self) -> bool {
        true
    }
}

/// A composition that grants in chunks, keeps the largest final size and
/// answers `STOP_SENDING` only by narrowing the write limit.
struct PatientPolicy {
    chunk: u64,
    headroom: u64,
}

impl PolicyModel for PatientPolicy {
    fn grant(&self, ceiling: u64) -> u64 {
        ceiling.min(self.chunk)
    }

    fn complete(&self, _minimum: u64, maximum: u64) -> u64 {
        maximum
    }

    fn on_stop(&self, stream: &mut ModelStream, _code: u32) {
        if matches!(stream.end, ModelEnd::Open) {
            let target = stream.written + self.headroom;
            match stream.write_limit {
                Some((current, _)) if target >= current => {}
                _ => {
                    stream.write_limit = Some((target, stream.stops));
                }
            }
        }
    }

    fn on_abandon(&self, _stream: &mut ModelStream) {}

    fn signals(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Chunked {
    chunk: u64,
}

impl SendFlowControlPolicy for Chunked {
    fn admit_write(
        &mut self,
        attempt: &WriteAttempt,
        _context: &SendFlowContext,
    ) -> Option<AdmissionGuard> {
        AdmissionGuard::new(attempt, attempt.ceiling.min(v(self.chunk))).ok()
    }

    fn on_admission_used(&mut self, _: AdmissionGuard, _: VarInt, _: &SendFlowContext) {}

    fn on_admission_abandoned(&mut self, _: AdmissionGuard, _: &SendFlowContext) {}

    fn on_flow_event(&mut self, _: StreamCreditEvent, _: &SendFlowContext) {}

    fn wants_stream_data_blocked(&self, _: &SendFlowContext) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Narrowing {
    headroom: u64,
    stops: u64,
}

impl SendTerminationPolicy for Narrowing {
    type WriteLimitReason = u64;

    fn on_termination_event(
        &mut self,
        event: SendTerminationEvent,
        context: &SendTerminationContext,
    ) -> TerminationAction<u64> {
        if let SendTerminationEvent::StopSendingReceived { .. } = event {
            self.stops += 1;
            if !context.connection_closed
                && context.terminal_state.is_none()
                && context.end_state == SendEndState::Open
            {
                let target = v(context.written_end.get() + self.headroom);
                let write_limit_end = context
                    .write_limit_end
                    .map_or(target, |end| end.min(target));
                return TerminationAction::NarrowWriteLimit {
                    write_limit_end,
                    reason: self.stops,
                };
            }
        }
        TerminationAction::Keep
    }

    fn complete_final_size(
        &mut self,
        request: FinalSizeRequest,
        _context: &SendTerminationContext,
    ) -> VarInt {
        request.maximum
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ModelEnd {
    Open,
    Closed {
        final_size: u64,
        source: EndSource,
    },
    Reset {
        code: u32,
        final_size: u64,
    },
    ResetAt {
        code: u32,
        reliable: u64,
        final_size: u64,
    },
}

/// The reset frame exposed last.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ModelResetFrame {
    ResetStream,
    ResetStreamAt { reliable: u64 },
}

#[derive(Clone, Debug)]
struct ModelStream {
    written: u64,
    limit: u64,
    exposure: u64,
    /// The end of the coverage kept: the written end, or a reset's final size.
    coverage_end: u64,
    end: ModelEnd,
    end_source: EndSource,
    exposed_final: Option<u64>,
    /// The end frames whose exposure succeeded.
    sent_fin: bool,
    sent_reset_stream_at: bool,
    last_reset_frame: Option<ModelResetFrame>,
    terminal: Option<SendTerminalState>,
    stop_code: Option<u32>,
    stops: u64,
    write_limit: Option<(u64, u64)>,
    connection_closed: bool,
    wants_signal: bool,
    signalled: Option<u64>,
}

impl ModelStream {
    fn new(limit: u64) -> Self {
        Self {
            written: 0,
            limit,
            exposure: 0,
            coverage_end: 0,
            end: ModelEnd::Open,
            end_source: EndSource::Application,
            exposed_final: None,
            sent_fin: false,
            sent_reset_stream_at: false,
            last_reset_frame: None,
            terminal: None,
            stop_code: None,
            stops: 0,
            write_limit: None,
            connection_closed: false,
            wants_signal: false,
            signalled: None,
        }
    }

    fn final_size(&self) -> Option<u64> {
        match self.end {
            ModelEnd::Open => None,
            ModelEnd::Closed { final_size, .. }
            | ModelEnd::Reset { final_size, .. }
            | ModelEnd::ResetAt { final_size, .. } => Some(final_size),
        }
    }

    fn commit_reset(&mut self, code: u32, final_size: u64, source: EndSource) {
        self.end = ModelEnd::Reset { code, final_size };
        self.end_source = source;
        self.coverage_end = final_size;
    }

    fn commit_reset_at(&mut self, code: u32, reliable: u64, final_size: u64, source: EndSource) {
        self.end = ModelEnd::ResetAt {
            code,
            reliable,
            final_size,
        };
        self.end_source = source;
        self.coverage_end = final_size;
    }

    fn is_reset(&self) -> bool {
        matches!(self.end, ModelEnd::Reset { .. } | ModelEnd::ResetAt { .. })
    }

    /// Whether a `RESET_STREAM` was the reset frame exposed last.
    fn sent_reset_stream(&self) -> bool {
        self.last_reset_frame == Some(ModelResetFrame::ResetStream)
    }

    fn reliable_size(&self) -> u64 {
        match self.end {
            ModelEnd::Open => self.written,
            ModelEnd::Closed { final_size, .. } => final_size,
            ModelEnd::Reset { .. } => 0,
            ModelEnd::ResetAt { reliable, .. } => reliable,
        }
    }
}

struct Model<P> {
    policy: P,
    streams: [ModelStream; STREAMS],
    limit: u64,
    reset_stream_at: bool,
}

impl<P: PolicyModel> Model<P> {
    fn reserved(&self) -> u64 {
        self.streams
            .iter()
            .map(|s| s.coverage_end - s.exposure)
            .sum()
    }

    fn committed(&self) -> u64 {
        self.streams.iter().map(|s| s.exposure).sum()
    }

    fn available(&self) -> u64 {
        self.limit - self.reserved() - self.committed()
    }
}

/// A sender as the driver sees it.
trait Sender {
    fn write_len(&mut self, source: &mut Bytes) -> Result<WriteOutcome, WriteFailure>;
    fn sender_flush(&self) -> Result<(), FlushError>;
    fn on_max(&mut self, limit: VarInt);
    fn expose(&mut self, usage_end: VarInt) -> Result<VarInt, SenderExposeUsageError>;
    /// Prepares the end frame that is due; exposes it if `expose`, drops the
    /// guard otherwise. Returns the frame and the newly committed credit.
    fn end_frame(&mut self, expose: bool) -> Option<(EndFrame, Option<VarInt>)>;
    fn sender_close(&mut self) -> Result<(), CloseError>;
    fn request(
        &mut self,
        at: bool,
        code: ApplicationErrorCode,
        reliable: VarInt,
        final_size: Option<VarInt>,
    ) -> Result<(), ResetAtWithFinalSizeError>;
    fn stop(&mut self, code: ApplicationErrorCode);
    fn abandon(&mut self);
    fn blocked_limit(&self) -> Option<VarInt>;
    fn blocked_sent(&mut self, limit: VarInt);
    fn terminal(&mut self, state: SendTerminalState) -> Result<(), EnterTerminalStateError>;
    fn close_connection(&mut self);
    fn snapshot(&self) -> Snapshot;
}

/// The failure of `reset` as one of `reset_at_with_final_size`.
fn widen_reset(error: ResetError) -> ResetAtWithFinalSizeError {
    use ResetAtWithFinalSizeError as General;
    match error {
        ResetError::ConnectionClosed { source } => General::ConnectionClosed { source },
        ResetError::ErrorCodeConflict { source } => General::ErrorCodeConflict { source },
        ResetError::ProtocolTerminal { source } => General::ProtocolTerminal { source },
    }
}

/// The failure of `reset_at` as one of `reset_at_with_final_size`.
fn widen_reset_at(error: ResetAtError) -> ResetAtWithFinalSizeError {
    use ResetAtWithFinalSizeError as General;
    match error {
        ResetAtError::ConnectionClosed { source } => General::ConnectionClosed { source },
        ResetAtError::ErrorCodeConflict { source } => General::ErrorCodeConflict { source },
        ResetAtError::ReliableSizeIncrease { source } => General::ReliableSizeIncrease { source },
        ResetAtError::ProtocolTerminal { source } => General::ProtocolTerminal { source },
        ResetAtError::PlainResetEffective { source } => General::PlainResetEffective { source },
        ResetAtError::UnsupportedExtension { source } => General::UnsupportedExtension { source },
        ResetAtError::ReliablePrefixNotPrepared { source } => {
            General::ReliablePrefixNotPrepared { source }
        }
    }
}

/// The failure of `reset_with_final_size` as one of
/// `reset_at_with_final_size`.
fn widen_reset_with_final_size(error: ResetWithFinalSizeError) -> ResetAtWithFinalSizeError {
    use ResetAtWithFinalSizeError as General;
    match error {
        ResetWithFinalSizeError::ConnectionClosed { source } => {
            General::ConnectionClosed { source }
        }
        ResetWithFinalSizeError::ErrorCodeConflict { source } => {
            General::ErrorCodeConflict { source }
        }
        ResetWithFinalSizeError::FinalSizeConflictsWithReset { source } => {
            General::FinalSizeConflictsWithReset { source }
        }
        ResetWithFinalSizeError::FinalSizeConflictsWithClose { source } => {
            General::FinalSizeConflictsWithClose { source }
        }
        ResetWithFinalSizeError::ProtocolTerminal { source } => {
            General::ProtocolTerminal { source }
        }
        ResetWithFinalSizeError::FinalSizeBelowExposure { source } => {
            General::FinalSizeBelowExposure { source }
        }
        ResetWithFinalSizeError::FinalSizeBeyondWrittenEnd { source } => {
            General::FinalSizeBeyondWrittenEnd { source }
        }
    }
}

/// The kinds of write failure the contract distinguishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WriteFailure {
    ConnectionClosed,
    Reset,
    Closed,
    Limit { end: VarInt, reason: u64 },
    Exhausted,
}

#[derive(Debug)]
struct Snapshot {
    written: VarInt,
    limit: VarInt,
    exposure: VarInt,
    end: SendEndState,
    reliable: VarInt,
    write_limit: Option<VarInt>,
    write_limit_reason: Option<u64>,
    stop_code: Option<ApplicationErrorCode>,
    terminal: Option<SendTerminalState>,
    retained: Vec<(u64, Bytes)>,
    covered: VarInt,
    exposed_final: Option<VarInt>,
}

macro_rules! impl_sender {
    ($composition:ty, $reason:expr) => {
        impl Sender for StreamSender<$composition, AtomicConnectionSendFlowController> {
            fn write_len(&mut self, source: &mut Bytes) -> Result<WriteOutcome, WriteFailure> {
                #[allow(clippy::redundant_closure_call)]
                self.write(source).map_err(|error| match error {
                    WriteError::ConnectionClosed { .. } => WriteFailure::ConnectionClosed,
                    WriteError::Reset { .. } => WriteFailure::Reset,
                    WriteError::Closed => WriteFailure::Closed,
                    WriteError::WriteLimitReached {
                        write_limit_end,
                        reason,
                    } => WriteFailure::Limit {
                        end: write_limit_end,
                        reason: ($reason)(&*reason),
                    },
                    WriteError::StreamSizeExhausted => WriteFailure::Exhausted,
                })
            }

            fn sender_flush(&self) -> Result<(), FlushError> {
                self.flush()
            }

            fn on_max(&mut self, limit: VarInt) {
                self.on_max_stream_data(limit);
            }

            fn expose(&mut self, usage_end: VarInt) -> Result<VarInt, SenderExposeUsageError> {
                self.expose_usage_through(usage_end)
            }

            fn end_frame(&mut self, expose: bool) -> Option<(EndFrame, Option<VarInt>)> {
                let prepared = self.prepare_end_frame()?;
                let frame = *prepared;
                Some((frame, expose.then(|| prepared.expose())))
            }

            fn sender_close(&mut self) -> Result<(), CloseError> {
                self.close()
            }

            fn request(
                &mut self,
                at: bool,
                code: ApplicationErrorCode,
                reliable: VarInt,
                final_size: Option<VarInt>,
            ) -> Result<(), ResetAtWithFinalSizeError> {
                match (at, final_size) {
                    (false, None) => self.reset(code).map_err(widen_reset),
                    (true, None) => self.reset_at(code, reliable).map_err(widen_reset_at),
                    (false, Some(size)) => self
                        .reset_with_final_size(code, size)
                        .map_err(widen_reset_with_final_size),
                    (true, Some(size)) => self.reset_at_with_final_size(code, reliable, size),
                }
            }

            fn stop(&mut self, code: ApplicationErrorCode) {
                self.on_stop_sending(code);
            }

            fn abandon(&mut self) {
                self.on_writer_abandoned();
            }

            fn blocked_limit(&self) -> Option<VarInt> {
                self.stream_data_blocked_limit()
            }

            fn blocked_sent(&mut self, limit: VarInt) {
                self.on_stream_data_blocked_sent(limit);
            }

            fn terminal(
                &mut self,
                state: SendTerminalState,
            ) -> Result<(), EnterTerminalStateError> {
                self.enter_terminal_state(state)
            }

            fn close_connection(&mut self) {
                self.on_connection_closed(close_reason());
            }

            #[allow(clippy::redundant_closure_call)]
            fn snapshot(&self) -> Snapshot {
                let buffer = &self.composition().buffer;
                Snapshot {
                    written: self.written_end(),
                    limit: self.peer_stream_limit(),
                    exposure: self.exposure_end(),
                    end: self.end_state(),
                    reliable: self.reliable_size(),
                    write_limit: self.write_limit_end(),
                    write_limit_reason: self
                        .write_limit_reason()
                        .map(|reason| ($reason)(&**reason)),
                    stop_code: self.stop_sending_code(),
                    terminal: self.terminal_state(),
                    retained: buffer
                        .retained()
                        .map(|(offset, bytes)| (offset.get(), bytes.clone()))
                        .collect(),
                    covered: buffer.visibility().covered(),
                    exposed_final: buffer.visibility().exposed_final_size(),
                }
            }
        }
    };
}

type Patient = SendComposition<
    OffsetMapStreamSendBuffer<AtomicConnectionCreditReservation>,
    Chunked,
    Narrowing,
>;
impl_sender!(
    DefaultSendComposition,
    |reason: &core::convert::Infallible| match *reason {}
);
impl_sender!(Patient, |reason: &u64| *reason);

/// Applies `op` to the model and to the implementation and compares.
fn step<S: Sender, P: PolicyModel>(
    op: &Op,
    model: &mut Model<P>,
    senders: &mut [S; STREAMS],
    connection: &AtomicConnectionSendFlowController,
) {
    match *op {
        Op::Write { stream, len } => write(stream, len, model, senders),
        Op::Flush { stream } => {
            let s = &model.streams[stream];
            let expected = if s.connection_closed {
                Err(FlushError::ConnectionClosed {
                    source: ConnectionClosedError::new(close_reason()),
                })
            } else if s.is_reset() {
                Err(FlushError::Reset {
                    source: StreamResetError,
                })
            } else {
                Ok(())
            };
            assert_eq!(senders[stream].sender_flush(), expected);
        }
        Op::MaxStreamData { stream, limit } => {
            senders[stream].on_max(v(limit));
            let s = &mut model.streams[stream];
            if limit > s.limit {
                s.limit = limit;
                s.wants_signal = false;
            }
        }
        Op::MaxData { limit } => {
            let grew = connection.on_max_data(v(limit));
            assert_eq!(grew.is_some(), limit > model.limit);
            model.limit = model.limit.max(limit);
        }
        Op::ExposeData { stream, usage_end } => {
            expose_data(stream, usage_end, model, senders);
        }
        Op::SendEndFrame { stream, expose } => {
            send_end_frame(stream, expose, model, senders);
        }
        Op::Close { stream } => {
            let s = &mut model.streams[stream];
            let expected = if s.connection_closed {
                Err(CloseError::ConnectionClosed {
                    source: ConnectionClosedError::new(close_reason()),
                })
            } else if s.is_reset() {
                Err(CloseError::AlreadyReset {
                    source: StreamResetError,
                })
            } else {
                if s.end == ModelEnd::Open {
                    s.end = ModelEnd::Closed {
                        final_size: s.written,
                        source: EndSource::Application,
                    };
                    s.end_source = EndSource::Application;
                }
                Ok(())
            };
            assert_eq!(senders[stream].sender_close(), expected);
        }
        Op::Reset {
            stream,
            at,
            code: requested,
            reliable,
            final_size,
        } => {
            reset(stream, at, requested, reliable, final_size, model, senders);
        }
        Op::StopSending { stream, code: stop } => {
            senders[stream].stop(code(stop));
            let s = &mut model.streams[stream];
            if s.connection_closed {
                return;
            }
            s.stops += 1;
            if s.stop_code.is_none() {
                s.stop_code = Some(stop);
            }
            if s.terminal.is_none() {
                model.policy.on_stop(s, stop);
            }
        }
        Op::WriterAbandoned { stream } => {
            senders[stream].abandon();
            let s = &mut model.streams[stream];
            if !s.connection_closed && s.terminal.is_none() {
                model.policy.on_abandon(s);
            }
        }
        Op::BlockedSent { stream } => {
            if let Some(limit) = senders[stream].blocked_limit() {
                let s = &mut model.streams[stream];
                assert_eq!(limit, v(s.limit), "the frame carries the current limit");
                senders[stream].blocked_sent(limit);
                s.signalled = Some(s.limit);
                s.wants_signal = false;
            }
        }
        Op::Terminal { stream, reset } => {
            let state = if reset {
                SendTerminalState::ResetRecvd
            } else {
                SendTerminalState::DataRecvd
            };
            // A terminal state needs a committed end that can reach it, then
            // the end frame it acknowledges: a FIN, or a RESET_STREAM_AT that
            // no RESET_STREAM followed, for Data Recvd, a RESET_STREAM for
            // Reset Recvd.
            let s = &mut model.streams[stream];
            let expected = match (s.end, reset) {
                (ModelEnd::Open, _) => Err(EnterTerminalStateError::EndNotCommitted),
                (ModelEnd::Closed { .. }, true) => Err(EnterTerminalStateError::ResetNotCommitted),
                (_, false)
                    if !(s.sent_fin || (s.sent_reset_stream_at && !s.sent_reset_stream())) =>
                {
                    Err(EnterTerminalStateError::FinOrResetStreamAtNotSent)
                }
                (_, true) if !s.sent_reset_stream() => {
                    Err(EnterTerminalStateError::ResetStreamNotSent)
                }
                _ => Ok(()),
            };
            assert_eq!(senders[stream].terminal(state), expected);
            if expected.is_ok() {
                s.terminal.get_or_insert(state);
            }
        }
        Op::ConnectionClosed { stream } => {
            senders[stream].close_connection();
            model.streams[stream].connection_closed = true;
        }
    }
}

fn write<S: Sender, P: PolicyModel>(
    stream: usize,
    len: u64,
    model: &mut Model<P>,
    senders: &mut [S; STREAMS],
) {
    let available = model.available();
    let signals = model.policy.signals();
    let s = &mut model.streams[stream];
    let offset = s.written;
    let mut input = source(stream, offset, len);
    let expected = if s.connection_closed {
        Err(WriteFailure::ConnectionClosed)
    } else if s.is_reset() {
        Err(WriteFailure::Reset)
    } else if matches!(s.end, ModelEnd::Closed { .. }) {
        Err(WriteFailure::Closed)
    } else if len == 0 {
        Ok(Ok(0))
    } else if let Some((end, reason)) = s.write_limit.filter(|(end, _)| s.written >= *end) {
        Err(WriteFailure::Limit {
            end: v(end),
            reason,
        })
    } else {
        let limit_room = s.write_limit.map(|(end, _)| end - s.written);
        let stream_room = s.limit - s.written;
        let wanted = limit_room.map_or(len, |room| room.min(len));
        if signals && stream_room < wanted && s.signalled != Some(s.limit) {
            s.wants_signal = true;
        }
        let ceiling = wanted.min(stream_room);
        if ceiling == 0 {
            Ok(Err(WriteWait::StreamCredit))
        } else if available == 0 {
            Ok(Err(WriteWait::ConnectionCredit))
        } else {
            Ok(Ok(model.policy.grant(ceiling).min(available)))
        }
    };
    let outcome = senders[stream].write_len(&mut input);
    match (expected, outcome) {
        (Err(failure), Err(actual)) => {
            assert_eq!(failure, actual);
            assert_eq!(
                input.remaining() as u64,
                len,
                "a failed write consumes nothing"
            );
        }
        (Ok(Ok(used)), Ok(WriteOutcome::Written(report))) => {
            assert_eq!(report.new_bytes.get(), used);
            assert_eq!(input.remaining() as u64, len - used);
            let s = &mut model.streams[stream];
            s.written += used;
            s.coverage_end = s.written;
        }
        (Ok(Err(wait)), Ok(WriteOutcome::Wait(actual))) => {
            assert_eq!(wait, actual);
            assert_eq!(
                input.remaining() as u64,
                len,
                "a waiting write consumes nothing"
            );
        }
        (expected, actual) => panic!("expected {expected:?}, got {actual:?}"),
    }
}

fn expose_data<S: Sender, P: PolicyModel>(
    stream: usize,
    usage_end: u64,
    model: &mut Model<P>,
    senders: &mut [S; STREAMS],
) {
    let s = &mut model.streams[stream];
    let expected = match s.final_size() {
        Some(final_size) if usage_end > final_size => {
            Err(SenderExposeUsageError::BeyondFinalSize {
                source: BeyondFinalSizeError::check(v(final_size), v(usage_end)).unwrap_err(),
            })
        }
        _ if usage_end > s.written => Err(SenderExposeUsageError::BeyondWrittenEnd {
            source: UsageBeyondWrittenEndError::check(v(usage_end), v(s.written)).unwrap_err(),
        }),
        _ => Ok(usage_end.saturating_sub(s.exposure)),
    };
    let actual = senders[stream].expose(v(usage_end));
    assert_eq!(actual, expected.map(v));
    if let Ok(newly) = expected {
        s.exposure += newly;
    }
}

/// The end frame the contract says is due, if any.
fn due_frame(index: usize, s: &ModelStream) -> Option<(EndFrame, ModelEndFrame)> {
    if s.connection_closed || s.terminal.is_some() {
        return None;
    }
    let sid = stream_id(index);
    match s.end {
        ModelEnd::Open => None,
        ModelEnd::Closed { final_size, .. } => (!s.sent_fin).then(|| {
            (
                EndFrame::Fin(fin_frame(sid, final_size)),
                ModelEndFrame::Fin,
            )
        }),
        ModelEnd::Reset {
            code: c,
            final_size,
        } => (!s.sent_reset_stream()).then(|| {
            (
                EndFrame::ResetStream(ResetStreamFrame::new(
                    VarIntField::shortest(sid),
                    VarIntField::shortest(code(c)),
                    VarIntField::shortest(v(final_size)),
                )),
                ModelEndFrame::Reset(ModelResetFrame::ResetStream),
            )
        }),
        ModelEnd::ResetAt {
            code: c,
            reliable,
            final_size,
        } => (s.last_reset_frame != Some(ModelResetFrame::ResetStreamAt { reliable })).then(|| {
            (
                EndFrame::ResetStreamAt(
                    ResetStreamAtFrame::new(
                        VarIntField::shortest(sid),
                        VarIntField::shortest(code(c)),
                        VarIntField::shortest(v(final_size)),
                        VarIntField::shortest(v(reliable)),
                    )
                    .unwrap(),
                ),
                ModelEndFrame::Reset(ModelResetFrame::ResetStreamAt { reliable }),
            )
        }),
    }
}

/// An end frame as the model records it once exposed.
#[derive(Clone, Copy, Debug)]
enum ModelEndFrame {
    Fin,
    Reset(ModelResetFrame),
}

fn fin_frame(stream: StreamId, final_size: u64) -> StreamFrame<&'static [u8], UndecidedLength> {
    let offset = (final_size > 0).then(|| VarIntField::shortest(v(final_size)));
    StreamFrame::new(VarIntField::shortest(stream), offset, &[][..], true).unwrap()
}

fn send_end_frame<S: Sender, P: PolicyModel>(
    stream: usize,
    expose: bool,
    model: &mut Model<P>,
    senders: &mut [S; STREAMS],
) {
    let s = &mut model.streams[stream];
    let expected = due_frame(stream, s);
    let actual = senders[stream].end_frame(expose);
    match (expected, actual) {
        (None, None) => {}
        (Some((frame, recorded)), Some((actual, committed))) => {
            assert_eq!(actual, frame, "the end frame that is due");
            if !expose {
                assert_eq!(committed, None);
                return;
            }
            let final_size = s
                .final_size()
                .expect("an end frame follows a committed end");
            assert_eq!(committed, Some(v(final_size.saturating_sub(s.exposure))));
            s.exposure = s.exposure.max(final_size);
            s.exposed_final = Some(final_size);
            match recorded {
                ModelEndFrame::Fin => s.sent_fin = true,
                ModelEndFrame::Reset(reset) => {
                    if let ModelResetFrame::ResetStreamAt { .. } = reset {
                        s.sent_reset_stream_at = true;
                    }
                    s.last_reset_frame = Some(reset);
                }
            }
        }
        (expected, actual) => panic!("expected {expected:?}, got {actual:?}"),
    }
}

fn reset<S: Sender, P: PolicyModel>(
    stream: usize,
    at: bool,
    requested: u32,
    reliable: u64,
    final_size: Option<u64>,
    model: &mut Model<P>,
    senders: &mut [S; STREAMS],
) {
    let supported = model.reset_stream_at;
    // A plain reset has reliable size zero, whatever the generator drew.
    let reliable = if at { reliable } else { 0 };
    let s = &model.streams[stream];
    let code_value = code(requested);
    // The order in which the sender checks a reset: connection, identical target,
    // conflicts, terminal state, extension, prefix, final size range.
    let expected: Result<Option<(u64, u64)>, ResetAtWithFinalSizeError> = (|| {
        use ResetAtWithFinalSizeError as E;
        if s.connection_closed {
            return Err(E::ConnectionClosed {
                source: ConnectionClosedError::new(close_reason()),
            });
        }
        // The reset in effect: its kind, error code, reliable size and final
        // size.
        let effective = match s.end {
            ModelEnd::Reset {
                code: current,
                final_size: fixed,
            } => Some((false, current, 0, fixed)),
            ModelEnd::ResetAt {
                code: current,
                reliable: effective,
                final_size: fixed,
            } => Some((true, current, effective, fixed)),
            ModelEnd::Closed { .. } | ModelEnd::Open => None,
        };
        match s.end {
            ModelEnd::Reset { .. } | ModelEnd::ResetAt { .. } => {
                let (effective_at, current, effective, fixed) = effective.unwrap();
                if effective_at == at
                    && current == requested
                    && effective == reliable
                    && final_size.is_none_or(|size| size == fixed)
                {
                    return Ok(None);
                }
                if current != requested {
                    return Err(E::ErrorCodeConflict {
                        source: ResetCodeChangeError::check(code(current), code_value).unwrap_err(),
                    });
                }
                if let Some(size) = final_size.filter(|size| *size != fixed) {
                    return Err(E::FinalSizeConflictsWithReset {
                        source: FinalSizeChangeError::check(v(fixed), v(size)).unwrap_err(),
                    });
                }
                if reliable > effective {
                    return Err(E::ReliableSizeIncrease {
                        source: ReliableSizeIncreaseError::check(v(effective), v(reliable))
                            .unwrap_err(),
                    });
                }
            }
            ModelEnd::Closed {
                final_size: fixed, ..
            } => {
                if let Some(size) = final_size.filter(|size| *size != fixed) {
                    return Err(E::FinalSizeConflictsWithClose {
                        source: FinalSizeChangeError::check(v(fixed), v(size)).unwrap_err(),
                    });
                }
            }
            ModelEnd::Open => {}
        }
        if let Some(state) = s.terminal {
            return Err(E::ProtocolTerminal {
                source: ProtocolTerminalError::check(Some(state)).unwrap_err(),
            });
        }
        if at && effective.is_some_and(|(effective_at, ..)| !effective_at) {
            return Err(E::PlainResetEffective {
                source: PlainResetEffectiveError,
            });
        }
        if at && !supported {
            return Err(E::UnsupportedExtension {
                source: ResetStreamAtNotNegotiatedError::check(v(reliable), false).unwrap_err(),
            });
        }
        if reliable > s.written {
            return Err(E::ReliablePrefixNotPrepared {
                source: ReliablePrefixNotPreparedError::check(v(reliable), v(s.written))
                    .unwrap_err(),
            });
        }
        let chosen = match s.final_size() {
            Some(fixed) => fixed,
            None => {
                let minimum = s.exposure.max(reliable);
                match final_size {
                    Some(size) if size < reliable => {
                        return Err(E::FinalSizeBelowReliableSize {
                            source: ReliableSizeError::check(v(size), v(reliable)).unwrap_err(),
                        });
                    }
                    Some(size) if size < s.exposure => {
                        return Err(E::FinalSizeBelowExposure {
                            source: FinalSizeBelowExposureError::check(v(size), v(s.exposure))
                                .unwrap_err(),
                        });
                    }
                    Some(size) if size > s.written => {
                        return Err(E::FinalSizeBeyondWrittenEnd {
                            source: FinalSizeBeyondWrittenEndError::check(v(size), v(s.written))
                                .unwrap_err(),
                        });
                    }
                    Some(size) => size,
                    None => model.policy.complete(minimum, s.written),
                }
            }
        };
        Ok(Some((reliable, chosen)))
    })();
    let actual = senders[stream].request(at, code_value, v(reliable), final_size.map(v));
    assert_eq!(actual, expected.clone().map(|_| ()));
    if let Ok(Some((reliable, chosen))) = expected {
        let s = &mut model.streams[stream];
        if at {
            s.commit_reset_at(requested, reliable, chosen, EndSource::Application);
        } else {
            s.commit_reset(requested, chosen, EndSource::Application);
        }
    }
}

fn check<S: Sender, P: PolicyModel>(
    model: &Model<P>,
    senders: &[S; STREAMS],
    connection: &AtomicConnectionSendFlowController,
) {
    for (index, (s, sender)) in model.streams.iter().zip(senders).enumerate() {
        let snapshot = sender.snapshot();
        assert_eq!(snapshot.written.get(), s.written, "written end");
        assert_eq!(snapshot.limit.get(), s.limit, "peer stream limit");
        assert_eq!(snapshot.exposure.get(), s.exposure, "exposure end");
        assert_eq!(
            snapshot.covered.get(),
            s.coverage_end - s.exposure,
            "coverage"
        );
        assert_eq!(snapshot.reliable.get(), s.reliable_size(), "reliable size");
        assert_eq!(
            snapshot.write_limit.map(VarInt::get),
            s.write_limit.map(|l| l.0)
        );
        assert_eq!(snapshot.write_limit_reason, s.write_limit.map(|l| l.1));
        assert_eq!(snapshot.stop_code, s.stop_code.map(code));
        assert_eq!(snapshot.terminal, s.terminal);
        assert_eq!(snapshot.exposed_final.map(VarInt::get), s.exposed_final);
        match (s.end, snapshot.end) {
            (ModelEnd::Open, SendEndState::Open) => {}
            (
                ModelEnd::Closed {
                    final_size,
                    source: expected,
                },
                SendEndState::Closed {
                    final_size: actual,
                    source,
                },
            ) => {
                assert_eq!(actual.get(), final_size);
                assert_eq!(source, expected);
            }
            (
                ModelEnd::Reset {
                    code: c,
                    final_size,
                },
                SendEndState::Reset {
                    error_code,
                    final_size: actual,
                    source,
                },
            ) => {
                assert_eq!((error_code, actual), (code(c), v(final_size)));
                assert_eq!(source, s.end_source);
            }
            (
                ModelEnd::ResetAt {
                    code: c,
                    reliable,
                    final_size,
                },
                SendEndState::ResetAt { target, source },
            ) => {
                assert_eq!(
                    target,
                    ResetTarget {
                        error_code: code(c),
                        reliable_size: v(reliable),
                        final_size: v(final_size),
                    }
                );
                assert_eq!(source, s.end_source);
            }
            (expected, actual) => panic!("end state: expected {expected:?}, got {actual:?}"),
        }
        // RFC 9000 §4.1, §4.5: the sender never exceeds the limits, and the
        // final size bounds everything exposed.
        assert!(s.written <= s.limit);
        assert!(s.exposure <= s.written);
        if let Some(final_size) = s.final_size() {
            assert!(s.exposure <= final_size);
            assert!(final_size <= s.written);
            assert!(s.reliable_size() <= final_size);
        }
        // Reset drops the tail: only `[0, reliable)` stays selectable, and
        // retained bytes keep their offsets.
        let selectable = match s.end {
            ModelEnd::Reset { .. } => 0,
            ModelEnd::ResetAt { reliable, .. } => reliable,
            ModelEnd::Open | ModelEnd::Closed { .. } => s.written,
        };
        let mut cursor = 0;
        for (offset, bytes) in &snapshot.retained {
            assert_eq!(*offset, cursor, "retained data is contiguous");
            assert_eq!(*bytes, source(index, *offset, bytes.len() as u64));
            cursor += bytes.len() as u64;
        }
        assert_eq!(cursor, selectable, "retained end");
        // RFC 9000 §3.3: no STREAM_DATA_BLOCKED after a reset or from a
        // terminal state.
        let blocked = sender.blocked_limit();
        if s.is_reset() || s.terminal.is_some() || s.connection_closed {
            assert_eq!(blocked, None);
        } else if model.policy.signals() {
            assert_eq!(blocked, s.wants_signal.then(|| v(s.limit)));
        }
    }
    assert_eq!(connection.limit().get(), model.limit, "L");
    assert_eq!(connection.reserved().get(), model.reserved(), "R");
    assert_eq!(connection.committed().get(), model.committed(), "C");
    assert_eq!(connection.available().get(), model.available(), "available");
}

fn run<S: Sender, P: PolicyModel>(
    ops: &[Op],
    policy: P,
    make: impl Fn(usize, u64, Arc<AtomicConnectionSendFlowController>) -> S,
    limits: [u64; STREAMS],
    connection_limit: u64,
    reset_stream_at: bool,
) {
    let connection = Arc::new(AtomicConnectionSendFlowController::new(v(connection_limit)));
    let mut senders = [
        make(0, limits[0], Arc::clone(&connection)),
        make(1, limits[1], Arc::clone(&connection)),
    ];
    let mut model = Model {
        policy,
        streams: limits.map(ModelStream::new),
        limit: connection_limit,
        reset_stream_at,
    };
    for op in ops {
        let (old_limit, old_committed, old_streams) =
            (model.limit, model.committed(), model.streams.clone());
        step(op, &mut model, &mut senders, &connection);
        check(&model, &senders, &connection);
        // Monotonic facts of RFC 9000 §4.1 and §4.5, stated apart from the
        // model's own transitions.
        assert!(model.limit >= old_limit);
        assert!(model.committed() >= old_committed);
        for (old, new) in old_streams.iter().zip(&model.streams) {
            assert!(new.limit >= old.limit && new.written >= old.written);
            assert!(new.exposure >= old.exposure);
            if let Some(final_size) = old.final_size() {
                assert_eq!(new.final_size(), Some(final_size), "final size changed");
            }
            let reset_code = |end: ModelEnd| match end {
                ModelEnd::Reset { code, .. } | ModelEnd::ResetAt { code, .. } => Some(code),
                ModelEnd::Open | ModelEnd::Closed { .. } => None,
            };
            if let (Some(a), Some(b)) = (reset_code(old.end), reset_code(new.end)) {
                assert_eq!(a, b, "error code changed");
                assert!(
                    new.reliable_size() <= old.reliable_size(),
                    "reliable size rose"
                );
            }
            // A `reset_at` never follows a `reset`.
            if matches!(old.end, ModelEnd::Reset { .. }) {
                assert!(matches!(new.end, ModelEnd::Reset { .. }));
            }
        }
    }
    // Dropping every sender cancels what was never exposed and nothing else.
    let committed = model.committed();
    drop(senders);
    assert_eq!(
        connection.reserved(),
        VarInt::ZERO,
        "uncommitted credit leaked"
    );
    assert_eq!(connection.committed().get(), committed);
}

fn stream_id(index: usize) -> StreamId {
    StreamId::from_var_int(VarInt::from_u32(u32::try_from(index).unwrap() * 4))
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 2000,
        max_shrink_iters: 4000,
        ..ProptestConfig::default()
    })]

    #[test]
    fn default_composition_follows_the_model(
        ops in prop::collection::vec(op(), 0..60),
        limits in [0u64..300, 0u64..300],
        connection_limit in 0u64..500,
        reset_stream_at in any::<bool>(),
    ) {
        run(
            &ops,
            DefaultPolicy,
            |index, limit, connection| StreamSender::new(
                stream_id(index),
                v(limit),
                reset_stream_at,
                DefaultSendComposition::with_abandon_code(code(ABANDON_CODE)),
                connection,
            ),
            limits,
            connection_limit,
            reset_stream_at,
        );
    }

    #[test]
    fn chunked_composition_follows_the_model(
        ops in prop::collection::vec(op(), 0..60),
        limits in [0u64..300, 0u64..300],
        connection_limit in 0u64..500,
        chunk in 1u64..50,
        headroom in 0u64..80,
    ) {
        run(
            &ops,
            PatientPolicy { chunk, headroom },
            |index, limit, connection| StreamSender::new(
                stream_id(index),
                v(limit),
                true,
                SendComposition::new(
                    OffsetMapStreamSendBuffer::new(),
                    Chunked { chunk },
                    Narrowing { headroom, stops: 0 },
                ),
                connection,
            ),
            limits,
            connection_limit,
            true,
        );
    }
}

/// The reason the tests close connections for.
fn close_reason() -> CloseReason {
    CloseReason::Local(ImmediateClose::Application {
        code: ApplicationErrorCode::new(VarInt::from_u32(9)),
        reason_phrase: Bytes::from_static(b"done"),
    })
}
