use super::composition::{DefaultSendComposition, SendComposition};
use super::finish::{
    CloseError, ProtocolTerminalError, ReliablePrefixNotPreparedError, ReliableSizeIncreaseError,
    ResetAtError, ResetAtWithFinalSizeError, ResetError, ResetStreamAtNotNegotiatedError,
    ResetWithFinalSizeError,
};
use super::flow_control::{
    AdmissionGrantError, AdmissionGuard, DefaultSendFlowControlPolicy, SendFlowContext,
    SendFlowControlPolicy, StreamCreditEvent, WriteAttempt,
};
use super::termination::{
    FinalSizeRequest, SendTerminationContext, SendTerminationEvent, SendTerminationPolicy,
    TerminationAction,
};
use super::write::{FlushError, WriteError, WriteOutcome, WriteReport, WriteWait};
use super::*;
use crate::connection::ConnectionClosedError;
use crate::send_buffer::covered_bytes::CoveredBytes;
use crate::send_buffer::offset_map::OffsetMapSendBuffer;
use crate::send_buffer::visibility::FinalSizeBelowExposureError;
use crate::send_buffer::{
    AppendError, ApplyResetError, ExposedEnd, FinalSizeBeyondWrittenEndError, ResetRetention,
    Selection, SelectionConstraints, TransmissionReceipt,
};
use crate::stream_end::{FinalSizeChangeError, ResetCodeChangeError};
use bytes::{Buf, Bytes};
use sakuya_wire::frame::reset_stream_at::ReliableSizeError;

fn v(value: u32) -> VarInt {
    VarInt::from_u32(value)
}

fn code(value: u32) -> ApplicationErrorCode {
    ApplicationErrorCode::new(v(value))
}

fn stream() -> StreamId {
    StreamId::from(v(4))
}

const CODE: ApplicationErrorCode = ApplicationErrorCode::new(VarInt::from_u32(7));
const OTHER_CODE: ApplicationErrorCode = ApplicationErrorCode::new(VarInt::from_u32(9));

// ---------------------------------------------------------------------------
// Test policies

/// A flow-control policy that records what it is told, caps grants at
/// `grant_cap` and otherwise behaves like the default policy.
#[derive(Debug, Default)]
struct RecordingFlow {
    grant_cap: Option<VarInt>,
    admit_nothing: bool,
    over_grant: bool,
    foreign_offset: bool,
    attempts: Vec<WriteAttempt>,
    settlements: Vec<(VarInt, Option<VarInt>)>,
    events: Vec<StreamCreditEvent>,
    inner: DefaultSendFlowControlPolicy,
}

impl SendFlowControlPolicy for RecordingFlow {
    fn admit_write(
        &mut self,
        attempt: &WriteAttempt,
        context: &SendFlowContext,
    ) -> Option<AdmissionGuard> {
        self.attempts.push(*attempt);
        let guard = self.inner.admit_write(attempt, context);
        if self.over_grant {
            // A guard built from a widened copy of the attempt.
            let granted = attempt.ceiling.saturating_add(v(1));
            let widened = WriteAttempt {
                ceiling: granted,
                ..*attempt
            };
            return Some(AdmissionGuard::new(&widened, granted).unwrap());
        }
        if self.foreign_offset {
            let shifted = WriteAttempt {
                offset: attempt.offset.saturating_add(v(1)),
                ..*attempt
            };
            return Some(AdmissionGuard::new(&shifted, attempt.ceiling).unwrap());
        }
        if self.admit_nothing {
            return None;
        }
        match (guard, self.grant_cap) {
            (Some(guard), Some(cap)) => {
                Some(AdmissionGuard::new(attempt, guard.granted().min(cap)).unwrap())
            }
            (guard, _) => guard,
        }
    }

    fn on_admission_used(&mut self, guard: AdmissionGuard, used: VarInt, _: &SendFlowContext) {
        self.settlements.push((guard.granted(), Some(used)));
    }

    fn on_admission_abandoned(&mut self, guard: AdmissionGuard, _: &SendFlowContext) {
        self.settlements.push((guard.granted(), None));
    }

    fn on_flow_event(&mut self, event: StreamCreditEvent, context: &SendFlowContext) {
        self.events.push(event);
        self.inner.on_flow_event(event, context);
    }

    fn wants_stream_data_blocked(&self, context: &SendFlowContext) -> bool {
        self.inner.wants_stream_data_blocked(context)
    }
}

/// A termination policy that answers events through a script and records
/// them; it completes final sizes with the minimum unless `final_size` says
/// otherwise.
struct ScriptedTermination<S> {
    script: S,
    final_size: Option<VarInt>,
    events: Vec<SendTerminationEvent>,
    completions: Vec<FinalSizeRequest>,
}

impl<S> ScriptedTermination<S> {
    fn new(script: S) -> Self {
        Self {
            script,
            final_size: None,
            events: Vec::new(),
            completions: Vec::new(),
        }
    }
}

impl<S> SendTerminationPolicy for ScriptedTermination<S>
where
    S: FnMut(&SendTerminationEvent, &SendTerminationContext) -> TerminationAction<&'static str>,
{
    type WriteLimitReason = &'static str;

    fn on_termination_event(
        &mut self,
        event: SendTerminationEvent,
        context: &SendTerminationContext,
    ) -> TerminationAction<&'static str> {
        let action = (self.script)(&event, context);
        self.events.push(event);
        action
    }

    fn complete_final_size(
        &mut self,
        request: FinalSizeRequest,
        _: &SendTerminationContext,
    ) -> VarInt {
        self.completions.push(request);
        self.final_size.unwrap_or(request.minimum)
    }
}

type TestSender<S> =
    StreamSender<SendComposition<OffsetMapSendBuffer, RecordingFlow, ScriptedTermination<S>>>;

fn keep(_: &SendTerminationEvent, _: &SendTerminationContext) -> TerminationAction<&'static str> {
    TerminationAction::Keep
}

fn sender_with<S>(peer_stream_limit: u32, reset_stream_at: bool, script: S) -> TestSender<S>
where
    S: FnMut(&SendTerminationEvent, &SendTerminationContext) -> TerminationAction<&'static str>,
{
    StreamSender::new(
        stream(),
        v(peer_stream_limit),
        reset_stream_at,
        SendComposition::new(
            OffsetMapSendBuffer::new(),
            RecordingFlow::default(),
            ScriptedTermination::new(script),
        ),
    )
}

fn test_sender(
    peer_stream_limit: u32,
    reset_stream_at: bool,
) -> TestSender<
    impl FnMut(&SendTerminationEvent, &SendTerminationContext) -> TerminationAction<&'static str>,
> {
    sender_with(peer_stream_limit, reset_stream_at, keep)
}

fn scripted_sender<S>(peer_stream_limit: u32, script: S) -> TestSender<S>
where
    S: FnMut(&SendTerminationEvent, &SendTerminationContext) -> TerminationAction<&'static str>,
{
    sender_with(peer_stream_limit, true, script)
}

fn default_sender(
    peer_stream_limit: u32,
    reset_stream_at: bool,
) -> StreamSender<DefaultSendComposition> {
    StreamSender::new(
        stream(),
        v(peer_stream_limit),
        reset_stream_at,
        DefaultSendComposition::with_abandon_code(code(0x10c)),
    )
}

fn source(length: usize) -> Bytes {
    Bytes::from(vec![0xa5; length])
}

fn written(new_bytes: u32) -> WriteOutcome {
    WriteOutcome::Written(WriteReport {
        new_bytes: v(new_bytes),
    })
}

/// Writes `length` bytes that must all be accepted.
fn write_all<C>(
    sender: &mut StreamSender<C>,
    connection: &mut ConnectionSendFlowController,
    length: u32,
) where
    C: SendBuffer + SendFlowControlPolicy + SendTerminationPolicy,
    C::WriteLimitReason: core::fmt::Debug,
{
    let mut input = source(length as usize);
    assert_eq!(
        sender.write(&mut input, connection).unwrap(),
        written(length)
    );
    assert!(!input.has_remaining());
}

fn expose<C>(
    sender: &mut StreamSender<C>,
    connection: &mut ConnectionSendFlowController,
    usage_end: u32,
) where
    C: SendBuffer + SendFlowControlPolicy + SendTerminationPolicy,
{
    sender
        .expose_usage_through(v(usage_end), ExposedEnd::Data, connection)
        .unwrap();
}

fn reset_target(
    error_code: ApplicationErrorCode,
    reliable_size: u32,
    final_size: u32,
) -> ResetTarget {
    ResetTarget {
        error_code,
        reliable_size: v(reliable_size),
        final_size: v(final_size),
    }
}

fn end_commits<S>(sender: &TestSender<S>) -> usize
where
    S: FnMut(&SendTerminationEvent, &SendTerminationContext) -> TerminationAction<&'static str>,
{
    sender
        .composition
        .termination
        .events
        .iter()
        .filter(|event| matches!(event, SendTerminationEvent::EndCommitted { .. }))
        .count()
}

/// A narrowing policy: on `STOP_SENDING`, the write limit end becomes `end`.
fn narrow_on_stop_sending(
    end: u32,
) -> impl FnMut(&SendTerminationEvent, &SendTerminationContext) -> TerminationAction<&'static str> {
    move |event, _| match event {
        SendTerminationEvent::StopSendingReceived { .. } => TerminationAction::NarrowWriteLimit {
            write_limit_end: v(end),
            reason: "stopped",
        },
        _ => TerminationAction::Keep,
    }
}

// ---------------------------------------------------------------------------
// Write flow

/// Input and stream limit allow 1000 bytes, the policy grants
/// 600 and the connection has 400 left; 400 are appended with their
/// reservation, the guard settles 400, and the input keeps the rest.
#[test]
fn write_takes_the_reserved_part_of_the_grant() {
    let mut connection = ConnectionSendFlowController::new(v(400));
    let mut sender = test_sender(1000, false);
    sender.composition.flow_control.grant_cap = Some(v(600));

    let mut input = source(1000);
    assert_eq!(
        sender.write(&mut input, &mut connection).unwrap(),
        written(400)
    );
    assert_eq!(input.remaining(), 600);
    assert_eq!(sender.written_end(), v(400));
    assert_eq!(
        (connection.reserved(), connection.committed()),
        (v(400), v(0))
    );

    let flow = &sender.composition.flow_control;
    assert_eq!(flow.settlements, [(v(600), Some(v(400)))]);
    let attempt = flow.attempts[0];
    assert_eq!(
        (
            attempt.offset,
            attempt.requested,
            attempt.ceiling,
            attempt.connection_available
        ),
        (v(0), v(1000), v(1000), v(400))
    );
    assert_eq!(
        sender.composition.termination.events,
        [SendTerminationEvent::DataAppended {
            appended_range: v(0)..v(400),
        }]
    );
}

#[test]
fn write_without_connection_credit_waits_and_consumes_nothing() {
    let mut connection = ConnectionSendFlowController::new(v(0));
    let mut sender = test_sender(1000, false);
    let mut input = source(100);
    assert_eq!(
        sender.write(&mut input, &mut connection).unwrap(),
        WriteOutcome::Wait(WriteWait::ConnectionCredit)
    );
    assert_eq!(input.remaining(), 100);
    assert_eq!(sender.written_end(), v(0));
    assert_eq!(
        sender.composition.flow_control.settlements,
        [(v(100), None)]
    );
    assert!(sender.composition.termination.events.is_empty());

    connection.on_max_data(v(60));
    assert_eq!(
        sender.write(&mut input, &mut connection).unwrap(),
        written(60)
    );
    assert_eq!(input.remaining(), 40);
}

#[test]
fn write_at_the_stream_limit_waits_after_consulting_the_policy() {
    let mut connection = ConnectionSendFlowController::new(v(1000));
    let mut sender = test_sender(100, false);
    write_all(&mut sender, &mut connection, 100);
    let mut input = source(10);
    assert_eq!(
        sender.write(&mut input, &mut connection).unwrap(),
        WriteOutcome::Wait(WriteWait::StreamCredit)
    );
    assert_eq!(input.remaining(), 10);
    let attempt = *sender.composition.flow_control.attempts.last().unwrap();
    assert_eq!((attempt.stream_available, attempt.ceiling), (v(0), v(0)));
    assert!(attempt.is_stream_limited());
}

#[test]
fn write_waits_when_the_policy_admits_nothing() {
    let mut connection = ConnectionSendFlowController::new(v(1000));
    let mut sender = test_sender(1000, false);
    sender.composition.flow_control.admit_nothing = true;
    let mut input = source(10);
    assert_eq!(
        sender.write(&mut input, &mut connection).unwrap(),
        WriteOutcome::Wait(WriteWait::Admission)
    );
    assert_eq!(input.remaining(), 10);
    assert_eq!(connection.reserved(), v(0));
}

#[test]
fn write_accepts_a_prefix_of_a_chained_source() {
    let mut connection = ConnectionSendFlowController::new(v(1000));
    let mut sender = test_sender(5, false);
    let mut input = Bytes::from_static(b"abc").chain(Bytes::from_static(b"defg"));
    assert_eq!(
        sender.write(&mut input, &mut connection).unwrap(),
        written(5)
    );
    assert_eq!(input.chunk(), b"fg");
}

#[test]
#[should_panic(expected = "outside 1..=")]
fn grant_beyond_the_ceiling_is_a_policy_violation() {
    let mut connection = ConnectionSendFlowController::new(v(1000));
    let mut sender = test_sender(100, false);
    sender.composition.flow_control.over_grant = true;
    let mut input = source(10);
    let _ = sender.write(&mut input, &mut connection);
}

#[test]
#[should_panic(expected = "for offset 1, not 0")]
fn guard_for_another_offset_is_a_policy_violation() {
    let mut connection = ConnectionSendFlowController::new(v(1000));
    let mut sender = test_sender(100, false);
    sender.composition.flow_control.foreign_offset = true;
    let mut input = source(10);
    let _ = sender.write(&mut input, &mut connection);
}

#[test]
fn admission_guards_are_checked_at_construction() {
    let attempt = WriteAttempt {
        offset: v(10),
        requested: v(50),
        stream_available: v(40),
        write_limit_remaining: None,
        connection_available: v(1000),
        ceiling: v(40),
    };
    let guard = AdmissionGuard::new(&attempt, v(40)).unwrap();
    assert_eq!((guard.offset(), guard.granted()), (v(10), v(40)));
    assert_eq!(
        AdmissionGuard::new(&attempt, v(41)),
        Err(AdmissionGrantError {
            granted: v(41),
            ceiling: v(40),
        })
    );
    assert!(AdmissionGuard::new(&attempt, VarInt::ZERO).is_err());
}

/// A send buffer that claims its written end has reached `VarInt::MAX`.
struct ExhaustedBuffer;

impl SendBuffer for ExhaustedBuffer {
    fn written_end(&self) -> VarInt {
        VarInt::MAX
    }

    fn exposure_end(&self) -> VarInt {
        VarInt::ZERO
    }

    fn append(&mut self, data: CoveredBytes) -> Result<(), AppendError> {
        Err(AppendError::WrittenEndOverflow {
            written_end: VarInt::MAX,
            data,
        })
    }

    fn apply_reset(&mut self, _: ResetRetention) -> Result<(), ApplyResetError> {
        Ok(())
    }

    fn expose_usage_through(
        &mut self,
        _: VarInt,
        _: ExposedEnd,
        _: &mut ConnectionSendFlowController,
    ) -> Result<VarInt, ExposeUsageError> {
        Ok(VarInt::ZERO)
    }

    fn select(&mut self, constraints: SelectionConstraints) -> Selection {
        match constraints {}
    }

    fn on_acknowledged(&mut self, receipt: TransmissionReceipt) {
        match receipt {}
    }

    fn on_lost(&mut self, receipt: TransmissionReceipt) {
        match receipt {}
    }
}

/// At the largest stream offset a write fails before it consumes input;
/// growth of the peer's limit cannot help.
#[test]
fn write_at_the_largest_offset_is_a_permanent_error() {
    let mut connection = ConnectionSendFlowController::new(v(1000));
    let mut sender = StreamSender::new(
        stream(),
        VarInt::MAX,
        false,
        SendComposition::new(
            ExhaustedBuffer,
            RecordingFlow::default(),
            ScriptedTermination::new(keep),
        ),
    );
    let mut input = source(10);
    assert!(matches!(
        sender.write(&mut input, &mut connection),
        Err(WriteError::StreamSizeExhausted)
    ));
    assert_eq!(input.remaining(), 10);
    assert!(sender.composition.flow_control.attempts.is_empty());
    assert_eq!(connection.reserved(), VarInt::ZERO);
    // Empty input still succeeds with zero bytes.
    assert_eq!(
        sender.write(&mut Bytes::new(), &mut connection).unwrap(),
        written(0)
    );
}

#[test]
fn terminal_state_needs_a_committed_end() {
    let mut sender = test_sender(1000, false);
    assert_eq!(
        sender.enter_terminal_state(SendTerminalState::DataRecvd),
        Err(EnterTerminalStateError::EndNotCommitted)
    );
    assert_eq!(sender.terminal_state(), None);
    sender.close().unwrap();
    sender
        .enter_terminal_state(SendTerminalState::DataRecvd)
        .unwrap();
    // Only the first terminal state is kept.
    sender
        .enter_terminal_state(SendTerminalState::DataRecvd)
        .unwrap();
    assert_eq!(sender.terminal_state(), Some(SendTerminalState::DataRecvd));
}

#[test]
fn reset_recvd_needs_a_committed_reset() {
    let mut connection = ConnectionSendFlowController::new(v(1000));

    // Closed and never reset: neither before nor after Data Recvd.
    let mut sender = test_sender(1000, false);
    write_all(&mut sender, &mut connection, 10);
    sender.close().unwrap();
    let events = sender.composition.termination.events.len();
    assert_eq!(
        sender.enter_terminal_state(SendTerminalState::ResetRecvd),
        Err(EnterTerminalStateError::ResetNotCommitted)
    );
    assert_eq!(sender.terminal_state(), None);
    assert_eq!(sender.composition.termination.events.len(), events);
    sender
        .enter_terminal_state(SendTerminalState::DataRecvd)
        .unwrap();
    assert_eq!(
        sender.enter_terminal_state(SendTerminalState::ResetRecvd),
        Err(EnterTerminalStateError::ResetNotCommitted)
    );
    assert_eq!(sender.terminal_state(), Some(SendTerminalState::DataRecvd));

    // A reset that replaced a close can be acknowledged.
    let mut sender = test_sender(1000, false);
    write_all(&mut sender, &mut connection, 10);
    sender.close().unwrap();
    sender.reset(CODE).unwrap();
    sender
        .enter_terminal_state(SendTerminalState::ResetRecvd)
        .unwrap();
    assert_eq!(sender.terminal_state(), Some(SendTerminalState::ResetRecvd));
}

#[test]
fn exposure_with_another_controller_fails_without_effect() {
    let mut connection = ConnectionSendFlowController::new(v(1000));
    let mut other = ConnectionSendFlowController::new(v(1000));
    let mut sender = test_sender(1000, false);
    write_all(&mut sender, &mut connection, 100);
    assert!(matches!(
        sender.expose_usage_through(v(50), ExposedEnd::Data, &mut other),
        Err(SenderExposeUsageError::ForeignReservation { .. })
    ));
    assert_eq!(sender.exposure_end(), VarInt::ZERO);
    assert!(
        !sender
            .composition
            .flow_control
            .events
            .iter()
            .any(|event| matches!(event, StreamCreditEvent::FirstExposed { .. }))
    );
}

// ---------------------------------------------------------------------------
// Empty input and flush

/// A state, a sender in it, and the expected empty-write and flush results.
type Row<S> = (
    &'static str,
    S,
    Result<(), &'static str>,
    Result<(), FlushError>,
);

/// Empty input and flush, one row per state.
#[test]
fn empty_input_and_flush_table() {
    let mut connection = ConnectionSendFlowController::new(v(10_000));
    // One script type for every row, so that the rows share a type.
    let sender =
        |peer_stream_limit| scripted_sender(peer_stream_limit, narrow_on_stop_sending(100));

    let open = sender(1000);

    let mut no_credit = sender(0);
    no_credit.composition.flow_control.admit_nothing = true;

    let mut limited = sender(1000);
    write_all(&mut limited, &mut connection, 100);
    limited.on_stop_sending(CODE);
    assert_eq!(limited.write_limit_end(), Some(v(100)));

    let mut closed = sender(1000);
    write_all(&mut closed, &mut connection, 10);
    closed.close().unwrap();

    let mut reset = sender(1000);
    write_all(&mut reset, &mut connection, 10);
    reset.reset(CODE).unwrap();

    let mut reset_delivered = sender(1000);
    reset_delivered.reset(CODE).unwrap();
    reset_delivered
        .enter_terminal_state(SendTerminalState::ResetRecvd)
        .unwrap();

    let mut connection_closed = sender(1000);
    connection_closed.on_connection_closed();

    let rows: Vec<Row<_>> = vec![
        ("open", open, Ok(()), Ok(())),
        ("credit or admission short", no_credit, Ok(()), Ok(())),
        ("write limit reached", limited, Ok(()), Ok(())),
        ("closed", closed, Err("closed"), Ok(())),
        (
            "reset",
            reset,
            Err("reset"),
            Err(FlushError::Reset {
                source: StreamResetError,
            }),
        ),
        (
            "reset, nothing left to deliver",
            reset_delivered,
            Err("reset"),
            Err(FlushError::Reset {
                source: StreamResetError,
            }),
        ),
        (
            "connection closed",
            connection_closed,
            Err("connection closed"),
            Err(FlushError::ConnectionClosed {
                source: ConnectionClosedError::new(),
            }),
        ),
    ];
    for (state, mut sender, empty_write, flush) in rows {
        let written_end = sender.written_end();
        let reserved = connection.reserved();
        let attempts = sender.composition.flow_control.attempts.len();
        let events = sender.composition.termination.events.len();

        let result = sender.write(&mut Bytes::new(), &mut connection);
        let result = match result {
            Ok(outcome) => {
                assert_eq!(outcome, written(0), "{state}");
                Ok(())
            }
            Err(WriteError::Closed) => Err("closed"),
            Err(WriteError::Reset {
                source: StreamResetError,
            }) => Err("reset"),
            Err(WriteError::ConnectionClosed { .. }) => Err("connection closed"),
            Err(error) => panic!("{state}: unexpected {error:?}"),
        };
        assert_eq!(result, empty_write, "{state}: empty write");
        assert_eq!(sender.flush(), flush, "{state}: flush");

        // Empty input asks for nothing and reports nothing.
        assert_eq!(sender.written_end(), written_end, "{state}");
        assert_eq!(connection.reserved(), reserved, "{state}");
        assert_eq!(
            sender.composition.flow_control.attempts.len(),
            attempts,
            "{state}"
        );
        assert_eq!(
            sender.composition.termination.events.len(),
            events,
            "{state}"
        );
    }
}

/// A received `STOP_SENDING` that the policy has not answered does not make
/// writes or flushes fail.
#[test]
fn unanswered_stop_sending_leaves_writes_open() {
    let mut connection = ConnectionSendFlowController::new(v(1000));
    let mut sender = test_sender(1000, true);
    sender.on_stop_sending(CODE);
    assert_eq!(sender.stop_sending_code(), Some(CODE));
    write_all(&mut sender, &mut connection, 10);
    assert_eq!(sender.flush(), Ok(()));
}

// ---------------------------------------------------------------------------
// Error check order

#[test]
fn write_errors_follow_the_check_order() {
    let mut connection = ConnectionSendFlowController::new(v(1000));

    // Connection closed before reset.
    let mut sender = test_sender(1000, true);
    sender.reset(CODE).unwrap();
    sender.on_connection_closed();
    assert!(matches!(
        sender.write(&mut source(1), &mut connection),
        Err(WriteError::ConnectionClosed { .. })
    ));

    // Reset before closed, when a reset replaced a close.
    let mut sender = test_sender(1000, true);
    sender.close().unwrap();
    sender.reset(CODE).unwrap();
    assert!(matches!(
        sender.write(&mut source(1), &mut connection),
        Err(WriteError::Reset {
            source: StreamResetError
        })
    ));

    // A close before the write limit, when both apply.
    let mut sender = scripted_sender(1000, narrow_on_stop_sending(0));
    sender.on_stop_sending(CODE);
    sender.close().unwrap();
    assert!(matches!(
        sender.write(&mut source(1), &mut connection),
        Err(WriteError::Closed)
    ));

    // The write limit before temporary admission: no attempt is made.
    let mut sender = scripted_sender(0, narrow_on_stop_sending(0));
    sender.on_stop_sending(CODE);
    let error = sender.write(&mut source(1), &mut connection).unwrap_err();
    let WriteError::WriteLimitReached {
        write_limit_end,
        reason,
    } = error
    else {
        panic!("unexpected {error:?}");
    };
    assert_eq!((write_limit_end, *reason), (v(0), "stopped"));
    assert!(sender.composition.flow_control.attempts.is_empty());
}

#[test]
fn close_errors_follow_the_check_order() {
    let mut sender = test_sender(1000, true);
    sender.reset(CODE).unwrap();
    assert_eq!(
        sender.close(),
        Err(CloseError::AlreadyReset {
            source: StreamResetError
        })
    );
    sender.on_connection_closed();
    assert_eq!(
        sender.close(),
        Err(CloseError::ConnectionClosed {
            source: ConnectionClosedError::new()
        })
    );
}

#[test]
fn reset_errors_follow_the_check_order() {
    let mut connection = ConnectionSendFlowController::new(v(1000));

    // A conflict with the fixed target is reported before the terminal state.
    let mut sender = test_sender(1000, true);
    write_all(&mut sender, &mut connection, 100);
    sender.reset(CODE).unwrap();
    sender
        .enter_terminal_state(SendTerminalState::ResetRecvd)
        .unwrap();
    assert!(matches!(
        sender.reset(OTHER_CODE),
        Err(ResetError::ErrorCodeConflict { .. })
    ));
    assert_eq!(
        sender.reset_at(CODE, VarInt::ZERO),
        Ok(()),
        "an identical target is a no-op even in a terminal state"
    );

    // The terminal state before the missing extension.
    let mut sender = test_sender(1000, false);
    write_all(&mut sender, &mut connection, 100);
    sender.close().unwrap();
    sender
        .enter_terminal_state(SendTerminalState::DataRecvd)
        .unwrap();
    assert_eq!(
        sender.reset_at(CODE, v(50)),
        Err(ResetAtError::ProtocolTerminal {
            source: ProtocolTerminalError::check(Some(SendTerminalState::DataRecvd)).unwrap_err(),
        })
    );

    // The missing extension before an unprepared prefix.
    let mut sender = test_sender(1000, false);
    write_all(&mut sender, &mut connection, 100);
    assert_eq!(
        sender.reset_at(CODE, v(500)),
        Err(ResetAtError::UnsupportedExtension {
            source: ResetStreamAtNotNegotiatedError::check(v(500), false).unwrap_err(),
        })
    );

    // An unprepared prefix before an invalid final size.
    let mut sender = test_sender(1000, true);
    write_all(&mut sender, &mut connection, 100);
    assert_eq!(
        sender.reset_at_with_final_size(CODE, v(500), v(2000)),
        Err(ResetAtWithFinalSizeError::ReliablePrefixNotPrepared {
            source: ReliablePrefixNotPreparedError::check(v(500), v(100)).unwrap_err(),
        })
    );
    assert_eq!(
        sender.reset_at_with_final_size(CODE, v(50), v(2000)),
        Err(ResetAtWithFinalSizeError::FinalSizeBeyondWrittenEnd {
            source: FinalSizeBeyondWrittenEndError::check(v(2000), v(100)).unwrap_err(),
        })
    );
    // Failed requests change nothing and never reach the policy.
    assert_eq!(sender.end_state(), SendEndState::Open);
    assert!(sender.composition.termination.completions.is_empty());
    assert_eq!(end_commits(&sender), 0);
}

// ---------------------------------------------------------------------------
// State transitions, idempotence and conflicts

/// State transitions, idempotence and conflicts, row by row.
#[test]
fn state_transition_table() {
    let mut connection = ConnectionSendFlowController::new(v(10_000));

    // Close, then close again: success without a new action.
    let mut sender = test_sender(1000, true);
    write_all(&mut sender, &mut connection, 100);
    sender.close().unwrap();
    sender.close().unwrap();
    assert_eq!(end_commits(&sender), 1);
    assert_eq!(
        sender.end_state(),
        SendEndState::Closed {
            final_size: v(100),
            source: EndSource::Application,
        }
    );

    // Reset, then the identical target: a no-op, also in a terminal state.
    let mut sender = test_sender(1000, true);
    write_all(&mut sender, &mut connection, 100);
    sender.reset_at(CODE, v(60)).unwrap();
    let target = sender.end_state();
    sender.reset_at(CODE, v(60)).unwrap();
    sender.reset_at_with_final_size(CODE, v(60), v(60)).unwrap();
    sender
        .enter_terminal_state(SendTerminalState::ResetRecvd)
        .unwrap();
    sender.reset_at(CODE, v(60)).unwrap();
    assert_eq!(sender.end_state(), target);
    assert_eq!(end_commits(&sender), 1);
    assert_eq!(sender.composition.termination.completions.len(), 1);

    // reset_at with the same code and final size and a smaller reliable size.
    let mut sender = test_sender(1000, true);
    write_all(&mut sender, &mut connection, 100);
    sender.reset_at(CODE, v(80)).unwrap();
    sender.reset_at(CODE, v(30)).unwrap();
    assert_eq!(
        sender.end_state(),
        SendEndState::Reset {
            target: reset_target(CODE, 30, 80),
            source: EndSource::Application,
        }
    );
    assert_eq!(end_commits(&sender), 2);

    // A larger reliable size conflicts.
    assert_eq!(
        sender.reset_at(CODE, v(31)),
        Err(ResetAtError::ReliableSizeIncrease {
            source: ReliableSizeIncreaseError::check(v(30), v(31)).unwrap_err(),
        })
    );

    // A different error code or final size conflicts.
    assert_eq!(
        sender.reset_at(OTHER_CODE, v(30)),
        Err(ResetAtError::ErrorCodeConflict {
            source: ResetCodeChangeError::check(CODE, OTHER_CODE).unwrap_err(),
        })
    );
    assert_eq!(
        sender.reset_at_with_final_size(CODE, v(30), v(90)),
        Err(ResetAtWithFinalSizeError::FinalSizeConflictsWithReset {
            source: FinalSizeChangeError::check(v(80), v(90)).unwrap_err(),
        })
    );
    assert_eq!(
        sender.reset_with_final_size(CODE, v(90)),
        Err(ResetWithFinalSizeError::FinalSizeConflictsWithReset {
            source: FinalSizeChangeError::check(v(80), v(90)).unwrap_err(),
        }),
        "a plain reset with a final size meets the effective reset's"
    );

    // Close, then reset: legal, keeping the fixed final size.
    let mut sender = test_sender(1000, true);
    write_all(&mut sender, &mut connection, 100);
    sender.close().unwrap();
    sender.reset_at(CODE, v(40)).unwrap();
    assert_eq!(
        sender.end_state(),
        SendEndState::Reset {
            target: reset_target(CODE, 40, 100),
            source: EndSource::Application,
        }
    );
    assert!(sender.composition.termination.completions.is_empty());
    let mut closed = test_sender(1000, true);
    write_all(&mut closed, &mut connection, 100);
    closed.close().unwrap();
    assert_eq!(
        closed.reset_with_final_size(CODE, v(90)),
        Err(ResetWithFinalSizeError::FinalSizeConflictsWithClose {
            source: FinalSizeChangeError::check(v(100), v(90)).unwrap_err(),
        })
    );

    // Reset, then close: an error.
    assert_eq!(
        sender.close(),
        Err(CloseError::AlreadyReset {
            source: StreamResetError
        })
    );

    // A terminal state after complete delivery takes no new reset.
    closed
        .enter_terminal_state(SendTerminalState::DataRecvd)
        .unwrap();
    assert_eq!(
        closed.reset(CODE),
        Err(ResetError::ProtocolTerminal {
            source: ProtocolTerminalError::check(Some(SendTerminalState::DataRecvd)).unwrap_err(),
        })
    );
    assert_eq!(closed.close(), Ok(()));

    // A closed connection fails every new call, ahead of no-ops and empty
    // input.
    sender.on_connection_closed();
    assert_eq!(
        sender.reset_at(CODE, v(40)),
        Err(ResetAtError::ConnectionClosed {
            source: ConnectionClosedError::new()
        })
    );
    assert_eq!(
        sender.close(),
        Err(CloseError::ConnectionClosed {
            source: ConnectionClosedError::new()
        })
    );
    assert!(matches!(
        sender.write(&mut Bytes::new(), &mut connection),
        Err(WriteError::ConnectionClosed { .. })
    ));
    assert_eq!(
        sender.flush(),
        Err(FlushError::ConnectionClosed {
            source: ConnectionClosedError::new()
        })
    );
    closed.on_connection_closed();
    assert_eq!(
        closed.close(),
        Err(CloseError::ConnectionClosed {
            source: ConnectionClosedError::new()
        })
    );
}

/// Whether a request conflicts depends on the effective target, not on the
/// history of requests: 800 lowered to 400 makes 800 an increase.
#[test]
fn conflicts_follow_the_effective_target() {
    let mut connection = ConnectionSendFlowController::new(v(10_000));
    let mut sender = test_sender(1000, true);
    write_all(&mut sender, &mut connection, 1000);
    sender.reset_at(CODE, v(800)).unwrap();
    sender.reset_at(CODE, v(400)).unwrap();
    assert!(matches!(
        sender.reset_at(CODE, v(800)),
        Err(ResetAtError::ReliableSizeIncrease { .. })
    ));
}

/// An active reset_at of 600 that the policy then lowers to 400: a later
/// active request for 600 fails, one for 400 succeeds without effect.
#[test]
fn active_requests_meet_the_automatic_target_in_effect() {
    let mut connection = ConnectionSendFlowController::new(v(10_000));
    let mut sender = scripted_sender(1000, |event, context| match (event, context.end_state) {
        (
            SendTerminationEvent::EndCommitted {
                source: EndSource::Application,
            },
            SendEndState::Reset { target, .. },
        ) => TerminationAction::Reset(ResetTarget {
            reliable_size: v(400),
            ..target
        }),
        _ => TerminationAction::Keep,
    });
    write_all(&mut sender, &mut connection, 1000);
    sender.reset_at(CODE, v(600)).unwrap();
    assert_eq!(
        sender.end_state(),
        SendEndState::Reset {
            target: reset_target(CODE, 400, 600),
            source: EndSource::Policy,
        }
    );
    assert!(matches!(
        sender.reset_at(CODE, v(600)),
        Err(ResetAtError::ReliableSizeIncrease { .. })
    ));
    sender.reset_at(CODE, v(400)).unwrap();
    assert_eq!(
        sender.end_state(),
        SendEndState::Reset {
            target: reset_target(CODE, 400, 600),
            source: EndSource::Policy,
        }
    );
}

// ---------------------------------------------------------------------------
// reset_at and the handed-over prefix

/// With 600 written, reset_at(800) fails without effect;
/// after writing 200 more it succeeds.
#[test]
fn reset_at_needs_the_prefix_written() {
    let mut connection = ConnectionSendFlowController::new(v(10_000));
    let mut sender = test_sender(1000, true);
    write_all(&mut sender, &mut connection, 600);
    assert_eq!(
        sender.reset_at(CODE, v(800)),
        Err(ResetAtError::ReliablePrefixNotPrepared {
            source: ReliablePrefixNotPreparedError::check(v(800), v(600)).unwrap_err(),
        })
    );
    assert_eq!(sender.end_state(), SendEndState::Open);
    write_all(&mut sender, &mut connection, 200);
    sender.reset_at(CODE, v(800)).unwrap();
    assert_eq!(sender.reliable_size(), v(800));
}

/// A write limit of 700 makes reset_at(800) impossible; the request is
/// rejected, not shortened.
#[test]
fn reset_at_beyond_the_write_limit_cannot_be_prepared() {
    let mut connection = ConnectionSendFlowController::new(v(10_000));
    let mut sender = scripted_sender(1000, narrow_on_stop_sending(700));
    write_all(&mut sender, &mut connection, 600);
    sender.on_stop_sending(CODE);
    let mut input = source(200);
    assert_eq!(
        sender.write(&mut input, &mut connection).unwrap(),
        written(100)
    );
    assert!(matches!(
        sender.reset_at(CODE, v(800)),
        Err(ResetAtError::ReliablePrefixNotPrepared { .. })
    ));
}

/// A write limit below the written end does not limit the reliable size of a
/// reset: it only restricts new input.
#[test]
fn write_limit_below_the_written_end_keeps_the_prefix() {
    let mut connection = ConnectionSendFlowController::new(v(10_000));
    let mut sender = scripted_sender(1000, narrow_on_stop_sending(300));
    write_all(&mut sender, &mut connection, 600);
    sender.on_stop_sending(CODE);
    assert_eq!(sender.write_limit_end(), Some(v(300)));
    sender.reset_at(CODE, v(400)).unwrap();
    assert_eq!(sender.reliable_size(), v(400));
}

// ---------------------------------------------------------------------------
// Final size range and credit retention

/// Written end 1000, exposure end 400, reliable size
/// 600; the final size ranges from 600 to 1000.
#[test]
fn reset_final_size_range() {
    let mut connection = ConnectionSendFlowController::new(v(10_000));
    let prepare = |connection: &mut ConnectionSendFlowController| {
        let mut sender = test_sender(1000, true);
        write_all(&mut sender, connection, 1000);
        expose(&mut sender, connection, 400);
        sender
    };

    let mut sender = prepare(&mut connection);
    sender.reset_at(CODE, v(600)).unwrap();
    assert_eq!(
        sender.composition.termination.completions,
        [FinalSizeRequest {
            error_code: CODE,
            reliable_size: v(600),
            minimum: v(600),
            maximum: v(1000),
        }]
    );

    for (final_size, expected) in [
        (
            399,
            Err(ResetAtWithFinalSizeError::FinalSizeBelowReliableSize {
                source: ReliableSizeError::check(v(399), v(600)).unwrap_err(),
            }),
        ),
        (
            599,
            Err(ResetAtWithFinalSizeError::FinalSizeBelowReliableSize {
                source: ReliableSizeError::check(v(599), v(600)).unwrap_err(),
            }),
        ),
        (600, Ok(())),
        (1000, Ok(())),
        (
            1001,
            Err(ResetAtWithFinalSizeError::FinalSizeBeyondWrittenEnd {
                source: FinalSizeBeyondWrittenEndError::check(v(1001), v(1000)).unwrap_err(),
            }),
        ),
    ] {
        let mut sender = prepare(&mut connection);
        let result = sender.reset_at_with_final_size(CODE, v(600), v(final_size));
        assert_eq!(result, expected, "final size {final_size}");
        if expected.is_ok() {
            assert_eq!(sender.end_state().final_size(), Some(v(final_size)));
        }
        // An explicit final size never asks the policy.
        assert!(sender.composition.termination.completions.is_empty());
    }

    // Below both the reliable size and the exposure end: the reliable size
    // is reported first.
    let mut sender = prepare(&mut connection);
    assert!(matches!(
        sender.reset_at_with_final_size(CODE, v(300), v(200)),
        Err(ResetAtWithFinalSizeError::FinalSizeBelowReliableSize { .. })
    ));

    // A reliable size below the exposure end: the exposure end bounds the
    // final size.
    let mut sender = prepare(&mut connection);
    assert_eq!(
        sender.reset_at_with_final_size(CODE, v(300), v(399)),
        Err(ResetAtWithFinalSizeError::FinalSizeBelowExposure {
            source: FinalSizeBelowExposureError::check(v(399), v(400)).unwrap_err(),
        })
    );

    // Plain reset: the minimum is the exposure end.
    let mut sender = prepare(&mut connection);
    assert_eq!(
        sender.reset_with_final_size(CODE, v(399)),
        Err(ResetWithFinalSizeError::FinalSizeBelowExposure {
            source: FinalSizeBelowExposureError::check(v(399), v(400)).unwrap_err(),
        })
    );
    let mut sender = prepare(&mut connection);
    assert_eq!(
        sender.reset_with_final_size(CODE, v(1001)),
        Err(ResetWithFinalSizeError::FinalSizeBeyondWrittenEnd {
            source: FinalSizeBeyondWrittenEndError::check(v(1001), v(1000)).unwrap_err(),
        })
    );
}

/// Final size 800 and reliable size 600 keep the coverage up to 800 and
/// cancel the 200 beyond; lowering the reliable size to 200 later returns
/// nothing of the coverage of 800.
#[test]
fn reset_keeps_coverage_up_to_the_final_size() {
    let mut connection = ConnectionSendFlowController::new(v(10_000));
    let mut sender = test_sender(1000, true);
    write_all(&mut sender, &mut connection, 1000);
    expose(&mut sender, &mut connection, 400);
    assert_eq!(
        (connection.reserved(), connection.committed()),
        (v(600), v(400))
    );

    sender
        .reset_at_with_final_size(CODE, v(600), v(800))
        .unwrap();
    assert_eq!(
        (connection.reserved(), connection.committed()),
        (v(400), v(400))
    );
    assert_eq!(connection.available(), v(10_000 - 800));

    sender.reset_at(CODE, v(200)).unwrap();
    assert_eq!(
        (connection.reserved(), connection.committed()),
        (v(400), v(400))
    );
    assert_eq!(sender.written_end(), v(1000));

    // Exposing the reset's final size commits the retained coverage.
    sender
        .expose_usage_through(v(800), ExposedEnd::FinalSize, &mut connection)
        .unwrap();
    assert_eq!(
        (connection.reserved(), connection.committed()),
        (v(0), v(800))
    );
}

/// L = 100: writing 80, exposing 30 and resetting at the
/// exposure end leaves 70 available.
#[test]
fn connection_credit_example_through_a_stream() {
    let mut connection = ConnectionSendFlowController::new(v(100));
    let mut sender = default_sender(1000, false);
    write_all(&mut sender, &mut connection, 80);
    assert_eq!(connection.available(), v(20));
    expose(&mut sender, &mut connection, 30);
    assert_eq!(
        (connection.reserved(), connection.committed()),
        (v(50), v(30))
    );
    assert_eq!(connection.available(), v(20));
    sender.reset(CODE).unwrap();
    assert_eq!(sender.end_state().final_size(), Some(v(30)));
    assert_eq!(
        (connection.reserved(), connection.committed()),
        (v(0), v(30))
    );
    assert_eq!(connection.available(), v(70));
}

/// Close succeeded, FIN not yet exposed: a later reset_at keeps the final
/// size and its existing coverage, and needs no available credit.
#[test]
fn reset_at_after_close_before_the_fin_is_exposed() {
    let mut connection = ConnectionSendFlowController::new(v(1000));
    let mut sender = test_sender(1000, true);
    write_all(&mut sender, &mut connection, 1000);
    expose(&mut sender, &mut connection, 300);
    sender.close().unwrap();
    assert_eq!(connection.available(), v(0));

    sender.reset_at(CODE, v(200)).unwrap();
    assert_eq!(sender.end_state().final_size(), Some(v(1000)));
    assert_eq!(
        (connection.reserved(), connection.committed()),
        (v(700), v(300))
    );
    sender
        .expose_usage_through(v(1000), ExposedEnd::FinalSize, &mut connection)
        .unwrap();
    assert_eq!(
        (connection.reserved(), connection.committed()),
        (v(0), v(1000))
    );
}

/// FIN possibly visible: the final size is committed; a later reset_at adds
/// no usage, works without available credit and returns nothing.
#[test]
fn reset_at_after_the_fin_is_exposed() {
    let mut connection = ConnectionSendFlowController::new(v(1000));
    let mut sender = test_sender(1000, true);
    write_all(&mut sender, &mut connection, 1000);
    sender.close().unwrap();
    assert_eq!(
        sender
            .expose_usage_through(v(1000), ExposedEnd::FinalSize, &mut connection)
            .unwrap(),
        v(1000)
    );
    assert_eq!(connection.available(), v(0));

    sender.reset_at(CODE, v(200)).unwrap();
    assert_eq!(
        (connection.reserved(), connection.committed()),
        (v(0), v(1000))
    );
    assert_eq!(
        sender
            .expose_usage_through(v(1000), ExposedEnd::FinalSize, &mut connection)
            .unwrap(),
        VarInt::ZERO
    );
    assert!(matches!(
        sender.expose_usage_through(v(900), ExposedEnd::FinalSize, &mut connection),
        Err(SenderExposeUsageError::FinalSizeMismatch { .. })
    ));
}

#[test]
fn exposure_needs_a_fixed_final_size() {
    let mut connection = ConnectionSendFlowController::new(v(1000));
    let mut sender = test_sender(1000, true);
    write_all(&mut sender, &mut connection, 100);
    assert_eq!(
        sender.expose_usage_through(v(100), ExposedEnd::FinalSize, &mut connection),
        Err(SenderExposeUsageError::FinalSizeNotFixed { final_size: v(100) })
    );
    expose(&mut sender, &mut connection, 50);
    assert_eq!(
        sender.composition.flow_control.events,
        [StreamCreditEvent::FirstExposed {
            exposure_end: v(50)
        }]
    );
    assert_eq!(
        sender.composition.termination.events.last(),
        Some(&SendTerminationEvent::FirstExposed {
            exposure_end: v(50)
        })
    );
}

// ---------------------------------------------------------------------------
// Write limit

/// The write limit only narrows; an attempt crossing it takes the permitted
/// part first and the next attempt fails, also after the peer raises its
/// limit.
#[test]
fn write_limit_narrows_and_stops_new_input() {
    let mut connection = ConnectionSendFlowController::new(v(10_000));
    let mut sender = scripted_sender(1000, |event, _| match event {
        SendTerminationEvent::StopSendingReceived { .. } => TerminationAction::NarrowWriteLimit {
            write_limit_end: v(700),
            reason: "first",
        },
        SendTerminationEvent::WriterAbandoned => TerminationAction::NarrowWriteLimit {
            write_limit_end: v(700),
            reason: "second",
        },
        _ => TerminationAction::Keep,
    });
    write_all(&mut sender, &mut connection, 600);
    sender.on_stop_sending(CODE);
    assert_eq!(sender.write_limit_end(), Some(v(700)));

    let mut input = source(300);
    assert_eq!(
        sender.write(&mut input, &mut connection).unwrap(),
        written(100)
    );
    assert_eq!(input.remaining(), 200);
    sender.on_max_stream_data(v(5000));
    let error = sender.write(&mut input, &mut connection).unwrap_err();
    assert!(matches!(
        error,
        WriteError::WriteLimitReached { write_limit_end, ref reason }
            if write_limit_end == v(700) && **reason == "first"
    ));
    assert_eq!(input.remaining(), 200);

    // An equal limit keeps the original reason.
    sender.on_writer_abandoned();
    assert_eq!(
        sender.write_limit_reason().map(|reason| **reason),
        Some("first")
    );
    assert_eq!(
        sender
            .composition
            .flow_control
            .events
            .iter()
            .filter(|event| matches!(event, StreamCreditEvent::WriteLimitNarrowed { .. }))
            .count(),
        1
    );
    // Closing ends normally at the written end, not at the write limit.
    sender.close().unwrap();
    assert_eq!(sender.end_state().final_size(), Some(v(700)));
}

#[test]
#[should_panic(expected = "widened the write limit")]
fn widening_the_write_limit_is_a_policy_violation() {
    let mut limits = [v(500), v(600)].into_iter();
    let mut sender = scripted_sender(1000, move |event, _| match event {
        SendTerminationEvent::StopSendingReceived { .. } => TerminationAction::NarrowWriteLimit {
            write_limit_end: limits.next().unwrap(),
            reason: "stopped",
        },
        _ => TerminationAction::Keep,
    });
    sender.on_stop_sending(CODE);
    sender.on_stop_sending(CODE);
}

#[test]
#[should_panic(expected = "without a STOP_SENDING request")]
fn narrowing_without_stop_sending_is_a_policy_violation() {
    let mut sender = scripted_sender(1000, |event, _| match event {
        SendTerminationEvent::WriterAbandoned => TerminationAction::NarrowWriteLimit {
            write_limit_end: v(0),
            reason: "abandoned",
        },
        _ => TerminationAction::Keep,
    });
    sender.on_writer_abandoned();
}

// ---------------------------------------------------------------------------
// Policy violations

#[test]
#[should_panic(expected = "chose a final size beyond the written end")]
fn final_size_beyond_the_written_end_is_a_policy_violation() {
    let mut connection = ConnectionSendFlowController::new(v(10_000));
    let mut sender = test_sender(1000, true);
    sender.composition.termination.final_size = Some(v(1200));
    write_all(&mut sender, &mut connection, 1000);
    expose(&mut sender, &mut connection, 400);
    let _ = sender.reset_at(CODE, v(600));
}

#[test]
#[should_panic(expected = "chose a final size below the reliable size")]
fn final_size_below_the_reliable_size_is_a_policy_violation() {
    let mut connection = ConnectionSendFlowController::new(v(10_000));
    let mut sender = test_sender(1000, true);
    sender.composition.termination.final_size = Some(v(500));
    write_all(&mut sender, &mut connection, 1000);
    expose(&mut sender, &mut connection, 400);
    let _ = sender.reset_at(CODE, v(600));
}

#[test]
#[should_panic(expected = "chose a final size below the exposure end")]
fn final_size_below_the_exposure_end_is_a_policy_violation() {
    let mut connection = ConnectionSendFlowController::new(v(10_000));
    let mut sender = test_sender(1000, true);
    sender.composition.termination.final_size = Some(v(300));
    write_all(&mut sender, &mut connection, 1000);
    expose(&mut sender, &mut connection, 400);
    let _ = sender.reset(CODE);
}

#[test]
#[should_panic(expected = "illegal reset")]
fn changing_the_error_code_automatically_is_a_policy_violation() {
    let mut sender = scripted_sender(1000, |event, context| match (event, context.end_state) {
        (SendTerminationEvent::StopSendingReceived { .. }, SendEndState::Reset { target, .. }) => {
            TerminationAction::Reset(ResetTarget {
                error_code: OTHER_CODE,
                ..target
            })
        }
        _ => TerminationAction::Keep,
    });
    sender.reset(CODE).unwrap();
    sender.on_stop_sending(CODE);
}

#[test]
#[should_panic(expected = "illegal reset")]
fn automatic_reset_below_the_exposure_end_is_a_policy_violation() {
    let mut connection = ConnectionSendFlowController::new(v(10_000));
    let mut sender = scripted_sender(1000, |event, _| match event {
        SendTerminationEvent::WriterAbandoned => {
            TerminationAction::Reset(reset_target(CODE, 0, 10))
        }
        _ => TerminationAction::Keep,
    });
    write_all(&mut sender, &mut connection, 100);
    expose(&mut sender, &mut connection, 50);
    sender.on_writer_abandoned();
}

#[test]
#[should_panic(expected = "closed a stream that was reset")]
fn closing_after_a_reset_is_a_policy_violation() {
    let mut sender = scripted_sender(1000, |event, _| match event {
        SendTerminationEvent::WriterAbandoned => TerminationAction::Close,
        _ => TerminationAction::Keep,
    });
    sender.reset(CODE).unwrap();
    sender.on_writer_abandoned();
}

#[test]
#[should_panic(expected = "illegal reset")]
fn acting_after_the_connection_closed_is_a_policy_violation() {
    let mut sender = scripted_sender(1000, |event, context| match event {
        SendTerminationEvent::ConnectionClosed => {
            TerminationAction::Reset(reset_target(CODE, 0, context.written_end.get() as u32))
        }
        _ => TerminationAction::Keep,
    });
    sender.on_connection_closed();
}

/// An automatic action committed after data was appended does not turn the
/// write into an error.
#[test]
fn automatic_end_after_an_append_keeps_the_write_successful() {
    let mut connection = ConnectionSendFlowController::new(v(10_000));
    let mut sender = scripted_sender(1000, |event, _| match event {
        SendTerminationEvent::DataAppended { .. } => TerminationAction::Close,
        _ => TerminationAction::Keep,
    });
    write_all(&mut sender, &mut connection, 10);
    assert_eq!(
        sender.end_state(),
        SendEndState::Closed {
            final_size: v(10),
            source: EndSource::Policy,
        }
    );
    // The policy observed its own close, and the chain stopped there.
    assert_eq!(
        sender.composition.termination.events,
        [
            SendTerminationEvent::DataAppended {
                appended_range: v(0)..v(10),
            },
            SendTerminationEvent::EndCommitted {
                source: EndSource::Policy,
            },
        ]
    );
}

// ---------------------------------------------------------------------------
// Default composition

#[test]
fn default_flow_control_admits_all_room() {
    let mut connection = ConnectionSendFlowController::new(v(10_000));
    let mut sender = default_sender(700, false);
    let mut input = source(1000);
    assert_eq!(
        sender.write(&mut input, &mut connection).unwrap(),
        written(700)
    );
    assert_eq!(input.remaining(), 300);
}

#[test]
fn default_flow_control_signals_only_when_stream_limited() {
    let mut connection = ConnectionSendFlowController::new(v(10_000));
    let mut sender = default_sender(700, false);
    write_all(&mut sender, &mut connection, 500);
    assert_eq!(sender.stream_data_blocked_limit(), None);

    // Limited by the connection, not the stream: no signal.
    let mut tight = default_sender(700, false);
    let mut small = ConnectionSendFlowController::new(v(10));
    let mut input = source(100);
    assert_eq!(tight.write(&mut input, &mut small).unwrap(), written(10));
    assert_eq!(tight.stream_data_blocked_limit(), None);

    // Limited by the stream: signal the current limit, until sent.
    let mut input = source(500);
    assert_eq!(
        sender.write(&mut input, &mut connection).unwrap(),
        written(200)
    );
    assert_eq!(sender.stream_data_blocked_limit(), Some(v(700)));
    sender.on_stream_data_blocked_sent(v(700));
    assert_eq!(sender.stream_data_blocked_limit(), None);

    // Blocked again at the same limit: not repeated at once.
    assert_eq!(
        sender.write(&mut input, &mut connection).unwrap(),
        WriteOutcome::Wait(WriteWait::StreamCredit)
    );
    assert_eq!(sender.stream_data_blocked_limit(), None);

    // A larger limit clears the intent; blocking at it signals the new limit.
    sender.on_max_stream_data(v(800));
    assert_eq!(sender.stream_data_blocked_limit(), None);
    assert_eq!(
        sender.write(&mut input, &mut connection).unwrap(),
        written(100)
    );
    assert_eq!(sender.stream_data_blocked_limit(), Some(v(800)));

    // An acknowledgement of the old value clears nothing.
    sender.on_stream_data_blocked_acknowledged(v(700));
    assert_eq!(sender.stream_data_blocked_limit(), Some(v(800)));

    // No signal once the stream is reset.
    sender.reset(CODE).unwrap();
    assert_eq!(sender.stream_data_blocked_limit(), None);
}

#[test]
fn default_termination_chooses_the_smallest_final_size() {
    let mut connection = ConnectionSendFlowController::new(v(10_000));
    let mut sender = default_sender(1000, true);
    write_all(&mut sender, &mut connection, 1000);
    expose(&mut sender, &mut connection, 400);
    sender.reset_at(CODE, v(600)).unwrap();
    assert_eq!(sender.end_state().final_size(), Some(v(600)));

    let mut sender = default_sender(1000, true);
    write_all(&mut sender, &mut connection, 1000);
    expose(&mut sender, &mut connection, 400);
    sender.reset(CODE).unwrap();
    assert_eq!(sender.end_state().final_size(), Some(v(400)));
}

#[test]
fn default_termination_resets_on_stop_sending() {
    let mut connection = ConnectionSendFlowController::new(v(10_000));

    // Open: reset at once with the request's error code.
    let mut sender = default_sender(1000, true);
    write_all(&mut sender, &mut connection, 1000);
    expose(&mut sender, &mut connection, 250);
    sender.on_stop_sending(OTHER_CODE);
    assert_eq!(
        sender.end_state(),
        SendEndState::Reset {
            target: reset_target(OTHER_CODE, 0, 250),
            source: EndSource::Policy,
        }
    );

    // Closed: reset with the fixed final size.
    let mut sender = default_sender(1000, true);
    write_all(&mut sender, &mut connection, 100);
    sender.close().unwrap();
    sender.on_stop_sending(OTHER_CODE);
    assert_eq!(
        sender.end_state(),
        SendEndState::Reset {
            target: reset_target(OTHER_CODE, 0, 100),
            source: EndSource::Policy,
        }
    );

    // Reset already: keep the code and final size, lower the reliable size.
    let mut sender = default_sender(1000, true);
    write_all(&mut sender, &mut connection, 1000);
    sender.reset_at(CODE, v(600)).unwrap();
    sender.on_stop_sending(OTHER_CODE);
    assert_eq!(
        sender.end_state(),
        SendEndState::Reset {
            target: reset_target(CODE, 0, 600),
            source: EndSource::Policy,
        }
    );

    // Terminal: nothing new.
    let mut sender = default_sender(1000, true);
    write_all(&mut sender, &mut connection, 100);
    sender.close().unwrap();
    sender
        .enter_terminal_state(SendTerminalState::DataRecvd)
        .unwrap();
    sender.on_stop_sending(OTHER_CODE);
    assert!(matches!(sender.end_state(), SendEndState::Closed { .. }));
}

#[test]
fn default_termination_resets_an_abandoned_open_writer() {
    let mut connection = ConnectionSendFlowController::new(v(10_000));
    let mut sender = default_sender(1000, false);
    write_all(&mut sender, &mut connection, 100);
    sender.on_writer_abandoned();
    assert_eq!(
        sender.end_state(),
        SendEndState::Reset {
            target: reset_target(code(0x10c), 0, 0),
            source: EndSource::Policy,
        }
    );

    // An abandoned writer of a closed stream changes nothing.
    let mut sender = default_sender(1000, false);
    write_all(&mut sender, &mut connection, 100);
    sender.close().unwrap();
    sender.on_writer_abandoned();
    assert_eq!(
        sender.end_state(),
        SendEndState::Closed {
            final_size: v(100),
            source: EndSource::Application,
        }
    );
}

/// A policy that keeps the stream open after its writer is abandoned leaves
/// the accepted data with the stream sender, which still handles
/// `STOP_SENDING`.
#[test]
fn keeping_an_abandoned_stream_retains_its_data() {
    let mut connection = ConnectionSendFlowController::new(v(10_000));
    let mut sender = test_sender(1000, false);
    write_all(&mut sender, &mut connection, 100);
    sender.on_writer_abandoned();
    assert_eq!(sender.end_state(), SendEndState::Open);
    assert_eq!(sender.composition.buffer.retained().count(), 1);
    assert_eq!(connection.reserved(), v(100));
    sender.on_stop_sending(CODE);
    assert_eq!(
        sender.composition.termination.events.last(),
        Some(&SendTerminationEvent::StopSendingReceived { error_code: CODE })
    );
}
