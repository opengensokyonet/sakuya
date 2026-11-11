//! What the tests of stream senders share, whatever the type of their reset
//! target: recording policies, senders built from them and the steps a packet
//! writer takes.
use super::composition::{DefaultSendComposition, SendComposition};
use super::flow_control::{
    AdmissionGuard, DefaultSendFlowControlPolicy, SendFlowContext, SendFlowControlPolicy,
    StreamCreditEvent, WriteAttempt,
};
use super::local_reset::LocalResetTarget;
use super::termination::{
    DefaultSendTerminationPolicy, FinalSizeRequest, SendTerminationContext, SendTerminationEvent,
    SendTerminationPolicy, TerminationAction,
};
use super::write::{WriteOutcome, WriteReport};
use super::{StreamEndFrame, StreamSender};
use crate::connection::{CloseReason, ImmediateClose};
use crate::connection_send_credit::{
    AtomicConnectionCreditReservation, AtomicConnectionSendFlowController,
};
use crate::send_buffer::StreamSendBuffer;
use crate::send_buffer::offset_map::OffsetMapStreamSendBuffer;
use bytes::{Buf, Bytes};
use sakuya_wire::v1::application_error::ApplicationErrorCode;
use sakuya_wire::v1::stream_id::StreamId;
use sakuya_wire::var_int::VarInt;
use std::sync::Arc;

pub(crate) fn v(value: u32) -> VarInt {
    VarInt::from_u32(value)
}

pub(crate) fn code(value: u32) -> ApplicationErrorCode {
    ApplicationErrorCode::new(v(value))
}

pub(crate) fn stream() -> StreamId {
    StreamId::from(v(4))
}

pub(crate) const CODE: ApplicationErrorCode = ApplicationErrorCode::new(VarInt::from_u32(7));
pub(crate) const OTHER_CODE: ApplicationErrorCode = ApplicationErrorCode::new(VarInt::from_u32(9));

/// The reason the tests close connections for.
pub(crate) fn close_reason() -> CloseReason {
    CloseReason::Local(ImmediateClose::Application {
        code: ApplicationErrorCode::new(VarInt::from_u32(9)),
        reason_phrase: Bytes::from_static(b"done"),
    })
}

/// A flow-control policy that records what it is told, caps grants at
/// `grant_cap` and otherwise behaves like the default policy.
#[derive(Debug, Default)]
pub(crate) struct RecordingFlow {
    pub(crate) grant_cap: Option<VarInt>,
    pub(crate) admit_nothing: bool,
    pub(crate) over_grant: bool,
    pub(crate) foreign_offset: bool,
    pub(crate) attempts: Vec<WriteAttempt>,
    pub(crate) settlements: Vec<(VarInt, Option<VarInt>)>,
    pub(crate) events: Vec<StreamCreditEvent>,
    inner: DefaultSendFlowControlPolicy,
}

impl<T: LocalResetTarget> SendFlowControlPolicy<T> for RecordingFlow {
    fn admit_write(
        &mut self,
        attempt: &WriteAttempt,
        context: &SendFlowContext<T>,
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

    fn on_admission_used(&mut self, guard: AdmissionGuard, used: VarInt, _: &SendFlowContext<T>) {
        self.settlements.push((guard.granted(), Some(used)));
    }

    fn on_admission_abandoned(&mut self, guard: AdmissionGuard, _: &SendFlowContext<T>) {
        self.settlements.push((guard.granted(), None));
    }

    fn on_flow_event(&mut self, event: StreamCreditEvent, context: &SendFlowContext<T>) {
        self.events.push(event);
        self.inner.on_flow_event(event, context);
    }

    fn wants_stream_data_blocked(&self, context: &SendFlowContext<T>) -> bool {
        SendFlowControlPolicy::<T>::wants_stream_data_blocked(&self.inner, context)
    }
}

/// A termination policy that answers events through a script and records
/// them; it completes final sizes with the minimum unless `final_size` says
/// otherwise.
pub(crate) struct ScriptedTermination<S, T: LocalResetTarget> {
    script: S,
    final_size: Option<VarInt>,
    pub(crate) events: Vec<SendTerminationEvent>,
    pub(crate) completions: Vec<FinalSizeRequest<T>>,
}

impl<S, T: LocalResetTarget> ScriptedTermination<S, T> {
    pub(crate) fn new(script: S) -> Self {
        Self {
            script,
            final_size: None,
            events: Vec::new(),
            completions: Vec::new(),
        }
    }
}

/// The action a script of these tests decides.
pub(crate) type Action<T> = TerminationAction<&'static str, T>;

impl<S, T> SendTerminationPolicy<T> for ScriptedTermination<S, T>
where
    T: LocalResetTarget,
    S: FnMut(&SendTerminationEvent, &SendTerminationContext<T>) -> Action<T>,
{
    type WriteLimitReason = &'static str;

    fn on_termination_event(
        &mut self,
        event: SendTerminationEvent,
        context: &SendTerminationContext<T>,
    ) -> Action<T> {
        let action = (self.script)(&event, context);
        self.events.push(event);
        action
    }

    fn complete_final_size(
        &mut self,
        request: FinalSizeRequest<T>,
        _: &SendTerminationContext<T>,
    ) -> VarInt {
        self.completions.push(request);
        self.final_size.unwrap_or(request.minimum)
    }
}

pub(crate) type Connection = AtomicConnectionSendFlowController;
pub(crate) type Reservation = AtomicConnectionCreditReservation;

/// A sender over the recording policies, with the reset target `T`.
pub(crate) type TestSender<S, T> = StreamSender<
    SendComposition<
        OffsetMapStreamSendBuffer<Reservation>,
        RecordingFlow,
        ScriptedTermination<S, T>,
    >,
    Connection,
    T,
>;

pub(crate) fn new_connection(limit: u32) -> Arc<Connection> {
    Arc::new(Connection::new(v(limit)))
}

/// The script that never acts.
pub(crate) fn keep<T>(_: &SendTerminationEvent, _: &SendTerminationContext<T>) -> Action<T> {
    TerminationAction::Keep
}

pub(crate) fn scripted_sender<S, T>(
    connection: &Arc<Connection>,
    peer_stream_limit: u32,
    script: S,
) -> TestSender<S, T>
where
    T: LocalResetTarget,
    S: FnMut(&SendTerminationEvent, &SendTerminationContext<T>) -> Action<T>,
{
    sender_with(
        connection,
        peer_stream_limit,
        ScriptedTermination::new(script),
    )
}

/// The type of [`keep`].
pub(crate) type Keep<T> = fn(&SendTerminationEvent, &SendTerminationContext<T>) -> Action<T>;

/// A sender whose policy never acts and completes every final size with
/// `final_size`, legal or not.
pub(crate) fn completing_sender<T: LocalResetTarget>(
    connection: &Arc<Connection>,
    peer_stream_limit: u32,
    final_size: u32,
) -> TestSender<Keep<T>, T> {
    let mut termination = ScriptedTermination::new(keep::<T> as Keep<T>);
    termination.final_size = Some(v(final_size));
    sender_with(connection, peer_stream_limit, termination)
}

fn sender_with<S, T>(
    connection: &Arc<Connection>,
    peer_stream_limit: u32,
    termination: ScriptedTermination<S, T>,
) -> TestSender<S, T>
where
    T: LocalResetTarget,
    S: FnMut(&SendTerminationEvent, &SendTerminationContext<T>) -> Action<T>,
{
    StreamSender::new(
        stream(),
        v(peer_stream_limit),
        SendComposition::new(
            OffsetMapStreamSendBuffer::new(),
            RecordingFlow::default(),
            termination,
        ),
        Arc::clone(connection),
    )
}

/// A sender over the default composition.
pub(crate) fn default_sender<T>(
    connection: &Arc<Connection>,
    peer_stream_limit: u32,
) -> StreamSender<DefaultSendComposition, Connection, T>
where
    T: LocalResetTarget,
    DefaultSendTerminationPolicy: SendTerminationPolicy<T>,
{
    StreamSender::new(
        stream(),
        v(peer_stream_limit),
        DefaultSendComposition::with_abandon_code(code(0x10c)),
        Arc::clone(connection),
    )
}

pub(crate) fn source(length: usize) -> Bytes {
    Bytes::from(vec![0xa5; length])
}

pub(crate) fn written(new_bytes: u32) -> WriteOutcome {
    WriteOutcome::Written(WriteReport {
        new_bytes: v(new_bytes),
    })
}

/// Writes `length` bytes that must all be accepted.
pub(crate) fn write_all<C, T>(sender: &mut StreamSender<C, Connection, T>, length: u32)
where
    T: LocalResetTarget,
    C: StreamSendBuffer<Reservation = Reservation>
        + SendFlowControlPolicy<T>
        + SendTerminationPolicy<T>,
    C::WriteLimitReason: core::fmt::Debug,
{
    let mut input = source(length as usize);
    assert_eq!(sender.write(&mut input).unwrap(), written(length));
    assert!(!input.has_remaining());
}

pub(crate) fn expose<C, T>(sender: &mut StreamSender<C, Connection, T>, usage_end: u32)
where
    T: LocalResetTarget,
    C: StreamSendBuffer<Reservation = Reservation>
        + SendFlowControlPolicy<T>
        + SendTerminationPolicy<T>,
{
    sender.expose_usage_through(v(usage_end)).unwrap();
}

/// Prepares the end frame that is due and exposes it, as a packet writer
/// does after writing the frame; returns the frame.
pub(crate) fn send_end<C, T>(
    sender: &mut StreamSender<C, Connection, T>,
) -> StreamEndFrame<T::Frame>
where
    T: LocalResetTarget,
    C: StreamSendBuffer<Reservation = Reservation>
        + SendFlowControlPolicy<T>
        + SendTerminationPolicy<T>,
{
    let prepared = sender.prepare_end_frame().expect("an end frame is due");
    let frame = *prepared;
    prepared.expose();
    frame
}

/// The end frame the guard offers, if any, without exposing it.
pub(crate) fn due_end_frame<C, T>(
    sender: &mut StreamSender<C, Connection, T>,
) -> Option<StreamEndFrame<T::Frame>>
where
    T: LocalResetTarget,
    C: StreamSendBuffer<Reservation = Reservation>
        + SendFlowControlPolicy<T>
        + SendTerminationPolicy<T>,
{
    sender.prepare_end_frame().map(|prepared| *prepared)
}

/// How many ends the policy of `sender` saw committed.
pub(crate) fn end_commits<S, T>(sender: &TestSender<S, T>) -> usize
where
    T: LocalResetTarget,
    S: FnMut(&SendTerminationEvent, &SendTerminationContext<T>) -> Action<T>,
{
    sender
        .composition()
        .termination
        .events
        .iter()
        .filter(|event| matches!(event, SendTerminationEvent::EndCommitted { .. }))
        .count()
}

/// A narrowing policy: on `STOP_SENDING`, the write limit end becomes `end`.
pub(crate) fn narrow_on_stop_sending<T>(
    end: u32,
) -> impl FnMut(&SendTerminationEvent, &SendTerminationContext<T>) -> Action<T> {
    move |event, _| match event {
        SendTerminationEvent::StopSendingReceived { .. } => TerminationAction::NarrowWriteLimit {
            write_limit_end: v(end),
            reason: "stopped",
        },
        _ => TerminationAction::Keep,
    }
}
