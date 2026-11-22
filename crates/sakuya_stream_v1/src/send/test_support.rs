//! What the tests of stream senders share, whatever the type of their reset
//! target: recording policies, senders built from them and the steps a packet
//! writer takes.
use super::flow_control::{
    AdmissionGuard, FullCeilingAdmission, SendFlowContext, SendFlowControlPolicy,
    StreamCreditEvent, WriteAttempt,
};
use super::local_reset::LocalResetTarget;
use super::termination::{
    FinalSizeRequest, SendTerminationContext, SendTerminationEvent, SendTerminationPolicy,
    TerminationAction,
};
use super::write::{WriteOutcome, WriteReport};
use crate::connection::CloseReason;
use crate::connection_send_credit::{
    AtomicConnectionCreditReservation, AtomicConnectionSendFlowController,
};
use crate::send_options::SendOptions;
use crate::send_options::destination::{
    AnyActiveLinkPath, DestinationFallback, SendDestination, StreamSendDestination, Unfulfilled,
};
use crate::send_options::urgency::Urgency;
use bytes::Bytes;
use sakuya_wire_v1::application_error::ApplicationErrorCode;
use sakuya_wire_v1::stream_id::StreamId;
use sakuya_wire_v1::var_int::VarInt;
use std::sync::Arc;

pub fn v(value: u32) -> VarInt {
    VarInt::from_u32(value)
}

pub fn code(value: u32) -> ApplicationErrorCode {
    ApplicationErrorCode::new(v(value))
}

pub fn stream() -> StreamId {
    StreamId::from(v(4))
}

pub const CODE: ApplicationErrorCode = ApplicationErrorCode::new(VarInt::from_u32(7));
pub const OTHER_CODE: ApplicationErrorCode = ApplicationErrorCode::new(VarInt::from_u32(9));

/// The reason the tests close connections for.
pub fn close_reason() -> CloseReason<TestCloseCause> {
    CloseReason::Local(Arc::new(TestCloseCause("done")))
}

/// The local close cause of the test connections.
#[derive(Debug, PartialEq, Eq)]
pub struct TestCloseCause(pub &'static str);

impl core::fmt::Display for TestCloseCause {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}

impl core::error::Error for TestCloseCause {}

/// A flow-control policy that records what it is told, caps grants at
/// `grant_cap` and otherwise behaves like the default policy.
#[derive(Debug, Default)]
pub struct RecordingFlow {
    pub grant_cap: Option<VarInt>,
    pub admit_nothing: bool,
    pub over_grant: bool,
    pub foreign_offset: bool,
    pub attempts: Vec<WriteAttempt>,
    pub settlements: Vec<(VarInt, Option<VarInt>)>,
    pub events: Vec<StreamCreditEvent>,
    inner: FullCeilingAdmission,
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
pub struct ScriptedTermination<S, T: LocalResetTarget> {
    script: S,
    pub final_size: Option<VarInt>,
    pub events: Vec<SendTerminationEvent>,
    pub completions: Vec<FinalSizeRequest<T>>,
}

impl<S, T: LocalResetTarget> ScriptedTermination<S, T> {
    pub fn new(script: S) -> Self {
        Self {
            script,
            final_size: None,
            events: Vec::new(),
            completions: Vec::new(),
        }
    }
}

/// The action a script of these tests decides.
pub type Action<T> = TerminationAction<&'static str, T>;

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

pub type Connection = AtomicConnectionSendFlowController;
pub type Reservation = AtomicConnectionCreditReservation;
/// The marker the tests write with: the default send options.
pub type Options = SendOptions<Urgency, AnyActiveLinkPath>;

/// The options of the tests' writes: the default urgency, to any active link
/// path.
pub fn options() -> Options {
    SendOptions::new(Urgency::default(), AnyActiveLinkPath)
}

pub fn new_connection(limit: u32) -> Arc<Connection> {
    Arc::new(Connection::new(v(limit)))
}

/// The script that never acts.
pub fn keep<T>(_: &SendTerminationEvent, _: &SendTerminationContext<T>) -> Action<T> {
    TerminationAction::Keep
}

/// The type of [`keep`].
pub type Keep<T> = fn(&SendTerminationEvent, &SendTerminationContext<T>) -> Action<T>;

/// A destination with nothing to fall back to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectOnly;

impl SendDestination for DirectOnly {
    type Current = Self;

    fn current(&self) -> Self {
        Self
    }

    fn on_unfulfilled(&mut self, _: Unfulfilled) -> DestinationFallback {
        DestinationFallback::Exhausted
    }
}

impl StreamSendDestination for DirectOnly {
    fn on_lost(&mut self) -> DestinationFallback {
        DestinationFallback::Exhausted
    }
}

/// The marker of writes that go only direct.
pub type DirectOptions = SendOptions<Urgency, DirectOnly>;

/// The default urgency, only direct.
pub fn direct() -> DirectOptions {
    SendOptions::new(Urgency::default(), DirectOnly)
}

/// The error code the default termination policy of these tests resets with
/// when data has no destination left.
pub const EXHAUSTED_CODE: ApplicationErrorCode = ApplicationErrorCode::new(VarInt::from_u32(0x10d));

pub fn source(length: usize) -> Bytes {
    Bytes::from(vec![0xa5; length])
}

pub fn written(new_bytes: u32) -> WriteOutcome {
    WriteOutcome::Written(WriteReport {
        new_bytes: v(new_bytes),
    })
}

/// A narrowing policy: on `STOP_SENDING`, the write limit end becomes `end`.
pub fn narrow_on_stop_sending<T>(
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
