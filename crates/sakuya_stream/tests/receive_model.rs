//! Model-based tests of the stream receiver, driven by generated operation
//! sequences on two streams that share one connection receive flow
//! controller.
//!
//! The model restates the contract of RFC 9000 §3.2, §3.5 and §4 and of the
//! stream receiver independently of the code: final size and flow control
//! checks, the read priorities, the local limits, the STOP request table and
//! the released progress. A scripted termination policy takes only legal
//! decisions, so that any panic is a defect of the receiver.

use bytes::{BufMut, Bytes, BytesMut};
use proptest::prelude::*;
use sakuya_stream::connection::{CloseReason, ConnectionClosedError, ImmediateClose};
use sakuya_stream::connection_receive_flow::{ConnectionReceiveFlowController, RecordUsageError};
use sakuya_stream::receive::flow_control::{
    AdvertisementIntent, ReceiveFlowControlPolicy, ReceiveFlowEvent, ReceiveFlowView,
};
use sakuya_stream::receive::read::{ReadError, ReadOutcome, RemoteReset};
use sakuya_stream::receive::stop::{StopError, StopNotNeededReason};
use sakuya_stream::receive::termination::{
    BoundaryAction, BoundaryUpdate, ReceiveTerminationPolicy, ResetPresentation,
    TerminationDecision, TerminationEvent, TerminationView,
};
use sakuya_stream::receive::violation::{
    FinalSizeBelowReceivedError, OnResetStreamAtError, OnResetStreamError, OnStreamFrameError,
    StreamLimitExceededError,
};
use sakuya_stream::receive::{
    BoundaryMode, ResetStreamAtFrame, ResetStreamFrame, StreamFrame, StreamReceiver,
};
use sakuya_stream::receive_buffer::fragmented::FragmentedStreamReceiveBuffer;
use sakuya_stream::receive_buffer::{StreamDataInput, StreamReceiveBuffer};
use sakuya_stream::stream_end::{BeyondFinalSizeError, FinalSizeChangeError, ResetCodeChangeError};
use sakuya_wire::reset_stream_at::ReliableSizeError;
use sakuya_wire::v1::application_error::ApplicationErrorCode;
use sakuya_wire::v1::transport_error::TransportErrorCode;
use sakuya_wire::var_int::VarInt;

const STREAMS: usize = 2;

fn v(value: u64) -> VarInt {
    VarInt::new(value).unwrap()
}

fn code(value: u32) -> ApplicationErrorCode {
    ApplicationErrorCode::new(VarInt::from_u32(value))
}

fn byte_at(stream: usize, offset: u64) -> u8 {
    u8::try_from((offset * 3 + stream as u64 * 17 + 5) % 251).unwrap()
}

fn content(stream: usize, offset: u64, len: u64) -> Bytes {
    (offset..offset + len)
        .map(|at| byte_at(stream, at))
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OnReset {
    Nothing,
    Destroy,
    Restrict {
        acceptance: Option<u64>,
        delivery: Option<u64>,
    },
}

/// A termination policy that only takes legal decisions. Both the policy and
/// the model ask [`Script::decide`], from their own view of the state.
#[derive(Clone, Copy, Debug)]
struct Script {
    on_stop_sent: Option<(Option<u64>, Option<u64>)>,
    on_reset: OnReset,
    suppress_on_complete: bool,
    abandon: u32,
}

/// The facts [`Script::decide`] reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Facts {
    final_size: Option<u64>,
    delivered: u64,
    reliable: Option<u64>,
    acceptance: Option<u64>,
    delivery: Option<u64>,
    destroyed: bool,
    committed: bool,
    stop_sent: bool,
    reader_dropped: bool,
    failed: bool,
    stop_allowed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Keep,
    Destroy {
        reason: u32,
    },
    Restrict {
        acceptance: Option<u64>,
        delivery: Option<u64>,
        reason: u32,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Choice {
    action: Action,
    stop: Option<u32>,
    presentation: Option<ResetPresentation>,
}

impl Script {
    fn decide(&self, event: TerminationEvent, facts: &Facts) -> Choice {
        let mut choice = Choice {
            action: Action::Keep,
            stop: None,
            presentation: None,
        };
        match event {
            TerminationEvent::ReaderDropped if facts.stop_allowed => {
                choice.stop = Some(self.abandon);
            }
            TerminationEvent::DataComplete if self.suppress_on_complete => {
                choice.presentation = Some(ResetPresentation::Suppress);
            }
            TerminationEvent::StopSent => {
                if let Some((acceptance, delivery)) = self.on_stop_sent {
                    choice.action = restrict(acceptance, delivery, 1, facts);
                }
            }
            TerminationEvent::RemoteReset | TerminationEvent::ReliablePrefixLowered => {
                match self.on_reset {
                    OnReset::Nothing => {}
                    OnReset::Destroy => {
                        let cancelled = facts.stop_sent || facts.reader_dropped;
                        let reliable = facts.reliable.unwrap_or(0);
                        if !facts.destroyed
                            && !facts.failed
                            && (cancelled || facts.delivered >= reliable || facts.committed)
                        {
                            choice.action = Action::Destroy { reason: 3 };
                        }
                    }
                    OnReset::Restrict {
                        acceptance,
                        delivery,
                    } => {
                        choice.action = restrict(acceptance, delivery, 2, facts);
                    }
                }
            }
            _ => {}
        }
        choice
    }
}

fn restrict(acceptance: Option<u64>, delivery: Option<u64>, reason: u32, facts: &Facts) -> Action {
    if facts.destroyed || facts.committed || facts.failed {
        return Action::Keep;
    }
    let cancelled = facts.stop_sent || facts.reader_dropped;
    let floor = match facts.reliable {
        Some(reliable) if !cancelled => reliable,
        _ => 0,
    };
    let legal = |wanted: Option<u64>, current: Option<u64>| {
        wanted.map(|wanted| {
            let limit = wanted.max(floor);
            let limit = facts.final_size.map_or(limit, |size| limit.min(size));
            current.map_or(limit, |current| limit.min(current))
        })
    };
    Action::Restrict {
        acceptance: legal(acceptance, facts.acceptance),
        delivery: legal(delivery, facts.delivery),
        reason,
    }
}

/// The components: buffer, a fixed advertisement intent, and the script.
struct Parts {
    buffer: FragmentedStreamReceiveBuffer,
    intent: AdvertisementIntent,
    script: Script,
}

impl StreamReceiveBuffer for Parts {
    type Chunk = Bytes;

    fn receive_data(&mut self, input: StreamDataInput) {
        self.buffer.receive_data(input);
    }

    fn receive_final_size(&mut self, final_size: VarInt) {
        self.buffer.receive_final_size(final_size);
    }

    fn accounted_end(&self) -> VarInt {
        self.buffer.accounted_end()
    }

    fn final_size(&self) -> Option<VarInt> {
        self.buffer.final_size()
    }

    fn delivered_end(&self) -> VarInt {
        self.buffer.delivered_end()
    }

    fn read_chunk(&mut self, limit: VarInt) -> Option<Bytes> {
        self.buffer.read_chunk(limit)
    }

    fn read_into<T: BufMut + ?Sized>(&mut self, limit: VarInt, target: &mut T) -> usize {
        self.buffer.read_into(limit, target)
    }

    fn release_from(&mut self, end: VarInt) {
        self.buffer.release_from(end);
    }

    fn destroy(&mut self) {
        self.buffer.destroy();
    }
}

impl ReceiveFlowControlPolicy for Parts {
    fn on_receive_flow_event(&mut self, _: ReceiveFlowEvent, _: &ReceiveFlowView) {}

    fn advertisement_intent(&self) -> AdvertisementIntent {
        self.intent
    }
}

fn fixed(mode: BoundaryMode) -> Option<u64> {
    match mode {
        BoundaryMode::Following => None,
        BoundaryMode::Fixed(limit) => Some(limit.get()),
    }
}

impl ReceiveTerminationPolicy for Parts {
    type Reason = u32;

    fn on_termination_event(
        &mut self,
        event: TerminationEvent,
        view: &TerminationView,
    ) -> TerminationDecision<u32> {
        let facts = Facts {
            final_size: view.final_size.map(VarInt::get),
            delivered: view.delivered_end.get(),
            reliable: view.reset.map(|reset| reset.reliable_size.get()),
            acceptance: fixed(view.acceptance),
            delivery: fixed(view.delivery),
            destroyed: view.destroyed,
            committed: view.read_result_committed,
            stop_sent: view.stop_sent,
            reader_dropped: view.reader_dropped,
            failed: view.connection_closed,
            stop_allowed: view.stop_allowed,
        };
        let choice = self.script.decide(event, &facts);
        let update =
            |limit: Option<u64>| limit.map_or(BoundaryUpdate::Keep, |l| BoundaryUpdate::Fix(v(l)));
        let action = match choice.action {
            Action::Keep => BoundaryAction::Keep,
            Action::Destroy { reason } => BoundaryAction::Destroy { reason },
            Action::Restrict {
                acceptance,
                delivery,
                reason,
            } => BoundaryAction::Restrict {
                acceptance: update(acceptance),
                delivery: update(delivery),
                reason,
            },
        };
        TerminationDecision {
            action,
            stop: choice.stop.map(code),
            reset_presentation: choice.presentation,
        }
    }
}

#[derive(Clone, Debug)]
enum Op {
    Honest {
        stream: usize,
        at: prop::sample::Index,
        len: u64,
    },
    Wild {
        stream: usize,
        offset: u64,
        len: u64,
        fin: bool,
    },
    Reset {
        stream: usize,
        code: u32,
        final_size: Option<u64>,
    },
    ResetAt {
        stream: usize,
        code: u32,
        final_size: Option<u64>,
        reliable: u64,
    },
    ReadChunk {
        stream: usize,
    },
    ReadInto {
        stream: usize,
        room: usize,
    },
    Stop {
        stream: usize,
        code: u32,
    },
    StopSent {
        stream: usize,
    },
    ReaderDropped {
        stream: usize,
    },
    ConnectionClosed {
        stream: usize,
    },
    OpenLimit {
        stream: usize,
        limit: u64,
    },
    RaiseConnection {
        limit: u64,
    },
    ReportRelease {
        stream: usize,
    },
    Blocked {
        stream: usize,
    },
}

fn op() -> impl Strategy<Value = Op> {
    let stream = 0..STREAMS;
    prop_oneof![
        12 => (stream.clone(), any::<prop::sample::Index>(), 0u64..48)
            .prop_map(|(stream, at, len)| Op::Honest { stream, at, len }),
        1 => (stream.clone(), 0u64..260, 0u64..48, any::<bool>())
            .prop_map(|(stream, offset, len, fin)| Op::Wild { stream, offset, len, fin }),
        1 => (stream.clone(), 1u32..3, prop::option::weighted(0.1, 0u64..260))
            .prop_map(|(stream, code, final_size)| Op::Reset { stream, code, final_size }),
        2 => (stream.clone(), 1u32..3, prop::option::weighted(0.1, 0u64..260), 0u64..240).prop_map(
            |(stream, code, final_size, reliable)| Op::ResetAt { stream, code, final_size, reliable }
        ),
        6 => stream.clone().prop_map(|stream| Op::ReadChunk { stream }),
        6 => (stream.clone(), 0usize..40).prop_map(|(stream, room)| Op::ReadInto { stream, room }),
        2 => (stream.clone(), 1u32..3).prop_map(|(stream, code)| Op::Stop { stream, code }),
        2 => stream.clone().prop_map(|stream| Op::StopSent { stream }),
        1 => stream.clone().prop_map(|stream| Op::ReaderDropped { stream }),
        1 => stream.clone().prop_map(|stream| Op::ConnectionClosed { stream }),
        1 => (stream.clone(), 0u64..400).prop_map(|(stream, limit)| Op::OpenLimit { stream, limit }),
        1 => (0u64..800).prop_map(|limit| Op::RaiseConnection { limit }),
        2 => stream.clone().prop_map(|stream| Op::ReportRelease { stream }),
        1 => stream.prop_map(|stream| Op::Blocked { stream }),
    ]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stop {
    None,
    Pending(u32),
    Sent(u32),
}

impl Stop {
    fn code(self) -> Option<u32> {
        match self {
            Self::None => None,
            Self::Pending(code) | Self::Sent(code) => Some(code),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Phase {
    Live,
    Destroyed(Option<(u32, TerminationEvent)>),
}

/// How far the connection's end has reached the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Link {
    Open,
    /// A frame violated the protocol; the connection has not closed yet.
    Violated,
    Closed,
}

/// A violation as the model finds it, before it takes the shape of the
/// error of one frame method.
#[derive(Clone, Copy, Debug)]
enum Violation {
    FinalSizeChanged(FinalSizeChangeError),
    BeyondFinalSize(BeyondFinalSizeError),
    FinalSizeBelowReceived(FinalSizeBelowReceivedError),
    StreamLimitExceeded(StreamLimitExceededError),
    ConnectionLimitExceeded(RecordUsageError),
    ResetCodeChanged(ResetCodeChangeError),
    ReliableSizeExceedsFinalSize(ReliableSizeError),
}

impl Violation {
    fn on_stream_frame(self) -> OnStreamFrameError {
        match self {
            Self::FinalSizeChanged(source) => OnStreamFrameError::FinalSizeChanged { source },
            Self::BeyondFinalSize(source) => OnStreamFrameError::BeyondFinalSize { source },
            Self::FinalSizeBelowReceived(source) => {
                OnStreamFrameError::FinalSizeBelowReceived { source }
            }
            Self::StreamLimitExceeded(source) => OnStreamFrameError::StreamLimitExceeded { source },
            Self::ConnectionLimitExceeded(source) => {
                OnStreamFrameError::ConnectionLimitExceeded { source }
            }
            Self::ResetCodeChanged(_) | Self::ReliableSizeExceedsFinalSize(_) => {
                panic!("a STREAM frame cannot commit {self:?}")
            }
        }
    }

    fn on_reset_stream(self) -> OnResetStreamError {
        match self {
            Self::FinalSizeChanged(source) => OnResetStreamError::FinalSizeChanged { source },
            Self::FinalSizeBelowReceived(source) => {
                OnResetStreamError::FinalSizeBelowReceived { source }
            }
            Self::ResetCodeChanged(source) => OnResetStreamError::ResetCodeChanged { source },
            Self::StreamLimitExceeded(source) => OnResetStreamError::StreamLimitExceeded { source },
            Self::ConnectionLimitExceeded(source) => {
                OnResetStreamError::ConnectionLimitExceeded { source }
            }
            Self::BeyondFinalSize(_) | Self::ReliableSizeExceedsFinalSize(_) => {
                panic!("a RESET_STREAM frame cannot commit {self:?}")
            }
        }
    }

    fn on_reset_stream_at(self) -> OnResetStreamAtError {
        match self {
            Self::ReliableSizeExceedsFinalSize(source) => {
                OnResetStreamAtError::ReliableSizeExceedsFinalSize { source }
            }
            Self::BeyondFinalSize(_) => panic!("a RESET_STREAM_AT frame cannot commit {self:?}"),
            other => other.on_reset_stream().into(),
        }
    }
}

/// A read result that does not need the data.
#[derive(Clone, Copy, Debug)]
enum Settled {
    End,
    Wait,
}

impl Settled {
    fn outcome<T>(self) -> ReadOutcome<T> {
        match self {
            Self::End => ReadOutcome::End,
            Self::Wait => ReadOutcome::Wait,
        }
    }
}

/// A read error as the model predicts it, with the local reason unshared.
#[derive(Clone, Debug, PartialEq)]
enum Expected {
    ReaderDropped,
    ConnectionClosed(ConnectionClosedError),
    Reset {
        reset: RemoteReset,
        complete: bool,
    },
    Local {
        cause: LocalCause,
        reason: u32,
        trigger: TerminationEvent,
        remote: Option<RemoteReset>,
    },
}

/// Which local termination a read error reports.
#[derive(Clone, Copy, Debug, PartialEq)]
enum LocalCause {
    BufferDestroyed,
    DeliveryLimitReached,
    AcceptanceLimitReached,
}

/// The model's view of a read error of the stream receiver.
fn observed(error: ReadError<u32>) -> Expected {
    match error {
        ReadError::ReaderDropped => Expected::ReaderDropped,
        ReadError::ConnectionClosed { source } => Expected::ConnectionClosed(source),
        ReadError::Reset { reset, complete } => Expected::Reset { reset, complete },
        ReadError::BufferDestroyed {
            reason,
            trigger,
            remote,
        } => Expected::Local {
            cause: LocalCause::BufferDestroyed,
            reason: *reason,
            trigger,
            remote,
        },
        ReadError::DeliveryLimitReached {
            reason,
            trigger,
            remote,
        } => Expected::Local {
            cause: LocalCause::DeliveryLimitReached,
            reason: *reason,
            trigger,
            remote,
        },
        ReadError::AcceptanceLimitReached {
            reason,
            trigger,
            remote,
        } => Expected::Local {
            cause: LocalCause::AcceptanceLimitReached,
            reason: *reason,
            trigger,
            remote,
        },
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Reading {
    Open,
    End,
    Error(Expected),
    Dropped { committed: bool },
}

#[derive(Clone, Copy, Debug)]
struct Limit {
    at: u64,
    reason: u32,
    trigger: TerminationEvent,
}

#[derive(Clone, Copy, Debug)]
struct Reset {
    code: u32,
    final_size: u64,
    reliable: u64,
}

impl Reset {
    fn remote(self) -> RemoteReset {
        RemoteReset {
            code: code(self.code),
            final_size: v(self.final_size),
            reliable_size: v(self.reliable),
        }
    }
}

struct Model {
    total: u64,
    script: Script,
    held: Vec<bool>,
    /// Offsets some accepted STREAM frame covered, whatever became of the
    /// payload.
    arrived: Vec<bool>,
    delivered: u64,
    accounted: u64,
    final_size: Option<u64>,
    reset: Option<Reset>,
    stop: Stop,
    acceptance: Option<Limit>,
    delivery: Option<Limit>,
    presentation: ResetPresentation,
    phase: Phase,
    link: Link,
    reading: Reading,
    data_complete_notified: bool,
    opened_limit: u64,
    released: u64,
}

impl Model {
    fn new(total: u64, script: Script, opened_limit: u64) -> Self {
        Self {
            total,
            script,
            held: vec![false; 600],
            arrived: vec![false; 600],
            delivered: 0,
            accounted: 0,
            final_size: None,
            reset: None,
            stop: Stop::None,
            acceptance: None,
            delivery: None,
            presentation: ResetPresentation::Report,
            phase: Phase::Live,
            link: Link::Open,
            reading: Reading::Open,
            data_complete_notified: false,
            opened_limit,
            released: 0,
        }
    }

    fn closed(&self) -> bool {
        self.link == Link::Closed
    }

    fn takes_frames(&self) -> bool {
        self.link == Link::Open
    }

    fn destroyed(&self) -> bool {
        self.phase != Phase::Live
    }

    fn committed(&self) -> bool {
        match self.reading {
            Reading::Open => false,
            Reading::End | Reading::Error(_) => true,
            Reading::Dropped { committed } => committed,
        }
    }

    fn reader_dropped(&self) -> bool {
        matches!(self.reading, Reading::Dropped { .. })
    }

    fn is_received(&self, start: u64, end: u64) -> bool {
        (start..end).all(|at| self.arrived[at as usize])
    }

    fn fully_received(&self) -> bool {
        self.final_size
            .is_some_and(|size| self.is_received(0, size))
    }

    fn stop_not_needed(&self) -> Option<StopNotNeededReason> {
        if self.fully_received() {
            return Some(StopNotNeededReason::DataComplete);
        }
        let reset = self.reset?;
        self.is_received(0, reset.reliable)
            .then_some(StopNotNeededReason::PeerReset)
    }

    fn facts(&self) -> Facts {
        Facts {
            final_size: self.final_size,
            delivered: self.delivered,
            reliable: self.reset.map(|reset| reset.reliable),
            acceptance: self.acceptance.map(|limit| limit.at),
            delivery: self.delivery.map(|limit| limit.at),
            destroyed: self.destroyed(),
            committed: self.committed(),
            stop_sent: matches!(self.stop, Stop::Sent(_)),
            reader_dropped: self.reader_dropped(),
            failed: self.closed(),
            stop_allowed: self.stop.code().is_none()
                && !self.closed()
                && self.stop_not_needed().is_none(),
        }
    }

    fn clear_held(&mut self) {
        self.held.fill(false);
    }

    fn destroy(&mut self, cause: Option<(u32, TerminationEvent)>) {
        if !self.destroyed() {
            self.clear_held();
            self.phase = Phase::Destroyed(cause);
        }
    }

    fn event(&mut self, event: TerminationEvent) {
        let choice = self.script.decide(event, &self.facts());
        if let Some(presentation) = choice.presentation
            && !self.committed()
        {
            self.presentation = presentation;
        }
        match choice.action {
            Action::Keep => {}
            Action::Destroy { reason } => self.destroy(Some((reason, event))),
            Action::Restrict {
                acceptance,
                delivery,
                reason,
            } => {
                let apply = |current: &mut Option<Limit>, wanted: Option<u64>| {
                    let Some(at) = wanted else { return false };
                    if current.is_none_or(|limit| at < limit.at) {
                        *current = Some(Limit {
                            at,
                            reason,
                            trigger: event,
                        });
                        return true;
                    }
                    false
                };
                apply(&mut self.acceptance, acceptance);
                if apply(&mut self.delivery, delivery) {
                    let from = self.delivery.unwrap().at.max(self.delivered) as usize;
                    self.held[from..].fill(false);
                }
            }
        }
        if let Some(stop) = choice.stop {
            assert!(self.stop.code().is_none_or(|installed| installed == stop));
            if self.stop == Stop::None {
                self.stop = Stop::Pending(stop);
            }
        }
    }

    fn progress(&self) -> u64 {
        if self.destroyed() || self.committed() {
            return self.accounted;
        }
        let limit = self.delivery.map_or(u64::MAX, |limit| limit.at);
        let retained = limit.min(self.accounted).saturating_sub(self.delivered);
        self.accounted - retained
    }

    fn report(&mut self, connection: &mut ModelConnection) {
        if self.closed() {
            return;
        }
        let progress = self.progress();
        if progress > self.released {
            connection.released += progress - self.released;
            self.released = progress;
        }
    }

    fn after_input(&mut self, event: Option<TerminationEvent>, connection: &mut ModelConnection) {
        if let Some(event) = event {
            self.event(event);
        }
        if !self.data_complete_notified && self.fully_received() {
            self.data_complete_notified = true;
            self.event(TerminationEvent::DataComplete);
        }
        self.report(connection);
    }

    fn close(&mut self) {
        self.link = Link::Closed;
        self.destroy(None);
        self.event(TerminationEvent::ConnectionClosed);
    }

    /// Checks the stream limit and the connection limit for an accounted end
    /// of `accounted`; changes nothing.
    fn check_account(&self, accounted: u64, connection: &ModelConnection) -> Result<(), Violation> {
        StreamLimitExceededError::check(v(accounted), v(self.opened_limit))
            .map_err(Violation::StreamLimitExceeded)?;
        let increase = accounted.max(self.accounted) - self.accounted;
        if connection.used + increase > connection.limit {
            return Err(Violation::ConnectionLimitExceeded(RecordUsageError {
                used: v(connection.used),
                increase: v(increase),
                limit: v(connection.limit),
            }));
        }
        Ok(())
    }

    fn on_frame(
        &mut self,
        offset: u64,
        len: u64,
        fin: bool,
        connection: &mut ModelConnection,
    ) -> Result<(), Violation> {
        if !self.takes_frames() {
            return Ok(());
        }
        let end = offset + len;
        let checked = match self.final_size {
            Some(final_size) if fin && end != final_size => Err(Violation::FinalSizeChanged(
                FinalSizeChangeError::check(v(final_size), v(end)).unwrap_err(),
            )),
            Some(final_size) if end > final_size => Err(Violation::BeyondFinalSize(
                BeyondFinalSizeError::check(v(final_size), v(end)).unwrap_err(),
            )),
            None if fin && end < self.accounted => Err(Violation::FinalSizeBelowReceived(
                FinalSizeBelowReceivedError::check(v(end), v(self.accounted)).unwrap_err(),
            )),
            _ => Ok(()),
        }
        .and_then(|()| self.check_account(self.accounted.max(end), connection));
        if let Err(violation) = checked {
            // The violating frame leaves nothing behind.
            self.link = Link::Violated;
            return Err(violation);
        }
        for at in offset..end {
            self.arrived[at as usize] = true;
        }
        if !self.destroyed() {
            let limit = [self.acceptance, self.delivery]
                .iter()
                .flatten()
                .map(|limit| limit.at)
                .min()
                .unwrap_or(u64::MAX);
            let kept_end = end.min(limit);
            for at in offset.max(self.delivered)..kept_end {
                self.held[at as usize] = true;
            }
        }
        connection.used += end.max(self.accounted) - self.accounted;
        self.accounted = self.accounted.max(end);
        if fin && self.final_size.is_none() {
            self.final_size = Some(end);
        }
        self.after_input(None, connection);
        Ok(())
    }

    fn on_reset(
        &mut self,
        code_value: u32,
        final_size: u64,
        reliable: u64,
        connection: &mut ModelConnection,
    ) -> Result<(), Violation> {
        if !self.takes_frames() {
            return Ok(());
        }
        let checked = if reliable > final_size {
            Err(Violation::ReliableSizeExceedsFinalSize(
                ReliableSizeError::check(v(final_size), v(reliable)).unwrap_err(),
            ))
        } else {
            match self.final_size {
                Some(known) if final_size != known => Err(Violation::FinalSizeChanged(
                    FinalSizeChangeError::check(v(known), v(final_size)).unwrap_err(),
                )),
                None if final_size < self.accounted => Err(Violation::FinalSizeBelowReceived(
                    FinalSizeBelowReceivedError::check(v(final_size), v(self.accounted))
                        .unwrap_err(),
                )),
                _ => match self.reset {
                    Some(facts) if facts.code != code_value => Err(Violation::ResetCodeChanged(
                        ResetCodeChangeError::check(code(facts.code), code(code_value))
                            .unwrap_err(),
                    )),
                    _ => Ok(()),
                },
            }
            .and_then(|()| self.check_account(self.accounted.max(final_size), connection))
        };
        if let Err(violation) = checked {
            // The violating frame leaves nothing behind.
            self.link = Link::Violated;
            return Err(violation);
        }
        connection.used += final_size.max(self.accounted) - self.accounted;
        self.accounted = self.accounted.max(final_size);
        self.final_size.get_or_insert(final_size);
        let event = match &mut self.reset {
            None => {
                self.reset = Some(Reset {
                    code: code_value,
                    final_size,
                    reliable,
                });
                Some(TerminationEvent::RemoteReset)
            }
            Some(facts) if reliable < facts.reliable => {
                facts.reliable = reliable;
                Some(TerminationEvent::ReliablePrefixLowered)
            }
            Some(_) => None,
        };
        self.after_input(event, connection);
        Ok(())
    }

    fn commit_error(&mut self, error: Expected) -> Expected {
        self.reading = Reading::Error(error.clone());
        self.destroy(None);
        self.event(TerminationEvent::ReadResultCommitted);
        error
    }

    /// The first read priorities, those that need no look at the data.
    fn settled(&mut self) -> Option<Result<Settled, Expected>> {
        if self.reader_dropped() {
            return Some(Err(Expected::ReaderDropped));
        }
        if self.closed() {
            return Some(Err(Expected::ConnectionClosed(ConnectionClosedError::new(
                close_reason(),
            ))));
        }
        match &self.reading {
            Reading::End => return Some(Ok(Settled::End)),
            Reading::Error(error) => return Some(Err(error.clone())),
            Reading::Open | Reading::Dropped { .. } => {}
        }
        if self.link == Link::Violated {
            return Some(Ok(Settled::Wait));
        }
        if let Phase::Destroyed(Some((reason, trigger))) = self.phase {
            let error = Expected::Local {
                cause: LocalCause::BufferDestroyed,
                reason,
                trigger,
                remote: self.reset.map(Reset::remote),
            };
            return Some(Err(self.commit_error(error)));
        }
        None
    }

    fn deliverable(&self) -> u64 {
        let limit = self.delivery.map_or(u64::MAX, |limit| limit.at);
        (self.delivered..limit.min(self.held.len() as u64))
            .take_while(|&at| self.held[at as usize])
            .count() as u64
    }

    fn end_or_wait(&mut self) -> Result<ReadOutcome<()>, Expected> {
        let remote = self.reset.map(Reset::remote);
        if self.final_size == Some(self.delivered) {
            return match remote {
                Some(reset) if self.presentation == ResetPresentation::Report => Err(self
                    .commit_error(Expected::Reset {
                        reset,
                        complete: true,
                    })),
                _ => {
                    self.reading = Reading::End;
                    self.event(TerminationEvent::ReadResultCommitted);
                    Ok(ReadOutcome::End)
                }
            };
        }
        let local = |cause: LocalCause, limit: Limit| Expected::Local {
            cause,
            reason: limit.reason,
            trigger: limit.trigger,
            remote,
        };
        if let Some(limit) = self.delivery.filter(|limit| self.delivered >= limit.at) {
            return Err(self.commit_error(local(LocalCause::DeliveryLimitReached, limit)));
        }
        if let Some(reset) = remote.filter(|reset| self.delivered >= reset.reliable_size.get()) {
            return Err(self.commit_error(Expected::Reset {
                reset,
                complete: false,
            }));
        }
        if let Some(limit) = self.acceptance.filter(|limit| self.delivered >= limit.at) {
            return Err(self.commit_error(local(LocalCause::AcceptanceLimitReached, limit)));
        }
        Ok(ReadOutcome::Wait)
    }

    fn take_delivered(&mut self, len: u64) {
        for at in self.delivered..self.delivered + len {
            self.held[at as usize] = false;
        }
        self.delivered += len;
    }
}

#[derive(Debug, Default)]
struct ModelConnection {
    limit: u64,
    used: u64,
    released: u64,
}

fn read_chunk(
    stream: usize,
    model: &mut Model,
    receiver: &mut StreamReceiver<Parts>,
) -> Result<ReadOutcome<Bytes>, ReadError<u32>> {
    let actual = receiver.read_chunk();
    let expected = match model.settled() {
        Some(settled) => settled.map(Settled::outcome),
        None => {
            let run = model.deliverable();
            if run > 0 {
                let Ok(ReadOutcome::Data(chunk)) = &actual else {
                    panic!("expected data of up to {run} bytes, got {actual:?}");
                };
                assert!(!chunk.is_empty(), "a data item is never empty");
                assert!(chunk.len() as u64 <= run);
                assert_eq!(*chunk, content(stream, model.delivered, chunk.len() as u64));
                model.take_delivered(chunk.len() as u64);
                return actual;
            }
            model.end_or_wait().map(|outcome| match outcome {
                ReadOutcome::End => ReadOutcome::End,
                ReadOutcome::Wait => ReadOutcome::Wait,
                ReadOutcome::Data(()) | ReadOutcome::NoProgress => unreachable!(),
            })
        }
    };
    assert_eq!(actual.clone().map_err(observed), expected);
    actual
}

fn read_into(
    stream: usize,
    room: usize,
    model: &mut Model,
    receiver: &mut StreamReceiver<Parts>,
) -> Result<ReadOutcome<usize>, ReadError<u32>> {
    let mut target = BytesMut::with_capacity(room).limit(room);
    let actual = receiver
        .read_into(&mut target)
        .map(|outcome| match outcome {
            ReadOutcome::Data(copied) => ReadOutcome::Data(copied.get()),
            ReadOutcome::NoProgress => ReadOutcome::NoProgress,
            ReadOutcome::End => ReadOutcome::End,
            ReadOutcome::Wait => ReadOutcome::Wait,
        });
    let bytes = target.into_inner().freeze();
    let expected = match model.settled() {
        Some(settled) => settled.map(Settled::outcome),
        None if room == 0 => Ok(ReadOutcome::NoProgress),
        None => {
            let run = model.deliverable();
            if run > 0 {
                let copied = run.min(room as u64);
                assert_eq!(bytes, content(stream, model.delivered, copied));
                model.take_delivered(copied);
                Ok(ReadOutcome::Data(copied as usize))
            } else {
                model.end_or_wait().map(|outcome| match outcome {
                    ReadOutcome::End => ReadOutcome::End,
                    ReadOutcome::Wait => ReadOutcome::Wait,
                    ReadOutcome::Data(()) | ReadOutcome::NoProgress => unreachable!(),
                })
            }
        }
    };
    assert_eq!(actual.clone().map_err(observed), expected);
    if !matches!(expected, Ok(ReadOutcome::Data(_))) {
        assert!(bytes.is_empty(), "nothing is copied without a data result");
    }
    actual
}

fn step(
    op: &Op,
    models: &mut [Model; STREAMS],
    receivers: &mut [StreamReceiver<Parts>; STREAMS],
    connection: &mut ConnectionReceiveFlowController,
    ledger: &mut ModelConnection,
) {
    match *op {
        Op::Honest { stream, at, len } => {
            let total = models[stream].total;
            let offset = at.index(total as usize + 1) as u64;
            let len = len.min(total - offset);
            let fin = offset + len == total;
            let frame = StreamFrame {
                offset: v(offset),
                data: content(stream, offset, len),
                fin,
            };
            let actual = receivers[stream].on_stream_frame(frame, connection);
            let expected = models[stream].on_frame(offset, len, fin, ledger);
            assert_eq!(actual, expected.map_err(Violation::on_stream_frame));
        }
        Op::Wild {
            stream,
            offset,
            len,
            fin,
        } => {
            let frame = StreamFrame {
                offset: v(offset),
                data: content(stream, offset, len),
                fin,
            };
            let actual = receivers[stream].on_stream_frame(frame, connection);
            let expected = models[stream].on_frame(offset, len, fin, ledger);
            assert_eq!(actual, expected.map_err(Violation::on_stream_frame));
        }
        Op::Reset {
            stream,
            code: value,
            final_size,
        } => {
            let size = final_size.unwrap_or(models[stream].total);
            let frame = ResetStreamFrame {
                code: code(value),
                final_size: v(size),
            };
            let actual = receivers[stream].on_reset_stream(frame, connection);
            let expected = models[stream].on_reset(value, size, 0, ledger);
            assert_eq!(actual, expected.map_err(Violation::on_reset_stream));
        }
        Op::ResetAt {
            stream,
            code: value,
            final_size,
            reliable,
        } => {
            let size = final_size.unwrap_or(models[stream].total);
            let reliable = if final_size.is_none() {
                reliable.min(size)
            } else {
                reliable
            };
            let frame = ResetStreamAtFrame {
                code: code(value),
                final_size: v(size),
                reliable_size: v(reliable),
            };
            let actual = receivers[stream].on_reset_stream_at(frame, connection);
            let expected = models[stream].on_reset(value, size, reliable, ledger);
            assert_eq!(actual, expected.map_err(Violation::on_reset_stream_at));
        }
        Op::ReadChunk { stream } => {
            drop(read_chunk(
                stream,
                &mut models[stream],
                &mut receivers[stream],
            ));
        }
        Op::ReadInto { stream, room } => {
            drop(read_into(
                stream,
                room,
                &mut models[stream],
                &mut receivers[stream],
            ));
        }
        Op::Stop {
            stream,
            code: value,
        } => {
            let actual = receivers[stream].stop(code(value));
            let model = &mut models[stream];
            let expected = if model.closed() {
                Err(StopError::ConnectionClosed {
                    source: ConnectionClosedError::new(close_reason()),
                })
            } else if let Some(installed) = model.stop.code() {
                if installed == value {
                    Ok(())
                } else {
                    Err(StopError::StopConflict {
                        installed: code(installed),
                        requested: code(value),
                    })
                }
            } else if let Some(reason) = model.stop_not_needed() {
                Err(StopError::StopNotNeeded { reason })
            } else {
                model.stop = Stop::Pending(value);
                model.event(TerminationEvent::StopRequested);
                Ok(())
            };
            assert_eq!(actual, expected);
        }
        Op::StopSent { stream } => {
            let actual = receivers[stream].on_stop_sent();
            let model = &mut models[stream];
            match model.stop {
                Stop::None => assert!(actual.is_err()),
                Stop::Sent(_) => assert!(actual.is_ok()),
                Stop::Pending(value) => {
                    assert!(actual.is_ok());
                    model.stop = Stop::Sent(value);
                    model.event(TerminationEvent::StopSent);
                }
            }
        }
        Op::ReaderDropped { stream } => {
            receivers[stream].reader_dropped();
            let model = &mut models[stream];
            if !model.reader_dropped() {
                model.reading = Reading::Dropped {
                    committed: model.committed(),
                };
                model.destroy(None);
                model.event(TerminationEvent::ReaderDropped);
            }
        }
        Op::ConnectionClosed { stream } => {
            receivers[stream].connection_closed(close_reason());
            let model = &mut models[stream];
            if !model.closed() {
                model.close();
            }
        }
        Op::OpenLimit { stream, limit } => {
            receivers[stream].open_limit(v(limit));
            let model = &mut models[stream];
            model.opened_limit = model.opened_limit.max(limit);
        }
        Op::RaiseConnection { limit } => {
            assert_eq!(connection.raise_limit(v(limit)), limit > ledger.limit);
            ledger.limit = ledger.limit.max(limit);
        }
        Op::ReportRelease { stream } => {
            receivers[stream].report_release(connection).unwrap();
            models[stream].report(ledger);
        }
        Op::Blocked { stream } => receivers[stream].on_stream_data_blocked(v(0)),
    }
}

fn check(
    models: &[Model; STREAMS],
    receivers: &[StreamReceiver<Parts>; STREAMS],
    connection: &ConnectionReceiveFlowController,
    ledger: &ModelConnection,
    target: u64,
) {
    for (model, receiver) in models.iter().zip(receivers) {
        let buffer = &receiver.parts().buffer;
        assert_eq!(
            buffer.accounted_end().get(),
            model.accounted,
            "accounted end"
        );
        assert_eq!(
            buffer.final_size().map(VarInt::get),
            model.final_size,
            "final size"
        );
        assert_eq!(
            buffer.delivered_end().get(),
            model.delivered,
            "delivered end"
        );
        assert_eq!(
            buffer.held_len(),
            model.held.iter().filter(|held| **held).count(),
            "held bytes"
        );
        assert_eq!(buffer.is_destroyed(), model.destroyed(), "destroyed");
        assert_eq!(
            receiver.closed().cloned(),
            model
                .closed()
                .then(|| ConnectionClosedError::new(close_reason())),
            "closure"
        );
        assert_eq!(
            receiver.remote_reset(),
            model.reset.map(Reset::remote),
            "reset facts"
        );
        assert_eq!(
            fixed(receiver.acceptance_limit()),
            model.acceptance.map(|l| l.at)
        );
        assert_eq!(
            fixed(receiver.delivery_limit()),
            model.delivery.map(|l| l.at)
        );
        assert_eq!(receiver.opened_limit().get(), model.opened_limit);
        let pending = match model.stop {
            Stop::Pending(value) if !model.closed() && model.stop_not_needed().is_none() => {
                Some(code(value))
            }
            _ => None,
        };
        assert_eq!(receiver.pending_stop(), pending, "pending STOP");
        let advertised =
            (!model.closed() && model.final_size.is_none() && target > model.opened_limit)
                .then(|| v(target));
        assert_eq!(receiver.advertisement(), advertised, "advertisement");
        // RFC 9000 §4.5: everything delivered lies within the final size, also
        // after a violation, which leaves no trace.
        if let Some(final_size) = model.final_size {
            assert!(model.delivered <= final_size);
            assert!(model.accounted <= final_size);
        }
    }
    assert_eq!(connection.limit().get(), ledger.limit, "connection limit");
    assert_eq!(connection.used().get(), ledger.used, "connection usage");
    assert_eq!(connection.released().get(), ledger.released, "released");
    assert!(ledger.released <= ledger.used);
    let accounted: u64 = models.iter().map(|m| m.accounted).sum();
    assert!(
        ledger.used <= accounted,
        "usage counts every stream's accounted end once"
    );
}

/// After the sequence the peer delivers the whole stream; a reader that keeps
/// reading must reach a terminal result, never wait for a gap that nothing can
/// fill, and read exactly the stream's bytes.
fn drain(
    stream: usize,
    model: &mut Model,
    receiver: &mut StreamReceiver<Parts>,
    connection: &mut ConnectionReceiveFlowController,
    ledger: &mut ModelConnection,
) {
    if model.link != Link::Open {
        return;
    }
    // The limits that belong to the peer are not what is tested here.
    receiver.open_limit(v(model.total));
    model.opened_limit = model.opened_limit.max(model.total);
    if ledger.limit < ledger.used + model.total {
        ledger.limit = ledger.used + model.total;
        connection.raise_limit(v(ledger.limit));
    }
    let total = model.final_size.unwrap_or(model.total);
    if model.accounted > total {
        return;
    }
    let frame = StreamFrame {
        offset: v(0),
        data: content(stream, 0, total),
        fin: true,
    };
    let actual = receiver.on_stream_frame(frame, connection);
    let expected = model.on_frame(0, total, true, ledger);
    assert_eq!(actual, expected.map_err(Violation::on_stream_frame));
    if actual.is_err() {
        return;
    }
    loop {
        match read_chunk(stream, model, receiver) {
            Ok(ReadOutcome::Data(_)) => {}
            Ok(ReadOutcome::Wait) => panic!("a reader waits although nothing can arrive"),
            Ok(ReadOutcome::End | ReadOutcome::NoProgress) | Err(_) => break,
        }
    }
    let first = read_chunk(stream, model, receiver);
    let second = read_chunk(stream, model, receiver);
    assert_eq!(first, second, "repeated reads return one result");
}

#[allow(clippy::too_many_arguments)]
fn run(
    ops: &[Op],
    script: Script,
    totals: [u64; STREAMS],
    limits: [u64; STREAMS],
    connection_limit: u64,
    target: u64,
) {
    let mut connection = ConnectionReceiveFlowController::new(v(connection_limit));
    let mut ledger = ModelConnection {
        limit: connection_limit,
        ..ModelConnection::default()
    };
    let make = |limit| {
        StreamReceiver::new(
            Parts {
                buffer: FragmentedStreamReceiveBuffer::new(),
                intent: AdvertisementIntent::Advertise {
                    target_limit: v(target),
                },
                script,
            },
            v(limit),
        )
    };
    let mut receivers = [make(limits[0]), make(limits[1])];
    let mut models = [
        Model::new(totals[0], script, limits[0]),
        Model::new(totals[1], script, limits[1]),
    ];
    for op in ops {
        let before: Vec<_> = models
            .iter()
            .map(|m| (m.accounted, m.delivered, m.final_size))
            .collect();
        step(
            op,
            &mut models,
            &mut receivers,
            &mut connection,
            &mut ledger,
        );
        check(&models, &receivers, &connection, &ledger, target);
        for ((accounted, delivered, final_size), model) in before.into_iter().zip(&models) {
            assert!(model.accounted >= accounted, "accounted end fell");
            assert!(model.delivered >= delivered, "delivery moved back");
            if let Some(final_size) = final_size {
                assert_eq!(model.final_size, Some(final_size), "final size changed");
            }
        }
    }
    let [first, second] = &mut models;
    let [one, two] = &mut receivers;
    drain(0, first, one, &mut connection, &mut ledger);
    drain(1, second, two, &mut connection, &mut ledger);
    check(&models, &receivers, &connection, &ledger, target);
}

fn script() -> impl Strategy<Value = Script> {
    let limit = prop::option::of(0u64..240);
    let on_reset = prop_oneof![
        3 => Just(OnReset::Nothing),
        1 => Just(OnReset::Destroy),
        2 => (limit.clone(), limit.clone())
            .prop_map(|(acceptance, delivery)| OnReset::Restrict { acceptance, delivery }),
    ];
    (
        prop::option::of((limit.clone(), limit)),
        on_reset,
        any::<bool>(),
    )
        .prop_map(|(on_stop_sent, on_reset, suppress_on_complete)| Script {
            on_stop_sent,
            on_reset,
            suppress_on_complete,
            abandon: 9,
        })
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 3000,
        max_shrink_iters: 6000,
        ..ProptestConfig::default()
    })]

    #[test]
    fn receiver_follows_the_model(
        ops in prop::collection::vec(op(), 0..70),
        script in script(),
        totals in [0u64..240, 0u64..240],
        extra in [0u64..300, 0u64..40],
        connection_extra in 0u64..500,
        target in 0u64..500,
    ) {
        let limits = [totals[0] + extra[0], totals[1] + extra[1]];
        run(
            &ops,
            script,
            totals,
            limits,
            totals[0] + totals[1] + connection_extra,
            target,
        );
    }

    /// Tight limits make flow-control violations common.
    #[test]
    fn receiver_follows_the_model_under_tight_limits(
        ops in prop::collection::vec(op(), 0..50),
        script in script(),
        totals in [0u64..240, 0u64..240],
        limits in [0u64..120, 0u64..120],
        connection_limit in 0u64..160,
    ) {
        run(&ops, script, totals, limits, connection_limit, 0);
    }
}

/// The reason the tests close connections for.
fn close_reason() -> CloseReason {
    CloseReason::Peer(ImmediateClose::Transport {
        code: TransportErrorCode::PROTOCOL_VIOLATION,
        frame_type: Some(VarInt::from(0x08u8)),
        reason_phrase: Bytes::from_static(b"bad stream"),
    })
}
