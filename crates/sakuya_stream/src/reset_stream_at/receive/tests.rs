//! The stream receiver with [`RemoteResetAt`] facts: `RESET_STREAM_AT` and
//! `RESET_STREAM` in every order, the reliable prefix in reads, STOP requests
//! and the termination policy contract, and the violations of both frames.
use super::{
    OnResetStreamAtError, OnResetStreamError as ResetAtOnResetStreamError, RemoteResetAt,
    RemoteResetAtChange, ResetStreamAtFrame,
};
use crate::connection::{
    CloseReason, ConnectionClosedError, ImmediateClose, TransportImmediateClose,
};
use crate::connection_receive_flow::{ConnectionReceiveFlowController, RecordUsageError};
use crate::receive::flow_control::{
    AdvertisementIntent, ReceiveFlowControlPolicy, ReceiveFlowEvent, ReceiveFlowView,
};
use crate::receive::read::{ReadError, ReadOutcome, SharedTerminationReason};
use crate::receive::stop::{StopError, StopNotNeededReason};
use crate::receive::termination::{
    BoundaryAction, BoundaryUpdate, FollowingTermination, ReceiveTerminationPolicy,
    TerminationDecision, TerminationEvent, TerminationView,
};
use crate::receive::violation::{
    FinalSizeBelowReceivedError, OnRemoteResetError, OnResetStreamError, StreamLimitExceededError,
};
use crate::receive::{BoundaryMode, ResetStreamFrame, StreamFrame, StreamReceiver};
use crate::receive_buffer::{
    StreamDataInput, StreamReceiveBuffer, fragmented::FragmentedStreamReceiveBuffer,
};
use crate::send::test_support::TestCloseCause;
use crate::stream_end::{FinalSizeChangeError, ResetCodeChangeError};
use bytes::{BufMut, Bytes};
use core::fmt::Debug;
use sakuya_wire::reset_stream_at::ReliableSizeError;
use sakuya_wire::v1::application_error::ApplicationErrorCode;
use sakuya_wire::v1::transport_error::TransportErrorCode;
use sakuya_wire::var_int::VarInt;

/// The events a policy of these receivers observes.
type Event = TerminationEvent<RemoteResetAtChange>;

/// The state a policy of these receivers decides on.
type View = TerminationView<RemoteResetAt>;

/// A later reset lowered the effective reliable size.
const LOWERED: Event = TerminationEvent::ResetChanged(RemoteResetAtChange::ReliablePrefixLowered);

/// The reason the tests close connections for.
fn close_reason() -> CloseReason<TestCloseCause> {
    CloseReason::Peer(ImmediateClose::Transport(TransportImmediateClose {
        code: TransportErrorCode::PROTOCOL_VIOLATION,
        frame_type: Some(VarInt::from(0x08u8)),
        reason_phrase: Bytes::from_static(b"bad stream"),
    }))
}

fn v(value: u32) -> VarInt {
    VarInt::from_u32(value)
}

fn c(value: u32) -> ApplicationErrorCode {
    ApplicationErrorCode::new(v(value))
}

/// `len` bytes whose values are their stream offsets modulo 251.
fn data(offset: u32, len: u32) -> Bytes {
    (offset..offset + len)
        .map(|at| u8::try_from(at % 251).unwrap())
        .collect()
}

fn stream(offset: u32, len: u32, fin: bool) -> StreamFrame {
    StreamFrame {
        offset: v(offset),
        data: data(offset, len),
        fin,
    }
}

fn reset(code: u32, final_size: u32) -> ResetStreamFrame {
    ResetStreamFrame {
        code: c(code),
        final_size: v(final_size),
    }
}

fn reset_at(code: u32, final_size: u32, reliable_size: u32) -> ResetStreamAtFrame {
    ResetStreamAtFrame {
        code: c(code),
        final_size: v(final_size),
        reliable_size: v(reliable_size),
    }
}

fn facts(code: u32, final_size: u32, reliable_size: u32) -> RemoteResetAt {
    RemoteResetAt::new(c(code), v(final_size), v(reliable_size)).unwrap()
}

/// A termination policy that answers each event with a closure.
struct Scripted<S>(S);

impl<S> ReceiveTerminationPolicy<RemoteResetAt> for Scripted<S>
where
    S: FnMut(Event, &View) -> TerminationDecision<&'static str>,
{
    type Reason = &'static str;

    fn on_termination_event(
        &mut self,
        event: Event,
        view: &View,
    ) -> TerminationDecision<&'static str> {
        (self.0)(event, view)
    }
}

fn scripted<S>(script: S) -> Scripted<S>
where
    S: FnMut(Event, &View) -> TerminationDecision<&'static str>,
{
    Scripted(script)
}

fn keep(_: Event, _: &View) -> TerminationDecision<&'static str> {
    TerminationDecision::keep()
}

fn keep_all() -> Scripted<impl FnMut(Event, &View) -> TerminationDecision<&'static str>> {
    scripted(keep)
}

fn restrict(
    acceptance: BoundaryUpdate,
    delivery: BoundaryUpdate,
    reason: &'static str,
) -> TerminationDecision<&'static str> {
    TerminationDecision::new(BoundaryAction::Restrict {
        acceptance,
        delivery,
        reason,
    })
}

fn fix_both(limit: u32, reason: &'static str) -> TerminationDecision<&'static str> {
    restrict(
        BoundaryUpdate::Fix(v(limit)),
        BoundaryUpdate::Fix(v(limit)),
        reason,
    )
}

fn destroy(reason: &'static str) -> TerminationDecision<&'static str> {
    TerminationDecision::new(BoundaryAction::Destroy { reason })
}

/// The components of the receivers under test: the fragmented buffer, a
/// flow control policy that withholds, and a termination policy. Both
/// policies log the events they observe.
struct Parts<T> {
    buffer: FragmentedStreamReceiveBuffer,
    flow_events: Vec<ReceiveFlowEvent>,
    termination: T,
    events: Vec<Event>,
}

impl<T> Parts<T> {
    fn count(&self, kind: Event) -> usize {
        self.events.iter().filter(|event| **event == kind).count()
    }
}

impl<T> StreamReceiveBuffer for Parts<T> {
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

    fn read_into<B: BufMut + ?Sized>(&mut self, limit: VarInt, target: &mut B) -> usize {
        self.buffer.read_into(limit, target)
    }

    fn release_from(&mut self, end: VarInt) {
        self.buffer.release_from(end);
    }

    fn destroy(&mut self) {
        self.buffer.destroy();
    }
}

impl<T> ReceiveFlowControlPolicy for Parts<T> {
    fn on_receive_flow_event(&mut self, event: ReceiveFlowEvent, _view: &ReceiveFlowView) {
        self.flow_events.push(event);
    }

    fn advertisement_intent(&self) -> AdvertisementIntent {
        AdvertisementIntent::Withhold
    }
}

impl<T: ReceiveTerminationPolicy<RemoteResetAt>> ReceiveTerminationPolicy<RemoteResetAt>
    for Parts<T>
{
    type Reason = T::Reason;

    fn on_termination_event(
        &mut self,
        event: Event,
        view: &View,
    ) -> TerminationDecision<T::Reason> {
        self.events.push(event);
        self.termination.on_termination_event(event, view)
    }
}

type Receiver<T> = StreamReceiver<Parts<T>, TestCloseCause, RemoteResetAt>;

/// The result of one chunk read.
type ChunkRead<R = &'static str> =
    Result<ReadOutcome<Bytes>, ReadError<R, TestCloseCause, RemoteResetAt>>;

/// A receiver with stream limit `stream_limit` on a connection with limit
/// `connection_limit`.
fn receiver_with<T: ReceiveTerminationPolicy<RemoteResetAt>>(
    termination: T,
    stream_limit: u32,
    connection_limit: u32,
) -> (Receiver<T>, ConnectionReceiveFlowController) {
    let parts = Parts {
        buffer: FragmentedStreamReceiveBuffer::new(),
        flow_events: Vec::new(),
        termination,
        events: Vec::new(),
    };
    (
        StreamReceiver::new(parts, v(stream_limit)),
        ConnectionReceiveFlowController::new(v(connection_limit)),
    )
}

/// A receiver with generous limits.
fn new_receiver<T: ReceiveTerminationPolicy<RemoteResetAt>>(
    termination: T,
) -> (Receiver<T>, ConnectionReceiveFlowController) {
    receiver_with(termination, 1 << 20, 1 << 20)
}

/// Reads chunks until a read returns something else than data.
fn read_all<T: ReceiveTerminationPolicy<RemoteResetAt>>(
    receiver: &mut Receiver<T>,
) -> (Vec<u8>, ChunkRead<T::Reason>) {
    let mut out = Vec::new();
    loop {
        match receiver.read_chunk() {
            Ok(ReadOutcome::Data(chunk)) => {
                assert!(!chunk.is_empty());
                out.extend_from_slice(&chunk);
            }
            other => return (out, other),
        }
    }
}

fn reset_error<R>(code: u32, final_size: u32, reliable_size: u32, complete: bool) -> ChunkRead<R> {
    Err(ReadError::Reset {
        reset: facts(code, final_size, reliable_size),
        complete,
    })
}

fn delivery_limit(
    reason: &'static str,
    trigger: Event,
    remote: Option<RemoteResetAt>,
) -> ChunkRead {
    Err(ReadError::DeliveryLimitReached {
        reason: SharedTerminationReason::new(reason),
        trigger,
        remote,
    })
}

fn acceptance_limit(
    reason: &'static str,
    trigger: Event,
    remote: Option<RemoteResetAt>,
) -> ChunkRead {
    Err(ReadError::AcceptanceLimitReached {
        reason: SharedTerminationReason::new(reason),
        trigger,
        remote,
    })
}

/// A receiver whose policy answers `StopSent` with `on_stop` and everything
/// else with `later`, with [0, 500) received and the STOP request sent.
fn stopped_with(
    on_stop: TerminationDecision<&'static str>,
    later: impl FnMut(Event, &View) -> TerminationDecision<&'static str> + 'static,
) -> (
    Receiver<impl ReceiveTerminationPolicy<RemoteResetAt, Reason = &'static str>>,
    ConnectionReceiveFlowController,
) {
    let mut on_stop = Some(on_stop);
    let mut later = later;
    let (mut receiver, mut connection) = new_receiver(scripted(move |event, view| {
        if event == TerminationEvent::StopSent {
            on_stop.take().unwrap()
        } else {
            later(event, view)
        }
    }));
    receiver
        .on_stream_frame(stream(0, 500, false), &mut connection)
        .unwrap();
    receiver.stop(c(1)).unwrap();
    receiver.on_stop_sent().unwrap();
    (receiver, connection)
}

/// Everything about a receiver and its connection that an observer can see
/// without reading.
#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    accounted_end: VarInt,
    final_size: Option<VarInt>,
    delivered_end: VarInt,
    held_len: usize,
    destroyed: bool,
    reset: Option<RemoteResetAt>,
    pending_stop: Option<ApplicationErrorCode>,
    acceptance: BoundaryMode,
    delivery: BoundaryMode,
    flow_events: Vec<ReceiveFlowEvent>,
    termination_events: Vec<Event>,
    used: VarInt,
    released: VarInt,
}

fn snapshot<T: ReceiveTerminationPolicy<RemoteResetAt>>(
    receiver: &Receiver<T>,
    connection: &ConnectionReceiveFlowController,
) -> Snapshot {
    let parts = receiver.parts();
    Snapshot {
        accounted_end: parts.accounted_end(),
        final_size: parts.final_size(),
        delivered_end: parts.delivered_end(),
        held_len: parts.buffer.held_len(),
        destroyed: parts.buffer.is_destroyed(),
        reset: receiver.remote_reset(),
        pending_stop: receiver.pending_stop(),
        acceptance: receiver.acceptance_limit(),
        delivery: receiver.delivery_limit(),
        flow_events: parts.flow_events.clone(),
        termination_events: parts.events.clone(),
        used: connection.used(),
        released: connection.released(),
    }
}

/// Runs a frame that is expected to violate the protocol, checks that the
/// receiver and the connection are as before it, and returns the violation.
fn violation<T, E>(
    receiver: &mut Receiver<T>,
    connection: &mut ConnectionReceiveFlowController,
    frame: impl FnOnce(&mut Receiver<T>, &mut ConnectionReceiveFlowController) -> Result<(), E>,
) -> E
where
    T: ReceiveTerminationPolicy<RemoteResetAt>,
    E: Debug,
{
    let before = snapshot(receiver, connection);
    let error = frame(receiver, connection).expect_err("the frame violates the protocol");
    assert_eq!(snapshot(receiver, connection), before, "{error:?}");
    error
}

fn reset_violation<T: ReceiveTerminationPolicy<RemoteResetAt>>(
    receiver: &mut Receiver<T>,
    connection: &mut ConnectionReceiveFlowController,
    frame: ResetStreamFrame,
) -> ResetAtOnResetStreamError {
    violation(receiver, connection, |receiver, connection| {
        receiver.on_reset_stream(frame, connection)
    })
}

fn reset_at_violation<T: ReceiveTerminationPolicy<RemoteResetAt>>(
    receiver: &mut Receiver<T>,
    connection: &mut ConnectionReceiveFlowController,
    frame: ResetStreamAtFrame,
) -> OnResetStreamAtError {
    violation(receiver, connection, |receiver, connection| {
        receiver.on_reset_stream_at(frame, connection)
    })
}

/// The violation of a rule that `RESET_STREAM_AT` shares with
/// `RESET_STREAM`, as each of the two frame methods reports it.
fn shared(
    source: impl Into<ResetAtOnResetStreamError>,
) -> (ResetAtOnResetStreamError, OnResetStreamAtError) {
    let source = source.into();
    (source, OnResetStreamAtError::Reset { source })
}

/// The violation of a rule of RFC 9000 for resets.
fn rfc9000(source: impl Into<OnResetStreamError>) -> ResetAtOnResetStreamError {
    ResetAtOnResetStreamError::ResetStream {
        source: source.into(),
    }
}

/// The following termination policy, end to end.
mod following {
    use super::*;

    #[test]
    fn reliable_prefix_gap_waits() {
        let (mut receiver, mut connection) = new_receiver(FollowingTermination::new(c(9)));
        receiver
            .on_reset_stream_at(reset_at(4, 1000, 500), &mut connection)
            .unwrap();
        receiver
            .on_stream_frame(stream(0, 200, false), &mut connection)
            .unwrap();
        let (read, outcome) = read_all(&mut receiver);
        assert_eq!(read, data(0, 200));
        assert_eq!(outcome, Ok(ReadOutcome::Wait));
        receiver
            .on_stream_frame(stream(200, 400, false), &mut connection)
            .unwrap();
        let (read, end) = read_all(&mut receiver);
        assert_eq!(read, data(200, 400));
        assert_eq!(end, reset_error(4, 1000, 500, false));
    }
}

/// Remote end facts in every order of observation, and the reliable prefix.
mod order {
    use super::*;

    /// RESET_STREAM_AT(800), then RESET_STREAM_AT(400): the effective prefix
    /// drops to 400 and a read waiting for the gap at 500 ends.
    #[test]
    fn lower_reliable_size_releases_a_waiting_read() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_reset_stream_at(reset_at(4, 1000, 800), &mut connection)
            .unwrap();
        receiver
            .on_stream_frame(stream(0, 500, false), &mut connection)
            .unwrap();
        let (read, outcome) = read_all(&mut receiver);
        assert_eq!(read.len(), 500);
        assert_eq!(outcome, Ok(ReadOutcome::Wait));
        receiver
            .on_reset_stream_at(reset_at(4, 1000, 400), &mut connection)
            .unwrap();
        assert_eq!(receiver.remote_reset().unwrap().reliable_size(), v(400));
        assert_eq!(receiver.parts().count(LOWERED), 1);
        assert_eq!(receiver.read_chunk(), reset_error(4, 1000, 400, false));
    }

    /// RESET_STREAM_AT(400), then RESET_STREAM_AT(800): out of order; the
    /// prefix stays 400 and nothing new happens.
    #[test]
    fn higher_reliable_size_is_ignored() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_reset_stream_at(reset_at(4, 1000, 400), &mut connection)
            .unwrap();
        receiver
            .on_reset_stream_at(reset_at(4, 1000, 800), &mut connection)
            .unwrap();
        assert_eq!(receiver.remote_reset().unwrap().reliable_size(), v(400));
        assert_eq!(receiver.parts().events, vec![TerminationEvent::RemoteReset]);
    }

    /// RESET_STREAM_AT, then plain RESET: the prefix drops to zero, but held
    /// contiguous data stays readable.
    #[test]
    fn plain_reset_after_reset_at_keeps_readable_data() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_stream_frame(stream(0, 300, false), &mut connection)
            .unwrap();
        receiver
            .on_reset_stream_at(reset_at(4, 1000, 800), &mut connection)
            .unwrap();
        receiver
            .on_reset_stream(reset(4, 1000), &mut connection)
            .unwrap();
        assert_eq!(
            receiver.remote_reset().unwrap().reliable_size(),
            VarInt::ZERO
        );
        let (read, end) = read_all(&mut receiver);
        assert_eq!(read, data(0, 300));
        assert_eq!(end, reset_error(4, 1000, 0, false));
    }

    /// Plain RESET, then RESET_STREAM_AT: an extension frame sent earlier and
    /// delivered late; the prefix stays zero.
    #[test]
    fn reset_at_after_plain_reset_keeps_zero() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_reset_stream(reset(4, 1000), &mut connection)
            .unwrap();
        receiver
            .on_reset_stream_at(reset_at(4, 1000, 800), &mut connection)
            .unwrap();
        assert_eq!(
            receiver.remote_reset().unwrap().reliable_size(),
            VarInt::ZERO
        );
        assert_eq!(receiver.read_chunk(), reset_error(4, 1000, 0, false));
    }

    /// FIN and RESET_STREAM_AT in both orders agree on the final size, and FIN
    /// does not restore a lowered prefix.
    #[test]
    fn fin_and_reset_at_in_either_order() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_stream_frame(stream(900, 100, true), &mut connection)
            .unwrap();
        receiver
            .on_reset_stream_at(reset_at(4, 1000, 400), &mut connection)
            .unwrap();
        assert_eq!(receiver.remote_reset().unwrap().final_size(), v(1000));

        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_reset_stream_at(reset_at(4, 1000, 800), &mut connection)
            .unwrap();
        receiver
            .on_reset_stream_at(reset_at(4, 1000, 400), &mut connection)
            .unwrap();
        receiver
            .on_stream_frame(stream(900, 100, true), &mut connection)
            .unwrap();
        assert_eq!(receiver.parts().final_size(), Some(v(1000)));
        assert_eq!(receiver.remote_reset().unwrap().reliable_size(), v(400));
    }

    /// A RESET_STREAM_AT that arrives before any data does not wipe the
    /// reliable prefix: the read waits for it.
    #[test]
    fn reset_at_before_data_keeps_the_prefix() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_reset_stream_at(reset_at(4, 1000, 800), &mut connection)
            .unwrap();
        assert_eq!(receiver.read_chunk(), Ok(ReadOutcome::Wait));
        assert_eq!(receiver.acceptance_limit(), BoundaryMode::Following);
        receiver
            .on_stream_frame(stream(0, 800, false), &mut connection)
            .unwrap();
        let (read, end) = read_all(&mut receiver);
        assert_eq!(read, data(0, 800));
        assert_eq!(end, reset_error(4, 1000, 800, false));
    }

    /// Data beyond the reliable prefix is delivered when it is there.
    #[test]
    fn data_beyond_the_prefix_is_delivered() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_stream_frame(stream(0, 600, false), &mut connection)
            .unwrap();
        receiver
            .on_reset_stream_at(reset_at(4, 1000, 400), &mut connection)
            .unwrap();
        let (read, end) = read_all(&mut receiver);
        assert_eq!(read.len(), 600);
        assert_eq!(end, reset_error(4, 1000, 400, false));
    }

    /// The STOP request was sent and the policy truncated delivery at 300; a
    /// later RESET_STREAM_AT promising 800 does not lift the truncation, and the
    /// read ends at 300 with the local reason and the remote facts.
    #[test]
    fn stop_truncation_survives_a_larger_reliable_size() {
        let (mut receiver, mut connection) = new_receiver(scripted(|event, _| match event {
            TerminationEvent::StopSent => fix_both(300, "stop"),
            _ => TerminationDecision::keep(),
        }));
        receiver
            .on_stream_frame(stream(0, 200, false), &mut connection)
            .unwrap();
        receiver.stop(c(7)).unwrap();
        receiver.on_stop_sent().unwrap();
        assert_eq!(receiver.delivery_limit(), BoundaryMode::Fixed(v(300)));
        receiver
            .on_stream_frame(stream(200, 600, false), &mut connection)
            .unwrap();
        // Only [200, 300) of the frame is kept; all of it is accounted.
        assert_eq!(receiver.parts().buffer.held_len(), 300);
        assert_eq!(connection.used(), v(800));
        receiver
            .on_reset_stream_at(reset_at(4, 1000, 800), &mut connection)
            .unwrap();
        assert_eq!(receiver.delivery_limit(), BoundaryMode::Fixed(v(300)));
        let (read, end) = read_all(&mut receiver);
        assert_eq!(read, data(0, 300));
        assert_eq!(
            end,
            Err(ReadError::DeliveryLimitReached {
                reason: SharedTerminationReason::new("stop"),
                trigger: TerminationEvent::StopSent,
                remote: Some(facts(4, 1000, 800)),
            })
        );
    }

    /// RESET_STREAM_AT whose prefix is not yet received, then a local STOP
    /// request: still allowed.
    #[test]
    fn stop_is_allowed_while_the_prefix_is_missing() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_stream_frame(stream(0, 500, false), &mut connection)
            .unwrap();
        receiver
            .on_reset_stream_at(reset_at(4, 1000, 800), &mut connection)
            .unwrap();
        assert_eq!(receiver.stop(c(5)), Ok(()));
        assert_eq!(receiver.pending_stop(), Some(c(5)));
        // Once the prefix arrives, the pending request lapses.
        receiver
            .on_stream_frame(stream(500, 300, false), &mut connection)
            .unwrap();
        assert_eq!(receiver.pending_stop(), None);
    }
}

/// The STOP request and the reliable prefix.
mod stop {
    use super::*;

    #[test]
    fn received_reliable_prefix_needs_no_request() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_stream_frame(stream(0, 400, false), &mut connection)
            .unwrap();
        receiver
            .on_reset_stream_at(reset_at(4, 1000, 400), &mut connection)
            .unwrap();
        assert_eq!(
            receiver.stop(c(1)),
            Err(StopError::StopNotNeeded {
                reason: StopNotNeededReason::PeerReset,
            })
        );
    }
}

/// Whether the reliable prefix was received, after the buffer is gone.
mod completion {
    use super::*;

    #[test]
    fn reliable_prefix_arriving_after_destruction_needs_no_request() {
        let (mut receiver, mut connection) = new_receiver(FollowingTermination::new(c(9)));
        receiver
            .on_reset_stream_at(reset_at(4, 1000, 100), &mut connection)
            .unwrap();
        receiver
            .on_stream_frame(stream(0, 50, false), &mut connection)
            .unwrap();
        receiver.reader_dropped();
        assert_eq!(receiver.pending_stop(), Some(c(9)));
        receiver
            .on_stream_frame(stream(50, 50, false), &mut connection)
            .unwrap();
        assert_eq!(receiver.pending_stop(), None);
    }
}

/// Limit actions of the receive termination policy and the reliable prefix.
mod boundary {
    use super::*;

    /// A tighter limit records the new reason and trigger; the other limit
    /// keeps its own.
    #[test]
    fn tightening_records_the_new_reason_per_limit() {
        let tighten_delivery_to = |limit: u32| {
            stopped_with(
                restrict(
                    BoundaryUpdate::Fix(v(500)),
                    BoundaryUpdate::Fix(v(800)),
                    "first",
                ),
                move |event, _| match event {
                    TerminationEvent::RemoteReset => restrict(
                        BoundaryUpdate::Keep,
                        BoundaryUpdate::Fix(v(limit)),
                        "second",
                    ),
                    _ => TerminationDecision::keep(),
                },
            )
        };
        // The reset promises the whole stream, so neither its gap rule nor its
        // prefix rule ends the read before the local limits do.
        let whole = reset_at(4, 1000, 1000);

        // Reading ends at the acceptance limit, which kept the first reason.
        let (mut receiver, mut connection) = tighten_delivery_to(700);
        receiver.on_reset_stream_at(whole, &mut connection).unwrap();
        assert_eq!(receiver.delivery_limit(), BoundaryMode::Fixed(v(700)));
        let (read, end) = read_all(&mut receiver);
        assert_eq!(read.len(), 500);
        let remote = receiver.remote_reset();
        assert_eq!(
            end,
            acceptance_limit("first", TerminationEvent::StopSent, remote)
        );

        // Reading ends at the tightened delivery limit, with the second reason.
        let (mut receiver, mut connection) = tighten_delivery_to(400);
        receiver.on_reset_stream_at(whole, &mut connection).unwrap();
        let (read, end) = read_all(&mut receiver);
        assert_eq!(read.len(), 400);
        let remote = receiver.remote_reset();
        assert_eq!(
            end,
            delivery_limit("second", TerminationEvent::RemoteReset, remote)
        );
    }

    /// A sent STOP request is a local cancellation: the policy may then give up
    /// a reliable prefix, and reading ends with the local reason.
    #[test]
    fn sent_stop_cancels_the_reliable_prefix() {
        let (mut receiver, mut connection) = new_receiver(scripted(|event, _| match event {
            TerminationEvent::StopSent => fix_both(100, "stop"),
            _ => TerminationDecision::keep(),
        }));
        receiver
            .on_stream_frame(stream(0, 200, false), &mut connection)
            .unwrap();
        receiver
            .on_reset_stream_at(reset_at(4, 1000, 800), &mut connection)
            .unwrap();
        receiver.stop(c(1)).unwrap();
        receiver.on_stop_sent().unwrap();
        assert_eq!(receiver.delivery_limit(), BoundaryMode::Fixed(v(100)));
        let (read, end) = read_all(&mut receiver);
        assert_eq!(read, data(0, 100));
        let remote = receiver.remote_reset();
        assert_eq!(
            end,
            delivery_limit("stop", TerminationEvent::StopSent, remote)
        );
    }

    /// With the whole reliable prefix received and held, the acceptance limit
    /// may drop below it.
    #[test]
    fn acceptance_below_a_received_prefix() {
        let (mut receiver, mut connection) = new_receiver(scripted(|event, _| match event {
            TerminationEvent::RemoteReset => restrict(
                BoundaryUpdate::Fix(VarInt::ZERO),
                BoundaryUpdate::Keep,
                "prefix complete",
            ),
            _ => TerminationDecision::keep(),
        }));
        receiver
            .on_stream_frame(stream(0, 800, false), &mut connection)
            .unwrap();
        receiver
            .on_reset_stream_at(reset_at(4, 1000, 800), &mut connection)
            .unwrap();
        assert_eq!(
            receiver.acceptance_limit(),
            BoundaryMode::Fixed(VarInt::ZERO)
        );
        let (read, end) = read_all(&mut receiver);
        assert_eq!(read.len(), 800);
        assert_eq!(end, reset_error(4, 1000, 800, false));
    }

    /// A reset gives a basis: the base-composition style of fixing both limits
    /// at the final size keeps reading to the first gap.
    #[test]
    fn fixing_at_the_final_size_after_a_reset() {
        let (mut receiver, mut connection) = new_receiver(scripted(|event, view| match event {
            TerminationEvent::RemoteReset => fix_both(
                u32::try_from(view.final_size.unwrap().get()).unwrap(),
                "reset",
            ),
            _ => TerminationDecision::keep(),
        }));
        receiver
            .on_stream_frame(stream(0, 100, false), &mut connection)
            .unwrap();
        receiver
            .on_reset_stream_at(reset_at(4, 300, 200), &mut connection)
            .unwrap();
        receiver
            .on_stream_frame(stream(100, 200, false), &mut connection)
            .unwrap();
        let (read, end) = read_all(&mut receiver);
        assert_eq!(read, data(0, 300));
        assert_eq!(end, reset_error(4, 300, 200, true));
    }

    /// Decisions that break the reliable prefix without a local cancellation.
    mod violations {
        use super::*;

        #[test]
        #[should_panic(expected = "inside the undelivered prefix the peer still owes up to 800")]
        fn delivery_inside_the_reliable_prefix() {
            let (mut receiver, mut connection) = new_receiver(scripted(|event, _| match event {
                TerminationEvent::RemoteReset => {
                    restrict(BoundaryUpdate::Keep, BoundaryUpdate::Fix(v(300)), "reset")
                }
                _ => TerminationDecision::keep(),
            }));
            receiver
                .on_reset_stream_at(reset_at(4, 1000, 800), &mut connection)
                .unwrap();
        }

        #[test]
        #[should_panic(expected = "inside the unreceived prefix the peer still owes up to 800")]
        fn acceptance_inside_an_unreceived_prefix() {
            let (mut receiver, mut connection) = new_receiver(scripted(|event, _| match event {
                TerminationEvent::RemoteReset => {
                    restrict(BoundaryUpdate::Fix(v(300)), BoundaryUpdate::Keep, "reset")
                }
                _ => TerminationDecision::keep(),
            }));
            receiver
                .on_stream_frame(stream(0, 500, false), &mut connection)
                .unwrap();
            receiver
                .on_reset_stream_at(reset_at(4, 1000, 800), &mut connection)
                .unwrap();
        }

        #[test]
        #[should_panic(expected = "while the prefix the peer still owes is undelivered")]
        fn destroying_an_undelivered_prefix() {
            let (mut receiver, mut connection) = new_receiver(scripted(|event, _| match event {
                TerminationEvent::RemoteReset => destroy("reset"),
                _ => TerminationDecision::keep(),
            }));
            receiver
                .on_reset_stream_at(reset_at(4, 1000, 800), &mut connection)
                .unwrap();
        }
    }
}

/// The violations of the two frame methods and the absence of any trace
/// they leave.
mod violation {
    use super::*;

    #[test]
    fn reliable_size_exceeds_final_size() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        let error = reset_at_violation(&mut receiver, &mut connection, reset_at(1, 100, 101));
        assert_eq!(
            error,
            OnResetStreamAtError::ReliableSizeExceedsFinalSize {
                source: ReliableSizeError::check(v(100), v(101)).unwrap_err(),
            }
        );
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::FRAME_ENCODING_ERROR
        );
    }

    #[test]
    fn final_size_changed() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_stream_frame(stream(0, 100, true), &mut connection)
            .unwrap();
        let (expected, expected_at) = shared(rfc9000(
            FinalSizeChangeError::check(v(100), v(200)).unwrap_err(),
        ));
        let error = reset_at_violation(&mut receiver, &mut connection, reset_at(1, 200, 0));
        assert_eq!(error, expected_at);
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::FINAL_SIZE_ERROR
        );

        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_stream_frame(stream(0, 100, true), &mut connection)
            .unwrap();
        let error = reset_violation(&mut receiver, &mut connection, reset(1, 200));
        assert_eq!(error, expected);
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::FINAL_SIZE_ERROR
        );
    }

    #[test]
    fn final_size_below_received() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_stream_frame(stream(0, 100, false), &mut connection)
            .unwrap();
        let (_, expected) = shared(rfc9000(
            FinalSizeBelowReceivedError::check(v(50), v(100)).unwrap_err(),
        ));
        let error = reset_at_violation(&mut receiver, &mut connection, reset_at(1, 50, 10));
        assert_eq!(error, expected);
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::FINAL_SIZE_ERROR
        );
    }

    /// `RESET_STREAM_AT` after `RESET_STREAM` with another error code.
    #[test]
    fn reset_code_changed() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_reset_stream(reset(1, 100), &mut connection)
            .unwrap();
        let (_, expected) = shared(ResetCodeChangeError::check(c(1), c(2)).unwrap_err());
        let error = reset_at_violation(&mut receiver, &mut connection, reset_at(2, 100, 10));
        assert_eq!(error, expected);
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::STREAM_STATE_ERROR
        );
    }

    /// `RESET_STREAM` after `RESET_STREAM_AT` with another error code.
    #[test]
    fn reset_stream_changes_the_code() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_reset_stream_at(reset_at(1, 100, 50), &mut connection)
            .unwrap();
        let error = reset_violation(&mut receiver, &mut connection, reset(2, 100));
        assert_eq!(
            error,
            ResetAtOnResetStreamError::ResetCodeChanged {
                source: ResetCodeChangeError::check(c(1), c(2)).unwrap_err(),
            }
        );
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::STREAM_STATE_ERROR
        );
    }

    /// Two `RESET_STREAM` frames with different error codes violate the
    /// protocol on a stream that takes `RESET_STREAM_AT`.
    #[test]
    fn second_reset_stream_changes_the_code() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_reset_stream(reset(1, 100), &mut connection)
            .unwrap();
        let error = reset_violation(&mut receiver, &mut connection, reset(2, 100));
        assert_eq!(
            error,
            ResetAtOnResetStreamError::ResetCodeChanged {
                source: ResetCodeChangeError::check(c(1), c(2)).unwrap_err(),
            }
        );
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::STREAM_STATE_ERROR
        );
        // The stream waits for the connection to close.
        assert_eq!(receiver.read_chunk(), Ok(ReadOutcome::Wait));
    }

    /// The final size is checked before the error code.
    #[test]
    fn final_size_is_checked_before_the_code() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_reset_stream(reset(1, 100), &mut connection)
            .unwrap();
        let error = reset_violation(&mut receiver, &mut connection, reset(2, 200));
        assert_eq!(
            error,
            rfc9000(FinalSizeChangeError::check(v(100), v(200)).unwrap_err())
        );
    }

    #[test]
    fn stream_limit_exceeded() {
        let (mut receiver, mut connection) = receiver_with(keep_all(), 1000, 1 << 20);
        let (expected, expected_at) = shared(rfc9000(
            StreamLimitExceededError::check(v(1001), v(1000)).unwrap_err(),
        ));
        let error = reset_at_violation(&mut receiver, &mut connection, reset_at(1, 1001, 10));
        assert_eq!(error, expected_at);
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::FLOW_CONTROL_ERROR
        );

        let (mut receiver, mut connection) = receiver_with(keep_all(), 1000, 1 << 20);
        let error = reset_violation(&mut receiver, &mut connection, reset(1, 1001));
        assert_eq!(error, expected);
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::FLOW_CONTROL_ERROR
        );
    }

    #[test]
    fn connection_limit_exceeded() {
        let (mut receiver, mut connection) = receiver_with(keep_all(), 1000, 100);
        let (_, expected) = shared(rfc9000(RecordUsageError {
            used: VarInt::ZERO,
            increase: v(101),
            limit: v(100),
        }));
        let error = reset_at_violation(&mut receiver, &mut connection, reset_at(1, 101, 10));
        assert_eq!(error, expected);
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::FLOW_CONTROL_ERROR
        );
    }

    /// The reliable size is checked first: a frame that breaks it and a
    /// rule of reset frames reports the encoding error.
    #[test]
    fn reliable_size_is_checked_first() {
        let (mut receiver, mut connection) = receiver_with(keep_all(), 1000, 1 << 20);
        let error = reset_at_violation(&mut receiver, &mut connection, reset_at(1, 2000, 3000));
        assert!(matches!(
            error,
            OnResetStreamAtError::ReliableSizeExceedsFinalSize { .. }
        ));
    }

    /// The entry point every kind of reset shares tells the three kinds of
    /// failure apart.
    #[test]
    fn the_shared_entry_point_keeps_the_kinds_apart() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        let error = violation(&mut receiver, &mut connection, |receiver, connection| {
            receiver.on_remote_reset(reset_at(1, 100, 101), connection)
        });
        assert_eq!(
            error,
            OnRemoteResetError::Malformed {
                source: ReliableSizeError::check(v(100), v(101)).unwrap_err(),
            }
        );

        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_remote_reset(reset_at(1, 100, 50), &mut connection)
            .unwrap();
        assert_eq!(receiver.remote_reset(), Some(facts(1, 100, 50)));
        let error = violation(&mut receiver, &mut connection, |receiver, connection| {
            receiver.on_remote_reset(reset(2, 100), connection)
        });
        assert_eq!(
            error,
            OnRemoteResetError::Conflict {
                source: ResetCodeChangeError::check(c(1), c(2)).unwrap_err(),
            }
        );
    }

    /// Between a violation and the connection's closure, and after the
    /// closure, both reset frames are ignored, also a malformed one.
    #[test]
    fn frames_are_ignored_after_a_violation_and_after_the_close() {
        let (mut receiver, mut connection) = receiver_with(keep_all(), 1000, 1 << 20);
        receiver
            .on_stream_frame(stream(0, 100, false), &mut connection)
            .unwrap();
        reset_at_violation(&mut receiver, &mut connection, reset_at(1, 2000, 10));
        let before = snapshot(&receiver, &connection);
        assert_eq!(
            receiver.on_reset_stream(reset(1, 300), &mut connection),
            Ok(())
        );
        assert_eq!(
            receiver.on_reset_stream_at(reset_at(1, 300, 200), &mut connection),
            Ok(())
        );
        assert_eq!(
            receiver.on_reset_stream_at(reset_at(1, 50, 60), &mut connection),
            Ok(())
        );
        assert_eq!(snapshot(&receiver, &connection), before);
        assert_eq!(receiver.read_chunk(), Ok(ReadOutcome::Wait));

        receiver.connection_closed(close_reason());
        let before = snapshot(&receiver, &connection);
        assert_eq!(
            receiver.on_reset_stream(reset(1, 300), &mut connection),
            Ok(())
        );
        assert_eq!(
            receiver.on_reset_stream_at(reset_at(1, 50, 60), &mut connection),
            Ok(())
        );
        assert_eq!(snapshot(&receiver, &connection), before);
        assert_eq!(
            receiver.read_chunk(),
            Err(ReadError::ConnectionClosed {
                source: ConnectionClosedError::new(close_reason()),
            })
        );
    }

    /// A malformed frame leaves the stream waiting for the connection to
    /// close, like any other violation.
    #[test]
    fn a_malformed_frame_is_a_violation_of_the_stream() {
        let (mut receiver, mut connection) = new_receiver(keep_all());
        receiver
            .on_stream_frame(stream(0, 100, false), &mut connection)
            .unwrap();
        reset_at_violation(&mut receiver, &mut connection, reset_at(1, 100, 101));
        assert_eq!(receiver.read_chunk(), Ok(ReadOutcome::Wait));
        assert_eq!(
            receiver.on_stream_frame(stream(100, 100, false), &mut connection),
            Ok(())
        );
        assert_eq!(connection.used(), v(100));
    }
}
