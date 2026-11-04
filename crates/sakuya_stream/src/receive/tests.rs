use super::{
    BoundaryMode, ResetStreamAtFrame, ResetStreamFrame, StreamFrame, StreamReceiver,
    flow_control::{
        AdvertisementIntent, ReceiveFlowControlPolicy, ReceiveFlowEvent, ReceiveFlowView,
    },
    read::{ReadError, ReadOutcome, RemoteReset, SharedTerminationReason},
    termination::{
        BoundaryAction, BoundaryUpdate, FollowingTermination, ReceiveTerminationPolicy,
        ResetPresentation, TerminationDecision, TerminationEvent, TerminationView,
    },
};
use crate::connection::{CloseReason, ImmediateClose};
use crate::{
    connection_receive_flow::ConnectionReceiveFlowController,
    receive_buffer::{
        StreamDataInput, StreamReceiveBuffer, fragmented::FragmentedStreamReceiveBuffer,
    },
};
use bytes::{BufMut, Bytes};
use core::cell::Cell;
use sakuya_wire::application_error::ApplicationErrorCode;
use sakuya_wire::transport_error::TransportErrorCode;
use sakuya_wire::var_int::VarInt;
use std::rc::Rc;

mod accounting;
mod boundary;
mod order;
mod read;
mod stop;
mod violation;

/// The reason the tests close connections for.
fn close_reason() -> CloseReason {
    CloseReason::Peer(ImmediateClose::Transport {
        code: TransportErrorCode::PROTOCOL_VIOLATION,
        frame_type: Some(VarInt::from(0x08u8)),
        reason_phrase: Bytes::from_static(b"bad stream"),
    })
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

/// A termination policy that answers each event with a closure.
struct Scripted<S>(S);

impl<S> ReceiveTerminationPolicy for Scripted<S>
where
    S: FnMut(TerminationEvent, &TerminationView) -> TerminationDecision<&'static str>,
{
    type Reason = &'static str;

    fn on_termination_event(
        &mut self,
        event: TerminationEvent,
        view: &TerminationView,
    ) -> TerminationDecision<&'static str> {
        (self.0)(event, view)
    }
}

fn scripted<S>(script: S) -> Scripted<S>
where
    S: FnMut(TerminationEvent, &TerminationView) -> TerminationDecision<&'static str>,
{
    Scripted(script)
}

fn keep(_: TerminationEvent, _: &TerminationView) -> TerminationDecision<&'static str> {
    TerminationDecision::keep()
}

fn keep_all()
-> Scripted<impl FnMut(TerminationEvent, &TerminationView) -> TerminationDecision<&'static str>> {
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
/// flow control policy whose intent the test sets, and a termination policy.
/// Both policies log what they observe.
struct Parts<T> {
    buffer: FragmentedStreamReceiveBuffer,
    intent: Rc<Cell<AdvertisementIntent>>,
    flow_events: Vec<ReceiveFlowEvent>,
    termination: T,
    events: Vec<(TerminationEvent, TerminationView)>,
}

impl<T> Parts<T> {
    fn event_kinds(&self) -> Vec<TerminationEvent> {
        self.events.iter().map(|(event, _)| *event).collect()
    }

    fn count(&self, kind: TerminationEvent) -> usize {
        self.events
            .iter()
            .filter(|(event, _)| *event == kind)
            .count()
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
        self.intent.get()
    }
}

impl<T: ReceiveTerminationPolicy> ReceiveTerminationPolicy for Parts<T> {
    type Reason = T::Reason;

    fn on_termination_event(
        &mut self,
        event: TerminationEvent,
        view: &TerminationView,
    ) -> TerminationDecision<T::Reason> {
        self.events.push((event, *view));
        self.termination.on_termination_event(event, view)
    }
}

type Receiver<T> = StreamReceiver<Parts<T>>;

/// The result of one chunk read.
type ChunkRead<R = &'static str> = Result<ReadOutcome<Bytes>, ReadError<R>>;

/// A receiver with stream limit `stream_limit` on a connection with limit
/// `connection_limit`.
fn receiver_with<T: ReceiveTerminationPolicy>(
    termination: T,
    stream_limit: u32,
    connection_limit: u32,
) -> (Receiver<T>, ConnectionReceiveFlowController) {
    let parts = Parts {
        buffer: FragmentedStreamReceiveBuffer::new(),
        intent: Rc::default(),
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
fn new_receiver<T: ReceiveTerminationPolicy>(
    termination: T,
) -> (Receiver<T>, ConnectionReceiveFlowController) {
    receiver_with(termination, 1 << 20, 1 << 20)
}

/// Reads chunks until a read returns something else than data.
fn read_all<T: ReceiveTerminationPolicy>(
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
        reset: RemoteReset {
            code: c(code),
            final_size: v(final_size),
            reliable_size: v(reliable_size),
        },
        complete,
    })
}

/// The following termination policy, end to end.
mod following {
    use super::*;

    #[test]
    fn reader_drop_requests_stop_with_the_abandon_code() {
        let (mut receiver, mut connection) = new_receiver(FollowingTermination::new(c(9)));
        receiver
            .on_stream_frame(stream(0, 100, false), &mut connection)
            .unwrap();
        receiver.reader_dropped();
        assert!(receiver.parts().buffer.is_destroyed());
        assert_eq!(receiver.pending_stop(), Some(c(9)));
        // The protocol duties go on: input is still checked and accounted.
        receiver
            .on_stream_frame(stream(100, 100, false), &mut connection)
            .unwrap();
        assert_eq!(connection.used(), v(200));
        assert_eq!(receiver.parts().buffer.held_len(), 0);
    }

    #[test]
    fn reader_drop_keeps_an_installed_stop() {
        let (mut receiver, mut connection) = new_receiver(FollowingTermination::new(c(9)));
        receiver
            .on_stream_frame(stream(0, 100, false), &mut connection)
            .unwrap();
        receiver.stop(c(3)).unwrap();
        receiver.reader_dropped();
        assert_eq!(receiver.pending_stop(), Some(c(3)));
    }

    #[test]
    fn reader_drop_after_complete_reception_only_cleans_up() {
        let (mut receiver, mut connection) = new_receiver(FollowingTermination::new(c(9)));
        receiver
            .on_stream_frame(stream(0, 100, true), &mut connection)
            .unwrap();
        receiver.reader_dropped();
        assert_eq!(receiver.pending_stop(), None);
        assert!(receiver.parts().buffer.is_destroyed());
    }

    #[test]
    fn plain_reset_uses_late_data_and_reports_completeness() {
        let (mut receiver, mut connection) = new_receiver(FollowingTermination::new(c(9)));
        receiver
            .on_stream_frame(stream(0, 100, false), &mut connection)
            .unwrap();
        receiver
            .on_reset_stream(reset(4, 300), &mut connection)
            .unwrap();
        receiver
            .on_stream_frame(stream(100, 200, false), &mut connection)
            .unwrap();
        let (read, end) = read_all(&mut receiver);
        assert_eq!(read, data(0, 300));
        assert_eq!(end, reset_error(4, 300, 0, true));
    }

    #[test]
    fn plain_reset_stops_at_a_gap() {
        let (mut receiver, mut connection) = new_receiver(FollowingTermination::new(c(9)));
        receiver
            .on_stream_frame(stream(0, 100, false), &mut connection)
            .unwrap();
        receiver
            .on_stream_frame(stream(200, 100, false), &mut connection)
            .unwrap();
        receiver
            .on_reset_stream(reset(4, 300), &mut connection)
            .unwrap();
        let (read, end) = read_all(&mut receiver);
        assert_eq!(read, data(0, 100));
        assert_eq!(end, reset_error(4, 300, 0, false));
    }

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
