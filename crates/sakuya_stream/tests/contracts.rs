//! Directed tests of contracts that the generated sequences do not reach:
//! policy violations must end the operation before any state changes, and a
//! chain of automatic actions must end.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use bytes::{BufMut, Bytes};
use sakuya_stream::connection_receive_flow::ConnectionReceiveFlowController;
use sakuya_stream::connection_send_credit::{
    AtomicConnectionCreditReservation, AtomicConnectionSendFlowController,
};
use sakuya_stream::receive::flow_control::{
    AdvertisementIntent, ReceiveFlowControlPolicy, ReceiveFlowEvent, ReceiveFlowView,
};
use sakuya_stream::receive::termination::{
    FollowingTermination, ReceiveTerminationPolicy, TerminationDecision, TerminationEvent,
    TerminationView,
};
use sakuya_stream::receive::{StreamFrame, StreamReceiver};
use sakuya_stream::receive_buffer::fragmented::FragmentedStreamReceiveBuffer;
use sakuya_stream::receive_buffer::{StreamDataInput, StreamReceiveBuffer};
use sakuya_stream::send::composition::SendComposition;
use sakuya_stream::send::flow_control::{
    AdmissionGuard, FullCeilingAdmission, SendFlowContext, SendFlowControlPolicy,
    StreamCreditEvent, WriteAttempt,
};
use sakuya_stream::send::termination::{
    FinalSizeRequest, SendTerminationContext, SendTerminationEvent, SendTerminationPolicy,
    TerminationAction,
};
use sakuya_stream::send::write::WriteOutcome;
use sakuya_stream::send::{EndFrame, SendEndState, SendTerminalState, StreamSender};
use sakuya_stream::send_buffer::ResetRetention;
use sakuya_stream::send_buffer::offset_map::OffsetMapStreamSendBuffer;
use sakuya_wire::application_error::ApplicationErrorCode;
use sakuya_wire::stream_id::StreamId;
use sakuya_wire::var_int::VarInt;

fn v(value: u32) -> VarInt {
    VarInt::from_u32(value)
}

fn code(value: u32) -> ApplicationErrorCode {
    ApplicationErrorCode::new(v(value))
}

/// A termination policy that answers everything through a closure.
struct Answering<F>(F);

impl<F> SendTerminationPolicy for Answering<F>
where
    F: FnMut(&SendTerminationEvent, &SendTerminationContext) -> TerminationAction<()>,
{
    type WriteLimitReason = ();

    fn on_termination_event(
        &mut self,
        event: SendTerminationEvent,
        context: &SendTerminationContext,
    ) -> TerminationAction<()> {
        (self.0)(&event, context)
    }

    fn complete_final_size(
        &mut self,
        request: FinalSizeRequest,
        _: &SendTerminationContext,
    ) -> VarInt {
        request.maximum.saturating_add(v(1))
    }
}

type Composition<F> = SendComposition<
    OffsetMapStreamSendBuffer<AtomicConnectionCreditReservation>,
    FullCeilingAdmission,
    Answering<F>,
>;

type Sender<F> = StreamSender<Composition<F>, AtomicConnectionSendFlowController>;

fn sender<F>(connection: &Arc<AtomicConnectionSendFlowController>, answer: F) -> Sender<F>
where
    F: FnMut(&SendTerminationEvent, &SendTerminationContext) -> TerminationAction<()>,
{
    StreamSender::new(
        StreamId::from_var_int(v(0)),
        v(1000),
        true,
        SendComposition::new(
            OffsetMapStreamSendBuffer::new(),
            FullCeilingAdmission::new(),
            Answering(answer),
        ),
        Arc::clone(connection),
    )
}

fn write<F>(stream: &mut Sender<F>, len: usize)
where
    F: FnMut(&SendTerminationEvent, &SendTerminationContext) -> TerminationAction<()>,
{
    let mut source = Bytes::from(vec![7; len]);
    assert!(matches!(
        stream.write(&mut source),
        Ok(WriteOutcome::Written(_))
    ));
}

#[test]
fn an_illegal_automatic_reset_changes_nothing_before_the_panic() {
    let connection = Arc::new(AtomicConnectionSendFlowController::new(v(1000)));
    let mut stream = sender(&connection, |event, context| match event {
        SendTerminationEvent::StopSendingReceived { error_code } => {
            TerminationAction::Reset {
                error_code: *error_code,
                // Beyond the written end.
                final_size: context.written_end.saturating_add(v(1)),
            }
        }
        _ => TerminationAction::Keep,
    });
    write(&mut stream, 100);
    let reserved = connection.reserved();
    let outcome = catch_unwind(AssertUnwindSafe(|| stream.on_stop_sending(code(1))));
    assert!(outcome.is_err(), "the violation panics");
    assert_eq!(stream.end_state(), SendEndState::Open);
    assert_eq!(stream.reliable_size(), v(100));
    assert_eq!(stream.composition().buffer.retained().count(), 1);
    assert_eq!(connection.reserved(), reserved, "no credit was released");
    assert_eq!(
        stream.composition().buffer.retention(),
        None::<ResetRetention>
    );
}

#[test]
fn an_out_of_range_final_size_changes_nothing_before_the_panic() {
    let connection = Arc::new(AtomicConnectionSendFlowController::new(v(1000)));
    let mut stream = sender(&connection, |_, _| TerminationAction::Keep);
    write(&mut stream, 100);
    let outcome = catch_unwind(AssertUnwindSafe(|| stream.reset(code(1))));
    assert!(outcome.is_err(), "the violation panics");
    assert_eq!(stream.end_state(), SendEndState::Open);
    assert_eq!(connection.reserved(), v(100));
    assert_eq!(stream.composition().buffer.visibility().covered(), v(100));
}

/// A flow-control policy that grants at a stale offset.
struct StaleOffset;

impl SendFlowControlPolicy for StaleOffset {
    fn admit_write(
        &mut self,
        attempt: &WriteAttempt,
        _: &SendFlowContext,
    ) -> Option<AdmissionGuard> {
        let mut stale = *attempt;
        stale.offset = attempt.offset.saturating_add(v(1));
        AdmissionGuard::new(&stale, attempt.ceiling).ok()
    }

    fn on_admission_used(&mut self, _: AdmissionGuard, _: VarInt, _: &SendFlowContext) {}

    fn on_admission_abandoned(&mut self, _: AdmissionGuard, _: &SendFlowContext) {}

    fn on_flow_event(&mut self, _: StreamCreditEvent, _: &SendFlowContext) {}

    fn wants_stream_data_blocked(&self, _: &SendFlowContext) -> bool {
        false
    }
}

#[test]
fn a_stale_guard_consumes_nothing_before_the_panic() {
    let connection = Arc::new(AtomicConnectionSendFlowController::new(v(1000)));
    let mut stream = StreamSender::new(
        StreamId::from_var_int(v(0)),
        v(1000),
        true,
        SendComposition::new(
            OffsetMapStreamSendBuffer::new(),
            StaleOffset,
            Answering(|_: &SendTerminationEvent, _: &SendTerminationContext| {
                TerminationAction::<()>::Keep
            }),
        ),
        Arc::clone(&connection),
    );
    let mut source = Bytes::from(vec![7; 10]);
    let outcome = catch_unwind(AssertUnwindSafe(|| stream.write(&mut source).is_ok()));
    assert!(outcome.is_err(), "the violation panics");
    assert_eq!(source.len(), 10, "input stays with the caller");
    assert_eq!(connection.reserved(), VarInt::ZERO);
    assert_eq!(stream.written_end(), VarInt::ZERO);
}

/// A policy that repeats the state in effect after every event: the chain of
/// receipts must end, because repeating changes nothing.
#[test]
fn repeated_automatic_decisions_end_the_chain() {
    let mut events = 0_u32;
    let connection = Arc::new(AtomicConnectionSendFlowController::new(v(1000)));
    let mut stream = sender(&connection, move |_, context| {
        events += 1;
        assert!(events < 64, "the chain of receipts does not end");
        match context.end_state {
            SendEndState::Open | SendEndState::Closed { .. } => TerminationAction::Close,
            SendEndState::Reset {
                error_code,
                final_size,
                ..
            } => TerminationAction::Reset {
                error_code,
                final_size,
            },
            SendEndState::ResetAt { target, .. } => TerminationAction::ResetAt(target),
        }
    });
    write(&mut stream, 10);
    assert!(
        matches!(stream.end_state(), SendEndState::Closed { final_size, .. } if final_size == v(10))
    );
    stream.reset(code(3)).unwrap();
    assert!(matches!(stream.end_state(), SendEndState::Reset { .. }));
}

/// RFC 9000 §3.1: "Reset Recvd" is reached from "Reset Sent" only. A stream
/// that was closed and never reset cannot be in it.
#[test]
fn a_terminal_reset_needs_a_reset() {
    let connection = Arc::new(AtomicConnectionSendFlowController::new(v(1000)));
    let mut stream = sender(&connection, |_, _| TerminationAction::Keep);
    write(&mut stream, 10);
    stream.close().unwrap();
    let fin = stream.prepare_end_frame().unwrap();
    assert!(matches!(*fin, EndFrame::Fin(_)));
    fin.expose();
    assert!(
        stream
            .enter_terminal_state(SendTerminalState::ResetRecvd)
            .is_err()
    );
}

/// The base composition of the receive direction.
struct BaseReceive {
    buffer: FragmentedStreamReceiveBuffer,
    termination: FollowingTermination,
    events: Vec<TerminationEvent>,
}

impl StreamReceiveBuffer for BaseReceive {
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

    fn is_received(&self, range: core::ops::Range<VarInt>) -> bool {
        self.buffer.is_received(range)
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

impl ReceiveFlowControlPolicy for BaseReceive {
    fn on_receive_flow_event(&mut self, _: ReceiveFlowEvent, _: &ReceiveFlowView) {}

    fn advertisement_intent(&self) -> AdvertisementIntent {
        AdvertisementIntent::Withhold
    }
}

impl ReceiveTerminationPolicy for BaseReceive {
    type Reason = core::convert::Infallible;

    fn on_termination_event(
        &mut self,
        event: TerminationEvent,
        view: &TerminationView,
    ) -> TerminationDecision<Self::Reason> {
        self.events.push(event);
        self.termination.on_termination_event(event, view)
    }
}

/// RFC 9000 §3.2 leaves "Size Known" for "Data Recvd" once all data arrived,
/// and §3.5 makes `STOP_SENDING` unnecessary from then on. Whether all data
/// arrived cannot be answered from the highest received end alone, so the
/// buffer must keep tracking which ranges arrived after it stopped keeping
/// payload.
#[test]
#[ignore = "known defect: a receiver whose buffer was destroyed does not learn that all data arrived"]
fn reception_completes_after_the_reader_is_gone() {
    let mut connection = ConnectionReceiveFlowController::new(v(1000));
    let mut receiver = StreamReceiver::new(
        BaseReceive {
            buffer: FragmentedStreamReceiveBuffer::new(),
            termination: FollowingTermination::new(code(9)),
            events: Vec::new(),
        },
        v(1000),
    );
    let frame = |offset: u32, len: usize, fin| StreamFrame {
        offset: v(offset),
        data: Bytes::from(vec![1; len]),
        fin,
    };
    receiver
        .on_stream_frame(frame(0, 50, false), &mut connection)
        .unwrap();
    receiver.reader_dropped();
    assert_eq!(receiver.pending_stop(), Some(code(9)));
    receiver
        .on_stream_frame(frame(50, 50, true), &mut connection)
        .unwrap();
    assert!(
        receiver
            .parts()
            .events
            .contains(&TerminationEvent::DataComplete)
    );
    assert_eq!(
        receiver.pending_stop(),
        None,
        "STOP_SENDING is unnecessary now"
    );
}
