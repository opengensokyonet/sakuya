//! What the tests of stream senders share, whatever the type of their reset
//! target: senders built from the recording policies and the steps a packet
//! writer takes.
use super::StreamSender;
use super::termination::ResetOnAbandonTermination;
use bytes::{Buf, Bytes};
use sakuya_stream_v1::connection_send_credit::AtomicConnectionCreditReservation;
use sakuya_stream_v1::send::StreamEndFrame;
use sakuya_stream_v1::send::composition::SendComposition;
use sakuya_stream_v1::send::flow_control::{FullCeilingAdmission, SendFlowControlPolicy};
use sakuya_stream_v1::send::local_reset::LocalResetTarget;
use sakuya_stream_v1::send::termination::{
    SendTerminationContext, SendTerminationEvent, SendTerminationPolicy,
};
pub use sakuya_stream_v1::send::test_support::*;
use sakuya_stream_v1::send_buffer::StreamSendBuffer;
use sakuya_stream_v1::send_buffer::offset_map::OffsetMapStreamSendBuffer;
use sakuya_stream_v1::send_options::SendOptions;
use sakuya_stream_v1::send_options::destination::AnyActiveLinkPath;
use sakuya_stream_v1::send_options::urgency::Urgency;
use std::sync::Arc;

/// A sender over the recording policies, with the reset target `T`.
pub type TestSender<S, T> = StreamSender<
    SendComposition<
        OffsetMapStreamSendBuffer<Bytes, Reservation, Options>,
        RecordingFlow,
        ScriptedTermination<S, T>,
    >,
    Connection,
    TestCloseCause,
    T,
>;

pub fn scripted_sender<S, T>(
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

/// A sender whose policy never acts and completes every final size with
/// `final_size`, legal or not.
pub fn completing_sender<T: LocalResetTarget>(
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

/// A sender over the default composition whose writes go only direct.
#[allow(clippy::type_complexity)] // the composition written out
pub fn direct_sender<T>(
    connection: &Arc<Connection>,
) -> StreamSender<
    SendComposition<
        OffsetMapStreamSendBuffer<Bytes, Reservation, DirectOptions>,
        FullCeilingAdmission,
        ResetOnAbandonTermination,
    >,
    Connection,
    TestCloseCause,
    T,
    Bytes,
    DirectOptions,
>
where
    T: LocalResetTarget,
    ResetOnAbandonTermination: SendTerminationPolicy<T>,
{
    StreamSender::new(
        stream(),
        v(1000),
        SendComposition::new(
            OffsetMapStreamSendBuffer::new(),
            FullCeilingAdmission::new(),
            ResetOnAbandonTermination::new(code(0x10c), EXHAUSTED_CODE),
        ),
        Arc::clone(connection),
    )
}

/// A sender over the default composition.
#[allow(clippy::type_complexity)] // the composition written out
pub fn default_sender<T>(
    connection: &Arc<Connection>,
    peer_stream_limit: u32,
) -> StreamSender<
    SendComposition<
        OffsetMapStreamSendBuffer<
            Bytes,
            AtomicConnectionCreditReservation,
            SendOptions<Urgency, AnyActiveLinkPath>,
        >,
        FullCeilingAdmission,
        ResetOnAbandonTermination,
    >,
    Connection,
    TestCloseCause,
    T,
>
where
    T: LocalResetTarget,
    ResetOnAbandonTermination: SendTerminationPolicy<T>,
{
    StreamSender::new(
        stream(),
        v(peer_stream_limit),
        SendComposition::new(
            OffsetMapStreamSendBuffer::new(),
            FullCeilingAdmission::new(),
            ResetOnAbandonTermination::new(code(0x10c), EXHAUSTED_CODE),
        ),
        Arc::clone(connection),
    )
}

/// Writes `length` bytes that must all be accepted.
pub fn write_all<C, Lc, T>(sender: &mut StreamSender<C, Connection, Lc, T>, length: u32)
where
    T: LocalResetTarget,
    C: StreamSendBuffer<Bytes, Reservation, Options>
        + SendFlowControlPolicy<T>
        + SendTerminationPolicy<T>,
    C::WriteLimitReason: core::fmt::Debug,
    Lc: core::fmt::Debug,
{
    let mut input = source(length as usize);
    assert_eq!(
        sender.write(&mut input, &options()).unwrap(),
        written(length)
    );
    assert!(!input.has_remaining());
}

pub fn expose<C, Lc, T>(sender: &mut StreamSender<C, Connection, Lc, T>, usage_end: u32)
where
    T: LocalResetTarget,
    C: StreamSendBuffer<Bytes, Reservation, Options>
        + SendFlowControlPolicy<T>
        + SendTerminationPolicy<T>,
{
    sender.expose_usage_through(v(usage_end)).unwrap();
}

/// Prepares the end frame that is due and exposes it, as a packet writer
/// does after writing the frame; returns the frame.
pub fn send_end<C, Lc, T>(
    sender: &mut StreamSender<C, Connection, Lc, T>,
) -> StreamEndFrame<T::Frame>
where
    T: LocalResetTarget,
    C: StreamSendBuffer<Bytes, Reservation, Options>
        + SendFlowControlPolicy<T>
        + SendTerminationPolicy<T>,
{
    let prepared = sender.prepare_end_frame().expect("an end frame is due");
    let frame = *prepared;
    prepared.expose();
    frame
}

/// The end frame the guard offers, if any, without exposing it.
pub fn due_end_frame<C, Lc, T>(
    sender: &mut StreamSender<C, Connection, Lc, T>,
) -> Option<StreamEndFrame<T::Frame>>
where
    T: LocalResetTarget,
    C: StreamSendBuffer<Bytes, Reservation, Options>
        + SendFlowControlPolicy<T>
        + SendTerminationPolicy<T>,
{
    sender.prepare_end_frame().map(|prepared| *prepared)
}

/// How many ends the policy of `sender` saw committed.
pub fn end_commits<S, T>(sender: &TestSender<S, T>) -> usize
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
