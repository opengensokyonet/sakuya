//! What both stream sets of version 1 keep, whatever they keep it under:
//! the sending and the receiving part of a stream with the tickets of the
//! intents of their frames ([`SendingEnd`], [`ReceivingEnd`]), the
//! connection's receive flow controller with its MAX_DATA
//! ([`ConnectionReceive`]), and the state of the set as a whole
//! ([`SetState`]), with how each brings its intents to what is due and
//! writes its frames.
//!
//! [`LockedStreamSet`](super::locked::LockedStreamSet) keeps them under
//! its locks, [`OwnedStreamSet`](super::owned::OwnedStreamSet) directly;
//! the logic is written once here, over whatever its intents are published
//! through ([`IntentPublisher`]). What happens around them, where the parts
//! are found and when a stream is reclaimed, is each set's.

use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};
use core::{
    num::NonZeroUsize,
    task::{Poll, Waker},
};
use sakuya_stream_v1::resets::StreamResets;
use sakuya_wire_v1::frame::write::{DelimitedFrame, InFlightClass};

use bytes::{Buf, Bytes};
use sakuya_stream_v1::{
    connection::LayerEnd,
    connection_receive_flow::ConnectionReceiveFlowController,
    connection_send_credit::{
        AtomicConnectionCreditReservation, AtomicConnectionSendFlowController,
        data_blocked::DataBlockedSignal,
    },
    receive::{
        ReceiveStreamState, StreamReceiver,
        composition::ReceiveComposition,
        flow_control::SlidingWindowAdvertisement,
        read::{ReadError, ReadOutcome},
        termination::{FollowingTermination, ReceiveTerminationPolicy},
    },
    receive_buffer::{StreamReceiveBuffer, fragmented::FragmentedStreamReceiveBuffer},
    send::{
        SendEndState, SendStreamState, SendTerminalState, StreamEndFrame, StreamResetError,
        StreamSender,
        composition::SendComposition,
        finish::CloseError,
        flow_control::FullCeilingAdmission,
        local_reset::LocalResetTarget,
        termination::SendTerminationPolicy,
        write::{FlushError, WriteError, WriteOutcome},
    },
    send_buffer::offset_map::OffsetMapStreamSendBuffer,
    send_options::{
        SendOptions,
        destination::AnyActiveLinkPath,
        urgency::{SendUrgency, Urgency},
    },
    stream_id_ledger::{InitialMaxStreams, StreamIdLedger},
};
use sakuya_wire_v1::{
    application_error::ApplicationErrorCode,
    frame::{
        data_blocked::DataBlockedFrame, max_data::MaxDataFrame,
        max_stream_data::MaxStreamDataFrame, max_streams::MaxStreamsFrame,
        stop_sending::StopSendingFrame, stream::StreamFrame,
        stream_data_blocked::StreamDataBlockedFrame, streams_blocked::StreamsBlockedFrame,
    },
    role::Role,
    stream_count::StreamCount,
    stream_id::{Directionality, Initiator, StreamId},
};
use sakuya_wire_v1::{
    frame::NoLength,
    var_int::{VarInt, VarIntField, VarIntWidth},
};
use smallvec::SmallVec;

use super::{
    FlowControlParameters, StreamSetFacts,
    send::{
        DataBlockedSummary, MaxDataSummary, MaxStreamDataSummary, MaxStreamsSummary,
        ResetStreamSummary, StopSendingSummary, StreamDataBlockedSummary, StreamIntent,
        StreamSetFrameSummary, StreamSummary, StreamsBlockedSummary, shortest_stream_frame,
    },
};
use crate::{
    feedback::InjectSummary,
    send_strategy::{IntentPublisher, SendIntent},
    v1::{
        application_handles::{connection::wake_all, stream::AllAcknowledgedError},
        events::{
            DataLocation, DataMovedAdditionalInfo, EventInitiator, SharedEvents, StreamDataMoved,
            StreamStateChange,
        },
    },
    write::{OpenPacket, PacketPosition, PacketWriting, SummaryOf, Supplied},
};

/// The marker of the data of the default set: the send parameters `P` to
/// any active link path, the one destination of this set.
pub(super) type MarkerOf<P> = SendOptions<P, AnyActiveLinkPath>;

/// The composition of a sending part of the default set: the default send
/// buffer over [`Bytes`] with the marker of the parameters `P`, the default
/// flow control policy, and the termination policy of the reset kind `Rs`.
pub(super) type SendCompositionOf<Rs, P> = SendComposition<
    OffsetMapStreamSendBuffer<Bytes, AtomicConnectionCreditReservation, MarkerOf<P>>,
    FullCeilingAdmission,
    <Rs as StreamResets>::SendTermination,
>;

/// The sending part of a stream of the default set: its composition
/// ([`SendCompositionOf`]), sharing the connection's atomic send flow
/// controller, with the resets of the reset kind `Rs`.
pub(super) type SenderOf<Lc, Rs, P> = StreamSender<
    SendCompositionOf<Rs, P>,
    AtomicConnectionSendFlowController,
    Lc,
    <Rs as StreamResets>::Local,
    Bytes,
    MarkerOf<P>,
>;

/// The receiving part of a stream of the default set: the default
/// composition, with the resets of the reset kind `Rs`.
pub(super) type ReceiverOf<Lc, Rs> = StreamReceiver<
    ReceiveComposition<
        FragmentedStreamReceiveBuffer,
        SlidingWindowAdvertisement,
        FollowingTermination,
    >,
    Lc,
    <Rs as StreamResets>::Remote,
>;

/// The composition of a new sending part of the default set: an empty
/// buffer, and the codes of the resets its policies send by themselves.
pub(super) fn send_composition<Rs: StreamResets, P>(
    send_abandon_code: ApplicationErrorCode,
    destination_exhausted_code: ApplicationErrorCode,
) -> SendCompositionOf<Rs, P> {
    SendComposition::new(
        OffsetMapStreamSendBuffer::new(),
        FullCeilingAdmission::new(),
        Rs::send_termination(send_abandon_code, destination_exhausted_code),
    )
}

/// A part of a stream that tells whether it is done: its protocol duties
/// are over and the application has its last result of it, or gave it up.
/// Once done, a part stays done, and none of its frames is due any more.
pub(super) trait PartDone {
    /// Whether the part is done.
    fn is_done(&self) -> bool;
}

/// A part of a stream whose state the events give: its state machine's
/// state (RFC 9000 §3.1, §3.2).
pub(super) trait PartState {
    /// The states of the part.
    type State: Copy + PartialEq;

    /// The state the part is in.
    fn state(&self) -> Self::State;

    /// The change of a part of this kind from `old` to `new`.
    fn change(old: Option<Self::State>, new: Option<Self::State>) -> StreamStateChange;
}

// ---- the intents a component keeps ----

/// The ticket of an intent, with the intent as it was published or last
/// resized.
pub(super) struct Ticketed<K, P> {
    pub(super) ticket: K,
    pub(super) intent: StreamIntent<P>,
}

/// Bring the intent kept in `slot` to `wanted`, the intent due now if any:
/// publish one through `publish` where there is none, resize it where only
/// the room it needs changed, publish it again where its parameters
/// changed, and withdraw it where nothing is due. `publish` is the set's
/// intake, or the strategy's publisher placed for the stream intents: the
/// logic is the same over either.
pub(super) fn sync_ticket<K, P, H>(
    slot: &mut Option<Ticketed<K, P>>,
    wanted: Option<StreamIntent<P>>,
    publish: &mut H,
) where
    P: Clone + PartialEq,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
{
    *slot = match (slot.take(), wanted) {
        (None, None) => None,
        (Some(kept), None) => {
            publish.withdraw(kept.ticket);
            None
        }
        (Some(mut kept), Some(wanted)) if same_but_for_room(&kept.intent, &wanted) => {
            if kept.intent != wanted {
                publish.resize(&mut kept.ticket, wanted.min_lengths());
                kept.intent = wanted;
            }
            Some(kept)
        }
        (kept, Some(wanted)) => {
            if let Some(kept) = kept {
                publish.withdraw(kept.ticket);
            }
            Some(Ticketed {
                ticket: publish.publish_to(wanted.clone(), AnyActiveLinkPath),
                intent: wanted,
            })
        }
    };
}

/// Whether `kept` and `wanted` are the same intent but for the room they
/// need: the same key and, for STREAM, the same parameters.
pub(super) fn same_but_for_room<P: PartialEq>(
    kept: &StreamIntent<P>,
    wanted: &StreamIntent<P>,
) -> bool {
    match (kept, wanted) {
        (
            StreamIntent::Stream {
                stream_id: kept_id,
                parameters: kept_parameters,
                ..
            },
            StreamIntent::Stream {
                stream_id: wanted_id,
                parameters: wanted_parameters,
                ..
            },
        ) => kept_id == wanted_id && kept_parameters == wanted_parameters,
        _ => kept.key() == wanted.key(),
    }
}

/// Withdraw the intent kept in `slot`, if any, through `publish`: the
/// strategy ended it, and withdrawing what it ended changes nothing more.
pub(super) fn forget_ticket<K, P, H>(slot: &mut Option<Ticketed<K, P>>, publish: &mut H)
where
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
{
    if let Some(kept) = slot.take() {
        publish.withdraw(kept.ticket);
    }
}

/// The frame of the intent kept in `slot` was written: the plan that gave
/// it consumes the intent, and its ticket goes through `publish` without
/// withdrawing it.
pub(super) fn release_ticket<K, P, H>(slot: &mut Option<Ticketed<K, P>>, publish: &mut H)
where
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
{
    if let Some(kept) = slot.take() {
        publish.release_written(kept.ticket);
    }
}

/// Write `frame` into `packet` with `summary`; whether it fitted.
pub(super) fn write_frame<W, F, S, Q, Idx>(
    packet: &mut OpenPacket<W, InFlightClass, Q>,
    frame: F,
    summary: S,
) -> bool
where
    W: PacketWriting,
    F: DelimitedFrame<Class = InFlightClass>,
    SummaryOf<W>: InjectSummary<S, Idx>,
{
    packet
        .write_frame(frame, <SummaryOf<W>>::inject_summary(summary))
        .is_ok()
}

/// The wakers of those who wait on one part of a stream (`PartWaiters`):
/// one task most often, and several when the holders of a shared
/// credential wait at once, each of which is woken.
pub(super) type PartWaiters = SmallVec<[Waker; 1]>;

/// Keep `waker` among `waiters`, unless one there wakes the same task.
pub(super) fn keep_part_waiter(waiters: &mut PartWaiters, waker: &Waker) {
    if !waiters.iter().any(|kept| kept.will_wake(waker)) {
        waiters.push(waker.clone());
    }
}

/// Wake each of `waiters`.
pub(super) fn wake_part_waiters(waiters: PartWaiters) {
    for waker in waiters {
        waker.wake();
    }
}

// ---- the sending part ----

impl<Lc, K, Rs: StreamResets, P> SendingEnd<Lc, K, Rs, P> {
    /// Wake the writers that wait: what they wait for may have come.
    pub(super) fn wake_writer(&mut self) {
        wake_part_waiters(core::mem::take(&mut self.writer));
    }
}

impl<Lc, K, Rs: StreamResets, P> ReceivingEnd<Lc, K, Rs, P> {
    /// Wake the readers that wait: data or an end may have come.
    pub(super) fn wake_reader(&mut self) {
        wake_part_waiters(core::mem::take(&mut self.reader));
    }
}

/// Where a stream's FIN stands: not sent, in flight, lost, or acknowledged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EndFrameDelivery {
    /// Not sent.
    NotSent,
    /// Sent, neither acknowledged nor lost.
    Sent,
    /// Its last packet was lost; it waits to be sent again.
    Lost,
    /// Acknowledged.
    Acknowledged,
}

impl EndFrameDelivery {
    /// Whether it waits to be sent, first or again.
    pub(super) fn waits(self) -> bool {
        matches!(self, Self::NotSent | Self::Lost)
    }

    /// A packet with it was lost: unless it was acknowledged, it waits to be
    /// sent again.
    pub(super) fn lost(&mut self) {
        if *self != Self::Acknowledged {
            *self = Self::Lost;
        }
    }
}

/// The sending part of a stream with the tickets of the intents of its
/// frames: its data and FIN for its one destination, its reset frame and
/// its STREAM_DATA_BLOCKED; and where its FIN and its reset frame stand.
///
/// The reset frame is the one of the target in effect
/// ([`LocalResetTarget::frame`]): RESET_STREAM, or another kind's, such as
/// RESET_STREAM_AT. `reset_written` is the target whose frame was written
/// last, and `reset_frame` where that frame stands; a target that changed
/// since, as a reset at a reliable size may lower its size, has its frame
/// due again.
///
/// The waker of the writer is woken when what it waits for may have come:
/// room for its writes, or the end of the stream's sending. A write held
/// back by the connection's credit keeps it too, for the layer's end, and
/// is woken for credit by the send flow controller.
pub(super) struct SendingEnd<Lc, K, Rs: StreamResets, P> {
    pub(super) sender: SenderOf<Lc, Rs, P>,
    pub(super) data: Option<Ticketed<K, P>>,
    pub(super) reset: Option<Ticketed<K, P>>,
    pub(super) blocked: Option<Ticketed<K, P>>,
    pub(super) fin: EndFrameDelivery,
    pub(super) reset_written: Option<Rs::Local>,
    pub(super) reset_frame: EndFrameDelivery,
    pub(super) writer: PartWaiters,
}

impl<Lc, K, Rs: StreamResets, P> SendingEnd<Lc, K, Rs, P>
where
    P: Clone + PartialEq + Default + SendUrgency,
{
    pub(super) fn new(sender: SenderOf<Lc, Rs, P>) -> Self {
        Self {
            sender,
            data: None,
            reset: None,
            blocked: None,
            fin: EndFrameDelivery::NotSent,
            reset_written: None,
            reset_frame: EndFrameDelivery::NotSent,
            writer: PartWaiters::new(),
        }
    }

    /// Whether frames are still sent: the layer has not ended and the part
    /// is not done.
    pub(super) fn sends(&self) -> bool {
        !self.sender.is_connection_closed() && self.sender.terminal_state().is_none()
    }

    /// The final size of a close whose FIN waits to be sent.
    pub(super) fn fin_due(&self) -> Option<VarInt> {
        match self.sender.end_state() {
            SendEndState::Closed { final_size, .. } if self.sends() && self.fin.waits() => {
                Some(final_size)
            }
            SendEndState::Open | SendEndState::Closed { .. } | SendEndState::Reset { .. } => None,
        }
    }

    /// The reset whose frame waits to be sent: its frame was not written,
    /// or was lost, or the target changed since it was.
    pub(super) fn reset_due(&self) -> Option<Rs::Local> {
        match self.sender.end_state() {
            SendEndState::Reset { target, .. }
                if self.sends()
                    && (self.reset_written != Some(target) || self.reset_frame.waits()) =>
            {
                Some(target)
            }
            SendEndState::Open | SendEndState::Closed { .. } | SendEndState::Reset { .. } => None,
        }
    }

    /// The intent of the data and FIN due now: one byte of the next data,
    /// with its parameters, or else the FIN alone.
    pub(super) fn data_due(&self) -> Option<StreamIntent<P>> {
        if !self.sends() {
            return None;
        }
        let stream_id = self.sender.stream_id();
        if let Some(next) = self.sender.next_segment(&AnyActiveLinkPath) {
            return Some(StreamIntent::Stream {
                stream_id,
                parameters: next.marker.parameters().clone(),
                min: shortest_stream_frame(stream_id, next.offset, true),
            });
        }
        let final_size = self.fin_due()?;
        Some(StreamIntent::Stream {
            stream_id,
            parameters: P::default(),
            min: shortest_stream_frame(stream_id, final_size, false),
        })
    }

    /// Bring the intents of this part to what is due now; see the
    /// [module documentation](self).
    pub(super) fn sync_intents<
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    >(
        &mut self,
        publish: &mut H,
    ) {
        let stream_id = self.sender.stream_id();
        let data = self.data_due();
        sync_ticket(&mut self.data, data, publish);
        let reset = self.reset_due().map(|target| StreamIntent::ResetStream {
            stream_id,
            len: target.frame(stream_id).encoded_len(),
        });
        sync_ticket(&mut self.reset, reset, publish);
        let blocked =
            self.sender
                .stream_data_blocked_limit()
                .map(|limit| StreamIntent::StreamDataBlocked {
                    stream_id,
                    len: stream_data_blocked_frame(stream_id, limit).encoded_len(),
                });
        sync_ticket(&mut self.blocked, blocked, publish);
    }

    /// Write STREAM frames into `packet`: as much of the next data as fits,
    /// with the FIN when it ends at the final size, or the FIN alone; the
    /// data and the FIN are first exposed before it returns.
    pub(super) fn write_stream<W, Q, Idx>(
        &mut self,
        urgency: Urgency,
        mut packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<StreamSummary, Idx>,
        Q: PacketPosition,
    {
        if !self.sends() {
            return Supplied::Open(packet);
        }
        let stream_id = self.sender.stream_id();
        let id_field = VarIntField::shortest(stream_id);
        let fin_due = self.fin_due();
        let Some(next) = self.sender.next_segment(&AnyActiveLinkPath) else {
            let Some(final_size) = fin_due.filter(|_| P::default().urgency() == urgency) else {
                return Supplied::Open(packet);
            };
            let (supplied, written) = write_stream_frame(
                packet,
                id_field,
                Bytes::new(),
                Q::LAST,
                StreamSummary {
                    stream_id,
                    offset: final_size,
                    len: 0,
                    fin: true,
                },
            );
            if written {
                self.fin_exposed();
            }
            return supplied;
        };
        if next.marker.parameters().urgency() != urgency {
            return Supplied::Open(packet);
        }
        let mut offset = next.offset;
        loop {
            let offset_field = offset_field(offset);
            let room = packet.remaining();
            let max_len = if Q::LAST {
                StreamFrame::<Bytes, NoLength>::max_data_len(id_field, offset_field, room)
            } else {
                StreamFrame::<Bytes, VarIntWidth>::max_data_len(id_field, offset_field, room)
            };
            let Some(max_len) = max_len.filter(|&len| len > 0) else {
                return Supplied::Open(packet);
            };
            let Some(selected) = self.sender.select(&AnyActiveLinkPath, max_len) else {
                return Supplied::Open(packet);
            };
            let len = selected.bytes.len();
            // invariant: the selected data lies below the written end, a `VarInt`
            let end = VarInt::try_from(selected.offset.get().saturating_add(len as u64))
                .unwrap_or(VarInt::MAX);
            let fin = fin_due == Some(end);
            let summary = StreamSummary {
                stream_id,
                offset: selected.offset,
                len,
                fin,
            };
            // Once the room is full, skip looking up the next segment.
            let following = if len < max_len
                && let Some(StreamIntent::Stream { parameters, .. }) =
                    self.data.as_ref().map(|ticket| &ticket.intent)
            {
                self.sender
                    .next_segment(&AnyActiveLinkPath)
                    .filter(|next| next.marker.parameters() == parameters)
                    .map(|next| next.offset)
            } else {
                None
            };
            // A last-position source may write a delimited frame first if it
            // leaves space for at least one byte of the following segment.
            let close = Q::LAST
                && !following.is_some_and(|next| {
                    room.checked_sub(shortest_stream_frame(stream_id, next, true).as_last)
                        .and_then(|room| {
                            StreamFrame::<Bytes, VarIntWidth>::max_data_len(
                                id_field,
                                offset_field,
                                room,
                            )
                        })
                        .is_some_and(|capacity| len <= capacity)
                });
            let (supplied, written) =
                write_stream_frame(packet, id_field, selected.bytes, close, summary);
            // invariant: the length was measured against the room
            debug_assert!(written, "the data was measured against the room");
            if written {
                let exposed = self.sender.expose_usage_through(end);
                // invariant: the data was written into the stream and selected
                // from it, within its final size
                debug_assert!(exposed.is_ok(), "selected data is exposed: {exposed:?}");
                if fin {
                    self.fin_exposed();
                }
            } else {
                // the data waits again, as if its frame were lost
                let _ = self.sender.on_data_lost(selected.offset..end);
                return supplied;
            }
            match (supplied, following) {
                (Supplied::Open(open), Some(next)) => {
                    packet = open;
                    offset = next;
                }
                (supplied, _) => return supplied,
            }
        }
    }

    /// A frame with the FIN was written: its final size is first exposed if
    /// it was not yet, and the FIN is in flight.
    pub(super) fn fin_exposed(&mut self) {
        if let Some(prepared) = self.sender.prepare_end_frame()
            && matches!(*prepared, StreamEndFrame::Fin(_))
        {
            prepared.expose();
        }
        self.fin = EndFrameDelivery::Sent;
    }

    /// Write the reset frame of the reset in effect into `packet`, its final
    /// size first exposed if it was not yet.
    pub(super) fn write_reset_stream<H, W, Q, Idx>(
        &mut self,
        publish: &mut H,
        mut packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<ResetStreamSummary, Idx>,
    {
        let Some(target) = self.reset_due() else {
            return Supplied::Open(packet);
        };
        let stream_id = self.sender.stream_id();
        let summary = ResetStreamSummary {
            stream_id,
            final_size: target.final_size(),
            reliable_size: target.reliable_size(),
        };
        if write_frame(&mut packet, target.frame(stream_id), summary) {
            if let Some(prepared) = self.sender.prepare_end_frame()
                && matches!(*prepared, StreamEndFrame::Reset(_))
            {
                prepared.expose();
            }
            self.reset_written = Some(target);
            self.reset_frame = EndFrameDelivery::Sent;
            release_ticket(&mut self.reset, publish);
        }
        Supplied::Open(packet)
    }

    /// Write the STREAM_DATA_BLOCKED frame of the limit in effect.
    pub(super) fn write_stream_data_blocked<H, W, Q, Idx>(
        &mut self,
        publish: &mut H,
        mut packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<StreamDataBlockedSummary, Idx>,
    {
        let Some(limit) = self.sender.stream_data_blocked_limit() else {
            return Supplied::Open(packet);
        };
        let stream_id = self.sender.stream_id();
        let summary = StreamDataBlockedSummary {
            stream_id,
            maximum_stream_data: limit,
        };
        if write_frame(
            &mut packet,
            stream_data_blocked_frame(stream_id, limit),
            summary,
        ) {
            self.sender.on_stream_data_blocked_sent(limit);
            release_ticket(&mut self.blocked, publish);
        }
        Supplied::Open(packet)
    }

    /// The data and FIN of `summary` were acknowledged: once all data and
    /// the FIN of a stream that was closed, and not reset, are, the part is
    /// done (RFC 9000 §3.1). A stream that was reset waits for its reset to
    /// be acknowledged instead (RFC 9000 §13.3), and one reset at a reliable
    /// size also for the data below it
    /// ([`reset_settled`](Self::reset_settled)).
    pub(super) fn stream_delivered(&mut self, summary: StreamSummary) {
        if let Some(range) = data_range(summary.offset, summary.len) {
            let _ = self.sender.on_data_acknowledged(range);
        }
        if summary.fin {
            self.fin = EndFrameDelivery::Acknowledged;
        }
        let closed = matches!(self.sender.end_state(), SendEndState::Closed { .. });
        let all_acknowledged = self.sender.composition().buffer.retained().next().is_none();
        if closed && self.fin == EndFrameDelivery::Acknowledged && all_acknowledged {
            let _ = self
                .sender
                .enter_terminal_state(SendTerminalState::DataRecvd);
        }
        self.reset_settled();
    }

    /// The reset frame of `summary` was acknowledged: it counts when it is
    /// the frame of the target in effect, as written last, with its final
    /// size and reliable size; an earlier frame with a larger reliable size
    /// does not (draft-ietf-quic-reliable-stream-reset §5.3). Then the part
    /// may be done ([`reset_settled`](Self::reset_settled)).
    pub(super) fn reset_delivered(&mut self, summary: ResetStreamSummary) {
        let SendEndState::Reset { target, .. } = self.sender.end_state() else {
            return;
        };
        if self.reset_written == Some(target)
            && summary.final_size == target.final_size()
            && summary.reliable_size == target.reliable_size()
        {
            self.reset_frame = EndFrameDelivery::Acknowledged;
            self.reset_settled();
        }
    }

    /// Once the reset frame of the target in effect is acknowledged, the
    /// part reaches the state the target's acknowledgment leads to
    /// ([`LocalResetTarget::acknowledged_state`]): "Reset Recvd" for
    /// RESET_STREAM; for a reset that keeps a reliable size, "Data Recvd"
    /// once every byte below that size is acknowledged too
    /// (draft-ietf-quic-reliable-stream-reset §5.3).
    pub(super) fn reset_settled(&mut self) {
        let SendEndState::Reset { target, .. } = self.sender.end_state() else {
            return;
        };
        if self.reset_written != Some(target) || self.reset_frame != EndFrameDelivery::Acknowledged
        {
            return;
        }
        let state = target.acknowledged_state();
        let reliable_size = target.reliable_size();
        let prefix_acknowledged = self
            .sender
            .composition()
            .buffer
            .retained()
            .all(|(offset, _)| offset >= reliable_size);
        if state == SendTerminalState::ResetRecvd || prefix_acknowledged {
            let _ = self.sender.enter_terminal_state(state);
        }
    }

    /// The data and FIN of `summary` were lost: the data waits to be sent
    /// again, and the FIN unless it was acknowledged.
    pub(super) fn stream_lost(&mut self, summary: StreamSummary) {
        if let Some(range) = data_range(summary.offset, summary.len) {
            let _ = self.sender.on_data_lost(range);
        }
        if summary.fin {
            self.fin.lost();
        }
    }
}

/// A sending part is done in "Data Recvd" or "Reset Recvd" (RFC 9000
/// §3.1): what it sent, its FIN or its reset, was acknowledged.
impl<Lc, K, Rs: StreamResets, P> PartDone for SendingEnd<Lc, K, Rs, P> {
    fn is_done(&self) -> bool {
        self.sender.terminal_state().is_some()
    }
}

/// A sending part is in its sender's state.
impl<Lc, K, Rs: StreamResets, P> PartState for SendingEnd<Lc, K, Rs, P>
where
    P: Clone + PartialEq + Default + SendUrgency,
{
    type State = SendStreamState;

    fn state(&self) -> SendStreamState {
        self.sender.send_state()
    }

    fn change(old: Option<SendStreamState>, new: Option<SendStreamState>) -> StreamStateChange {
        StreamStateChange::Sending { old, new }
    }
}

/// The STREAM_DATA_BLOCKED frame of `stream_id` at `limit`.
pub(super) fn stream_data_blocked_frame(
    stream_id: StreamId,
    limit: VarInt,
) -> StreamDataBlockedFrame {
    StreamDataBlockedFrame::new(
        VarIntField::shortest(stream_id),
        VarIntField::shortest(limit),
    )
}

/// The Offset field of data at `offset`: none at 0.
pub(super) fn offset_field(offset: VarInt) -> Option<VarIntField<VarInt>> {
    (offset > VarInt::ZERO).then(|| VarIntField::shortest(offset))
}

/// The range of `len` bytes at `offset`, if any.
pub(super) fn data_range(offset: VarInt, len: usize) -> Option<core::ops::Range<VarInt>> {
    let end = VarInt::try_from(offset.get().checked_add(len as u64)?).ok()?;
    (end > offset).then_some(offset..end)
}

/// Write a STREAM frame of `data` at `offset` into `packet`: without a
/// Length field, closing the packet, when it is the last, otherwise with
/// one. Hands back the packet and whether the frame fitted.
pub(super) fn write_stream_frame<W, Q, Idx>(
    packet: OpenPacket<W, InFlightClass, Q>,
    stream_id: VarIntField<StreamId>,
    data: Bytes,
    close: bool,
    summary: StreamSummary,
) -> (Supplied<W, InFlightClass, Q>, bool)
where
    W: PacketWriting,
    SummaryOf<W>: InjectSummary<StreamSummary, Idx>,
    Q: PacketPosition,
{
    let Ok(frame) = StreamFrame::new(stream_id, offset_field(summary.offset), data, summary.fin)
    else {
        return (Supplied::Open(packet), false);
    };
    let mut packet = if close {
        match packet.into_last() {
            Ok(last) => {
                return match last.write_last(
                    frame.into_without_length(),
                    <SummaryOf<W>>::inject_summary(summary),
                ) {
                    Ok(closed) => (Supplied::Closed(closed), true),
                    Err(rejected) => (
                        Supplied::Open(rejected.into_parts().0.into_position()),
                        false,
                    ),
                };
            }
            Err(packet) => packet,
        }
    } else {
        packet
    };
    let width = VarIntWidth::shortest(VarInt::try_from(summary.len).unwrap_or(VarInt::MAX));
    let Ok(frame) = frame.into_with_length(width) else {
        return (Supplied::Open(packet), false);
    };
    let written = write_frame(&mut packet, frame, summary);
    (Supplied::Open(packet), written)
}

// ---- the receiving part ----

/// The receiving part of a stream with the tickets of the intents of its
/// frames, STOP_SENDING and MAX_STREAM_DATA, whether a lost
/// MAX_STREAM_DATA waits to be sent again, and the waker of the reader,
/// woken when data or an end may have come.
pub(super) struct ReceivingEnd<Lc, K, Rs: StreamResets, P> {
    pub(super) receiver: ReceiverOf<Lc, Rs>,
    pub(super) stop: Option<Ticketed<K, P>>,
    pub(super) max_stream_data: Option<Ticketed<K, P>>,
    pub(super) max_stream_data_lost: bool,
    pub(super) reader: PartWaiters,
}

impl<Lc, K, Rs: StreamResets, P> ReceivingEnd<Lc, K, Rs, P>
where
    P: Clone + PartialEq,
{
    pub(super) fn new(receiver: ReceiverOf<Lc, Rs>) -> Self {
        Self {
            receiver,
            stop: None,
            max_stream_data: None,
            max_stream_data_lost: false,
            reader: PartWaiters::new(),
        }
    }

    /// The limit to advertise in MAX_STREAM_DATA now: the policy's target,
    /// or the limit in effect when one sent before was lost and the stream
    /// still needs its limit raised (RFC 9000 §13.3).
    pub(super) fn max_stream_data_due(&self) -> Option<VarInt> {
        self.receiver.advertisement().or_else(|| {
            let needed =
                self.receiver.closed().is_none() && self.receiver.parts().final_size().is_none();
            (self.max_stream_data_lost && needed).then(|| self.receiver.opened_limit())
        })
    }

    /// Bring the intents of this part, of the stream `stream_id`, to what is
    /// due now; see the [module documentation](self).
    pub(super) fn sync_intents<
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    >(
        &mut self,
        stream_id: StreamId,
        publish: &mut H,
    ) {
        let stop = self
            .receiver
            .pending_stop()
            .map(|code| StreamIntent::StopSending {
                stream_id,
                len: stop_sending_frame(stream_id, code).encoded_len(),
            });
        sync_ticket(&mut self.stop, stop, publish);
        let max_stream_data = self
            .max_stream_data_due()
            .map(|limit| StreamIntent::MaxStreamData {
                stream_id,
                len: max_stream_data_frame(stream_id, limit).encoded_len(),
            });
        sync_ticket(&mut self.max_stream_data, max_stream_data, publish);
    }

    /// Write the STOP_SENDING frame of the request waiting.
    pub(super) fn write_stop_sending<H, W, Q, Idx>(
        &mut self,
        publish: &mut H,
        stream_id: StreamId,
        mut packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<StopSendingSummary, Idx>,
    {
        let Some(code) = self.receiver.pending_stop() else {
            return Supplied::Open(packet);
        };
        let summary = StopSendingSummary {
            stream_id,
            application_error_code: code,
        };
        if write_frame(&mut packet, stop_sending_frame(stream_id, code), summary) {
            let _ = self.receiver.on_stop_sent();
            release_ticket(&mut self.stop, publish);
        }
        Supplied::Open(packet)
    }

    /// Write the MAX_STREAM_DATA frame of the limit due; once written, the
    /// limit may be visible to the peer.
    pub(super) fn write_max_stream_data<H, W, Q, Idx>(
        &mut self,
        publish: &mut H,
        stream_id: StreamId,
        mut packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<MaxStreamDataSummary, Idx>,
    {
        let Some(limit) = self.max_stream_data_due() else {
            return Supplied::Open(packet);
        };
        let summary = MaxStreamDataSummary {
            stream_id,
            maximum_stream_data: limit,
        };
        if write_frame(
            &mut packet,
            max_stream_data_frame(stream_id, limit),
            summary,
        ) {
            self.receiver.open_limit(limit);
            self.max_stream_data_lost = false;
            release_ticket(&mut self.max_stream_data, publish);
        }
        Supplied::Open(packet)
    }
}

/// A receiving part is done when its receiver is terminal
/// ([`StreamReceiver::is_terminal`]): everything the peer owes was received,
/// and its reader read the end or the reset, or was dropped.
impl<Lc, K, Rs: StreamResets, P> PartDone for ReceivingEnd<Lc, K, Rs, P> {
    fn is_done(&self) -> bool {
        self.receiver.is_terminal()
    }
}

/// A receiving part is in its receiver's state.
impl<Lc, K, Rs: StreamResets, P> PartState for ReceivingEnd<Lc, K, Rs, P> {
    type State = ReceiveStreamState;

    fn state(&self) -> ReceiveStreamState {
        self.receiver.receive_state()
    }

    fn change(
        old: Option<ReceiveStreamState>,
        new: Option<ReceiveStreamState>,
    ) -> StreamStateChange {
        StreamStateChange::Receiving { old, new }
    }
}

pub(super) fn stop_sending_frame(
    stream_id: StreamId,
    code: ApplicationErrorCode,
) -> StopSendingFrame {
    StopSendingFrame::new(
        VarIntField::shortest(stream_id),
        VarIntField::shortest(code),
    )
}

pub(super) fn max_stream_data_frame(stream_id: StreamId, limit: VarInt) -> MaxStreamDataFrame {
    MaxStreamDataFrame::new(
        VarIntField::shortest(stream_id),
        VarIntField::shortest(limit),
    )
}

// ---- the connection's frames ----

/// What the receive flow controller's lock holds: the controller, the
/// ticket of the MAX_DATA intent, whether a lost MAX_DATA waits to be sent
/// again, and whether the layer ended.
pub(super) struct ConnectionReceive<K, P> {
    pub(super) flow: ConnectionReceiveFlowController,
    pub(super) max_data: Option<Ticketed<K, P>>,
    pub(super) max_data_lost: bool,
    pub(super) ended: bool,
}

impl<K, P> ConnectionReceive<K, P>
where
    P: Clone + PartialEq,
{
    /// The limit to advertise in MAX_DATA now: the sliding target, or the
    /// limit in effect when one sent before was lost (RFC 9000 §13.3).
    pub(super) fn max_data_due(&self) -> Option<VarInt> {
        if self.ended {
            return None;
        }
        self.flow
            .advertisement()
            .or_else(|| self.max_data_lost.then(|| self.flow.limit()))
    }

    /// Bring the MAX_DATA intent to what is due now.
    pub(super) fn sync_intents<
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    >(
        &mut self,
        publish: &mut H,
    ) {
        let wanted = self.max_data_due().map(|limit| StreamIntent::MaxData {
            len: max_data_frame(limit).encoded_len(),
        });
        sync_ticket(&mut self.max_data, wanted, publish);
    }
}

pub(super) fn max_data_frame(limit: VarInt) -> MaxDataFrame {
    MaxDataFrame::new(VarIntField::shortest(limit))
}

pub(super) fn data_blocked_frame(limit: VarInt) -> DataBlockedFrame {
    DataBlockedFrame::new(VarIntField::shortest(limit))
}

pub(super) fn max_streams_frame(
    directionality: Directionality,
    limit: StreamCount,
) -> MaxStreamsFrame {
    MaxStreamsFrame::new(directionality, VarIntField::shortest(limit))
}

pub(super) fn streams_blocked_frame(
    directionality: Directionality,
    limit: StreamCount,
) -> StreamsBlockedFrame {
    StreamsBlockedFrame::new(directionality, VarIntField::shortest(limit))
}

/// One value for each directionality.
#[derive(Default)]
pub(super) struct ByDirectionality<X> {
    pub(super) bidirectional: X,
    pub(super) unidirectional: X,
}

impl<X> ByDirectionality<X> {
    pub(super) fn get_mut(&mut self, directionality: Directionality) -> &mut X {
        match directionality {
            Directionality::Bidirectional => &mut self.bidirectional,
            Directionality::Unidirectional => &mut self.unidirectional,
        }
    }

    pub(super) fn get(&self, directionality: Directionality) -> &X {
        match directionality {
            Directionality::Bidirectional => &self.bidirectional,
            Directionality::Unidirectional => &self.unidirectional,
        }
    }
}

pub(super) const DIRECTIONALITIES: [Directionality; 2] = [
    Directionality::Bidirectional,
    Directionality::Unidirectional,
];

/// What the set's lock holds of the connection's frames about the streams'
/// identity and its send credit: the tickets of MAX_STREAMS and
/// STREAMS_BLOCKED of each directionality, whether a lost MAX_STREAMS waits
/// to be sent again, and the DATA_BLOCKED signal with its ticket.
pub(super) struct ConnectionIntents<K, P> {
    pub(super) max_streams: ByDirectionality<Option<Ticketed<K, P>>>,
    pub(super) max_streams_lost: ByDirectionality<bool>,
    pub(super) streams_blocked: ByDirectionality<Option<Ticketed<K, P>>>,
    pub(super) data_blocked_signal: DataBlockedSignal,
    pub(super) data_blocked: Option<Ticketed<K, P>>,
}

impl<K, P> Default for ConnectionIntents<K, P> {
    fn default() -> Self {
        Self {
            max_streams: ByDirectionality {
                bidirectional: None,
                unidirectional: None,
            },
            max_streams_lost: ByDirectionality::default(),
            streams_blocked: ByDirectionality {
                bidirectional: None,
                unidirectional: None,
            },
            data_blocked_signal: DataBlockedSignal::new(),
            data_blocked: None,
        }
    }
}

/// What a set keeps of its streams as a whole (`SetState`), under its lock
/// in a [`LockedStreamSet`](super::locked::LockedStreamSet): the streams'
/// identity, the tables of the parts `S` and `R` of the streams, the queues
/// of the streams to accept, the end of the layer, the connection's frames
/// about the streams' identity and its send credit, and the wakers of those
/// who wait to open or accept.
pub(super) struct SetState<Lc, K, P, S, R, Ps> {
    pub(super) ledger: StreamIdLedger,
    pub(super) senders: BTreeMap<StreamId, S>,
    pub(super) receivers: BTreeMap<StreamId, R>,
    /// The sending parts reclaimed while they were held through the shared
    /// connection, with their last result, until their holders'
    /// credentials come back.
    pub(super) held_senders: BTreeMap<StreamId, S>,
    /// The receiving parts reclaimed while they were held, as the sending.
    pub(super) held_receivers: BTreeMap<StreamId, R>,
    /// The bidirectional streams the peer opened, in the order their first
    /// frames arrived, not accepted yet.
    pub(super) accept_bidirectional: VecDeque<StreamId>,
    /// The unidirectional streams the peer opened, as the bidirectional.
    pub(super) accept_unidirectional: VecDeque<StreamId>,
    /// How the layer ended, once it did.
    pub(super) end: Option<LayerEnd<Lc>>,
    /// The connection's frames about the streams' identity and its send
    /// credit.
    pub(super) connection: ConnectionIntents<K, P>,
    /// The limits the peer grants this side, which a stream made gets its
    /// send limit from: the facts' at first, the peer's transport
    /// parameters of this handshake once they replace the remembered ones
    /// ([`peer_parameters_known`](Self::peer_parameters_known)).
    pub(super) granted_by_peer: FlowControlParameters,
    /// What the peer allows the resets of the set
    /// ([`StreamResets::PeerSupport`](sakuya_stream_v1::resets::StreamResets::PeerSupport)):
    /// the facts' at first, that of the peer's transport parameters of this
    /// handshake once they replace the remembered ones.
    pub(super) peer_reset_support: Ps,
    /// The wakers of those who wait to open a stream of each
    /// directionality: woken when the peer's limit may have grown.
    pub(super) open_wakers: ByDirectionality<Vec<Waker>>,
    /// The wakers of those who wait to accept a stream of each
    /// directionality: woken when one may have come.
    pub(super) accept_wakers: ByDirectionality<Vec<Waker>>,
}

impl<Lc, K, P, S, R, Ps> SetState<Lc, K, P, S, R, Ps>
where
    P: Clone + PartialEq,
{
    /// The MAX_STREAMS limit due now for `directionality`: the target from
    /// the reclaimed streams, or the limit in effect when one sent before
    /// was lost.
    pub(super) fn max_streams_due(&self, directionality: Directionality) -> Option<StreamCount> {
        if self.end.is_some() {
            return None;
        }
        self.ledger.max_streams(directionality).or_else(|| {
            (*self.connection.max_streams_lost.get(directionality))
                .then(|| self.ledger.peer_limit(directionality))
        })
    }

    pub(super) fn streams_blocked_due(
        &self,
        directionality: Directionality,
    ) -> Option<StreamCount> {
        self.end
            .is_none()
            .then(|| self.ledger.streams_blocked(directionality))
            .flatten()
    }

    pub(super) fn data_blocked_due(&self) -> Option<VarInt> {
        self.end
            .is_none()
            .then(|| self.connection.data_blocked_signal.wanted())
            .flatten()
    }

    /// Bring the intents of the connection's frames in the set's state to
    /// what is due now; see the [module documentation](self).
    pub(super) fn sync_intents<
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    >(
        &mut self,
        publish: &mut H,
    ) {
        for directionality in DIRECTIONALITIES {
            let wanted =
                self.max_streams_due(directionality)
                    .map(|limit| StreamIntent::MaxStreams {
                        directionality,
                        len: max_streams_frame(directionality, limit).encoded_len(),
                    });
            sync_ticket(
                self.connection.max_streams.get_mut(directionality),
                wanted,
                publish,
            );
            let wanted = self.streams_blocked_due(directionality).map(|limit| {
                StreamIntent::StreamsBlocked {
                    directionality,
                    len: streams_blocked_frame(directionality, limit).encoded_len(),
                }
            });
            sync_ticket(
                self.connection.streams_blocked.get_mut(directionality),
                wanted,
                publish,
            );
        }
        let wanted = self
            .data_blocked_due()
            .map(|limit| StreamIntent::DataBlocked {
                len: data_blocked_frame(limit).encoded_len(),
            });
        sync_ticket(&mut self.connection.data_blocked, wanted, publish);
    }
}

/// The initiator of the streams an endpoint in `role` opens.
pub(super) fn initiator(role: Role) -> Initiator {
    match role {
        Role::Client => Initiator::Client,
        Role::Server => Initiator::Server,
    }
}

/// The limits of one side's transport parameters, `parameters`, on the
/// streams of each directionality the other side opens, in the ledger's
/// terms.
pub(super) fn initial_max_streams(parameters: &FlowControlParameters) -> InitialMaxStreams {
    InitialMaxStreams {
        bidirectional: parameters.initial_max_streams_bidi.get(),
        unidirectional: parameters.initial_max_streams_uni.get(),
    }
}

impl<S> StreamSetFacts<S> {
    /// Whether this side opens `id`.
    pub(super) fn opens(&self, id: StreamId) -> bool {
        id.initiator() == initiator(self.role)
    }

    /// The window of the receiving part of `id`: what this side's
    /// transport parameters grant a stream of its type (RFC 9000 §18.2).
    /// `initial_max_stream_data_bidi_local` is for the bidirectional
    /// streams this side opens, `_bidi_remote` for those the peer opens,
    /// `_uni` for the unidirectional streams the peer opens.
    pub(super) fn receive_window(&self, id: StreamId) -> VarInt {
        let granted = &self.granted_to_peer;
        match (id.directionality(), self.opens(id)) {
            (Directionality::Bidirectional, true) => {
                granted.initial_max_stream_data_bidi_local.get()
            }
            (Directionality::Bidirectional, false) => {
                granted.initial_max_stream_data_bidi_remote.get()
            }
            // the peer's: a unidirectional stream of this side has no
            // receiving part
            (Directionality::Unidirectional, _) => granted.initial_max_stream_data_uni.get(),
        }
    }

    /// The limit of the sending part of `id`: what the peer's transport
    /// parameters, `granted`, grant a stream of its type, the side that
    /// sent them being the peer (RFC 9000 §18.2). A bidirectional stream
    /// the peer opens is its `_bidi_local`, one this side opens its
    /// `_bidi_remote`, a unidirectional stream this side opens its `_uni`.
    pub(super) fn send_limit(&self, granted: &FlowControlParameters, id: StreamId) -> VarInt {
        match (id.directionality(), self.opens(id)) {
            (Directionality::Bidirectional, false) => {
                granted.initial_max_stream_data_bidi_local.get()
            }
            (Directionality::Bidirectional, true) => {
                granted.initial_max_stream_data_bidi_remote.get()
            }
            // this side's: a unidirectional stream of the peer has no
            // sending part
            (Directionality::Unidirectional, _) => granted.initial_max_stream_data_uni.get(),
        }
    }
}

/// Withdraw the intents of the connection in the set's state through
/// `publish`: the layer ended, and its intents end with it.
pub(super) fn withdraw_connection_intents<K, P, H>(
    connection: &mut ConnectionIntents<K, P>,
    publish: &mut H,
) where
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
{
    forget_ticket(&mut connection.max_streams.bidirectional, publish);
    forget_ticket(&mut connection.max_streams.unidirectional, publish);
    forget_ticket(&mut connection.streams_blocked.bidirectional, publish);
    forget_ticket(&mut connection.streams_blocked.unidirectional, publish);
    forget_ticket(&mut connection.data_blocked, publish);
}

// ---- what the application does on a part ----

/// The reason the termination policy of a sending part gives for a write
/// limit.
pub(super) type WriteLimitReasonOf<Rs, P> = <SendCompositionOf<Rs, P> as SendTerminationPolicy<
    <Rs as StreamResets>::Local,
>>::WriteLimitReason;

/// The reason the termination policy of a receiving part gives for a
/// destroyed buffer.
pub(super) type ReceiveTerminationReasonOf<Rs> =
    <ReceiveComposition<
        FragmentedStreamReceiveBuffer,
        SlidingWindowAdvertisement,
        FollowingTermination,
    > as ReceiveTerminationPolicy<<Rs as StreamResets>::Remote>>::Reason;

/// The failure of a read of a receiving part.
pub(super) type ReadErrorOf<Lc, Rs> =
    ReadError<ReceiveTerminationReasonOf<Rs>, Lc, <Rs as StreamResets>::Remote>;

/// A block a read of a receiving part gives.
pub(super) type ChunkOf = <ReceiveComposition<
    FragmentedStreamReceiveBuffer,
    SlidingWindowAdvertisement,
    FollowingTermination,
> as StreamReceiveBuffer>::Chunk;

impl<Lc, K, Rs: StreamResets, P> SendingEnd<Lc, K, Rs, P>
where
    P: Clone + PartialEq + Default + SendUrgency,
{
    /// One try of a write of `input` with `marker`: the data it took moves
    /// from the application to the transport, given through `events`.
    /// Held back by the stream's limit or its policy, it keeps `waker`, for
    /// the MAX_STREAM_DATA, the STOP_SENDING or the layer's end that wakes
    /// it; held back by the connection's credit, it keeps it too, for the
    /// layer's end, and whoever writes waits for credit through the send
    /// flow controller.
    #[allow(clippy::type_complexity)] // the write's result
    pub(super) fn write_from<B: Buf + ?Sized, E: SharedEvents>(
        &mut self,
        events: &E,
        input: &mut B,
        marker: &MarkerOf<P>,
        waker: &Waker,
    ) -> Result<WriteOutcome, WriteError<WriteLimitReasonOf<Rs, P>, Lc>> {
        let offset = recorded(events).map(|_| self.sender.written_end());
        let outcome = self.sender.write(input, marker);
        if let Some(offset) = offset
            && let Ok(WriteOutcome::Written(report)) = &outcome
            && report.new_bytes > VarInt::ZERO
        {
            data_moved(
                events,
                &StreamDataMoved {
                    stream_id: self.sender.stream_id(),
                    offset: offset.get(),
                    length: report.new_bytes.get(),
                    from: DataLocation::Application,
                    to: DataLocation::Transport,
                    additional_info: None,
                },
            );
        }
        if let Ok(WriteOutcome::Wait(_)) = &outcome {
            keep_part_waiter(&mut self.writer, waker);
        }
        outcome
    }

    /// Close the stream: its end moves to the transport, given through
    /// `events`, when the close ends a stream that was open; closing again
    /// moves nothing.
    pub(super) fn close_from<E: SharedEvents>(&mut self, events: &E) -> Result<(), CloseError<Lc>> {
        let was_open =
            recorded(events).map(|_| matches!(self.sender.end_state(), SendEndState::Open));
        let closed = self.sender.close();
        if was_open == Some(true)
            && closed.is_ok()
            && let SendEndState::Closed { final_size, .. } = self.sender.end_state()
        {
            data_moved(
                events,
                &StreamDataMoved {
                    stream_id: self.sender.stream_id(),
                    offset: final_size.get(),
                    length: 0,
                    from: DataLocation::Application,
                    to: DataLocation::Transport,
                    additional_info: Some(DataMovedAdditionalInfo::FinSet),
                },
            );
        }
        closed
    }

    /// One poll of a wait for every byte and the FIN to be acknowledged:
    /// keeps `waker` while they are not, for the acknowledgment, the
    /// STOP_SENDING or the layer's end that wakes it.
    pub(super) fn poll_all_acknowledged(
        &mut self,
        waker: &Waker,
    ) -> Poll<Result<(), AllAcknowledgedError<Lc>>> {
        match self.sender.terminal_state() {
            Some(SendTerminalState::DataRecvd) => return Poll::Ready(Ok(())),
            Some(SendTerminalState::ResetRecvd) => {
                return Poll::Ready(Err(StreamResetError.into()));
            }
            None => {}
        }
        match self.sender.flush() {
            Err(FlushError::LayerEnded { source }) => return Poll::Ready(Err(source.into())),
            Err(FlushError::Reset { source }) => return Poll::Ready(Err(source.into())),
            Ok(()) => {}
        }
        keep_part_waiter(&mut self.writer, waker);
        Poll::Pending
    }

    /// The writer gives the stream up: the sending part hears that its
    /// writer was abandoned, and nobody waits to write any more.
    pub(super) fn give_up(&mut self) {
        self.sender.on_writer_abandoned();
        self.writer.clear();
    }
}

impl<Lc, K, Rs: StreamResets, P> ReceivingEnd<Lc, K, Rs, P>
where
    P: Clone + PartialEq,
{
    /// Read with `read`, which gives what the receiving part of `stream_id`
    /// gives; keep `waker` when it has to wait, for the STREAM or
    /// RESET_STREAM frame, or the layer's end, that wakes it.
    ///
    /// The data read moves from the transport to the application, given
    /// through `events`; so does the peer's reset the first time a read
    /// gives it, as it leaves the part in a state that keeps it.
    pub(super) fn poll_read_with<E: SharedEvents, R>(
        &mut self,
        stream_id: StreamId,
        events: &E,
        waker: &Waker,
        read: impl FnOnce(&mut Self) -> Result<ReadOutcome<R>, ReadErrorOf<Lc, Rs>>,
    ) -> Poll<Result<ReadOutcome<R>, ReadErrorOf<Lc, Rs>>> {
        let before = recorded(events).map(|_| {
            (
                self.receiver.parts().delivered_end(),
                self.receiver.receive_state(),
            )
        });
        let result = read(self);
        if let Some((offset, state)) = before {
            let moved = match &result {
                Ok(ReadOutcome::Data(_)) => {
                    let delivered = self.receiver.parts().delivered_end();
                    Some((delivered.get().saturating_sub(offset.get()), None))
                }
                Err(ReadError::Reset { .. }) if self.receiver.receive_state() != state => {
                    Some((0, Some(DataMovedAdditionalInfo::StreamReset)))
                }
                Ok(_) | Err(_) => None,
            };
            if let Some((length, additional_info)) = moved {
                data_moved(
                    events,
                    &StreamDataMoved {
                        stream_id,
                        offset: offset.get(),
                        length,
                        from: DataLocation::Transport,
                        to: DataLocation::Application,
                        additional_info,
                    },
                );
            }
        }
        match result {
            Ok(ReadOutcome::Wait) => {
                keep_part_waiter(&mut self.reader, waker);
                Poll::Pending
            }
            other => Poll::Ready(other),
        }
    }

    /// The reader gives the reading up: the receiving part hears that its
    /// reader was dropped, and nobody waits to read any more.
    pub(super) fn give_up(&mut self) {
        self.receiver.reader_dropped();
        self.reader.clear();
    }
}

/// What a read into a buffer gave, as nitori_io's `Read` has it: `0` at
/// the end of the stream or for no room.
pub(super) fn read_count<Er>(
    read: Poll<Result<ReadOutcome<NonZeroUsize>, Er>>,
) -> Poll<Result<usize, Er>> {
    read.map_ok(|outcome| match outcome {
        ReadOutcome::Data(copied) => copied.get(),
        ReadOutcome::NoProgress | ReadOutcome::End | ReadOutcome::Wait => 0,
    })
}

/// What a read of a block gave: `None` at the end of the stream.
pub(super) fn read_block<X, Er>(
    read: Poll<Result<ReadOutcome<X>, Er>>,
) -> Poll<Result<Option<X>, Er>> {
    read.map_ok(|outcome| match outcome {
        ReadOutcome::Data(chunk) => Some(chunk),
        // invariant: a block read takes no target that can be full
        ReadOutcome::NoProgress | ReadOutcome::End | ReadOutcome::Wait => None,
    })
}

// ---- the events of the streams ----

/// `events`, when the events are recorded.
#[inline(always)]
pub(super) fn recorded<E: SharedEvents>(events: &E) -> Option<&E> {
    (E::ENABLED && events.enabled()).then_some(events)
}

/// The part `end` of `id` was just made, on the action of `trigger`: it
/// leaves idle for the state it starts in.
pub(super) fn part_made<E: SharedEvents, X: PartState>(
    events: &E,
    id: StreamId,
    end: &X,
    trigger: EventInitiator,
) {
    if let Some(events) = recorded(events) {
        events.stream_state(id, X::change(None, Some(end.state())), trigger);
    }
}

/// The state of `end` before a change, read only when the events are
/// recorded.
#[inline(always)]
pub(super) fn state_before<E: SharedEvents, X: PartState>(events: &E, end: &X) -> Option<X::State> {
    recorded(events).map(|_| end.state())
}

/// After a change of the part `end` of `id`, on the action of `trigger`:
/// its state change, if its state differs from `before`, what
/// [`state_before`] read.
#[inline(always)]
pub(super) fn state_after<E: SharedEvents, X: PartState>(
    events: &E,
    id: StreamId,
    before: Option<X::State>,
    end: &X,
    trigger: EventInitiator,
) {
    if let Some(events) = recorded(events)
        && let Some(old) = before
    {
        let new = end.state();
        if new != old {
            events.stream_state(id, X::change(Some(old), Some(new)), trigger);
        }
    }
}

/// Data of a stream moved as `moved` says.
pub(super) fn data_moved<E: SharedEvents>(events: &E, moved: &StreamDataMoved) {
    if let Some(events) = recorded(events) {
        events.stream_data_moved(moved);
    }
}

/// The part `end` of `id` was reclaimed, in the state it is in: its last.
pub(super) fn part_reclaimed<E: SharedEvents, X: PartState>(events: &E, id: StreamId, end: &X) {
    if let Some(events) = recorded(events) {
        events.stream_state(
            id,
            X::change(Some(end.state()), None),
            EventInitiator::Local,
        );
    }
}

// ---- making the parts, and the frames of the connection ----

/// The sending part of `id`, a stream of the set of `facts` that the peer
/// grants `granted`, as it is made: the peer's limit for its type, an empty
/// buffer, the codes of the resets its policies send by themselves, and the
/// connection's send flow controller `connection`.
pub(super) fn new_sending_end<Lc, K, Rs: StreamResets, P>(
    facts: &StreamSetFacts<Rs::PeerSupport>,
    granted: &FlowControlParameters,
    id: StreamId,
    send_abandon_code: ApplicationErrorCode,
    destination_exhausted_code: ApplicationErrorCode,
    connection: &Arc<AtomicConnectionSendFlowController>,
) -> SendingEnd<Lc, K, Rs, P>
where
    P: Clone + PartialEq + Default + SendUrgency,
{
    SendingEnd::new(StreamSender::new(
        id,
        facts.send_limit(granted, id),
        send_composition::<Rs, P>(send_abandon_code, destination_exhausted_code),
        Arc::clone(connection),
    ))
}

/// The receiving part of `id`, a stream of the set of `facts`, as it is
/// made: the window this side grants a stream of its type, and the code of
/// the STOP_SENDING its policy sends by itself.
pub(super) fn new_receiving_end<Lc, K, Rs: StreamResets, P>(
    facts: &StreamSetFacts<Rs::PeerSupport>,
    id: StreamId,
    receive_abandon_code: ApplicationErrorCode,
) -> ReceivingEnd<Lc, K, Rs, P>
where
    P: Clone + PartialEq,
{
    let window = facts.receive_window(id);
    ReceivingEnd::new(StreamReceiver::new(
        ReceiveComposition::with_window_and_abandon_code(window, receive_abandon_code),
        window,
    ))
}

impl<Lc, K, Rs: StreamResets, P> SendingEnd<Lc, K, Rs, P>
where
    P: Clone + PartialEq + Default + SendUrgency,
{
    /// The layer ended as `end`: the sending part hears of it, the
    /// intents of its tickets are withdrawn through `publish`, and the
    /// writers that wait are woken.
    pub(super) fn layer_ended<H>(&mut self, end: LayerEnd<Lc>, publish: &mut H)
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    {
        self.sender.on_layer_ended(end);
        forget_ticket(&mut self.data, publish);
        forget_ticket(&mut self.reset, publish);
        forget_ticket(&mut self.blocked, publish);
        self.wake_writer();
    }
}

impl<Lc, K, Rs: StreamResets, P> ReceivingEnd<Lc, K, Rs, P> {
    /// The layer ended as `end`: the receiving part hears of it, the
    /// intents of its tickets are withdrawn through `publish`, and the
    /// readers that wait are woken.
    pub(super) fn layer_ended<H>(&mut self, end: LayerEnd<Lc>, publish: &mut H)
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    {
        self.receiver.layer_ended(end);
        forget_ticket(&mut self.stop, publish);
        forget_ticket(&mut self.max_stream_data, publish);
        self.wake_reader();
    }

    /// A MAX_STREAM_DATA of `maximum` was lost: the limit in effect is sent
    /// again while it is no lower (RFC 9000 §13.3).
    pub(super) fn max_stream_data_lost(&mut self, maximum: VarInt) {
        if self.receiver.opened_limit() >= maximum {
            self.max_stream_data_lost = true;
        }
    }
}

impl<K, P> ConnectionReceive<K, P>
where
    P: Clone + PartialEq,
{
    /// Write the MAX_DATA frame of the limit due into `packet`; once
    /// written, the limit is in effect, and its ticket goes through
    /// `publish` as written.
    pub(super) fn write_max_data<H, W, Q, Idx>(
        &mut self,
        publish: &mut H,
        mut packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<MaxDataSummary, Idx>,
    {
        let Some(limit) = self.max_data_due() else {
            return Supplied::Open(packet);
        };
        let summary = MaxDataSummary {
            maximum_data: limit,
        };
        if write_frame(&mut packet, max_data_frame(limit), summary) {
            self.flow.raise_limit(limit);
            self.max_data_lost = false;
            release_ticket(&mut self.max_data, publish);
        }
        Supplied::Open(packet)
    }

    /// A MAX_DATA of `maximum` was lost: the limit in effect is sent again
    /// while it is no lower (RFC 9000 §13.3).
    pub(super) fn max_data_lost(&mut self, maximum: VarInt) {
        if self.flow.limit() >= maximum {
            self.max_data_lost = true;
        }
    }

    /// The layer ended: no MAX_DATA is sent any more, and the intent of
    /// its ticket is withdrawn through `publish`.
    pub(super) fn layer_ended<H>(&mut self, publish: &mut H)
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    {
        self.ended = true;
        forget_ticket(&mut self.max_data, publish);
    }
}

impl<Lc, K, P, S, R, Ps> SetState<Lc, K, P, S, R, Ps>
where
    P: Clone + PartialEq,
{
    /// The set of a ledger of the facts `facts`, with nothing in it.
    pub(super) fn new(facts: &StreamSetFacts<Ps>) -> Self
    where
        Ps: Copy,
    {
        Self {
            ledger: StreamIdLedger::new(
                facts.role,
                initial_max_streams(&facts.granted_by_peer),
                initial_max_streams(&facts.granted_to_peer),
            ),
            senders: BTreeMap::new(),
            receivers: BTreeMap::new(),
            held_senders: BTreeMap::new(),
            held_receivers: BTreeMap::new(),
            accept_bidirectional: VecDeque::new(),
            accept_unidirectional: VecDeque::new(),
            end: None,
            connection: ConnectionIntents::default(),
            granted_by_peer: facts.granted_by_peer,
            peer_reset_support: facts.peer_reset_support,
            open_wakers: ByDirectionality::default(),
            accept_wakers: ByDirectionality::default(),
        }
    }

    /// The peer's MAX_STREAMS `frame`: a limit that grows wakes those who
    /// wait to open a stream of its directionality; one that does not is
    /// ignored (RFC 9000 §19.11), as is any once the layer ended.
    pub(super) fn on_max_streams(&mut self, frame: &MaxStreamsFrame) {
        if self.end.is_none()
            && self
                .ledger
                .on_max_streams(frame.directionality(), frame.maximum_streams().get())
        {
            wake_all(self.open_wakers.get_mut(frame.directionality()));
        }
    }

    /// Write the MAX_STREAMS frame of `directionality` with the limit due
    /// into `packet`; once written, the peer may open streams up to it.
    pub(super) fn write_max_streams<H, W, Q, Idx>(
        &mut self,
        publish: &mut H,
        directionality: Directionality,
        mut packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<MaxStreamsSummary, Idx>,
    {
        let Some(limit) = self.max_streams_due(directionality) else {
            return Supplied::Open(packet);
        };
        let summary = MaxStreamsSummary {
            directionality,
            maximum_streams: limit,
        };
        if write_frame(
            &mut packet,
            max_streams_frame(directionality, limit),
            summary,
        ) {
            self.ledger.raise_peer_limit(directionality, limit);
            *self.connection.max_streams_lost.get_mut(directionality) = false;
            release_ticket(self.connection.max_streams.get_mut(directionality), publish);
        }
        Supplied::Open(packet)
    }

    /// Write the DATA_BLOCKED frame of the connection's limit into
    /// `packet`.
    pub(super) fn write_data_blocked<H, W, Q, Idx>(
        &mut self,
        publish: &mut H,
        mut packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<DataBlockedSummary, Idx>,
    {
        let Some(limit) = self.data_blocked_due() else {
            return Supplied::Open(packet);
        };
        let summary = DataBlockedSummary {
            maximum_data: limit,
        };
        if write_frame(&mut packet, data_blocked_frame(limit), summary) {
            self.connection.data_blocked_signal.on_sent(limit);
            release_ticket(&mut self.connection.data_blocked, publish);
        }
        Supplied::Open(packet)
    }

    /// Write the STREAMS_BLOCKED frame of this side's streams of
    /// `directionality` into `packet`.
    pub(super) fn write_streams_blocked<H, W, Q, Idx>(
        &mut self,
        publish: &mut H,
        directionality: Directionality,
        mut packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<StreamsBlockedSummary, Idx>,
    {
        let Some(limit) = self.streams_blocked_due(directionality) else {
            return Supplied::Open(packet);
        };
        let summary = StreamsBlockedSummary {
            directionality,
            maximum_streams: limit,
        };
        if write_frame(
            &mut packet,
            streams_blocked_frame(directionality, limit),
            summary,
        ) {
            self.ledger.on_streams_blocked_sent(directionality, limit);
            release_ticket(
                self.connection.streams_blocked.get_mut(directionality),
                publish,
            );
        }
        Supplied::Open(packet)
    }

    /// A frame of the connection's that `summary` describes was lost: what
    /// it carried is sent again as the set has it now (RFC 9000 §13.3). The
    /// frames of a stream's parts are not the set's and change nothing.
    pub(super) fn connection_frame_lost(&mut self, summary: &StreamSetFrameSummary) {
        match summary {
            StreamSetFrameSummary::MaxStreams(summary) => {
                let directionality = summary.directionality;
                if self.ledger.peer_limit(directionality) >= summary.maximum_streams {
                    *self.connection.max_streams_lost.get_mut(directionality) = true;
                }
            }
            StreamSetFrameSummary::DataBlocked(summary) => {
                self.connection
                    .data_blocked_signal
                    .on_lost(summary.maximum_data);
            }
            StreamSetFrameSummary::StreamsBlocked(summary) => {
                self.ledger
                    .on_streams_blocked_lost(summary.directionality, summary.maximum_streams);
            }
            StreamSetFrameSummary::Stream(_)
            | StreamSetFrameSummary::ResetStream(_)
            | StreamSetFrameSummary::StopSending(_)
            | StreamSetFrameSummary::MaxData(_)
            | StreamSetFrameSummary::MaxStreamData(_)
            | StreamSetFrameSummary::StreamDataBlocked(_) => {}
        }
    }

    /// The layer ended as `end`: it is kept, the connection's intents are
    /// withdrawn through `publish`, and those who wait to open or accept
    /// are woken. Only the first end is kept: `false` for any after it.
    pub(super) fn layer_ended<H>(&mut self, end: LayerEnd<Lc>, publish: &mut H) -> bool
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    {
        if self.end.is_some() {
            return false;
        }
        self.end = Some(end);
        withdraw_connection_intents(&mut self.connection, publish);
        self.wake_waiting();
        true
    }

    /// The peer's transport parameters of this handshake grant `granted`
    /// and allow the resets `reset_support` in place of those the layer was
    /// made on, as a client's early layer is made on the remembered ones: a
    /// stream made from now on gets its limit from `granted`, and the
    /// limits on the streams this side opens grow to `granted`'s, waking
    /// those who wait to open; a limit does not shrink (RFC 9000 §7.4.1,
    /// §19.11). Every reset from now on goes by `reset_support`. Nothing
    /// once the layer ended.
    pub(super) fn peer_parameters_known(
        &mut self,
        granted: &FlowControlParameters,
        reset_support: Ps,
    ) {
        if self.end.is_some() {
            return;
        }
        self.granted_by_peer = *granted;
        self.peer_reset_support = reset_support;
        let limits = initial_max_streams(granted);
        self.on_max_streams(&max_streams_frame(
            Directionality::Bidirectional,
            limits.bidirectional,
        ));
        self.on_max_streams(&max_streams_frame(
            Directionality::Unidirectional,
            limits.unidirectional,
        ));
    }

    /// Wake those who wait to open or accept a stream.
    pub(super) fn wake_waiting(&mut self) {
        for directionality in DIRECTIONALITIES {
            wake_all(self.open_wakers.get_mut(directionality));
            wake_all(self.accept_wakers.get_mut(directionality));
        }
    }
}
