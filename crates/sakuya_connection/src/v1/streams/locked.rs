//! The default stream set: the streams under one lock, each part of a
//! stream under a lock of its own ([`LockedStreamSet`]).
//!
//! One lock, the set's, holds the streams' identity ([`StreamIdLedger`]),
//! the table of the sending parts and the table of the receiving parts, the
//! queues of the streams the peer opened that the application has not
//! accepted yet, the end of the layer, and what the connection sends about
//! the streams' identity and its own send credit: the MAX_STREAMS and
//! STREAMS_BLOCKED frames of each directionality and the DATA_BLOCKED
//! frame, with the tickets of their intents. Each part of each stream is
//! under a lock of its own ([`LockedStreamEnd`]), together with the tickets
//! of the intents of its frames: one operation on the part has it to
//! itself. The connection's receive flow controller is under a third kind of
//! lock, with the ticket of the MAX_DATA intent, as the application's reads
//! update it too; the connection's send flow controller is shared by the
//! sending parts and takes no lock.
//!
//! The order of the locks: the set's lock and a part's lock are never held
//! together: a part is found or made under the set's lock, the set's lock is
//! let go, and then the part's lock is taken. The lock of the receive flow
//! controller is taken under a receiving part's lock or under none, and
//! takes none. Publishing, resizing and withdrawing an intent take only the
//! send strategy's locks for it, which take none of these. So a frame of
//! one stream waits neither for a write on another stream nor for a read.
//!
//! The application's side keeps the same order ([`application`]): a write
//! or a read takes the part's lock, and a read the receive flow
//! controller's under it; a write held back by the connection's credit lets
//! the part's lock go before it takes the set's lock, to have DATA_BLOCKED
//! sent, and registers its waker with the send flow controller, whose lock
//! takes none. Opening a stream makes its parts under the set's lock
//! without taking theirs, as a frame that creates a stream does; accepting
//! takes the set's lock only. Whoever waits keeps its waker under the lock
//! of what it waits on: to open or accept, the set's; to write or read, the
//! part's.
//!
//! Whoever changes a part, or the state under the set's lock or the
//! receive flow controller's, brings the intents of what it holds to what
//! is due now before it lets the lock go (`sync_intents`): an intent is
//! published when something is due and none is there, resized when the
//! room it needs changed, published again when its parameters changed, and
//! withdrawn when nothing is due any more. The frames of the streams, the
//! acknowledgments and losses of their packets, the peer's frames and the
//! application's operations all go through it. A stream's data and FIN have
//! one intent for its one destination; the other frames, one each.
//!
//! The streams of a type the peer opens below one a frame names are opened
//! with it (RFC 9000 §3.2), but only the stream the frame names gets its
//! parts; each of the others gets them when its own first frame arrives,
//! and then enters the queue of streams to accept. A late frame of a stream
//! whose state was reclaimed is ignored.

use core::task::Waker;
use std::{
    collections::{HashMap, VecDeque},
    fmt,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use bytes::Bytes;
use sakuya_stream::{
    connection::LayerEnd,
    connection_receive_flow::ConnectionReceiveFlowController,
    connection_send_credit::{
        AtomicConnectionCreditReservation, AtomicConnectionSendFlowController,
        ConnectionSendFlowController, data_blocked::DataBlockedSignal,
    },
    receive::{StreamReceiver, composition::DefaultReceiveComposition},
    receive_buffer::StreamReceiveBuffer,
    send::{
        SendEndState, SendTerminalState, StreamEndFrame, StreamSender,
        composition::SendComposition, flow_control::DefaultSendFlowControlPolicy,
        local_reset::LocalResetTarget,
    },
    send_buffer::{StreamSendBuffer, offset_map::OffsetMapStreamSendBuffer},
    send_options::{
        SendOptions,
        destination::{AnyActiveLinkPath, Unfulfilled},
        urgency::{SendUrgency, Urgency},
    },
    stream_id_ledger::{
        IdentifiedStream, InitialMaxStreams, ReceivingPartFrameType, SendingPartFrameType,
        StreamIdLedger,
    },
};
use sakuya_wire::{
    frame::NoLength,
    v1::{
        application_error::ApplicationErrorCode,
        encryption_level::EncryptionLevel,
        frame::{
            data_blocked::DataBlockedFrame, max_data::MaxDataFrame,
            max_stream_data::MaxStreamDataFrame, max_streams::MaxStreamsFrame,
            reset_stream::ResetStreamFrame, stop_sending::StopSendingFrame, stream::StreamFrame,
            stream_data_blocked::StreamDataBlockedFrame, streams_blocked::StreamsBlockedFrame,
        },
        role::Role,
        stream_count::StreamCount,
        stream_id::{Directionality, Initiator, StreamId},
    },
    var_int::{VarInt, VarIntField, VarIntWidth},
};
use snafu::ResultExt;

use super::{
    FlowControlParameters, ReceivingPartFrameSnafu, ResetStreamSnafu, SendingPartFrameSnafu,
    StreamSet, StreamSetFacts, StreamSetFrameErrorOf, StreamSnafu,
    resets::StreamResets,
    send::{
        DataBlockedSummary, MaxDataSummary, MaxStreamDataSummary, MaxStreamsSummary,
        ResetStreamSummary, StopSendingSummary, StreamDataBlockedSummary, StreamIntent,
        StreamIntentHandle, StreamIntentKey, StreamSetFrameSummary, StreamSummary,
        StreamsBlockedSummary, shortest_stream_frame,
    },
};
use crate::{
    feedback::InjectSummary,
    send_strategy::{IntentTicketResize, IntentTicketWithdraw, SendIntent},
    v1::application_handles::connection::wake_all,
    write::{
        DelimitedFrame, InFlightClass, OpenPacket, PacketPosition, PacketWriting, SummaryOf,
        Supplied,
    },
};

pub mod application;
#[cfg(feature = "reset_stream_at")]
mod reset_stream_at;
#[cfg(test)]
mod tests;

/// The marker of the data of the default set: the send parameters `P` to
/// any active link path, the one destination of this set.
type MarkerOf<P> = SendOptions<P, AnyActiveLinkPath>;

/// The composition of a sending part of the default set: the default send
/// buffer over [`Bytes`] with the marker of the parameters `P`, the default
/// flow control policy, and the termination policy of the reset kind `Rs`.
type SendCompositionOf<Rs, P> = SendComposition<
    OffsetMapStreamSendBuffer<Bytes, AtomicConnectionCreditReservation, MarkerOf<P>>,
    DefaultSendFlowControlPolicy,
    <Rs as StreamResets>::SendTermination,
>;

/// The sending part of a stream of the default set: its composition
/// ([`SendCompositionOf`]), sharing the connection's atomic send flow
/// controller, with the resets of the reset kind `Rs`.
type SenderOf<Lc, Rs, P> = StreamSender<
    SendCompositionOf<Rs, P>,
    AtomicConnectionSendFlowController,
    Lc,
    <Rs as StreamResets>::Local,
    Bytes,
    MarkerOf<P>,
>;

/// The receiving part of a stream of the default set: the default
/// composition, with the resets of the reset kind `Rs`.
type ReceiverOf<Lc, Rs> =
    StreamReceiver<DefaultReceiveComposition, Lc, <Rs as StreamResets>::Remote>;

/// The composition of a new sending part of the default set: an empty
/// buffer, and the reset codes of `config`.
fn send_composition<Rs: StreamResets, P>(
    config: &LockedStreamSetConfig,
) -> SendCompositionOf<Rs, P> {
    SendComposition::new(
        OffsetMapStreamSendBuffer::new(),
        DefaultSendFlowControlPolicy::new(),
        Rs::send_termination(config.send_abandon_code, config.destination_exhausted_code),
    )
}

/// The sending part of a stream as the set's table and its users share it.
type SendingPart<Lc, K, Rs, P> = Arc<LockedStreamEnd<SendingEnd<Lc, K, Rs, P>>>;

/// The receiving part of a stream as the set's table and its users share
/// it.
type ReceivingPart<Lc, K, Rs, P> = Arc<LockedStreamEnd<ReceivingEnd<Lc, K, Rs, P>>>;

/// What `mutex` holds, whether or not a holder panicked: a holder panics
/// only on a broken invariant of its own, and the state is taken as it was
/// left.
fn lock<X>(mutex: &Mutex<X>) -> MutexGuard<'_, X> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The default stream set: the streams under one lock, each part of a
/// stream under a lock of its own; see the [module documentation](self).
///
/// `Lc` is the type of this endpoint's reason for closing, `K` the ticket
/// of a stream intent, `Rs` how its streams are reset
/// ([`StreamResets`]), and `P` the parameters application data is sent
/// with, by default an [`Urgency`]; all data goes to [`AnyActiveLinkPath`].
/// Of the peer's resets it takes RESET_STREAM, and RESET_STREAM_AT where
/// its streams reset reliably (`reset_stream_at::ResetStreamAtSet`, with
/// the feature `reset_stream_at`).
pub struct LockedStreamSet<Lc, K, Rs: StreamResets, P = Urgency> {
    shared: Arc<StreamSetShare<Lc, K, Rs, P>>,
}

/// The handle of a [`LockedStreamSet`]: it shares the set's state.
pub struct LockedStreamSetHandle<Lc, K, Rs: StreamResets, P = Urgency> {
    shared: Arc<StreamSetShare<Lc, K, Rs, P>>,
}

impl<Lc, K, Rs: StreamResets, P> Clone for LockedStreamSetHandle<Lc, K, Rs, P> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

/// Version 1's share of an established layer's handle.
impl<Lc, K, Rs: StreamResets, P> crate::v1::application_handles::KeyedHandleShare
    for LockedStreamSetHandle<Lc, K, Rs, P>
{
    type Part = crate::v1::Part;
}

impl<Lc, K, Rs: StreamResets, P> fmt::Debug for LockedStreamSetHandle<Lc, K, Rs, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedStreamSetHandle")
            .finish_non_exhaustive()
    }
}

impl<Lc, K, Rs: StreamResets, P> fmt::Debug for LockedStreamSet<Lc, K, Rs, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedStreamSet").finish_non_exhaustive()
    }
}

/// What [`LockedStreamSet`] is configured with: the error codes of the
/// resets and STOP_SENDING frames the default policies of its streams send
/// by themselves. Each is 0 by default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LockedStreamSetConfig {
    /// The code a stream resets with when the application gives up its
    /// stream writer.
    pub send_abandon_code: ApplicationErrorCode,
    /// The code a stream resets with when data has no destination left to
    /// fall back to.
    pub destination_exhausted_code: ApplicationErrorCode,
    /// The code a stream asks the peer to stop sending with when the
    /// application drops its stream reader.
    pub receive_abandon_code: ApplicationErrorCode,
}

/// One part of one stream, under a lock of its own; `X` is the sending or
/// the receiving part, with the tickets of the intents of its frames.
pub struct LockedStreamEnd<X> {
    end: Mutex<X>,
}

impl<X> LockedStreamEnd<X> {
    fn new(end: X) -> Self {
        Self {
            end: Mutex::new(end),
        }
    }

    /// The part, for one operation. Taken under no lock of the set; the
    /// lock of the connection's receive flow controller may be taken under
    /// it.
    pub fn lock(&self) -> MutexGuard<'_, X> {
        lock(&self.end)
    }
}

impl<X> fmt::Debug for LockedStreamEnd<X> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedStreamEnd").finish_non_exhaustive()
    }
}

// ---- the intents a component keeps ----

/// The ticket of an intent, with the intent as it was published or last
/// resized.
struct Ticketed<K, P> {
    ticket: K,
    intent: StreamIntent<P>,
}

/// Bring the intent kept in `slot` to `wanted`, the intent due now if any:
/// publish one through `publish` where there is none, resize it where only
/// the room it needs changed, publish it again where its parameters
/// changed, and withdraw it where nothing is due.
fn sync_ticket<K, P, H>(
    slot: &mut Option<Ticketed<K, P>>,
    wanted: Option<StreamIntent<P>>,
    publish: &H,
) where
    P: Clone + PartialEq,
    H: StreamIntentHandle<P, K>,
    K: IntentTicketResize + IntentTicketWithdraw,
{
    *slot = match (slot.take(), wanted) {
        (None, None) => None,
        (Some(kept), None) => {
            let _ = kept.ticket.withdraw();
            None
        }
        (Some(mut kept), Some(wanted)) if same_but_for_room(&kept.intent, &wanted) => {
            if kept.intent != wanted {
                kept.ticket.resize(wanted.min_lengths());
                kept.intent = wanted;
            }
            Some(kept)
        }
        (kept, Some(wanted)) => {
            if let Some(kept) = kept {
                let _ = kept.ticket.withdraw();
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
fn same_but_for_room<P: PartialEq>(kept: &StreamIntent<P>, wanted: &StreamIntent<P>) -> bool {
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

/// Withdraw the intent kept in `slot`, if any: its frame was written, or
/// the strategy ended it.
fn forget_ticket<K: IntentTicketWithdraw, P>(slot: &mut Option<Ticketed<K, P>>) {
    if let Some(kept) = slot.take() {
        let _ = kept.ticket.withdraw();
    }
}

/// Write `frame` into `packet` with `summary`; whether it fitted.
fn write_frame<W, F, S, Q, Idx>(
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

// ---- the sending part ----

impl<Lc, K, Rs: StreamResets, P> SendingEnd<Lc, K, Rs, P> {
    /// Wake the writer, if it waits: what it waits for may have come.
    fn wake_writer(&mut self) {
        if let Some(waker) = self.writer.take() {
            waker.wake();
        }
    }
}

impl<Lc, K, Rs: StreamResets, P> ReceivingEnd<Lc, K, Rs, P> {
    /// Wake the reader, if it waits: data or an end may have come.
    fn wake_reader(&mut self) {
        if let Some(waker) = self.reader.take() {
            waker.wake();
        }
    }
}

/// Where a stream's FIN stands: not sent, in flight, lost, or acknowledged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EndFrameDelivery {
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
    fn waits(self) -> bool {
        matches!(self, Self::NotSent | Self::Lost)
    }

    /// A packet with it was lost: unless it was acknowledged, it waits to be
    /// sent again.
    fn lost(&mut self) {
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
/// room for its writes, or the end of the stream's sending.
struct SendingEnd<Lc, K, Rs: StreamResets, P> {
    sender: SenderOf<Lc, Rs, P>,
    data: Option<Ticketed<K, P>>,
    reset: Option<Ticketed<K, P>>,
    blocked: Option<Ticketed<K, P>>,
    fin: EndFrameDelivery,
    reset_written: Option<Rs::Local>,
    reset_frame: EndFrameDelivery,
    writer: Option<Waker>,
}

impl<Lc, K, Rs: StreamResets, P> SendingEnd<Lc, K, Rs, P>
where
    K: IntentTicketResize + IntentTicketWithdraw,
    P: Clone + PartialEq + Default + SendUrgency,
{
    fn new(sender: SenderOf<Lc, Rs, P>) -> Self {
        Self {
            sender,
            data: None,
            reset: None,
            blocked: None,
            fin: EndFrameDelivery::NotSent,
            reset_written: None,
            reset_frame: EndFrameDelivery::NotSent,
            writer: None,
        }
    }

    /// Whether frames are still sent: the layer has not ended and the part
    /// is not done.
    fn sends(&self) -> bool {
        !self.sender.is_connection_closed() && self.sender.terminal_state().is_none()
    }

    /// The final size of a close whose FIN waits to be sent.
    fn fin_due(&self) -> Option<VarInt> {
        match self.sender.end_state() {
            SendEndState::Closed { final_size, .. } if self.sends() && self.fin.waits() => {
                Some(final_size)
            }
            SendEndState::Open | SendEndState::Closed { .. } | SendEndState::Reset { .. } => None,
        }
    }

    /// The reset whose frame waits to be sent: its frame was not written,
    /// or was lost, or the target changed since it was.
    fn reset_due(&self) -> Option<Rs::Local> {
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
    fn data_due(&self) -> Option<StreamIntent<P>> {
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
    fn sync_intents<H: StreamIntentHandle<P, K>>(&mut self, publish: &H) {
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
    fn write_stream<W, Q, Idx>(
        &mut self,
        packet: OpenPacket<W, InFlightClass, Q>,
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
            let Some(final_size) = fin_due else {
                return Supplied::Open(packet);
            };
            let (supplied, written) = write_stream_frame(
                packet,
                id_field,
                final_size,
                Bytes::new(),
                true,
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
        let offset_field = offset_field(next.offset);
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
        let (supplied, written) = write_stream_frame(
            packet,
            id_field,
            selected.offset,
            selected.bytes,
            fin,
            summary,
        );
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
        }
        supplied
    }

    /// A frame with the FIN was written: its final size is first exposed if
    /// it was not yet, and the FIN is in flight.
    fn fin_exposed(&mut self) {
        if let Some(prepared) = self.sender.prepare_end_frame()
            && matches!(*prepared, StreamEndFrame::Fin(_))
        {
            prepared.expose();
        }
        self.fin = EndFrameDelivery::Sent;
    }

    /// Write the reset frame of the reset in effect into `packet`, its final
    /// size first exposed if it was not yet.
    fn write_reset_stream<W, Q, Idx>(
        &mut self,
        mut packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
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
            forget_ticket(&mut self.reset);
        }
        Supplied::Open(packet)
    }

    /// Write the STREAM_DATA_BLOCKED frame of the limit in effect.
    fn write_stream_data_blocked<W, Q, Idx>(
        &mut self,
        mut packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
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
            forget_ticket(&mut self.blocked);
        }
        Supplied::Open(packet)
    }

    /// The data and FIN of `summary` were acknowledged: once all data and
    /// the FIN of a stream that was closed, and not reset, are, the part is
    /// done (RFC 9000 §3.1). A stream that was reset waits for its reset to
    /// be acknowledged instead (RFC 9000 §13.3), and one reset at a reliable
    /// size also for the data below it
    /// ([`reset_settled`](Self::reset_settled)).
    fn stream_delivered(&mut self, summary: StreamSummary) {
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
    fn reset_delivered(&mut self, summary: ResetStreamSummary) {
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
    fn reset_settled(&mut self) {
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
    fn stream_lost(&mut self, summary: StreamSummary) {
        if let Some(range) = data_range(summary.offset, summary.len) {
            let _ = self.sender.on_data_lost(range);
        }
        if summary.fin {
            self.fin.lost();
        }
    }
}

/// The STREAM_DATA_BLOCKED frame of `stream_id` at `limit`.
fn stream_data_blocked_frame(stream_id: StreamId, limit: VarInt) -> StreamDataBlockedFrame {
    StreamDataBlockedFrame::new(
        VarIntField::shortest(stream_id),
        VarIntField::shortest(limit),
    )
}

/// The Offset field of data at `offset`: none at 0.
fn offset_field(offset: VarInt) -> Option<VarIntField<VarInt>> {
    (offset > VarInt::ZERO).then(|| VarIntField::shortest(offset))
}

/// The range of `len` bytes at `offset`, if any.
fn data_range(offset: VarInt, len: usize) -> Option<core::ops::Range<VarInt>> {
    let end = VarInt::try_from(offset.get().checked_add(len as u64)?).ok()?;
    (end > offset).then_some(offset..end)
}

/// Write a STREAM frame of `data` at `offset` into `packet`: without a
/// Length field, closing the packet, when it is the last, otherwise with
/// one. Hands back the packet and whether the frame fitted.
fn write_stream_frame<W, Q, Idx>(
    packet: OpenPacket<W, InFlightClass, Q>,
    stream_id: VarIntField<StreamId>,
    offset: VarInt,
    data: Bytes,
    fin: bool,
    summary: StreamSummary,
) -> (Supplied<W, InFlightClass, Q>, bool)
where
    W: PacketWriting,
    SummaryOf<W>: InjectSummary<StreamSummary, Idx>,
    Q: PacketPosition,
{
    let offset = offset_field(offset);
    match packet.into_last() {
        Ok(last) => {
            let frame = match StreamFrame::without_length(stream_id, offset, data, fin) {
                Ok(frame) => frame,
                // invariant: the data lies below the written end, a `VarInt`
                Err(_) => return (Supplied::Open(last.into_position()), false),
            };
            match last.write_last(frame, <SummaryOf<W>>::inject_summary(summary)) {
                Ok(closed) => (Supplied::Closed(closed), true),
                Err(rejected) => (
                    Supplied::Open(rejected.into_parts().0.into_position()),
                    false,
                ),
            }
        }
        Err(mut packet) => {
            let width = VarIntWidth::shortest(VarInt::try_from(data.len()).unwrap_or(VarInt::MAX));
            let Ok(frame) = StreamFrame::with_length(stream_id, offset, width, data, fin) else {
                return (Supplied::Open(packet), false);
            };
            let written = write_frame(&mut packet, frame, summary);
            (Supplied::Open(packet), written)
        }
    }
}

// ---- the receiving part ----

/// The receiving part of a stream with the tickets of the intents of its
/// frames, STOP_SENDING and MAX_STREAM_DATA, whether a lost
/// MAX_STREAM_DATA waits to be sent again, and the waker of the reader,
/// woken when data or an end may have come.
struct ReceivingEnd<Lc, K, Rs: StreamResets, P> {
    receiver: ReceiverOf<Lc, Rs>,
    stop: Option<Ticketed<K, P>>,
    max_stream_data: Option<Ticketed<K, P>>,
    max_stream_data_lost: bool,
    reader: Option<Waker>,
}

impl<Lc, K, Rs: StreamResets, P> ReceivingEnd<Lc, K, Rs, P>
where
    K: IntentTicketResize + IntentTicketWithdraw,
    P: Clone + PartialEq,
{
    fn new(receiver: ReceiverOf<Lc, Rs>) -> Self {
        Self {
            receiver,
            stop: None,
            max_stream_data: None,
            max_stream_data_lost: false,
            reader: None,
        }
    }

    /// The limit to advertise in MAX_STREAM_DATA now: the policy's target,
    /// or the limit in effect when one sent before was lost and the stream
    /// still needs its limit raised (RFC 9000 §13.3).
    fn max_stream_data_due(&self) -> Option<VarInt> {
        self.receiver.advertisement().or_else(|| {
            let needed =
                self.receiver.closed().is_none() && self.receiver.parts().final_size().is_none();
            (self.max_stream_data_lost && needed).then(|| self.receiver.opened_limit())
        })
    }

    /// Bring the intents of this part, of the stream `stream_id`, to what is
    /// due now; see the [module documentation](self).
    fn sync_intents<H: StreamIntentHandle<P, K>>(&mut self, stream_id: StreamId, publish: &H) {
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
    fn write_stop_sending<W, Q, Idx>(
        &mut self,
        stream_id: StreamId,
        mut packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
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
            forget_ticket(&mut self.stop);
        }
        Supplied::Open(packet)
    }

    /// Write the MAX_STREAM_DATA frame of the limit due; once written, the
    /// limit may be visible to the peer.
    fn write_max_stream_data<W, Q, Idx>(
        &mut self,
        stream_id: StreamId,
        mut packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
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
            forget_ticket(&mut self.max_stream_data);
        }
        Supplied::Open(packet)
    }
}

fn stop_sending_frame(stream_id: StreamId, code: ApplicationErrorCode) -> StopSendingFrame {
    StopSendingFrame::new(
        VarIntField::shortest(stream_id),
        VarIntField::shortest(code),
    )
}

fn max_stream_data_frame(stream_id: StreamId, limit: VarInt) -> MaxStreamDataFrame {
    MaxStreamDataFrame::new(
        VarIntField::shortest(stream_id),
        VarIntField::shortest(limit),
    )
}

// ---- the connection's frames ----

/// What the receive flow controller's lock holds: the controller, the
/// ticket of the MAX_DATA intent, whether a lost MAX_DATA waits to be sent
/// again, and whether the layer ended.
struct ConnectionReceive<K, P> {
    flow: ConnectionReceiveFlowController,
    max_data: Option<Ticketed<K, P>>,
    max_data_lost: bool,
    ended: bool,
}

impl<K, P> ConnectionReceive<K, P>
where
    K: IntentTicketResize + IntentTicketWithdraw,
    P: Clone + PartialEq,
{
    /// The limit to advertise in MAX_DATA now: the sliding target, or the
    /// limit in effect when one sent before was lost (RFC 9000 §13.3).
    fn max_data_due(&self) -> Option<VarInt> {
        if self.ended {
            return None;
        }
        self.flow
            .advertisement()
            .or_else(|| self.max_data_lost.then(|| self.flow.limit()))
    }

    /// Bring the MAX_DATA intent to what is due now.
    fn sync_intents<H: StreamIntentHandle<P, K>>(&mut self, publish: &H) {
        let wanted = self.max_data_due().map(|limit| StreamIntent::MaxData {
            len: max_data_frame(limit).encoded_len(),
        });
        sync_ticket(&mut self.max_data, wanted, publish);
    }
}

fn max_data_frame(limit: VarInt) -> MaxDataFrame {
    MaxDataFrame::new(VarIntField::shortest(limit))
}

fn data_blocked_frame(limit: VarInt) -> DataBlockedFrame {
    DataBlockedFrame::new(VarIntField::shortest(limit))
}

fn max_streams_frame(directionality: Directionality, limit: StreamCount) -> MaxStreamsFrame {
    MaxStreamsFrame::new(directionality, VarIntField::shortest(limit))
}

fn streams_blocked_frame(
    directionality: Directionality,
    limit: StreamCount,
) -> StreamsBlockedFrame {
    StreamsBlockedFrame::new(directionality, VarIntField::shortest(limit))
}

/// One value for each directionality.
#[derive(Default)]
struct ByDirectionality<X> {
    bidirectional: X,
    unidirectional: X,
}

impl<X> ByDirectionality<X> {
    fn get_mut(&mut self, directionality: Directionality) -> &mut X {
        match directionality {
            Directionality::Bidirectional => &mut self.bidirectional,
            Directionality::Unidirectional => &mut self.unidirectional,
        }
    }

    fn get(&self, directionality: Directionality) -> &X {
        match directionality {
            Directionality::Bidirectional => &self.bidirectional,
            Directionality::Unidirectional => &self.unidirectional,
        }
    }
}

const DIRECTIONALITIES: [Directionality; 2] = [
    Directionality::Bidirectional,
    Directionality::Unidirectional,
];

/// What the set's lock holds of the connection's frames about the streams'
/// identity and its send credit: the tickets of MAX_STREAMS and
/// STREAMS_BLOCKED of each directionality, whether a lost MAX_STREAMS waits
/// to be sent again, and the DATA_BLOCKED signal with its ticket.
struct ConnectionIntents<K, P> {
    max_streams: ByDirectionality<Option<Ticketed<K, P>>>,
    max_streams_lost: ByDirectionality<bool>,
    streams_blocked: ByDirectionality<Option<Ticketed<K, P>>>,
    data_blocked_signal: DataBlockedSignal,
    data_blocked: Option<Ticketed<K, P>>,
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

// ---- the set ----

/// What the set and its handles share.
struct StreamSetShare<Lc, K, Rs: StreamResets, P> {
    set: Mutex<SetState<Lc, K, Rs, P>>,
    connection_receive: Mutex<ConnectionReceive<K, P>>,
    connection_send: Arc<AtomicConnectionSendFlowController>,
    facts: StreamSetFacts<Rs::PeerSupport>,
    config: LockedStreamSetConfig,
}

/// What the set's lock holds.
struct SetState<Lc, K, Rs: StreamResets, P> {
    ledger: StreamIdLedger,
    senders: HashMap<StreamId, SendingPart<Lc, K, Rs, P>>,
    receivers: HashMap<StreamId, ReceivingPart<Lc, K, Rs, P>>,
    /// The bidirectional streams the peer opened, in the order their first
    /// frames arrived, not accepted yet.
    accept_bidirectional: VecDeque<StreamId>,
    /// The unidirectional streams the peer opened, as the bidirectional.
    accept_unidirectional: VecDeque<StreamId>,
    /// How the layer ended, once it did.
    end: Option<LayerEnd<Lc>>,
    /// The connection's frames about the streams' identity and its send
    /// credit.
    connection: ConnectionIntents<K, P>,
    /// The wakers of those who wait to open a stream of each
    /// directionality: woken when the peer's limit may have grown.
    open_wakers: ByDirectionality<Vec<Waker>>,
    /// The wakers of those who wait to accept a stream of each
    /// directionality: woken when one may have come.
    accept_wakers: ByDirectionality<Vec<Waker>>,
}

impl<Lc, K, Rs: StreamResets, P> SetState<Lc, K, Rs, P>
where
    K: IntentTicketResize + IntentTicketWithdraw,
    P: Clone + PartialEq,
{
    /// The MAX_STREAMS limit due now for `directionality`: the target from
    /// the reclaimed streams, or the limit in effect when one sent before
    /// was lost.
    fn max_streams_due(&self, directionality: Directionality) -> Option<StreamCount> {
        if self.end.is_some() {
            return None;
        }
        self.ledger.max_streams(directionality).or_else(|| {
            (*self.connection.max_streams_lost.get(directionality))
                .then(|| self.ledger.peer_limit(directionality))
        })
    }

    fn streams_blocked_due(&self, directionality: Directionality) -> Option<StreamCount> {
        self.end
            .is_none()
            .then(|| self.ledger.streams_blocked(directionality))
            .flatten()
    }

    fn data_blocked_due(&self) -> Option<VarInt> {
        self.end
            .is_none()
            .then(|| self.connection.data_blocked_signal.wanted())
            .flatten()
    }

    /// Bring the intents of the connection's frames under the set's lock
    /// to what is due now; see the [module documentation](self).
    fn sync_intents<H: StreamIntentHandle<P, K>>(&mut self, publish: &H) {
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
fn initiator(role: Role) -> Initiator {
    match role {
        Role::Client => Initiator::Client,
        Role::Server => Initiator::Server,
    }
}

/// The limits of one side's transport parameters, `parameters`, on the
/// streams of each directionality the other side opens, in the ledger's
/// terms.
fn initial_max_streams(parameters: &FlowControlParameters) -> InitialMaxStreams {
    InitialMaxStreams {
        bidirectional: parameters.initial_max_streams_bidi.get(),
        unidirectional: parameters.initial_max_streams_uni.get(),
    }
}

impl<S> StreamSetFacts<S> {
    /// Whether this side opens `id`.
    fn opens(&self, id: StreamId) -> bool {
        id.initiator() == initiator(self.role)
    }

    /// The window of the receiving part of `id`: what this side's
    /// transport parameters grant a stream of its type (RFC 9000 §18.2).
    /// `initial_max_stream_data_bidi_local` is for the bidirectional
    /// streams this side opens, `_bidi_remote` for those the peer opens,
    /// `_uni` for the unidirectional streams the peer opens.
    fn receive_window(&self, id: StreamId) -> VarInt {
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
    /// parameters grant a stream of its type, the side that sent them being
    /// the peer (RFC 9000 §18.2). A bidirectional stream the peer opens is
    /// its `_bidi_local`, one this side opens its `_bidi_remote`, a
    /// unidirectional stream this side opens its `_uni`.
    fn send_limit(&self, id: StreamId) -> VarInt {
        let granted = &self.granted_by_peer;
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

impl<Lc, K, Rs: StreamResets, P> StreamSetShare<Lc, K, Rs, P>
where
    K: IntentTicketResize + IntentTicketWithdraw,
    P: Clone + PartialEq + Default + SendUrgency,
{
    /// Make the parts of `id`, a stream the peer opened that a frame just
    /// created, and queue it to be accepted. A bidirectional stream gets
    /// both parts, a unidirectional one its receiving part.
    fn create_peer_stream(&self, set: &mut SetState<Lc, K, Rs, P>, id: StreamId) {
        let window = self.facts.receive_window(id);
        let receiver = StreamReceiver::new(
            DefaultReceiveComposition::with_window_and_abandon_code(
                window,
                self.config.receive_abandon_code,
            ),
            window,
        );
        set.receivers.insert(
            id,
            Arc::new(LockedStreamEnd::new(ReceivingEnd::new(receiver))),
        );
        match id.directionality() {
            Directionality::Bidirectional => {
                let sender = StreamSender::new(
                    id,
                    self.facts.send_limit(id),
                    send_composition::<Rs, P>(&self.config),
                    Arc::clone(&self.connection_send),
                );
                set.senders
                    .insert(id, Arc::new(LockedStreamEnd::new(SendingEnd::new(sender))));
                set.accept_bidirectional.push_back(id);
            }
            Directionality::Unidirectional => set.accept_unidirectional.push_back(id),
        }
        wake_all(set.accept_wakers.get_mut(id.directionality()));
    }

    /// The receiving part of `id` for a frame of `frame_type`, once the
    /// frame passed the checks of the streams' identity: made if the frame
    /// creates the stream; `None` when the frame is to be ignored, as the
    /// stream was reclaimed or the layer ended.
    #[allow(clippy::type_complexity)] // a part of four type parameters
    fn receiving_part(
        &self,
        id: StreamId,
        frame_type: ReceivingPartFrameType,
    ) -> Result<Option<ReceivingPart<Lc, K, Rs, P>>, StreamSetFrameErrorOf<Rs>> {
        let mut set = lock(&self.set);
        if set.end.is_some() {
            return Ok(None);
        }
        match set
            .ledger
            .on_receiving_part_frame(id, frame_type)
            .context(ReceivingPartFrameSnafu)?
        {
            IdentifiedStream::Created => self.create_peer_stream(&mut set, id),
            IdentifiedStream::Existing => {}
            IdentifiedStream::Reclaimed => return Ok(None),
        }
        let part = set.receivers.get(&id).cloned();
        // invariant: a stream gets its parts when it is created, and leaves
        // the tables only when it is reclaimed
        debug_assert!(part.is_some(), "stream {id} has no receiving part");
        Ok(part)
    }

    /// The sending part of `id` for a frame of `frame_type`, as
    /// [`receiving_part`](Self::receiving_part) finds the receiving part.
    #[allow(clippy::type_complexity)] // a part of four type parameters
    fn sending_part(
        &self,
        id: StreamId,
        frame_type: SendingPartFrameType,
    ) -> Result<Option<SendingPart<Lc, K, Rs, P>>, StreamSetFrameErrorOf<Rs>> {
        let mut set = lock(&self.set);
        if set.end.is_some() {
            return Ok(None);
        }
        match set
            .ledger
            .on_sending_part_frame(id, frame_type)
            .context(SendingPartFrameSnafu)?
        {
            // a bidirectional stream of the peer, opened by a frame for its
            // sending part (RFC 9000 §3.2, §19.5, §19.10)
            IdentifiedStream::Created => self.create_peer_stream(&mut set, id),
            IdentifiedStream::Existing => {}
            IdentifiedStream::Reclaimed => return Ok(None),
        }
        let part = set.senders.get(&id).cloned();
        // invariant: as for the receiving part
        debug_assert!(part.is_some(), "stream {id} has no sending part");
        Ok(part)
    }

    /// The sending part of `id` that a frame source writes or takes back
    /// the frames of: `None` once it left the table.
    fn sender_of(&self, id: StreamId) -> Option<SendingPart<Lc, K, Rs, P>> {
        lock(&self.set).senders.get(&id).cloned()
    }

    /// The receiving part of `id`, as [`sender_of`](Self::sender_of).
    fn receiver_of(&self, id: StreamId) -> Option<ReceivingPart<Lc, K, Rs, P>> {
        lock(&self.set).receivers.get(&id).cloned()
    }

    /// Change the sending part of `id` with `change`, under its own lock,
    /// and bring its intents to what is due then.
    fn with_sender<H: StreamIntentHandle<P, K>>(
        &self,
        id: StreamId,
        publish: &H,
        change: impl FnOnce(&mut SendingEnd<Lc, K, Rs, P>),
    ) {
        if let Some(part) = self.sender_of(id) {
            let mut end = part.lock();
            change(&mut end);
            end.sync_intents(publish);
        }
    }

    /// Change the receiving part of `id`, as
    /// [`with_sender`](Self::with_sender).
    fn with_receiver<H: StreamIntentHandle<P, K>>(
        &self,
        id: StreamId,
        publish: &H,
        change: impl FnOnce(&mut ReceivingEnd<Lc, K, Rs, P>),
    ) {
        if let Some(part) = self.receiver_of(id) {
            let mut end = part.lock();
            change(&mut end);
            end.sync_intents(id, publish);
        }
    }

    /// Change what the set's lock holds with `change`, and bring the
    /// connection's intents there to what is due then.
    fn with_set<H: StreamIntentHandle<P, K>, R>(
        &self,
        publish: &H,
        change: impl FnOnce(&mut SetState<Lc, K, Rs, P>) -> R,
    ) -> R {
        let mut set = lock(&self.set);
        let result = change(&mut set);
        set.sync_intents(publish);
        result
    }

    /// Change what the receive flow controller's lock holds with `change`,
    /// and bring the MAX_DATA intent to what is due then.
    fn with_connection_receive<H: StreamIntentHandle<P, K>, R>(
        &self,
        publish: &H,
        change: impl FnOnce(&mut ConnectionReceive<K, P>) -> R,
    ) -> R {
        let mut connection = lock(&self.connection_receive);
        let result = change(&mut connection);
        connection.sync_intents(publish);
        result
    }
}

/// `P` is a send parameter the default send buffer orders data by.
impl<Lc, K, Rs: StreamResets, P> StreamSet<Lc, K, Rs> for LockedStreamSet<Lc, K, Rs, P>
where
    P: Clone + PartialEq + Default + SendUrgency,
    OffsetMapStreamSendBuffer<Bytes, AtomicConnectionCreditReservation, MarkerOf<P>>:
        StreamSendBuffer<Bytes, AtomicConnectionCreditReservation, MarkerOf<P>>,
{
    type Handle = LockedStreamSetHandle<Lc, K, Rs, P>;
    type Config = LockedStreamSetConfig;
    type SendParameters = P;

    fn new(facts: StreamSetFacts<Rs::PeerSupport>, config: LockedStreamSetConfig) -> Self {
        let ledger = StreamIdLedger::new(
            facts.role,
            initial_max_streams(&facts.granted_by_peer),
            initial_max_streams(&facts.granted_to_peer),
        );
        let set = SetState {
            ledger,
            senders: HashMap::new(),
            receivers: HashMap::new(),
            accept_bidirectional: VecDeque::new(),
            accept_unidirectional: VecDeque::new(),
            end: None,
            connection: ConnectionIntents::default(),
            open_wakers: ByDirectionality::default(),
            accept_wakers: ByDirectionality::default(),
        };
        Self {
            shared: Arc::new(StreamSetShare {
                set: Mutex::new(set),
                connection_receive: Mutex::new(ConnectionReceive {
                    flow: ConnectionReceiveFlowController::new(
                        facts.granted_to_peer.initial_max_data.get(),
                    ),
                    max_data: None,
                    max_data_lost: false,
                    ended: false,
                }),
                connection_send: Arc::new(AtomicConnectionSendFlowController::new(
                    facts.granted_by_peer.initial_max_data.get(),
                )),
                facts,
                config,
            }),
        }
    }

    fn handle(&self) -> LockedStreamSetHandle<Lc, K, Rs, P> {
        LockedStreamSetHandle {
            shared: Arc::clone(&self.shared),
        }
    }

    /// A STREAM frame in a 0-RTT packet marks its stream
    /// ([`StreamReceiver::received_zero_rtt`]) once the stream took it.
    fn on_stream_frame<H>(
        &mut self,
        publish: &H,
        level: EncryptionLevel,
        frame: StreamFrame<Bytes>,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>>
    where
        H: StreamIntentHandle<P, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
    {
        let id = frame.stream_id().get();
        let Some(part) = self
            .shared
            .receiving_part(id, ReceivingPartFrameType::Stream)?
        else {
            return Ok(());
        };
        let mut end = part.lock();
        {
            let mut connection = lock(&self.shared.connection_receive);
            end.receiver
                .on_stream_frame(frame, &mut connection.flow)
                .context(StreamSnafu)?;
        }
        if level == EncryptionLevel::ZeroRtt {
            end.receiver.mark_received_zero_rtt();
        }
        end.sync_intents(id, publish);
        end.wake_reader();
        Ok(())
    }

    fn on_reset_stream<H>(
        &mut self,
        publish: &H,
        frame: ResetStreamFrame,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>>
    where
        H: StreamIntentHandle<P, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
    {
        let id = frame.stream_id().get();
        let Some(part) = self
            .shared
            .receiving_part(id, ReceivingPartFrameType::ResetStream)?
        else {
            return Ok(());
        };
        let mut end = part.lock();
        {
            let mut connection = lock(&self.shared.connection_receive);
            Rs::on_reset_stream(&mut end.receiver, frame, &mut connection.flow)
                .context(ResetStreamSnafu)?;
        }
        end.sync_intents(id, publish);
        end.wake_reader();
        Ok(())
    }

    fn on_stop_sending<H>(
        &mut self,
        publish: &H,
        frame: StopSendingFrame,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>>
    where
        H: StreamIntentHandle<P, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
    {
        let id = frame.stream_id().get();
        if let Some(part) = self
            .shared
            .sending_part(id, SendingPartFrameType::StopSending)?
        {
            let mut end = part.lock();
            end.sender
                .on_stop_sending(frame.application_error_code().get());
            end.sync_intents(publish);
            end.wake_writer();
        }
        Ok(())
    }

    /// A larger limit clears the DATA_BLOCKED signal of a lower one.
    fn on_max_data<H>(
        &mut self,
        publish: &H,
        frame: MaxDataFrame,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>>
    where
        H: StreamIntentHandle<P, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
    {
        self.shared
            .connection_send
            .on_max_data(frame.maximum_data().get());
        let limit = self.shared.connection_send.limit();
        self.shared.with_set(publish, |set| {
            set.connection.data_blocked_signal.on_limit_raised(limit);
        });
        Ok(())
    }

    fn on_max_stream_data<H>(
        &mut self,
        publish: &H,
        frame: MaxStreamDataFrame,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>>
    where
        H: StreamIntentHandle<P, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
    {
        let id = frame.stream_id().get();
        if let Some(part) = self
            .shared
            .sending_part(id, SendingPartFrameType::MaxStreamData)?
        {
            let mut end = part.lock();
            end.sender
                .on_max_stream_data(frame.maximum_stream_data().get());
            end.sync_intents(publish);
            end.wake_writer();
        }
        Ok(())
    }

    /// A limit that does not grow is ignored (RFC 9000 §19.11).
    fn on_max_streams<H>(
        &mut self,
        publish: &H,
        frame: MaxStreamsFrame,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>>
    where
        H: StreamIntentHandle<P, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
    {
        self.shared.with_set(publish, |set| {
            if set.end.is_none()
                && set
                    .ledger
                    .on_max_streams(frame.directionality(), frame.maximum_streams().get())
            {
                wake_all(set.open_wakers.get_mut(frame.directionality()));
            }
        });
        Ok(())
    }

    /// The default policies send nothing for it; it changes nothing.
    fn on_data_blocked<H>(
        &mut self,
        _: &H,
        _: DataBlockedFrame,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>>
    where
        H: StreamIntentHandle<P, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
    {
        Ok(())
    }

    fn on_stream_data_blocked<H>(
        &mut self,
        publish: &H,
        frame: StreamDataBlockedFrame,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>>
    where
        H: StreamIntentHandle<P, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
    {
        let id = frame.stream_id().get();
        if let Some(part) = self
            .shared
            .receiving_part(id, ReceivingPartFrameType::StreamDataBlocked)?
        {
            let mut end = part.lock();
            end.receiver
                .on_stream_data_blocked(frame.maximum_stream_data().get());
            end.sync_intents(id, publish);
        }
        Ok(())
    }

    /// The default policies send nothing for it; it changes nothing. A
    /// limit beyond 2^60 is refused when the frame is read (RFC 9000
    /// §19.14).
    fn on_streams_blocked<H>(
        &mut self,
        _: &H,
        _: StreamsBlockedFrame,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>>
    where
        H: StreamIntentHandle<P, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
    {
        Ok(())
    }

    /// The end is kept first, under the set's lock; each part hears of it
    /// afterwards, under its own lock. Only the first end is kept. Every
    /// ticket is dropped, which withdraws its intent: nothing of the layer
    /// is sent any more.
    fn layer_ended(&mut self, end: LayerEnd<Lc>) {
        let (senders, receivers) = {
            let mut set = lock(&self.shared.set);
            if set.end.is_some() {
                return;
            }
            set.end = Some(end.clone());
            withdraw_connection_intents(&mut set.connection);
            for directionality in DIRECTIONALITIES {
                wake_all(set.open_wakers.get_mut(directionality));
                wake_all(set.accept_wakers.get_mut(directionality));
            }
            (
                set.senders.values().cloned().collect::<Vec<_>>(),
                set.receivers.values().cloned().collect::<Vec<_>>(),
            )
        };
        {
            let mut connection = lock(&self.shared.connection_receive);
            connection.ended = true;
            connection.max_data = None;
        }
        for sender in senders {
            let mut part = sender.lock();
            part.sender.on_layer_ended(end.clone());
            part.data = None;
            part.reset = None;
            part.blocked = None;
            part.wake_writer();
        }
        for receiver in receivers {
            let mut part = receiver.lock();
            part.receiver.layer_ended(end.clone());
            part.stop = None;
            part.max_stream_data = None;
            part.wake_reader();
        }
    }

    fn supply_stream<H, W, Q, Idx>(
        &mut self,
        publish: &H,
        stream_id: StreamId,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        H: StreamIntentHandle<P, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<StreamSummary, Idx>,
        Q: PacketPosition,
    {
        let Some(part) = self.shared.sender_of(stream_id) else {
            return Supplied::Open(packet);
        };
        let mut end = part.lock();
        let supplied = end.write_stream(packet);
        end.sync_intents(publish);
        supplied
    }

    fn supply_reset_stream<H, W, Q, Idx>(
        &mut self,
        publish: &H,
        stream_id: StreamId,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        H: StreamIntentHandle<P, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<ResetStreamSummary, Idx>,
        Q: PacketPosition,
    {
        let Some(part) = self.shared.sender_of(stream_id) else {
            return Supplied::Open(packet);
        };
        let mut end = part.lock();
        let supplied = end.write_reset_stream(packet);
        end.sync_intents(publish);
        supplied
    }

    fn supply_stop_sending<H, W, Q, Idx>(
        &mut self,
        publish: &H,
        stream_id: StreamId,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        H: StreamIntentHandle<P, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<StopSendingSummary, Idx>,
        Q: PacketPosition,
    {
        let Some(part) = self.shared.receiver_of(stream_id) else {
            return Supplied::Open(packet);
        };
        let mut end = part.lock();
        let supplied = end.write_stop_sending(stream_id, packet);
        end.sync_intents(stream_id, publish);
        supplied
    }

    fn supply_max_data<H, W, Q, Idx>(
        &mut self,
        publish: &H,
        mut packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        H: StreamIntentHandle<P, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<MaxDataSummary, Idx>,
        Q: PacketPosition,
    {
        self.shared.with_connection_receive(publish, |connection| {
            let Some(limit) = connection.max_data_due() else {
                return;
            };
            let summary = MaxDataSummary {
                maximum_data: limit,
            };
            if write_frame(&mut packet, max_data_frame(limit), summary) {
                connection.flow.raise_limit(limit);
                connection.max_data_lost = false;
                forget_ticket(&mut connection.max_data);
            }
        });
        Supplied::Open(packet)
    }

    fn supply_max_stream_data<H, W, Q, Idx>(
        &mut self,
        publish: &H,
        stream_id: StreamId,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        H: StreamIntentHandle<P, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<MaxStreamDataSummary, Idx>,
        Q: PacketPosition,
    {
        let Some(part) = self.shared.receiver_of(stream_id) else {
            return Supplied::Open(packet);
        };
        let mut end = part.lock();
        let supplied = end.write_max_stream_data(stream_id, packet);
        end.sync_intents(stream_id, publish);
        supplied
    }

    fn supply_max_streams<H, W, Q, Idx>(
        &mut self,
        publish: &H,
        directionality: Directionality,
        mut packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        H: StreamIntentHandle<P, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<MaxStreamsSummary, Idx>,
        Q: PacketPosition,
    {
        self.shared.with_set(publish, |set| {
            let Some(limit) = set.max_streams_due(directionality) else {
                return;
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
                set.ledger.raise_peer_limit(directionality, limit);
                *set.connection.max_streams_lost.get_mut(directionality) = false;
                forget_ticket(set.connection.max_streams.get_mut(directionality));
            }
        });
        Supplied::Open(packet)
    }

    fn supply_data_blocked<H, W, Q, Idx>(
        &mut self,
        publish: &H,
        mut packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        H: StreamIntentHandle<P, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<DataBlockedSummary, Idx>,
        Q: PacketPosition,
    {
        self.shared.with_set(publish, |set| {
            let Some(limit) = set.data_blocked_due() else {
                return;
            };
            let summary = DataBlockedSummary {
                maximum_data: limit,
            };
            if write_frame(&mut packet, data_blocked_frame(limit), summary) {
                set.connection.data_blocked_signal.on_sent(limit);
                forget_ticket(&mut set.connection.data_blocked);
            }
        });
        Supplied::Open(packet)
    }

    fn supply_stream_data_blocked<H, W, Q, Idx>(
        &mut self,
        publish: &H,
        stream_id: StreamId,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        H: StreamIntentHandle<P, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<StreamDataBlockedSummary, Idx>,
        Q: PacketPosition,
    {
        let Some(part) = self.shared.sender_of(stream_id) else {
            return Supplied::Open(packet);
        };
        let mut end = part.lock();
        let supplied = end.write_stream_data_blocked(packet);
        end.sync_intents(publish);
        supplied
    }

    fn supply_streams_blocked<H, W, Q, Idx>(
        &mut self,
        publish: &H,
        directionality: Directionality,
        mut packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        H: StreamIntentHandle<P, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<StreamsBlockedSummary, Idx>,
        Q: PacketPosition,
    {
        self.shared.with_set(publish, |set| {
            let Some(limit) = set.streams_blocked_due(directionality) else {
                return;
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
                set.ledger.on_streams_blocked_sent(directionality, limit);
                forget_ticket(set.connection.streams_blocked.get_mut(directionality));
            }
        });
        Supplied::Open(packet)
    }

    /// The acknowledgment of a STREAM frame's data and FIN, or of a reset
    /// frame, may make the sending part done; the others change
    /// nothing but the STREAM_DATA_BLOCKED signal's record.
    fn on_frame_delivered<H>(&mut self, publish: &H, summary: StreamSetFrameSummary)
    where
        H: StreamIntentHandle<P, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
    {
        match summary {
            StreamSetFrameSummary::Stream(summary) => {
                self.shared.with_sender(summary.stream_id, publish, |end| {
                    end.stream_delivered(summary);
                    end.wake_writer();
                })
            }
            StreamSetFrameSummary::ResetStream(summary) => {
                self.shared.with_sender(summary.stream_id, publish, |end| {
                    end.reset_delivered(summary);
                    end.wake_writer();
                });
            }
            StreamSetFrameSummary::StreamDataBlocked(summary) => {
                self.shared.with_sender(summary.stream_id, publish, |end| {
                    end.sender
                        .on_stream_data_blocked_acknowledged(summary.maximum_stream_data);
                });
            }
            StreamSetFrameSummary::StopSending(_)
            | StreamSetFrameSummary::MaxData(_)
            | StreamSetFrameSummary::MaxStreamData(_)
            | StreamSetFrameSummary::MaxStreams(_)
            | StreamSetFrameSummary::DataBlocked(_)
            | StreamSetFrameSummary::StreamsBlocked(_) => {}
        }
    }

    /// What a lost frame carried is sent again as its owner has it now
    /// (RFC 9000 §13.3): a stream's data and FIN while they are not
    /// acknowledged; a RESET_STREAM while the sending part is not done; a
    /// STOP_SENDING while the receiving part still needs it; the limit in
    /// effect of a MAX_DATA, MAX_STREAM_DATA or MAX_STREAMS, which is never
    /// lower than the one lost, while it is still advertised; a BLOCKED
    /// frame while the sender is still blocked at its limit.
    fn on_frame_lost<H>(&mut self, publish: &H, summary: StreamSetFrameSummary)
    where
        H: StreamIntentHandle<P, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
    {
        match summary {
            StreamSetFrameSummary::Stream(summary) => {
                self.shared
                    .with_sender(summary.stream_id, publish, |end| end.stream_lost(summary))
            }
            StreamSetFrameSummary::ResetStream(summary) => {
                self.shared
                    .with_sender(summary.stream_id, publish, |end| end.reset_frame.lost());
            }
            StreamSetFrameSummary::StreamDataBlocked(summary) => {
                self.shared.with_sender(summary.stream_id, publish, |end| {
                    end.sender
                        .on_stream_data_blocked_lost(summary.maximum_stream_data);
                });
            }
            StreamSetFrameSummary::StopSending(summary) => {
                self.shared
                    .with_receiver(summary.stream_id, publish, |end| {
                        end.receiver.on_stop_lost()
                    });
            }
            StreamSetFrameSummary::MaxStreamData(summary) => {
                self.shared
                    .with_receiver(summary.stream_id, publish, |end| {
                        if end.receiver.opened_limit() >= summary.maximum_stream_data {
                            end.max_stream_data_lost = true;
                        }
                    });
            }
            StreamSetFrameSummary::MaxData(summary) => {
                self.shared.with_connection_receive(publish, |connection| {
                    if connection.flow.limit() >= summary.maximum_data {
                        connection.max_data_lost = true;
                    }
                });
            }
            StreamSetFrameSummary::MaxStreams(summary) => {
                self.shared.with_set(publish, |set| {
                    let directionality = summary.directionality;
                    if set.ledger.peer_limit(directionality) >= summary.maximum_streams {
                        *set.connection.max_streams_lost.get_mut(directionality) = true;
                    }
                });
            }
            StreamSetFrameSummary::DataBlocked(summary) => {
                self.shared.with_set(publish, |set| {
                    set.connection
                        .data_blocked_signal
                        .on_lost(summary.maximum_data);
                });
            }
            StreamSetFrameSummary::StreamsBlocked(summary) => {
                self.shared.with_set(publish, |set| {
                    set.ledger
                        .on_streams_blocked_lost(summary.directionality, summary.maximum_streams);
                });
            }
        }
    }

    /// The ticket of the intent is ended and forgotten; a stream's data
    /// lets its destination fall back first. Then what is due is published
    /// again.
    fn on_intent_unfulfilled<H>(&mut self, publish: &H, key: StreamIntentKey, cause: Unfulfilled)
    where
        H: StreamIntentHandle<P, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
    {
        match key {
            StreamIntentKey::Stream(id) => self.shared.with_sender(id, publish, |end| {
                forget_ticket(&mut end.data);
                let _ = end.sender.on_unfulfilled(&AnyActiveLinkPath, cause);
                // a destination left without fallback may end the stream
                end.wake_writer();
            }),
            StreamIntentKey::ResetStream(id) => self
                .shared
                .with_sender(id, publish, |end| forget_ticket(&mut end.reset)),
            StreamIntentKey::StreamDataBlocked(id) => self
                .shared
                .with_sender(id, publish, |end| forget_ticket(&mut end.blocked)),
            StreamIntentKey::StopSending(id) => self
                .shared
                .with_receiver(id, publish, |end| forget_ticket(&mut end.stop)),
            StreamIntentKey::MaxStreamData(id) => self
                .shared
                .with_receiver(id, publish, |end| forget_ticket(&mut end.max_stream_data)),
            StreamIntentKey::MaxData => {
                self.shared.with_connection_receive(publish, |connection| {
                    forget_ticket(&mut connection.max_data);
                })
            }
            StreamIntentKey::MaxStreams(directionality) => self.shared.with_set(publish, |set| {
                forget_ticket(set.connection.max_streams.get_mut(directionality));
            }),
            StreamIntentKey::StreamsBlocked(directionality) => {
                self.shared.with_set(publish, |set| {
                    forget_ticket(set.connection.streams_blocked.get_mut(directionality));
                });
            }
            StreamIntentKey::DataBlocked => self.shared.with_set(publish, |set| {
                forget_ticket(&mut set.connection.data_blocked);
            }),
        }
    }
}

/// Drop the tickets of the connection's intents under the set's lock: the
/// layer ended, and its intents end with it.
fn withdraw_connection_intents<K, P>(connection: &mut ConnectionIntents<K, P>) {
    connection.max_streams.bidirectional = None;
    connection.max_streams.unidirectional = None;
    connection.streams_blocked.bidirectional = None;
    connection.streams_blocked.unidirectional = None;
    connection.data_blocked = None;
}
