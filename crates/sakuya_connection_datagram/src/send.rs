//! Sending datagrams: the intent of each datagram ([`DatagramIntent`]), the
//! DATAGRAM frames that write it ([`DatagramFrames`]), and the ticket the
//! application keeps for it apart from the connection ([`DatagramTicket`]).
//!
//! A datagram's intent carries its key in the queues of its layer
//! ([`DatagramKey`]), its length and its parameters; its payload stays in
//! the queues. The DATAGRAM frame source writes it through the queues of
//! the established layer, which the lend appends to the lineage, lent the
//! send strategy's publisher in the connection node: they find the payload
//! by the key, and only one of writing and withdrawing it takes place
//! (connection-driver «各组件对意愿票据的要求»). The summary of its frame is
//! the key, by which the queues find it again when its packet is
//! acknowledged or lost. A DATAGRAM is not sent again when it is lost
//! (RFC 9221 §5.1): its ticket hears of the loss, and the frame's
//! acknowledgment is its delivery (§5.2). Without the layer nothing is
//! written and nothing taken back: the datagrams ended with it.
//!
//! | Frame | Kind | Item | Summary | Delivered | Lost |
//! | --- | --- | --- | --- | --- | --- |
//! | DATAGRAM | [`DatagramFrames`] | the intent | [`DatagramSummary`]: the datagram's key | the ticket says acknowledged | the ticket says lost; nothing is sent again |

use core::{
    fmt,
    future::{Future, poll_fn},
    marker::PhantomData,
    task::{Context, Poll, Waker},
};
use frunk_core::{HList, hlist_pat};
use sakuya_wire_v1::frame::write::{DelimitedFrame, InFlightClass, ToPacketEndFrame};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use bytes::Bytes;
use sakuya_recovery_v1::packet_number_space::PacketNumberSpaceKind;
use sakuya_stream_v1::send_options::{
    destination::{DestinationFallback, SendDestination, Unfulfilled},
    urgency::{SendUrgency, Urgency},
};
use sakuya_var_int::{VarInt, VarIntWidth};
use sakuya_wire_datagram::DatagramFrame;

use super::{
    DatagramChoices, DatagramQueues, DatagramQueuesFamilyOf, DatagramQueuesOf, DatagramSide,
    frame_len_with_length,
};
use crate::lock;
use sakuya_connection::v1::Choices;
use sakuya_connection::{
    clock::InstantOf,
    error::ConnectionErrorsOf,
    feedback::InjectSummary,
    frame_source::{FindFrameSource, FrameSource, FrameSourceKind},
    send_strategy::{
        IntentState, IntentTicketState, IntentTicketWithdraw, MinimumLengths, SendIntent,
        SendIntentHandle,
        ranked::{RankedIntent, SendPriority, SendRank},
    },
    take::{GetOptionalAt, Lineage, Reborrow, Take, TakeEach},
    v1::application_handles::{
        connection::{keep_waker, wake_all},
        credential::CredentialPointer,
    },
    v1::{
        CloseCauseOf,
        send::SendTypes,
        send_planning::{
            ComponentPublishing, HostSendStrategyTypes, PublisherOf, SendStrategyPublisher,
            StrategyPublisherFor, StrategyPublisherOf,
        },
    },
    write::{OpenPacket, PacketPosition, PacketWriting, SummaryOf, Supplied},
};

// ---- the frames written ----

/// Write `payload` as one DATAGRAM frame into `packet`, with `summary`:
/// without a Length field when the packet has the last position, otherwise
/// with one of the shortest width. Nothing is written when the frame does
/// not fit, or when `start`, asked once the frame fits and before it is
/// written, says it may not be; whether it was written comes back too.
pub(super) fn write_datagram<W, Q, Idx>(
    payload: Bytes,
    packet: OpenPacket<W, InFlightClass, Q>,
    summary: DatagramSummary,
    start: impl FnOnce() -> bool,
) -> (Supplied<W, InFlightClass, Q>, bool)
where
    W: PacketWriting,
    SummaryOf<W>: InjectSummary<DatagramSummary, Idx>,
    Q: PacketPosition,
{
    let summary = <SummaryOf<W>>::inject_summary(summary);
    match packet.into_last() {
        Ok(last) => {
            let frame = DatagramFrame::without_length(payload);
            if ToPacketEndFrame::encoded_len(&frame) > last.remaining() || !start() {
                return (Supplied::Open(last.into_position()), false);
            }
            match last.write_last(frame, summary) {
                Ok(closed) => (Supplied::Closed(closed), true),
                Err(rejected) => {
                    debug_assert!(false, "the frame was measured against the room");
                    (
                        Supplied::Open(rejected.into_parts().0.into_position()),
                        false,
                    )
                }
            }
        }
        Err(mut packet) => {
            let width =
                VarIntWidth::shortest(VarInt::try_from(payload.len()).unwrap_or(VarInt::MAX));
            let Ok(frame) = DatagramFrame::with_length(width, payload) else {
                // invariant: the shortest width holds the length
                return (Supplied::Open(packet), false);
            };
            if DelimitedFrame::encoded_len(&frame) > packet.remaining() || !start() {
                return (Supplied::Open(packet), false);
            }
            let written = packet.write_frame(frame, summary);
            debug_assert!(written.is_ok(), "the frame was measured against the room");
            (Supplied::Open(packet), written.is_ok())
        }
    }
}

// ---- intents ----

/// The frame sources of the extension: DATAGRAM, its one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameSourceId {
    /// The DATAGRAM frames.
    Datagram,
}

/// Where one datagram is among those the queues of one layer sent
/// (`DatagramKey`): the queues give each datagram the next one as they take
/// it, and its intent, the summary of its frame and a ticket held through
/// the shared connection find it by the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DatagramKey(u64);

impl DatagramKey {
    /// The key of the first datagram of a layer's queues.
    pub(crate) const FIRST: Self = Self(0);

    /// The key of the datagram taken after this one's.
    pub(crate) fn next(self) -> Self {
        // invariant: no layer takes 2^64 datagrams
        Self(self.0 + 1)
    }
}

/// One datagram is to be sent (`DatagramIntent`): its key in the queues of
/// its layer, the length of its payload and the parameters `P` it is sent
/// with. The payload stays in the queues, which find it by the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DatagramIntent<P> {
    key: DatagramKey,
    len: usize,
    parameters: P,
}

impl<P> DatagramIntent<P> {
    /// The intent of the datagram of `key`, of `len` bytes of payload, sent
    /// with `parameters`.
    pub(crate) fn new(key: DatagramKey, len: usize, parameters: P) -> Self {
        Self {
            key,
            len,
            parameters,
        }
    }

    /// The datagram's key in the queues of its layer.
    pub fn key(&self) -> DatagramKey {
        self.key
    }

    /// The length of the datagram's payload.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the datagram has no payload.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The parameters it is sent with.
    pub fn parameters(&self) -> &P {
        &self.parameters
    }
}

impl<P> SendIntent for DatagramIntent<P> {
    type FrameSourceId = FrameSourceId;
    type Class = InFlightClass;

    fn frame_source(&self) -> FrameSourceId {
        FrameSourceId::Datagram
    }

    /// The whole payload in one frame: with a Length field of the shortest
    /// width, or without one as the last frame.
    fn min_lengths(&self) -> MinimumLengths {
        MinimumLengths {
            with_length: frame_len_with_length(self.len),
            as_last: 1 + self.len,
        }
    }
}

/// A datagram is application data, by the urgency of its parameters; it
/// does not hold its place. Withdrawing it and writing it are ordered in
/// its queues, not in the strategy: the queues write it only while it
/// waits, and count it as sent from then on, which a withdrawal that came
/// first keeps it from.
impl<P: SendUrgency> RankedIntent for DatagramIntent<P> {
    fn rank(&self) -> SendRank {
        SendRank {
            priority: SendPriority::ApplicationData,
            holds_place: false,
        }
    }

    fn urgency(&self) -> Urgency {
        self.parameters.urgency()
    }
}

// ---- the progress of a datagram ----

/// Why a datagram was withdrawn without its holder asking
/// (`DatagramWithdrawCause`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DatagramWithdrawCause {
    /// The send queue was full and dropped it as the oldest to make room
    /// for a new one ([`DatagramOverflow::DropOldest`](super::DatagramOverflow::DropOldest)).
    DroppedOldest,
    /// Its intent was not fulfilled and its destination had nothing left to
    /// fall back to ([`DestinationFallback::Exhausted`]).
    DestinationExhausted,
    /// The established layer ended before it was sent; how it ended is the
    /// layer's.
    LayerEnded,
}

/// Where a datagram stands (`DatagramState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DatagramState {
    /// Waiting to be sent.
    Waiting,
    /// Waiting to be sent, but none of the active link paths its
    /// destination allows can carry it now, as they are
    /// ([`IntentState::WaitingTooLarge`]): it waits for one that can, and
    /// its holder may withdraw it. Its wait for a settlement goes on.
    WaitingTooLarge,
    /// Withdrawn before it was written into a packet; it will not be.
    Withdrawn(DatagramWithdrawCause),
    /// Written into a packet, which is in flight.
    Sent,
    /// The packet it was written into was acknowledged.
    Acknowledged,
    /// The packet it was written into was declared lost; it is not sent
    /// again (RFC 9221 §5.1). A late acknowledgment of the packet makes it
    /// [`Acknowledged`](Self::Acknowledged).
    Lost,
}

/// How a datagram was settled (`DatagramSettlement`): what
/// [`DatagramTicket::settled`] waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DatagramSettlement {
    /// The packet it was written into was acknowledged.
    Acknowledged,
    /// The packet it was written into was declared lost.
    Lost,
    /// It was withdrawn without being sent: its intent was not fulfilled,
    /// or the queue or the layer's end dropped it.
    Withdrawn(DatagramWithdrawCause),
}

/// What withdrawing a datagram told (`WithdrawReport`): only one of the two
/// takes place, and it does not change afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WithdrawReport {
    /// The datagram was not written into a packet, and it will not be.
    Withdrawn,
    /// The datagram was written into a packet before it could be withdrawn.
    Consumed,
}

/// Where the progress of a datagram stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Waiting to be sent.
    Waiting,
    /// Withdrawn by its holder: no ticket is left to read it.
    WithdrawnByHolder,
    /// Withdrawn without its holder asking.
    Withdrawn(DatagramWithdrawCause),
    /// Written into a packet.
    Sent,
    /// Its packet was acknowledged.
    Acknowledged,
    /// Its packet was declared lost.
    Lost,
}

/// How a datagram is withdrawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Withdrawal {
    /// Its holder asked: it withdrew or dropped its ticket.
    Holder,
    /// Without its holder asking.
    Cause(DatagramWithdrawCause),
}

/// The progress of one datagram without a lock (`ProgressState`): where it
/// stands, and who waits for it to be settled. The queues that hold their
/// datagrams directly keep it in each datagram's record; a
/// [`DatagramProgress`] keeps it under a lock.
#[derive(Debug)]
pub(super) struct ProgressState {
    stage: Stage,
    /// Who waits for the datagram to be settled.
    wakers: Vec<Waker>,
}

impl ProgressState {
    /// The progress of a datagram that waits to be sent.
    pub(super) fn new() -> Self {
        Self {
            stage: Stage::Waiting,
            wakers: Vec::new(),
        }
    }

    /// Move from the stage as `next` says, waking who waits if it moved.
    fn advance<R>(&mut self, next: impl FnOnce(Stage) -> (Option<Stage>, R)) -> R {
        let (to, result) = next(self.stage);
        if let Some(to) = to {
            self.stage = to;
            wake_all(&mut self.wakers);
        }
        result
    }

    /// Whether the datagram waits to be sent.
    pub(super) fn is_waiting(&self) -> bool {
        self.stage == Stage::Waiting
    }

    /// Whether the datagram was written into a packet whose fate is not
    /// known yet.
    pub(super) fn is_in_flight(&self) -> bool {
        self.stage == Stage::Sent
    }

    /// Whether something may still happen to the datagram that a holder
    /// hears of: it waits, or its packet's fate is not known.
    pub(super) fn is_open(&self) -> bool {
        matches!(self.stage, Stage::Waiting | Stage::Sent)
    }

    /// Whether a late acknowledgment may still come: its packet was
    /// declared lost.
    pub(super) fn is_lost(&self) -> bool {
        self.stage == Stage::Lost
    }

    /// The datagram is about to be written: whether it may. It may only
    /// while it waits, and it counts as sent from then on.
    pub(super) fn start_writing(&mut self) -> bool {
        self.advance(|stage| match stage {
            Stage::Waiting => (Some(Stage::Sent), true),
            _ => (None, false),
        })
    }

    /// The packet the datagram was written into was acknowledged, or, if
    /// `delivered` is false, declared lost. A late acknowledgment of a lost
    /// packet counts too.
    pub(super) fn settle(&mut self, delivered: bool) {
        self.advance(|stage| match (stage, delivered) {
            (Stage::Sent | Stage::Lost, true) => (Some(Stage::Acknowledged), ()),
            (Stage::Sent, false) => (Some(Stage::Lost), ()),
            _ => (None, ()),
        });
    }

    /// The datagram is withdrawn as `withdrawal` says, unless it was
    /// written already.
    pub(super) fn withdraw(&mut self, withdrawal: Withdrawal) -> WithdrawReport {
        self.advance(|stage| match stage {
            Stage::Waiting => (
                Some(match withdrawal {
                    Withdrawal::Holder => Stage::WithdrawnByHolder,
                    Withdrawal::Cause(cause) => Stage::Withdrawn(cause),
                }),
                WithdrawReport::Withdrawn,
            ),
            Stage::WithdrawnByHolder | Stage::Withdrawn(_) => (None, WithdrawReport::Withdrawn),
            Stage::Sent | Stage::Acknowledged | Stage::Lost => (None, WithdrawReport::Consumed),
        })
    }

    /// Wake who waits for the datagram to be settled, without moving it:
    /// they look again.
    pub(super) fn wake_waiters(&mut self) {
        wake_all(&mut self.wakers);
    }

    /// What withdrawing the datagram would report now, without withdrawing
    /// it.
    pub(super) fn withdraw_report(&self) -> WithdrawReport {
        match self.stage {
            Stage::Waiting | Stage::WithdrawnByHolder | Stage::Withdrawn(_) => {
                WithdrawReport::Withdrawn
            }
            Stage::Sent | Stage::Acknowledged | Stage::Lost => WithdrawReport::Consumed,
        }
    }

    /// Where the datagram stands, for a holder of its ticket; `None` once
    /// its holder withdrew it. Once `panicked`, a datagram that waits counts
    /// as withdrawn as the layer ended, and one in flight as lost. Whether
    /// one that waits is too large for now is the strategy's to tell.
    pub(super) fn state(&self, panicked: bool) -> Option<DatagramState> {
        Some(match self.stage {
            Stage::Waiting if panicked => {
                DatagramState::Withdrawn(DatagramWithdrawCause::LayerEnded)
            }
            Stage::Sent if panicked => DatagramState::Lost,
            Stage::Waiting => DatagramState::Waiting,
            Stage::WithdrawnByHolder => return None,
            Stage::Withdrawn(cause) => DatagramState::Withdrawn(cause),
            Stage::Sent => DatagramState::Sent,
            Stage::Acknowledged => DatagramState::Acknowledged,
            Stage::Lost => DatagramState::Lost,
        })
    }

    /// The settlement of the datagram, once there is one; while there is
    /// none, the waker of `cx` is kept and woken when there may be. Once
    /// `panicked`, a datagram that waits is settled as withdrawn as the
    /// layer ended, and one in flight as lost: its packet's fate is never
    /// known, as when the link path it went on ended before it was settled.
    pub(super) fn poll_settled(
        &mut self,
        cx: &mut Context<'_>,
        panicked: bool,
    ) -> Poll<DatagramSettlement> {
        match self.stage {
            Stage::Waiting if panicked => Poll::Ready(DatagramSettlement::Withdrawn(
                DatagramWithdrawCause::LayerEnded,
            )),
            Stage::Sent if panicked => Poll::Ready(DatagramSettlement::Lost),
            Stage::Acknowledged => Poll::Ready(DatagramSettlement::Acknowledged),
            Stage::Lost => Poll::Ready(DatagramSettlement::Lost),
            Stage::Withdrawn(cause) => Poll::Ready(DatagramSettlement::Withdrawn(cause)),
            Stage::Waiting | Stage::Sent | Stage::WithdrawnByHolder => {
                keep_waker(&mut self.wakers, cx.waker());
                Poll::Pending
            }
        }
    }
}

/// The settlement a datagram whose layer ended reads from `state`, as its
/// layer's queues left it: what the layer's end left open settles as it
/// would at a panic of the driver, as nothing settles it any more.
pub(super) fn settlement_after_end(state: DatagramState) -> DatagramSettlement {
    match state {
        DatagramState::Acknowledged => DatagramSettlement::Acknowledged,
        DatagramState::Withdrawn(cause) => DatagramSettlement::Withdrawn(cause),
        DatagramState::Waiting | DatagramState::WaitingTooLarge => {
            // invariant: the layer's end withdrew what waits
            DatagramSettlement::Withdrawn(DatagramWithdrawCause::LayerEnded)
        }
        // invariant: the layer's end settled what was in flight as lost
        DatagramState::Sent | DatagramState::Lost => DatagramSettlement::Lost,
    }
}

/// What withdrawing a datagram whose layer ended reports, from `state`, as
/// its layer's queues left it.
pub(super) fn withdraw_report_after_end(state: DatagramState) -> WithdrawReport {
    match state {
        DatagramState::Waiting | DatagramState::WaitingTooLarge | DatagramState::Withdrawn(_) => {
            WithdrawReport::Withdrawn
        }
        DatagramState::Sent | DatagramState::Acknowledged | DatagramState::Lost => {
            WithdrawReport::Consumed
        }
    }
}

/// The progress of one datagram under a lock, shared by the queues that
/// lock their state and the datagram's ticket: what orders writing it
/// against withdrawing it, and what its ticket reads and waits on. Its lock
/// is taken under the queues' at most, and takes none.
pub(crate) struct DatagramProgress {
    state: Mutex<ProgressState>,
}

impl fmt::Debug for DatagramProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramProgress")
            .field("stage", &lock(&self.state).stage)
            .finish_non_exhaustive()
    }
}

impl DatagramProgress {
    /// The progress of a datagram that waits to be sent.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(ProgressState::new()),
        })
    }

    /// Whether the datagram waits to be sent.
    pub(crate) fn is_waiting(&self) -> bool {
        lock(&self.state).is_waiting()
    }

    /// Whether the datagram was written into a packet whose fate is not
    /// known yet, or declared lost, so that a late acknowledgment may come.
    fn awaits_acknowledgment(&self) -> bool {
        let state = lock(&self.state);
        state.is_in_flight() || state.is_lost()
    }

    /// The datagram is about to be written: whether it may.
    fn start_writing(&self) -> bool {
        lock(&self.state).start_writing()
    }

    /// The packet the datagram was written into was acknowledged, or
    /// declared lost.
    fn settle(&self, delivered: bool) {
        lock(&self.state).settle(delivered);
    }

    /// The datagram is withdrawn as `withdrawal` says, unless it was
    /// written already.
    pub(crate) fn withdraw(&self, withdrawal: Withdrawal) -> WithdrawReport {
        lock(&self.state).withdraw(withdrawal)
    }

    /// Wake who waits for the datagram to be settled, without moving it.
    fn wake_waiters(&self) {
        lock(&self.state).wake_waiters();
    }

    /// What withdrawing the datagram would report now, without withdrawing
    /// it.
    pub(crate) fn withdraw_report(&self) -> WithdrawReport {
        lock(&self.state).withdraw_report()
    }

    /// Where the datagram stands, for a holder of its ticket; `None` once
    /// its holder withdrew it. Once `panicked` is set, as
    /// [`ProgressState::state`] reads it.
    pub(crate) fn state(&self, panicked: &DriverPanicFlag) -> Option<DatagramState> {
        lock(&self.state).state(panicked.is_set())
    }

    /// The settlement of the datagram, or `Pending` with the waker of `cx`
    /// kept; `panicked` is looked at under the same lock.
    pub(crate) fn poll_settled(
        &self,
        cx: &mut Context<'_>,
        panicked: &DriverPanicFlag,
    ) -> Poll<DatagramSettlement> {
        let mut state = lock(&self.state);
        state.poll_settled(cx, panicked.is_set())
    }
}

// ---- the frame source ----

/// The summary of a DATAGRAM frame written into a packet
/// (`DatagramSummary`): the datagram's key, by which the queues of its
/// layer find it when the packet is acknowledged or lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramSummary {
    /// The datagram's key.
    pub key: DatagramKey,
}

/// The DATAGRAM frames of the datagrams' intents, as a kind of frame
/// source.
#[derive(Debug)]
pub enum DatagramFrames {}

impl FrameSourceKind for DatagramFrames {
    type Item<'a> = &'a DatagramIntent<Urgency>;
    type Summary<I> = DatagramSummary;
}

/// The frames are written by the queues of the established layer, which
/// the lend appends to the lineage, lent the send strategy's publisher in
/// the connection node; what comes of them, and an intent not fulfilled,
/// go to the queues too.
impl<T, L, V, Ip, Iq, Ij> FindFrameSource<T, L, V, (Ip, Iq, Ij)> for DatagramFrames
where
    T: Choices<Side: DatagramSide, Host: DatagramChoices>,
    L: ConnectionErrorsOf,
    SendTypes<T, L>: HostSendStrategyTypes,
    DatagramQueuesFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, DatagramIntent<Urgency>>,
    DatagramQueuesOf<T, L>: DatagramQueues<CloseCauseOf<T, L>, SendTypes<T, L>>,
    PublisherOf<T, L>: StrategyPublisherFor<DatagramIntent<Urgency>, Ij> + 'static,
    for<'s> V: Reborrow<'s>,
    for<'s> <V as Reborrow<'s>>::Out: TakeEach<'s, PublisherTake<SendTypes<T, L>>, HList![Ip]>,
    for<'s> <<V as Reborrow<'s>>::Out as TakeEach<'s, PublisherTake<SendTypes<T, L>>, HList![Ip]>>::Rest:
        GetOptionalAt<DatagramQueuesOf<T, L>, Iq>,
{
    type Source<'l, 'r>
        = LineageDatagramFrameSource<
        'l,
        'r,
        V,
        DatagramQueuesOf<T, L>,
        CloseCauseOf<T, L>,
        SendTypes<T, L>,
        Ip,
        Iq,
        Ij,
    >
    where
        V: 'l,
        'r: 'l;

    fn find<'l, 'r>(lineage: &'l mut Lineage<'r, V>, _: InstantOf<T>) -> Self::Source<'l, 'r> {
        LineageDatagramFrameSource::new(lineage)
    }
}

/// The DATAGRAM frame source in a lineage `V`
/// (`LineageDatagramFrameSource`): it writes the frames through the queues
/// `Q` of the established layer, which the lend appended to the lineage at
/// the position `Iq`, and lends them the publisher of the send strategy of
/// the strategy types `I`, at the position `Ip`. `Lc` is the queues' close
/// cause, and `Ij` the place of the datagram intents in the sum of intents.
pub struct LineageDatagramFrameSource<'l, 'r, V, Q, Lc, I, Ip, Iq, Ij> {
    lineage: &'l mut Lineage<'r, V>,
    types: PhantomData<DatagramSourceTypes<Q, Lc, I, Ip, Iq, Ij>>,
}

/// What [`LineageDatagramFrameSource`] takes its components by.
type DatagramSourceTypes<Q, Lc, I, Ip, Iq, Ij> = fn() -> (Q, Lc, I, Ip, Iq, Ij);

/// The strategy's publisher, as the DATAGRAM frame source takes it out of
/// its lineage.
type PublisherTake<I> = HList![SendStrategyPublisher<StrategyPublisherOf<I>>];

impl<V, Q, Lc, I, Ip, Iq, Ij> fmt::Debug
    for LineageDatagramFrameSource<'_, '_, V, Q, Lc, I, Ip, Iq, Ij>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LineageDatagramFrameSource")
    }
}

impl<'l, 'r, V, Q, Lc, I, Ip, Iq, Ij> LineageDatagramFrameSource<'l, 'r, V, Q, Lc, I, Ip, Iq, Ij> {
    /// The source in `lineage`.
    pub(crate) fn new(lineage: &'l mut Lineage<'r, V>) -> Self {
        Self {
            lineage,
            types: PhantomData,
        }
    }
}

/// Without the established layer, nothing is written and nothing taken
/// back: the datagrams ended with it. What the queues published or
/// withdrew through the publisher as their intent was not fulfilled is
/// handed on at the connection; what they did as they wrote is handed on by
/// the sending call once it filled its datagrams.
impl<V, Q, Lc, I, Ip, Iq, Ij> FrameSource
    for LineageDatagramFrameSource<'_, '_, V, Q, Lc, I, Ip, Iq, Ij>
where
    for<'s> V: Reborrow<'s>,
    for<'s> <V as Reborrow<'s>>::Out: TakeEach<'s, PublisherTake<I>, HList![Ip]>,
    for<'s> <<V as Reborrow<'s>>::Out as TakeEach<'s, PublisherTake<I>, HList![Ip]>>::Rest:
        GetOptionalAt<Q, Iq>,
    Q: DatagramQueues<Lc, I>,
    I: HostSendStrategyTypes,
    StrategyPublisherOf<I>: StrategyPublisherFor<DatagramIntent<Urgency>, Ij> + 'static,
{
    type Summary = DatagramSummary;
    type Class = InFlightClass;
    type Item<'a> = &'a DatagramIntent<Urgency>;

    fn supply<W, R, Idx>(
        &mut self,
        intent: &DatagramIntent<Urgency>,
        packet: OpenPacket<W, InFlightClass, R>,
    ) -> Supplied<W, InFlightClass, R>
    where
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<DatagramSummary, Idx>,
        R: PacketPosition,
    {
        let (hlist_pat![mut publisher], mut rest) =
            Take::<PublisherTake<I>, HList![Ip]>::take(self.lineage.reborrow());
        match rest.get_optional_mut::<Q, Iq>() {
            Some(mut queues) => queues.supply_datagram::<Ij, _, W, R, Idx>(
                publisher.publisher_mut(),
                intent.key(),
                packet,
            ),
            None => Supplied::Open(packet),
        }
    }

    fn delivered(&mut self, _: PacketNumberSpaceKind, summary: DatagramSummary) {
        let (_, mut rest) = Take::<PublisherTake<I>, HList![Ip]>::take(self.lineage.reborrow());
        if let Some(mut queues) = rest.get_optional_mut::<Q, Iq>() {
            queues.on_frame_delivered(summary);
        }
    }

    /// A lost DATAGRAM is not sent again (RFC 9221 §5.1).
    fn lost(&mut self, _: PacketNumberSpaceKind, summary: &DatagramSummary) {
        let (_, mut rest) = Take::<PublisherTake<I>, HList![Ip]>::take(self.lineage.reborrow());
        if let Some(mut queues) = rest.get_optional_mut::<Q, Iq>() {
            queues.on_frame_lost(*summary);
        }
    }

    /// The queues let the datagram's destination decide at once: it is
    /// published again, with the same ticket, while the destination
    /// degrades, and withdrawn once it has nothing left.
    fn unfulfilled(&mut self, intent: &DatagramIntent<Urgency>, cause: Unfulfilled) {
        let (hlist_pat![mut publisher], mut rest) =
            Take::<PublisherTake<I>, HList![Ip]>::take(self.lineage.reborrow());
        if let Some(mut queues) = rest.get_optional_mut::<Q, Iq>() {
            queues.on_intent_unfulfilled::<Ij, _>(publisher.publisher_mut(), intent.key(), cause);
        }
        if let Some(changed) = publisher.take_changed() {
            rest.publish(changed);
        }
    }
}

// ---- the holders through the shared connection ----

/// The credential of a datagram's ticket (`DatagramTicketCredential`):
/// that the ticket of the datagram it names is still held. The queues'
/// sending makes it; nothing outside this crate can. It cannot be cloned:
/// its holder through the shared connection lends it to the queues to name
/// the datagram ([`DatagramQueues::ticket_state`] and the others), and
/// hands it back once ([`DatagramQueues::withdraw_held`],
/// [`DatagramQueues::release_held`]).
///
/// [`DatagramQueues::ticket_state`]: super::DatagramQueues::ticket_state
/// [`DatagramQueues::withdraw_held`]: super::DatagramQueues::withdraw_held
/// [`DatagramQueues::release_held`]: super::DatagramQueues::release_held
#[derive(Debug)]
pub struct DatagramTicketCredential {
    key: DatagramKey,
}

impl DatagramTicketCredential {
    /// The credential of the ticket of the datagram of `key` just given
    /// out.
    pub(crate) fn new(key: DatagramKey) -> Self {
        Self { key }
    }

    /// The datagram's key.
    pub fn key(&self) -> DatagramKey {
        self.key
    }
}

/// Why an operation on the held datagram of `key` finds nothing: its
/// credential came back, so it ended for its holder as a layer whose end
/// is not known; the queues report it as withdrawn as the layer ended.
pub(super) fn held_datagram_gone(key: DatagramKey) -> DatagramWithdrawCause {
    // invariant: a held datagram stays in its queues until its credential
    // comes back, and no operation names it after that, as it borrows the
    // credential
    debug_assert!(false, "the held datagram {key:?} is gone");
    DatagramWithdrawCause::LayerEnded
}

// ---- the datagram's cell and ticket ----

/// Whether the driver of the queues a datagram went through panicked
/// (`DriverPanicFlag`): set once, by the queues' handle, and read by the
/// tickets of their datagrams, which nothing else tells of the layer's end
/// then.
#[derive(Debug, Default)]
pub(crate) struct DriverPanicFlag(AtomicBool);

impl DriverPanicFlag {
    /// The driver panicked.
    pub(crate) fn set(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether the driver panicked.
    pub(crate) fn is_set(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// A datagram as queues that lock their state and its ticket hold it: its
/// key, payload and parameters `P`, which it is published again from, its
/// progress, the ticket the strategy gave for its intent and its
/// destination `D`, and whether the driver of its queues panicked. The
/// strategy's ticket and the destination are under a lock of their own,
/// taken under the queues' lock at most and taking none.
pub(crate) struct DatagramCell<K, D, P> {
    key: DatagramKey,
    payload: Bytes,
    parameters: P,
    progress: Arc<DatagramProgress>,
    route: Mutex<Route<K, D>>,
    panicked: Arc<DriverPanicFlag>,
}

/// Where a datagram's intent went: the strategy's ticket, while it holds
/// one, and the destination.
struct Route<K, D> {
    ticket: Option<K>,
    destination: D,
}

impl<K, D, P> DatagramCell<K, D, P> {
    /// The cell of the datagram of `key`, of `payload` sent with
    /// `parameters`, published for `destination` with the strategy's
    /// `ticket`, through queues whose driver panicked once `panicked` is
    /// set.
    pub(crate) fn new(
        key: DatagramKey,
        payload: Bytes,
        parameters: P,
        ticket: K,
        destination: D,
        panicked: Arc<DriverPanicFlag>,
    ) -> Arc<Self> {
        Arc::new(Self {
            key,
            payload,
            parameters,
            progress: DatagramProgress::new(),
            route: Mutex::new(Route {
                ticket: Some(ticket),
                destination,
            }),
            panicked,
        })
    }

    /// The intent of the datagram.
    pub(crate) fn intent(&self) -> DatagramIntent<P>
    where
        P: Clone,
    {
        DatagramIntent::new(self.key, self.payload.len(), self.parameters.clone())
    }

    /// The datagram's payload.
    pub(crate) fn payload(&self) -> &Bytes {
        &self.payload
    }

    /// Wake who waits for the datagram to be settled, without moving it.
    pub(crate) fn wake_settled_waiters(&self) {
        self.progress.wake_waiters();
    }

    /// The datagram's progress, and whether the driver of its queues
    /// panicked: what its ticket reads.
    pub(crate) fn progress(&self) -> (&Arc<DatagramProgress>, &Arc<DriverPanicFlag>) {
        (&self.progress, &self.panicked)
    }

    /// Where the datagram stands, for a holder of its ticket; `None` once
    /// its holder withdrew it. One that waits is too large for now when
    /// the strategy's ticket says so.
    pub(crate) fn state(&self) -> Option<DatagramState>
    where
        K: IntentTicketState,
    {
        match self.progress.state(&self.panicked)? {
            DatagramState::Waiting => {
                let too_large = lock(&self.route)
                    .ticket
                    .as_ref()
                    .is_some_and(|ticket| matches!(ticket.state(), IntentState::WaitingTooLarge));
                Some(if too_large {
                    DatagramState::WaitingTooLarge
                } else {
                    DatagramState::Waiting
                })
            }
            state => Some(state),
        }
    }

    /// Withdraw the datagram for its holder; once the driver panicked,
    /// only what that would report, with nothing changed and the
    /// strategy's ticket left alone.
    pub(crate) fn withdraw_for_holder(&self) -> WithdrawReport
    where
        K: IntentTicketWithdraw,
    {
        if self.panicked.is_set() {
            return self.progress.withdraw_report();
        }
        self.withdraw(Withdrawal::Holder)
    }

    /// The length of the datagram's payload.
    pub(crate) fn len(&self) -> usize {
        self.payload.len()
    }

    /// Whether the datagram waits to be sent.
    pub(crate) fn is_waiting(&self) -> bool {
        self.progress.is_waiting()
    }

    /// Whether the datagram's packet may still be acknowledged, so that
    /// its ticket hears of it: it is in flight, or was declared lost.
    pub(crate) fn awaits_acknowledgment(&self) -> bool {
        self.progress.awaits_acknowledgment()
    }

    /// The datagram is about to be written: whether it may.
    pub(crate) fn start_writing(&self) -> bool {
        self.progress.start_writing()
    }

    /// The datagram's packet was acknowledged, or, if `delivered` is
    /// false, declared lost.
    pub(crate) fn settle(&self, delivered: bool) {
        self.progress.settle(delivered);
    }

    /// Withdraw the datagram as `withdrawal` says; then the strategy's
    /// ticket, if it was withdrawn now, outside the lock.
    pub(crate) fn withdraw(&self, withdrawal: Withdrawal) -> WithdrawReport
    where
        K: IntentTicketWithdraw,
    {
        let report = self.progress.withdraw(withdrawal);
        if report == WithdrawReport::Withdrawn {
            self.withdraw_from_strategy();
        }
        report
    }

    /// The strategy no longer needs to keep the intent: withdraw its ticket,
    /// outside the lock. Whether the datagram is written is its progress's
    /// to tell, so what the strategy reports does not matter.
    fn withdraw_from_strategy(&self)
    where
        K: IntentTicketWithdraw,
    {
        let ticket = lock(&self.route).ticket.take();
        if let Some(ticket) = ticket {
            let _ = ticket.withdraw();
        }
    }

    /// The datagram's intent was not fulfilled for `cause`: if it still
    /// waits, its destination falls back at once, and it is published again
    /// through `publish` to the destination it gives now if it degraded,
    /// or withdrawn if it has none left. The ticket of the datagram stays
    /// the same.
    pub(crate) fn resolve_unfulfilled<H>(&self, cause: Unfulfilled, publish: &H)
    where
        K: IntentTicketWithdraw,
        D: SendDestination,
        P: Clone,
        H: SendIntentHandle<DatagramIntent<P>, D::Current, Outcome = K>,
    {
        if !self.progress.is_waiting() {
            return;
        }
        let current = {
            let mut route = lock(&self.route);
            match route.destination.on_unfulfilled(cause) {
                DestinationFallback::Degraded => Some(route.destination.current()),
                DestinationFallback::Exhausted => None,
            }
        };
        match current {
            Some(destination) => {
                let ticket = publish.publish_to(self.intent(), destination);
                let replaced = lock(&self.route).ticket.replace(ticket);
                drop(replaced);
                // withdrawn while it was published again: the new intent is
                // not needed either
                if !self.progress.is_waiting() {
                    self.withdraw_from_strategy();
                }
            }
            None => {
                self.withdraw(Withdrawal::Cause(
                    DatagramWithdrawCause::DestinationExhausted,
                ));
            }
        }
    }
}

/// The ticket of one datagram sent (`DatagramTicket`), held apart from the
/// connection: it tells where the datagram stands and waits for it to be
/// settled. `K` is the ticket of the send strategy, `D` the destination and
/// `P` the parameters the datagram was sent with, `C` the pointer to the
/// ticket's credential ([`CredentialPointer`]).
///
/// It can be cloned where `C` can: sent with the credential itself, it is
/// turned into one with a shared credential by
/// [`into_shared`](Self::into_shared). Once the last holder of the
/// credential drops its ticket, the datagram is withdrawn, if it was not
/// written into a packet yet; [`release`](Self::release) lets it go
/// without withdrawing it.
#[must_use = "dropping the ticket withdraws the datagram; `release` lets it go without that"]
pub struct DatagramTicket<
    K: IntentTicketWithdraw,
    D,
    P,
    C: CredentialPointer<DatagramTicketCredential> = DatagramTicketCredential,
> {
    cell: Arc<DatagramCell<K, D, P>>,
    /// `None` once it was handed back, by a release, a withdrawal or a
    /// move to a shared pointer.
    credential: Option<C>,
}

impl<K: IntentTicketWithdraw, D, P, C: CredentialPointer<DatagramTicketCredential>> fmt::Debug
    for DatagramTicket<K, D, P, C>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramTicket")
            .field("key", &self.cell.key)
            .field("progress", &self.cell.progress)
            .finish_non_exhaustive()
    }
}

/// A clone holds the same credential, and is a ticket of the same
/// datagram.
impl<K: IntentTicketWithdraw, D, P, C: CredentialPointer<DatagramTicketCredential> + Clone> Clone
    for DatagramTicket<K, D, P, C>
{
    fn clone(&self) -> Self {
        Self {
            cell: Arc::clone(&self.cell),
            credential: self.credential.clone(),
        }
    }
}

impl<K: IntentTicketWithdraw, D, P> DatagramTicket<K, D, P> {
    /// The ticket of the datagram of `cell`, with its credential.
    pub(crate) fn new(cell: Arc<DatagramCell<K, D, P>>) -> Self {
        let credential = DatagramTicketCredential::new(cell.key);
        Self {
            cell,
            credential: Some(credential),
        }
    }

    /// The same ticket with the credential behind the shared pointer `Q`
    /// ([`Arc`] or [`Rc`](alloc::rc::Rc)), so that it can be cloned.
    pub fn into_shared<Q>(mut self) -> DatagramTicket<K, D, P, Q>
    where
        Q: CredentialPointer<DatagramTicketCredential> + From<DatagramTicketCredential>,
    {
        DatagramTicket {
            cell: Arc::clone(&self.cell),
            credential: self.credential.take().map(Q::from),
        }
    }

    /// Withdraw the datagram: [`WithdrawReport::Withdrawn`] if it was not
    /// written into a packet, and then it will not be;
    /// [`WithdrawReport::Consumed`] if it was. A datagram withdrawn already,
    /// by its queue or as its destination had nothing left, reports
    /// `Withdrawn` as well. Only the one holder of the credential itself
    /// withdraws.
    ///
    /// Once the driver of its queues panicked, it reports as it would, but
    /// changes nothing.
    pub fn withdraw(mut self) -> WithdrawReport {
        self.credential = None;
        self.cell.withdraw_for_holder()
    }
}

impl<K: IntentTicketWithdraw, D, P, C: CredentialPointer<DatagramTicketCredential>>
    DatagramTicket<K, D, P, C>
{
    /// Let the datagram go without withdrawing it, if this holder is the
    /// last of its credential: it is still sent, and nothing hears whether
    /// it is acknowledged or lost. Otherwise only this holder lets go.
    pub fn release(mut self) {
        let _ = self.credential.take().and_then(C::into_credential);
    }

    /// Done once the datagram was acknowledged, declared lost, or withdrawn
    /// without its holder asking; called again, the same at once, unless a
    /// late acknowledgment of a lost datagram came between. A datagram that
    /// waits as too large for now goes on waiting.
    ///
    /// Once the driver of its queues panicked, a datagram that waits to be
    /// sent is settled as withdrawn as the layer ended
    /// ([`DatagramWithdrawCause::LayerEnded`]), one in flight as
    /// [`Lost`](DatagramSettlement::Lost), and the wait ends.
    pub fn settled(&mut self) -> impl Future<Output = DatagramSettlement> + '_ {
        let cell = &self.cell;
        poll_fn(move |cx| cell.progress.poll_settled(cx, &cell.panicked))
    }
}

/// The strategy's ticket tells whether a datagram that waits is too large
/// for now.
impl<K, D, P, C> DatagramTicket<K, D, P, C>
where
    K: IntentTicketWithdraw + IntentTicketState,
    C: CredentialPointer<DatagramTicketCredential>,
{
    /// Where the datagram stands now.
    pub fn state(&self) -> DatagramState {
        // invariant: only `withdraw` withdraws for the holder, and it takes
        // the ticket, which only the one holder of the credential has
        self.cell
            .state()
            .expect("a ticket that reads the state did not withdraw the datagram")
    }
}

/// The last holder of the credential withdraws the datagram when it drops
/// its ticket.
impl<K: IntentTicketWithdraw, D, P, C: CredentialPointer<DatagramTicketCredential>> Drop
    for DatagramTicket<K, D, P, C>
{
    fn drop(&mut self) {
        if self
            .credential
            .take()
            .and_then(C::into_credential)
            .is_some()
        {
            self.cell.withdraw_for_holder();
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
