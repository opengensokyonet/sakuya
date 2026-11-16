//! Sending datagrams: the intent of each datagram ([`DatagramIntent`]), the
//! DATAGRAM frames that write it ([`DatagramFrames`]), and the ticket the
//! application keeps for it ([`DatagramTicket`]).
//!
//! A datagram's content is fixed in its intent, so writing it takes no
//! component's lock: the DATAGRAM frame source writes the payload it
//! borrows from the intent the strategy planned. Every intent of a datagram
//! shares the datagram's progress with its ticket and the summary of its
//! frame: whether it waits, was withdrawn, sent, acknowledged or lost. The
//! progress orders writing and withdrawing, which may happen at once on the
//! driver's thread and the application's: only one of them takes place
//! (connection-driver «各组件对意愿票据的要求»). A DATAGRAM is not sent
//! again when it is lost (RFC 9221 §5.1): its ticket hears of the loss, and
//! the frame's acknowledgment is its delivery (§5.2).
//!
//! | Frame | Kind | Item | Summary | Delivered | Lost |
//! | --- | --- | --- | --- | --- | --- |
//! | DATAGRAM | [`DatagramFrames`] | the intent | [`DatagramSummary`]: the datagram's progress | the ticket says acknowledged | the ticket says lost; nothing is sent again |

use core::{
    fmt,
    future::{Future, poll_fn},
    marker::PhantomData,
    task::{Context, Poll, Waker},
};
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicBool, Ordering},
};

use bytes::{Buf, Bytes, BytesMut};
use sakuya_recovery::packet_number_space::PacketNumberSpaceKind;
use sakuya_stream::send_options::{
    destination::{DestinationFallback, SendDestination, Unfulfilled},
    urgency::{SendUrgency, Urgency},
};
use sakuya_wire::{
    datagram::{
        DatagramFrame,
        codec::{
            WriteDatagramFrameWithLengthHostExt as _, WriteDatagramFrameWithoutLengthHostExt as _,
        },
    },
    frame::NoLength,
    var_int::{VarInt, VarIntWidth},
};

use super::{
    DatagramChoices, DatagramIntentHandleOf, DatagramQueues, DatagramQueuesOf, DatagramTicketOf,
    frame_len_with_length,
};
use crate::{
    clock::InstantOf,
    error::ConnectionErrorsOf,
    feedback::InjectSummary,
    frame_source::{FindFrameSource, FrameSource, FrameSourceKind, NoIntent, PublishIntent},
    send_strategy::{
        AnyActiveLinkPath, IntentTicketWithdraw, MinimumLengths, SendIntent, SendIntentHandle,
        SendIntentIntake, SendStrategy, SharedPublishTo,
        ranked::{IntentTicket, RankedCoreIntent, RankedIntent, SendPriority, SendRank},
    },
    take::{GetAt, GetOptionalAt, Lineage},
    v1::application_handles::connection::{keep_waker, lock, wake_all},
    v1::{
        CloseCauseOf,
        send::SendTypes,
        send_planning::{IntakeOf, IntakePublishOutcome, SendStrategyIntake, SendStrategyOf},
    },
    write::{
        DelimitedFrame, InFlightClass, OpenPacket, PacketPosition, PacketWriting, SummaryOf,
        Supplied, ToPacketEndFrame,
    },
};

/// The invariant of every write here: a `BytesMut` takes every byte, so
/// writing into one does not fail.
const TAKES_EVERY_BYTE: &str = "a BytesMut takes every byte";

// ---- the frames written ----

/// A DATAGRAM frame with a Length field may be followed by more frames.
impl<D: Buf> DelimitedFrame for DatagramFrame<D, VarIntWidth> {
    type Class = InFlightClass;
    const ACK_ELICITING: bool = true;

    fn encoded_len(&self) -> usize {
        DatagramFrame::encoded_len(self)
    }

    fn write_to(self, buffer: &mut BytesMut) {
        buffer
            .sync_write_datagram_frame_with_length_unpin(self)
            .expect(TAKES_EVERY_BYTE);
    }
}

/// A DATAGRAM frame without a Length field extends to the end of the
/// packet.
impl<D: Buf> ToPacketEndFrame for DatagramFrame<D, NoLength> {
    type Class = InFlightClass;
    const ACK_ELICITING: bool = true;

    fn encoded_len(&self) -> usize {
        DatagramFrame::encoded_len(self)
    }

    fn write_to(self, buffer: &mut BytesMut) {
        buffer
            .sync_write_datagram_frame_without_length_unpin(self)
            .expect(TAKES_EVERY_BYTE);
    }
}

// ---- intents ----

/// The frame sources of the extension: DATAGRAM, its one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameSourceId {
    /// The DATAGRAM frames.
    Datagram,
}

/// One datagram is to be sent (`DatagramIntent`): its payload and the
/// parameters `P` it is sent with, and the progress it shares with its
/// ticket. Its content is fixed in it: writing it takes no lock but the
/// progress's.
#[derive(Clone)]
pub struct DatagramIntent<P> {
    payload: Bytes,
    parameters: P,
    progress: Arc<DatagramProgress>,
}

impl<P: fmt::Debug> fmt::Debug for DatagramIntent<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramIntent")
            .field("len", &self.payload.len())
            .field("parameters", &self.parameters)
            .finish_non_exhaustive()
    }
}

impl<P> DatagramIntent<P> {
    /// The intent of a datagram of `payload`, sent with `parameters`, whose
    /// progress is `progress`.
    pub(crate) fn new(payload: Bytes, parameters: P, progress: Arc<DatagramProgress>) -> Self {
        Self {
            payload,
            parameters,
            progress,
        }
    }

    /// The datagram's payload.
    pub fn payload(&self) -> &Bytes {
        &self.payload
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
        let len = self.payload.len();
        MinimumLengths {
            with_length: frame_len_with_length(len),
            as_last: 1 + len,
        }
    }
}

/// A datagram is application data, by the urgency of its parameters; it
/// does not hold its place, and it is consumed before its source is given
/// it, as its content is fixed and no component's lock orders withdrawing
/// it against writing it.
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

/// The ticket of a datagram keeps the strategy's ticket, to withdraw the
/// intent when the datagram is withdrawn.
impl<P> RankedCoreIntent for DatagramIntent<P> {
    type Outcome<C> = IntentTicket<C>;
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
    /// Waiting, but its intent was not fulfilled for the cause: its
    /// destination decides what follows, the next time the queue looks.
    Unfulfilled(Unfulfilled),
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

impl Stage {
    fn is_waiting(self) -> bool {
        matches!(self, Self::Waiting | Self::Unfulfilled(_))
    }
}

/// How a datagram is withdrawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Withdrawal {
    /// Its holder asked: it withdrew or dropped its ticket.
    Holder,
    /// Without its holder asking.
    Cause(DatagramWithdrawCause),
}

/// The progress of one datagram, shared by its intents, the summary of its
/// frame and its ticket: what orders writing it against withdrawing it,
/// and what its ticket reads and waits on. Its lock is taken under the
/// queue's at most, and takes none.
pub(crate) struct DatagramProgress {
    state: Mutex<ProgressState>,
}

struct ProgressState {
    stage: Stage,
    /// Who waits for the datagram to be settled.
    wakers: Vec<Waker>,
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
            state: Mutex::new(ProgressState {
                stage: Stage::Waiting,
                wakers: Vec::new(),
            }),
        })
    }

    /// Move from `stage` as `next` says, waking who waits if it moved.
    fn advance<R>(&self, next: impl FnOnce(Stage) -> (Option<Stage>, R)) -> R {
        let mut state = lock(&self.state);
        let (to, result) = next(state.stage);
        if let Some(to) = to {
            state.stage = to;
            wake_all(&mut state.wakers);
        }
        result
    }

    /// Whether the datagram waits to be sent.
    pub(crate) fn is_waiting(&self) -> bool {
        lock(&self.state).stage.is_waiting()
    }

    /// Whether the datagram was written into a packet whose fate is not
    /// known yet.
    fn is_in_flight(&self) -> bool {
        lock(&self.state).stage == Stage::Sent
    }

    /// The frame source is about to write the datagram: whether it may. It
    /// may only while the datagram waits, and the datagram counts as sent
    /// from then on.
    fn start_writing(&self) -> bool {
        self.advance(|stage| match stage {
            Stage::Waiting => (Some(Stage::Sent), true),
            _ => (None, false),
        })
    }

    /// The packet the datagram was written into was acknowledged, or, if
    /// `delivered` is false, declared lost. A late acknowledgment of a lost
    /// packet counts too.
    fn settle(&self, delivered: bool) {
        self.advance(|stage| match (stage, delivered) {
            (Stage::Sent | Stage::Lost, true) => (Some(Stage::Acknowledged), ()),
            (Stage::Sent, false) => (Some(Stage::Lost), ()),
            _ => (None, ()),
        });
    }

    /// The datagram is withdrawn as `withdrawal` says, unless it was
    /// written already.
    pub(crate) fn withdraw(&self, withdrawal: Withdrawal) -> WithdrawReport {
        self.advance(|stage| match stage {
            Stage::Waiting | Stage::Unfulfilled(_) => (
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

    /// The datagram's intent was not fulfilled for `cause`.
    fn unfulfilled(&self, cause: Unfulfilled) {
        self.advance(|stage| match stage {
            Stage::Waiting => (Some(Stage::Unfulfilled(cause)), ()),
            _ => (None, ()),
        });
    }

    /// Why the datagram's intent was not fulfilled, if it was and nothing
    /// followed yet; it waits again.
    fn take_unfulfilled(&self) -> Option<Unfulfilled> {
        let mut state = lock(&self.state);
        match state.stage {
            Stage::Unfulfilled(cause) => {
                state.stage = Stage::Waiting;
                Some(cause)
            }
            _ => None,
        }
    }

    /// Wake who waits for the datagram to be settled, without moving it:
    /// they look again.
    fn wake_waiters(&self) {
        wake_all(&mut lock(&self.state).wakers);
    }

    /// What withdrawing the datagram would report now, without withdrawing
    /// it.
    fn withdraw_report(&self) -> WithdrawReport {
        match lock(&self.state).stage {
            Stage::Waiting
            | Stage::Unfulfilled(_)
            | Stage::WithdrawnByHolder
            | Stage::Withdrawn(_) => WithdrawReport::Withdrawn,
            Stage::Sent | Stage::Acknowledged | Stage::Lost => WithdrawReport::Consumed,
        }
    }

    /// Where the datagram stands, for a holder of its ticket; `None` once
    /// its holder withdrew it. Once `panicked` is set, a datagram that waits
    /// counts as withdrawn as the layer ended, and one in flight as lost.
    fn state(&self, panicked: &DriverPanicFlag) -> Option<DatagramState> {
        Some(match lock(&self.state).stage {
            Stage::Waiting | Stage::Unfulfilled(_) if panicked.is_set() => {
                DatagramState::Withdrawn(DatagramWithdrawCause::LayerEnded)
            }
            Stage::Sent if panicked.is_set() => DatagramState::Lost,
            Stage::Waiting | Stage::Unfulfilled(_) => DatagramState::Waiting,
            Stage::WithdrawnByHolder => return None,
            Stage::Withdrawn(cause) => DatagramState::Withdrawn(cause),
            Stage::Sent => DatagramState::Sent,
            Stage::Acknowledged => DatagramState::Acknowledged,
            Stage::Lost => DatagramState::Lost,
        })
    }

    /// The settlement of the datagram, once there is one; while there is
    /// none, the waker of `cx` is kept and woken when there may be. Once
    /// `panicked` is set, looked at under the same lock, a datagram that
    /// waits is settled as withdrawn as the layer ended, and one in flight
    /// as lost: its packet's fate is never known, as when the link path it
    /// went on ended before it was settled.
    fn poll_settled(
        &self,
        cx: &mut Context<'_>,
        panicked: &DriverPanicFlag,
    ) -> Poll<DatagramSettlement> {
        let mut state = lock(&self.state);
        match state.stage {
            Stage::Waiting | Stage::Unfulfilled(_) if panicked.is_set() => Poll::Ready(
                DatagramSettlement::Withdrawn(DatagramWithdrawCause::LayerEnded),
            ),
            Stage::Sent if panicked.is_set() => Poll::Ready(DatagramSettlement::Lost),
            Stage::Acknowledged => Poll::Ready(DatagramSettlement::Acknowledged),
            Stage::Lost => Poll::Ready(DatagramSettlement::Lost),
            Stage::Withdrawn(cause) => Poll::Ready(DatagramSettlement::Withdrawn(cause)),
            Stage::Waiting | Stage::Unfulfilled(_) | Stage::Sent | Stage::WithdrawnByHolder => {
                keep_waker(&mut state.wakers, cx.waker());
                Poll::Pending
            }
        }
    }
}

// ---- the frame source ----

/// The summary of a DATAGRAM frame written into a packet: the datagram's
/// progress, which its ticket reads, as long as anything holds it.
#[derive(Debug, Clone)]
pub struct DatagramSummary {
    progress: Weak<DatagramProgress>,
}

/// The DATAGRAM frames of the datagrams' intents, as a kind of frame
/// source.
#[derive(Debug)]
pub enum DatagramFrames {}

impl FrameSourceKind for DatagramFrames {
    type Item<'a> = &'a DatagramIntent<Urgency>;
    type Summary<I> = DatagramSummary;
    type Intent = NoIntent;
}

/// The frames are written from the intents themselves, and what comes of
/// them goes to the progress the summaries hold; an intent not fulfilled
/// goes on as its destination says at once, through the queues of the
/// established layer, which the lend appends to the lineage, publishing
/// through the handle of the intake in the connection node.
impl<T, L, V, Ii, Iq, Idx> FindFrameSource<T, L, V, (Ii, Iq, Idx)> for DatagramFrames
where
    T: DatagramChoices,
    L: ConnectionErrorsOf,
    SendTypes<T, L>: IntakePublishOutcome<DatagramIntent<Urgency>, AnyActiveLinkPath>,
    SendStrategyOf<T, L>: SendStrategy<SendTypes<T, L>>,
    DatagramTicketOf<T, L>: IntentTicketWithdraw,
    IntakeOf<T, L>: SendIntentIntake<AnyActiveLinkPath>
        + SharedPublishTo<DatagramIntent<Urgency>, AnyActiveLinkPath, Idx>,
    DatagramIntentHandleOf<T, L, Idx>: SendIntentHandle<
            DatagramIntent<Urgency>,
            AnyActiveLinkPath,
            Outcome = DatagramTicketOf<T, L>,
        >,
    V: GetAt<SendStrategyIntake<IntakeOf<T, L>>, Ii> + GetOptionalAt<DatagramQueuesOf<T, L>, Iq>,
{
    type Source<'l, 'r>
        = LineageDatagramFrameSource<
        'l,
        'r,
        V,
        DatagramQueuesOf<T, L>,
        CloseCauseOf<T, L>,
        DatagramIntentHandleOf<T, L, Idx>,
        Iq,
    >
    where
        V: 'l,
        'r: 'l;

    fn find<'l, 'r>(lineage: &'l mut Lineage<'r, V>, _: InstantOf<T>) -> Self::Source<'l, 'r> {
        let publish = lineage
            .get::<SendStrategyIntake<IntakeOf<T, L>>, Ii>()
            .intake()
            .handle::<DatagramIntent<Urgency>, Idx>();
        LineageDatagramFrameSource::new(lineage, publish)
    }
}

/// The DATAGRAM frame source in a lineage `V`
/// (`LineageDatagramFrameSource`): it writes as [`DatagramFrameSource`]
/// does, and when an intent is not fulfilled it lets the queues `Q` of the
/// established layer, which the lend appended to the lineage at the
/// position `Iq`, resolve it at once, publishing again through the handle
/// `P`. `Lc` is the queues' close cause.
pub struct LineageDatagramFrameSource<'l, 'r, V, Q, Lc, P, Iq> {
    lineage: &'l mut Lineage<'r, V>,
    publish: P,
    types: PhantomData<DatagramSourceTypes<Q, Lc, Iq>>,
}

/// What [`LineageDatagramFrameSource`] takes its components by.
type DatagramSourceTypes<Q, Lc, Iq> = fn() -> (Q, Lc, Iq);

impl<V, Q, Lc, P, Iq> fmt::Debug for LineageDatagramFrameSource<'_, '_, V, Q, Lc, P, Iq> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LineageDatagramFrameSource")
    }
}

impl<'l, 'r, V, Q, Lc, P, Iq> LineageDatagramFrameSource<'l, 'r, V, Q, Lc, P, Iq> {
    /// The source in `lineage`, publishing through `publish`.
    pub(crate) fn new(lineage: &'l mut Lineage<'r, V>, publish: P) -> Self {
        Self {
            lineage,
            publish,
            types: PhantomData,
        }
    }
}

/// Without the established layer an intent not fulfilled only keeps its
/// cause: its queue ended with the layer and withdrew it.
impl<V, Q, Lc, P, Iq> FrameSource for LineageDatagramFrameSource<'_, '_, V, Q, Lc, P, Iq>
where
    V: GetOptionalAt<Q, Iq>,
    Q: DatagramQueues<Lc>,
    P: SendIntentHandle<DatagramIntent<Urgency>, AnyActiveLinkPath, Outcome = Q::StrategyTicket>,
{
    type Summary = DatagramSummary;
    type Class = InFlightClass;
    type Item<'a> = &'a DatagramIntent<Urgency>;
    /// A lost DATAGRAM is not sent again (RFC 9221 §5.1).
    type Intent = NoIntent;

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
        DatagramFrameSource.supply::<W, R, Idx>(intent, packet)
    }

    fn delivered<Pb, Idx>(
        &mut self,
        publish: &mut Pb,
        space: PacketNumberSpaceKind,
        summary: DatagramSummary,
    ) where
        Pb: PublishIntent<NoIntent, Idx>,
    {
        DatagramFrameSource.delivered::<Pb, Idx>(publish, space, summary);
    }

    fn lost<Pb, Idx>(
        &mut self,
        publish: &mut Pb,
        space: PacketNumberSpaceKind,
        summary: &DatagramSummary,
    ) where
        Pb: PublishIntent<NoIntent, Idx>,
    {
        DatagramFrameSource.lost::<Pb, Idx>(publish, space, summary);
    }

    /// The datagram's progress keeps the cause, and the queues let its
    /// destination decide at once: it is published again, with the same
    /// ticket, while the destination degrades, and withdrawn once it has
    /// nothing left.
    fn unfulfilled(&mut self, intent: &DatagramIntent<Urgency>, cause: Unfulfilled) {
        intent.progress.unfulfilled(cause);
        if let Some(queues) = self.lineage.get_optional_mut::<Q, Iq>() {
            queues.resolve_unfulfilled(&self.publish);
        }
    }
}

/// What writes the DATAGRAM frames and takes back what comes of them: it
/// holds nothing, as the payload and the progress are in each intent.
#[derive(Debug, Clone, Copy, Default)]
pub struct DatagramFrameSource;

impl FrameSource for DatagramFrameSource {
    type Summary = DatagramSummary;
    type Class = InFlightClass;
    type Item<'a> = &'a DatagramIntent<Urgency>;
    /// A lost DATAGRAM is not sent again (RFC 9221 §5.1).
    type Intent = NoIntent;

    /// The whole payload in one frame: without a Length field when the
    /// item has the last position, otherwise with one. Nothing is written
    /// when the datagram was withdrawn before, or the frame does not fit.
    fn supply<W, Q, Idx>(
        &mut self,
        intent: &DatagramIntent<Urgency>,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<DatagramSummary, Idx>,
        Q: PacketPosition,
    {
        let summary = || {
            <SummaryOf<W>>::inject_summary(DatagramSummary {
                progress: Arc::downgrade(&intent.progress),
            })
        };
        let payload = intent.payload.clone();
        match packet.into_last() {
            Ok(last) => {
                let frame = DatagramFrame::without_length(payload);
                if ToPacketEndFrame::encoded_len(&frame) > last.remaining()
                    || !intent.progress.start_writing()
                {
                    return Supplied::Open(last.into_position());
                }
                match last.write_last(frame, summary()) {
                    Ok(closed) => Supplied::Closed(closed),
                    Err(rejected) => {
                        debug_assert!(false, "the frame was measured against the room");
                        Supplied::Open(rejected.into_parts().0.into_position())
                    }
                }
            }
            Err(mut packet) => {
                let width =
                    VarIntWidth::shortest(VarInt::try_from(payload.len()).unwrap_or(VarInt::MAX));
                let Ok(frame) = DatagramFrame::with_length(width, payload) else {
                    // invariant: the shortest width holds the length
                    return Supplied::Open(packet);
                };
                if DelimitedFrame::encoded_len(&frame) > packet.remaining()
                    || !intent.progress.start_writing()
                {
                    return Supplied::Open(packet);
                }
                let written = packet.write_frame(frame, summary());
                debug_assert!(written.is_ok(), "the frame was measured against the room");
                Supplied::Open(packet)
            }
        }
    }

    fn delivered<Pb, Idx>(&mut self, _: &mut Pb, _: PacketNumberSpaceKind, summary: DatagramSummary)
    where
        Pb: PublishIntent<NoIntent, Idx>,
    {
        if let Some(progress) = summary.progress.upgrade() {
            progress.settle(true);
        }
    }

    fn lost<Pb, Idx>(&mut self, _: &mut Pb, _: PacketNumberSpaceKind, summary: &DatagramSummary)
    where
        Pb: PublishIntent<NoIntent, Idx>,
    {
        if let Some(progress) = summary.progress.upgrade() {
            progress.settle(false);
        }
    }

    /// The datagram's progress keeps the cause; its destination decides
    /// what follows when its queue next looks at it: it is published again,
    /// with the same ticket, while the destination degrades, and withdrawn
    /// once it has nothing left.
    fn unfulfilled(&mut self, intent: &DatagramIntent<Urgency>, cause: Unfulfilled) {
        intent.progress.unfulfilled(cause);
    }
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

/// A datagram as its queue and its ticket hold it: its intent, which it is
/// published again from, its progress, the ticket the strategy gave for its
/// intent and its destination `D`, and whether the driver of its queues
/// panicked. The strategy's ticket and the destination are under a lock of
/// their own, taken under no other lock and taking none.
pub(crate) struct DatagramCell<K, D, P> {
    intent: DatagramIntent<P>,
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
    /// The cell of `intent`, published for `destination` with the
    /// strategy's `ticket`, through queues whose driver panicked once
    /// `panicked` is set.
    pub(crate) fn new(
        intent: DatagramIntent<P>,
        ticket: K,
        destination: D,
        panicked: Arc<DriverPanicFlag>,
    ) -> Arc<Self> {
        Arc::new(Self {
            intent,
            route: Mutex::new(Route {
                ticket: Some(ticket),
                destination,
            }),
            panicked,
        })
    }

    /// Wake who waits for the datagram to be settled, without moving it.
    pub(crate) fn wake_settled_waiters(&self) {
        self.intent.progress.wake_waiters();
    }

    /// Withdraw the datagram for its holder; once the driver panicked,
    /// only what that would report, with nothing changed and the
    /// strategy's ticket left alone.
    fn withdraw_for_holder(&self) -> WithdrawReport
    where
        K: IntentTicketWithdraw,
    {
        if self.panicked.is_set() {
            return self.intent.progress.withdraw_report();
        }
        self.withdraw(Withdrawal::Holder)
    }

    /// The length of the datagram's payload.
    pub(crate) fn len(&self) -> usize {
        self.intent.payload.len()
    }

    /// Whether the datagram waits to be sent.
    pub(crate) fn is_waiting(&self) -> bool {
        self.intent.progress.is_waiting()
    }

    /// Whether the datagram was written into a packet whose fate is not
    /// known yet.
    pub(crate) fn is_in_flight(&self) -> bool {
        self.intent.progress.is_in_flight()
    }

    /// Withdraw the datagram as `withdrawal` says; then the strategy's
    /// ticket, if it was withdrawn now, outside the lock.
    pub(crate) fn withdraw(&self, withdrawal: Withdrawal) -> WithdrawReport
    where
        K: IntentTicketWithdraw,
    {
        let report = self.intent.progress.withdraw(withdrawal);
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

    /// If the datagram's intent was not fulfilled, let its destination fall
    /// back: published again through `publish` to the destination it gives
    /// now if it degraded, withdrawn if it has none left. The ticket of the
    /// datagram stays the same.
    pub(crate) fn resolve_unfulfilled<H>(&self, publish: &H)
    where
        K: IntentTicketWithdraw,
        D: SendDestination,
        P: Clone,
        H: SendIntentHandle<DatagramIntent<P>, D::Current, Outcome = K>,
    {
        let Some(cause) = self.intent.progress.take_unfulfilled() else {
            return;
        };
        let current = {
            let mut route = lock(&self.route);
            match route.destination.on_unfulfilled(cause) {
                DestinationFallback::Degraded => Some(route.destination.current()),
                DestinationFallback::Exhausted => None,
            }
        };
        match current {
            Some(destination) => {
                let ticket = publish.publish_to(self.intent.clone(), destination);
                let replaced = lock(&self.route).ticket.replace(ticket);
                drop(replaced);
                // withdrawn while it was published again: the new intent is
                // not needed either
                if !self.intent.progress.is_waiting() {
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

/// The ticket of one datagram sent (`DatagramTicket`): it tells where the
/// datagram stands and waits for it to be settled. `K` is the ticket of
/// the send strategy, `D` the destination and `P` the parameters the
/// datagram was sent with.
///
/// Dropping it withdraws the datagram, if it was not written into a packet
/// yet; [`release`](Self::release) lets it go without withdrawing it.
#[must_use = "dropping the ticket withdraws the datagram; `release` lets it go without that"]
pub struct DatagramTicket<K: IntentTicketWithdraw, D, P> {
    cell: Arc<DatagramCell<K, D, P>>,
    /// Whether dropping the ticket withdraws the datagram: until it is
    /// withdrawn or released.
    withdraws_on_drop: bool,
}

impl<K: IntentTicketWithdraw, D, P> fmt::Debug for DatagramTicket<K, D, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramTicket")
            .field("progress", &self.cell.intent.progress)
            .finish_non_exhaustive()
    }
}

impl<K: IntentTicketWithdraw, D, P> DatagramTicket<K, D, P> {
    /// The ticket of the datagram of `cell`.
    pub(crate) fn new(cell: Arc<DatagramCell<K, D, P>>) -> Self {
        Self {
            cell,
            withdraws_on_drop: true,
        }
    }

    /// Withdraw the datagram: [`WithdrawReport::Withdrawn`] if it was not
    /// written into a packet, and then it will not be;
    /// [`WithdrawReport::Consumed`] if it was. A datagram withdrawn already,
    /// by its queue or as its destination had nothing left, reports
    /// `Withdrawn` as well.
    ///
    /// Once the driver of its queues panicked, it reports as it would, but
    /// changes nothing.
    pub fn withdraw(mut self) -> WithdrawReport {
        self.withdraws_on_drop = false;
        self.cell.withdraw_for_holder()
    }

    /// Let the datagram go without withdrawing it: it is still sent, and
    /// nothing hears whether it is acknowledged or lost.
    pub fn release(mut self) {
        self.withdraws_on_drop = false;
    }

    /// Where the datagram stands now.
    pub fn state(&self) -> DatagramState {
        // invariant: only `withdraw` withdraws for the holder, and it takes
        // the ticket
        self.cell
            .intent
            .progress
            .state(&self.cell.panicked)
            .expect("a ticket that reads the state did not withdraw the datagram")
    }

    /// Done once the datagram was acknowledged, declared lost, or withdrawn
    /// without its holder asking; called again, the same at once, unless a
    /// late acknowledgment of a lost datagram came between.
    ///
    /// Once the driver of its queues panicked, a datagram that waits to be
    /// sent is settled as withdrawn as the layer ended
    /// ([`DatagramWithdrawCause::LayerEnded`]), one in flight as
    /// [`Lost`](DatagramSettlement::Lost), and the wait ends.
    pub fn settled(&mut self) -> impl Future<Output = DatagramSettlement> + '_ {
        let cell = &self.cell;
        poll_fn(move |cx| cell.intent.progress.poll_settled(cx, &cell.panicked))
    }
}

impl<K: IntentTicketWithdraw, D, P> Drop for DatagramTicket<K, D, P> {
    fn drop(&mut self) {
        if self.withdraws_on_drop {
            self.cell.withdraw_for_holder();
        }
    }
}

#[cfg(test)]
pub(in crate::datagram) mod tests;
