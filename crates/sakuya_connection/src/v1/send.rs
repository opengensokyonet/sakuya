//! What QUIC version 1 sends through the send strategy: acknowledgments of
//! each packet number space and the PING of a probe timeout, as send
//! intents, the items a packet of each kind may carry, and the frame
//! sources that write them.

use core::{marker::PhantomData, time::Duration};

use sakuya_recovery::{
    ack_obligation::{AckDue, AckObligation},
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaces},
    receive_journals::ReceiveJournals,
};
use sakuya_wire::v1::packet_number::PacketNumber;
use sakuya_wire::{
    parts::{CNil, Coproduct},
    v1::frame::{
        ack::{AckFrame, EcnCounts},
        ping::PingFrame,
    },
    var_int::{VarInt, VarIntField},
};

use super::{
    AckObligationsOf, Choices, CloseCauseOf, Part,
    feedback::{AckSummary, FeedbackSummary, ProbePingSummary},
    key_phase::KeyPhaseNumbers,
};
use crate::{
    clock::InstantOf,
    error::ConnectionErrorsOf,
    frame_source::{
        FrameSource, FrameSourceDispatch, FrameSourcePart, HandshakePacket, InitialPacket,
        OneRttPacket, OneRttProbePacket, PacketKind, PartsFrameSources, SettlingResponsePacket,
        ZeroRttPacket,
    },
    send_strategy::{
        FrameSourceSet, MinimumLengths, PlannedPacketKind, SendIntent, SendIntentPart,
        SendIntentsOf, SendStrategyTypes,
        ranked::{RankedIntent, SendPriority, SendRank},
    },
    share::{LinkPathIdentifierOf, LogicalPathKeys},
    take::{GetAt, Lineage},
    write::{
        AckOnlyClass, ClassOfSource, FlightClass, InFlightClass, OpenPacket, PacketPosition,
        PacketWriting, SummaryOf, Supplied,
    },
};

/// The exponent the ACK Delay of this endpoint's ACK frames is encoded
/// with: the default, as this endpoint does not send the
/// `ack_delay_exponent` transport parameter (RFC 9000 §18.2).
const ACK_DELAY_EXPONENT: u32 = 3;

/// The frame sources of version 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameSourceId {
    /// The ACK frames of a packet number space.
    Ack(PacketNumberSpaceKind),
    /// The PING that a probe timeout of a packet number space sends.
    ProbePing(PacketNumberSpaceKind),
}

/// An ACK frame is due in a packet number space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AckIntent {
    space: PacketNumberSpaceKind,
    shortest: usize,
}

impl AckIntent {
    /// An ACK frame is due in `space`, and the shortest one the receive
    /// journals of the space give is `shortest` bytes.
    pub fn new(space: PacketNumberSpaceKind, shortest: usize) -> Self {
        Self { space, shortest }
    }

    /// The packet number space.
    pub fn space(&self) -> PacketNumberSpaceKind {
        self.space
    }
}

impl SendIntent for AckIntent {
    type FrameSourceId = FrameSourceId;
    type Class = AckOnlyClass;

    fn frame_source(&self) -> FrameSourceId {
        FrameSourceId::Ack(self.space)
    }

    fn min_lengths(&self) -> MinimumLengths {
        MinimumLengths {
            with_length: self.shortest,
            as_last: self.shortest,
        }
    }
}

/// The shortest ACK frame `journals` give: the first range only, with no
/// ACK Delay, and the ECN counts if any were received; `None` when nothing
/// was received.
///
/// The ACK frame source writes no more than this when the packet has room
/// for nothing longer, so an intent that needs this much is never planned
/// for a packet its frame does not fit.
pub fn shortest_ack_frame<I: Copy>(journals: &ReceiveJournals<I>) -> Option<usize> {
    shortest_frame(journals).map(|frame| frame.encoded_len())
}

fn ecn_counts<I: Copy>(journals: &ReceiveJournals<I>) -> Option<EcnCounts> {
    journals.ecn_counts().map(|counts| EcnCounts {
        ect0: var_int(counts.ect0),
        ect1: var_int(counts.ect1),
        ce: var_int(counts.ce),
    })
}

fn shortest_frame<I: Copy>(journals: &ReceiveJournals<I>) -> Option<AckFrame> {
    let first = journals.ranges().first()?.clone();
    AckFrame::from_packet_ranges([first], var_int(0), ecn_counts(journals)).ok()
}

impl RankedIntent for AckIntent {
    fn rank(&self) -> SendRank {
        SendRank {
            priority: SendPriority::Acknowledgment,
            holds_place: true,
        }
    }
}

/// A probe timeout of a packet number space wants an ack-eliciting packet
/// sent (RFC 9002 §6.2.4), and nothing else is there to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProbePingIntent {
    space: PacketNumberSpaceKind,
}

impl ProbePingIntent {
    /// A probe of `space`.
    pub fn new(space: PacketNumberSpaceKind) -> Self {
        Self { space }
    }

    /// The packet number space.
    pub fn space(&self) -> PacketNumberSpaceKind {
        self.space
    }
}

impl SendIntent for ProbePingIntent {
    type FrameSourceId = FrameSourceId;
    type Class = InFlightClass;

    fn frame_source(&self) -> FrameSourceId {
        FrameSourceId::ProbePing(self.space)
    }

    fn min_lengths(&self) -> MinimumLengths {
        MinimumLengths {
            with_length: 1,
            as_last: 1,
        }
    }
}

impl RankedIntent for ProbePingIntent {
    fn rank(&self) -> SendRank {
        SendRank {
            priority: SendPriority::Control,
            holds_place: true,
        }
    }
}

/// Version 1's intents.
pub type SendIntents = Coproduct<AckIntent, Coproduct<ProbePingIntent, CNil>>;

impl SendIntentPart for Part {
    type FrameSourceId = FrameSourceId;
    type SendIntents = SendIntents;
}

/// One planned item of version 1: which frame source, for which packet
/// number space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SendItem {
    /// An ACK frame of the space.
    Ack(PacketNumberSpaceKind),
    /// The PING of a probe of the space.
    ProbePing(PacketNumberSpaceKind),
}

/// Whether a packet of `kind` carries content of `space` from a source of
/// `ack`: ACK frames are not allowed in 0-RTT packets (RFC 9000 §12.4); a
/// candidate's and a settling link path's packets carry neither.
fn carries(kind: PlannedPacketKind, space: PacketNumberSpaceKind, ack: bool) -> bool {
    match kind {
        PlannedPacketKind::Initial => space == PacketNumberSpaceKind::Initial,
        PlannedPacketKind::Handshake => space == PacketNumberSpaceKind::Handshake,
        PlannedPacketKind::OneRtt => space == PacketNumberSpaceKind::ApplicationData,
        PlannedPacketKind::ZeroRtt => !ack && space == PacketNumberSpaceKind::ApplicationData,
        PlannedPacketKind::OneRttProbe | PlannedPacketKind::SettlingResponse => false,
    }
}

impl<K: PacketKind> FrameSourcePart<K> for Part {
    type Item<'a> = SendItem;

    fn item(intent: &SendIntents) -> Option<SendItem> {
        let item = match intent {
            Coproduct::Inl(ack) => SendItem::Ack(ack.space),
            Coproduct::Inr(Coproduct::Inl(ping)) => SendItem::ProbePing(ping.space),
            Coproduct::Inr(Coproduct::Inr(never)) => match *never {},
        };
        let (space, ack) = match item {
            SendItem::Ack(space) => (space, true),
            SendItem::ProbePing(space) => (space, false),
        };
        carries(K::KIND, space, ack).then_some(item)
    }

    fn source(item: &SendItem) -> FrameSourceId {
        match *item {
            SendItem::Ack(space) => FrameSourceId::Ack(space),
            SendItem::ProbePing(space) => FrameSourceId::ProbePing(space),
        }
    }
}

// ---- the frame sources ----

/// What the ACK frames of a logical path are made from: the receive
/// journals of its packet number spaces, and what writing one does to them
/// and to the space's ACK obligation.
pub trait AckFrameState<I> {
    /// The receive journals of `space`, if the space is still there.
    fn journals(&self, space: PacketNumberSpaceKind) -> Option<&ReceiveJournals<I>>;

    /// An ACK frame whose Largest Acknowledged is `largest` was written in
    /// `space`: the journals and the obligation learn it. Returns what the
    /// obligation owed before.
    fn ack_written(&mut self, space: PacketNumberSpaceKind, largest: PacketNumber) -> AckDue<I>;
}

/// The ACK frames of a logical path's packet number spaces: what was
/// received, from the receive journals, as far as the packet has room;
/// writing one meets what the space's ACK obligation owed.
#[derive(Debug)]
pub struct AckFrameSource<A, I> {
    state: A,
    now: I,
}

impl<A, I> AckFrameSource<A, I> {
    /// The ACK frames of `state` at `now`.
    pub fn new(state: A, now: I) -> Self {
        Self { state, now }
    }
}

fn var_int(value: u64) -> VarIntField<VarInt> {
    VarIntField::shortest(VarInt::try_from(value).unwrap_or(VarInt::MAX))
}

impl<A, I> FrameSource for AckFrameSource<A, I>
where
    A: AckFrameState<I>,
    I: Copy + Ord + core::ops::Sub<Output = Duration>,
{
    type Summary = FeedbackSummary<I>;
    type Class = AckOnlyClass;
    type Item<'b> = PacketNumberSpaceKind;

    fn supply<W, P>(
        &mut self,
        space: PacketNumberSpaceKind,
        mut packet: OpenPacket<W, AckOnlyClass, P>,
    ) -> Supplied<W, AckOnlyClass, P>
    where
        W: PacketWriting,
        SummaryOf<W>: From<FeedbackSummary<I>>,
        P: PacketPosition,
    {
        let Some(journals) = self.state.journals(space) else {
            return Supplied::Open(packet);
        };
        let Some((largest, arrived)) = journals.largest() else {
            return Supplied::Open(packet);
        };
        // The ACK Delay runs from the arrival of the packet with the largest
        // packet number, in every packet number space: it includes the time
        // a packet waited for its keys (RFC 9000 §13.2.5, SHOULD), which
        // Handshake packets in particular do, and the peer may ignore it in
        // the Initial space (RFC 9002 §5.3). `arrived` is not after `now`.
        let delay = if self.now > arrived {
            let micros = u64::try_from((self.now - arrived).as_micros()).unwrap_or(u64::MAX);
            micros >> ACK_DELAY_EXPONENT
        } else {
            0
        };
        let ecn = ecn_counts(journals);
        // An ACK frame that cannot hold every range leaves out the last
        // ones (the smallest packet numbers); one that cannot hold even the
        // first with its ACK Delay reports no delay, which the peer reads
        // as a longer round trip, never a shorter one.
        let ranges = journals.ranges();
        let room = packet.remaining();
        let frame = (1..=ranges.len())
            .rev()
            .find_map(|count| {
                AckFrame::from_packet_ranges(ranges[..count].iter().cloned(), var_int(delay), ecn)
                    .ok()
                    .filter(|frame| frame.encoded_len() <= room)
            })
            .or_else(|| shortest_frame(journals).filter(|frame| frame.encoded_len() <= room));
        let Some(frame) = frame else {
            return Supplied::Open(packet);
        };
        let before = self.state.ack_written(space, largest);
        let written =
            packet.write_frame(frame, FeedbackSummary::Ack(AckSummary { largest, before }));
        debug_assert!(written.is_ok(), "the frame was measured against the room");
        Supplied::Open(packet)
    }
}

/// The PING of a probe timeout: it makes the probe packet ack-eliciting.
#[derive(Debug, Default)]
pub struct ProbePingFrameSource<I> {
    instants: PhantomData<fn() -> I>,
}

impl<I> ProbePingFrameSource<I> {
    /// The source.
    pub fn new() -> Self {
        Self {
            instants: PhantomData,
        }
    }
}

impl<I> FrameSource for ProbePingFrameSource<I> {
    type Summary = FeedbackSummary<I>;
    type Class = InFlightClass;
    type Item<'b> = PacketNumberSpaceKind;

    fn supply<W, P>(
        &mut self,
        _: PacketNumberSpaceKind,
        mut packet: OpenPacket<W, InFlightClass, P>,
    ) -> Supplied<W, InFlightClass, P>
    where
        W: PacketWriting,
        SummaryOf<W>: From<FeedbackSummary<I>>,
        P: PacketPosition,
    {
        // A PING that does not fit leaves the packet as it is.
        let _ = packet.write_frame(PingFrame, FeedbackSummary::ProbePing(ProbePingSummary));
        Supplied::Open(packet)
    }
}

/// Version 1 finds its frame sources in the lineage of the sending call:
/// the receive journals, ACK obligations and key phase numbers of the
/// logical path.
impl<T, K, V, S, Ij, Ia, Ikp> FrameSourceDispatch<T, K, V, S, (Ij, Ia, Ikp)> for Part
where
    T: Choices,
    K: PacketKind,
    V: GetAt<PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>, Ij>
        + GetAt<AckObligationsOf<T>, Ia>
        + GetAt<KeyPhaseNumbers, Ikp>,
    S: From<FeedbackSummary<InstantOf<T>>>,
{
    fn supply<W, P>(
        lineage: &mut Lineage<'_, V>,
        now: InstantOf<T>,
        item: SendItem,
        packet: OpenPacket<W, ClassOfSource, P>,
    ) -> Supplied<W, ClassOfSource, P>
    where
        W: PacketWriting,
        W::Attempt: sakuya_recovery::send_journals::PacketSendAttempt<Summary = S>,
        P: PacketPosition,
    {
        match item {
            SendItem::Ack(space) => AckFrameSource::new(
                LineageAckFrameState::<_, InstantOf<T>, T::AckObligation, Ij, Ia, Ikp>::new(
                    lineage,
                ),
                now,
            )
            .supply(space, packet.into_source_class())
            .into_class_of_source(),
            SendItem::ProbePing(space) => ProbePingFrameSource::<InstantOf<T>>::new()
                .supply(space, packet.into_source_class())
                .into_class_of_source(),
        }
    }
}

/// What [`LineageAckFrameState`] takes its components by: the instants
/// and ACK obligations of their types, and their positions.
type Positions<I, O, Ij, Ia, Ikp> = fn() -> (I, O, Ij, Ia, Ikp);

/// The ACK frame state of a logical path, in the lineage of a call. An ACK
/// frame of the Application Data space is written in a 1-RTT packet, and
/// the key phase numbers learn of it (RFC 9001 §6.2). `I` is the type of
/// instants, `O` the ACK obligation of a space.
struct LineageAckFrameState<'l, 'v, V, I, O, Ij, Ia, Ikp> {
    lineage: &'l mut Lineage<'v, V>,
    positions: PhantomData<Positions<I, O, Ij, Ia, Ikp>>,
}

impl<'l, 'v, V, I, O, Ij, Ia, Ikp> LineageAckFrameState<'l, 'v, V, I, O, Ij, Ia, Ikp> {
    fn new(lineage: &'l mut Lineage<'v, V>) -> Self {
        Self {
            lineage,
            positions: PhantomData,
        }
    }
}

impl<V, I, O, Ij, Ia, Ikp> AckFrameState<I> for LineageAckFrameState<'_, '_, V, I, O, Ij, Ia, Ikp>
where
    I: Copy,
    O: AckObligation<I>,
    V: GetAt<PacketNumberSpaces<ReceiveJournals<I>>, Ij>
        + GetAt<PacketNumberSpaces<O>, Ia>
        + GetAt<KeyPhaseNumbers, Ikp>,
{
    fn journals(&self, space: PacketNumberSpaceKind) -> Option<&ReceiveJournals<I>> {
        self.lineage
            .get::<PacketNumberSpaces<ReceiveJournals<I>>, Ij>()
            .get(space)
    }

    fn ack_written(&mut self, space: PacketNumberSpaceKind, largest: PacketNumber) -> AckDue<I> {
        if let Some(journals) = self
            .lineage
            .get_mut::<PacketNumberSpaces<ReceiveJournals<I>>, Ij>()
            .get_mut(space)
        {
            journals.on_ack_written();
        }
        if space == PacketNumberSpaceKind::ApplicationData {
            self.lineage
                .get_mut::<KeyPhaseNumbers, Ikp>()
                .ack_frame_sent(largest);
        }
        self.lineage
            .get_mut::<PacketNumberSpaces<O>, Ia>()
            .get_mut(space)
            .map_or(AckDue::NotDue, |obligation| obligation.ack_written(largest))
    }
}

/// The types a composition of version 1 gives its send strategy: the
/// parts' intents and frame sources, version 1's link path identifier and
/// close cause, and the parts' frame sources for each kind of packet.
pub struct SendTypes<T, L>(PhantomData<fn() -> (T, L)>);

impl<T, L> core::fmt::Debug for SendTypes<T, L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SendTypes")
    }
}

impl<T, L> SendStrategyTypes for SendTypes<T, L>
where
    T: Choices,
    L: SendIntentsOf + LogicalPathKeys + ConnectionErrorsOf,
    L::SendIntents: 'static,
    PartsFrameSources<InitialPacket, L>:
        FrameSourceSet<Intents = L::SendIntents, FrameSourceId = L::FrameSourceIds>,
    PartsFrameSources<HandshakePacket, L>:
        FrameSourceSet<Intents = L::SendIntents, FrameSourceId = L::FrameSourceIds>,
    PartsFrameSources<ZeroRttPacket, L>:
        FrameSourceSet<Intents = L::SendIntents, FrameSourceId = L::FrameSourceIds>,
    PartsFrameSources<OneRttPacket, L>:
        FrameSourceSet<Intents = L::SendIntents, FrameSourceId = L::FrameSourceIds>,
    PartsFrameSources<OneRttProbePacket, L>:
        FrameSourceSet<Intents = L::SendIntents, FrameSourceId = L::FrameSourceIds>,
    PartsFrameSources<SettlingResponsePacket, L>:
        FrameSourceSet<Intents = L::SendIntents, FrameSourceId = L::FrameSourceIds>,
{
    type SendIntents = L::SendIntents;
    type FrameSourceId = L::FrameSourceIds;
    type LinkPathIdentifier = LinkPathIdentifierOf<T, L>;
    type CloseCause = CloseCauseOf<T, L>;
    type InitialFrameSources = PartsFrameSources<InitialPacket, L>;
    type HandshakeFrameSources = PartsFrameSources<HandshakePacket, L>;
    type ZeroRttFrameSources = PartsFrameSources<ZeroRttPacket, L>;
    type OneRttFrameSources = PartsFrameSources<OneRttPacket, L>;
    type ProbeFrameSources = PartsFrameSources<OneRttProbePacket, L>;
    type SettlingFrameSources = PartsFrameSources<SettlingResponsePacket, L>;

    fn frame_source(intent: &L::SendIntents) -> L::FrameSourceIds {
        L::frame_source(intent)
    }

    fn min_lengths(intent: &L::SendIntents) -> MinimumLengths {
        L::min_lengths(intent)
    }

    fn flight_class(intent: &L::SendIntents) -> FlightClass {
        L::flight_class(intent)
    }
}

#[cfg(test)]
mod tests;
