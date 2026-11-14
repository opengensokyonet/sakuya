//! What QUIC version 1 sends through the send strategy: acknowledgments of
//! each packet number space, the PING of a probe timeout, the retirement of
//! the peer's connection IDs, the CRYPTO data of each encryption level and
//! a server's HANDSHAKE_DONE, as send intents, the items a packet of each
//! kind may carry, and the frame sources that write them.

use core::{marker::PhantomData, time::Duration};

use sakuya_recovery::{
    ack_obligation::{AckDue, AckObligation},
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaces},
    receive_journals::ReceiveJournals,
};
use sakuya_tls::engine::CryptoLevel;
use sakuya_wire::v1::packet_number::PacketNumber;
use sakuya_wire::{
    parts::{CNil, Coproduct},
    v1::frame::{
        ack::{AckFrame, EcnCounts},
        handshake_done::HandshakeDoneFrame,
        ping::PingFrame,
        retire_connection_id::RetireConnectionIdFrame,
    },
    var_int::{VarInt, VarIntField, VarIntWidth},
};

use super::{
    AckObligationsOf, Choices, CloseCauseOf, Part, Side,
    connection_ids::ConnectionIdsOf,
    crypto::send::{CryptoSendBuffer, CryptoSender},
    feedback::{AckSummary, CryptoSummary, HandshakeDoneSummary, ProbePingSummary},
    key_phase::KeyPhaseNumbers,
    send_planning::{
        AckIntentTicketOf, AckIntentTickets, CorePublishOutcome, CryptoIntentTicketOf,
        CryptoIntentTickets,
    },
};
use crate::{
    clock::InstantOf,
    error::ConnectionErrorsOf,
    frame_source::{
        FindFrameSource, FrameSource, FrameSourceItemsOf, FrameSourceKind, FrameSourcePart,
        HandshakePacket, InitialPacket, NoIntent, OneRttPacket, OneRttProbePacket, PacketKind,
        PartsFrameSources, PublishIntent, SettlingResponsePacket, ZeroRttPacket,
    },
    send_strategy::{
        AnyActiveLinkPath, FrameSourceSet, MinimumLengths, PlannedPacketKind, SendIntent,
        SendIntentPart, SendIntentsOf, SendStrategyTypes,
        ranked::{IntentTicket, RankedCoreIntent, RankedIntent, SendPriority, SendRank},
    },
    share::{LinkPathIdentifierOf, LogicalPathKeys},
    take::{GetAt, Lineage},
    write::{
        AckOnlyClass, FlightClass, InFlightClass, OpenPacket, PacketPosition, PacketWriting,
        PaddingFrames, SummaryOf, Supplied,
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
    /// The RETIRE_CONNECTION_ID frames of the destination connection ID
    /// strategy.
    RetireConnectionId,
    /// The CRYPTO frames of an encryption level.
    Crypto(CryptoLevel),
    /// A server's HANDSHAKE_DONE frame.
    HandshakeDone,
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

/// The ACK obligation's component keeps the ticket, to withdraw the intent
/// once no ACK frame is due.
impl RankedCoreIntent for AckIntent {
    type Outcome<C> = IntentTicket<C>;
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

/// A connection ID the peer issued is retired: a RETIRE_CONNECTION_ID
/// frame with its sequence number is to be sent (RFC 9000 §19.16), and sent
/// again with the same sequence number while its packets are lost
/// (RFC 9000 §13.3). It is sent and forgotten: publishing it gives back
/// nothing to keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RetireConnectionIdIntent {
    sequence: u64,
}

impl RetireConnectionIdIntent {
    /// The connection ID numbered `sequence` is retired.
    pub fn new(sequence: u64) -> Self {
        Self { sequence }
    }

    /// The sequence number of the connection ID retired.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// The frame that retires the connection ID.
    pub fn frame(&self) -> RetireConnectionIdFrame {
        RetireConnectionIdFrame::new(var_int(self.sequence))
    }
}

impl SendIntent for RetireConnectionIdIntent {
    type FrameSourceId = FrameSourceId;
    type Class = InFlightClass;

    fn frame_source(&self) -> FrameSourceId {
        FrameSourceId::RetireConnectionId
    }

    fn min_lengths(&self) -> MinimumLengths {
        let len = self.frame().encoded_len();
        MinimumLengths {
            with_length: len,
            as_last: len,
        }
    }
}

impl RankedIntent for RetireConnectionIdIntent {
    fn rank(&self) -> SendRank {
        SendRank {
            priority: SendPriority::Control,
            holds_place: true,
        }
    }
}

/// Nothing keeps a retirement's intent: only its frame being written takes
/// it away.
impl RankedCoreIntent for RetireConnectionIdIntent {
    type Outcome<C> = ();
}

/// CRYPTO data of an encryption level is unsent (RFC 9000 §19.6), and the
/// shortest CRYPTO frame of it, one byte at its first unsent offset, is
/// `shortest` bytes long.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CryptoIntent {
    level: CryptoLevel,
    shortest: usize,
}

impl CryptoIntent {
    /// CRYPTO data of `level` is unsent from `first_unsent` on.
    pub fn new(level: CryptoLevel, first_unsent: VarInt) -> Self {
        Self {
            level,
            shortest: shortest_crypto_frame(first_unsent),
        }
    }

    /// The encryption level.
    pub fn level(&self) -> CryptoLevel {
        self.level
    }

    /// How long the shortest CRYPTO frame of the unsent data is.
    pub fn shortest(&self) -> usize {
        self.shortest
    }
}

/// The length of a CRYPTO frame with one byte at `offset`: the Frame
/// Type, the Offset and Length fields at their shortest, and the byte. A
/// packet with at least this much room takes some of the data.
pub fn shortest_crypto_frame(offset: VarInt) -> usize {
    1 + VarIntWidth::shortest(offset).encoded_len() + 1 + 1
}

impl SendIntent for CryptoIntent {
    type FrameSourceId = FrameSourceId;
    type Class = InFlightClass;

    fn frame_source(&self) -> FrameSourceId {
        FrameSourceId::Crypto(self.level)
    }

    fn min_lengths(&self) -> MinimumLengths {
        MinimumLengths {
            with_length: self.shortest,
            as_last: self.shortest,
        }
    }
}

/// The rank is provisional.
impl RankedIntent for CryptoIntent {
    fn rank(&self) -> SendRank {
        SendRank {
            priority: SendPriority::Handshake,
            holds_place: true,
        }
    }
}

/// The CRYPTO intent tickets keep the ticket, to withdraw the intent once
/// nothing of the level is unsent or its keys are gone.
impl RankedCoreIntent for CryptoIntent {
    type Outcome<C> = IntentTicket<C>;
}

/// The handshake is complete: a server's HANDSHAKE_DONE frame is to be
/// sent (RFC 9000 §19.20), and sent again while its packets are lost (RFC
/// 9000 §13.3). It is sent and forgotten: publishing it gives back nothing
/// to keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HandshakeDoneIntent;

impl SendIntent for HandshakeDoneIntent {
    type FrameSourceId = FrameSourceId;
    type Class = InFlightClass;

    fn frame_source(&self) -> FrameSourceId {
        FrameSourceId::HandshakeDone
    }

    fn min_lengths(&self) -> MinimumLengths {
        let len = HandshakeDoneFrame.encoded_len();
        MinimumLengths {
            with_length: len,
            as_last: len,
        }
    }
}

/// The rank is provisional.
impl RankedIntent for HandshakeDoneIntent {
    fn rank(&self) -> SendRank {
        SendRank {
            priority: SendPriority::Handshake,
            holds_place: true,
        }
    }
}

/// Nothing keeps the intent: only its frame being written takes it away.
impl RankedCoreIntent for HandshakeDoneIntent {
    type Outcome<C> = ();
}

/// The summary of a RETIRE_CONNECTION_ID frame written into a packet: the
/// sequence number it retires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RetireConnectionIdSummary {
    /// The sequence number of the connection ID retired.
    pub sequence: u64,
}

/// Version 1's intents.
pub type SendIntents = Coproduct<
    AckIntent,
    Coproduct<
        ProbePingIntent,
        Coproduct<
            RetireConnectionIdIntent,
            Coproduct<HandshakeDoneIntent, Coproduct<CryptoIntent, CNil>>,
        >,
    >,
>;

/// The kinds of version 1's frame sources: PADDING, which the packet
/// writer writes, the ACK frames of each packet number space, the PING of
/// a probe timeout, the RETIRE_CONNECTION_ID frames of the destination
/// connection ID strategy, a server's HANDSHAKE_DONE and the CRYPTO frames
/// of each encryption level.
pub type FrameSources = frunk_core::HList![
    PaddingFrames,
    AckFrames,
    ProbePingFrames,
    RetireConnectionIdFrames,
    HandshakeDoneFrames,
    CryptoFrames
];

impl SendIntentPart for Part {
    type FrameSourceId = FrameSourceId;
    type SendIntents = SendIntents;
    type FrameSources = FrameSources;
}

/// One planned item of version 1: an item of one of [`FrameSources`].
/// PADDING is never planned; the ACK frames and the PING of a probe are
/// planned for a packet number space.
pub type SendItem = FrameSourceItemsOf<'static, Part>;

/// The level of the CRYPTO frames a packet of `kind` carries: those of its
/// own encryption level; 0-RTT packets carry none (RFC 9000 §12.4), and
/// neither do a candidate's nor a settling link path's.
fn crypto_level(kind: PlannedPacketKind) -> Option<CryptoLevel> {
    match kind {
        PlannedPacketKind::Initial => Some(CryptoLevel::Initial),
        PlannedPacketKind::Handshake => Some(CryptoLevel::Handshake),
        PlannedPacketKind::OneRtt => Some(CryptoLevel::OneRtt),
        PlannedPacketKind::ZeroRtt
        | PlannedPacketKind::OneRttProbe
        | PlannedPacketKind::SettlingResponse => None,
    }
}

/// Whether a packet of `kind` carries content of `space` from a source of
/// `ack`: ACK frames are not allowed in 0-RTT packets (RFC 9000 §12.4); a
/// candidate's and a settling link path's packets carry neither.
/// RETIRE_CONNECTION_ID and HANDSHAKE_DONE frames go in 1-RTT packets only
/// (RFC 9000 §12.4, §12.5).
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
    fn item(intent: &SendIntents) -> Option<SendItem> {
        match intent {
            Coproduct::Inl(ack) => carries(K::KIND, ack.space, true)
                .then_some(Coproduct::Inr(Coproduct::Inl(ack.space))),
            Coproduct::Inr(Coproduct::Inl(ping)) => carries(K::KIND, ping.space, false)
                .then_some(Coproduct::Inr(Coproduct::Inr(Coproduct::Inl(ping.space)))),
            Coproduct::Inr(Coproduct::Inr(Coproduct::Inl(retire))) => {
                (K::KIND == PlannedPacketKind::OneRtt).then_some(Coproduct::Inr(Coproduct::Inr(
                    Coproduct::Inr(Coproduct::Inl(retire.sequence)),
                )))
            }
            Coproduct::Inr(Coproduct::Inr(Coproduct::Inr(Coproduct::Inl(HandshakeDoneIntent)))) => {
                (K::KIND == PlannedPacketKind::OneRtt).then_some(Coproduct::Inr(Coproduct::Inr(
                    Coproduct::Inr(Coproduct::Inr(Coproduct::Inl(()))),
                )))
            }
            Coproduct::Inr(Coproduct::Inr(Coproduct::Inr(Coproduct::Inr(Coproduct::Inl(
                crypto,
            ))))) => (crypto_level(K::KIND) == Some(crypto.level)).then_some(Coproduct::Inr(
                Coproduct::Inr(Coproduct::Inr(Coproduct::Inr(Coproduct::Inr(
                    Coproduct::Inl(crypto.level),
                )))),
            )),
            Coproduct::Inr(Coproduct::Inr(Coproduct::Inr(Coproduct::Inr(Coproduct::Inr(
                never,
            ))))) => match *never {},
        }
    }

    fn source(item: &SendItem) -> FrameSourceId {
        match item {
            Coproduct::Inl(never) => match *never {},
            Coproduct::Inr(Coproduct::Inl(space)) => FrameSourceId::Ack(*space),
            Coproduct::Inr(Coproduct::Inr(Coproduct::Inl(space))) => {
                FrameSourceId::ProbePing(*space)
            }
            Coproduct::Inr(Coproduct::Inr(Coproduct::Inr(Coproduct::Inl(_)))) => {
                FrameSourceId::RetireConnectionId
            }
            Coproduct::Inr(Coproduct::Inr(Coproduct::Inr(Coproduct::Inr(Coproduct::Inl(()))))) => {
                FrameSourceId::HandshakeDone
            }
            Coproduct::Inr(Coproduct::Inr(Coproduct::Inr(Coproduct::Inr(Coproduct::Inr(
                Coproduct::Inl(level),
            ))))) => FrameSourceId::Crypto(*level),
            Coproduct::Inr(Coproduct::Inr(Coproduct::Inr(Coproduct::Inr(Coproduct::Inr(
                Coproduct::Inr(never),
            ))))) => match *never {},
        }
    }
}

// ---- the frame sources ----

/// What the ACK frames of a logical path are made from: the receive
/// journals of its packet number spaces, and what writing one, and its
/// being delivered or lost, does to them and to the space's ACK
/// obligation.
pub trait AckFrameState<I> {
    /// The receive journals of `space`, if the space is still there.
    fn journals(&self, space: PacketNumberSpaceKind) -> Option<&ReceiveJournals<I>>;

    /// An ACK frame whose Largest Acknowledged is `largest` was written in
    /// `space`: the journals and the obligation learn it. Returns what the
    /// obligation owed before.
    fn ack_written(&mut self, space: PacketNumberSpaceKind, largest: PacketNumber) -> AckDue<I>;

    /// An ACK frame of `space` whose Largest Acknowledged is `largest` was
    /// delivered: the journals stop reporting what lies below it (RFC 9000
    /// §13.2.4). A space that is gone takes nothing.
    fn ack_delivered(&mut self, space: PacketNumberSpaceKind, largest: PacketNumber);

    /// An ACK frame of `space`, written when the obligation owed `before`,
    /// was lost: the obligation owes it again (RFC 9000 §13.2.1), and the
    /// space's ACK intent is published again while an ACK frame is due. A
    /// space that is gone takes nothing.
    fn ack_lost(&mut self, space: PacketNumberSpaceKind, before: AckDue<I>);
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
    type Summary = AckSummary<I>;
    type Class = AckOnlyClass;
    type Item<'b> = PacketNumberSpaceKind;
    /// A lost ACK frame is not sent again as it was: the space's ACK
    /// intent is published again from the obligation, as any other time an
    /// ACK frame is due.
    type Intent = NoIntent;

    fn supply<W, P>(
        &mut self,
        space: PacketNumberSpaceKind,
        mut packet: OpenPacket<W, AckOnlyClass, P>,
    ) -> Supplied<W, AckOnlyClass, P>
    where
        W: PacketWriting,
        SummaryOf<W>: From<AckSummary<I>>,
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
        let written = packet.write_frame(frame, AckSummary { largest, before });
        debug_assert!(written.is_ok(), "the frame was measured against the room");
        Supplied::Open(packet)
    }

    fn delivered<Pb, Idx>(&mut self, _: &mut Pb, space: PacketNumberSpaceKind, ack: AckSummary<I>)
    where
        Pb: PublishIntent<NoIntent, Idx>,
    {
        self.state.ack_delivered(space, ack.largest);
    }

    fn lost<Pb, Idx>(&mut self, _: &mut Pb, space: PacketNumberSpaceKind, ack: &AckSummary<I>)
    where
        Pb: PublishIntent<NoIntent, Idx>,
    {
        self.state.ack_lost(space, ack.before);
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
    type Summary = ProbePingSummary;
    type Class = InFlightClass;
    type Item<'b> = PacketNumberSpaceKind;
    type Intent = NoIntent;

    fn supply<W, P>(
        &mut self,
        _: PacketNumberSpaceKind,
        mut packet: OpenPacket<W, InFlightClass, P>,
    ) -> Supplied<W, InFlightClass, P>
    where
        W: PacketWriting,
        SummaryOf<W>: From<ProbePingSummary>,
        P: PacketPosition,
    {
        // A PING that does not fit leaves the packet as it is.
        let _ = packet.write_frame(PingFrame, ProbePingSummary);
        Supplied::Open(packet)
    }

    fn delivered<Pb, Idx>(&mut self, _: &mut Pb, _: PacketNumberSpaceKind, _: ProbePingSummary)
    where
        Pb: PublishIntent<NoIntent, Idx>,
    {
    }

    fn lost<Pb, Idx>(&mut self, _: &mut Pb, _: PacketNumberSpaceKind, _: &ProbePingSummary)
    where
        Pb: PublishIntent<NoIntent, Idx>,
    {
    }
}

// ---- where the frame sources are ----

/// The ACK frames of a logical path's packet number spaces, as a kind of
/// frame source.
#[derive(Debug)]
pub enum AckFrames {}

impl FrameSourceKind for AckFrames {
    type Item<'a> = PacketNumberSpaceKind;
    type Summary<I> = AckSummary<I>;
    type Intent = NoIntent;
}

/// The ACK frames are made from the receive journals, ACK obligations, ACK
/// intents and key phase numbers of the logical path in the lineage.
impl<T, L, V, Ij, Ia, Ik, Ikp> FindFrameSource<T, L, V, (Ij, Ia, Ik, Ikp)> for AckFrames
where
    T: Choices,
    SendTypes<T, L>: CorePublishOutcome<AckIntent, AnyActiveLinkPath>,
    V: GetAt<PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>, Ij>
        + GetAt<AckObligationsOf<T>, Ia>
        + GetAt<AckIntentTickets<AckIntentTicketOf<T, L>>, Ik>
        + GetAt<KeyPhaseNumbers, Ikp>,
{
    type Source<'l, 'r>
        = AckFrameSource<
        LineageAckFrameState<
            'l,
            'r,
            V,
            InstantOf<T>,
            T::AckObligation,
            AckIntentTicketOf<T, L>,
            (Ij, Ia, Ik, Ikp),
        >,
        InstantOf<T>,
    >
    where
        V: 'l,
        'r: 'l;

    fn find<'l, 'r>(lineage: &'l mut Lineage<'r, V>, now: InstantOf<T>) -> Self::Source<'l, 'r> {
        AckFrameSource::new(LineageAckFrameState::new(lineage), now)
    }
}

/// The PING of a probe timeout, as a kind of frame source.
#[derive(Debug)]
pub enum ProbePingFrames {}

impl FrameSourceKind for ProbePingFrames {
    type Item<'a> = PacketNumberSpaceKind;
    type Summary<I> = ProbePingSummary;
    type Intent = NoIntent;
}

/// The PING of a probe timeout is in no lineage: it holds nothing.
impl<T: Choices, L, V> FindFrameSource<T, L, V, ()> for ProbePingFrames {
    type Source<'l, 'r>
        = ProbePingFrameSource<InstantOf<T>>
    where
        V: 'l,
        'r: 'l;

    fn find<'l, 'r>(_: &'l mut Lineage<'r, V>, _: InstantOf<T>) -> Self::Source<'l, 'r> {
        ProbePingFrameSource::new()
    }
}

/// The RETIRE_CONNECTION_ID frames of the destination connection ID
/// strategy, as a kind of frame source: the strategy writes them.
#[derive(Debug)]
pub enum RetireConnectionIdFrames {}

impl FrameSourceKind for RetireConnectionIdFrames {
    type Item<'a> = u64;
    type Summary<I> = RetireConnectionIdSummary;
    type Intent = RetireConnectionIdIntent;
}

/// The RETIRE_CONNECTION_ID frames are written by the destination
/// connection ID strategy of the logical path in the lineage.
impl<T, L, V, Ic> FindFrameSource<T, L, V, Ic> for RetireConnectionIdFrames
where
    T: Choices,
    V: GetAt<ConnectionIdsOf<T>, Ic>,
{
    type Source<'l, 'r>
        = &'l mut T::DestinationConnectionIds
    where
        V: 'l,
        'r: 'l;

    fn find<'l, 'r>(lineage: &'l mut Lineage<'r, V>, _: InstantOf<T>) -> Self::Source<'l, 'r> {
        lineage
            .get_mut::<ConnectionIdsOf<T>, Ic>()
            .destination_mut()
    }
}

/// The CRYPTO frames of the encryption levels, as a kind of frame source.
#[derive(Debug)]
pub enum CryptoFrames {}

impl FrameSourceKind for CryptoFrames {
    type Item<'a> = CryptoLevel;
    type Summary<I> = CryptoSummary;
    type Intent = NoIntent;
}

/// The CRYPTO frames are written from the connection's CRYPTO output, and
/// take the tickets of its intents.
impl<T, L, V, Is, It> FindFrameSource<T, L, V, (Is, It)> for CryptoFrames
where
    T: Choices,
    SendTypes<T, L>: CorePublishOutcome<CryptoIntent, AnyActiveLinkPath>,
    V: GetAt<CryptoSender<T::CryptoSendBuffer>, Is>
        + GetAt<CryptoIntentTickets<CryptoIntentTicketOf<T, L>>, It>,
{
    type Source<'l, 'r>
        = LineageCryptoFrameSource<
        'l,
        'r,
        V,
        T::CryptoSendBuffer,
        CryptoIntentTicketOf<T, L>,
        (Is, It),
    >
    where
        V: 'l,
        'r: 'l;

    fn find<'l, 'r>(lineage: &'l mut Lineage<'r, V>, _: InstantOf<T>) -> Self::Source<'l, 'r> {
        LineageCryptoFrameSource::new(lineage)
    }
}

/// The CRYPTO frames of the connection's output, in a lineage: they are
/// written from its [`CryptoSender`], and writing them takes the ticket
/// of their level's intent from its [`CryptoIntentTickets`]. `B` is the
/// buffer of a level, `K` what publishing a CRYPTO intent gave back, `H`
/// the positions of the two components.
///
/// Supplying a level always drops its ticket: when a frame was written the
/// plan consumed the intent, and when none was, nothing is unsent. The
/// tickets publish the intent again while bytes of the level are unsent,
/// also once a frame of it is lost.
pub struct LineageCryptoFrameSource<'l, 'r, V, B, K, H> {
    lineage: &'l mut Lineage<'r, V>,
    types: PhantomData<SourceTypes<B, K, H>>,
}

/// What [`LineageCryptoFrameSource`] takes its components by: the buffer
/// of a level, the tickets of the intents and the positions.
type SourceTypes<B, K, H> = fn() -> (B, K, H);

impl<V, B, K, H> core::fmt::Debug for LineageCryptoFrameSource<'_, '_, V, B, K, H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LineageCryptoFrameSource")
    }
}

impl<'l, 'r, V, B, K, H> LineageCryptoFrameSource<'l, 'r, V, B, K, H> {
    pub(crate) fn new(lineage: &'l mut Lineage<'r, V>) -> Self {
        Self {
            lineage,
            types: PhantomData,
        }
    }
}

impl<V, B, K, Is, It> FrameSource for LineageCryptoFrameSource<'_, '_, V, B, K, (Is, It)>
where
    B: CryptoSendBuffer,
    V: GetAt<CryptoSender<B>, Is> + GetAt<CryptoIntentTickets<K>, It>,
{
    type Summary = CryptoSummary;
    type Class = InFlightClass;
    type Item<'b> = CryptoLevel;
    type Intent = NoIntent;

    fn supply<W, P>(
        &mut self,
        level: CryptoLevel,
        mut packet: OpenPacket<W, InFlightClass, P>,
    ) -> Supplied<W, InFlightClass, P>
    where
        W: PacketWriting,
        SummaryOf<W>: From<CryptoSummary>,
        P: PacketPosition,
    {
        self.lineage
            .get_mut::<CryptoSender<B>, Is>()
            .write_frames(level, &mut packet);
        self.lineage
            .get_mut::<CryptoIntentTickets<K>, It>()
            .forget(level);
        Supplied::Open(packet)
    }

    fn delivered<Pb, Idx>(&mut self, _: &mut Pb, _: PacketNumberSpaceKind, summary: CryptoSummary)
    where
        Pb: PublishIntent<NoIntent, Idx>,
    {
        self.lineage.get_mut::<CryptoSender<B>, Is>().acknowledged(
            summary.level,
            summary.offset,
            summary.len,
        );
    }

    fn lost<Pb, Idx>(&mut self, _: &mut Pb, _: PacketNumberSpaceKind, summary: &CryptoSummary)
    where
        Pb: PublishIntent<NoIntent, Idx>,
    {
        self.lineage.get_mut::<CryptoSender<B>, Is>().lost(
            summary.level,
            summary.offset,
            summary.len,
        );
    }
}

/// A server's HANDSHAKE_DONE frame, as a kind of frame source.
#[derive(Debug)]
pub enum HandshakeDoneFrames {}

impl FrameSourceKind for HandshakeDoneFrames {
    type Item<'a> = ();
    type Summary<I> = HandshakeDoneSummary;
    type Intent = HandshakeDoneIntent;
}

/// The HANDSHAKE_DONE frame is written by the [`Own`](Side::Own) data of
/// the side, in the connection node: a server's sends it, a client's writes
/// nothing.
impl<T, L, V, Io> FindFrameSource<T, L, V, Io> for HandshakeDoneFrames
where
    T: Choices,
    V: GetAt<<T::Side as Side>::Own, Io>,
{
    type Source<'l, 'r>
        = &'l mut <T::Side as Side>::Own
    where
        V: 'l,
        'r: 'l;

    fn find<'l, 'r>(lineage: &'l mut Lineage<'r, V>, _: InstantOf<T>) -> Self::Source<'l, 'r> {
        lineage.get_mut::<<T::Side as Side>::Own, Io>()
    }
}

/// The ACK frame state of a logical path, in a lineage. An ACK frame of
/// the Application Data space is written in a 1-RTT packet, and the key
/// phase numbers learn of it (RFC 9001 §6.2). `I` is the type of instants,
/// `O` the ACK obligation of a space, `K` what publishing an ACK intent
/// gave back, `H` the positions of the components.
pub struct LineageAckFrameState<'l, 'r, V, I, O, K, H> {
    lineage: &'l mut Lineage<'r, V>,
    types: PhantomData<StateTypes<I, O, K, H>>,
}

/// What [`LineageAckFrameState`] takes its components by: the instants,
/// the ACK obligations, the tickets of the ACK intents and the positions.
type StateTypes<I, O, K, H> = fn() -> (I, O, K, H);

impl<V, I, O, K, H> core::fmt::Debug for LineageAckFrameState<'_, '_, V, I, O, K, H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LineageAckFrameState")
    }
}

impl<'l, 'r, V, I, O, K, H> LineageAckFrameState<'l, 'r, V, I, O, K, H> {
    fn new(lineage: &'l mut Lineage<'r, V>) -> Self {
        Self {
            lineage,
            types: PhantomData,
        }
    }
}

impl<V, I, O, K, Ij, Ia, Ik, Ikp> AckFrameState<I>
    for LineageAckFrameState<'_, '_, V, I, O, K, (Ij, Ia, Ik, Ikp)>
where
    I: Copy,
    O: AckObligation<I>,
    V: GetAt<PacketNumberSpaces<ReceiveJournals<I>>, Ij>
        + GetAt<PacketNumberSpaces<O>, Ia>
        + GetAt<AckIntentTickets<K>, Ik>
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

    fn ack_delivered(&mut self, space: PacketNumberSpaceKind, largest: PacketNumber) {
        if let Some(journals) = self
            .lineage
            .get_mut::<PacketNumberSpaces<ReceiveJournals<I>>, Ij>()
            .get_mut(space)
        {
            journals.acknowledged_up_to(largest);
        }
    }

    /// The lost frame also forgets the ticket of its space's ACK intent:
    /// the frame consumed the intent, and when it was written and lost
    /// before the tickets were read again, the ticket left looks like an
    /// intent still waiting for the frame that is due again.
    fn ack_lost(&mut self, space: PacketNumberSpaceKind, before: AckDue<I>) {
        if let Some(obligation) = self
            .lineage
            .get_mut::<PacketNumberSpaces<O>, Ia>()
            .get_mut(space)
        {
            obligation.ack_lost(before);
        }
        self.lineage
            .get_mut::<AckIntentTickets<K>, Ik>()
            .forget(space);
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
