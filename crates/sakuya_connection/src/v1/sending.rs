//! What a link path sends: the call that fills its batch of datagrams by
//! the plans of its send planner, hands the batch to its link and settles
//! what the link did with it.
//!
//! [`link_path_sending`] is the call of each link path. It keeps one
//! [`DatagramBatch`] of at most
//! [`max_datagrams_per_send`](LinkPathSendingLimits::max_datagrams_per_send)
//! datagrams, the one thing it keeps across waiting, and goes round three
//! steps:
//!
//! 1. Waiting and filling, in the poll that finds a plan: with nothing in
//!    the batch the call waits until the planner has one. Each datagram
//!    starts by
//!    refilling the link path's pacer to the instant of the poll and
//!    reading afresh what the link path can send ([`DatagramLimits`]) and
//!    what each kind of packet takes beyond its frames ([`PacketOverheads`]),
//!    which the planner is told before it is asked for the plan. The
//!    connection ID is the first one offered for the link path with which
//!    the content planned first fits; each planned packet then gets a
//!    packet of its kind, opened with the keys of its level, and each
//!    planned item whose least room fits is given to its frame source; one
//!    datagram carries one connection ID (RFC 9000 §12.2), and a 0-RTT
//!    packet is never written, as no keys to send one with are kept.
//!    Before a packet is sealed, the plan says what the
//!    next packet leads with: the packet is the last of the datagram, and
//!    padded to its floor, when that does not fit after it. A datagram the
//!    content left empty is filled again from the start. Filling ends when
//!    the batch is full, when the planner has nothing to plan or asks for
//!    the close packet again before one is sealed, or when the plan
//!    names content that cannot go now: no connection ID fits it, its
//!    level has no keys to send with, or it does not fit its packet. With
//!    nothing in the batch the call then waits for the planner; in the last
//!    cases it wakes itself first, so that what the lend changed is reread
//!    before it plans again. What the batch still holds from the last round
//!    is handed over with what is filled.
//! 2. Handing over. The datagrams that carry a packet of a level whose
//!    keys to send with are gone by now are taken out, and their packets
//!    are given up; then the batch goes to [`Link::send`], whose future
//!    borrows the batch only.
//! 3. Settling. The datagrams the link accepted have their packets marked
//!    sent at the instant the link gives; they enter the loss detection
//!    state of their space, and an ack-eliciting one restarts the idle
//!    timeout (RFC 9000 §10.1). When the link gives the first datagram up,
//!    its packets are given up; the rest wait for the next round.
//!
//! A packet given up counts as declared lost: it leaves the bytes in
//! flight without a congestion signal, its record is kept as long as one of
//! a packet declared lost, and the summaries of its frames go back to their
//! parts as lost. What the datagram was charged with when it was sealed
//! stays charged.
//!
//! Before each filling, the call initiates a 1-RTT key update when one is
//! due and may be initiated, as the [`key_update`](super::key_update) module
//! says, and notes the next packet number of the Application Data space as
//! sent with the current sending generation. Filling stops at a 1-RTT
//! packet that would leave the current keys only the closing packet within
//! their AEAD's confidentiality limit, and the next filling initiates the
//! update; when none may be initiated, the call writes AEAD_LIMIT_REACHED
//! into the record of why the connection closed and fills nothing more
//! (RFC 9001 §6.6).
//!
//! A client discards its Initial keys once it seals its first Handshake
//! packet (RFC 9001 §4.9.1); the Initial packets it sealed before still go
//! out. A server's Initial packets are always padded when they elicit an
//! acknowledgment, and a client's always (RFC 9000 §14.1); content planned
//! first in an Initial packet that counts in flight is taken to elicit one.
//! Every datagram is marked Not-ECT.
//!
//! A link path without a recovery layer sends nothing new: the call is
//! woken when its layer is built.
//!
//! Once the link path's close packet is sealed, the call fills nothing:
//! each time the planner asks for the close packet to go again, the sealed
//! datagram joins the batch as it is, charged first to the
//! anti-amplification limit of the logical link; a copy the credit does
//! not allow is not sent ([`ClosePacket`]). It enters no send journal and
//! counts nothing in flight. A send in flight when the link path began
//! closing is still settled.
//!
//! [`link_path_sending`] is also the operation struct
//! [`LinkPathSending`], with `LinkPathSendingExt` on receiver accesses.
// `#[call]` generates a constructor and an extension trait without
// documentation comments; the module documentation above describes them.
#![allow(missing_docs)]

use core::{
    future::poll_fn,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll},
};

use std::sync::Arc;

use bytes::Bytes;
use frunk_core::hlist_pat;
use nitori_call::{LentAccess, LentCall, ReceiverFamily, call};
use sakuya_link::{Link, MIN_DATAGRAM_SIZE, SendAcceptance};
use sakuya_recovery::{
    congestion::{CongestionContext, CongestionController, RemovedPacket},
    factory::{LendCongestion, RecoveryFactory},
    loss::LossThresholds,
    loss_detection::LossDetectionState,
    pacing::Pacer,
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaceState, PacketNumberSpaces},
    pmtu::PmtuPolicy,
    pto::probe_timeout,
    rtt::{RttEstimate, RttEstimator},
    send_journals::{PacketSendAttempt, SendJournals},
};
use sakuya_stream::connection::CloseReason;
use sakuya_wire::{
    parameters::ParametersOf,
    parts::{CoprodInjector, HList, Selector},
    v1::{
        role::Role,
        transport_parameters::{
            TransportParameterSlots, TransportParameterSpace,
            integer::{MaxAckDelay, MaxUdpPayloadSize},
        },
    },
};

use super::{
    Choices, CloseCauseOf, Side,
    aead_usage::{AeadLimitReachedError, AeadUsage},
    amplification::AntiAmplification,
    close::{CloseReasonRecord, LocalCloseCause},
    close_packet::ClosePacket,
    confirmation::HandshakeConfirmation,
    connection_ids::{ConnectionIdsOf, LinkPathResetTokenRegistrar, ResetTokenRegistrarOf},
    datagram_batch::{BatchedDatagram, BatchedPacket, DatagramBatch},
    error::ConnectionError,
    idle::IdleTimeout,
    key_phase::KeyPhaseNumbers,
    key_update::prepare_one_rtt_packets,
    keys::{DirectionKeys, HandshakeKeys, InitialKeys, OneRttKeys},
    largest_probe_timeout,
    link::{LinkClone, LinkFacts},
    parameters::PeerTransportParameters,
    receive::v1_error,
    recovery::{
        CongestionPartOf, LinkPathCongestionState, OthersOf, PmtuOf, RecoveryFactoryOf, RttOf,
        lend_congestion, max_datagram_size_in_use, peer_max_udp_payload_size, refill,
    },
    send::SendTypes,
    send_planning::{
        CongestionAllowance, LinkPathPlanner, LinkPathSendPlannerOf, SendKeyLevels,
        SendStrategyCore, SendStrategyOf, datagram_limits, link_path_packet_overheads,
    },
    spaces::{DEFAULT_MAX_ACK_DELAY, SendJournalsOf, peer_max_ack_delay},
};
use crate::{
    call::{CallBundle, CallKind, NodeCallFamily, NodeLoan},
    clock::{InstantOf, LinkIdOf},
    component::{ArgsOf, LineageOf, ReadSet},
    connection_id::{OfferedConnectionId, datagram::DatagramConnectionId},
    error::ConnectionErrorsOf,
    feedback::{FeedbackSummariesOf, FeedbackSummaryOf, PartsSendFeedback},
    frame_source::{
        HandshakePacket, InitialPacket, OneRttPacket, OneRttProbePacket, PacketKind,
        PartsFrameSourceDispatch, PartsFrameSources, SettlingResponsePacket, ZeroRttPacket,
    },
    layer::{self, LinkPath, NodeKey},
    others::OtherNodes,
    send_strategy::{
        DatagramFillPlan, DatagramLimits, FrameSourceCursor, FrameSourceSet, LeadingContent,
        LinkPathSendPlanner, Observe, PacketOverheads, PlannedDatagram, PlannedPacket,
        PlannedPacketKind, SendStrategy, SendStrategyTypes,
    },
    share::{FlatMut, FlatRef, LineageLists, LineagePartList, LinkPathIdentifierOf, NodeData},
    take::{GetAt, Lineage, ReadEach, Reborrow, Take, TakeEach},
    write::{
        ClassOfSource, FlightClass, Last, NotLast, OpenPacket, PacketWriting, PaddingSummary,
        Supplied,
    },
};

/// The limits of the sending call of every link path of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkPathSendingLimits {
    /// How many datagrams the call fills before it hands them to the link
    /// at once: as many as one call of [`Link::send`] takes well, such as
    /// the segments of one generic segmentation offload, or one.
    pub max_datagrams_per_send: NonZeroUsize,
}

/// The sealed packet of the send journals of the choices `T` and the list
/// of parts `L`.
pub type SealedPacketOf<T, L> = <<T as Choices>::SendJournals<
    FeedbackSummaryOf<T, L>,
    LinkPathIdentifierOf<T, L>,
> as SendJournals<
    FeedbackSummaryOf<T, L>,
    InstantOf<T>,
    LinkPathIdentifierOf<T, L>,
>>::SealedPacket;

/// The batch of a link path of the choices `T` and the list of parts `L`,
/// whose congestion controller keeps `S` for each packet in flight.
pub type DatagramBatchOf<T, L, S> =
    DatagramBatch<SealedPacketOf<T, L>, SealedPacketOf<T, L>, SealedPacketOf<T, L>, S>;

/// What one call of [`Link::send`] over the link `Lk` came to.
pub type SendResultOf<Lk> = Result<SendAcceptance<<Lk as Link>::Instant>, <Lk as Link>::SendError>;

/// What the sending call of a link path does with its view: everything
/// but waiting.
pub trait LinkPathSendingCapability: ReceiverFamily {
    /// The link the datagrams go over.
    type Link: Link;
    /// The batch the call keeps across waiting.
    type Batch;

    /// The empty batch the call starts with, of the connection's limit.
    fn start_batch<'v>(view: Pin<&mut Self::ReceiverView<'v>>) -> Self::Batch
    where
        Self: 'v;

    /// Fill `batch` as far as the planner plans and the batch holds; ready
    /// once it holds a datagram, and otherwise `Pending` with the waker
    /// kept where it is woken.
    fn poll_fill<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        batch: &mut Self::Batch,
        cx: &mut Context<'_>,
    ) -> Poll<()>
    where
        Self: 'v;

    /// Take out of `batch` what carries a level whose keys are gone, and
    /// hand the rest to the link; `None` when nothing is left.
    fn hand_over<'v, 'b>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        batch: &'b mut Self::Batch,
    ) -> Option<<Self::Link as Link>::Send<'b>>
    where
        Self: 'v;

    /// Settle what the link did with `batch`: `sent`.
    fn settle<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        batch: &mut Self::Batch,
        sent: SendResultOf<Self::Link>,
    ) where
        Self: 'v;
}

/// What filling takes out of the link path's lineage: the send strategy's
/// core and planner, the connection IDs and the registrar of the link
/// path's reset tokens, the send journals, the count of the AEAD's usage,
/// the recovery factory and the anti-amplification limit of the logical
/// link.
pub type FillTakes<T, L> = HList![
    SendStrategyCore<SendStrategyOf<T, L>>,
    LinkPathPlanner<LinkPathSendPlannerOf<T, L>>,
    ConnectionIdsOf<T>,
    LinkPathResetTokenRegistrar<ResetTokenRegistrarOf<T>>,
    SendJournalsOf<T, L>,
    AeadUsage,
    RecoveryFactoryOf<T, L>,
    AntiAmplification,
];

/// What sending the close packet again takes out of the link path's
/// lineage: the send strategy's core and planner, and the
/// anti-amplification limit of the logical link.
pub type ResendTakes<T, L> = HList![
    SendStrategyCore<SendStrategyOf<T, L>>,
    LinkPathPlanner<LinkPathSendPlannerOf<T, L>>,
    AntiAmplification,
];

/// What filling takes out of what is left to read only: the keys of each
/// level, which packets are sealed with while the frame sources write.
pub type FillReadTakes<T> = HList![
    InitialKeys<<T as Choices>::Crypto>,
    HandshakeKeys<<T as Choices>::Crypto>,
    OneRttKeys<<T as Choices>::Crypto, InstantOf<T>>,
];

/// What is left of the link path's lineage once filling took
/// [`FillTakes`]: what the keys are taken from to read.
pub type FillKeysRest<'x, T, L, It> =
    <<L as LineageLists<'x, T>>::LinkPath as TakeEach<'x, FillTakes<T, L>, It>>::Rest;

/// What is left of the link path's lineage once filling took
/// [`FillTakes`] and [`FillReadTakes`]: where the frame sources are found.
pub type FillRest<'x, T, L, It, Iw> =
    <FillKeysRest<'x, T, L, It> as TakeEach<'x, FillReadTakes<T>, Iw>>::Rest;

/// What filling reads from what is left of the lineage at the start of
/// each datagram: the link's clone and facts, the peer's transport
/// parameters and the packet number states of the spaces.
pub type FillReads<T, L> = HList![
    LinkClone<<T as crate::clock::ConnectionChoices>::Link>,
    LinkFacts,
    PeerTransportParameters<TransportParameterSlots<L>>,
    PacketNumberSpaces<PacketNumberSpaceState>,
];

/// What filling takes from the link path's recovery layer.
pub type FillRecoveryTakes<T, L> = HList![
    CongestionPartOf<T, L>,
    LinkPathCongestionState<InstantOf<T>>,
];

/// What settling takes from the link path's recovery layer, with the loss
/// detection states of the controller's `S` and `Ls`.
pub type SettleRecoveryTakes<T, L, S, Ls> = HList![
    CongestionPartOf<T, L>,
    LinkPathCongestionState<InstantOf<T>>,
    PacketNumberSpaces<LossDetectionState<InstantOf<T>, S, Ls>>,
];

/// What settling reads from the link path's lineage: the link's clone, the
/// thresholds of loss detection and the peer's transport parameters.
pub type SettleReads<T, L> = HList![
    LinkClone<<T as crate::clock::ConnectionChoices>::Link>,
    LossThresholds,
    PeerTransportParameters<TransportParameterSlots<L>>,
];

/// The positions the sending call takes by, grouped as the steps use them:
/// `Is` of its limits; for filling, `It` of [`FillTakes`], `Iw` of
/// [`FillReadTakes`] and `Ir` of [`FillReads`] in what is left, `Ik` of
/// [`FillRecoveryTakes`], `Hs` of
/// each part's frame sources; for handing over, `Ii`, `Ih`, `Io` of the
/// keys and `Il` of the link's clone; for settling, `Ij` of the send
/// journals, `If` of the recovery factory, `Iv` of [`SettleReads`], `Ie`
/// of the idle timeout, `Iq` of [`SettleRecoveryTakes`], `Hf` of each
/// part's feedback; `Ipp` and `Ima` of the peer's `max_udp_payload_size`
/// and `max_ack_delay`; `Jx`, `Jr` and `Jm` of the stored part of
/// congestion control, the RTT estimate and the datagram size probing
/// policy in a recovery layer; for 1-RTT key updates, `Iu` of the AEAD's
/// usage, `Ihc` of whether the handshake is confirmed, `Ikp` of the key
/// phase numbers, `Ic` of the record of why the connection closed, `Ier`
/// of version 1's connection error among the composition's, `Irt` of the
/// RTT estimator in a recovery layer; for the close packet, `Icp` of it,
/// `Irs` of [`ResendTakes`] and `Ilf` of the logical link's facts.
type Positions<
    Is,
    It,
    Iw,
    Ir,
    Ik,
    Hs,
    Ii,
    Ih,
    Io,
    Il,
    Ij,
    If,
    Iv,
    Ie,
    Iq,
    Hf,
    Ipp,
    Ima,
    Jx,
    Jr,
    Jm,
    Iu,
    Ihc,
    Ikp,
    Ic,
    Ier,
    Irt,
    Icp,
    Irs,
    Ilf,
> = (
    Is,
    (It, Iw, Ir, Ik, Hs),
    (Ii, Ih, Io, Il),
    (Ij, If, Iv, Ie, Iq, Hf),
    (Ipp, Ima, Jx, Jr, Jm),
    (Iu, Ihc, Ikp, Ic, Ier, Irt),
    (Icp, Irs, Ilf),
);

/// The upper bound, in debug builds, of the datagrams one poll fills again
/// because the content planned for them left them empty. A frame source
/// that writes nothing for an item has updated or withdrawn its intent
/// already, so each empty datagram takes planned content away and the
/// filling settles; past the bound a source broke that contract.
const EMPTY_DATAGRAMS_PER_POLL: usize = 1024;

/// Why one poll stopped filling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FillEnd {
    /// The batch holds as many datagrams as it may.
    Full,
    /// The planner has nothing to plan; it keeps the waker.
    NothingPlanned,
    /// The plan names content that cannot go now; the planner keeps no
    /// waker.
    Blocked,
    /// The planner asks for the close packet to be sent again before it is
    /// sealed: nothing is filled, and the call does not wake itself for it;
    /// once the close packet is sealed the planner is asked again.
    ResendClose,
}

/// What filling one datagram came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatagramEnd {
    /// It was sealed into the batch, or left empty by content that wrote
    /// nothing: the next datagram starts.
    Next,
    /// Filling ends.
    End(FillEnd),
}

impl<
    T,
    L,
    K,
    B,
    S,
    Ls,
    Is,
    It,
    Iw,
    Ir,
    Ik,
    Hs,
    Ii,
    Ih,
    Io,
    Il,
    Ij,
    If,
    Iv,
    Ie,
    Iq,
    Hf,
    Ipp,
    Ima,
    Jx,
    Jr,
    Jm,
    Iu,
    Ihc,
    Ikp,
    Ic,
    Ier,
    Irt,
    Icp,
    Irs,
    Ilf,
> LinkPathSendingCapability
    for NodeCallFamily<
        T,
        L,
        LinkPath,
        K,
        Positions<
            Is,
            It,
            Iw,
            Ir,
            Ik,
            Hs,
            Ii,
            Ih,
            Io,
            Il,
            Ij,
            If,
            Iv,
            Ie,
            Iq,
            Hf,
            Ipp,
            Ima,
            Jx,
            Jr,
            Jm,
            Iu,
            Ihc,
            Ikp,
            Ic,
            Ier,
            Irt,
            Icp,
            Irs,
            Ilf,
        >,
        B,
    >
where
    T: Choices,
    L: LineagePartList<T> + FeedbackSummariesOf + ParametersOf<TransportParameterSpace>,
    B: CallBundle,
    S: 'static,
    Ls: Clone + 'static,
    PartsFrameSources<InitialPacket, L>: FrameSourceSet,
    PartsFrameSources<HandshakePacket, L>: FrameSourceSet,
    PartsFrameSources<ZeroRttPacket, L>: FrameSourceSet,
    PartsFrameSources<OneRttPacket, L>: FrameSourceSet,
    PartsFrameSources<OneRttProbePacket, L>: FrameSourceSet,
    PartsFrameSources<SettlingResponsePacket, L>: FrameSourceSet,
    FeedbackSummaryOf<T, L>: From<PaddingSummary>,
    SendTypes<T, L>: SendStrategyTypes<
            LinkPathIdentifier = LinkPathIdentifierOf<T, L>,
            InitialFrameSources = PartsFrameSources<InitialPacket, L>,
            HandshakeFrameSources = PartsFrameSources<HandshakePacket, L>,
            ZeroRttFrameSources = PartsFrameSources<ZeroRttPacket, L>,
            OneRttFrameSources = PartsFrameSources<OneRttPacket, L>,
            ProbeFrameSources = PartsFrameSources<OneRttProbePacket, L>,
            SettlingFrameSources = PartsFrameSources<SettlingResponsePacket, L>,
        >,
    SendStrategyOf<T, L>: SendStrategy<SendTypes<T, L>>,
    LinkPathSendPlannerOf<T, L>: Observe<DatagramLimits> + Observe<PacketOverheads>,
    RecoveryFactoryOf<T, L>: RecoveryFactory<T::Link>
        + for<'s> LendCongestion<
            InstantOf<T>,
            OthersOf<'s, T, L>,
            Part = CongestionPartOf<T, L>,
            SentState = S,
            LossState = Ls,
        >,
    TransportParameterSlots<L>:
        Selector<Option<MaxUdpPayloadSize>, Ipp> + Selector<Option<MaxAckDelay>, Ima>,
    for<'v, 's> <L as LineageLists<'v, T>>::LinkPath:
        Reborrow<'s, Out = <L as LineageLists<'s, T>>::LinkPath>,
    for<'x> <L as LineageLists<'x, T>>::LinkPath: GetAt<LinkPathSendingLimits, Is>
        + TakeEach<'x, FillTakes<T, L>, It>
        + GetAt<InitialKeys<T::Crypto>, Ii>
        + GetAt<HandshakeKeys<T::Crypto>, Ih>
        + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>
        + GetAt<LinkClone<T::Link>, Il>
        + GetAt<SendJournalsOf<T, L>, Ij>
        + GetAt<RecoveryFactoryOf<T, L>, If>
        + ReadEach<SettleReads<T, L>, Iv>
        + GetAt<IdleTimeout<InstantOf<T>>, Ie>
        + GetAt<AeadUsage, Iu>
        + GetAt<HandshakeConfirmation, Ihc>
        + GetAt<KeyPhaseNumbers, Ikp>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>
        + GetAt<ClosePacket, Icp>
        + GetAt<LinkFacts, Ilf>
        + TakeEach<'x, ResendTakes<T, L>, Irs>,
    L: ConnectionErrorsOf,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<ConnectionError, Ier>,
    for<'x> FillKeysRest<'x, T, L, It>: TakeEach<'x, FillReadTakes<T>, Iw>,
    for<'x> FillRest<'x, T, L, It, Iw>: ReadEach<FillReads<T, L>, Ir>,
    for<'x> L: PartsFrameSourceDispatch<
            T,
            InitialPacket,
            FillRest<'x, T, L, It, Iw>,
            FeedbackSummaryOf<T, L>,
            Hs,
        > + PartsFrameSourceDispatch<
            T,
            HandshakePacket,
            FillRest<'x, T, L, It, Iw>,
            FeedbackSummaryOf<T, L>,
            Hs,
        > + PartsFrameSourceDispatch<
            T,
            ZeroRttPacket,
            FillRest<'x, T, L, It, Iw>,
            FeedbackSummaryOf<T, L>,
            Hs,
        > + PartsFrameSourceDispatch<
            T,
            OneRttPacket,
            FillRest<'x, T, L, It, Iw>,
            FeedbackSummaryOf<T, L>,
            Hs,
        > + PartsFrameSourceDispatch<
            T,
            OneRttProbePacket,
            FillRest<'x, T, L, It, Iw>,
            FeedbackSummaryOf<T, L>,
            Hs,
        > + PartsFrameSourceDispatch<
            T,
            SettlingResponsePacket,
            FillRest<'x, T, L, It, Iw>,
            FeedbackSummaryOf<T, L>,
            Hs,
        > + PartsSendFeedback<T, L, <L as LineageLists<'x, T>>::LinkPath, Hf>,
    for<'x> NodeData<T, L, layer::Recovery>: FlatMut<'x>,
    for<'x> <NodeData<T, L, layer::Recovery> as FlatMut<'x>>::Out: TakeEach<'x, FillRecoveryTakes<T, L>, Ik>
        + TakeEach<'x, SettleRecoveryTakes<T, L, S, Ls>, Iq>
        + GetAt<RttOf<T, L>, Irt>,
    for<'a> NodeData<T, L, layer::Recovery>: FlatRef<'a>,
    for<'a> <NodeData<T, L, layer::Recovery> as FlatRef<'a>>::Out: Selector<&'a CongestionPartOf<T, L>, Jx>
        + Selector<&'a RttOf<T, L>, Jr>
        + Selector<&'a PmtuOf<T, L>, Jm>,
{
    type Link = T::Link;
    type Batch = DatagramBatchOf<T, L, S>;

    fn start_batch<'v>(view: Pin<&mut NodeLoan<'v, T, L, LinkPath, B>>) -> Self::Batch
    where
        Self: 'v,
    {
        let limits = view.get_mut().lineage.get::<LinkPathSendingLimits, Is>();
        DatagramBatch::new(limits.max_datagrams_per_send)
    }

    fn poll_fill<'v>(
        view: Pin<&mut NodeLoan<'v, T, L, LinkPath, B>>,
        batch: &mut Self::Batch,
        cx: &mut Context<'_>,
    ) -> Poll<()>
    where
        Self: 'v,
    {
        if batch.is_full() {
            return Poll::Ready(());
        }
        let NodeLoan { lineage, others } = view.get_mut();
        if let Some(datagram) = lineage
            .get::<ClosePacket, Icp>()
            .sealed()
            .map(|sealed| sealed.datagram().clone())
        {
            return resend_close::<T, L, S, Ilf, Irs>(lineage, datagram, batch, cx);
        }
        let NodeKey::LinkPath(path, link) = others.here().clone() else {
            unreachable!("a link path's lend carries its key")
        };
        let link_path = L::link_path_identifier(&path, &link);
        let now = others.now();
        // what the layer only reads is read without taking it
        let read = others.recovery_ref().map(|flat| {
            let rtt: &&RttOf<T, L> = Selector::<_, Jr>::get(&flat);
            let pmtu: &&PmtuOf<T, L> = Selector::<_, Jm>::get(&flat);
            (rtt.estimate(), pmtu.conclusion())
        });
        // woken when the layer is built
        let no_layer = if batch.is_empty() {
            Poll::Pending
        } else {
            Poll::Ready(())
        };
        let Some((estimate, pmtu_conclusion)) = read else {
            return no_layer;
        };
        if let Err(source) =
            prepare_key_update::<T, L, B, Ij, Iv, Ima, Io, Iu, Ihc, Ikp, Irt>(lineage, others, now)
        {
            if !lineage
                .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
                .is_written()
            {
                let error = v1_error::<L, Ier>(ConnectionError::AeadLimitReached { source });
                lineage
                    .get_mut::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
                    .record(CloseReason::Local(Arc::new(LocalCloseCause::Connection(
                        error,
                    ))));
            }
            // what the batch holds still goes; the close is the closing
            // packet's to send
            return if batch.is_empty() {
                Poll::Pending
            } else {
                Poll::Ready(())
            };
        }
        let (
            hlist_pat![
                core,
                planner,
                ids,
                registrar,
                journals,
                usage,
                factory,
                amplification
            ],
            rest,
        ) = Take::<FillTakes<T, L>, It>::take(lineage.reborrow());
        let (hlist_pat![initial_keys, handshake_keys, one_rtt_keys], mut rest) =
            rest.take_read::<FillReadTakes<T>, Iw>();
        let filled = others.with_own_recovery::<FillRecoveryTakes<T, L>, Ik, _>(
            |hlist_pat![part, state], others| {
                lend_congestion::<T, L, B, Jx, Jr, _>(factory, part, others, |mut access| {
                    let mut filling = Filling::<T, L, _, _, Ir, Ipp, Hs> {
                        now,
                        link: &link,
                        link_path: &link_path,
                        core,
                        planner,
                        ids,
                        registrar,
                        journals,
                        initial_keys,
                        handshake_keys,
                        one_rtt_keys,
                        initial_discarded: false,
                        usage,
                        amplification,
                        rest: &mut rest,
                        access: &mut access,
                        estimate,
                        pmtu_conclusion,
                        state,
                        positions: core::marker::PhantomData,
                    };
                    let end = filling.fill(batch, cx);
                    (end, filling.initial_discarded)
                })
            },
        );
        drop(rest);
        let Some((end, initial_discarded)) = filled else {
            return no_layer;
        };
        if initial_discarded {
            // the first Handshake packet sent (RFC 9001 §4.9.1)
            lineage.get_mut::<InitialKeys<T::Crypto>, Ii>().discard();
        }
        match end {
            _ if !batch.is_empty() => Poll::Ready(()),
            FillEnd::Full | FillEnd::NothingPlanned | FillEnd::ResendClose => Poll::Pending,
            FillEnd::Blocked => {
                // what this lend changed is reread before the next plan
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    fn hand_over<'v, 'b>(
        view: Pin<&mut NodeLoan<'v, T, L, LinkPath, B>>,
        batch: &'b mut Self::Batch,
    ) -> Option<<T::Link as Link>::Send<'b>>
    where
        Self: 'v,
    {
        let NodeLoan { lineage, others } = view.get_mut();
        let discarded = {
            let initial = lineage.get::<InitialKeys<T::Crypto>, Ii>().send().is_none();
            let handshake = lineage
                .get::<HandshakeKeys<T::Crypto>, Ih>()
                .send()
                .is_none();
            let one_rtt = lineage
                .get::<OneRttKeys<T::Crypto, InstantOf<T>>, Io>()
                .send()
                .is_none();
            batch.take_discarded(|datagram| {
                (initial && datagram.initial.is_some() && !datagram.initial_goes_out())
                    || (handshake && datagram.handshake.is_some())
                    || (one_rtt && datagram.application_data.is_some())
            })
        };
        if !discarded.as_slice().is_empty() {
            give_up::<T, L, B, S, Ls, Ij, If, Iv, Iq, Hf, Ipp, Ima, Jx, Jr, Jm>(
                lineage, others, discarded,
            );
        }
        if batch.is_empty() {
            return None;
        }
        let batch: &'b Self::Batch = batch;
        Some(
            lineage
                .get::<LinkClone<T::Link>, Il>()
                .0
                .send(batch.outgoing()),
        )
    }

    fn settle<'v>(
        view: Pin<&mut NodeLoan<'v, T, L, LinkPath, B>>,
        batch: &mut Self::Batch,
        sent: SendResultOf<T::Link>,
    ) where
        Self: 'v,
    {
        let NodeLoan { lineage, others } = view.get_mut();
        match sent {
            Ok(acceptance) => accept::<T, L, B, S, Ls, Ij, Ie, Iq>(
                lineage,
                others,
                batch.take_accepted(acceptance.count.get()),
                acceptance.at,
            ),
            Err(_) => {
                if let Some(datagram) = batch.take_first() {
                    give_up::<T, L, B, S, Ls, Ij, If, Iv, Iq, Hf, Ipp, Ima, Jx, Jr, Jm>(
                        lineage,
                        others,
                        core::iter::once(datagram),
                    );
                }
            }
        }
    }
}

// ---- filling ----

/// What [`Filling`] reads its components and finds its frame sources by.
type FillPositions<Ir, Ipp, Hs> = fn() -> (Ir, Ipp, Hs);

/// What one poll fills with: the borrows of what it took, the instant of
/// the poll and the link path it fills for.
///
/// `V` is what is left of the lineage, where the frame sources are found;
/// `A` the congestion access lent for the poll.
struct Filling<'f, 'r, T, L, V, A, Ir, Ipp, Hs>
where
    T: Choices,
    L: LineagePartList<T> + FeedbackSummariesOf,
    SendTypes<T, L>: SendStrategyTypes,
    SendStrategyOf<T, L>: SendStrategy<SendTypes<T, L>>,
{
    now: InstantOf<T>,
    link: &'f LinkIdOf<T>,
    link_path: &'f LinkPathIdentifierOf<T, L>,
    core: &'f mut SendStrategyCore<SendStrategyOf<T, L>>,
    planner: &'f mut LinkPathPlanner<LinkPathSendPlannerOf<T, L>>,
    ids: &'f mut ConnectionIdsOf<T>,
    registrar: &'f mut LinkPathResetTokenRegistrar<ResetTokenRegistrarOf<T>>,
    journals: &'f mut SendJournalsOf<T, L>,
    initial_keys: &'f InitialKeys<T::Crypto>,
    handshake_keys: &'f HandshakeKeys<T::Crypto>,
    one_rtt_keys: &'f OneRttKeys<T::Crypto, InstantOf<T>>,
    /// Whether this side discarded its Initial keys in this poll: they are
    /// discarded once the filling is over, and none is used before.
    initial_discarded: bool,
    usage: &'f mut AeadUsage,
    amplification: &'f mut AntiAmplification,
    rest: &'f mut Lineage<'r, V>,
    access: &'f mut A,
    estimate: RttEstimate,
    pmtu_conclusion: usize,
    state: &'f mut LinkPathCongestionState<InstantOf<T>>,
    positions: core::marker::PhantomData<FillPositions<Ir, Ipp, Hs>>,
}

impl<T, L, V, A, S, Ir, Ipp, Hs> Filling<'_, '_, T, L, V, A, Ir, Ipp, Hs>
where
    T: Choices,
    L: LineagePartList<T> + FeedbackSummariesOf + ParametersOf<TransportParameterSpace>,
    PartsFrameSources<InitialPacket, L>: FrameSourceSet,
    PartsFrameSources<HandshakePacket, L>: FrameSourceSet,
    PartsFrameSources<ZeroRttPacket, L>: FrameSourceSet,
    PartsFrameSources<OneRttPacket, L>: FrameSourceSet,
    PartsFrameSources<OneRttProbePacket, L>: FrameSourceSet,
    PartsFrameSources<SettlingResponsePacket, L>: FrameSourceSet,
    FeedbackSummaryOf<T, L>: From<PaddingSummary>,
    SendTypes<T, L>: SendStrategyTypes<
            LinkPathIdentifier = LinkPathIdentifierOf<T, L>,
            InitialFrameSources = PartsFrameSources<InitialPacket, L>,
            HandshakeFrameSources = PartsFrameSources<HandshakePacket, L>,
            ZeroRttFrameSources = PartsFrameSources<ZeroRttPacket, L>,
            OneRttFrameSources = PartsFrameSources<OneRttPacket, L>,
            ProbeFrameSources = PartsFrameSources<OneRttProbePacket, L>,
            SettlingFrameSources = PartsFrameSources<SettlingResponsePacket, L>,
        >,
    SendStrategyOf<T, L>: SendStrategy<SendTypes<T, L>>,
    LinkPathSendPlannerOf<T, L>: Observe<DatagramLimits> + Observe<PacketOverheads>,
    A: CongestionController<InstantOf<T>, SentState = S> + Pacer<InstantOf<T>>,
    TransportParameterSlots<L>: Selector<Option<MaxUdpPayloadSize>, Ipp>,
    V: ReadEach<FillReads<T, L>, Ir>,
    L: PartsFrameSourceDispatch<T, InitialPacket, V, FeedbackSummaryOf<T, L>, Hs>
        + PartsFrameSourceDispatch<T, HandshakePacket, V, FeedbackSummaryOf<T, L>, Hs>
        + PartsFrameSourceDispatch<T, ZeroRttPacket, V, FeedbackSummaryOf<T, L>, Hs>
        + PartsFrameSourceDispatch<T, OneRttPacket, V, FeedbackSummaryOf<T, L>, Hs>
        + PartsFrameSourceDispatch<T, OneRttProbePacket, V, FeedbackSummaryOf<T, L>, Hs>
        + PartsFrameSourceDispatch<T, SettlingResponsePacket, V, FeedbackSummaryOf<T, L>, Hs>,
{
    /// Fill datagrams into `batch` until the batch is full or the plans
    /// stop.
    fn fill(&mut self, batch: &mut DatagramBatchOf<T, L, S>, cx: &mut Context<'_>) -> FillEnd {
        let mut empty = 0;
        loop {
            if batch.is_full() {
                return FillEnd::Full;
            }
            let before = batch.len();
            if let DatagramEnd::End(end) = self.fill_datagram(batch, cx) {
                return end;
            }
            if batch.len() == before {
                empty += 1;
                debug_assert!(
                    empty <= EMPTY_DATAGRAMS_PER_POLL,
                    "a frame source wrote nothing and left its intent as it was"
                );
            }
        }
    }

    /// The keys to send Initial packets with, while there are any.
    fn initial_send_keys(&self) -> Option<&DirectionKeys<T::Crypto>> {
        if self.initial_discarded {
            None
        } else {
            self.initial_keys.send()
        }
    }

    /// Fill one datagram into `batch`, from the limits and the plan of this
    /// moment.
    fn fill_datagram(
        &mut self,
        batch: &mut DatagramBatchOf<T, L, S>,
        cx: &mut Context<'_>,
    ) -> DatagramEnd {
        let role = <T::Side as Side>::ROLE;
        // what the link path can send now, the pacer refilled first: it
        // releases nothing before its first refill
        let hlist_pat![link, facts, peer, numbers] =
            Lineage::read_each::<FillReads<T, L>, Ir>(&*self.rest);
        let link_ceiling = link.0.max_datagram_size().ok();
        let peer_max_udp_payload = peer_max_udp_payload_size::<L, Ipp>(peer);
        let validation = facts.validation;
        let numbers = numbers.clone();
        refill(
            &mut *self.access,
            self.now,
            &self.estimate,
            max_datagram_size_in_use(self.pmtu_conclusion, peer_max_udp_payload, link_ceiling),
        );
        let limits = datagram_limits(
            link_ceiling,
            peer_max_udp_payload,
            self.amplification.credit(validation),
            Some((
                self.pmtu_conclusion,
                CongestionAllowance {
                    window_left: self.state.window_left(&*self.access),
                    pacing_allowance: Pacer::allowance(&*self.access),
                    probe_permits: self.state.probe_permits(),
                },
            )),
        );
        let max_len = limits.capacity_for(FlightClass::AckOnly);
        let in_flight_room = limits.capacity_for(FlightClass::InFlight);
        let scid = self.ids.local();
        let keys = SendKeyLevels {
            initial: self.initial_send_keys().is_some(),
            handshake: self.handshake_keys.send().is_some(),
            one_rtt: self.one_rtt_keys.send().is_some(),
        };
        let (shortest, mut overheads) = link_path_packet_overheads::<T, L>(
            self.ids,
            self.link,
            &numbers,
            self.journals,
            keys,
            max_len,
        );
        self.planner.observe_conditions(limits, overheads);

        let planned = match self
            .planner
            .planner_mut()
            .poll_plan(self.core.strategy_mut(), cx)
        {
            Poll::Pending => return DatagramEnd::End(FillEnd::NothingPlanned),
            Poll::Ready(planned) => planned,
        };
        let mut plan = match planned {
            PlannedDatagram::Fill(plan) => plan,
            // no close packet is sealed yet: nothing to fill
            PlannedDatagram::ResendClose => return DatagramEnd::End(FillEnd::ResendClose),
        };
        let Some(leading) = plan.leading_content() else {
            return DatagramEnd::End(FillEnd::Blocked);
        };
        // a planned level without keys to send with stops the filling, so
        // that the planner hears of it before it plans again
        let Some(leading_overhead) = overheads.of(leading.packet) else {
            return DatagramEnd::End(FillEnd::Blocked);
        };

        // the connection ID: the first offered with which the content
        // planned first fits; where it goes in its packet is not known yet,
        // so it takes its least room, as the last frame, as the planner
        // takes it
        let shortest = shortest.unwrap_or(0);
        let padded = leading.packet == PlannedPacketKind::Initial
            && (overheads.expands_every_initial || leading.class == FlightClass::InFlight);
        let capacity = limits.capacity_for(leading.class);
        let fits = |offered: &OfferedConnectionId| {
            let overhead = leading_overhead + offered.id.len().saturating_sub(shortest);
            (!padded || in_flight_room >= MIN_DATAGRAM_SIZE)
                && capacity >= overhead + leading.min.as_last
        };
        let Some(cid) = DatagramConnectionId::<_, _, _, InstantOf<T>>::choose_first(
            self.ids.destination_mut(),
            self.registrar.registrar_mut(),
            self.link,
            fits,
        ) else {
            return DatagramEnd::End(FillEnd::Blocked);
        };
        let probe = limits.probe_permits > 0
            && limits.congestion_window_left.min(limits.pacing_allowance) < max_len;
        let mut datagram = batch.start_datagram(
            self.now,
            cid,
            role,
            scid.length(),
            max_len,
            in_flight_room,
            probe,
            &mut *self.state,
            &mut *self.access,
            &mut *self.amplification,
        );

        // the packets, in the order of the plan
        let largest = |space| {
            numbers
                .get(space)
                .and_then(PacketNumberSpaceState::largest_acked)
        };
        let mut blocked = false;
        let mut skipped = false;
        // a 1-RTT packet of the kind `$kind`, filled from `$cursor`; the
        // filling of the datagram ends without keys to send it with
        macro_rules! one_rtt_packet {
            ($cursor:ident, $kind:ty) => {{
                let Some(keys) = self.one_rtt_keys.send() else {
                    blocked = true;
                    break;
                };
                // what is left within the AEAD's limit is the closing
                // packet's: the next filling initiates a key update, or
                // closes the connection
                if self
                    .usage
                    .only_closing_packet_left(keys.generation().aead())
                {
                    blocked = true;
                    break;
                }
                let attempt = self
                    .journals
                    .application_data
                    .start_attempt(self.link_path.clone());
                let Ok(writer) = datagram.start_one_rtt_packet(
                    attempt,
                    keys,
                    &mut *self.usage,
                    largest(PacketNumberSpaceKind::ApplicationData),
                ) else {
                    blocked = true;
                    break;
                };
                fill_packet::<T, L, $kind, V, Hs, _, _>(
                    writer.open(),
                    &mut $cursor,
                    self.rest,
                    self.now,
                )
            }};
        }
        loop {
            let Some(packet) = plan.next_packet() else {
                break;
            };
            let kind = packet.kind();
            // moved in here, so that the plan is free once the packet is
            // filled
            let (supplied, item_skipped) = {
                let packet = packet;
                match packet {
                    PlannedPacket::Initial(mut cursor) => {
                        let keys = (!self.initial_discarded)
                            .then(|| self.initial_keys.send())
                            .flatten();
                        let (Some(keys), Some(journals)) = (keys, self.journals.initial.as_mut())
                        else {
                            blocked = true;
                            break;
                        };
                        let attempt = journals.start_attempt(self.link_path.clone());
                        let Ok(writer) = datagram.start_initial_packet(
                            attempt,
                            keys,
                            largest(PacketNumberSpaceKind::Initial),
                            scid,
                            Bytes::new(),
                        ) else {
                            blocked = true;
                            break;
                        };
                        fill_packet::<T, L, InitialPacket, V, Hs, _, _>(
                            writer.open(),
                            &mut cursor,
                            self.rest,
                            self.now,
                        )
                    }
                    PlannedPacket::Handshake(mut cursor) => {
                        let (Some(keys), Some(journals)) =
                            (self.handshake_keys.send(), self.journals.handshake.as_mut())
                        else {
                            blocked = true;
                            break;
                        };
                        let attempt = journals.start_attempt(self.link_path.clone());
                        let Ok(writer) = datagram.start_handshake_packet(
                            attempt,
                            keys,
                            largest(PacketNumberSpaceKind::Handshake),
                            scid,
                        ) else {
                            blocked = true;
                            break;
                        };
                        fill_packet::<T, L, HandshakePacket, V, Hs, _, _>(
                            writer.open(),
                            &mut cursor,
                            self.rest,
                            self.now,
                        )
                    }
                    // no keys to send 0-RTT packets with are kept
                    PlannedPacket::ZeroRtt(cursor) => {
                        drop(cursor);
                        blocked = true;
                        break;
                    }
                    PlannedPacket::OneRtt(mut cursor) => {
                        one_rtt_packet!(cursor, OneRttPacket)
                    }
                    PlannedPacket::OneRttProbe(mut cursor) => {
                        one_rtt_packet!(cursor, OneRttProbePacket)
                    }
                    PlannedPacket::SettlingResponse(mut cursor) => {
                        one_rtt_packet!(cursor, SettlingResponsePacket)
                    }
                }
            };
            skipped |= item_skipped;
            // looking ahead: the packet is the last unless what the plan
            // leads the next one with fits after it
            let more = !item_skipped
                && plan
                    .peek_next_packet()
                    .is_some_and(|next| next_fits(&next, &supplied, &overheads));
            supplied.conclude(more);
            if kind == PlannedPacketKind::Handshake
                && role == Role::Client
                && datagram.carries(PacketNumberSpaceKind::Handshake)
                && !self.initial_discarded
                && self.initial_keys.send().is_some()
            {
                // the first Handshake packet sent (RFC 9001 §4.9.1)
                self.initial_discarded = true;
                datagram.keep_initial_packets();
                overheads.initial = None;
            }
            if !more {
                break;
            }
        }
        let sealed = !datagram.is_empty();
        drop(datagram);
        drop(plan);
        if blocked || (skipped && !sealed) {
            DatagramEnd::End(FillEnd::Blocked)
        } else {
            DatagramEnd::Next
        }
    }
}

/// Fill `batch` with the sealed close packet `datagram` as often as the
/// planner of the link path of `lineage` asks for it to go again, until
/// the batch is full or the planner has nothing to plan. Each copy is
/// charged to the anti-amplification limit of the logical link before it
/// joins the batch; a copy the credit does not allow is not sent. A copy
/// enters no send journal and counts nothing in flight. Ready once the
/// batch holds a datagram.
///
/// A plan to fill a datagram is dropped as it comes: a closing link path
/// sends nothing else.
fn resend_close<'v, T, L, S, Ilf, Irs>(
    lineage: &mut LineageOf<'v, T, L, LinkPath>,
    datagram: Bytes,
    batch: &mut DatagramBatchOf<T, L, S>,
    cx: &mut Context<'_>,
) -> Poll<()>
where
    T: Choices,
    L: LineagePartList<T> + FeedbackSummariesOf,
    SendTypes<T, L>: SendStrategyTypes,
    SendStrategyOf<T, L>: SendStrategy<SendTypes<T, L>>,
    for<'w, 's> <L as LineageLists<'w, T>>::LinkPath:
        Reborrow<'s, Out = <L as LineageLists<'s, T>>::LinkPath>,
    for<'x> <L as LineageLists<'x, T>>::LinkPath:
        GetAt<LinkFacts, Ilf> + TakeEach<'x, ResendTakes<T, L>, Irs>,
{
    let validation = lineage.get::<LinkFacts, Ilf>().validation;
    let (hlist_pat![core, planner, amplification], _) =
        Take::<ResendTakes<T, L>, Irs>::take(lineage.reborrow());
    while !batch.is_full() {
        match planner.planner_mut().poll_plan(core.strategy_mut(), cx) {
            Poll::Pending => break,
            Poll::Ready(PlannedDatagram::Fill(plan)) => {
                drop(plan);
                break;
            }
            Poll::Ready(PlannedDatagram::ResendClose) => {
                let len = u64::try_from(datagram.len()).unwrap_or(u64::MAX);
                let allowed = amplification
                    .credit(validation)
                    .is_none_or(|credit| credit >= len);
                if allowed {
                    amplification.sent(datagram.len());
                    batch.push_close_packet(datagram.clone());
                }
            }
        }
    }
    if batch.is_empty() {
        Poll::Pending
    } else {
        Poll::Ready(())
    }
}

/// Before a filling of a link path at `now`: initiate a 1-RTT key update
/// when one is due and may be initiated, and note the next packet number of
/// the Application Data space as sent with the current sending generation
/// ([`prepare_one_rtt_packets`]). The probe timeout waited after an
/// acknowledgment is the largest among the link paths.
///
/// # Errors
///
/// [`AeadLimitReachedError::ConfidentialityLimitReached`]: the current
/// sending generation may seal only the closing packet, and no key update
/// may be initiated.
#[allow(clippy::type_complexity)] // the positions of what it takes
fn prepare_key_update<'v, T, L, B, Ij, Iv, Ima, Io, Iu, Ihc, Ikp, Irt>(
    lineage: &mut LineageOf<'v, T, L, LinkPath>,
    others: &mut OtherNodes<'v, T, L, B>,
    now: InstantOf<T>,
) -> Result<(), AeadLimitReachedError>
where
    T: Choices,
    L: LineagePartList<T> + FeedbackSummariesOf + ParametersOf<TransportParameterSpace>,
    B: CallBundle,
    TransportParameterSlots<L>: Selector<Option<MaxAckDelay>, Ima>,
    for<'x> <L as LineageLists<'x, T>>::LinkPath: GetAt<SendJournalsOf<T, L>, Ij>
        + ReadEach<SettleReads<T, L>, Iv>
        + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>
        + GetAt<AeadUsage, Iu>
        + GetAt<HandshakeConfirmation, Ihc>
        + GetAt<KeyPhaseNumbers, Ikp>,
    for<'x> NodeData<T, L, layer::Recovery>: FlatMut<'x>,
    for<'x> <NodeData<T, L, layer::Recovery> as FlatMut<'x>>::Out: GetAt<RttOf<T, L>, Irt>,
{
    let next = lineage
        .get::<SendJournalsOf<T, L>, Ij>()
        .application_data
        .next_packet_number();
    let hlist_pat![_, thresholds, peer] = (*lineage).read_each::<SettleReads<T, L>, Iv>();
    let peer_max_ack_delay = peer_max_ack_delay::<L, Ima>(peer).unwrap_or(DEFAULT_MAX_ACK_DELAY);
    let granularity = thresholds.granularity();
    prepare_one_rtt_packets::<T::Crypto, _, _, _, Io, Iu, Ihc, Ikp>(lineage, next, now, || {
        largest_probe_timeout::<T, L, B, Irt>(peer_max_ack_delay, granularity, others)
            // invariant: the link path that fills has a recovery layer
            .unwrap_or_else(|| unreachable!("the filling link path has a recovery layer"))
    })
}

/// Whether the content `next` leads the next packet with fits after the
/// packet `current`: its packet's overhead and its least room as the last
/// frame of that packet, since its position is not known yet, in what is
/// left of the datagram for its class.
fn next_fits<Id, W: PacketWriting, P>(
    next: &LeadingContent<Id>,
    current: &Supplied<W, ClassOfSource, P>,
    overheads: &PacketOverheads,
) -> bool {
    overheads
        .of(next.packet)
        .is_some_and(|overhead| current.room(next.class) >= overhead + next.min.as_last)
}

/// Fill the packet `open` of the kind `K` with the items of `cursor`, each
/// given to its frame source among `rest` at `now`; what is left is the
/// packet, last in its datagram until the look-ahead says otherwise, and
/// whether an item was not given to its source because it did not fit.
///
/// An item is the last of the packet when the plan says so, or when what
/// is left takes it as the last frame and no longer with a Length field;
/// it then may close the packet, and no item after it is given a source.
/// An item whose least room for its position does not fit is dropped
/// unsupplied, and nothing after it goes into the datagram.
fn fill_packet<T, L, K, V, Hs, C, W>(
    mut open: OpenPacket<W, ClassOfSource, NotLast>,
    cursor: &mut C,
    rest: &mut Lineage<'_, V>,
    now: InstantOf<T>,
) -> (Supplied<W, ClassOfSource, Last>, bool)
where
    T: Choices,
    L: LineagePartList<T>
        + FeedbackSummariesOf
        + PartsFrameSourceDispatch<T, K, V, FeedbackSummaryOf<T, L>, Hs>,
    K: PacketKind,
    PartsFrameSources<K, L>: FrameSourceSet,
    C: FrameSourceCursor<PartsFrameSources<K, L>>,
    W: PacketWriting,
    W::Attempt: PacketSendAttempt<Summary = FeedbackSummaryOf<T, L>>,
{
    loop {
        let Some(item) = cursor.next() else {
            return (Supplied::Open(open.make_last()), false);
        };
        let min = item.min();
        let room = open.room(item.class());
        let last = item.last_in_packet() || (room < min.with_length && room >= min.as_last);
        let needed = if last { min.as_last } else { min.with_length };
        if room < needed {
            drop(item);
            return (Supplied::Open(open.make_last()), true);
        }
        if last {
            let supplied = item.supply(open.make_last(), |item, packet| {
                <L as PartsFrameSourceDispatch<T, K, V, FeedbackSummaryOf<T, L>, Hs>>::supply(
                    rest, now, item, packet,
                )
            });
            return (supplied, false);
        }
        let supplied = item.supply(open, |item, packet| {
            <L as PartsFrameSourceDispatch<T, K, V, FeedbackSummaryOf<T, L>, Hs>>::supply(
                rest, now, item, packet,
            )
        });
        match supplied {
            Supplied::Open(packet) => open = packet,
            // only a packet in the last position can be closed, so this is
            // not reached; the closed packet is the last all the same
            Supplied::Closed(packet) => return (Supplied::Closed(packet), false),
        }
    }
}

// ---- settling ----

/// The packets `datagram` carries, with their spaces, in the order
/// Initial, Handshake, application data.
fn packets_of<P, C>(
    datagram: BatchedDatagram<P, P, P, C>,
) -> impl Iterator<Item = (PacketNumberSpaceKind, BatchedPacket<P, C>)> {
    let BatchedDatagram {
        initial,
        handshake,
        application_data,
        ..
    } = datagram;
    [
        (PacketNumberSpaceKind::Initial, initial),
        (PacketNumberSpaceKind::Handshake, handshake),
        (PacketNumberSpaceKind::ApplicationData, application_data),
    ]
    .into_iter()
    .filter_map(|(space, packet)| packet.map(|packet| (space, packet)))
}

/// The link accepted the datagrams `accepted` at `at`: their packets are
/// marked sent then and enter the loss detection state of their space,
/// and an ack-eliciting one restarts the idle timeout.
fn accept<'v, T, L, B, S, Ls, Ij, Ie, Iq>(
    lineage: &mut LineageOf<'v, T, L, LinkPath>,
    others: &mut OtherNodes<'v, T, L, B>,
    accepted: impl Iterator<
        Item = BatchedDatagram<SealedPacketOf<T, L>, SealedPacketOf<T, L>, SealedPacketOf<T, L>, S>,
    >,
    at: InstantOf<T>,
) where
    T: Choices,
    L: LineagePartList<T> + FeedbackSummariesOf,
    B: CallBundle,
    S: 'static,
    Ls: 'static,
    for<'x> <L as LineageLists<'x, T>>::LinkPath:
        GetAt<SendJournalsOf<T, L>, Ij> + GetAt<IdleTimeout<InstantOf<T>>, Ie>,
    for<'x> NodeData<T, L, layer::Recovery>: FlatMut<'x>,
    for<'x> <NodeData<T, L, layer::Recovery> as FlatMut<'x>>::Out:
        TakeEach<'x, SettleRecoveryTakes<T, L, S, Ls>, Iq>,
{
    let accepted: Vec<_> = accepted.collect();
    let journals = lineage.get_mut::<SendJournalsOf<T, L>, Ij>();
    let mut ack_eliciting = false;
    let mut mark = Some(
        |mut detections: Option<
            &mut PacketNumberSpaces<LossDetectionState<InstantOf<T>, S, Ls>>,
        >| {
            for datagram in accepted {
                for (space, packet) in packets_of(datagram) {
                    let Some(journals) = journals.get_mut(space) else {
                        continue;
                    };
                    let record = journals.sent(packet.sealed, at);
                    ack_eliciting |= record.ack_eliciting;
                    if let Some(detection) = detections
                        .as_mut()
                        .and_then(|detections| detections.get_mut(space))
                    {
                        detection.accept(record.number, at, record.ack_eliciting, packet.in_flight);
                    }
                }
            }
        },
    );
    let marked = others.with_own_recovery::<SettleRecoveryTakes<T, L, S, Ls>, Iq, _>(
        |hlist_pat![_, _, detections], _| {
            if let Some(mark) = mark.take() {
                mark(Some(detections));
            }
        },
    );
    if marked.is_none()
        && let Some(mark) = mark.take()
    {
        mark(None);
    }
    if ack_eliciting {
        lineage
            .get_mut::<IdleTimeout<InstantOf<T>>, Ie>()
            .ack_eliciting_sent(at);
    }
}

/// Give up the packets of `datagrams`: their send result is unknown. Each
/// is kept as declared lost for three probe timeouts of its space, the
/// summaries of its frames go back to their parts as lost, and those that
/// count in flight leave the bytes in flight without a congestion signal.
fn give_up<'v, T, L, B, S, Ls, Ij, If, Iv, Iq, Hf, Ipp, Ima, Jx, Jr, Jm>(
    lineage: &mut LineageOf<'v, T, L, LinkPath>,
    others: &mut OtherNodes<'v, T, L, B>,
    datagrams: impl IntoIterator<
        Item = BatchedDatagram<SealedPacketOf<T, L>, SealedPacketOf<T, L>, SealedPacketOf<T, L>, S>,
    >,
) where
    T: Choices,
    L: LineagePartList<T> + FeedbackSummariesOf + ParametersOf<TransportParameterSpace>,
    B: CallBundle,
    S: 'static,
    Ls: Clone + 'static,
    RecoveryFactoryOf<T, L>: RecoveryFactory<T::Link>
        + for<'s> LendCongestion<
            InstantOf<T>,
            OthersOf<'s, T, L>,
            Part = CongestionPartOf<T, L>,
            SentState = S,
            LossState = Ls,
        >,
    TransportParameterSlots<L>:
        Selector<Option<MaxUdpPayloadSize>, Ipp> + Selector<Option<MaxAckDelay>, Ima>,
    for<'x> <L as LineageLists<'x, T>>::LinkPath: GetAt<SendJournalsOf<T, L>, Ij>
        + GetAt<RecoveryFactoryOf<T, L>, If>
        + ReadEach<SettleReads<T, L>, Iv>,
    for<'x> L: PartsSendFeedback<T, L, <L as LineageLists<'x, T>>::LinkPath, Hf>,
    for<'x> NodeData<T, L, layer::Recovery>: FlatMut<'x>,
    for<'x> <NodeData<T, L, layer::Recovery> as FlatMut<'x>>::Out:
        TakeEach<'x, SettleRecoveryTakes<T, L, S, Ls>, Iq>,
    for<'a> NodeData<T, L, layer::Recovery>: FlatRef<'a>,
    for<'a> <NodeData<T, L, layer::Recovery> as FlatRef<'a>>::Out: Selector<&'a CongestionPartOf<T, L>, Jx>
        + Selector<&'a RttOf<T, L>, Jr>
        + Selector<&'a PmtuOf<T, L>, Jm>,
{
    let now = others.now();
    let hlist_pat![link, thresholds, peer] = Lineage::read_each::<SettleReads<T, L>, Iv>(&*lineage);
    let link_ceiling = link.0.max_datagram_size().ok();
    let granularity = thresholds.granularity();
    let peer_max_ack_delay = peer_max_ack_delay::<L, Ima>(peer).unwrap_or(DEFAULT_MAX_ACK_DELAY);
    let peer_max_udp_payload = peer_max_udp_payload_size::<L, Ipp>(peer);
    let read = others.recovery_ref().map(|flat| {
        let rtt: &&RttOf<T, L> = Selector::<_, Jr>::get(&flat);
        let pmtu: &&PmtuOf<T, L> = Selector::<_, Jm>::get(&flat);
        (rtt.estimate(), pmtu.conclusion())
    });
    // as long as a packet declared lost is kept (RFC 9002 §6.1); a link
    // path without a recovery layer keeps it no longer than now
    let retain_until = |space| {
        read.map_or(now, |(estimate, _)| {
            let pto = probe_timeout(&estimate, granularity, space, peer_max_ack_delay, 0);
            now + pto.saturating_mul(3)
        })
    };
    // out of the lineage while the summaries go back to the parts beside
    // it; the empty journals left in their place take nothing meanwhile
    let mut journals = core::mem::take(lineage.get_mut::<SendJournalsOf<T, L>, Ij>());
    let mut removed = Vec::new();
    for datagram in datagrams {
        for (space, packet) in packets_of(datagram) {
            let Some(space_journals) = journals.get_mut(space) else {
                continue;
            };
            let record = space_journals.send_result_unknown(packet.sealed, retain_until(space));
            if let Some(charge) = packet.in_flight {
                removed.push(RemovedPacket {
                    bytes: charge.bytes,
                    sent_state: charge.sent_state,
                });
            }
            for summary in &record.summaries {
                <L as PartsSendFeedback<T, L, _, Hf>>::lost(lineage, others, space, summary);
            }
        }
    }
    *lineage.get_mut::<SendJournalsOf<T, L>, Ij>() = journals;
    let Some((estimate, conclusion)) = read else {
        return;
    };
    if removed.is_empty() {
        return;
    }
    let factory = lineage.get_mut::<RecoveryFactoryOf<T, L>, If>();
    others.with_own_recovery::<SettleRecoveryTakes<T, L, S, Ls>, Iq, _>(
        |hlist_pat![part, state, _], others| {
            for packet in &removed {
                state.remove_in_flight(packet.bytes);
            }
            let context = CongestionContext {
                now,
                bytes_in_flight: state.bytes_in_flight(),
                rtt: estimate,
                rtt_sampled: false,
                max_datagram_size: max_datagram_size_in_use(
                    conclusion,
                    peer_max_udp_payload,
                    link_ceiling,
                ),
            };
            lend_congestion::<T, L, B, Jx, Jr, _>(factory, part, others, |mut access| {
                access.on_removed(removed.into_iter(), &context);
            });
        },
    );
}

// ---- the call ----

/// The sending call of a link path; the steps are those of the
/// [module documentation](self).
#[call]
pub async fn link_path_sending<W: LinkPathSendingCapability>(
    host: &mut impl LentAccess<Family = W>,
) {
    let mut batch = host.with(|mut view| W::start_batch(view.as_pin()));
    loop {
        poll_fn(|cx| host.with(|mut view| W::poll_fill(view.as_pin(), &mut batch, cx))).await;
        let handed = &mut batch;
        let Some(sending) = host.with(move |mut view| W::hand_over(view.as_pin(), handed)) else {
            continue;
        };
        let sent = sending.await;
        host.with(|mut view| W::settle(view.as_pin(), &mut batch, sent));
    }
}

/// The kind of the sending call of a link path. It reads the datagram size
/// probing policy of the link path's recovery layer: the call is woken when
/// the layer is built, and when the policy changes what the link path
/// sends at; and the link path's close packet, once it is sealed.
/// Everything else that lets it send more is the send planner's to wake it
/// for.
#[derive(Debug)]
pub struct LinkPathSendingKind;

impl<
    T,
    L,
    S,
    Ls,
    Is,
    It,
    Iw,
    Ir,
    Ik,
    Hs,
    Ii,
    Ih,
    Io,
    Il,
    Ij,
    If,
    Iv,
    Ie,
    Iq,
    Hf,
    Ipp,
    Ima,
    Jx,
    Jr,
    Jm,
    Iu,
    Ihc,
    Ikp,
    Ic,
    Ier,
    Irt,
    Icp,
    Irs,
    Ilf,
>
    CallKind<
        T,
        L,
        LinkPath,
        Positions<
            Is,
            It,
            Iw,
            Ir,
            Ik,
            Hs,
            Ii,
            Ih,
            Io,
            Il,
            Ij,
            If,
            Iv,
            Ie,
            Iq,
            Hf,
            Ipp,
            Ima,
            Jx,
            Jr,
            Jm,
            Iu,
            Ihc,
            Ikp,
            Ic,
            Ier,
            Irt,
            Icp,
            Irs,
            Ilf,
        >,
    > for LinkPathSendingKind
where
    T: Choices,
    L: LineagePartList<T> + FeedbackSummariesOf + ParametersOf<TransportParameterSpace>,
    S: 'static,
    Ls: Clone + 'static,
    PartsFrameSources<InitialPacket, L>: FrameSourceSet,
    PartsFrameSources<HandshakePacket, L>: FrameSourceSet,
    PartsFrameSources<ZeroRttPacket, L>: FrameSourceSet,
    PartsFrameSources<OneRttPacket, L>: FrameSourceSet,
    PartsFrameSources<OneRttProbePacket, L>: FrameSourceSet,
    PartsFrameSources<SettlingResponsePacket, L>: FrameSourceSet,
    FeedbackSummaryOf<T, L>: From<PaddingSummary>,
    SendTypes<T, L>: SendStrategyTypes<
            LinkPathIdentifier = LinkPathIdentifierOf<T, L>,
            InitialFrameSources = PartsFrameSources<InitialPacket, L>,
            HandshakeFrameSources = PartsFrameSources<HandshakePacket, L>,
            ZeroRttFrameSources = PartsFrameSources<ZeroRttPacket, L>,
            OneRttFrameSources = PartsFrameSources<OneRttPacket, L>,
            ProbeFrameSources = PartsFrameSources<OneRttProbePacket, L>,
            SettlingFrameSources = PartsFrameSources<SettlingResponsePacket, L>,
        >,
    SendStrategyOf<T, L>: SendStrategy<SendTypes<T, L>>,
    LinkPathSendPlannerOf<T, L>: Observe<DatagramLimits> + Observe<PacketOverheads>,
    RecoveryFactoryOf<T, L>: RecoveryFactory<T::Link>
        + for<'s> LendCongestion<
            InstantOf<T>,
            OthersOf<'s, T, L>,
            Part = CongestionPartOf<T, L>,
            SentState = S,
            LossState = Ls,
        >,
    TransportParameterSlots<L>:
        Selector<Option<MaxUdpPayloadSize>, Ipp> + Selector<Option<MaxAckDelay>, Ima>,
    for<'v, 's> <L as LineageLists<'v, T>>::LinkPath:
        Reborrow<'s, Out = <L as LineageLists<'s, T>>::LinkPath>,
    for<'x> <L as LineageLists<'x, T>>::LinkPath: GetAt<LinkPathSendingLimits, Is>
        + TakeEach<'x, FillTakes<T, L>, It>
        + GetAt<InitialKeys<T::Crypto>, Ii>
        + GetAt<HandshakeKeys<T::Crypto>, Ih>
        + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>
        + GetAt<LinkClone<T::Link>, Il>
        + GetAt<SendJournalsOf<T, L>, Ij>
        + GetAt<RecoveryFactoryOf<T, L>, If>
        + ReadEach<SettleReads<T, L>, Iv>
        + GetAt<IdleTimeout<InstantOf<T>>, Ie>
        + GetAt<AeadUsage, Iu>
        + GetAt<HandshakeConfirmation, Ihc>
        + GetAt<KeyPhaseNumbers, Ikp>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>
        + GetAt<ClosePacket, Icp>
        + GetAt<LinkFacts, Ilf>
        + TakeEach<'x, ResendTakes<T, L>, Irs>,
    L: ConnectionErrorsOf,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<ConnectionError, Ier>,
    for<'x> FillKeysRest<'x, T, L, It>: TakeEach<'x, FillReadTakes<T>, Iw>,
    for<'x> FillRest<'x, T, L, It, Iw>: ReadEach<FillReads<T, L>, Ir>,
    for<'x> L: PartsFrameSourceDispatch<
            T,
            InitialPacket,
            FillRest<'x, T, L, It, Iw>,
            FeedbackSummaryOf<T, L>,
            Hs,
        > + PartsFrameSourceDispatch<
            T,
            HandshakePacket,
            FillRest<'x, T, L, It, Iw>,
            FeedbackSummaryOf<T, L>,
            Hs,
        > + PartsFrameSourceDispatch<
            T,
            ZeroRttPacket,
            FillRest<'x, T, L, It, Iw>,
            FeedbackSummaryOf<T, L>,
            Hs,
        > + PartsFrameSourceDispatch<
            T,
            OneRttPacket,
            FillRest<'x, T, L, It, Iw>,
            FeedbackSummaryOf<T, L>,
            Hs,
        > + PartsFrameSourceDispatch<
            T,
            OneRttProbePacket,
            FillRest<'x, T, L, It, Iw>,
            FeedbackSummaryOf<T, L>,
            Hs,
        > + PartsFrameSourceDispatch<
            T,
            SettlingResponsePacket,
            FillRest<'x, T, L, It, Iw>,
            FeedbackSummaryOf<T, L>,
            Hs,
        > + PartsSendFeedback<T, L, <L as LineageLists<'x, T>>::LinkPath, Hf>,
    for<'x> NodeData<T, L, layer::Recovery>: FlatMut<'x>,
    for<'x> <NodeData<T, L, layer::Recovery> as FlatMut<'x>>::Out: TakeEach<'x, FillRecoveryTakes<T, L>, Ik>
        + TakeEach<'x, SettleRecoveryTakes<T, L, S, Ls>, Iq>
        + GetAt<RttOf<T, L>, Irt>,
    for<'a> NodeData<T, L, layer::Recovery>: FlatRef<'a>,
    for<'a> <NodeData<T, L, layer::Recovery> as FlatRef<'a>>::Out: Selector<&'a CongestionPartOf<T, L>, Jx>
        + Selector<&'a RttOf<T, L>, Jr>
        + Selector<&'a PmtuOf<T, L>, Jm>,
    Positions<
        Is,
        It,
        Iw,
        Ir,
        Ik,
        Hs,
        Ii,
        Ih,
        Io,
        Il,
        Ij,
        If,
        Iv,
        Ie,
        Iq,
        Hf,
        Ipp,
        Ima,
        Jx,
        Jr,
        Jm,
        Iu,
        Ihc,
        Ikp,
        Ic,
        Ier,
        Irt,
        Icp,
        Irs,
        Ilf,
    >: 'static,
    S: 'static,
{
    type Call<B: CallBundle> = LentCall<
        NodeCallFamily<
            T,
            L,
            LinkPath,
            LinkPathSendingKind,
            Positions<
                Is,
                It,
                Iw,
                Ir,
                Ik,
                Hs,
                Ii,
                Ih,
                Io,
                Il,
                Ij,
                If,
                Iv,
                Ie,
                Iq,
                Hf,
                Ipp,
                Ima,
                Jx,
                Jr,
                Jm,
                Iu,
                Ihc,
                Ikp,
                Ic,
                Ier,
                Irt,
                Icp,
                Irs,
                Ilf,
            >,
            B,
        >,
        LinkPathSending,
    >;
    fn start<B: CallBundle>(_: &mut ArgsOf<T, L, LinkPath>) -> Self::Call<B> {
        LentCall::new(LinkPathSending::new())
    }
    fn reads(reads: &mut ReadSet) {
        reads.add::<PmtuOf<T, L>>().add::<ClosePacket>();
    }
}
