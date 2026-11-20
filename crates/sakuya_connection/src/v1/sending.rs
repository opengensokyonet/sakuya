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
//!    which the planner is told before it is asked for the plan; the
//!    request carries what the driver's own components have to send on the
//!    link path then
//!    ([`DriverContent`](crate::send_strategy::DriverContent)), gathered
//!    afresh for each datagram. The connection ID is the first one offered for the link
//!    path with which the content planned first fits, chosen by reading the
//!    destination connection ID strategy only; each planned packet then
//!    gets a packet of its kind, opened with the keys of its level, and its
//!    planned items go in order to their frame sources, which find their
//!    components in what filling left of the lineage, the logical path's
//!    connection IDs among them. Whether an item fits is what its source
//!    writes: one whose least room does not fit is not given to its source
//!    and counts as having written nothing. An item that wrote nothing ends
//!    the datagram when it holds its place, and is passed over when it does
//!    not. One datagram carries one connection ID (RFC 9000 §12.2), and a
//!    0-RTT packet is never written, as no keys to send one with are kept.
//!    Once the datagram is sealed with content, the
//!    strategy is told that the connection ID was used, with the
//!    datagram's size and the link path's reset token registrar; a datagram
//!    left empty used nothing.
//!    Before a packet is sealed, the plan says what the
//!    next packet leads with: the packet is the last of the datagram, and
//!    padded to its floor, when that does not fit after it. A datagram the
//!    content left empty is filled again from the start, up to a bound of
//!    empty datagrams in one poll. Filling ends when the batch is full,
//!    when the planner has nothing to plan or asks for the close packet
//!    again before one is sealed, when the bound of empty datagrams is
//!    reached, or when the plan names content that cannot go now: no
//!    connection ID fits it, its level has no keys to send with, or some of
//!    it did not fit its packet and the datagram was left empty. With
//!    nothing in the batch the call then
//!    waits for the planner. In the last case it wakes itself first, so
//!    that what the lend published is handled before it plans again; blocked
//!    again while nothing the planner is told has changed, it waits until
//!    something does. What the batch still holds from the last round is
//!    handed over with what is filled.
//! 2. Handing over. The datagrams that carry a packet of a level whose
//!    keys to send with are gone by now are taken out, and their packets
//!    are given up; then the batch goes to [`Link::send`], whose future
//!    borrows the batch only.
//! 3. Settling. The datagrams the link accepted have their packets marked
//!    sent at the instant the link gives; they enter the loss detection
//!    state of their space, and an ack-eliciting one restarts the idle
//!    timeout (RFC 9000 §10.1). The first datagram a link accepts is noted
//!    in the connection's [`DatagramAcceptance`]. When the link gives the
//!    first datagram up, its packets are given up; the rest wait for the
//!    next round.
//!
//! A packet given up counts as declared lost: it leaves the bytes in
//! flight without a congestion signal, its record is kept as long as one of
//! a packet declared lost, and the summaries of its frames go back to their
//! frame sources as lost. What the datagram was charged with when it was
//! sealed stays charged. A packet of a packet number space retired after it
//! was sealed ([`space_retirement`](super::space_retirement)) has no record:
//! when the link accepts it or gives it up, it leaves the bytes in flight
//! without a signal, and the summaries of its frames go with it.
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
//!
//! Each datagram is marked as the link path's ECN state says at its start
//! ([`ecn`](super::ecn)): an active link path over a link that may mark
//! asks its ECN policy, with the probe timeout without backoff of the
//! Application Data space, unless it holds, another link path of its
//! logical path having marked packets outstanding, or its validation
//! failed; every other datagram is Not-ECT. A marked datagram sealed counts
//! its QUIC packets toward the test; a marked packet the link accepts
//! counts in the packet number space as sent with its codepoint and is
//! outstanding in the link path's ECN state.
//!
//! A link path without a recovery layer sends nothing new, and its call is
//! woken when its layer is built, except a candidate's: it sends its
//! probes in uncharged datagrams of 1200 bytes, which count in no
//! congestion control and nothing in flight (RFC 9000 §9.4), held by the
//! anti-amplification limit alone, with no datagram size probing; path
//! validation times its challenges. A datagram sealed with
//! a PATH_CHALLENGE tells the link path's path validation whether it was
//! expanded to 1200 bytes.
//!
//! Once the link path's close packet is sealed, the call fills nothing:
//! each time the planner asks for the close packet to go again, the sealed
//! datagram joins the batch as it is, charged first to the
//! anti-amplification limit of the logical link; a copy the credit does
//! not allow is not sent ([`ClosePacket`]). It enters no send journal and
//! counts nothing in flight. A send in flight when the link path began
//! closing is still settled; once the link path is `Draining`, the call is
//! dropped, with what its link still holds (RFC 9000 §10.2.2).
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
    time::Duration,
};
use sakuya_wire_v1::frame::write::FlightClass;

use std::sync::Arc;

use bytes::Bytes;
use frunk_core::hlist_pat;
use nitori_call::{LentAccess, LentCall, ReceiverFamily, call};
use nitori_tls::engine::CryptoLevel;
use sakuya_link::{EcnMarking, Link, MIN_DATAGRAM_SIZE, SendAcceptance};
use sakuya_recovery::{
    congestion::{CongestionContext, CongestionController, RemovedPacket},
    ecn::EcnPolicy,
    factory::{LendCongestion, RecoveryFactory},
    loss::LossThresholds,
    loss_detection::{InFlightCharge, LossDetectionState},
    pacing::Pacer,
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaceState, PacketNumberSpaces},
    pmtu::{PmtuPolicy, PmtuProbeFailure},
    pto::{SecondProbe, probe_timeout},
    rtt::{INITIAL_RTT, RttEstimate, RttEstimator},
    send_journals::{PacketSendAttempt, SendJournals},
};
use sakuya_stream::connection::CloseReason;
use sakuya_wire::{
    parameters::ParametersOf,
    parts::{CoprodInjector, HList, Selector},
};
use sakuya_wire_v1::{
    role::Role,
    transport_parameters::{
        TransportParameterSlots, TransportParameterSpace,
        integer::{MaxAckDelay, MaxUdpPayloadSize},
    },
};

use super::{
    Choices, CloseCauseOf, CryptoSendBufferOf, EventsOf, OwnZeroRttKeysOf, Side,
    aead_usage::{AeadLimitReachedError, AeadUsage},
    amplification::{AddressValidation, AntiAmplification},
    close::{CloseReasonRecord, LocalCloseCause},
    close_packet::ClosePacket,
    component_events::{
        AmplificationCreditChanged, ClosePacketChanged, CongestionChanged,
        DestinationConnectionIdsChanged, LinkPathRoleChanged, PacketsSent, PmtuConcluded,
    },
    confirmation::HandshakeConfirmation,
    connection_ids::{ConnectionIdsOf, LinkPathResetTokenRegistrar, ResetTokenRegistrarOf},
    crypto::send::CryptoSender,
    datagram_batch::{BatchedDatagram, BatchedPacket, DatagramBatch, UnchargedCongestion},
    ecn::LinkPathEcnState,
    error::{ConnectionError, V1ConnectionErrorOf},
    events::{
        ConnectionEventSink, ConnectionEvents, EventInitiator, KeyChange, PacketEvents,
        PlainPacket, SealObserver,
    },
    feedback::LineageFeedback,
    idle::IdleTimeout,
    key_phase::KeyPhaseNumbers,
    key_update::prepare_one_rtt_packets,
    keys::{DirectionKeys, HandshakeKeys, InitialKeys, OneRttKeys},
    largest_probe_timeout,
    link::{LinkClone, LinkFacts},
    parameters::PeerTransportParameters,
    path_validation::PathValidationOf,
    pmtu_probe::PendingPmtuProbe,
    receive::v1_error,
    recovery::{
        CongestionPartOf, LinkPathCongestionState, OthersOf, PmtuOf, RecoveryFactoryOf, RttOf,
        lend_congestion, max_datagram_size_in_use, peer_max_udp_payload_size, refill,
    },
    send::{FrameSourceId, PendingProbePings, SendTypes},
    send_planning::{
        ComponentPublishing, CongestionAllowance, HostSendStrategyTypes, LinkPathPlannerOf,
        LinkPathSendPlannerOf, PublisherOf, SendKeyLevels, SendStrategyCore, SendStrategyOf,
        SendStrategyPublisher, datagram_limits, link_path_packet_overheads,
    },
    spaces::{DEFAULT_MAX_ACK_DELAY, SendJournalsOf, peer_max_ack_delay},
    streams::send::StreamIntent,
    zero_rtt_rejection::ZeroRttRejection,
};
use crate::v1::StreamSetFamilyOf;
use crate::v1::{HostChoices, HostOf, SendParametersOf};
use crate::{
    call::{CallBundle, CallKind, NodeCallFamily, NodeLoan},
    clock::{InstantOf, LinkIdOf},
    component::{ArgsOf, LineageOf},
    component_event::{EventSubscriptions, Happened, NodeStarted},
    connection_id::{OfferedConnectionId, datagram::DatagramConnectionId},
    error::ConnectionErrorsOf,
    feedback::{FeedbackSummariesOf, FeedbackSummaryOf, InjectSummary},
    frame_source::{
        DriverContentOf, EstablishedSourceComponentsOf, EstablishedSourceComponentsOfParts,
        HandshakePacket, InitialPacket, OneRttPacket, OneRttProbePacket, PacketKind,
        PartsFrameSourceDispatch, PartsFrameSources, SettlingProbePacket, ZeroRttPacket,
    },
    layer::{self, LinkPath, NodeKey},
    others::OtherNodes,
    role::LinkPathRole,
    send_strategy::{
        CloseResendFacts, DatagramFillPlan, DatagramLimits, FrameSourceCursor, FrameSourceSet,
        LeadingContent, LinkPathRoleKind, LinkPathSendPlanner, Observe, PacketOverheads,
        PlannedDatagram, PlannedPacket, PlannedPacketKind, SendIntentsOf, SendStrategyTypes,
    },
    share::{FlatMut, FlatRef, LineageLists, LineagePartList, LinkPathIdentifierOf, NodeData},
    take::{
        AppendEach, GetAt, Lineage, OptionalRefs, ReadEach, Reborrow, Take, TakeEach, WithOptionals,
    },
    write::{ClassOfSource, Last, NotLast, OpenPacket, PacketWriting, PaddingSummary, Supplied},
};

/// The limits of the sending call of every link path of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkPathSendingLimits {
    /// How many datagrams the call fills before it hands them to the link
    /// at once: as many as one call of [`Link::send`] takes well, such as
    /// the segments of one generic segmentation offload, or one.
    pub max_datagrams_per_send: NonZeroUsize,
}

/// Whether a link has accepted a datagram of the connection: whether the
/// peer can know of the connection.
///
/// The sending calls note the first datagram a link accepts; it is the last
/// boundary this side sees, not that the datagram went out. A client that
/// closes before any was accepted ends with nothing sent
/// ([`close_request`](super::close_request)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramAcceptance {
    /// No link has accepted a datagram of the connection yet.
    NoneAccepted,
    /// A link has accepted a datagram of the connection.
    Accepted,
}

/// The sealed packet of the send journals of the choices `T` and the list
/// of parts `L`.
pub type SealedPacketOf<T, L> = <<HostOf<T> as HostChoices<T>>::SendJournals<
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
/// core and planner, the registrar of the link path's reset tokens, the
/// send journals, the count of the AEAD's usage, the recovery factory and
/// the anti-amplification limit of the logical link.
///
/// The logical path's [`ConnectionIds`](super::connection_ids::ConnectionIds)
/// stay in what is left, where frame sources find them too: filling reads
/// them at the start of each datagram and tells the destination connection
/// ID strategy of a use once a datagram is sealed with content.
pub type FillTakes<T, L> = HList![
    SendStrategyCore<SendStrategyOf<T, L>>,
    LinkPathPlannerOf<T, L>,
    LinkPathResetTokenRegistrar<ResetTokenRegistrarOf<T>>,
    SendJournalsOf<T, L>,
    AeadUsage,
    RecoveryFactoryOf<T, L>,
    AntiAmplification,
    ConnectionEventSink<EventsOf<T, L>>,
];

/// What sending the close packet again takes out of the link path's
/// lineage: the send strategy's core and planner, and the
/// anti-amplification limit of the logical link.
pub type ResendTakes<T, L> = HList![
    SendStrategyCore<SendStrategyOf<T, L>>,
    SendStrategyPublisher<PublisherOf<T, L>>,
    LinkPathPlannerOf<T, L>,
    AntiAmplification,
];

/// What filling takes out of what is left to read only: the keys of each
/// level, which packets are sealed with while the frame sources write.
pub type FillReadTakes<T> = HList![
    InitialKeys<<T as crate::v1::MakerChoices>::Crypto>,
    HandshakeKeys<<T as crate::v1::MakerChoices>::Crypto>,
    OwnZeroRttKeysOf<T>,
    OneRttKeys<<T as crate::v1::MakerChoices>::Crypto, InstantOf<T>>,
];

/// What is left of the link path's lineage once filling took
/// [`FillTakes`]: what the keys are taken from to read.
pub type FillKeysRest<'x, T, L, It> =
    <<L as LineageLists<'x, T>>::LinkPath as TakeEach<'x, FillTakes<T, L>, It>>::Rest;

/// What is left of the link path's lineage once filling took
/// [`FillTakes`] and [`FillReadTakes`].
pub type FillRest<'x, T, L, It, Iw> =
    <FillKeysRest<'x, T, L, It> as TakeEach<'x, FillReadTakes<T>, Iw>>::Rest;

/// What is left of the link path's lineage once filling took
/// [`FillTakes`] and [`FillReadTakes`], with the components of the
/// established layer the frame sources find there appended
/// ([`EstablishedSourceComponentsOfParts`]), each `None` while there is no
/// such layer: where the frame sources are found.
pub type FillStreamsRest<'x, T, L, It, Iw> =
    WithOptionals<'x, FillRest<'x, T, L, It, Iw>, EstablishedSourceComponentsOfParts<T, L>>;

/// What filling reads from what is left of the lineage at the start of
/// each datagram: the link's clone and facts, the peer's transport
/// parameters, the packet number states of the spaces, the data only this
/// side has, which gives the token of its Initial packets, whether the
/// handshake is confirmed, and the link path's role.
pub type FillReads<T, L> = HList![
    LinkClone<<T as crate::clock::ConnectionChoices>::Link>,
    LinkFacts,
    PeerTransportParameters<TransportParameterSlots<L>>,
    PacketNumberSpaces<PacketNumberSpaceState>,
    <<T as crate::v1::MakerChoices>::Side as Side>::Own,
    HandshakeConfirmation,
    LinkPathRole<InstantOf<T>>,
];

/// What filling takes from the link path's recovery layer: the stored part
/// of congestion control, the fixed state beside it, the datagram size
/// probing policy, which sees the start of each datagram, and the ECN
/// state, which gives each datagram its marking.
pub type FillRecoveryTakes<T, L> = HList![
    CongestionPartOf<T, L>,
    LinkPathCongestionState<InstantOf<T>>,
    PmtuOf<T, L>,
    LinkPathEcnState<InstantOf<T>>,
];

/// What settling takes from the link path's recovery layer, with the loss
/// detection states of the controller's `S` and `Ls`.
pub type SettleRecoveryTakes<T, L, S, Ls> = HList![
    CongestionPartOf<T, L>,
    LinkPathCongestionState<InstantOf<T>>,
    PacketNumberSpaces<LossDetectionState<InstantOf<T>, S, Ls>>,
    PmtuOf<T, L>,
    LinkPathEcnState<InstantOf<T>>,
];

/// What settling reads from the link path's lineage: the link's clone, the
/// thresholds of loss detection and the peer's transport parameters.
pub type SettleReads<T, L> = HList![
    LinkClone<<T as crate::clock::ConnectionChoices>::Link>,
    LossThresholds,
    PeerTransportParameters<TransportParameterSlots<L>>,
    ZeroRttRejection,
];

/// The positions the sending call takes by, grouped as the steps use them:
/// `Is` of its limits; for filling, `It` of [`FillTakes`], `Iw` of
/// [`FillReadTakes`], `Ir` of [`FillReads`] and `Ici` of the connection IDs
/// in what is left, `Ik` of
/// [`FillRecoveryTakes`], `Hs` of
/// each part's frame sources, `Hd` of what each part reads the driver's
/// content by ([`DriverContentOf`]), `Ipd` of PADDING's summary in the sum of summaries, `Ipm` of
/// the link path's [`PendingPmtuProbe`] in what is left, `Ipb` of its
/// [`PendingProbePings`] and `Ics` of the connection's [`CryptoSender`]
/// there, and `Ifs` of
/// version 1's frame sources among the composition's; for handing over, `Ii`, `Ih`, `Io` of the
/// keys and `Il` of the link's clone; for settling, `Ij` of the send
/// journals, `If` of the recovery factory, `Iv` of [`SettleReads`], `Ie`
/// of the idle timeout, `Iq` of [`SettleRecoveryTakes`], `Hf` of
/// each part's frame sources, for feedback, and `Ist` of the
/// components of the established layer the frame sources find
/// ([`EstablishedSourceComponentsOfParts`]), which filling and feedback borrow, and `In` of the
/// packet number states, which count the marked packets sent; `Ipp` and `Ima` of
/// the peer's `max_udp_payload_size` and `max_ack_delay`; `Jx`, `Jr`, `Jm` and `Je` of the stored part of
/// congestion control, the RTT estimate, the datagram size probing
/// policy and the ECN state in a recovery layer; for 1-RTT key updates, `Iu` of the AEAD's
/// usage, `Ihc` of whether the handshake is confirmed, `Ikp` of the key
/// phase numbers, `Ic` of the record of why the connection closed, `Ier`
/// of version 1's connection error among the composition's, `Irt` of the
/// RTT estimator in a recovery layer; for the close packet, `Icp` of it,
/// `Irs` of [`ResendTakes`] and `Ilf` of the logical link's facts; `Ida`
/// of whether a link has accepted a datagram of the connection; `Idr` of
/// the link path's role, which the kind reads to drop the call; `Iva` of
/// the link path's path validation, whose challenges count as sent when
/// the link accepted them.
type Positions<
    Is,
    It,
    Iw,
    Ir,
    Ici,
    Ik,
    Hs,
    Hd,
    Ipd,
    Ipm,
    Ipb,
    Ipr,
    Ics,
    Ipv,
    Ifs,
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
    Ist,
    In,
    Ipp,
    Ima,
    Jx,
    Jr,
    Jm,
    Je,
    Iu,
    Ihc,
    Ikp,
    Ic,
    Ier,
    Irt,
    Icp,
    Irs,
    Ilf,
    Ida,
    Idr,
    Iva,
> = (
    Is,
    (
        It,
        Iw,
        Ir,
        Ici,
        Ik,
        Hs,
        Hd,
        Ipd,
        (Ipm, Ipv),
        (Ipb, Ipr),
        Ics,
        Ifs,
    ),
    (Ii, Ih, Io, Il),
    (Ij, If, Iv, Ie, Iq, Hf, Ist, In),
    (Ipp, Ima, Jx, Jr, Jm, Je),
    (Iu, Ihc, Ikp, Ic, Ier, Irt),
    (Icp, Irs, Ilf, Ida, Idr, Iva),
);

/// The most datagrams one poll fills again because the content planned for
/// them left them empty. A frame source that writes nothing for an item
/// has updated or withdrawn its intent already, so each empty datagram
/// takes planned content away and the filling settles; past the bound a
/// source broke that contract, and the filling ends.
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
    /// The content planned left [`EMPTY_DATAGRAMS_PER_POLL`] datagrams
    /// empty in this poll: a frame source wrote nothing for its item and
    /// left its intent as it was. The call does not wake itself for it.
    LeftEmpty,
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
    Ici,
    Ik,
    Hs,
    Hd,
    Ipd,
    Ipm,
    Ipb,
    Ipr,
    Ics,
    Ipv,
    Ifs,
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
    Ist,
    In,
    Ipp,
    Ima,
    Jx,
    Jr,
    Jm,
    Je,
    Iu,
    Ihc,
    Ikp,
    Ic,
    Ier,
    Irt,
    Icp,
    Irs,
    Ilf,
    Ida,
    Idr,
    Iva,
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
            Ici,
            Ik,
            Hs,
            Hd,
            Ipd,
            Ipm,
            Ipb,
            Ipr,
            Ics,
            Ipv,
            Ifs,
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
            Ist,
            In,
            Ipp,
            Ima,
            Jx,
            Jr,
            Jm,
            Je,
            Iu,
            Ihc,
            Ikp,
            Ic,
            Ier,
            Irt,
            Icp,
            Irs,
            Ilf,
            Ida,
            Idr,
            Iva,
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
    PartsFrameSources<SettlingProbePacket, L>: FrameSourceSet,
    FeedbackSummaryOf<T, L>: InjectSummary<PaddingSummary, Ipd>,
    SendTypes<T, L>: SendStrategyTypes<
            LinkPathIdentifier = LinkPathIdentifierOf<T, L>,
            InitialFrameSources = PartsFrameSources<InitialPacket, L>,
            HandshakeFrameSources = PartsFrameSources<HandshakePacket, L>,
            ZeroRttFrameSources = PartsFrameSources<ZeroRttPacket, L>,
            OneRttFrameSources = PartsFrameSources<OneRttPacket, L>,
            ProbeFrameSources = PartsFrameSources<OneRttProbePacket, L>,
            SettlingFrameSources = PartsFrameSources<SettlingProbePacket, L>,
        >,
    SendTypes<T, L>: HostSendStrategyTypes,
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
    EventsOf<T, L>: PacketEvents<InstantOf<T>, L>,
    for<'x> <L as LineageLists<'x, T>>::LinkPath: GetAt<LinkPathSendingLimits, Is>
        + TakeEach<'x, FillTakes<T, L>, It>
        + GetAt<InitialKeys<T::Crypto>, Ii>
        + GetAt<HandshakeKeys<T::Crypto>, Ih>
        + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>
        + GetAt<LinkClone<T::Link>, Il>
        + GetAt<SendJournalsOf<T, L>, Ij>
        + GetAt<PacketNumberSpaces<PacketNumberSpaceState>, In>
        + GetAt<RecoveryFactoryOf<T, L>, If>
        + ReadEach<SettleReads<T, L>, Iv>
        + GetAt<IdleTimeout<InstantOf<T>>, Ie>
        + GetAt<AeadUsage, Iu>
        + GetAt<HandshakeConfirmation, Ihc>
        + GetAt<KeyPhaseNumbers, Ikp>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>
        + GetAt<ClosePacket, Icp>
        + GetAt<LinkFacts, Ilf>
        + GetAt<DatagramAcceptance, Ida>
        + TakeEach<'x, ResendTakes<T, L>, Irs>
        + GetAt<LinkPathRole<InstantOf<T>>, Idr>
        + GetAt<PathValidationOf<T>, Iva>,
    L: ConnectionErrorsOf,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<V1ConnectionErrorOf<L>, Ier>,
    for<'x> FillKeysRest<'x, T, L, It>: TakeEach<'x, FillReadTakes<T>, Iw>,
    for<'x> FillRest<'x, T, L, It, Iw>:
        AppendEach<<EstablishedSourceComponentsOfParts<T, L> as OptionalRefs>::Optional<'x>>,
    for<'x> FillStreamsRest<'x, T, L, It, Iw>: ReadEach<FillReads<T, L>, Ir>
        + GetAt<ConnectionIdsOf<T>, Ici>
        + GetAt<PendingPmtuProbe, Ipm>
        + GetAt<PendingProbePings, Ipb>
        + GetAt<SendStrategyPublisher<PublisherOf<T, L>>, Ipr>
        + GetAt<CryptoSender<CryptoSendBufferOf<T>>, Ics>
        + GetAt<PathValidationOf<T>, Ipv>,
    <SendTypes<T, L> as SendStrategyTypes>::FrameSourceId:
        CoprodInjector<FrameSourceId, Ifs> + PartialEq,
    <PartsFrameSources<OneRttPacket, L> as FrameSourceSet>::FrameSourceId:
        CoprodInjector<FrameSourceId, Ifs> + PartialEq,
    for<'x> L: DriverContentOf<T, L, FillStreamsRest<'x, T, L, It, Iw>, Hd>,
    <SendTypes<T, L> as SendStrategyTypes>::SendIntents: From<<L as SendIntentsOf>::SendIntents>,
    for<'x> L: PartsFrameSourceDispatch<
            T,
            L,
            InitialPacket,
            FillStreamsRest<'x, T, L, It, Iw>,
            FeedbackSummaryOf<T, L>,
            Hs,
        > + PartsFrameSourceDispatch<
            T,
            L,
            HandshakePacket,
            FillStreamsRest<'x, T, L, It, Iw>,
            FeedbackSummaryOf<T, L>,
            Hs,
        > + PartsFrameSourceDispatch<
            T,
            L,
            ZeroRttPacket,
            FillStreamsRest<'x, T, L, It, Iw>,
            FeedbackSummaryOf<T, L>,
            Hs,
        > + PartsFrameSourceDispatch<
            T,
            L,
            OneRttPacket,
            FillStreamsRest<'x, T, L, It, Iw>,
            FeedbackSummaryOf<T, L>,
            Hs,
        > + PartsFrameSourceDispatch<
            T,
            L,
            OneRttProbePacket,
            FillStreamsRest<'x, T, L, It, Iw>,
            FeedbackSummaryOf<T, L>,
            Hs,
        > + PartsFrameSourceDispatch<
            T,
            L,
            SettlingProbePacket,
            FillStreamsRest<'x, T, L, It, Iw>,
            FeedbackSummaryOf<T, L>,
            Hs,
        >,
    for<'x> <L as LineageLists<'x, T>>::LinkPath:
        LineageFeedback<T, L, EstablishedSourceComponentsOfParts<T, L>, Hf>,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
    L: EstablishedSourceComponentsOf<T, L>,
    for<'s> NodeData<T, L, layer::Established>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Established> as FlatMut<'s>>::Out:
        TakeEach<'s, EstablishedSourceComponentsOfParts<T, L>, Ist>,
    for<'x> NodeData<T, L, layer::Recovery>: FlatMut<'x>,
    for<'x> <NodeData<T, L, layer::Recovery> as FlatMut<'x>>::Out: TakeEach<'x, FillRecoveryTakes<T, L>, Ik>
        + TakeEach<'x, SettleRecoveryTakes<T, L, S, Ls>, Iq>
        + GetAt<RttOf<T, L>, Irt>,
    for<'a> NodeData<T, L, layer::Recovery>: FlatRef<'a>,
    for<'a> <NodeData<T, L, layer::Recovery> as FlatRef<'a>>::Out: Selector<&'a CongestionPartOf<T, L>, Jx>
        + Selector<&'a RttOf<T, L>, Jr>
        + Selector<&'a PmtuOf<T, L>, Jm>
        + Selector<&'a LinkPathEcnState<InstantOf<T>>, Je>,
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
        if let Some((datagram, facts)) = lineage.get::<ClosePacket, Icp>().sealed().map(|sealed| {
            (
                sealed.datagram().clone(),
                CloseResendFacts {
                    datagrams_received: sealed.datagrams_received(),
                },
            )
        }) {
            return resend_close::<T, L, S, Ilf, Irs>(lineage, datagram, facts, batch, cx);
        }
        let NodeKey::LinkPath(path, link) = others.here().clone() else {
            unreachable!("a link path's lend carries its key")
        };
        let link_path = L::link_path_identifier(&path, &link);
        let now = others.now();
        // what the layer only reads is read without taking it
        let read = others.recovery_ref().map(|flat| {
            let rtt: &&RttOf<T, L> = Selector::<_, Jr>::get(&flat);
            rtt.estimate()
        });
        // woken when the layer is built
        let no_layer = if batch.is_empty() {
            Poll::Pending
        } else {
            Poll::Ready(())
        };
        // a candidate without a recovery layer still sends its probes,
        // charged to no congestion control
        let uncharged = read.is_none()
            && lineage.get::<LinkPathRole<InstantOf<T>>, Idr>().kind()
                == LinkPathRoleKind::Candidate;
        if read.is_none() && !uncharged {
            return no_layer;
        }
        // what the ECN state is told at the start of each datagram besides:
        // the probe timeout without backoff, and whether another link path
        // of the logical path has marked packets outstanding
        let pto = {
            let hlist_pat![_, thresholds, peer, _] =
                Lineage::read_each::<SettleReads<T, L>, Iv>(&*lineage);
            let peer_max_ack_delay =
                peer_max_ack_delay::<L, Ima>(peer).unwrap_or(DEFAULT_MAX_ACK_DELAY);
            let estimate = read.unwrap_or_else(|| RttEstimate::initial(INITIAL_RTT));
            probe_timeout(
                &estimate,
                thresholds.granularity(),
                PacketNumberSpaceKind::ApplicationData,
                peer_max_ack_delay,
                0,
            )
        };
        let mut hold = false;
        others.each_recovery(|key, data| {
            if let NodeKey::Recovery(of, other) = key
                && *of == path
                && *other != link
            {
                let flat = data.flat_ref();
                let ecn: &&LinkPathEcnState<InstantOf<T>> = Selector::<_, Je>::get(&flat);
                hold |= ecn.marked_outstanding() > 0;
            }
        });
        let prepared =
            prepare_key_update::<T, L, B, Ij, Iv, Ima, Io, Iu, Ihc, Ikp, Irt>(lineage, others, now);
        if let Ok(Some(generation)) = prepared
            && <EventsOf<T, L> as ConnectionEvents<InstantOf<T>>>::ENABLED
        {
            let (hlist_pat![_, _, _, _, _, _, _, mut events], _) =
                Take::<FillTakes<T, L>, It>::take(lineage.reborrow());
            if let Some(events) = events.active::<InstantOf<T>>() {
                // only the sending half moves; the receiving half follows
                // once the peer answers (RFC 9001 §6.1)
                let own = <T::Side as Side>::ROLE;
                let key = KeyChange::updated(own, generation, EventInitiator::Local);
                events.key_updated(now, key);
            }
        }
        if let Err(source) = prepared {
            if !lineage
                .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
                .is_written()
            {
                let error = v1_error::<L, Ier>(ConnectionError::AeadLimitReached { source });
                let written = lineage
                    .get_mut::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
                    .record(CloseReason::Local(Arc::new(LocalCloseCause::Connection(
                        error,
                    ))));
                if let Some(written) = written {
                    lineage.publish(written);
                }
            }
            // what the batch holds still goes; the close is the closing
            // packet's to send
            return if batch.is_empty() {
                Poll::Pending
            } else {
                Poll::Ready(())
            };
        }
        // the frame sources find the components of the established layer
        // appended to what is left of the lineage; the layer is recorded as
        // taken, and the positions recorded past the lineage's components
        // are ignored
        let filled = others.with_established::<EstablishedSourceComponentsOfParts<T, L>, Ist, _>(
            |established, others| {
                let mut established =
                    EstablishedSourceComponentsOfParts::<T, L>::spread(established);
                let (
                    hlist_pat![
                        mut core,
                        mut planner,
                        mut registrar,
                        mut journals,
                        mut usage,
                        mut factory,
                        mut amplification,
                        mut events
                    ],
                    rest,
                ) = Take::<FillTakes<T, L>, It>::take(lineage.reborrow());
                let (hlist_pat![initial_keys, handshake_keys, zero_rtt_keys, one_rtt_keys], rest) =
                    rest.take_read::<FillReadTakes<T>, Iw>();
                let mut rest = rest.append_optionals::<EstablishedSourceComponentsOfParts<T, L>>(
                    EstablishedSourceComponentsOfParts::<T, L>::reborrow(&mut established),
                );
                // a filling of this poll, with the link path's congestion
                // access, RTT estimate, probing policy and fixed state
                macro_rules! filling {
                    ($access:expr, $estimate:expr, $pmtu:expr, $state:expr, $ecn:expr, $charged:expr) => {
                        Filling::<T, L, _, _, Ir, Ici, Ipp, Hs, Hd, Ipd, Ipm, Ipb, Ipr, Ics, Ipv, Ifs> {
                            now,
                            link: &link,
                            link_path: &link_path,
                            core: &mut *core,
                            planner: &mut *planner,
                            registrar: &mut *registrar,
                            journals: &mut *journals,
                            initial_keys,
                            handshake_keys,
                            zero_rtt_keys,
                            one_rtt_keys,
                            initial_discarded: false,
                            usage: &mut usage,
                            amplification: &mut amplification,
                            events: &mut *events,
                            rest: &mut rest,
                            access: $access,
                            estimate: $estimate,
                            pmtu: $pmtu,
                            pmtu_concluded: false,
                            congestion_changed: false,
                            state: $state,
                            ecn: $ecn,
                            hold,
                            pto,
                            charged: $charged,
                            positions: core::marker::PhantomData,
                        }
                    };
                }
                match read {
                    Some(estimate) => others.with_own_recovery::<FillRecoveryTakes<T, L>, Ik, _>(
                        |hlist_pat![mut part, mut state, mut pmtu, mut ecn], others| {
                            lend_congestion::<T, L, B, Jx, Jr, _>(
                                &mut *factory,
                                &mut *part,
                                others,
                                |mut access| {
                                    filling!(
                                        &mut access,
                                        estimate,
                                        Some(&mut *pmtu),
                                        &mut *state,
                                        Some(&mut *ecn),
                                        true
                                    )
                                    .fill_round(batch, cx)
                                },
                            )
                        },
                    ),
                    None => {
                        let mut state = LinkPathCongestionState::new();
                        let mut access = UnchargedCongestion::<S>::new();
                        Some(
                            filling!(
                                &mut access,
                                RttEstimate::initial(INITIAL_RTT),
                                None,
                                &mut state,
                                None,
                                false
                            )
                            .fill_round(batch, cx),
                        )
                    }
                }
            },
        );
        let Some((initial_discarded, pmtu_concluded, congestion_changed, wake_itself)) = filled
        else {
            return no_layer;
        };
        let recovery = NodeKey::Recovery(path, link);
        if congestion_changed && !uncharged {
            others.publish_at(&recovery, Happened::<CongestionChanged>::new());
        }
        if pmtu_concluded {
            others.publish_at(&recovery, Happened::<PmtuConcluded>::new());
        }
        if initial_discarded {
            // the first Handshake packet sent (RFC 9001 §4.9.1)
            let discarded = lineage.get_mut::<InitialKeys<T::Crypto>, Ii>().discard();
            if let Some(discarded) = discarded {
                lineage.publish(discarded);
            }
            if <EventsOf<T, L> as ConnectionEvents<InstantOf<T>>>::ENABLED {
                let (hlist_pat![_, _, _, _, _, _, _, mut events], _) =
                    Take::<FillTakes<T, L>, It>::take(lineage.reborrow());
                if let Some(events) = events.active::<InstantOf<T>>() {
                    for sender in [Role::Client, Role::Server] {
                        let level = sakuya_wire_v1::encryption_level::EncryptionLevel::Initial;
                        events.key_discarded(now, KeyChange::new(level, sender));
                    }
                }
            }
        }
        if !batch.is_empty() {
            return Poll::Ready(());
        }
        if wake_itself {
            // blocked: what this lend published is handled before the
            // next plan
            cx.waker().wake_by_ref();
        }
        Poll::Pending
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
            let zero_rtt = {
                let (_, rest) = Take::<FillTakes<T, L>, It>::take(lineage.reborrow());
                let (hlist_pat![_, _, zero_rtt_keys, _], _) =
                    rest.take_read::<FillReadTakes<T>, Iw>();
                <T::Side as Side>::zero_rtt_send_keys(zero_rtt_keys).is_none()
            };
            // a 0-RTT packet goes no more once the 0-RTT keys are closed:
            // the 1-RTT keys came in this poll (RFC 9001 §4.9.3)
            batch.take_discarded(|datagram| {
                (initial && datagram.initial.is_some() && !datagram.initial_goes_out())
                    || (handshake && datagram.handshake.is_some())
                    || (datagram.application_data.is_some()
                        && if datagram.carries_zero_rtt() {
                            zero_rtt
                        } else {
                            one_rtt
                        })
            })
        };
        if !discarded.as_slice().is_empty() {
            give_up::<T, L, B, S, Ls, Ij, If, Iv, Iq, Hf, Ist, Ipp, Ima, Jx, Jr, Jm>(
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
            Ok(acceptance) => {
                // taken only to note the first
                if *lineage.get::<DatagramAcceptance, Ida>() == DatagramAcceptance::NoneAccepted {
                    *lineage.get_mut::<DatagramAcceptance, Ida>() = DatagramAcceptance::Accepted;
                }
                let rejected = {
                    let hlist_pat![_, _, _, rejection] =
                        Lineage::read_each::<SettleReads<T, L>, Iv>(&*lineage);
                    rejection.is_rejected()
                };
                let retired = accept::<T, L, B, S, Ls, Ij, In, Ie, Iq>(
                    lineage,
                    others,
                    batch.take_accepted(acceptance.count.get()),
                    acceptance.at,
                    rejected,
                );
                // a challenge sealed counts as sent when the link accepted
                // it, which its RTT and its timing count from
                lineage
                    .get_mut::<PathValidationOf<T>, Iva>()
                    .accepted(acceptance.at);
                remove_without_signal::<T, L, B, S, Ls, If, Iv, Iq, Ipp, Jx, Jr, Jm>(
                    lineage, others, retired,
                );
            }
            Err(_) => {
                if let Some(datagram) = batch.take_first() {
                    give_up::<T, L, B, S, Ls, Ij, If, Iv, Iq, Hf, Ist, Ipp, Ima, Jx, Jr, Jm>(
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

/// Gives the connection's events each packet a datagram writer seals, sent
/// at `at`: nothing when they record nothing.
struct PacketSent<'e, X, I, L> {
    sink: &'e mut ConnectionEventSink<X>,
    at: I,
    list: core::marker::PhantomData<fn() -> L>,
}

impl<X, I, L> SealObserver for PacketSent<'_, X, I, L>
where
    X: ConnectionEvents<I> + PacketEvents<I, L>,
    I: Copy,
{
    const ENABLED: bool = X::ENABLED;

    fn sealing(&mut self, packet: &PlainPacket<'_>) {
        if let Some(events) = self.sink.active::<I>() {
            events.packet_sent(self.at, packet);
        }
        self.sink.packet_of_level(self.at, packet.level);
    }
}

/// What [`Filling`] reads its components and finds its frame sources by.
type FillPositions<Ir, Ici, Ipp, Hs, Hd, Ipd, Ipm, Ipb, Ipr, Ics, Ipv, Ifs> =
    core::marker::PhantomData<fn() -> (Ir, Ici, Ipp, Hs, Hd, Ipd, Ipm, Ipb, Ipr, Ics, Ipv, Ifs)>;

/// What one poll fills with: the borrows of what it took, the instant of
/// the poll and the link path it fills for.
///
/// `V` is what is left of the lineage, where the connection IDs and the
/// frame sources are found; `A` the congestion access lent for the poll.
struct Filling<'f, 'r, T, L, V, A, Ir, Ici, Ipp, Hs, Hd, Ipd, Ipm, Ipb, Ipr, Ics, Ipv, Ifs>
where
    T: Choices,
    L: LineagePartList<T> + FeedbackSummariesOf,
    SendTypes<T, L>: HostSendStrategyTypes,
{
    now: InstantOf<T>,
    link: &'f LinkIdOf<T>,
    link_path: &'f LinkPathIdentifierOf<T, L>,
    core: &'f mut SendStrategyCore<SendStrategyOf<T, L>>,
    planner: &'f mut LinkPathPlannerOf<T, L>,
    registrar: &'f mut LinkPathResetTokenRegistrar<ResetTokenRegistrarOf<T>>,
    journals: &'f mut SendJournalsOf<T, L>,
    initial_keys: &'f InitialKeys<T::Crypto>,
    handshake_keys: &'f HandshakeKeys<T::Crypto>,
    /// A client's 0-RTT keys; a server's receive only.
    zero_rtt_keys: &'f OwnZeroRttKeysOf<T>,
    one_rtt_keys: &'f OneRttKeys<T::Crypto, InstantOf<T>>,
    /// Whether this side discarded its Initial keys in this poll: they are
    /// discarded once the filling is over, and none is used before.
    initial_discarded: bool,
    usage: &'f mut AeadUsage,
    amplification: &'f mut AntiAmplification,
    /// Sees each packet just before it is sealed.
    events: &'f mut ConnectionEventSink<EventsOf<T, L>>,
    rest: &'f mut Lineage<'r, V>,
    access: &'f mut A,
    estimate: RttEstimate,
    /// Sees the start of each datagram, and gives the size it is sent at;
    /// `None` without a recovery layer, which sends at 1200 bytes.
    pmtu: Option<&'f mut PmtuOf<T, L>>,
    /// Whether the probing policy reported that its conclusion changed, to
    /// be published once the filling is over.
    pmtu_concluded: bool,
    /// Whether what congestion control allows changed: pacing was refilled
    /// with a change, the controller heard of a new datagram size, or a
    /// datagram was sealed and charged; published once the filling is
    /// over.
    congestion_changed: bool,
    state: &'f mut LinkPathCongestionState<InstantOf<T>>,
    /// Gives each datagram its marking, and counts the marked ones sealed;
    /// `None` without a recovery layer, whose datagrams are Not-ECT.
    ecn: Option<&'f mut LinkPathEcnState<InstantOf<T>>>,
    /// Whether another link path of the logical path has marked packets
    /// outstanding: this one holds.
    hold: bool,
    /// The link path's probe timeout without backoff, for the ECN test.
    pto: Duration,
    /// Whether the datagrams are charged to congestion control: those of a
    /// candidate without a recovery layer are not.
    charged: bool,
    positions: FillPositions<Ir, Ici, Ipp, Hs, Hd, Ipd, Ipm, Ipb, Ipr, Ics, Ipv, Ifs>,
}

impl<T, L, V, A, S, Ir, Ici, Ipp, Hs, Hd, Ipd, Ipm, Ipb, Ipr, Ics, Ipv, Ifs>
    Filling<'_, '_, T, L, V, A, Ir, Ici, Ipp, Hs, Hd, Ipd, Ipm, Ipb, Ipr, Ics, Ipv, Ifs>
where
    T: Choices,
    L: LineagePartList<T> + FeedbackSummariesOf + ParametersOf<TransportParameterSpace>,
    PartsFrameSources<InitialPacket, L>: FrameSourceSet,
    PartsFrameSources<HandshakePacket, L>: FrameSourceSet,
    PartsFrameSources<ZeroRttPacket, L>: FrameSourceSet,
    PartsFrameSources<OneRttPacket, L>: FrameSourceSet,
    PartsFrameSources<OneRttProbePacket, L>: FrameSourceSet,
    PartsFrameSources<SettlingProbePacket, L>: FrameSourceSet,
    FeedbackSummaryOf<T, L>: InjectSummary<PaddingSummary, Ipd>,
    SendTypes<T, L>: SendStrategyTypes<
            LinkPathIdentifier = LinkPathIdentifierOf<T, L>,
            InitialFrameSources = PartsFrameSources<InitialPacket, L>,
            HandshakeFrameSources = PartsFrameSources<HandshakePacket, L>,
            ZeroRttFrameSources = PartsFrameSources<ZeroRttPacket, L>,
            OneRttFrameSources = PartsFrameSources<OneRttPacket, L>,
            ProbeFrameSources = PartsFrameSources<OneRttProbePacket, L>,
            SettlingFrameSources = PartsFrameSources<SettlingProbePacket, L>,
        >,
    SendTypes<T, L>: HostSendStrategyTypes,
    LinkPathSendPlannerOf<T, L>: Observe<DatagramLimits> + Observe<PacketOverheads>,
    A: CongestionController<InstantOf<T>, SentState = S>
        + Pacer<InstantOf<T>>
        + EcnPolicy<InstantOf<T>>,
    TransportParameterSlots<L>: Selector<Option<MaxUdpPayloadSize>, Ipp>,
    V: ReadEach<FillReads<T, L>, Ir>
        + GetAt<ConnectionIdsOf<T>, Ici>
        + GetAt<PendingPmtuProbe, Ipm>
        + GetAt<PendingProbePings, Ipb>
        + GetAt<SendStrategyPublisher<PublisherOf<T, L>>, Ipr>
        + GetAt<CryptoSender<CryptoSendBufferOf<T>>, Ics>
        + GetAt<PathValidationOf<T>, Ipv>,
    <SendTypes<T, L> as SendStrategyTypes>::FrameSourceId:
        CoprodInjector<FrameSourceId, Ifs> + PartialEq,
    <PartsFrameSources<OneRttPacket, L> as FrameSourceSet>::FrameSourceId:
        CoprodInjector<FrameSourceId, Ifs> + PartialEq,
    L: PartsFrameSourceDispatch<T, L, InitialPacket, V, FeedbackSummaryOf<T, L>, Hs>
        + PartsFrameSourceDispatch<T, L, HandshakePacket, V, FeedbackSummaryOf<T, L>, Hs>
        + PartsFrameSourceDispatch<T, L, ZeroRttPacket, V, FeedbackSummaryOf<T, L>, Hs>
        + PartsFrameSourceDispatch<T, L, OneRttPacket, V, FeedbackSummaryOf<T, L>, Hs>
        + PartsFrameSourceDispatch<T, L, OneRttProbePacket, V, FeedbackSummaryOf<T, L>, Hs>
        + PartsFrameSourceDispatch<T, L, SettlingProbePacket, V, FeedbackSummaryOf<T, L>, Hs>
        + DriverContentOf<T, L, V, Hd>,
    <SendTypes<T, L> as SendStrategyTypes>::SendIntents: From<<L as SendIntentsOf>::SendIntents>,
    EventsOf<T, L>: PacketEvents<InstantOf<T>, L>,
{
    /// Fill datagrams into `batch` as [`fill`](Self::fill) does, and tell the
    /// planner how it ended: whether this side discarded its Initial keys,
    /// the probing policy's conclusion changed, what congestion control
    /// allows changed, and the call is to wake itself.
    fn fill_round(
        &mut self,
        batch: &mut DatagramBatchOf<T, L, S>,
        cx: &mut Context<'_>,
    ) -> (bool, bool, bool, bool) {
        let end = self.fill(batch, cx);
        // what the frame sources published, resized or withdrawn as they
        // wrote may change the plan of a link path
        if let Some(changed) = self
            .rest
            .get_mut::<SendStrategyPublisher<PublisherOf<T, L>>, Ipr>()
            .take_changed()
        {
            self.rest.publish(changed);
        }
        let waits = batch.is_empty() && matches!(end, FillEnd::NothingPlanned | FillEnd::Blocked);
        let wake_itself = self.planner.filling_ended(
            end == FillEnd::Blocked && batch.is_empty(),
            waits,
            cx.waker(),
        );
        (
            self.initial_discarded,
            self.pmtu_concluded,
            self.congestion_changed,
            wake_itself,
        )
    }

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
                if empty >= EMPTY_DATAGRAMS_PER_POLL {
                    return FillEnd::LeftEmpty;
                }
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
        let hlist_pat![
            link,
            facts,
            peer,
            numbers,
            own,
            confirmation,
            link_path_role
        ] = Lineage::read_each::<FillReads<T, L>, Ir>(&*self.rest);
        let initial_token = <T::Side as Side>::initial_token(own);
        let link_ceiling = link.0.max_datagram_size().ok();
        let may_mark_ecn = link.0.may_mark_ecn();
        let peer_max_udp_payload = peer_max_udp_payload_size::<L, Ipp>(peer);
        let validation = facts.validation;
        let numbers = numbers.clone();
        let confirmation = *confirmation;
        let link_path_role = link_path_role.kind();
        // the probing policy sees the start of the datagram with the
        // largest size a probe may try, and then gives its conclusion and
        // the probe to send
        let ceiling =
            datagram_limits(link_ceiling, peer_max_udp_payload, None, None).probe_ceiling();
        let (pmtu_conclusion, wanted) = match self.pmtu.as_deref_mut() {
            Some(pmtu) => {
                self.pmtu_concluded |= pmtu.on_datagram_start(&link.0, ceiling);
                let wanted = PendingPmtuProbe::wanted(
                    link_path_role,
                    confirmation,
                    || {
                        let size = pmtu.probe_size();
                        debug_assert!(
                            size.is_none_or(|size| ceiling.is_some_and(|limit| size <= limit)),
                            "the PMTU policy requested a probe above the datagram ceiling"
                        );
                        size
                    },
                    self.state.pmtu_probe_awaited(),
                );
                (pmtu.conclusion(), wanted)
            }
            // a candidate without a recovery layer probes nothing
            None => (DatagramLimits::MINIMUM, None),
        };
        if self.rest.get::<PendingPmtuProbe, Ipm>().size() != wanted {
            let changed = self.rest.get_mut::<PendingPmtuProbe, Ipm>().set(wanted);
            self.rest.publish(changed);
        }
        // the controller hears of the size in use before the pacer is
        // refilled with its window
        let size = max_datagram_size_in_use(pmtu_conclusion, peer_max_udp_payload, link_ceiling);
        let context = CongestionContext {
            now: self.now,
            bytes_in_flight: self.state.bytes_in_flight(),
            rtt: self.estimate,
            rtt_sampled: false,
            max_datagram_size: size,
        };
        self.congestion_changed |= self.state.on_max_datagram_size(
            &mut *self.access,
            size,
            confirmation == HandshakeConfirmation::Confirmed,
            &context,
        );
        // what the link path can send now, the pacer refilled first: it
        // releases nothing before its first refill
        self.congestion_changed |= refill(&mut *self.access, self.now, &self.estimate, size);
        let limits = datagram_limits(
            link_ceiling,
            peer_max_udp_payload,
            self.amplification.credit(validation),
            Some((
                pmtu_conclusion,
                CongestionAllowance {
                    window_left: self.state.window_left(&*self.access),
                    pacing_allowance: Pacer::allowance(&*self.access),
                    pacing_release_pending: Pacer::next_release(&*self.access).is_some(),
                    probe_permits: self.state.probe_permits(),
                },
            )),
        );
        let max_len = limits.capacity_for(FlightClass::AckOnly);
        let in_flight_room = limits.capacity_for(FlightClass::InFlight);
        // only read, so that the frame sources find them in what is left
        let ids = self.rest.get::<ConnectionIdsOf<T>, Ici>();
        let keys = SendKeyLevels {
            initial: self.initial_send_keys().is_some(),
            handshake: self.handshake_keys.send().is_some(),
            zero_rtt: <T::Side as Side>::zero_rtt_send_keys(self.zero_rtt_keys).is_some(),
            one_rtt: self.one_rtt_keys.send().is_some(),
        };
        let (shortest, mut overheads) = link_path_packet_overheads::<T, L>(
            ids,
            self.link,
            &numbers,
            self.journals,
            keys,
            initial_token.len(),
            max_len,
        );
        self.planner.observe_conditions(limits, overheads);

        // what the driver's components have to send now, gathered afresh:
        // what was written for the last datagram is no longer there
        let (planner, driver) = self.planner.planner_and_driver_content();
        <L as DriverContentOf<T, L, V, Hd>>::pending(
            &*self.rest,
            self.link_path,
            driver,
            From::from,
        );
        // every link path drained: nothing goes again
        let Some(core) = self.core.strategy_mut() else {
            return DatagramEnd::End(FillEnd::NothingPlanned);
        };
        let planned = {
            let mut publisher = self
                .rest
                .get_mut::<SendStrategyPublisher<PublisherOf<T, L>>, Ipr>();
            match planner.poll_plan(core, publisher.publisher_mut(), driver, cx) {
                Poll::Pending => return DatagramEnd::End(FillEnd::NothingPlanned),
                Poll::Ready(planned) => planned,
            }
        };
        // read again once the publisher is let go
        let ids = self.rest.get::<ConnectionIdsOf<T>, Ici>();
        let scid = ids.local();
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
        // a datagram size probe led by its PING is a datagram of exactly
        // its size, the size the link path keeps; it goes only when that
        // size can go now, as the strategy judged
        let probe_source =
            <<SendTypes<T, L> as SendStrategyTypes>::FrameSourceId as CoprodInjector<
                FrameSourceId,
                Ifs,
            >>::inject(FrameSourceId::PmtuProbe);
        let pmtu_probe = if leading.source == probe_source {
            match self.rest.get::<PendingPmtuProbe, Ipm>().size() {
                Some(size) if size <= limits.pmtu_probe_capacity() => Some(size),
                _ => return DatagramEnd::End(FillEnd::Blocked),
            }
        } else {
            None
        };
        let (max_len, in_flight_room) = match pmtu_probe {
            Some(size) => (size, size),
            None => (max_len, in_flight_room),
        };

        // the connection ID: the first offered with which the content
        // planned first fits; where it goes in its packet is not known yet,
        // so it takes its least room, as the last frame, as the planner
        // takes it
        let shortest = shortest.unwrap_or(0);
        let padded = leading.packet == PlannedPacketKind::Initial
            && (overheads.expands_every_initial || leading.class == FlightClass::InFlight);
        let capacity = pmtu_probe.unwrap_or_else(|| limits.capacity_for(leading.class));
        let fits = |offered: &OfferedConnectionId| {
            let overhead = leading_overhead + offered.id.len().saturating_sub(shortest);
            (!padded || in_flight_room >= MIN_DATAGRAM_SIZE)
                && capacity >= overhead + leading.min.as_last
        };
        let Some(chosen) = DatagramConnectionId::<_, _, _, InstantOf<T>>::choose_first(
            ids.destination(),
            self.link,
            fits,
        ) else {
            return DatagramEnd::End(FillEnd::Blocked);
        };
        // a datagram size probe goes within the window: it uses no permit
        let probe = pmtu_probe.is_none()
            && limits.probe_permits > 0
            && limits.congestion_window_left.min(limits.pacing_allowance) < max_len;
        // the marking, asked at the start of the datagram: only an active
        // link path marks, a candidate's probes and a settling link path's
        // packets are Not-ECT
        let marking = match self.ecn.as_deref_mut() {
            Some(ecn) => ecn.marking(
                &mut *self.access,
                may_mark_ecn && link_path_role == LinkPathRoleKind::Active,
                self.hold,
                self.now,
                self.estimate,
                self.pto,
            ),
            None => EcnMarking::NotEct,
        };
        let observer = PacketSent::<_, _, L> {
            sink: &mut *self.events,
            at: self.now,
            list: core::marker::PhantomData,
        };
        let mut datagram = if self.charged {
            batch.start_observed_datagram(
                self.now,
                chosen.connection_id(),
                role,
                scid.length(),
                max_len,
                in_flight_room,
                probe,
                marking,
                &mut *self.state,
                &mut *self.access,
                &mut *self.amplification,
                observer,
            )
        } else {
            batch.start_uncharged_datagram(
                self.now,
                chosen.connection_id(),
                role,
                scid.length(),
                max_len.min(in_flight_room),
                &mut *self.state,
                &mut *self.access,
                &mut *self.amplification,
                observer,
            )
        };
        if let Some(size) = pmtu_probe {
            // its 1-RTT packet is padded to the whole size
            datagram.raise_floor(size);
        }
        // while the probe timeout wants another probe datagram of the
        // Initial or Handshake space after this one, and its policy has
        // the second carry the CRYPTO data again, a packet of the space
        // that carries all of its level's CRYPTO data waiting to be sent
        // leaves that data unsent for the next one too
        let pings = *self.rest.get::<PendingProbePings, Ipb>();
        let repeat_crypto = pings.second() == Some(SecondProbe::RepeatsCrypto);
        let mut repeating = false;
        for (space, level) in [
            (PacketNumberSpaceKind::Initial, CryptoLevel::Initial),
            (PacketNumberSpaceKind::Handshake, CryptoLevel::Handshake),
        ] {
            if repeat_crypto && pings.pending(space) > 1 {
                self.rest
                    .get_mut::<CryptoSender<CryptoSendBufferOf<T>>, Ics>()
                    .repeat_in_packet(level);
                repeating = true;
            }
        }

        // the packets, in the order of the plan
        let largest = |space| {
            numbers
                .get(space)
                .and_then(PacketNumberSpaceState::largest_acked)
        };
        let mut blocked = false;
        let mut skipped = false;
        // only the PING planned first in a datagram size probe is the
        // probe's: a strategy that plans it anywhere else broke its
        // contract
        let mut leading_item = pmtu_probe.is_some();
        let source_id = <<PartsFrameSources<OneRttPacket, L> as FrameSourceSet>::FrameSourceId as CoprodInjector<
                FrameSourceId,
                Ifs,
            >>::inject(FrameSourceId::PmtuProbe);
        let mut check_one_rtt =
            |source: &<PartsFrameSources<OneRttPacket, L> as FrameSourceSet>::FrameSourceId| {
                let allowed = core::mem::replace(&mut leading_item, false);
                assert!(
                    allowed == (*source == source_id),
                    "the send strategy must report a datagram size probe as its leading item and place it first"
                );
                allowed
            };
        // a 1-RTT packet of the kind `$kind`, filled from `$cursor`, its
        // items' frame sources seen by `$check`; the filling of the
        // datagram ends without keys to send it with
        macro_rules! one_rtt_packet {
            ($cursor:ident, $kind:ty, $check:expr) => {{
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
                let Ok(mut writer) = datagram.start_one_rtt_packet(
                    attempt,
                    keys,
                    &mut *self.usage,
                    largest(PacketNumberSpaceKind::ApplicationData),
                ) else {
                    blocked = true;
                    break;
                };
                if pmtu_probe.is_some() {
                    // its loss is no congestion signal (RFC 9000 §14.4)
                    writer.mark_pmtu_probe();
                }
                fill_packet::<T, L, $kind, V, Hs, _, _>(
                    writer.open(),
                    &mut $cursor,
                    self.rest,
                    self.now,
                    $check,
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
            let (supplied, items) = {
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
                            initial_token.clone(),
                        ) else {
                            blocked = true;
                            break;
                        };
                        fill_packet::<T, L, InitialPacket, V, Hs, _, _>(
                            writer.open(),
                            &mut cursor,
                            self.rest,
                            self.now,
                            |_| false,
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
                            |_| false,
                        )
                    }
                    PlannedPacket::ZeroRtt(mut cursor) => {
                        let Some(keys) = <T::Side as Side>::zero_rtt_send_keys(self.zero_rtt_keys)
                        else {
                            blocked = true;
                            break;
                        };
                        let attempt = self
                            .journals
                            .application_data
                            .start_attempt(self.link_path.clone());
                        let Ok(writer) = datagram.start_zero_rtt_packet(
                            attempt,
                            keys,
                            largest(PacketNumberSpaceKind::ApplicationData),
                            scid,
                        ) else {
                            blocked = true;
                            break;
                        };
                        fill_packet::<T, L, ZeroRttPacket, V, Hs, _, _>(
                            writer.open(),
                            &mut cursor,
                            self.rest,
                            self.now,
                            |_| false,
                        )
                    }
                    PlannedPacket::OneRtt(mut cursor) => {
                        one_rtt_packet!(cursor, OneRttPacket, &mut check_one_rtt)
                    }
                    PlannedPacket::OneRttProbe(mut cursor) => {
                        one_rtt_packet!(cursor, OneRttProbePacket, |_| false)
                    }
                    PlannedPacket::SettlingProbe(mut cursor) => {
                        one_rtt_packet!(cursor, SettlingProbePacket, |_| false)
                    }
                }
            };
            skipped |= items.unfit;
            // looking ahead: the packet is the last unless what the plan
            // leads the next one with fits after it, and an item that holds
            // its place and wrote nothing ends the datagram
            let more = !items.held_place
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
        let ack_eliciting =
            PacketNumberSpaceKind::ALL.map(|space| datagram.carries_ack_eliciting(space));
        let packets = PacketNumberSpaceKind::ALL
            .into_iter()
            .filter(|space| datagram.carries(*space))
            .count();
        let sealed = datagram.finish();
        if sealed.is_some()
            && let Some(ecn) = self.ecn.as_deref_mut()
        {
            ecn.on_datagram_sealed(marking, u64::try_from(packets).unwrap_or(u64::MAX));
        }
        drop(plan);
        if repeating {
            self.rest
                .get_mut::<CryptoSender<CryptoSendBufferOf<T>>, Ics>()
                .clear_repeats();
        }
        // a datagram counts as one probe in each space it carries an
        // ack-eliciting packet of, whatever made the packet so
        // (RFC 9002 §6.2.4)
        if sealed.is_some()
            && let Some(changed) = self.rest.get_mut::<PendingProbePings, Ipb>().sealed(
                PacketNumberSpaceKind::ALL
                    .into_iter()
                    .zip(ack_eliciting)
                    .filter_map(|(space, ack_eliciting)| ack_eliciting.then_some(space)),
            )
        {
            self.rest.publish(changed);
        }
        if let (Some(size), Some(_)) = (pmtu_probe, sealed) {
            self.state.on_pmtu_probe_sealed(size);
        }
        if let Some(len) = sealed {
            // a challenge it carries is expanded or not by its size
            self.rest
                .get_mut::<PathValidationOf<T>, Ipv>()
                .datagram_sealed(len);
        }
        // a datagram with content used its connection ID; for one left
        // empty, the choice is dropped and nothing happened
        if let Some(len) = sealed {
            // charged to congestion control and pacing
            self.congestion_changed |= self.charged;
            let changed = chosen.used(
                self.rest
                    .get_mut::<ConnectionIdsOf<T>, Ici>()
                    .destination_mut(),
                self.registrar.registrar_mut(),
                self.link,
                len,
            );
            if changed {
                self.rest
                    .publish(Happened::<DestinationConnectionIdsChanged>::new());
            }
            // the datagram was charged to the anti-amplification limit
            if validation == AddressValidation::NotValidated {
                self.rest
                    .publish(Happened::<AmplificationCreditChanged>::new());
            }
        }
        let sealed = sealed.is_some();
        if blocked || (skipped && !sealed) {
            DatagramEnd::End(FillEnd::Blocked)
        } else {
            DatagramEnd::Next
        }
    }
}

/// Fill `batch` with the sealed close packet `datagram` as often as the
/// planner of the link path of `lineage`, given the close packet's `facts`
/// as the driver's content, asks for it to go again, until the batch is
/// full or the planner has nothing to plan. Each copy is charged to the
/// anti-amplification limit of the logical link before it joins the batch;
/// a copy the credit does not allow is not sent. A copy enters no send
/// journal and counts nothing in flight. Ready once the batch holds a
/// datagram.
///
/// A plan to fill a datagram is dropped as it comes: a closing link path
/// sends nothing else, so the driver's content holds the close packet only.
fn resend_close<'v, T, L, S, Ilf, Irs>(
    lineage: &mut LineageOf<'v, T, L, LinkPath>,
    datagram: Bytes,
    facts: CloseResendFacts,
    batch: &mut DatagramBatchOf<T, L, S>,
    cx: &mut Context<'_>,
) -> Poll<()>
where
    T: Choices,
    L: LineagePartList<T> + FeedbackSummariesOf,
    SendTypes<T, L>: HostSendStrategyTypes,
    for<'w, 's> <L as LineageLists<'w, T>>::LinkPath:
        Reborrow<'s, Out = <L as LineageLists<'s, T>>::LinkPath>,
    for<'x> <L as LineageLists<'x, T>>::LinkPath:
        GetAt<LinkFacts, Ilf> + TakeEach<'x, ResendTakes<T, L>, Irs>,
{
    let validation = lineage.get::<LinkFacts, Ilf>().validation;
    let (hlist_pat![mut core, mut publisher, mut planner, mut amplification], _) =
        Take::<ResendTakes<T, L>, Irs>::take(lineage.reborrow());
    let mut waits = false;
    let mut charged = false;
    let (send_planner, driver) = planner.planner_and_driver_content();
    driver.close = Some(facts);
    while !batch.is_full() {
        let Some(strategy) = core.strategy_mut() else {
            waits = true;
            break;
        };
        match send_planner.poll_plan(strategy, publisher.publisher_mut(), driver, cx) {
            Poll::Pending => {
                waits = true;
                break;
            }
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
                    charged |= validation == AddressValidation::NotValidated;
                }
            }
        }
    }
    planner.filling_ended(false, waits && batch.is_empty(), cx.waker());
    if charged {
        lineage.publish(Happened::<AmplificationCreditChanged>::new());
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
/// acknowledgment is the largest among the link paths, or the one of a new
/// path while none has a recovery layer. The generation a key update
/// initiated now made, if one did.
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
) -> Result<Option<u64>, AeadLimitReachedError>
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
    let hlist_pat![_, thresholds, peer, _] = (*lineage).read_each::<SettleReads<T, L>, Iv>();
    let peer_max_ack_delay = peer_max_ack_delay::<L, Ima>(peer).unwrap_or(DEFAULT_MAX_ACK_DELAY);
    let granularity = thresholds.granularity();
    prepare_one_rtt_packets::<T::Crypto, _, _, _, Io, Iu, Ihc, Ikp>(lineage, next, now, || {
        largest_probe_timeout::<T, L, B, Irt>(peer_max_ack_delay, granularity, others)
            // a candidate fills while no link path has a recovery layer:
            // the probe timeout of a new path
            .unwrap_or_else(|| {
                probe_timeout(
                    &RttEstimate::initial(INITIAL_RTT),
                    granularity,
                    PacketNumberSpaceKind::ApplicationData,
                    peer_max_ack_delay,
                    0,
                )
            })
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

/// How the items of one packet went ([`fill_packet`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct PacketItems {
    /// An item that holds its place wrote nothing: nothing after it goes
    /// into the datagram.
    held_place: bool,
    /// An item was not given to its source because its least room did not
    /// fit.
    unfit: bool,
}

/// Fill the packet `open` of the kind `K` with the items of `cursor`, each
/// given to its frame source among `rest` at `now`; what is left is the
/// packet, last in its datagram until the look-ahead says otherwise, and
/// how its items went.
///
/// An item is the last of the packet when the plan says so, or when what
/// is left takes it as the last frame and no longer with a Length field;
/// it then may close the packet. An item whose least room for its position
/// does not fit is not given to its source: it counts as having written
/// nothing. An item that wrote nothing ends the datagram when it holds its
/// place; one that does not is passed over, and the next goes where it
/// would have, the last position included.
fn fill_packet<T, L, K, V, Hs, C, W>(
    mut open: OpenPacket<W, ClassOfSource, NotLast>,
    cursor: &mut C,
    rest: &mut Lineage<'_, V>,
    now: InstantOf<T>,
    mut requires_leading_probe: impl FnMut(
        &<PartsFrameSources<K, L> as FrameSourceSet>::FrameSourceId,
    ) -> bool,
) -> (Supplied<W, ClassOfSource, Last>, PacketItems)
where
    T: Choices,
    L: LineagePartList<T>
        + FeedbackSummariesOf
        + PartsFrameSourceDispatch<T, L, K, V, FeedbackSummaryOf<T, L>, Hs>,
    K: PacketKind,
    PartsFrameSources<K, L>: FrameSourceSet,
    C: FrameSourceCursor<PartsFrameSources<K, L>>,
    W: PacketWriting,
    W::Attempt: PacketSendAttempt<Summary = FeedbackSummaryOf<T, L>>,
{
    let mut items = PacketItems::default();
    loop {
        let Some(item) = cursor.next() else {
            return (Supplied::Open(open.make_last()), items);
        };
        // If the leading probe writes nothing, neither later content nor
        // padding may be mistaken for a probe of this size.
        let mut probe = requires_leading_probe(&PartsFrameSources::<K, L>::source(item.item()));
        let min = item.min();
        let holds_place = probe || item.holds_place();
        let room = open.room(item.class());
        let last = item.last_in_packet() || (room < min.with_length && room >= min.as_last);
        if !last {
            if room < min.with_length {
                drop(item);
                items.unfit = true;
                if holds_place {
                    items.held_place = true;
                    return (Supplied::Open(open.make_last()), items);
                }
                continue;
            }
            let before = open.buffer_len();
            let supplied = item.supply(open, |item, packet| {
                <L as PartsFrameSourceDispatch<T, L, K, V, FeedbackSummaryOf<T, L>, Hs>>::supply(
                    rest, now, item, packet,
                )
            });
            match supplied {
                Supplied::Open(packet) => {
                    let wrote = packet.buffer_len() > before;
                    open = packet;
                    if !wrote && holds_place {
                        items.held_place = true;
                        return (Supplied::Open(open.make_last()), items);
                    }
                }
                // only a packet in the last position can be closed, so this
                // is not reached; the closed packet is the last all the
                // same
                Supplied::Closed(packet) => return (Supplied::Closed(packet), items),
            }
            continue;
        }
        // the last position: this item, and after it each next one while
        // the one before wrote nothing and did not hold its place
        let mut open = open.make_last();
        let mut item = item;
        loop {
            let min = item.min();
            let holds_place = probe || item.holds_place();
            if open.room(item.class()) >= min.as_last {
                let before = open.buffer_len();
                let supplied = item.supply(open, |item, packet| {
                    <L as PartsFrameSourceDispatch<T, L, K, V, FeedbackSummaryOf<T, L>, Hs>>::supply(
                        rest, now, item, packet,
                    )
                });
                if supplied.buffer_len() > before {
                    return (supplied, items);
                }
                open = match supplied {
                    Supplied::Open(packet) => packet,
                    Supplied::Closed(packet) => return (Supplied::Closed(packet), items),
                };
            } else {
                drop(item);
                items.unfit = true;
            }
            if holds_place {
                items.held_place = true;
                return (Supplied::Open(open), items);
            }
            let Some(next) = cursor.next() else {
                return (Supplied::Open(open), items);
            };
            probe = requires_leading_probe(&PartsFrameSources::<K, L>::source(next.item()));
            item = next;
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
/// and an ack-eliciting one restarts the idle timeout. A marked packet
/// counts in its space as sent with its codepoint, and is outstanding in
/// the ECN state of the recovery layer whose loss detection state it
/// enters. That packets were sent is published at the link path.
///
/// A packet of a space retired since it was sealed, and a 0-RTT packet
/// once the server rejected 0-RTT (`zero_rtt_rejected`), has no record to
/// mark: it is returned, to leave the bytes in flight without a signal,
/// when it counts in flight, and the summaries of its frames go with it.
fn accept<'v, T, L, B, S, Ls, Ij, In, Ie, Iq>(
    lineage: &mut LineageOf<'v, T, L, LinkPath>,
    others: &mut OtherNodes<'v, T, L, B>,
    accepted: impl Iterator<
        Item = BatchedDatagram<SealedPacketOf<T, L>, SealedPacketOf<T, L>, SealedPacketOf<T, L>, S>,
    >,
    at: InstantOf<T>,
    zero_rtt_rejected: bool,
) -> Vec<RemovedPacket<S>>
where
    T: Choices,
    L: LineagePartList<T> + FeedbackSummariesOf,
    B: CallBundle,
    S: 'static,
    Ls: 'static,
    for<'x> <L as LineageLists<'x, T>>::LinkPath: GetAt<SendJournalsOf<T, L>, Ij>
        + GetAt<PacketNumberSpaces<PacketNumberSpaceState>, In>
        + GetAt<IdleTimeout<InstantOf<T>>, Ie>,
    for<'x> NodeData<T, L, layer::Recovery>: FlatMut<'x>,
    for<'x> <NodeData<T, L, layer::Recovery> as FlatMut<'x>>::Out:
        TakeEach<'x, SettleRecoveryTakes<T, L, S, Ls>, Iq>,
{
    let accepted: Vec<_> = accepted.collect();
    let sent = !accepted.is_empty();
    let mut journals = lineage.get_mut::<SendJournalsOf<T, L>, Ij>();
    let mut ack_eliciting = false;
    let mut retired = Vec::new();
    let mut marked_sent = Vec::new();
    let mut mark = Some(
        |mut detections: Option<
            &mut PacketNumberSpaces<LossDetectionState<InstantOf<T>, S, Ls>>,
        >,
         mut ecn: Option<&mut LinkPathEcnState<InstantOf<T>>>| {
            for datagram in accepted {
                let zero_rtt = zero_rtt_rejected && datagram.carries_zero_rtt();
                for (space, packet) in packets_of(datagram) {
                    let journals = journals
                        .get_mut(space)
                        .filter(|_| !(zero_rtt && space == PacketNumberSpaceKind::ApplicationData));
                    let Some(journals) = journals else {
                        retired.extend(packet.in_flight.map(removed_packet));
                        continue;
                    };
                    let record = journals.sent(packet.sealed, at);
                    ack_eliciting |= record.ack_eliciting;
                    if record.ecn != EcnMarking::NotEct {
                        marked_sent.push((space, record.ecn));
                    }
                    if let Some(detection) = detections
                        .as_mut()
                        .and_then(|detections| detections.get_mut(space))
                    {
                        detection.accept(
                            record.number,
                            at,
                            record.ack_eliciting,
                            record.pmtu_probe,
                            packet.in_flight,
                        );
                        if let Some(ecn) = ecn.as_mut() {
                            ecn.on_accepted(space, record.ecn);
                        }
                    }
                }
            }
        },
    );
    let marked = others.with_own_recovery::<SettleRecoveryTakes<T, L, S, Ls>, Iq, _>(
        |hlist_pat![_, _, mut detections, _, mut ecn], _| {
            if let Some(mark) = mark.take() {
                mark(Some(&mut *detections), Some(&mut *ecn));
            }
        },
    );
    if marked.is_none()
        && let Some(mark) = mark.take()
    {
        mark(None, None);
    }
    if !marked_sent.is_empty() {
        let mut numbers = lineage.get_mut::<PacketNumberSpaces<PacketNumberSpaceState>, In>();
        for (space, marking) in marked_sent {
            if let Some(numbers) = numbers.get_mut(space) {
                numbers.marked_sent(marking);
            }
        }
    }
    if ack_eliciting {
        lineage
            .get_mut::<IdleTimeout<InstantOf<T>>, Ie>()
            .ack_eliciting_sent(at);
    }
    if sent {
        lineage.publish(Happened::<PacketsSent>::new());
    }
    retired
}

/// What leaves the bytes in flight of a packet that counted with `charge`,
/// as its controller hears of it.
fn removed_packet<S>(charge: InFlightCharge<S>) -> RemovedPacket<S> {
    RemovedPacket {
        bytes: charge.bytes,
        sent_state: charge.sent_state,
    }
}

/// Give up the packets of `datagrams`: their send result is unknown. Each
/// is kept as declared lost for three probe timeouts of its space, the
/// summaries of its frames go back to their frame sources as lost, and
/// those that count in flight leave the bytes in flight without a
/// congestion signal. A packet of a space retired since it was sealed,
/// and a 0-RTT packet once the server rejected 0-RTT, has no record to
/// keep, and the summaries of its frames go with it.
fn give_up<'v, T, L, B, S, Ls, Ij, If, Iv, Iq, Hf, Ist, Ipp, Ima, Jx, Jr, Jm>(
    lineage: &mut LineageOf<'v, T, L, LinkPath>,
    others: &mut OtherNodes<'v, T, L, B>,
    datagrams: impl IntoIterator<
        Item = BatchedDatagram<SealedPacketOf<T, L>, SealedPacketOf<T, L>, SealedPacketOf<T, L>, S>,
    >,
) where
    T: Choices,
    L: LineagePartList<T>
        + FeedbackSummariesOf
        + ParametersOf<TransportParameterSpace>
        + ConnectionErrorsOf,
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
    for<'x> <L as LineageLists<'x, T>>::LinkPath:
        LineageFeedback<T, L, EstablishedSourceComponentsOfParts<T, L>, Hf>,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
    L: EstablishedSourceComponentsOf<T, L>,
    for<'s> NodeData<T, L, layer::Established>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Established> as FlatMut<'s>>::Out:
        TakeEach<'s, EstablishedSourceComponentsOfParts<T, L>, Ist>,
    for<'x> NodeData<T, L, layer::Recovery>: FlatMut<'x>,
    for<'x> <NodeData<T, L, layer::Recovery> as FlatMut<'x>>::Out:
        TakeEach<'x, SettleRecoveryTakes<T, L, S, Ls>, Iq>,
    for<'a> NodeData<T, L, layer::Recovery>: FlatRef<'a>,
    for<'a> <NodeData<T, L, layer::Recovery> as FlatRef<'a>>::Out: Selector<&'a CongestionPartOf<T, L>, Jx>
        + Selector<&'a RttOf<T, L>, Jr>
        + Selector<&'a PmtuOf<T, L>, Jm>,
{
    let now = others.now();
    let hlist_pat![_, thresholds, peer, rejection] =
        Lineage::read_each::<SettleReads<T, L>, Iv>(&*lineage);
    let rejected = rejection.is_rejected();
    let granularity = thresholds.granularity();
    let peer_max_ack_delay = peer_max_ack_delay::<L, Ima>(peer).unwrap_or(DEFAULT_MAX_ACK_DELAY);
    let estimate = others.recovery_ref().map(|flat| {
        let rtt: &&RttOf<T, L> = Selector::<_, Jr>::get(&flat);
        rtt.estimate()
    });
    // as long as a packet declared lost is kept (RFC 9002 §6.1); a link
    // path without a recovery layer keeps it no longer than now
    let retain_until = |space| {
        estimate.map_or(now, |estimate| {
            let pto = probe_timeout(&estimate, granularity, space, peer_max_ack_delay, 0);
            now + pto.saturating_mul(3)
        })
    };
    // out of the lineage while the summaries go back to the frame sources
    // beside it; the empty journals left in their place take nothing
    // meanwhile
    let mut journals = core::mem::take(&mut *lineage.get_mut::<SendJournalsOf<T, L>, Ij>());
    let mut removed = Vec::new();
    let mut unsent_probes = Vec::new();
    let mut established =
        others.borrow_established_optional::<EstablishedSourceComponentsOfParts<T, L>, Ist>();
    for datagram in datagrams {
        let zero_rtt = datagram.carries_zero_rtt();
        for (space, packet) in packets_of(datagram) {
            let BatchedPacket { sealed, in_flight } = packet;
            removed.extend(in_flight.map(removed_packet));
            // a 0-RTT packet of a rejected 0-RTT has no record any more
            if rejected && zero_rtt && space == PacketNumberSpaceKind::ApplicationData {
                continue;
            }
            let Some(space_journals) = journals.get_mut(space) else {
                continue;
            };
            let record = space_journals.send_result_unknown(sealed, retain_until(space));
            if record.pmtu_probe {
                unsent_probes.push(record.bytes);
            }
            LineageFeedback::<T, L, EstablishedSourceComponentsOfParts<T, L>, Hf>::lost_each(
                lineage,
                &mut established,
                now,
                space,
                &record.summaries,
            );
        }
    }
    // the borrow of the established layer ends before the others are lent
    // on
    drop(established);
    *lineage.get_mut::<SendJournalsOf<T, L>, Ij>() = journals;
    if !unsent_probes.is_empty() {
        others.with_own_recovery::<SettleRecoveryTakes<T, L, S, Ls>, Iq, _>(
            |hlist_pat![_, mut state, _, mut pmtu, _], _| {
                for size in unsent_probes {
                    state.on_pmtu_probe_settled();
                    pmtu.on_probe_failed(size, PmtuProbeFailure::Unsent, now);
                }
            },
        );
    }
    remove_without_signal::<T, L, B, S, Ls, If, Iv, Iq, Ipp, Jx, Jr, Jm>(lineage, others, removed);
}

/// The packets `removed` leave the bytes in flight of the link path whose
/// sending call `lineage` and `others` are the lend of, and its lent
/// congestion controller hears of them as removed without a signal. A link
/// path without a recovery layer has nothing in flight.
fn remove_without_signal<'v, T, L, B, S, Ls, If, Iv, Iq, Ipp, Jx, Jr, Jm>(
    lineage: &mut LineageOf<'v, T, L, LinkPath>,
    others: &mut OtherNodes<'v, T, L, B>,
    removed: Vec<RemovedPacket<S>>,
) where
    T: Choices,
    L: LineagePartList<T> + FeedbackSummariesOf + ParametersOf<TransportParameterSpace>,
    B: CallBundle,
    S: 'static,
    Ls: 'static,
    RecoveryFactoryOf<T, L>: RecoveryFactory<T::Link>
        + for<'s> LendCongestion<
            InstantOf<T>,
            OthersOf<'s, T, L>,
            Part = CongestionPartOf<T, L>,
            SentState = S,
            LossState = Ls,
        >,
    TransportParameterSlots<L>: Selector<Option<MaxUdpPayloadSize>, Ipp>,
    for<'x> <L as LineageLists<'x, T>>::LinkPath:
        GetAt<RecoveryFactoryOf<T, L>, If> + ReadEach<SettleReads<T, L>, Iv>,
    for<'x> NodeData<T, L, layer::Recovery>: FlatMut<'x>,
    for<'x> <NodeData<T, L, layer::Recovery> as FlatMut<'x>>::Out:
        TakeEach<'x, SettleRecoveryTakes<T, L, S, Ls>, Iq>,
    for<'a> NodeData<T, L, layer::Recovery>: FlatRef<'a>,
    for<'a> <NodeData<T, L, layer::Recovery> as FlatRef<'a>>::Out: Selector<&'a CongestionPartOf<T, L>, Jx>
        + Selector<&'a RttOf<T, L>, Jr>
        + Selector<&'a PmtuOf<T, L>, Jm>,
{
    if removed.is_empty() {
        return;
    }
    let now = others.now();
    let hlist_pat![link, _, peer, _] = Lineage::read_each::<SettleReads<T, L>, Iv>(&*lineage);
    let link_ceiling = link.0.max_datagram_size().ok();
    let peer_max_udp_payload = peer_max_udp_payload_size::<L, Ipp>(peer);
    let Some((estimate, conclusion)) = others.recovery_ref().map(|flat| {
        let rtt: &&RttOf<T, L> = Selector::<_, Jr>::get(&flat);
        let pmtu: &&PmtuOf<T, L> = Selector::<_, Jm>::get(&flat);
        (rtt.estimate(), pmtu.conclusion())
    }) else {
        return;
    };
    let mut factory = lineage.get_mut::<RecoveryFactoryOf<T, L>, If>();
    let removed_any = others.with_own_recovery::<SettleRecoveryTakes<T, L, S, Ls>, Iq, _>(
        |hlist_pat![mut part, mut state, _, _, _], others| {
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
            lend_congestion::<T, L, B, Jx, Jr, _>(
                &mut *factory,
                &mut *part,
                others,
                |mut access| {
                    access.on_removed(removed.into_iter(), &context);
                },
            );
        },
    );
    if removed_any.is_some() {
        let NodeKey::LinkPath(path, link) = others.here().clone() else {
            unreachable!("a link path's lend carries its key")
        };
        others.publish_at(
            &NodeKey::Recovery(path, link),
            Happened::<CongestionChanged>::new(),
        );
    }
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

/// The kind of the sending call of a link path. It subscribes to the link
/// path's recovery layer built and to its close packet changed, once it is
/// sealed. Everything else that lets it send more, the datagram size probe
/// to send and what the probing policy concludes among it, is the send
/// planner's to wake it for.
///
/// It subscribes to the link path's role changed too: once the link path is
/// `Draining`, it sends nothing again (RFC 9000 §10.2.2), and the call is
/// not needed any more. What it handed to its link is sent; what its batch
/// still holds is not, and goes with the call.
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
    Ici,
    Ik,
    Hs,
    Hd,
    Ipd,
    Ipm,
    Ipb,
    Ipr,
    Ics,
    Ipv,
    Ifs,
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
    Ist,
    In,
    Ipp,
    Ima,
    Jx,
    Jr,
    Jm,
    Je,
    Iu,
    Ihc,
    Ikp,
    Ic,
    Ier,
    Irt,
    Icp,
    Irs,
    Ilf,
    Ida,
    Idr,
    Iva,
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
            Ici,
            Ik,
            Hs,
            Hd,
            Ipd,
            Ipm,
            Ipb,
            Ipr,
            Ics,
            Ipv,
            Ifs,
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
            Ist,
            In,
            Ipp,
            Ima,
            Jx,
            Jr,
            Jm,
            Je,
            Iu,
            Ihc,
            Ikp,
            Ic,
            Ier,
            Irt,
            Icp,
            Irs,
            Ilf,
            Ida,
            Idr,
            Iva,
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
    PartsFrameSources<SettlingProbePacket, L>: FrameSourceSet,
    FeedbackSummaryOf<T, L>: InjectSummary<PaddingSummary, Ipd>,
    SendTypes<T, L>: SendStrategyTypes<
            LinkPathIdentifier = LinkPathIdentifierOf<T, L>,
            InitialFrameSources = PartsFrameSources<InitialPacket, L>,
            HandshakeFrameSources = PartsFrameSources<HandshakePacket, L>,
            ZeroRttFrameSources = PartsFrameSources<ZeroRttPacket, L>,
            OneRttFrameSources = PartsFrameSources<OneRttPacket, L>,
            ProbeFrameSources = PartsFrameSources<OneRttProbePacket, L>,
            SettlingFrameSources = PartsFrameSources<SettlingProbePacket, L>,
        >,
    SendTypes<T, L>: HostSendStrategyTypes,
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
    EventsOf<T, L>: PacketEvents<InstantOf<T>, L>,
    for<'x> <L as LineageLists<'x, T>>::LinkPath: GetAt<LinkPathSendingLimits, Is>
        + TakeEach<'x, FillTakes<T, L>, It>
        + GetAt<InitialKeys<T::Crypto>, Ii>
        + GetAt<HandshakeKeys<T::Crypto>, Ih>
        + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>
        + GetAt<LinkClone<T::Link>, Il>
        + GetAt<SendJournalsOf<T, L>, Ij>
        + GetAt<PacketNumberSpaces<PacketNumberSpaceState>, In>
        + GetAt<RecoveryFactoryOf<T, L>, If>
        + ReadEach<SettleReads<T, L>, Iv>
        + GetAt<IdleTimeout<InstantOf<T>>, Ie>
        + GetAt<AeadUsage, Iu>
        + GetAt<HandshakeConfirmation, Ihc>
        + GetAt<KeyPhaseNumbers, Ikp>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>
        + GetAt<ClosePacket, Icp>
        + GetAt<LinkFacts, Ilf>
        + GetAt<DatagramAcceptance, Ida>
        + TakeEach<'x, ResendTakes<T, L>, Irs>
        + GetAt<LinkPathRole<InstantOf<T>>, Idr>
        + GetAt<PathValidationOf<T>, Iva>,
    L: ConnectionErrorsOf,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<V1ConnectionErrorOf<L>, Ier>,
    for<'x> FillKeysRest<'x, T, L, It>: TakeEach<'x, FillReadTakes<T>, Iw>,
    for<'x> FillRest<'x, T, L, It, Iw>:
        AppendEach<<EstablishedSourceComponentsOfParts<T, L> as OptionalRefs>::Optional<'x>>,
    for<'x> FillStreamsRest<'x, T, L, It, Iw>: ReadEach<FillReads<T, L>, Ir>
        + GetAt<ConnectionIdsOf<T>, Ici>
        + GetAt<PendingPmtuProbe, Ipm>
        + GetAt<PendingProbePings, Ipb>
        + GetAt<SendStrategyPublisher<PublisherOf<T, L>>, Ipr>
        + GetAt<CryptoSender<CryptoSendBufferOf<T>>, Ics>
        + GetAt<PathValidationOf<T>, Ipv>,
    <SendTypes<T, L> as SendStrategyTypes>::FrameSourceId:
        CoprodInjector<FrameSourceId, Ifs> + PartialEq,
    <PartsFrameSources<OneRttPacket, L> as FrameSourceSet>::FrameSourceId:
        CoprodInjector<FrameSourceId, Ifs> + PartialEq,
    for<'x> L: DriverContentOf<T, L, FillStreamsRest<'x, T, L, It, Iw>, Hd>,
    <SendTypes<T, L> as SendStrategyTypes>::SendIntents: From<<L as SendIntentsOf>::SendIntents>,
    for<'x> L: PartsFrameSourceDispatch<
            T,
            L,
            InitialPacket,
            FillStreamsRest<'x, T, L, It, Iw>,
            FeedbackSummaryOf<T, L>,
            Hs,
        > + PartsFrameSourceDispatch<
            T,
            L,
            HandshakePacket,
            FillStreamsRest<'x, T, L, It, Iw>,
            FeedbackSummaryOf<T, L>,
            Hs,
        > + PartsFrameSourceDispatch<
            T,
            L,
            ZeroRttPacket,
            FillStreamsRest<'x, T, L, It, Iw>,
            FeedbackSummaryOf<T, L>,
            Hs,
        > + PartsFrameSourceDispatch<
            T,
            L,
            OneRttPacket,
            FillStreamsRest<'x, T, L, It, Iw>,
            FeedbackSummaryOf<T, L>,
            Hs,
        > + PartsFrameSourceDispatch<
            T,
            L,
            OneRttProbePacket,
            FillStreamsRest<'x, T, L, It, Iw>,
            FeedbackSummaryOf<T, L>,
            Hs,
        > + PartsFrameSourceDispatch<
            T,
            L,
            SettlingProbePacket,
            FillStreamsRest<'x, T, L, It, Iw>,
            FeedbackSummaryOf<T, L>,
            Hs,
        >,
    for<'x> <L as LineageLists<'x, T>>::LinkPath:
        LineageFeedback<T, L, EstablishedSourceComponentsOfParts<T, L>, Hf>,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
    L: EstablishedSourceComponentsOf<T, L>,
    for<'s> NodeData<T, L, layer::Established>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Established> as FlatMut<'s>>::Out:
        TakeEach<'s, EstablishedSourceComponentsOfParts<T, L>, Ist>,
    for<'x> NodeData<T, L, layer::Recovery>: FlatMut<'x>,
    for<'x> <NodeData<T, L, layer::Recovery> as FlatMut<'x>>::Out: TakeEach<'x, FillRecoveryTakes<T, L>, Ik>
        + TakeEach<'x, SettleRecoveryTakes<T, L, S, Ls>, Iq>
        + GetAt<RttOf<T, L>, Irt>,
    for<'a> NodeData<T, L, layer::Recovery>: FlatRef<'a>,
    for<'a> <NodeData<T, L, layer::Recovery> as FlatRef<'a>>::Out: Selector<&'a CongestionPartOf<T, L>, Jx>
        + Selector<&'a RttOf<T, L>, Jr>
        + Selector<&'a PmtuOf<T, L>, Jm>
        + Selector<&'a LinkPathEcnState<InstantOf<T>>, Je>,
    Positions<
        Is,
        It,
        Iw,
        Ir,
        Ici,
        Ik,
        Hs,
        Hd,
        Ipd,
        Ipm,
        Ipb,
        Ipr,
        Ics,
        Ipv,
        Ifs,
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
        Ist,
        In,
        Ipp,
        Ima,
        Jx,
        Jr,
        Jm,
        Je,
        Iu,
        Ihc,
        Ikp,
        Ic,
        Ier,
        Irt,
        Icp,
        Irs,
        Ilf,
        Ida,
        Idr,
        Iva,
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
                Ici,
                Ik,
                Hs,
                Hd,
                Ipd,
                Ipm,
                Ipb,
                Ipr,
                Ics,
                Ipv,
                Ifs,
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
                Ist,
                In,
                Ipp,
                Ima,
                Jx,
                Jr,
                Jm,
                Je,
                Iu,
                Ihc,
                Ikp,
                Ic,
                Ier,
                Irt,
                Icp,
                Irs,
                Ilf,
                Ida,
                Idr,
                Iva,
            >,
            B,
        >,
        LinkPathSending,
    >;
    fn start<B: CallBundle>(_: &mut ArgsOf<T, L, LinkPath>) -> Self::Call<B> {
        LentCall::new(LinkPathSending::new())
    }
    fn subscribes(out: &mut EventSubscriptions) {
        out.add::<NodeStarted<layer::Recovery>>()
            .add::<ClosePacketChanged>()
            .add::<LinkPathRoleChanged>();
    }
    fn no_longer_needed<'v>(lineage: &LineageOf<'v, T, L, LinkPath>) -> bool {
        lineage.get::<LinkPathRole<InstantOf<T>>, Idr>().kind() == LinkPathRoleKind::Draining
    }
}
